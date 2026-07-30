//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//
#![allow(clippy::unwrap_used)]
use crate::claim_mapper::{CelClaimMapper, ClaimMapper, merge_claim_mappings, unwrap_json_value};
use crate::config::{EndpointMapping, TokenSource, TransferType};
use crate::transfer_type::{MemoryTransferTypeMappingStore, TransferTypeMappingError, TransferTypeMappingRepository};
use bon::Builder;
use chrono::Utc;
use dataplane_sdk::core::error::HandlerError;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::{
    db::memory::MemoryTransaction,
    error::HandlerResult,
    handler::DataFlowHandler,
    model::{
        data_flow::{DataFlow, DataFlowState},
        messages::DataFlowStatusMessage,
    },
};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{TokenData, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use serde_json::Value;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

#[cfg(test)]
pub mod tests;

/// JWT claim key constants
pub const CLAIM_AGREEMENT_ID: &str = "agreementId";
pub const CLAIM_PARTICIPANT_ID: &str = "participantId";
pub const CLAIM_COUNTER_PARTY_ID: &str = "counterPartyId";
pub const CLAIM_DATASET_ID: &str = "datasetId";

/// DataFlowHandler implementation for Siglet
#[derive(Clone, Builder)]
pub struct SigletDataFlowHandler<Tx = MemoryTransaction> {
    #[allow(dead_code)]
    #[builder(into)]
    dataplane_id: String,
    token_store: Arc<dyn TokenStore>,
    token_manager: Arc<dyn TokenManager>,
    /// Per-participant-context transfer-type mappings configured at runtime via the management
    /// API. Consulted first on every request; when a context has no stored mappings the handler
    /// falls back to `transfer_type_mappings`. Defaults to an empty in-memory store, so a handler
    /// built without one behaves exactly like the static, config-only handler.
    #[builder(default = Arc::new(MemoryTransferTypeMappingStore::new()) as Arc<dyn TransferTypeMappingRepository>)]
    transfer_type_repo: Arc<dyn TransferTypeMappingRepository>,
    /// Static, global fallback mappings from configuration (`SigletConfig::transfer_types`).
    transfer_type_mappings: HashMap<String, TransferType>,
    /// Evaluates the configured claim mappings against the flow. Defaults to the CEL
    /// implementation, so a handler built without one behaves exactly as before whenever no claim
    /// mappings are configured.
    #[builder(default = Arc::new(CelClaimMapper::new()) as Arc<dyn ClaimMapper>)]
    claim_mapper: Arc<dyn ClaimMapper>,
    #[builder(skip)]
    _phantom: PhantomData<fn() -> Tx>,
}

impl<Tx> SigletDataFlowHandler<Tx> {
    /// Flattens a serde_json::Value into a plain String for endpoint-mapping comparison.
    ///
    /// - Objects and arrays are serialized as JSON
    /// - Primitives (string, number, bool) are serialized in raw format (no JSON encoding)
    /// - Null values are serialized as an empty string
    /// - If a string value is itself a JSON-encoded string, it will be unwrapped
    ///
    /// The unwrapping step is shared with the claim-mapper flow projection (see
    /// [`unwrap_json_value`]) so endpoint matching and claim-mapping expressions agree on what a
    /// JSON-encoded metadata value means.
    fn value_to_claim_string(v: &Value) -> String {
        match unwrap_json_value(v) {
            Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => s,
            other => serde_json::to_string(&other).unwrap_or_else(|_| other.to_string()),
        }
    }

    /// Generates authentication properties from a token pair
    fn create_auth_properties(pair: &RenewableTokenPair) -> Vec<EndpointProperty> {
        vec![
            EndpointProperty::builder()
                .name("authorization")
                .value(&pair.token)
                .build(),
            EndpointProperty::builder().name("authType").value("bearer").build(),
            EndpointProperty::builder()
                .name("refreshToken")
                .value(&pair.refresh_token)
                .build(),
            EndpointProperty::builder()
                .name("expiresIn")
                .value((pair.expires_at.timestamp() - Utc::now().timestamp()).to_string())
                .build(),
            EndpointProperty::builder()
                .name("refreshEndpoint")
                .value(&pair.refresh_endpoint)
                .build(),
        ]
    }

    /// Generates data-address properties for the special tx-token-renewal protocol.
    fn create_tx_renewal_properties(aud: &str, pair: &RenewableTokenPair) -> Vec<EndpointProperty> {
        vec![
            EndpointProperty::builder()
                .name("https://w3id.org/edc/v0.0.1/ns/authorization")
                .value(&pair.token)
                .build(),
            EndpointProperty::builder()
                .name("https://w3id.org/tractusx/auth/authType")
                .value("bearer")
                .build(),
            EndpointProperty::builder()
                .name("https://w3id.org/tractusx/auth/refreshToken")
                .value(&pair.refresh_token)
                .build(),
            EndpointProperty::builder()
                .name("https://w3id.org/tractusx/auth/expiresIn")
                .value((pair.expires_at.timestamp() - Utc::now().timestamp()).to_string())
                .build(),
            EndpointProperty::builder()
                .name("https://w3id.org/tractusx/auth/refreshEndpoint")
                .value(&pair.refresh_endpoint)
                .build(),
            EndpointProperty::builder()
                .name("https://w3id.org/tractusx/auth/refreshAudience")
                .value(aud)
                .build(),
        ]
    }

    /// Resolves the transfer type for the given flow, applying the per-participant-context
    /// override with a fallback to the static configuration.
    ///
    /// The participant context's stored mappings (configured via the management API) are loaded
    /// first. If the context has any stored mappings they are authoritative — the static config is
    /// ignored for that context (all-or-nothing). Only when the context has no stored mappings do
    /// we fall back to the static `transfer_type_mappings`. In either case the map is keyed by
    /// `flow.profile`; `None` means the profile is unsupported.
    async fn resolve_transfer_type(&self, flow: &DataFlow) -> HandlerResult<Option<TransferType>> {
        match self.transfer_type_repo.find(&flow.participant_context_id).await {
            // The participant context has a stored map -> it is authoritative.
            Ok(mapping) if !mapping.mappings.is_empty() => Ok(mapping.mappings.get(&flow.profile).cloned()),
            // No row, or an empty stored map -> fall back to the static configuration.
            Ok(_) | Err(TransferTypeMappingError::NotFound { .. }) => {
                Ok(self.transfer_type_mappings.get(&flow.profile).cloned())
            }
            Err(e) => Err(HandlerError::Generic(
                format!("Failed to load transfer type mappings: {}", e).into(),
            )),
        }
    }

    /// Looks up the transfer type configuration for the given flow, erroring if unsupported.
    async fn get_transfer_type(&self, flow: &DataFlow) -> HandlerResult<TransferType> {
        self.resolve_transfer_type(flow)
            .await?
            .ok_or_else(|| HandlerError::Generic(format!("Unsupported profile: {}", flow.profile).into()))
    }

    /// Resolves the endpoint for the given flow, returning the endpoint mapping that matched.
    ///
    /// If `endpoint_mappings` are configured, iterates over them and returns the endpoint whose
    /// `key`/`value` pair matches a `flow.metadata` entry. Returns an error if no mapping matches.
    /// If no mappings are configured falls back to the static `endpoint`, and there is no matched
    /// mapping to return.
    ///
    /// The matched mapping is handed back so the caller can layer its claim mappings on top of the
    /// transfer type's.
    fn resolve_endpoint<'a>(
        transfer_type: &'a TransferType,
        flow: &DataFlow,
    ) -> HandlerResult<(String, Option<&'a EndpointMapping>)> {
        if transfer_type.endpoint_mappings.is_empty() {
            let endpoint = transfer_type.endpoint.clone().ok_or_else(|| {
                HandlerError::Generic(
                    format!(
                        "No endpoint configured for transfer type '{}'",
                        transfer_type.transfer_type
                    )
                    .into(),
                )
            })?;
            return Ok((endpoint, None));
        }

        transfer_type
            .endpoint_mappings
            .iter()
            .find(|m| {
                flow.metadata
                    .get(&m.key)
                    .is_some_and(|v| Self::value_to_claim_string(v) == m.value)
            })
            .map(|m| (m.endpoint.clone(), Some(m)))
            .ok_or_else(|| {
                HandlerError::Generic(
                    format!(
                        "No endpoint mapping matched for flow '{}' with profile '{}'",
                        flow.id, flow.profile
                    )
                    .into(),
                )
            })
    }

    /// Generates a token pair for the flow.
    ///
    /// Callers are responsible for checking that the transfer type's token source matches; see
    /// `handle_flow`.
    ///
    /// Claims are assembled in three layers, each able to override the last:
    /// 1. `flow.metadata`, copied verbatim — values keep their JSON type
    /// 2. the flow-level claims (agreement, participant, dataset, counter-party), only when
    ///    `required_source` is `Provider`
    /// 3. the configured claim mappings, so an operator can reshape or replace anything above
    ///
    /// Claim keys that would collide with a reserved JWT claim are rejected when the configuration
    /// is written, and `TokenManager::generate_pair` rejects them again as a backstop.
    async fn generate_token(
        &self,
        participant_context: &ParticipantContext,
        config: &TransferType,
        endpoint_mapping: Option<&EndpointMapping>,
        flow: &DataFlow,
        required_source: TokenSource,
    ) -> HandlerResult<RenewableTokenPair> {
        let mut claims: HashMap<String, Value> = flow.metadata.clone();

        if matches!(required_source, TokenSource::Provider) {
            claims.insert(CLAIM_AGREEMENT_ID.to_string(), Value::String(flow.agreement_id.clone()));
            claims.insert(
                CLAIM_PARTICIPANT_ID.to_string(),
                Value::String(flow.participant_id.clone()),
            );
            claims.insert(
                CLAIM_COUNTER_PARTY_ID.to_string(),
                Value::String(flow.counter_party_id.clone()),
            );
            claims.insert(CLAIM_DATASET_ID.to_string(), Value::String(flow.dataset_id.clone()));
        }

        let mappings = merge_claim_mappings(
            &config.claim_mappings,
            endpoint_mapping.map(|m| m.claim_mappings.as_slice()),
        );
        if !mappings.is_empty() {
            let mapped = self.claim_mapper.map_claims(&mappings, flow).map_err(|e| {
                HandlerError::Generic(format!("Failed to map claims for flow '{}': {}", flow.id, e).into())
            })?;
            claims.extend(mapped);
        }

        self.token_manager
            .generate_pair(participant_context, &flow.counter_party_id, claims, flow.id.clone())
            .await
            .map_err(|e| HandlerError::Generic(format!("Failed to generate token pair: {}", e).into()))
    }

    async fn cleanup_tokens(&self, flow: &DataFlow, participant_context: &ParticipantContext) -> HandlerResult<()> {
        // TODO only revoke if this data plane is the token source, otherwise remove from the cache
        match self.token_manager.revoke_token(participant_context, &flow.id).await {
            Ok(_) => Ok(()),
            Err(TokenError::TokenNotFound { .. }) => {
                // Ignore NotFound errors
                self.token_store
                    .remove_token(participant_context.id.as_str(), flow.id.as_str())
                    .await
                    .map_err(|e| HandlerError::Generic(format!("Failed to remove token: {}", e).into()))?;
                Ok(())
            }
            Err(e) => Err(HandlerError::Generic(format!("Failed to revoke token: {}", e).into())),
        }
    }

    /// Extracts a ParticipantContext from a DataFlow
    ///
    /// This helper reduces duplication across handler methods that need
    /// to create participant context from flow data.
    fn build_participant_context(flow: &DataFlow) -> ParticipantContext {
        ParticipantContext::builder()
            .id(flow.participant_context_id.clone())
            .identifier(flow.participant_id.clone())
            .audience(flow.participant_id.clone())
            .build()
    }

    /// Builds a DataFlowResponseMessage with an optional data address.
    fn build_response(
        &self,
        flow_id: &str,
        state: DataFlowState,
        data_address: Option<DataAddress>,
    ) -> DataFlowStatusMessage {
        DataFlowStatusMessage::builder()
            .data_flow_id(flow_id)
            .state(state)
            .maybe_data_address(data_address)
            .build()
    }

    /// Shared implementation for `on_start` and `on_prepare`.
    ///
    /// Generates a token only when the transfer type's source matches `required_source`,
    /// then wraps the result in a response with the given `state`.
    async fn handle_flow(
        &self,
        flow: &DataFlow,
        required_source: TokenSource,
        state: DataFlowState,
    ) -> HandlerResult<DataFlowStatusMessage> {
        let transfer_type = self.get_transfer_type(flow).await?;

        // When this data plane is not the token source for the transfer type, nothing further
        // about it is resolved or validated. In particular an endpoint mapping that matches
        // nothing must not fail a flow we are not issuing a token for.
        if transfer_type.token_source != required_source {
            return Ok(self.build_response(&flow.id, state, None));
        }

        // Resolve the endpoint before minting anything: a token generated first would be orphaned
        // if endpoint resolution then failed.
        let (endpoint, endpoint_mapping) = Self::resolve_endpoint(&transfer_type, flow)?;

        let participant_context = Self::build_participant_context(flow);
        let pair = self
            .generate_token(
                &participant_context,
                &transfer_type,
                endpoint_mapping,
                flow,
                required_source,
            )
            .await?;

        let properties = if transfer_type.tx_renewal_support {
            Self::create_tx_renewal_properties(&flow.participant_id, &pair)
        } else {
            Self::create_auth_properties(&pair)
        };

        let data_address = DataAddress::builder()
            .endpoint_type(&transfer_type.endpoint_type)
            .endpoint(endpoint)
            .endpoint_properties(properties)
            .build();

        Ok(self.build_response(&flow.id, state, Some(data_address)))
    }
}

#[async_trait::async_trait]
impl<Tx: Send> DataFlowHandler for SigletDataFlowHandler<Tx> {
    type Transaction = Tx;

    async fn can_handle(&self, flow: &DataFlow) -> HandlerResult<bool> {
        Ok(self.resolve_transfer_type(flow).await?.is_some())
    }

    async fn on_start(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowStatusMessage> {
        self.handle_flow(flow, TokenSource::Provider, DataFlowState::Started)
            .await
    }

    async fn on_prepare(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowStatusMessage> {
        self.handle_flow(flow, TokenSource::Client, DataFlowState::Prepared)
            .await
    }

    async fn on_terminate(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        let participant_context = Self::build_participant_context(flow);
        self.cleanup_tokens(flow, &participant_context).await
    }

    async fn on_started(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        if let Some(data_address) = flow.data_address.as_ref() {
            let transfer_type = self.get_transfer_type(flow).await?;
            let renewal_properties = if transfer_type.tx_renewal_support {
                read_tx_renewal_properties(data_address)?
            } else {
                read_renewal_properties(data_address)?
            };

            let token_data = TokenData::builder()
                .identifier(flow.id.clone())
                .participant_context(flow.participant_context_id.clone())
                .participant_id(flow.participant_id.clone())
                .counter_party_id(flow.counter_party_id.clone())
                .token(renewal_properties.token)
                .refresh_token(renewal_properties.refresh_token)
                .expires_at(renewal_properties.expires_at)
                .refresh_endpoint(renewal_properties.refresh_endpoint)
                .endpoint(data_address.endpoint.to_string())
                .build();

            self.token_store
                .save_token(token_data)
                .await
                .map_err(|e| HandlerError::Generic(format!("Failed to save token: {}", e).into()))?;
        }

        Ok(())
    }

    async fn on_suspend(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        // TODO only revoke if this data plane is the token source, otherwise remove from the cache
        let participant_context = Self::build_participant_context(flow);
        self.cleanup_tokens(flow, &participant_context).await
    }
}

struct RenewalProperties {
    token: String,
    refresh_endpoint: String,
    refresh_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

fn read_renewal_properties(data_address: &DataAddress) -> HandlerResult<RenewalProperties> {
    let token = data_address
        .get_property("authorization")
        .ok_or_else(|| HandlerError::Generic("Data address must contain an authorization property".into()))?;

    let refresh_token = data_address
        .get_property("refreshToken")
        .ok_or_else(|| HandlerError::Generic("Data address must contain a refreshToken property".into()))?;

    let refresh_endpoint = data_address
        .get_property("refreshEndpoint")
        .ok_or_else(|| HandlerError::Generic("Data address must contain a refreshEndpoint property".into()))?;

    let expires_in = data_address
        .get_property("expiresIn")
        .ok_or_else(|| HandlerError::Generic("Data address must contain an expiresIn property".into()))
        .and_then(|s| {
            s.parse::<i64>()
                .map_err(|_| HandlerError::Generic("Invalid expiresIn format".into()))
        })?;

    // Calculate absolute expiration timestamp from relative seconds
    let expires_at_timestamp = Utc::now().timestamp() + expires_in;
    let expires_at = chrono::DateTime::from_timestamp(expires_at_timestamp, 0)
        .ok_or_else(|| HandlerError::Generic("Invalid expiration timestamp".into()))?;

    Ok(RenewalProperties {
        token: token.to_string(),
        refresh_token: refresh_token.to_string(),
        refresh_endpoint: refresh_endpoint.to_string(),
        expires_at,
    })
}

fn read_tx_renewal_properties(data_address: &DataAddress) -> HandlerResult<RenewalProperties> {
    let token = data_address
        .get_property("https://w3id.org/edc/v0.0.1/ns/authorization")
        .ok_or_else(|| HandlerError::Generic("Data address must contain an authorization property".into()))?;

    let refresh_token = data_address
        .get_property("https://w3id.org/tractusx/auth/refreshToken")
        .ok_or_else(|| HandlerError::Generic("Data address must contain a refreshToken property".into()))?;

    let refresh_endpoint = data_address
        .get_property("https://w3id.org/tractusx/auth/refreshEndpoint")
        .ok_or_else(|| HandlerError::Generic("Data address must contain a refreshEndpoint property".into()))?;

    let expires_in = data_address
        .get_property("https://w3id.org/tractusx/auth/expiresIn")
        .ok_or_else(|| HandlerError::Generic("Data address must contain an expiresIn property".into()))
        .and_then(|s| {
            s.parse::<i64>()
                .map_err(|_| HandlerError::Generic("Invalid expiresIn format".into()))
        })?;

    // Calculate absolute expiration timestamp from relative seconds
    let expires_at_timestamp = Utc::now().timestamp() + expires_in;
    let expires_at = chrono::DateTime::from_timestamp(expires_at_timestamp, 0)
        .ok_or_else(|| HandlerError::Generic("Invalid expiration timestamp".into()))?;

    Ok(RenewalProperties {
        token: token.to_string(),
        refresh_token: refresh_token.to_string(),
        refresh_endpoint: refresh_endpoint.to_string(),
        expires_at,
    })
}
