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
use crate::config::{TokenSource, TransferType};
use bon::Builder;
use chrono::Utc;
use dataplane_sdk::core::error::HandlerError;
use dataplane_sdk::core::model::data_address::{DataAddress, EndpointProperty};
use dataplane_sdk::core::{
    db::memory::MemoryContext,
    db::tx::TransactionalContext,
    error::HandlerResult,
    handler::DataFlowHandler,
    model::{
        data_flow::{DataFlow, DataFlowState},
        messages::DataFlowResponseMessage,
    },
};
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{TokenData, TokenStore};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use std::collections::HashMap;
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
pub struct SigletDataFlowHandler {
    #[builder(into)]
    dataplane_id: String,

    token_store: Arc<dyn TokenStore>,

    token_manager: Arc<dyn TokenManager>,

    transfer_type_mappings: HashMap<String, TransferType>,
}

impl SigletDataFlowHandler {
    /// Converts a serde_json::Value to a String for use in JWT claims.
    ///
    /// - Objects and arrays are serialized as JSON
    /// - Primitives (string, number, bool) are serialized in raw format (no JSON encoding)
    /// - Null values are serialized as an empty string
    /// - If a string value is itself a JSON-encoded string, it will be unwrapped
    fn value_to_claim_string(v: &serde_json::Value) -> String {
        use serde_json::Value;

        match v {
            Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => {
                // Check if the string is a JSON-encoded value and unwrap it if so
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    // If it's a JSON string, recursively process it to unwrap
                    Self::value_to_claim_string(&parsed)
                } else {
                    // Not a JSON value, use as-is
                    s.clone()
                }
            }
            Value::Array(_) | Value::Object(_) => serde_json::to_string(v).unwrap_or_else(|_| v.to_string()),
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

    /// Looks up the transfer type configuration for the given flow.
    fn get_transfer_type(&self, flow: &DataFlow) -> HandlerResult<&TransferType> {
        self.transfer_type_mappings
            .get(&flow.transfer_type)
            .ok_or_else(|| HandlerError::Generic(format!("Unsupported transfer type: {}", flow.transfer_type).into()))
    }

    /// Resolves the endpoint for the given flow and transfer type configuration.
    ///
    /// If `endpoint_mappings` are configured, iterates over them and returns the endpoint whose
    /// `key`/`value` pair matches a `flow.metadata` entry. Returns an error if no mapping matches.
    /// If no mappings are configured falls back to the static `endpoint`.
    fn resolve_endpoint(transfer_type: &TransferType, flow: &DataFlow) -> HandlerResult<String> {
        if transfer_type.endpoint_mappings.is_empty() {
            return transfer_type.endpoint.clone().ok_or_else(|| {
                HandlerError::Generic(
                    format!(
                        "No endpoint configured for transfer type '{}'",
                        transfer_type.transfer_type
                    )
                    .into(),
                )
            });
        }

        transfer_type
            .endpoint_mappings
            .iter()
            .find(|m| {
                flow.metadata
                    .get(&m.key)
                    .is_some_and(|v| Self::value_to_claim_string(v) == m.value)
            })
            .map(|m| m.endpoint.clone())
            .ok_or_else(|| {
                HandlerError::Generic(
                    format!(
                        "No endpoint mapping matched for flow '{}' with transfer type '{}'",
                        flow.id, flow.transfer_type
                    )
                    .into(),
                )
            })
    }

    /// Generates a token pair if the transfer type's token source matches `required_source`.
    ///
    /// Flow-level claims (agreement, participant, dataset, counter-party) are included
    /// only when `required_source` is `Provider`.
    async fn generate_token_for_source(
        &self,
        participant_context: &ParticipantContext,
        config: &TransferType,
        flow: &DataFlow,
        required_source: TokenSource,
    ) -> HandlerResult<Option<RenewableTokenPair>> {
        if config.token_source != required_source {
            return Ok(None);
        }

        // value_to_claim_string flattens each metadata value into a plain string for the JWT claim.
        // Notable behaviors to be aware of when reading claim output:
        //   - JSON-encoded strings are unwrapped: `"\"hello\""` → `hello`
        //   - `null` becomes an empty string `""`
        //   - objects and arrays are serialized as compact JSON
        // See value_to_claim_string for the full specification.
        let mut claims: HashMap<String, String> = flow
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), Self::value_to_claim_string(v)))
            .collect();

        if matches!(required_source, TokenSource::Provider) {
            claims.insert(CLAIM_AGREEMENT_ID.to_string(), flow.agreement_id.clone());
            claims.insert(CLAIM_PARTICIPANT_ID.to_string(), flow.participant_id.clone());
            claims.insert(CLAIM_COUNTER_PARTY_ID.to_string(), flow.counter_party_id.clone());
            claims.insert(CLAIM_DATASET_ID.to_string(), flow.dataset_id.clone());
        }

        let pair = self
            .token_manager
            .generate_pair(participant_context, &flow.counter_party_id, claims, flow.id.clone())
            .await
            .map_err(|e| HandlerError::Generic(format!("Failed to generate token pair: {}", e).into()))?;

        Ok(Some(pair))
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
    fn build_response(&self, state: DataFlowState, data_address: Option<DataAddress>) -> DataFlowResponseMessage {
        match data_address {
            Some(addr) => DataFlowResponseMessage::builder()
                .dataplane_id(self.dataplane_id.clone())
                .state(state)
                .data_address(addr)
                .build(),
            None => DataFlowResponseMessage::builder()
                .dataplane_id(self.dataplane_id.clone())
                .state(state)
                .build(),
        }
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
    ) -> HandlerResult<DataFlowResponseMessage> {
        let participant_context = Self::build_participant_context(flow);
        let transfer_type = self.get_transfer_type(flow)?;

        let data_address = if let Some(pair) = self
            .generate_token_for_source(&participant_context, transfer_type, flow, required_source)
            .await?
        {
            let endpoint = Self::resolve_endpoint(transfer_type, flow)?;
            Some(
                DataAddress::builder()
                    .endpoint_type(&transfer_type.endpoint_type)
                    .endpoint(endpoint)
                    .endpoint_properties(Self::create_auth_properties(&pair))
                    .build(),
            )
        } else {
            None
        };

        Ok(self.build_response(state, data_address))
    }
}

#[async_trait::async_trait]
impl DataFlowHandler for SigletDataFlowHandler {
    type Transaction = <MemoryContext as TransactionalContext>::Transaction;

    async fn can_handle(&self, flow: &DataFlow) -> HandlerResult<bool> {
        Ok(self.transfer_type_mappings.contains_key(&flow.transfer_type))
    }

    async fn on_start(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowResponseMessage> {
        self.handle_flow(flow, TokenSource::Provider, DataFlowState::Started)
            .await
    }

    async fn on_prepare(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<DataFlowResponseMessage> {
        self.handle_flow(flow, TokenSource::Client, DataFlowState::Prepared)
            .await
    }

    async fn on_terminate(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        let participant_context = Self::build_participant_context(flow);
        self.cleanup_tokens(flow, &participant_context).await
    }

    async fn on_started(&self, _tx: &mut Self::Transaction, flow: &DataFlow) -> HandlerResult<()> {
        if let Some(data_address) = flow.data_address.as_ref() {
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

            let token_data = TokenData {
                identifier: flow.id.clone(),
                participant_context: flow.participant_context_id.clone(),
                token: token.to_string(),
                refresh_token: refresh_token.to_string(),
                expires_at,
                refresh_endpoint: refresh_endpoint.to_string(),
                endpoint: data_address.endpoint.to_string(),
            };

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
