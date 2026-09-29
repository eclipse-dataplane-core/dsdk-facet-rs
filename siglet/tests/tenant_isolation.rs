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

//! Cross-tenant regression suite (see `docs/security-assessment-siglet.md`).
//!
//! Every test authenticates as one participant context (`tenant-a`) with a valid, correctly scoped
//! JWT and tries to reach another participant context's (`tenant-b`) data through the signaling
//! and token APIs, wired as in production: the enabled auth layer in front of the real routers.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use dataplane_sdk::core::db::control_plane::memory::MemoryControlPlaneRepo;
use dataplane_sdk::core::db::data_flow::memory::MemoryDataFlowRepo;
use dataplane_sdk::core::db::memory::{MemoryContext, MemoryTransaction};
use dataplane_sdk::sdk::DataPlaneSdk;
use dataplane_sdk_axum::router::participants_router;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwkSet as FacetJwkSet, TokenClaims};
use dsdk_facet_core::lock::MemoryLockManager;
use dsdk_facet_core::token::TokenError;
use dsdk_facet_core::token::client::{
    MemoryTokenStore, RefreshedTokenData, TokenClient, TokenClientApi, TokenData, TokenStore,
};
use dsdk_facet_core::token::manager::{RenewableTokenPair, TokenManager};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters,
        OctetKeyPairType, PublicKeyUse,
    },
};
use rand::Rng;
use serde_json::{Value, json};
use siglet::config::{TokenSource, TransferType};
use siglet::handler::signaling::SigletDataFlowHandler;
use siglet::handler::token::TokenApiHandler;
use siglet::server::auth::{AuthError, AuthLayer, KeyProvider, NoParticipantContext};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";
const FLOW_ID: &str = "flow-1";
const AUDIENCE: &str = "siglet";
const SIGNALING_SCOPE: &str = "dplane-signaling";
const TOKEN_API_SCOPE: &str = "siglet-token-api";
const TOKEN_API_ADMIN_SCOPE: &str = "siglet-token-api:admin";
const PROFILE: &str = "http-pull";

// ============================================================================
// Identity provider: an Ed25519 key served as a static JWKS
// ============================================================================

struct Idp {
    signing_key: SigningKey,
    jwk_set: JwkSet,
}

impl Idp {
    fn new() -> Self {
        use base64::Engine;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: Some("kid-1".to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x,
            }),
        };
        Self {
            signing_key,
            jwk_set: JwkSet { keys: vec![jwk] },
        }
    }

    /// Issues a token for `sub` carrying `scope`, valid for this siglet's audience.
    fn issue(&self, sub: &str, scope: &str) -> String {
        use base64::Engine;
        // PKCS8 v1 prefix for an Ed25519 private key (RFC 8410), followed by the 32-byte seed.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ];
        der.extend_from_slice(&self.signing_key.to_bytes());
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("kid-1".to_string());
        let now = Utc::now().timestamp();
        let claims = json!({ "sub": sub, "aud": AUDIENCE, "scope": scope, "iat": now, "exp": now + 3600 });
        encode(&header, &claims, &EncodingKey::from_ed_pem(pem.as_bytes()).unwrap()).unwrap()
    }

    fn provider(&self) -> Box<dyn KeyProvider> {
        Box::new(StaticKeyProvider(self.jwk_set.clone()))
    }
}

struct StaticKeyProvider(JwkSet);

#[async_trait]
impl KeyProvider for StaticKeyProvider {
    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        Ok(self.0.clone())
    }
}

// ============================================================================
// Token manager double: records revocations, binds validation to the issuing context
// ============================================================================

/// Records every revocation and remembers which participant context each generated flow token
/// belongs to, so `validate_token` can apply the participant-context binding like the real manager.
#[derive(Default)]
struct RecordingTokenManager {
    revoked: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl TokenManager for RecordingTokenManager {
    async fn generate_pair(
        &self,
        participant_context: &ParticipantContext,
        _subject: &str,
        _claims: HashMap<String, Value>,
        flow_id: String,
    ) -> Result<RenewableTokenPair, TokenError> {
        Ok(RenewableTokenPair::builder()
            .token(format!("{}/{}", participant_context.id, flow_id))
            .refresh_token("refresh".to_string())
            .expires_at(Utc::now() + chrono::TimeDelta::hours(1))
            .refresh_endpoint("https://siglet.example.com/token".to_string())
            .build())
    }

    async fn renew(&self, _bound_token: &str, _refresh_token: &str) -> Result<RenewableTokenPair, TokenError> {
        unimplemented!("not used")
    }

    async fn revoke_token(&self, participant_context: &ParticipantContext, flow_id: &str) -> Result<(), TokenError> {
        self.revoked
            .lock()
            .unwrap()
            .push((participant_context.id.clone(), flow_id.to_string()));
        Ok(())
    }

    /// Tokens have the form `{participant_context_id}/{flow_id}` (see `generate_pair`).
    async fn validate_token(
        &self,
        participant_context_id: Option<&str>,
        audience: &str,
        token: &str,
    ) -> Result<TokenClaims, TokenError> {
        let (owner, _) = token.split_once('/').ok_or(TokenError::Invalid)?;
        if participant_context_id.is_some_and(|pc| pc != owner) {
            return Err(TokenError::NotAuthorized("Token not found".to_string()));
        }
        Ok(TokenClaims::builder()
            .sub(owner)
            .aud(audience)
            .iss("siglet")
            .exp(0)
            .build())
    }

    async fn jwk_set(&self) -> Result<FacetJwkSet, TokenError> {
        unimplemented!("not used")
    }
}

struct NoRefreshTokenClient;

#[async_trait]
impl TokenClient for NoRefreshTokenClient {
    async fn refresh_token(
        &self,
        _participant_context: &ParticipantContext,
        _endpoint_identifier: &str,
        _access_token: &str,
        _refresh_token: &str,
        _refresh_endpoint: &str,
    ) -> Result<RefreshedTokenData, TokenError> {
        unimplemented!("tokens in these tests never expire")
    }
}

// ============================================================================
// Siglet under test
// ============================================================================

struct Siglet {
    idp: Idp,
    signaling: Router,
    token_api: Router,
    token_manager: Arc<RecordingTokenManager>,
    token_store: Arc<MemoryTokenStore>,
}

impl Siglet {
    fn new() -> Self {
        let idp = Idp::new();
        let token_manager = Arc::new(RecordingTokenManager::default());
        let token_store = Arc::new(MemoryTokenStore::new());

        let transfer_types = HashMap::from([(
            PROFILE.to_string(),
            TransferType::builder()
                .transfer_type(PROFILE.to_string())
                .endpoint_type("HTTP".to_string())
                .endpoint("https://provider.example.com/data".to_string())
                .token_source(TokenSource::Provider)
                .build(),
        )]);
        let handler = SigletDataFlowHandler::<MemoryTransaction>::builder()
            .dataplane_id("dataplane-1")
            .token_store(token_store.clone() as Arc<dyn TokenStore>)
            .token_manager(token_manager.clone() as Arc<dyn TokenManager>)
            .transfer_type_mappings(transfer_types)
            .build();
        let sdk = DataPlaneSdk::builder(MemoryContext)
            .with_repo(MemoryDataFlowRepo::default())
            .with_control_plane_repo(MemoryControlPlaneRepo::default())
            .with_handler(handler)
            .build()
            .unwrap();

        let signaling_auth = AuthLayer::enabled_with_provider_and_policy(
            idp.provider(),
            AUDIENCE,
            SIGNALING_SCOPE,
            None,
            NoParticipantContext::RequireToken,
        );
        let signaling = participants_router().layer(signaling_auth).with_state(sdk);

        let token_client_api = Arc::new(
            TokenClientApi::builder()
                .lock_manager(Arc::new(MemoryLockManager::new()))
                .token_store(token_store.clone() as Arc<dyn TokenStore>)
                .token_client(Arc::new(NoRefreshTokenClient))
                .build(),
        );
        let token_api_auth = AuthLayer::enabled_with_provider_and_policy(
            idp.provider(),
            AUDIENCE,
            TOKEN_API_SCOPE,
            Some(TOKEN_API_ADMIN_SCOPE.to_string()),
            NoParticipantContext::RequireToken,
        );
        let token_api = TokenApiHandler::builder()
            .token_client_api(token_client_api)
            .token_manager(token_manager.clone() as Arc<dyn TokenManager>)
            .build()
            .router(token_api_auth);

        Self {
            idp,
            signaling,
            token_api,
            token_manager,
            token_store,
        }
    }

    /// Sends a signaling request as `caller` against the participant context in `path_pc`.
    async fn signal(&self, caller: &str, method: &str, path_pc: &str, suffix: &str, body: Value) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/{}/dataflows{}", path_pc, suffix))
            .header(
                "authorization",
                format!("Bearer {}", self.idp.issue(caller, SIGNALING_SCOPE)),
            )
            .header("content-type", "application/json")
            .body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        self.signaling.clone().oneshot(request).await.unwrap().status()
    }

    async fn start_flow(&self, tenant: &str) -> StatusCode {
        let body = json!({
            "messageId": "msg-1",
            "participantId": format!("did:web:{}", tenant),
            "counterPartyId": "did:web:consumer",
            "dataspaceContext": "ctx",
            "dataFlowId": FLOW_ID,
            "agreementId": "agreement-1",
            "datasetId": "dataset-1",
            "profile": PROFILE,
        });
        self.signal(tenant, "POST", tenant, "/start", body).await
    }

    async fn status(&self, caller: &str, path_pc: &str) -> StatusCode {
        self.signal(caller, "GET", path_pc, &format!("/{}/status", FLOW_ID), Value::Null)
            .await
    }

    async fn token_api(&self, caller_token: &str, method: &str, uri: &str, body: Option<Value>) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", caller_token))
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        self.token_api.clone().oneshot(request).await.unwrap().status()
    }

    fn revoked(&self) -> Vec<(String, String)> {
        self.token_manager.revoked.lock().unwrap().clone()
    }

    async fn store_token(&self, tenant: &str) {
        self.token_store
            .save_token(
                TokenData::builder()
                    .participant_context(tenant)
                    .participant_id(format!("did:web:{}", tenant))
                    .counter_party_id("did:web:provider")
                    .identifier(FLOW_ID)
                    .token(format!("{}-secret-token", tenant))
                    .refresh_token("refresh")
                    .expires_at(Utc::now() + chrono::TimeDelta::hours(1))
                    .refresh_endpoint("https://provider.example.com/token")
                    .endpoint("https://provider.example.com/data")
                    .build(),
            )
            .await
            .unwrap();
    }

    async fn has_token(&self, tenant: &str) -> bool {
        let pc = ParticipantContext::builder().id(tenant).build();
        self.token_store.get_token(&pc, FLOW_ID).await.is_ok()
    }
}

// ============================================================================
// Signaling API
// ============================================================================

#[tokio::test]
async fn token_for_one_context_cannot_address_another_context_path() {
    let siglet = Siglet::new();
    assert_eq!(siglet.start_flow(TENANT_B).await, StatusCode::OK);

    // A's token on B's path is rejected by subject binding.
    assert_eq!(siglet.status(TENANT_A, TENANT_B).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn flow_of_another_context_is_invisible_under_own_path() {
    let siglet = Siglet::new();
    assert_eq!(siglet.start_flow(TENANT_B).await, StatusCode::OK);

    // A authenticates correctly for its own path and names B's flow id.
    assert_eq!(siglet.status(TENANT_A, TENANT_A).await, StatusCode::NOT_FOUND);
    for op in ["terminate", "suspend", "completed"] {
        let status = siglet
            .signal(TENANT_A, "POST", TENANT_A, &format!("/{}/{}", FLOW_ID, op), json!({}))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{op}");
    }
    let started = json!({ "dataAddress": { "endpointType": "HTTP", "endpoint": "https://attacker.example", "endpointProperties": [] } });
    let status = siglet
        .signal(TENANT_A, "POST", TENANT_A, &format!("/{}/started", FLOW_ID), started)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // B's flow and tokens are untouched.
    assert!(siglet.revoked().is_empty());
    assert_eq!(siglet.status(TENANT_B, TENANT_B).await, StatusCode::OK);
}

#[tokio::test]
async fn contexts_can_reuse_a_flow_id_independently() {
    let siglet = Siglet::new();
    assert_eq!(siglet.start_flow(TENANT_B).await, StatusCode::OK);
    assert_eq!(siglet.start_flow(TENANT_A).await, StatusCode::OK);

    let status = siglet
        .signal(
            TENANT_A,
            "POST",
            TENANT_A,
            &format!("/{}/terminate", FLOW_ID),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Only A's tokens were revoked, and B's flow is still live.
    assert_eq!(siglet.revoked(), vec![(TENANT_A.to_string(), FLOW_ID.to_string())]);
    assert_eq!(siglet.status(TENANT_B, TENANT_B).await, StatusCode::OK);
}

// ============================================================================
// Token API
// ============================================================================

#[tokio::test]
async fn token_id_cannot_traverse_into_another_context() {
    let siglet = Siglet::new();
    siglet.store_token(TENANT_B).await;
    let token = siglet.idp.issue(TENANT_A, TOKEN_API_SCOPE);

    for id in ["..%2Ftenant-b%2Fflow-1", "..%2F..%2Ftenant-b%2Fflow-1", "%2E%2E"] {
        let uri = format!("/tokens/{}/{}", TENANT_A, id);
        assert_eq!(
            siglet.token_api(&token, "GET", &uri, None).await,
            StatusCode::BAD_REQUEST,
            "{id}"
        );
        assert_eq!(
            siglet.token_api(&token, "DELETE", &uri, None).await,
            StatusCode::BAD_REQUEST,
            "{id}"
        );
    }

    assert!(siglet.has_token(TENANT_B).await);
}

#[tokio::test]
async fn token_of_another_context_is_not_reachable() {
    let siglet = Siglet::new();
    siglet.store_token(TENANT_B).await;
    let token = siglet.idp.issue(TENANT_A, TOKEN_API_SCOPE);

    // Own path, B's flow id: A has no token under that id.
    let own_path = format!("/tokens/{}/{}", TENANT_A, FLOW_ID);
    assert_eq!(
        siglet.token_api(&token, "GET", &own_path, None).await,
        StatusCode::NOT_FOUND
    );
    // B's path: subject binding.
    let b_path = format!("/tokens/{}/{}", TENANT_B, FLOW_ID);
    assert_eq!(
        siglet.token_api(&token, "GET", &b_path, None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        siglet.token_api(&token, "DELETE", &b_path, None).await,
        StatusCode::FORBIDDEN
    );

    assert!(siglet.has_token(TENANT_B).await);
}

#[tokio::test]
async fn verify_only_validates_tokens_of_the_callers_context() {
    let siglet = Siglet::new();
    let b_issued = format!("{}/{}", TENANT_B, FLOW_ID);
    let body = json!({ "token": b_issued, "audience": "did:web:tenant-b" });

    let a_caller = siglet.idp.issue(TENANT_A, TOKEN_API_SCOPE);
    assert_eq!(
        siglet
            .token_api(&a_caller, "POST", "/tokens/verify", Some(body.clone()))
            .await,
        StatusCode::UNAUTHORIZED
    );

    let b_caller = siglet.idp.issue(TENANT_B, TOKEN_API_SCOPE);
    assert_eq!(
        siglet
            .token_api(&b_caller, "POST", "/tokens/verify", Some(body.clone()))
            .await,
        StatusCode::OK
    );

    let admin = siglet
        .idp
        .issue("operator", &format!("{} {}", TOKEN_API_SCOPE, TOKEN_API_ADMIN_SCOPE));
    assert_eq!(
        siglet.token_api(&admin, "POST", "/tokens/verify", Some(body)).await,
        StatusCode::OK
    );
}
