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
use super::ManagementApiHandler;
use crate::server::auth::{AuthError, AuthLayer, KeyProvider, NoParticipantContext};
use crate::transfer_type::{MemoryTransferTypeMappingStore, TransferTypeMappingRepository};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dsdk_facet_core::jwt::{MemorySigningKeyMappingStore, SigningKeyMapping, SigningKeyMappingRepository};
use jsonwebtoken::jwk::JwkSet;
use std::sync::Arc;
use tower::ServiceExt;

fn empty_transfer_type_repo() -> Arc<dyn TransferTypeMappingRepository> {
    Arc::new(MemoryTransferTypeMappingStore::new())
}

fn router_with(repo: Arc<dyn SigningKeyMappingRepository>) -> Router {
    ManagementApiHandler::builder()
        .repo(repo)
        .transfer_type_repo(empty_transfer_type_repo())
        .build()
        .router(AuthLayer::Disabled, AuthLayer::Disabled)
}

fn router_with_transfer_type_repo(repo: Arc<dyn TransferTypeMappingRepository>) -> Router {
    ManagementApiHandler::builder()
        .repo(Arc::new(MemorySigningKeyMappingStore::new()))
        .transfer_type_repo(repo)
        .build()
        .router(AuthLayer::Disabled, AuthLayer::Disabled)
}

/// A `KeyProvider` with no keys. Used to build an enabled `AuthLayer` for the wiring tests below:
/// requests without an `Authorization` header are rejected before the JWKS is ever consulted, so
/// the empty set is enough to prove which routes a layer guards.
struct EmptyKeyProvider;

#[async_trait]
impl KeyProvider for EmptyKeyProvider {
    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        Ok(JwkSet { keys: vec![] })
    }
}

/// An enabled, token-requiring `AuthLayer` that rejects every unauthenticated request.
fn enabled_auth(scope: &str) -> AuthLayer {
    AuthLayer::enabled_with_provider_and_policy(
        Box::new(EmptyKeyProvider),
        "siglet",
        scope,
        NoParticipantContext::RequireToken,
    )
}

fn handler(repo: Arc<dyn SigningKeyMappingRepository>) -> ManagementApiHandler {
    ManagementApiHandler::builder()
        .repo(repo)
        .transfer_type_repo(empty_transfer_type_repo())
        .build()
}

fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn test_create_then_get() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = router_with(repo);

    let create = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/key-mappings",
            serde_json::json!({
                "participantContextId": "pc-1",
                "keyName": "client-signing-pc-1",
                "kid": "client-signing-pc-1-3"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let json = body_json(get).await;
    assert_eq!(json["keyName"], "client-signing-pc-1");
    assert_eq!(json["kid"], "client-signing-pc-1-3");
}

#[tokio::test]
async fn test_put_updates_with_path_id() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    repo.create(
        SigningKeyMapping::builder()
            .participant_context_id("pc-9")
            .key_name("key-old")
            .kid("kid-old")
            .build(),
    )
    .await
    .unwrap();
    let app = router_with(repo.clone());

    let put = app
        .oneshot(json_request(
            "PUT",
            "/key-mappings/pc-9",
            serde_json::json!({ "keyName": "key-9", "kid": "kid-9" }),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::NO_CONTENT);

    let stored = repo.find("pc-9").await.unwrap();
    assert_eq!(stored.key_name, "key-9");
    assert_eq!(stored.kid, "kid-9");
}

#[tokio::test]
async fn test_put_missing_returns_404() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = router_with(repo);

    let put = app
        .oneshot(json_request(
            "PUT",
            "/key-mappings/missing",
            serde_json::json!({ "keyName": "key-9", "kid": "kid-9" }),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_post_duplicate_returns_409() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = router_with(repo);

    let body = serde_json::json!({
        "participantContextId": "pc-1",
        "keyName": "key-1",
        "kid": "kid-1"
    });

    let first = app
        .clone()
        .oneshot(json_request("POST", "/key-mappings", body.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app.oneshot(json_request("POST", "/key-mappings", body)).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_missing_returns_404() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = router_with(repo);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/key-mappings/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_then_404() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    repo.create(
        SigningKeyMapping::builder()
            .participant_context_id("pc-1")
            .key_name("key-1")
            .kid("kid-1")
            .build(),
    )
    .await
    .unwrap();
    let app = router_with(repo);

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_missing_returns_404() {
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = router_with(repo);

    let delete = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/key-mappings/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_write_routes_require_write_layer() {
    // Read is open (Disabled); write is guarded by an enabled layer that rejects unauthenticated
    // requests. Proves POST/PUT/DELETE are bound to the write layer while GET is not.
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    repo.create(
        SigningKeyMapping::builder()
            .participant_context_id("pc-1")
            .key_name("key-1")
            .kid("kid-1")
            .build(),
    )
    .await
    .unwrap();
    let app = handler(repo).router(AuthLayer::Disabled, enabled_auth("siglet-mgmt-api:write"));

    // GET (read) is allowed through.
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);

    // Writes without a token are rejected by the write layer.
    let post = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/key-mappings",
            serde_json::json!({ "participantContextId": "pc-2", "keyName": "k", "kid": "kid" }),
        ))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::UNAUTHORIZED);

    let put = app
        .clone()
        .oneshot(json_request(
            "PUT",
            "/key-mappings/pc-1",
            serde_json::json!({ "keyName": "k", "kid": "kid" }),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::UNAUTHORIZED);

    let delete = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_read_routes_require_read_layer() {
    // Read is guarded; write is open. Proves GET is bound to the read layer while POST is not.
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = handler(repo).router(enabled_auth("siglet-mgmt-api:read"), AuthLayer::Disabled);

    // GET without a token is rejected by the read layer.
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/key-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::UNAUTHORIZED);

    // POST (write) is allowed through.
    let post = app
        .oneshot(json_request(
            "POST",
            "/key-mappings",
            serde_json::json!({ "participantContextId": "pc-1", "keyName": "k", "kid": "kid" }),
        ))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_unmatched_path_returns_404_not_auth() {
    // Both groups guarded by enabled, rejecting layers. Requests to paths that match no route must
    // fall through to 404 rather than being rejected (401) by the auth layer — i.e. auth is applied
    // with `route_layer`, not `layer`.
    let repo = Arc::new(MemorySigningKeyMappingStore::new());
    let app = handler(repo).router(
        enabled_auth("siglet-mgmt-api:read"),
        enabled_auth("siglet-mgmt-api:write"),
    );

    // Base path: no route, no token.
    let root = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(root.status(), StatusCode::NOT_FOUND);

    // Another unmatched path, with a write method, still 404 (not 401).
    let nope = app
        .oneshot(json_request("POST", "/nope", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(nope.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Transfer-type mapping routes
// ---------------------------------------------------------------------------

fn transfer_type_body() -> serde_json::Value {
    // Canonical wire format is camelCase for both the wrapper (`TransferTypeMapping`) and the inner
    // `TransferType`. (snake_case is also accepted on input via serde aliases for config parity.)
    serde_json::json!({
        "participantContextId": "pc-1",
        "mappings": {
            "http-pull": {
                "transferType": "http-pull",
                "endpointType": "HTTP",
                "endpoint": "http://provider:8080/data",
                "tokenSource": "provider"
            }
        }
    })
}

#[tokio::test]
async fn test_transfer_type_create_then_get() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo);

    let create = app
        .clone()
        .oneshot(json_request("POST", "/transfer-type-mappings", transfer_type_body()))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/transfer-type-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let json = body_json(get).await;
    assert_eq!(json["participantContextId"], "pc-1");
    assert_eq!(json["mappings"]["http-pull"]["endpoint"], "http://provider:8080/data");
    assert_eq!(json["mappings"]["http-pull"]["tokenSource"], "provider");
}

#[tokio::test]
async fn test_transfer_type_post_duplicate_returns_409() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo);

    let first = app
        .clone()
        .oneshot(json_request("POST", "/transfer-type-mappings", transfer_type_body()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app
        .oneshot(json_request("POST", "/transfer-type-mappings", transfer_type_body()))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_transfer_type_put_replaces_map() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo.clone());

    app.clone()
        .oneshot(json_request("POST", "/transfer-type-mappings", transfer_type_body()))
        .await
        .unwrap();

    let put_body = serde_json::json!({
        "http-push": {
            "transferType": "http-push",
            "endpointType": "HTTP",
            "endpoint": "http://provider:8080/push",
            "tokenSource": "client"
        }
    });
    let put = app
        .oneshot(json_request("PUT", "/transfer-type-mappings/pc-1", put_body))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::NO_CONTENT);

    let stored = repo.find("pc-1").await.unwrap();
    assert_eq!(stored.mappings.len(), 1);
    assert!(stored.mappings.contains_key("http-push"));
}

#[tokio::test]
async fn test_transfer_type_put_missing_returns_404() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo);

    let put = app
        .oneshot(json_request(
            "PUT",
            "/transfer-type-mappings/missing",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_transfer_type_get_missing_returns_404() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/transfer-type-mappings/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_transfer_type_delete_then_404() {
    let repo = Arc::new(MemoryTransferTypeMappingStore::new());
    let app = router_with_transfer_type_repo(repo);

    app.clone()
        .oneshot(json_request("POST", "/transfer-type-mappings", transfer_type_body()))
        .await
        .unwrap();

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/transfer-type-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let get = app
        .oneshot(
            Request::builder()
                .uri("/transfer-type-mappings/pc-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}
