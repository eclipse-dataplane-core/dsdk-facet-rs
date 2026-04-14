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

//! E2E tests for Siglet DataFlow handler
//!
//! These tests deploy Siglet in a Kind cluster and verify its DataFlow
//! handling capabilities, including signaling API interactions and health endpoints.
//!
//! Note: These tests share a single Siglet deployment and can run in parallel.

use crate::fixtures::consumer_did::ensure_consumer_did;
use crate::fixtures::siglet::{SigletDeployment, ensure_siglet_deployed};
use crate::fixtures::vault::ensure_vault_client;
use crate::utils::*;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwkSet, VaultJwtGenerator};
use dsdk_facet_core::token::client::TokenClient;
use dsdk_facet_core::token::client::oauth::OAuth2TokenClient;
use dsdk_facet_core::vault::VaultSigningClient;
use jsonwebtoken::Algorithm;
use reqwest::Client;
use std::sync::Arc;
use uuid::Uuid;

/// Test that Siglet deploys successfully and responds to health checks
#[tokio::test]
#[ignore]
async fn test_siglet_deployment_and_health() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    let pod_name = &deployment.pod_name;

    // Test health endpoint using kubectl exec
    let health_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/health"],
    )?;

    assert!(
        health_response.contains("healthy"),
        "Health endpoint should return healthy status"
    );

    // Test root endpoint
    let root_response = kubectl_exec(
        E2E_NAMESPACE,
        pod_name,
        "siglet",
        &["wget", "-q", "-O-", "http://localhost:8080/"],
    )?;

    assert!(
        root_response.contains("Siglet"),
        "Root endpoint should return Siglet metadata"
    );
    assert!(root_response.contains("version"), "Root endpoint should return version");
    assert!(
        root_response.contains("running"),
        "Root endpoint should indicate running status"
    );

    let logs = get_pod_logs(E2E_NAMESPACE, pod_name, "siglet")?;

    assert!(logs.contains("Siglet API"), "Logs should indicate Siglet API started");
    assert!(
        logs.contains("Signaling API"),
        "Logs should indicate Signaling API started"
    );
    assert!(logs.contains("Refresh API"), "Logs should indicate Refresh API started");
    assert!(logs.contains("Ready"), "Logs should indicate Siglet is ready");

    Ok(())
}

/// Test consumer-provider pull interactions
#[tokio::test]
#[ignore]
async fn test_pull_operations() -> Result<()> {
    let deployment = ensure_siglet_deployed().await?;
    ensure_consumer_did().await?;

    // Use unique IDs per run so retries don't collide with flows left in Siglet
    // state from a prior attempt.
    let run_id = Uuid::new_v4().to_string();
    let ctx = TestCtx::new(&deployment, &run_id);

    preflight_verify_did(&ctx).await?;
    step_prepare(&ctx).await?;
    let start_out = step_start(&ctx).await?;
    step_started(&ctx, &start_out.data_address).await?;
    let api_token = retrieve_and_verify_token(&ctx).await?;
    verify_jwks_signature(&ctx, &start_out.token).await?;
    let refresh_out = do_refresh(&ctx, &api_token, &start_out.refresh_token).await?;
    check_token_rotation(&ctx, &api_token, &refresh_out.new_access_token).await?;
    step_terminate(&ctx).await?;

    Ok(())
}

/// Immutable setup shared across all steps of the pull transfer test sequence.
struct TestCtx {
    client: Client,
    signaling_url: String,
    verify_url: String,
    siglet_api_port: u16,
    refresh_api_port: u16,
    run_id: String,
    dataset_id: String,
    agreement_id: String,
    consumer_flow_id: String,
    provider_flow_id: String,
    consumer_participant_context_id: String,
    provider_participant_context_id: String,
    pod_name: String,
}

impl TestCtx {
    fn new(deployment: &SigletDeployment, run_id: &str) -> Self {
        TestCtx {
            client: Client::new(),
            signaling_url: format!("http://localhost:{}", deployment.signaling_port),
            verify_url: format!("http://localhost:{}/tokens/verify", deployment.siglet_api_port),
            siglet_api_port: deployment.siglet_api_port,
            refresh_api_port: deployment.refresh_api_port,
            run_id: run_id.to_string(),
            dataset_id: format!("dataset-{}", run_id),
            agreement_id: format!("agreement-{}", run_id),
            consumer_flow_id: format!("consumer-flow-{}", run_id),
            provider_flow_id: format!("provider-flow-{}", run_id),
            consumer_participant_context_id: format!("consumer-participant-{}", run_id),
            provider_participant_context_id: format!("provider-participant-{}", run_id),
            pod_name: deployment.pod_name.clone(),
        }
    }
}

/// Data returned by `step_start` that subsequent steps depend on.
struct StartOutput {
    /// Raw JWT access token issued by Siglet.
    token: String,
    /// Full `dataAddress` value from the start response, forwarded to the started step.
    data_address: serde_json::Value,
    /// Opaque refresh token from `endpointProperties`.
    refresh_token: String,
}

/// Data returned by `do_refresh`.
struct RefreshOutput {
    new_access_token: String,
}

// ---------------------------------------------------------------------------
// Step functions
// ---------------------------------------------------------------------------

/// Pre-flight: verify that the DID document served by the consumer-did pod
/// contains the expected public key. A mismatch causes an opaque "Invalid token
/// signature" at the refresh step, so we fail fast with a clear message here.
async fn preflight_verify_did(ctx: &TestCtx) -> Result<()> {
    let consumer_did = ensure_consumer_did().await?;

    let did_doc_raw = kubectl_exec(
        E2E_NAMESPACE,
        &ctx.pod_name,
        "siglet",
        &["sh", "-c", "wget -q -O- http://consumer/.well-known/did.json"],
    )
    .context("Failed to fetch consumer DID document from inside siglet pod")?;

    let did_doc: serde_json::Value =
        serde_json::from_str(&did_doc_raw).context("Failed to parse consumer DID document")?;

    // Find the verification method matching the per-PC transit signing key.
    let expected_fragment = &consumer_did.pc_signing_key_id;
    let vms = did_doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .context("No verificationMethod array in DID document")?;

    let vm = vms
        .iter()
        .find(|vm| {
            vm.get("id")
                .and_then(|id| id.as_str())
                .map(|id| id.ends_with(&format!("#{}", expected_fragment)))
                .unwrap_or(false)
        })
        .with_context(|| {
            format!(
                "Verification method '{}' not found in DID document. \
                 Re-run 'cd e2e && ./scripts/setup.sh' to reprovision.",
                expected_fragment
            )
        })?;

    let served_multibase = vm
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        .context("No publicKeyMultibase in verification method")?;

    assert_eq!(
        served_multibase, consumer_did.pc_signing_key_multibase,
        "DID document public key mismatch for '{}'.\n\
         Served:   {}\n\
         Expected: {}\n\
         Re-run 'cd e2e && ./scripts/setup.sh' to reprovision the consumer DID server.",
        expected_fragment, served_multibase, consumer_did.pc_signing_key_multibase
    );
    println!("DID document key verified: {}", &served_multibase[..20]);
    Ok(())
}

/// Step 1: Consumer calls the prepare endpoint. For a pull transfer no data address is returned.
async fn step_prepare(ctx: &TestCtx) -> Result<()> {
    let message = serde_json::json!({
        "datasetId": ctx.dataset_id,
        "participantId": "did:web:consumer",
        "processId": ctx.consumer_flow_id,
        "agreementId": ctx.agreement_id,
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://consumer.example.com/callback",
        "messageId": format!("msg-prepare-{}", ctx.run_id),
        "counterPartyId": "did:web:provider",
        "labels": [],
        "metadata": {},
    });

    let response = ctx
        .client
        .post(format!(
            "{}/api/v1/{}/dataflows/prepare",
            ctx.signaling_url, ctx.consumer_participant_context_id
        ))
        .header("Content-Type", "application/json")
        .json(&message)
        .send()
        .await
        .context("Failed to send prepare request")?;

    assert!(
        response.status().is_success(),
        "Prepare request should succeed, got status: {}",
        response.status()
    );

    let result: serde_json::Value = response.json().await.context("Failed to parse prepare response")?;

    if let Some(data_address) = result.get("dataAddress") {
        assert!(
            data_address.is_null(),
            "Prepare response should not contain a dataAddress for pull transfers, got: {}",
            data_address
        );
    }
    Ok(())
}

/// Step 2: Provider calls the start endpoint. Returns the issued tokens and
/// data address for use in later steps.
async fn step_start(ctx: &TestCtx) -> Result<StartOutput> {
    let message = serde_json::json!({
        "datasetId": ctx.dataset_id,
        "participantId": "did:web:provider",
        "processId": ctx.provider_flow_id,
        "agreementId": ctx.agreement_id,
        "transferType": "http-pull",
        "dataspaceContext": "test-dataspace",
        "callbackAddress": "https://provider.example.com/callback",
        "messageId": format!("msg-start-{}", ctx.run_id),
        "counterPartyId": "did:web:consumer",
        "labels": [],
        "metadata": {
            "claim1": "claimvalue1",
            "claim2": "claimvalue2"
        }
    });

    let response = ctx
        .client
        .post(format!(
            "{}/api/v1/{}/dataflows/start",
            ctx.signaling_url, ctx.provider_participant_context_id
        ))
        .header("Content-Type", "application/json")
        .json(&message)
        .send()
        .await
        .context("Failed to send start request")?;

    assert!(
        response.status().is_success(),
        "Start request should succeed, got status: {}",
        response.status()
    );

    let result: serde_json::Value = response.json().await.context("Failed to parse start response")?;

    assert!(result.get("state").is_some(), "Response should contain 'state' field");
    assert!(
        result.get("dataplaneId").is_some(),
        "Response should contain 'dataplaneId' field"
    );
    assert_eq!(
        result["state"].as_str().unwrap(),
        "STARTED",
        "DataFlow should be in STARTED state"
    );

    let data_address = result
        .get("dataAddress")
        .context("Response should contain 'dataAddress'")?
        .clone();

    // Inspect endpoint properties within a block so the borrow on data_address
    // ends before data_address is moved into the return value.
    let (token, refresh_token) = {
        let properties = data_address["endpointProperties"]
            .as_array()
            .context("endpointProperties should be an array")?;

        let get_prop = |name: &str| -> Option<&str> {
            properties
                .iter()
                .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
                .and_then(|p| p.get("value"))
                .and_then(|v| v.as_str())
        };

        let token = get_prop("authorization")
            .filter(|s| !s.is_empty())
            .context("Authorization property not found or empty in data address")?;

        // Decode the JWT payload and verify the provider's custom claims are present.
        let token_parts: Vec<&str> = token.split('.').collect();
        assert_eq!(
            token_parts.len(),
            3,
            "JWT should have 3 parts (header.payload.signature)"
        );
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(token_parts[1])
            .context("Failed to decode JWT payload")?;
        let jwt_payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).context("Failed to parse JWT payload as JSON")?;
        assert_eq!(
            jwt_payload.get("claim1").and_then(|v| v.as_str()),
            Some("claimvalue1"),
            "claim1 should be present in JWT with correct value"
        );
        assert_eq!(
            jwt_payload.get("claim2").and_then(|v| v.as_str()),
            Some("claimvalue2"),
            "claim2 should be present in JWT with correct value"
        );

        let refresh_token = get_prop("refreshToken").context("Refresh token not found in data address")?;
        assert!(
            get_prop("refreshEndpoint").is_some(),
            "Refresh endpoint not found in data address"
        );

        (token.to_string(), refresh_token.to_string())
    };

    Ok(StartOutput {
        token,
        data_address,
        refresh_token,
    })
}

/// Step 3: Consumer calls the started endpoint, forwarding the provider's data address.
async fn step_started(ctx: &TestCtx, data_address: &serde_json::Value) -> Result<()> {
    let message = serde_json::json!({
        "participantId": "did:web:consumer",
        "counterPartyId": "did:web:provider",
        "dataAddress": data_address,
        "messageId": format!("msg-started-{}", ctx.run_id)
    });

    let response = ctx
        .client
        .post(format!(
            "{}/api/v1/{}/dataflows/{}/started",
            ctx.signaling_url, ctx.consumer_participant_context_id, ctx.consumer_flow_id
        ))
        .header("Content-Type", "application/json")
        .json(&message)
        .send()
        .await
        .context("Failed to send started request")?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error body".to_string());
        anyhow::bail!("Started request should succeed, got status: {}, body: {}", status, body);
    }
    Ok(())
}

/// Steps 4–5: Retrieve the access token stored for the consumer flow from the
/// token API, then verify it via the verify endpoint. Returns the raw token
/// string for use in subsequent steps.
async fn retrieve_and_verify_token(ctx: &TestCtx) -> Result<String> {
    let get_token_url = format!(
        "http://localhost:{}/tokens/{}/{}",
        ctx.siglet_api_port, ctx.consumer_participant_context_id, ctx.consumer_flow_id
    );
    let get_response = ctx
        .client
        .get(&get_token_url)
        .send()
        .await
        .context("Failed to retrieve token from token API")?;

    if !get_response.status().is_success() {
        let status = get_response.status();
        let body = get_response.text().await.unwrap_or_default();
        anyhow::bail!("Token retrieval returned HTTP {}: {}", status, body);
    }

    let get_result: serde_json::Value = get_response
        .json()
        .await
        .context("Failed to parse token retrieval response")?;

    let api_token = get_result
        .get("token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .with_context(|| format!("Retrieved token should not be empty, got: {}", get_result))?
        .to_string();

    let verify_response = ctx
        .client
        .post(&ctx.verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": api_token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("Token verification request failed")?;

    if !verify_response.status().is_success() {
        let status = verify_response.status();
        let body = verify_response.text().await.unwrap_or_default();
        anyhow::bail!("Token verification returned HTTP {}: {}", status, body);
    }

    let verify_result: serde_json::Value = verify_response
        .json()
        .await
        .context("Failed to parse token verification response")?;

    assert!(
        verify_result.get("sub").is_some(),
        "Verified token claims should contain 'sub' field, got: {}",
        verify_result
    );

    Ok(api_token)
}

/// Step 6: Fetch Siglet's JWKS and use it to verify the JWT signature of the
/// access token. This confirms the token is signed with the key Siglet advertises.
async fn verify_jwks_signature(ctx: &TestCtx, token: &str) -> Result<()> {
    let jwks_url = format!("http://localhost:{}/keys", ctx.siglet_api_port);
    let jwks_response = ctx
        .client
        .get(&jwks_url)
        .send()
        .await
        .context("Failed to fetch JWKS from /keys endpoint")?;

    assert!(
        jwks_response.status().is_success(),
        "JWKS endpoint should return 200 OK, got: {}",
        jwks_response.status()
    );

    let jwks: JwkSet = jwks_response.json().await.context("Failed to parse JWKS response")?;
    assert!(!jwks.keys.is_empty(), "JWKS should contain at least one key");

    let header = jsonwebtoken::decode_header(token).context("Failed to decode JWT header")?;
    let kid = header.kid.as_deref().unwrap_or("");
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .with_context(|| format!("No key with kid '{}' found in JWKS", kid))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(jwk.x.as_deref().context("JWKS key missing 'x' parameter")?)
        .context("Failed to base64url-decode JWKS key 'x' parameter")?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ed_der(&x_bytes);
    let mut validation = jsonwebtoken::Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.set_audience(&["did:web:provider"]);
    validation.required_spec_claims = std::collections::HashSet::new();

    jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .context("JWT signature verification failed using public key from JWKS endpoint")?;

    Ok(())
}

/// Step 7: Consumer refreshes the access token via the Refresh API.
///
/// consumer's per-PC Vault transit key (`client-signing-test-participant-context`).
/// This exercises the same production code path that Siglet uses internally.
async fn do_refresh(ctx: &TestCtx, api_token: &str, refresh_token: &str) -> Result<RefreshOutput> {
    let vault = ensure_vault_client().await?;

    let client_jwt_generator = Arc::new(
        VaultJwtGenerator::builder()
            .signing_client(vault.vault_client.clone() as Arc<dyn VaultSigningClient>)
            .key_name_prefix("client-signing")
            .build(),
    );

    let oauth_client = OAuth2TokenClient::builder().jwt_generator(client_jwt_generator).build();

    // PC id drives the transit key lookup: key = "client-signing-{pc.id}"
    // PC identifier becomes iss/sub in the proof JWT; must match the DID document issuer.
    let consumer_ctx = ParticipantContext::builder()
        .id("test-participant-context")
        .identifier("did:web:consumer")
        .build();

    let refresh_url = format!("http://localhost:{}/token/refresh", ctx.refresh_api_port);
    let result = oauth_client
        .refresh_token(
            &consumer_ctx,
            "did:web:provider", // endpoint_identifier → aud claim in proof JWT
            api_token,
            refresh_token,
            &refresh_url,
        )
        .await
        .context("Token refresh via OAuth2TokenClient failed")?;

    assert!(!result.token.is_empty(), "Refreshed access token should not be empty");
    assert!(
        !result.refresh_token.is_empty(),
        "New refresh token should not be empty"
    );

    Ok(RefreshOutput {
        new_access_token: result.token,
    })
}

/// Steps 8–9: Verify that the old access token is rejected after rotation and
/// that the new token is accepted.
async fn check_token_rotation(ctx: &TestCtx, old_token: &str, new_token: &str) -> Result<()> {
    let stale_response = ctx
        .client
        .post(&ctx.verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": old_token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("Stale token verification request failed")?;
    assert_eq!(
        stale_response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Old access token should be rejected after refresh"
    );

    let new_response = ctx
        .client
        .post(&ctx.verify_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "token": new_token, "audience": "did:web:provider" }))
        .send()
        .await
        .context("New token verification request failed")?;
    if !new_response.status().is_success() {
        let status = new_response.status();
        let body = new_response.text().await.unwrap_or_default();
        anyhow::bail!("New access token verification returned HTTP {}: {}", status, body);
    }
    Ok(())
}

/// Step 10: Provider terminates the transfer.
async fn step_terminate(ctx: &TestCtx) -> Result<()> {
    let response = ctx
        .client
        .post(format!(
            "{}/api/v1/{}/dataflows/{}/terminate",
            ctx.signaling_url, ctx.provider_participant_context_id, ctx.provider_flow_id
        ))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "reason": "Test termination" }))
        .send()
        .await
        .context("Failed to send terminate request")?;

    assert!(
        response.status().is_success(),
        "Terminate should return 200 OK for successful termination, got: {}",
        response.status()
    );
    Ok(())
}
