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

//! Signaling-API JWKS fixture.
//!
//! Stands up an nginx web server in the cluster that serves a JWKS document at
//! [`SIGNALING_JWKS_URL`], and hands the test the matching Ed25519 private key so
//! it can mint signaling-API bearer tokens.
//!
//! With `signaling_auth.mode = "enabled"`, siglet's `HttpKeyProvider` fetches this
//! JWKS over HTTP and verifies every incoming signaling JWT against it (matching
//! `kid` → JWKS key, `aud` == configured audience, `sub` == participant context,
//! and `scope` granting `dplane-signaling`).
//!
//! The keypair is derived from a fixed seed so every nextest test *process*
//! produces the identical key. The JWKS served by the cluster therefore always
//! matches the tokens any process mints, with no cross-process coordination — the
//! same trick `generate_ed25519_keypair_der_from_seed` was built for.

use crate::utils::*;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dsdk_facet_core::jwt::test_fixtures::generate_ed25519_keypair_der_from_seed;
use dsdk_facet_core::jwt::{Jwk, JwkKeyType, JwkPublicKeyUse, JwkSet};
use tokio::sync::OnceCell;

static SIGNALING_JWKS: OnceCell<SignalingJwksDeployment> = OnceCell::const_new();

/// Fixed 32-byte seed for the signaling-API signing key. Stable across processes
/// so concurrent nextest test processes derive the same keypair — and thus serve
/// and expect the same JWKS — without coordinating.
const SIGNING_KEY_SEED: [u8; 32] = [0x5a; 32];

/// `kid` advertised in the JWKS and stamped on minted tokens. Must match between
/// the served JWKS and the JWT header for key lookup to succeed.
pub const SIGNALING_KID: &str = "siglet-signaling-e2e-1";

/// In-cluster URL of the JWKS endpoint, mirrored by `signaling_auth.jwks_url` in
/// `manifests/siglet-config.yaml`.
pub const SIGNALING_JWKS_URL: &str = "http://signaling-jwks/.well-known/jwks.json";

/// Key material and metadata for the signaling-API JWKS server.
pub struct SignalingJwksDeployment {
    /// PKCS#8 DER-encoded Ed25519 private key used to sign signaling-API tokens.
    pub private_key_der: Vec<u8>,
    /// The `kid` advertised in the JWKS and stamped on minted tokens.
    pub kid: String,
}

/// Deploys the signaling-API JWKS web server and returns the signing key.
///
/// Idempotent and thread-safe. The JWKS ConfigMap is written *before* the nginx
/// Deployment is applied (subPath mounts don't hot-reload), and the keypair is
/// deterministic, so concurrent callers converge on identical cluster state.
pub async fn ensure_signaling_jwks() -> Result<&'static SignalingJwksDeployment> {
    SIGNALING_JWKS
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            let keypair = generate_ed25519_keypair_der_from_seed(&SIGNING_KEY_SEED)
                .context("Failed to derive signaling-API Ed25519 keypair")?;

            // RFC 7517 / RFC 8037 OKP JWK for the Ed25519 public key. This shape is
            // what jsonwebtoken's `DecodingKey::from_jwk` expects on the siglet side.
            let jwk = Jwk::builder()
                .kty(JwkKeyType::Okp)
                .crv("Ed25519")
                .x(URL_SAFE_NO_PAD.encode(&keypair.public_key))
                .kid(SIGNALING_KID)
                .alg("EdDSA")
                .key_use(JwkPublicKeyUse::Sig)
                .build();
            let jwk_set = JwkSet { keys: vec![jwk] };
            let jwks_json = serde_json::to_string(&jwk_set).context("Failed to serialize JWKS document")?;

            // ConfigMap first, then Deployment — see module docs on subPath mounts.
            apply_jwks_configmap(&jwks_json)?;

            kubectl_apply_server_side("manifests/signaling-jwks.yaml")
                .context("Failed to apply signaling-jwks.yaml")?;

            wait_for_rollout_complete(E2E_NAMESPACE, "signaling-jwks", 120).await?;

            println!(
                "Signaling JWKS server ready: {} (kid={})",
                SIGNALING_JWKS_URL, SIGNALING_KID
            );

            Ok(SignalingJwksDeployment {
                private_key_der: keypair.private_key,
                kid: SIGNALING_KID.to_string(),
            })
        })
        .await
}

/// Server-side applies the `signaling-jwks` ConfigMap carrying `jwks.json`.
///
/// The manifest is built with serde so the embedded JSON string is escaped
/// correctly regardless of its contents.
fn apply_jwks_configmap(jwks_json: &str) -> Result<()> {
    let manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "signaling-jwks",
            "namespace": E2E_NAMESPACE,
        },
        "data": {
            "jwks.json": jwks_json,
        },
    });
    kubectl_apply_server_side_stdin(&manifest.to_string()).context("Failed to apply signaling-jwks ConfigMap")
}
