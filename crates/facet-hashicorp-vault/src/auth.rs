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

use async_trait::async_trait;
use bon::Builder;
use dsdk_facet_core::vault::VaultError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

/// Trait for abstracting Vault authentication mechanisms.
#[async_trait]
pub trait VaultAuthClient: Send + Sync {
    /// Authenticates with Vault and returns the client token and lease duration.
    ///
    /// # Returns
    /// - `Ok((token, lease_duration))` - The Vault client token and its lease duration in seconds
    /// - `Err(VaultError)` - If authentication fails at any stage
    async fn authenticate(&self) -> Result<(String, u64), VaultError>;
}

/// Implementation that obtains a JWT access token from the OAuth2 token endpoint using client credentials flow and
/// uses it to authenticate with Vault.
#[derive(Builder)]
pub struct JwtVaultAuthClient {
    http_client: Client,
    #[builder(into)]
    vault_url: String,
    #[builder(into)]
    client_id: String,
    #[builder(into)]
    client_secret: String,
    #[builder(into)]
    token_url: String,
    #[builder(into)]
    role: String,
}

#[async_trait]
impl VaultAuthClient for JwtVaultAuthClient {
    async fn authenticate(&self) -> Result<(String, u64), VaultError> {
        let jwt =
            get_vault_access_token(&self.http_client, &self.client_id, &self.client_secret, &self.token_url).await?;

        jwt_login(&self.http_client, &self.vault_url, &jwt, &self.role).await
    }
}

/// Obtains a JWT access token from the OAuth2 token endpoint using client credentials flow.
pub(crate) async fn get_vault_access_token(
    client: &Client,
    client_id: &str,
    client_secret: &str,
    token_url: &str,
) -> Result<String, VaultError> {
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("grant_type", "client_credentials"),
    ];

    let response = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| VaultError::NetworkError(format!("Failed to request access token: {}", e)))?;

    if !response.status().is_success() {
        return Err(handle_error_response(response, "Token request failed").await);
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| VaultError::InvalidData(format!("Failed to parse token response: {}", e)))?;

    if token_response.access_token.is_empty() {
        return Err(VaultError::AuthenticationError(
            "Access token not found in response".to_string(),
        ));
    }

    Ok(token_response.access_token)
}

/// Authenticates with Vault using JWT and returns the client token and lease duration.
pub(crate) async fn jwt_login(
    client: &Client,
    vault_url: &str,
    jwt: &str,
    role: &str,
) -> Result<(String, u64), VaultError> {
    let url = format!("{}/v1/auth/jwt/login", vault_url);
    let request = JwtLoginRequest {
        jwt: jwt.to_string(),
        role: role.to_string(),
    };

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| VaultError::NetworkError(format!("Failed to authenticate with JWT: {}", e)))?;

    if !response.status().is_success() {
        return Err(handle_error_response(response, "JWT login failed").await);
    }

    let login_response: JwtLoginResponse = response
        .json()
        .await
        .map_err(|e| VaultError::InvalidData(format!("Failed to parse JWT login response: {}", e)))?;

    Ok((login_response.auth.client_token, login_response.auth.lease_duration))
}

/// Helper to extract error details from an HTTP response.
pub(crate) async fn handle_error_response(response: reqwest::Response, context: &str) -> VaultError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let message = format!("{} with status {}: {}", context, status, body);

    match status.as_u16() {
        400 => VaultError::InvalidData(message),
        401 => VaultError::AuthenticationError(message),
        403 => VaultError::PermissionDenied(message),
        404 => VaultError::InvalidData(message),
        429 => VaultError::NetworkError(message),
        500..=599 => VaultError::NetworkError(message),
        _ => VaultError::NetworkError(message),
    }
}

/// OAuth2 token response structure
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Vault JWT login request
#[derive(Debug, Serialize)]
struct JwtLoginRequest {
    jwt: String,
    role: String,
}

/// Vault JWT login response
#[derive(Debug, Deserialize)]
struct JwtLoginResponse {
    auth: AuthInfo,
}

#[derive(Debug, Deserialize)]
struct AuthInfo {
    client_token: String,
    lease_duration: u64,
}

/// Implementation that reads a Vault token from a file.
/// This is designed for Kubernetes service account authentication where a Vault agent sidecar
/// writes the token to a shared volume.
#[derive(Builder)]
pub struct FileBasedVaultAuthClient {
    #[builder(into)]
    token_file_path: PathBuf,
    /// Estimated TTL for the token in seconds. Since we read an existing token,
    /// we don't know the actual TTL. This value is used for renewal scheduling.
    /// Default is 3600 seconds (1 hour).
    #[builder(default = 3600)]
    estimated_ttl: u64,
}

#[async_trait]
impl VaultAuthClient for FileBasedVaultAuthClient {
    async fn authenticate(&self) -> Result<(String, u64), VaultError> {
        // Check if file exists
        if !self.token_file_path.exists() {
            return Err(VaultError::TokenFileNotFound(
                format!("Token file not found at path: {}", self.token_file_path.display())
            ));
        }

        // Read the token from file
        let token = fs::read_to_string(&self.token_file_path)
            .await
            .map_err(|e| VaultError::TokenFileReadError(
                format!("Failed to read token file {}: {}", self.token_file_path.display(), e)
            ))?;

        // Trim whitespace and validate
        let token = token.trim();
        if token.is_empty() {
            return Err(VaultError::InvalidTokenFormat(
                "Token file is empty".to_string()
            ));
        }

        // Return token and estimated TTL
        Ok((token.to_string(), self.estimated_ttl))
    }
}
