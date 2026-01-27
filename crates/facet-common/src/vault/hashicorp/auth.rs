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

use crate::vault::VaultError;
use async_trait::async_trait;
use bon::Builder;
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
        .map_err(|e| VaultError::GeneralError(format!("Failed to request access token: {}", e)))?;

    if !response.status().is_success() {
        return Err(handle_error_response(response, "Token request failed").await);
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| VaultError::GeneralError(format!("Failed to parse token response: {}", e)))?;

    if token_response.access_token.is_empty() {
        return Err(VaultError::GeneralError(
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
        .map_err(|e| VaultError::GeneralError(format!("Failed to authenticate with JWT: {}", e)))?;

    if !response.status().is_success() {
        return Err(handle_error_response(response, "JWT login failed").await);
    }

    let login_response: JwtLoginResponse = response
        .json()
        .await
        .map_err(|e| VaultError::GeneralError(format!("Failed to parse JWT login response: {}", e)))?;

    Ok((login_response.auth.client_token, login_response.auth.lease_duration))
}

/// Helper to extract error details from an HTTP response.
pub(crate) async fn handle_error_response(response: reqwest::Response, context: &str) -> VaultError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    VaultError::GeneralError(format!("{} with status {}: {}", context, status, body))
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