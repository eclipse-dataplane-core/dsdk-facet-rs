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

//! Policy for the refresh endpoints Siglet calls on behalf of a participant context.
//!
//! A refresh endpoint arrives in the data address sent by the counterparty, and a token refresh
//! POSTs the stored refresh token plus a proof JWT signed with the participant context's key to it.
//! An unchecked endpoint would let a counterparty aim those credentials at any URL reachable from
//! Siglet (cloud metadata services, internal admin APIs), so every endpoint must pass
//! [`RefreshEndpointPolicy::check`] before it is stored and again before it is called.

use crate::token::TokenError;
use serde::Deserialize;
use url::Url;

/// Which refresh endpoints may be called.
///
/// The default only requires HTTPS. Production deployments should also name the counterparties'
/// refresh hosts in `allowed_hosts`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RefreshEndpointPolicy {
    /// Also accept plain `http` endpoints. For development and in-cluster test setups only: the
    /// request carries a refresh token and a signed proof JWT.
    pub allow_http: bool,
    /// When non-empty, the endpoint's host must equal one of these entries (case-insensitive), or
    /// be a subdomain of an entry written as `*.example.com`.
    pub allowed_hosts: Vec<String>,
}

impl RefreshEndpointPolicy {
    /// A policy that accepts any `http` or `https` endpoint. For tests and local development.
    pub fn permissive() -> Self {
        Self {
            allow_http: true,
            allowed_hosts: Vec::new(),
        }
    }

    /// Returns the parsed endpoint if the policy accepts it.
    pub fn check(&self, endpoint: &str) -> Result<Url, TokenError> {
        let reject = |reason: &str| {
            Err(TokenError::NotAuthorized(format!(
                "Refresh endpoint rejected by policy: {}",
                reason
            )))
        };

        let url = match Url::parse(endpoint) {
            Ok(url) => url,
            Err(_) => return reject("not a valid URL"),
        };
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            _ => return reject("scheme must be https"),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return reject("credentials in the URL are not allowed");
        }
        let Some(host) = url.host_str() else {
            return reject("missing host");
        };
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|allowed| host_matches(allowed, host)) {
            return reject("host is not in the allowed hosts");
        }
        Ok(url)
    }
}

fn host_matches(allowed: &str, host: &str) -> bool {
    let allowed = allowed.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    match allowed.strip_prefix("*.") {
        Some(domain) => host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
        None => host == allowed,
    }
}
