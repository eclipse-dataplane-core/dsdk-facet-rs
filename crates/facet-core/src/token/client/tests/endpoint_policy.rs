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

use crate::token::client::RefreshEndpointPolicy;

fn hosts(hosts: &[&str]) -> RefreshEndpointPolicy {
    RefreshEndpointPolicy {
        allow_http: false,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
    }
}

#[test]
fn default_requires_https() {
    let policy = RefreshEndpointPolicy::default();
    assert!(policy.check("https://provider.example.com/token").is_ok());
    assert!(policy.check("http://provider.example.com/token").is_err());
    assert!(policy.check("http://169.254.169.254/latest/meta-data").is_err());
    assert!(policy.check("file:///etc/passwd").is_err());
    assert!(policy.check("not a url").is_err());
}

#[test]
fn rejects_credentials_in_url() {
    let policy = RefreshEndpointPolicy::default();
    assert!(policy.check("https://user:pass@provider.example.com/token").is_err());
}

#[test]
fn permissive_allows_http() {
    let policy = RefreshEndpointPolicy::permissive();
    assert!(policy.check("http://siglet:8082/token").is_ok());
    assert!(policy.check("ftp://siglet/token").is_err());
}

#[test]
fn allowed_hosts_exact_and_wildcard() {
    let policy = hosts(&["provider.example.com", "*.dataspace.example"]);
    assert!(policy.check("https://provider.example.com/token").is_ok());
    assert!(policy.check("https://PROVIDER.example.com/token").is_ok());
    assert!(policy.check("https://a.dataspace.example/token").is_ok());
    assert!(policy.check("https://a.b.dataspace.example/token").is_ok());
    assert!(policy.check("https://dataspace.example/token").is_err());
    assert!(policy.check("https://evildataspace.example/token").is_err());
    assert!(policy.check("https://provider.example.com.evil.io/token").is_err());
    assert!(policy.check("https://10.0.0.1/token").is_err());
}
