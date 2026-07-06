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

// Test-support code: unwrap/expect are acceptable here (failures should abort the test).
#![allow(clippy::unwrap_used)]

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod util;

/// Runs the Eclipse Dataspace Data Plane Signaling (DPS) TCK against an in-process siglet,
/// focused on the synchronous pull scenario.
///
/// Flow:
///   1. Start a dev-mode Vault container and provision the transit engine + `signing-siglet` key.
///   2. Start a Postgres container for the siglet's persistence backend.
///   3. Assemble and serve a real siglet (Postgres backend) with signaling auth disabled.
///   4. Run the DPS TCK container; it drives the siglet's signaling API and prints results.
///   5. Assert no `FAILED:` lines were emitted.
///
/// Requires Docker, so it is `#[ignore]`d by default. Run explicitly with:
///   `cargo test -p siglet-tck -- --ignored --nocapture`
#[tokio::test]
async fn siglet_dps_tck_pull() {
    init_tracing();

    // 1. Vault, provisioned with the siglet's signing key.
    let (vault_url, token_file, _vault) = util::setup_vault().await;

    // 2. Postgres, backing the siglet's persistence.
    let (pg_url, _pg) = util::setup_postgres().await;

    // 3. Real siglet, signaling API on util::SIGNALING_PORT.
    let cfg = util::build_config(&vault_url, &token_file, &pg_url);
    util::start_siglet(cfg).await;

    // 4. Run the TCK; this blocks until the container prints "Test run complete".
    let reporter = util::TckTestReporter::default();
    let _tck = util::setup_tck_container(reporter.clone()).await;

    // 5. Any FAILED: line the reporter captured fails the test.
    let failures = reporter.failures();
    assert!(failures.is_empty(), "TCK reported failures: {failures:?}");
}

fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}
