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

use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

/// Helper to create a PostgreSQL container and connection pool
pub async fn setup_postgres_container() -> (PgPool, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default().start().await.unwrap();

    let connection_string = format!(
        "postgresql://postgres:postgres@127.0.0.1:{}/postgres",
        container.get_host_port_ipv4(5432).await.unwrap()
    );

    // Wait for PostgreSQL to be ready
    let mut retries = 0;
    let pool = loop {
        match PgPool::connect(&connection_string).await {
            Ok(pool) => break pool,
            Err(_) if retries < 30 => {
                retries += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("Failed to connect to PostgreSQL: {}", e),
        }
    };

    (pool, container)
}
