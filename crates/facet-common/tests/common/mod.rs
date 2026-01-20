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

// Allow dead code in this module since test utilities are shared across multiple test files
// and each test binary is compiled separately
#![allow(dead_code)]

mod mocks;
mod proxy_s3;
mod minio;
mod postgres;

use std::net::TcpListener;
#[allow(unused_imports)] // Mocks are used in some test files but not others
pub use mocks::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use proxy_s3::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use minio::*;
#[allow(unused_imports)] // Used in some test files but not others
pub use postgres::*;


/// Get an available port by binding to port 0 and retrieving the assigned port
pub fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    let port = listener.local_addr().expect("Failed to get local address").port();
    drop(listener);
    port
}