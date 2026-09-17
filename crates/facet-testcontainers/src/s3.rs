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

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;

use testcontainers::core::WaitFor;
use testcontainers::{ContainerAsync, GenericImage, ImageExt, core::ContainerPort, runners::AsyncRunner};

pub const S3_ACCESS_KEY: &str = "rustfsadmin";
pub const S3_SECRET_KEY: &str = "rustfsadmin";
pub const TEST_BUCKET: &str = "test-bucket";
pub const TEST_KEY: &str = "test-file.txt";
pub const TEST_CONTENT: &[u8] = b"test content";

/// Build AWS SDK config for the S3 test server connection
async fn build_s3_client_config(endpoint: &str) -> aws_config::SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(S3_ACCESS_KEY, S3_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .load()
        .await
}

/// Create a direct S3 client (bypassing the proxy) for verification
pub async fn create_direct_s3_client(s3_endpoint: &str) -> Client {
    let config = build_s3_client_config(s3_endpoint).await;
    Client::new(&config)
}

/// Encapsulates an S3-compatible test server (RustFS) with convenient helper methods.
pub struct S3Instance {
    #[allow(dead_code)]
    pub container: ContainerAsync<GenericImage>,
    pub port: u16,
    pub host: String,
    pub endpoint: String,
}

impl S3Instance {
    /// Launches a new S3 test server and returns structured info.
    pub async fn launch() -> Self {
        let container = GenericImage::new("rustfs/rustfs", "1.0.0")
            .with_wait_for(WaitFor::message_on_stdout("Starting: /usr/bin/rustfs"))
            .with_exposed_port(ContainerPort::Tcp(9000))
            .with_env_var("RUSTFS_ACCESS_KEY", S3_ACCESS_KEY)
            .with_env_var("RUSTFS_SECRET_KEY", S3_SECRET_KEY)
            .start()
            .await
            .unwrap();

        let port = container.get_host_port_ipv4(9000).await.unwrap();
        let host = format!("127.0.0.1:{}", port);
        let endpoint = format!("http://{}", host);

        Self {
            container,
            port,
            host,
            endpoint,
        }
    }

    /// Sets up the default test bucket with a test file.
    pub async fn setup_default_bucket(&self) {
        let config = build_s3_client_config(&self.endpoint).await;
        let client = Client::new(&config);

        client
            .create_bucket()
            .bucket(TEST_BUCKET)
            .send()
            .await
            .expect("Failed to create bucket");

        // Upload a default test file
        client
            .put_object()
            .bucket(TEST_BUCKET)
            .key("test-file.txt")
            .body(ByteStream::from_static(b"test content"))
            .send()
            .await
            .expect("Failed to upload test file");
    }

    /// Sets up a bucket with a custom file.
    pub async fn setup_bucket_with_file(&self, bucket: &str, key: &str, content: &[u8]) {
        let config = build_s3_client_config(&self.endpoint).await;
        let client = Client::new(&config);

        let create_result = client.create_bucket().bucket(bucket).send().await;

        // Ignore bucket-already-exists errors (the server may persist state between test runs)
        if let Err(e) = create_result {
            let error_msg = format!("{:?}", e);
            if !error_msg.contains("BucketAlreadyOwnedByYou") && !error_msg.contains("BucketAlreadyExists") {
                panic!("Failed to create bucket: {:?}", e);
            }
        }

        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(content.to_vec()))
            .send()
            .await
            .expect("Failed to upload file");
    }

    /// Verify that an object exists in S3 bypassing the proxy.
    pub async fn verify_object_exists(&self, bucket: &str, key: &str) -> bool {
        let client = create_direct_s3_client(&self.endpoint).await;
        client.get_object().bucket(bucket).key(key).send().await.is_ok()
    }

    /// Verify object content matches the expected value bypassing the proxy.
    pub async fn verify_object_content(&self, bucket: &str, key: &str, expected: &[u8]) -> bool {
        let client = create_direct_s3_client(&self.endpoint).await;
        if let Ok(response) = client.get_object().bucket(bucket).key(key).send().await
            && let Ok(body) = response.body.collect().await
        {
            return body.to_vec() == expected;
        }
        false
    }

    /// Verify that an object does NOT exist in S3 bypassing the proxy.
    pub async fn verify_object_deleted(&self, bucket: &str, key: &str) -> bool {
        !self.verify_object_exists(bucket, key).await
    }
}
