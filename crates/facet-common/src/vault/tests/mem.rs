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

use crate::vault::{MemoryVaultClient, VaultClient, VaultError};
use crate::context::ParticipantContext;
use std::collections::HashMap;
use std::sync::RwLock;

fn create_client() -> MemoryVaultClient {
    MemoryVaultClient {
        secrets: RwLock::new(HashMap::new()),
    }
}

fn create_participant_context() -> ParticipantContext {
    ParticipantContext {
        id: "test-id".to_string(),
        identifier: "test-identifier".to_string(),
        audience: "test-audience".to_string(),
    }
}

#[tokio::test]
async fn test_store_and_resolve_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "test/path", "my-secret").await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await.unwrap();
    assert_eq!(result, "my-secret");
}

#[tokio::test]
async fn test_resolve_nonexistent_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    let result = client.resolve_secret(&ctx, "nonexistent/path").await;

    assert!(result.is_err());
    match result {
        Err(VaultError::SecretNotFound { identifier }) => {
            assert_eq!(identifier, "nonexistent/path");
        }
        _ => panic!("Expected SecretNotFound error"),
    }
}

#[tokio::test]
async fn test_remove_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "test/path", "my-secret").await.unwrap();
    client.remove_secret(&ctx, "test/path").await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_nonexistent_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    let result = client.remove_secret(&ctx, "nonexistent/path").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_overwrite_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "test/path", "original-secret").await.unwrap();
    client.store_secret(&ctx, "test/path", "updated-secret").await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await.unwrap();
    assert_eq!(result, "updated-secret");
}

#[tokio::test]
async fn test_empty_path() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "", "secret-value").await.unwrap();

    let result = client.resolve_secret(&ctx, "").await.unwrap();
    assert_eq!(result, "secret-value");
}

#[tokio::test]
async fn test_empty_secret_value() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "test/path", "").await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await.unwrap();
    assert_eq!(result, "");
}

#[tokio::test]
async fn test_multiple_secrets() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "path1", "secret1").await.unwrap();
    client.store_secret(&ctx, "path2", "secret2").await.unwrap();
    client.store_secret(&ctx, "path3", "secret3").await.unwrap();

    assert_eq!(client.resolve_secret(&ctx, "path1").await.unwrap(), "secret1");
    assert_eq!(client.resolve_secret(&ctx, "path2").await.unwrap(), "secret2");
    assert_eq!(client.resolve_secret(&ctx, "path3").await.unwrap(), "secret3");
}

#[tokio::test]
async fn test_concurrent_reads() {
    let client = std::sync::Arc::new(create_client());
    let ctx = std::sync::Arc::new(create_participant_context());

    client.store_secret(&ctx, "shared/path", "shared-secret").await.unwrap();

    let mut handles = vec![];
    for _ in 0..10 {
        let client_clone = client.clone();
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            client_clone.resolve_secret(&ctx_clone, "shared/path").await.unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert_eq!(result, "shared-secret");
    }
}

#[tokio::test]
async fn test_concurrent_writes_and_reads() {
    let client = std::sync::Arc::new(create_client());
    let ctx = std::sync::Arc::new(create_participant_context());

    let mut handles = vec![];

    for i in 0..5 {
        let client_clone = client.clone();
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            let path = format!("path/{}", i);
            let secret = format!("secret-{}", i);
            client_clone.store_secret(&ctx_clone, &path, &secret).await.unwrap();
            client_clone.resolve_secret(&ctx_clone, &path).await.unwrap()
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.unwrap();
        assert_eq!(result, format!("secret-{}", i));
    }
}

#[tokio::test]
async fn test_resolve_after_remove() {
    let client = create_client();
    let ctx = create_participant_context();

    client.store_secret(&ctx, "temp/path", "temp-secret").await.unwrap();
    assert!(client.resolve_secret(&ctx, "temp/path").await.is_ok());

    client.remove_secret(&ctx, "temp/path").await.unwrap();

    let result = client.resolve_secret(&ctx, "temp/path").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_special_characters_in_path() {
    let client = create_client();
    let ctx = create_participant_context();

    let path = "test/path-with_special.chars@123";
    client.store_secret(&ctx, path, "special-secret").await.unwrap();

    let result = client.resolve_secret(&ctx, path).await.unwrap();
    assert_eq!(result, "special-secret");
}

#[tokio::test]
async fn test_special_characters_in_secret() {
    let client = create_client();
    let ctx = create_participant_context();

    let secret = "secret!@#$%^&*(){}[]|\\:;\"'<>,.?/~`";
    client.store_secret(&ctx, "test/path", secret).await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await.unwrap();
    assert_eq!(result, secret);
}

#[tokio::test]
async fn test_participant_context_isolation() {
    let client = create_client();

    let ctx1 = ParticipantContext {
        id: "participant-1".to_string(),
        identifier: "participant-1-identifier".to_string(),
        audience: "participant-1-audience".to_string(),
    };

    let ctx2 = ParticipantContext {
        id: "participant-2".to_string(),
        identifier: "participant-2-identifier".to_string(),
        audience: "participant-2-audience".to_string(),
    };

    client.store_secret(&ctx1, "shared/path", "secret-for-p1").await.unwrap();
    client.store_secret(&ctx2, "shared/path", "secret-for-p2").await.unwrap();

    let result1 = client.resolve_secret(&ctx1, "shared/path").await.unwrap();
    let result2 = client.resolve_secret(&ctx2, "shared/path").await.unwrap();

    assert_eq!(result1, "secret-for-p1");
    assert_eq!(result2, "secret-for-p2");
}

#[tokio::test]
async fn test_remove_does_not_affect_other_participants() {
    let client = create_client();

    let ctx1 = ParticipantContext {
        id: "participant-1".to_string(),
        identifier: "participant-1-identifier".to_string(),
        audience: "participant-1-audience".to_string(),
    };

    let ctx2 = ParticipantContext {
        id: "participant-2".to_string(),
        identifier: "participant-2-identifier".to_string(),
        audience: "participant-2-audience".to_string(),
    };

    client.store_secret(&ctx1, "test/path", "secret-1").await.unwrap();
    client.store_secret(&ctx2, "test/path", "secret-2").await.unwrap();

    client.remove_secret(&ctx1, "test/path").await.unwrap();

    let result1 = client.resolve_secret(&ctx1, "test/path").await;
    assert!(result1.is_err());

    let result2 = client.resolve_secret(&ctx2, "test/path").await.unwrap();
    assert_eq!(result2, "secret-2");
}

#[tokio::test]
async fn test_resolve_nonexistent_for_different_participant() {
    let client = create_client();

    let ctx1 = ParticipantContext {
        id: "participant-1".to_string(),
        identifier: "participant-1-identifier".to_string(),
        audience: "participant-1-audience".to_string(),
    };

    let ctx2 = ParticipantContext {
        id: "participant-2".to_string(),
        identifier: "participant-2-identifier".to_string(),
        audience: "participant-2-audience".to_string(),
    };

    client.store_secret(&ctx1, "test/path", "secret-1").await.unwrap();

    let result = client.resolve_secret(&ctx2, "test/path").await;
    assert!(result.is_err());
    match result {
        Err(VaultError::SecretNotFound { identifier }) => {
            assert_eq!(identifier, "test/path");
        }
        _ => panic!("Expected SecretNotFound error"),
    }
}

#[tokio::test]
async fn test_multiple_participants_concurrent_operations() {
    let client = std::sync::Arc::new(create_client());

    let mut handles = vec![];

    for i in 0..5 {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let ctx = ParticipantContext {
                id: format!("participant-{}", i),
                identifier: format!("participant-{}-identifier", i),
                audience: format!("participant-{}-audience", i),
            };

            let secret = format!("secret-{}", i);
            client_clone.store_secret(&ctx, "shared/path", &secret).await.unwrap();

            let result = client_clone.resolve_secret(&ctx, "shared/path").await.unwrap();
            assert_eq!(result, secret);

            result
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.unwrap();
        assert_eq!(result, format!("secret-{}", i));
    }
}

#[tokio::test]
async fn test_overwrite_for_same_participant_different_contexts() {
    let client = create_client();

    let ctx = ParticipantContext {
        id: "participant-1".to_string(),
        identifier: "participant-1-identifier".to_string(),
        audience: "participant-1-audience".to_string(),
    };

    client.store_secret(&ctx, "test/path", "original").await.unwrap();

    let ctx_same_id = ParticipantContext {
        id: "participant-1".to_string(),
        identifier: "different-identifier".to_string(),
        audience: "different-audience".to_string(),
    };

    client.store_secret(&ctx_same_id, "test/path", "updated").await.unwrap();

    let result = client.resolve_secret(&ctx, "test/path").await.unwrap();
    assert_eq!(result, "updated");
}
