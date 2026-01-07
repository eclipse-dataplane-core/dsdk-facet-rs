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

use chrono::{DateTime, TimeDelta, Utc};
use sodiumoxide::crypto::{pwhash, secretbox};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Abstraction for time operations
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub fn default_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Real system clock
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Mock clock for testing
pub struct MockClock {
    current_time: Arc<Mutex<DateTime<Utc>>>,
}

impl MockClock {
    pub fn new(initial: DateTime<Utc>) -> Self {
        Self {
            current_time: Arc::new(Mutex::new(initial)),
        }
    }

    pub fn advance(&self, duration: TimeDelta) {
        let mut time = self.current_time.lock().unwrap();
        *time = *time + duration;
    }

    pub fn set(&self, instant: DateTime<Utc>) {
        *self.current_time.lock().unwrap() = instant;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.current_time.lock().unwrap()
    }
}

/// Errors that can occur during cryptographic key operations.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct KeyError(pub String);


/// Derives a cryptographic key from a password using Argon2id13.
///
/// `password` - The password to derive the key from.
/// `salt_hex` - A 16-character hexadecimal string representing 16 bytes.
///
/// Generate the salt with: `openssl rand -hex 16`
///
/// Returns a 256-bit encryption key for use with `secretbox`.
pub fn encryption_key(password: &str, salt_hex: &str) -> Result<secretbox::Key, KeyError> {
    sodiumoxide::init().ok(); // One-time initialization

    // Parse salt from config
    let salt_bytes = hex::decode(salt_hex).map_err(|e| KeyError(format!("Invalid salt: {}", e)))?;

    let salt = pwhash::argon2id13::Salt::from_slice(&salt_bytes)
        .ok_or_else(|| KeyError("Invalid salt size".to_string()))?;

    // Derive key using Argon2id13
    let mut key_bytes = [0u8; 32]; // 256 bits
    pwhash::argon2id13::derive_key(
        &mut key_bytes,
        password.as_bytes(),
        &salt,
        pwhash::argon2id13::OPSLIMIT_MODERATE,
        pwhash::argon2id13::MEMLIMIT_MODERATE,
    )
        .map_err(|_| KeyError("Key derivation failed".to_string()))?;

    secretbox::Key::from_slice(&key_bytes).ok_or_else(|| KeyError("Invalid key".to_string()))
}

// Encrypt plaintext and return (ciphertext, nonce)
pub fn encrypt(encryption_key: &secretbox::Key, plaintext: &[u8]) -> (Vec<u8>, secretbox::Nonce) {
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(plaintext, &nonce, encryption_key);
    (ciphertext, nonce)
}

// Decrypt ciphertext using nonce
pub fn decrypt(encryption_key: &secretbox::Key, ciphertext: &[u8], nonce: &secretbox::Nonce) -> Result<Vec<u8>, KeyError> {
    secretbox::open(ciphertext, nonce, encryption_key)
        .map_err(|_| KeyError("Decryption failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_encryption_key_success() {
        let password = "test_password_123";
        let salt_hex = "6b9768804c86626227e61acd9e06f8ff";

        let result = encryption_key(password, salt_hex);

        assert!(result.is_ok());
        let key = result.unwrap();

        // Verify key is 32 bytes (256 bits)
        assert_eq!(key.0.len(), 32);
    }
}