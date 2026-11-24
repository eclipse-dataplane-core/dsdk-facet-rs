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

//! JWS signing algorithms and the asymmetric key types that back them.
//!
//! The supported set is the intersection of what HashiCorp Vault transit can sign with and what
//! `jsonwebtoken` can verify: EdDSA (Ed25519), ECDSA on P-256/P-384, and RSA with PKCS#1 v1.5 or
//! PSS padding over SHA-256/384/512. Symmetric (HS*) algorithms are deliberately excluded: they
//! cannot be used with public-key distribution (JWKS, DID documents) without making the
//! "secret" public.

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Asymmetric JWS signing algorithms supported for signing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8037).
    EdDSA,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    PS512,
}

/// The digest a signing algorithm is defined over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// RSA signature padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    Pkcs1v15,
    Pss,
}

/// Algorithm family, mirroring the key families a JWS algorithm can be used with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFamily {
    Ed25519,
    Ec,
    Rsa,
}

impl SigningAlgorithm {
    /// Every supported algorithm. Used as the default verification allowlist.
    pub const ALL: [SigningAlgorithm; 9] = [
        SigningAlgorithm::EdDSA,
        SigningAlgorithm::ES256,
        SigningAlgorithm::ES384,
        SigningAlgorithm::RS256,
        SigningAlgorithm::RS384,
        SigningAlgorithm::RS512,
        SigningAlgorithm::PS256,
        SigningAlgorithm::PS384,
        SigningAlgorithm::PS512,
    ];

    /// The JWS `alg` header value (RFC 7518 §3.1).
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::EdDSA => "EdDSA",
            SigningAlgorithm::ES256 => "ES256",
            SigningAlgorithm::ES384 => "ES384",
            SigningAlgorithm::RS256 => "RS256",
            SigningAlgorithm::RS384 => "RS384",
            SigningAlgorithm::RS512 => "RS512",
            SigningAlgorithm::PS256 => "PS256",
            SigningAlgorithm::PS384 => "PS384",
            SigningAlgorithm::PS512 => "PS512",
        }
    }

    pub fn family(&self) -> KeyFamily {
        match self {
            SigningAlgorithm::EdDSA => KeyFamily::Ed25519,
            SigningAlgorithm::ES256 | SigningAlgorithm::ES384 => KeyFamily::Ec,
            SigningAlgorithm::RS256
            | SigningAlgorithm::RS384
            | SigningAlgorithm::RS512
            | SigningAlgorithm::PS256
            | SigningAlgorithm::PS384
            | SigningAlgorithm::PS512 => KeyFamily::Rsa,
        }
    }

    /// The digest the algorithm signs over, or `None` for EdDSA (which hashes internally).
    pub fn hash(&self) -> Option<HashAlgorithm> {
        match self {
            SigningAlgorithm::EdDSA => None,
            SigningAlgorithm::ES256 | SigningAlgorithm::RS256 | SigningAlgorithm::PS256 => Some(HashAlgorithm::Sha256),
            SigningAlgorithm::ES384 | SigningAlgorithm::RS384 | SigningAlgorithm::PS384 => Some(HashAlgorithm::Sha384),
            SigningAlgorithm::RS512 | SigningAlgorithm::PS512 => Some(HashAlgorithm::Sha512),
        }
    }

    /// The RSA padding scheme, or `None` for non-RSA algorithms.
    pub fn rsa_padding(&self) -> Option<RsaPadding> {
        match self {
            SigningAlgorithm::RS256 | SigningAlgorithm::RS384 | SigningAlgorithm::RS512 => Some(RsaPadding::Pkcs1v15),
            SigningAlgorithm::PS256 | SigningAlgorithm::PS384 | SigningAlgorithm::PS512 => Some(RsaPadding::Pss),
            _ => None,
        }
    }

    /// For EC algorithms, the JWK `crv` the key must use.
    pub fn ec_curve(&self) -> Option<&'static str> {
        match self {
            SigningAlgorithm::ES256 => Some("P-256"),
            SigningAlgorithm::ES384 => Some("P-384"),
            _ => None,
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when an algorithm or key type is not supported.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AlgorithmError {
    #[error("Unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Signing algorithm {algorithm} cannot be used with a {key_type} key")]
    Incompatible {
        algorithm: SigningAlgorithm,
        key_type: KeyType,
    },
}

impl FromStr for SigningAlgorithm {
    type Err = AlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SigningAlgorithm::ALL
            .into_iter()
            .find(|alg| alg.as_str() == s)
            .ok_or_else(|| AlgorithmError::UnsupportedAlgorithm(s.to_string()))
    }
}

impl Serialize for SigningAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl From<SigningAlgorithm> for Algorithm {
    fn from(algo: SigningAlgorithm) -> Self {
        match algo {
            SigningAlgorithm::EdDSA => Algorithm::EdDSA,
            SigningAlgorithm::ES256 => Algorithm::ES256,
            SigningAlgorithm::ES384 => Algorithm::ES384,
            SigningAlgorithm::RS256 => Algorithm::RS256,
            SigningAlgorithm::RS384 => Algorithm::RS384,
            SigningAlgorithm::RS512 => Algorithm::RS512,
            SigningAlgorithm::PS256 => Algorithm::PS256,
            SigningAlgorithm::PS384 => Algorithm::PS384,
            SigningAlgorithm::PS512 => Algorithm::PS512,
        }
    }
}

impl TryFrom<Algorithm> for SigningAlgorithm {
    type Error = AlgorithmError;

    /// Maps a `jsonwebtoken` algorithm onto the supported set. Symmetric (HS*) algorithms are rejected.
    fn try_from(alg: Algorithm) -> Result<Self, Self::Error> {
        match alg {
            Algorithm::EdDSA => Ok(SigningAlgorithm::EdDSA),
            Algorithm::ES256 => Ok(SigningAlgorithm::ES256),
            Algorithm::ES384 => Ok(SigningAlgorithm::ES384),
            Algorithm::RS256 => Ok(SigningAlgorithm::RS256),
            Algorithm::RS384 => Ok(SigningAlgorithm::RS384),
            Algorithm::RS512 => Ok(SigningAlgorithm::RS512),
            Algorithm::PS256 => Ok(SigningAlgorithm::PS256),
            Algorithm::PS384 => Ok(SigningAlgorithm::PS384),
            Algorithm::PS512 => Ok(SigningAlgorithm::PS512),
            other => Err(AlgorithmError::UnsupportedAlgorithm(format!("{:?}", other))),
        }
    }
}

/// Asymmetric key types usable for JWT signing, named after HashiCorp Vault transit key types.
///
/// `ecdsa-p521` is intentionally absent: `jsonwebtoken` has no ES512 support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl KeyType {
    pub const ALL: [KeyType; 6] = [
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::Rsa2048,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
    ];

    /// The Vault transit `type` value for this key type.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::Rsa2048 => "rsa-2048",
            KeyType::Rsa3072 => "rsa-3072",
            KeyType::Rsa4096 => "rsa-4096",
        }
    }

    pub fn family(&self) -> KeyFamily {
        match self {
            KeyType::Ed25519 => KeyFamily::Ed25519,
            KeyType::EcdsaP256 | KeyType::EcdsaP384 => KeyFamily::Ec,
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => KeyFamily::Rsa,
        }
    }

    /// The algorithm used when none is configured explicitly.
    ///
    /// EC and Ed25519 keys map to exactly one algorithm. RSA keys default to RS256, the most
    /// widely supported RSA algorithm among JWT verifiers.
    pub fn default_algorithm(&self) -> SigningAlgorithm {
        match self {
            KeyType::Ed25519 => SigningAlgorithm::EdDSA,
            KeyType::EcdsaP256 => SigningAlgorithm::ES256,
            KeyType::EcdsaP384 => SigningAlgorithm::ES384,
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => SigningAlgorithm::RS256,
        }
    }

    /// Whether `algorithm` can be used with this key type.
    pub fn supports(&self, algorithm: SigningAlgorithm) -> bool {
        match self {
            KeyType::Ed25519 => algorithm == SigningAlgorithm::EdDSA,
            KeyType::EcdsaP256 => algorithm == SigningAlgorithm::ES256,
            KeyType::EcdsaP384 => algorithm == SigningAlgorithm::ES384,
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => algorithm.family() == KeyFamily::Rsa,
        }
    }

    /// Resolves the algorithm to sign with: the explicit `requested` one if given (checked for
    /// compatibility), otherwise [`KeyType::default_algorithm`].
    pub fn resolve_algorithm(&self, requested: Option<SigningAlgorithm>) -> Result<SigningAlgorithm, AlgorithmError> {
        match requested {
            None => Ok(self.default_algorithm()),
            Some(algorithm) if self.supports(algorithm) => Ok(algorithm),
            Some(algorithm) => Err(AlgorithmError::Incompatible {
                algorithm,
                key_type: *self,
            }),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyType {
    type Err = AlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyType::ALL
            .into_iter()
            .find(|kt| kt.as_str() == s)
            .ok_or_else(|| AlgorithmError::UnsupportedKeyType(s.to_string()))
    }
}

impl Serialize for KeyType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
