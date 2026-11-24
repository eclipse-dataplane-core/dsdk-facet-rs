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

//! Conversions between public key encodings and JWKs, and checks that a JWS algorithm fits a key.

use crate::jwt::{Jwk, JwkKeyType, JwkPublicKeyUse, KeyFamily, KeyType, SigningAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pkcs8::der::Decode;
use pkcs8::{ObjectIdentifier, SubjectPublicKeyInfoRef};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;

/// `id-ecPublicKey` (RFC 5480).
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1` / P-256 (RFC 5480).
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` / P-384 (RFC 5480).
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Builds a public signing JWK from key bytes in the layout described by
/// [`PublicKeyFormat::Base64Url`]: raw 32 bytes for Ed25519, DER `SubjectPublicKeyInfo` for RSA/EC.
///
/// `algorithm` is advertised as the JWK `alg` and must be compatible with `key_type`.
///
/// [`PublicKeyFormat::Base64Url`]: crate::vault::PublicKeyFormat::Base64Url
pub fn public_key_to_jwk(
    key_type: KeyType,
    key_bytes: &[u8],
    kid: &str,
    algorithm: SigningAlgorithm,
) -> Result<Jwk, String> {
    if !key_type.supports(algorithm) {
        return Err(format!(
            "algorithm {} cannot be used with a {} key",
            algorithm, key_type
        ));
    }

    let builder = Jwk::builder()
        .kid(kid)
        .key_use(JwkPublicKeyUse::Sig)
        .alg(algorithm.as_str());

    let jwk = match key_type.family() {
        KeyFamily::Ed25519 => {
            if key_bytes.len() != 32 {
                return Err(format!("Ed25519 public key must be 32 bytes, got {}", key_bytes.len()));
            }
            builder
                .kty(JwkKeyType::Okp)
                .crv("Ed25519")
                .x(URL_SAFE_NO_PAD.encode(key_bytes))
                .build()
        }
        KeyFamily::Rsa => {
            let key = RsaPublicKey::from_public_key_der(key_bytes)
                .map_err(|e| format!("invalid RSA SubjectPublicKeyInfo: {}", e))?;
            builder
                .kty(JwkKeyType::Rsa)
                .n(URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()))
                .e(URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()))
                .build()
        }
        KeyFamily::Ec => {
            let (curve_oid, crv, coordinate_len) = match key_type {
                KeyType::EcdsaP256 => (OID_P256, "P-256", 32),
                KeyType::EcdsaP384 => (OID_P384, "P-384", 48),
                other => return Err(format!("unexpected EC key type {}", other)),
            };
            let spki = SubjectPublicKeyInfoRef::from_der(key_bytes)
                .map_err(|e| format!("invalid EC SubjectPublicKeyInfo: {}", e))?;
            if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(format!(
                    "expected an EC public key, got algorithm {}",
                    spki.algorithm.oid
                ));
            }
            let actual_curve = spki
                .algorithm
                .parameters_oid()
                .map_err(|e| format!("missing EC curve parameter: {}", e))?;
            if actual_curve != curve_oid {
                return Err(format!("expected curve {} ({}), got {}", crv, curve_oid, actual_curve));
            }
            // SEC1 uncompressed point: 0x04 || X || Y.
            let point = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| "EC public key bit string is not octet-aligned".to_string())?;
            if point.len() != 1 + 2 * coordinate_len || point[0] != 0x04 {
                return Err(format!("expected an uncompressed {} point", crv));
            }
            let (x, y) = point[1..].split_at(coordinate_len);
            builder
                .kty(JwkKeyType::Ec)
                .crv(crv)
                .x(URL_SAFE_NO_PAD.encode(x))
                .y(URL_SAFE_NO_PAD.encode(y))
                .build()
        }
    };
    Ok(jwk)
}

/// Checks that `algorithm` can be used with the key described by a JWK.
///
/// The key type (`kty`) and, for EC keys, the curve (`crv`) must match the algorithm, and when the
/// JWK advertises an `alg` it must equal `algorithm` exactly. Symmetric (`oct`) keys are always
/// rejected: a symmetric key published in a JWKS or DID document is a public "secret" that anyone
/// could use to forge tokens.
pub fn check_jwk_algorithm(jwk: &jsonwebtoken::jwk::Jwk, algorithm: SigningAlgorithm) -> Result<(), String> {
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};

    let family_ok = match (&jwk.algorithm, algorithm.family()) {
        (AlgorithmParameters::OctetKeyPair(params), KeyFamily::Ed25519) => params.curve == EllipticCurve::Ed25519,
        (AlgorithmParameters::RSA(_), KeyFamily::Rsa) => true,
        (AlgorithmParameters::EllipticCurve(params), KeyFamily::Ec) => match algorithm {
            SigningAlgorithm::ES256 => params.curve == EllipticCurve::P256,
            SigningAlgorithm::ES384 => params.curve == EllipticCurve::P384,
            _ => false,
        },
        _ => false,
    };
    if !family_ok {
        return Err(format!("algorithm {} does not match the JWK key type", algorithm));
    }

    if let Some(jwk_alg) = &jwk.common.key_algorithm {
        let advertised = jwk_alg.to_string();
        if advertised != algorithm.as_str() {
            return Err(format!(
                "algorithm {} does not match the JWK alg {}",
                algorithm, advertised
            ));
        }
    }
    Ok(())
}
