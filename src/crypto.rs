//! Cryptographic token generation, hashing, signature verification, and Ed25519 JWS signing.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

pub fn random_token(prefix: &str) -> Result<String, ApiError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::Internal)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[must_use]
pub fn hash_secret(value: &str, pepper: Option<&str>) -> String {
    let mut digest = Sha256::new();
    digest.update(pepper.unwrap_or_default().as_bytes());
    digest.update(b":");
    digest.update(value.as_bytes());
    hex_encode(&digest.finalize())
}

pub fn hmac_sha256_hex(secret: &str, value: &str) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ApiError::Internal)?;
    mac.update(value.as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

#[must_use]
pub fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub fn sign_jws<T: serde::Serialize>(
    claims: &T,
    key_id: &str,
    private_key_pem: &str,
) -> Result<String, ApiError> {
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": key_id });
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| ApiError::Internal)?);
    let claims =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| ApiError::Internal)?);
    let signing_input = format!("{header}.{claims}");
    let signing_key = SigningKey::from_pkcs8_pem(&normalize_pem(private_key_pem))
        .map_err(|_| ApiError::Configuration)?;
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

#[must_use]
pub fn normalize_pem(value: &str) -> String {
    value.replace("\\n", "\n").trim().to_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{constant_time_equal, hash_secret, hmac_sha256_hex, normalize_pem};

    #[test]
    fn hashes_are_stable_and_pepper_scoped() {
        assert_eq!(
            hash_secret("value", Some("a")),
            hash_secret("value", Some("a"))
        );
        assert_ne!(
            hash_secret("value", Some("a")),
            hash_secret("value", Some("b"))
        );
    }

    #[test]
    fn hmac_matches_known_sha256_vector() {
        let signature = hmac_sha256_hex("key", "value");
        assert!(signature.is_ok_and(|value| {
            value == "90fbfcf15e74a36b89dbdb2a721d9aecffdfdddc5c83e27f7592594f71932481"
        }));
    }

    #[test]
    fn equality_and_pem_normalization_are_explicit() {
        assert!(constant_time_equal("same", "same"));
        assert!(!constant_time_equal("same", "different"));
        assert_eq!(normalize_pem("a\\nb\n"), "a\nb");
    }
}
