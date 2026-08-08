//! Software key (P-256).
//!
//! The private scalar is derived in memory from the seed (ADR 0008) and is
//! NEVER persisted by the core — the seed lives in the platform Keychain
//! (`ThisDeviceOnly`) and is loaded into a session per app run. `p256::SecretKey`
//! zeroizes its scalar on drop; raw exports here are wiped after use. The
//! hardware-backed `HardwareSigner` path (Secure Enclave/StrongBox) remains the
//! future upgrade for a non-exportable signing key.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::{FieldBytes, SecretKey};
use serde_json::Value;
use zeroize::Zeroize;

use crate::{CoreError, Result};

pub struct SoftwareKey {
    secret: SecretKey,
}

impl SoftwareKey {
    /// Generate a new key using OS randomness.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::random(&mut rand_core::OsRng),
        }
    }

    /// Load from a persisted JWK string.
    pub fn from_jwk(jwk: &str) -> Result<Self> {
        let secret = SecretKey::from_jwk_str(jwk)
            .map_err(|e| CoreError::Key(format!("bad stored jwk: {e}")))?;
        Ok(Self { secret })
    }

    /// Full JWK (includes private part) — only for persistence.
    pub fn to_jwk_string(&self) -> String {
        self.secret.to_jwk_string().to_string()
    }

    /// Public-only JWK — used to build did:jwk and embed in credentials.
    pub fn public_jwk(&self) -> Result<Value> {
        let jwk = self.secret.public_key().to_jwk_string();
        serde_json::from_str(&jwk).map_err(|e| CoreError::Key(format!("public jwk parse: {e}")))
    }

    /// Raw 32-byte private scalar (the P-256 `d` value, big-endian).
    /// This is the entropy the BIP39 recovery phrase encodes (ADR 0001).
    pub fn to_scalar_bytes(&self) -> [u8; 32] {
        let mut fb = self.secret.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&fb);
        fb.as_mut_slice().zeroize(); // wipe the intermediate copy of the scalar
        out
    }

    /// Rebuild a key from a raw 32-byte scalar. Errors if the scalar is out of
    /// range for P-256 (i.e. not in [1, n-1]).
    pub fn from_scalar_bytes(b: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_bytes(FieldBytes::from_slice(b))
            .map_err(|e| CoreError::Key(format!("scalar out of range: {e}")))?;
        Ok(Self { secret })
    }

    /// Sign with ES256 (ECDSA P-256 + SHA-256).
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let signer = SigningKey::from(&self.secret);
        let sig: Signature = signer.sign(payload);
        Ok(sig.to_vec())
    }
}
