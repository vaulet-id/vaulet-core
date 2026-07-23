//! Key management (PLAN.md D3)
//! Real keys live in the Secure Enclave (iOS) / StrongBox (Android) — Rust only
//! sees a handle. Every signature goes through a platform channel to hardware.
//! Shamir recovery (2-of-3, custom n-of-m) arrives in M3.

pub mod hd;
pub mod software;

use serde::{Deserialize, Serialize};

/// Reference to a key held in secure hardware — not the key itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHandle {
    pub id: String,
    /// Algorithm — locked to ES256 for now (P-256 matches Secure Enclave and SD-JWT).
    pub algorithm: String,
}

/// Implemented by the native side (Swift/Kotlin), results returned to Rust.
pub trait HardwareSigner {
    fn public_jwk(&self, key: &KeyHandle) -> crate::Result<serde_json::Value>;
    fn sign(&self, key: &KeyHandle, payload: &[u8]) -> crate::Result<Vec<u8>>;
}
