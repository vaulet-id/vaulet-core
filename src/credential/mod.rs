//! Credential layer (PLAN.md D2, D13).
//! Stored format-agnostic: SD-JWT VC first, dual-rail with BBS+ later (Z3).

use serde::{Deserialize, Serialize};

/// One credential in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    /// e.g. "sd-jwt-vc" — never hardcode format-specific logic outside this module.
    pub format: String,
    /// Raw credential (encrypted at rest by the storage layer).
    pub raw: String,
    /// Display data cached for fast rendering (title, issuer, color, logo).
    pub display: CredentialDisplay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub title: String,
    pub issuer_name: String,
    pub issuer_did: String,
    /// Hex like "#0E7C66" — from the issuer's credential template.
    pub color: Option<String>,
}

/// Verify: issuer signature + not expired + not revoked (Status List, D10).
pub fn verify(_credential: &StoredCredential) -> crate::Result<()> {
    Err(crate::CoreError::Todo("credential::verify — M1 sprint 2"))
}
