//! DID layer (PLAN.md D4)
//! - holder binding: did:jwk
//! - chat peers (phase M2): did:peer
//! - issuers: did:web — the resolver must stay pluggable

use serde::{Deserialize, Serialize};

/// The primary identity of a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletIdentity {
    /// did:jwk derived from the public key in secure hardware.
    pub did: String,
    /// JWK public key (the private key never leaves Secure Enclave/StrongBox).
    pub public_jwk: serde_json::Value,
}

/// Pluggable resolver — phase one supports did:jwk / did:key / did:web only
/// (no blockchain DIDs — see D4).
pub trait DidResolver {
    fn resolve(&self, did: &str) -> crate::Result<serde_json::Value>;
}

/// Build a did:jwk from a public JWK per spec:
/// did:jwk:<base64url(public JWK JSON, no padding)>
pub fn did_jwk_from_public(public_jwk: &serde_json::Value) -> crate::Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let canonical = serde_json::to_string(public_jwk)
        .map_err(|e| crate::CoreError::Key(format!("jwk serialize: {e}")))?;
    Ok(format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(canonical)))
}
