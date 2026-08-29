//! Vaulet identity core: keys, DIDs, credentials, and the protocols over them.
//!
//! Principle: everything touching keys/credentials/protocols lives in this
//! crate. Flutter is UI only, calling in over FFI (flutter_rust_bridge).
//! The same crate is reused by the backend (axum) and, later, WASM.

pub mod chat;
pub mod credential;
pub mod dcbor;
pub mod did;
pub mod emrtd;
pub mod keys;
pub mod mnemonic;
pub mod protocol;
pub mod address;
pub mod mandate;
pub mod recovery;
pub mod rule;
pub mod requests;
pub mod statement;
pub mod certificate;
pub mod vouching;
pub mod shamir;
/// The shared cross-language capture vectors. Enabled for this crate's own
/// tests and, via the `test-fixtures` feature, for the backend's — the same
/// gate `emrtd::fixtures` uses, and for the same reason: test material must not
/// reach a production build.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod vectors;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("key operation failed: {0}")]
    Key(String),
    #[error("credential invalid: {0}")]
    Credential(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("not yet implemented: {0}")]
    Todo(&'static str),
}

pub type Result<T> = std::result::Result<T, CoreError>;

// ---------------------------------------------------------------------------
// The wallet SECRET is never persisted by this crate. It lives only in platform
// secure storage (iOS Keychain, `ThisDeviceOnly` — encrypted at rest, excluded
// from backups, non-migratable = anti-clone). The application reads it, holds
// the unlocked value for the session, and passes it into these modules per
// call. This crate is stateless: given the same secret it derives the same
// identity, signs, backs up and restores — and writes nothing.
//
// A `secret` is one of:
//   * seed-first BIP39 mnemonic (ADR 0008) — the normal case; the identity key
//     is SLIP-0010 P-256 at m/1077'/0'/0' derived from its seed;
//   * legacy raw-key JWK (ADR 0001 Approach A) — the private scalar itself,
//     kept working for wallets created before the seed-first migration.
// The two are told apart by whether the string parses as a BIP39 mnemonic.
//
// The twenty-one `wallet_*` functions that used to sit here have moved to the
// application that calls them (ADR 0033). They were one shape — take a secret
// as a string, take everything else as a string, return a string — and that
// shape is the FFI boundary's, not this crate's. A Rust caller passes the typed
// value. What is left below is what more than one of them needed.
// ---------------------------------------------------------------------------

/// The 32-byte BIP39 entropy behind a seed-first mnemonic — the secret Shamir
/// splits, so recovery rebuilds the mnemonic (not just the derived scalar).
/// The same, for the Simple Recovery module (ADR 0019), which splits the very
/// same 32 bytes rather than a second secret derived from them.
///
/// Public because the wallet splits shares outside this crate now (ADR 0033).
/// It reads a mnemonic and returns its entropy; it has no idea who is asking.
pub fn mnemonic_entropy_public(secret: &str) -> Result<[u8; 32]> {
    mnemonic_entropy(secret)
}

fn mnemonic_entropy(secret: &str) -> Result<[u8; 32]> {
    use bip39::Mnemonic;
    let m = Mnemonic::parse(secret.trim())
        .map_err(|_| CoreError::Key("advanced backup needs a seed-first wallet".into()))?;
    let (entropy, len) = m.to_entropy_array();
    if len != 32 {
        return Err(CoreError::Key(
            "advanced backup needs a 24-word seed".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&entropy[..32]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_key_signs() {
        let key = keys::software::SoftwareKey::generate();
        let sig = key.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64); // raw ECDSA P-256 (r||s)
    }

}

// ---------------------------------------------------------------------------
// Shared with the issuer.
//
// The `typ` values are protocol vocabulary: the wallet signs a JWT with one and
// the issuer refuses anything that does not carry it. Two parties reading one
// constant is exactly what belongs in this crate — a copy on each side is two
// constants that agree until one of them does not.
//
// `verify_passport_verdict` is here for the same reason, and only its name
// travelled from the wallet's facade — the issuer verifies chips too, and it is
// nobody's wallet. It is a shape adapter over `emrtd::verify_passport` for
// callers holding owned bytes.
// ---------------------------------------------------------------------------

/// `typ` of the JWT a wallet signs to sign in to Studio.
pub const STUDIO_SIGNIN_JWT_TYP: &str = "vaulet-studio-signin+jwt";
/// `typ` of the JWT a wallet signs to connect an external account (ADR 0024).
pub const SOCIAL_CONNECT_JWT_TYP: &str = "vaulet-connect-account+jwt";
/// `typ` of the JWT a wallet signs to join an organisation.
pub const ORG_JOIN_JWT_TYP: &str = "vaulet-org-join+jwt";

/// Passive and Active Authentication over owned bytes, for callers that have
/// them that way — the wallet across FFI, the issuer out of a request body.
pub fn verify_passport_verdict(
    sod: &[u8],
    dgs: std::collections::BTreeMap<u8, Vec<u8>>,
    csca: Vec<Vec<u8>>,
    aa: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> Result<emrtd::PassportVerdict> {
    let aa_ref = aa
        .as_ref()
        .map(|(a, b, c)| (a.as_slice(), b.as_slice(), c.as_slice()));
    emrtd::verify_passport(sod, &dgs, &csca, aa_ref)
}
