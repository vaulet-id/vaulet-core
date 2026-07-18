//! Vaulet identity core — structured per PLAN.md D2–D5.
//!
//! Principle: everything touching keys/credentials/protocols lives in this
//! crate. Flutter is UI only, calling in over FFI (flutter_rust_bridge).
//! The same crate is reused by the backend (axum) and, later, WASM.

pub mod credential;
pub mod did;
pub mod keys;
pub mod protocol;

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

/// Entry point Flutter calls on app start: load the existing wallet from
/// `storage_dir`, or create a new one (P-256 key + did:jwk) if none exists.
///
/// `storage_dir` is the app's data directory (from path_provider).
/// Currently a software key — see keys/software.rs for the Secure Enclave path.
pub fn wallet_init(storage_dir: &str) -> Result<did::WalletIdentity> {
    use keys::software::SoftwareKey;

    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");

    let key = if key_path.exists() {
        let jwk = std::fs::read_to_string(&key_path)
            .map_err(|e| CoreError::Key(format!("read key file: {e}")))?;
        SoftwareKey::from_jwk(&jwk)?
    } else {
        let key = SoftwareKey::generate();
        std::fs::create_dir_all(storage_dir)
            .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
        std::fs::write(&key_path, key.to_jwk_string())
            .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;
        key
    };

    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// Whether a wallet exists on this device — decides if onboarding is needed.
pub fn wallet_exists(storage_dir: &str) -> bool {
    std::path::Path::new(storage_dir)
        .join("wallet_key.jwk")
        .exists()
}

/// Delete the wallet entirely (key + everything derived from it). Used from
/// Settings. ⚠️ Unrecoverable until Shamir recovery ships (M3).
pub fn wallet_reset(storage_dir: &str) -> Result<()> {
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    if key_path.exists() {
        std::fs::remove_file(&key_path)
            .map_err(|e| CoreError::Key(format!("delete key file: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_init_creates_did_jwk() {
        let dir = tempfile::tempdir().unwrap();
        let id = wallet_init(dir.path().to_str().unwrap()).unwrap();
        assert!(id.did.starts_with("did:jwk:"));
        assert_eq!(id.public_jwk["kty"], "EC");
        assert_eq!(id.public_jwk["crv"], "P-256");
    }

    #[test]
    fn wallet_init_is_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let first = wallet_init(dir.path().to_str().unwrap()).unwrap();
        let second = wallet_init(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(first.did, second.did);
    }

    #[test]
    fn wallet_reset_returns_to_fresh_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let first = wallet_init(path).unwrap();
        assert!(wallet_exists(path));
        wallet_reset(path).unwrap();
        assert!(!wallet_exists(path));
        let second = wallet_init(path).unwrap();
        assert_ne!(first.did, second.did); // genuinely new identity, not the old one
    }

    #[test]
    fn software_key_signs() {
        let key = keys::software::SoftwareKey::generate();
        let sig = key.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64); // raw ECDSA P-256 (r||s)
    }
}
