//! Vaulet identity core — structured per PLAN.md D2–D5.
//!
//! Principle: everything touching keys/credentials/protocols lives in this
//! crate. Flutter is UI only, calling in over FFI (flutter_rust_bridge).
//! The same crate is reused by the backend (axum) and, later, WASM.

pub mod credential;
pub mod did;
pub mod keys;
pub mod mnemonic;
pub mod protocol;
pub mod recovery;
pub mod shamir;

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
        // Seed-first (ADR 0008): a fresh BIP39 mnemonic is the seed root; the
        // identity key is SLIP-0010 P-256 at m/1077'/0'/0'. We persist the
        // mnemonic (the backup root) AND the derived working key so the rest of
        // the core keeps reading wallet_key.jwk unchanged.
        let mnemonic = mnemonic::generate()?;
        let key = derive_identity_key(&mnemonic)?;
        std::fs::create_dir_all(storage_dir)
            .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
        std::fs::write(seed_path(storage_dir), &mnemonic)
            .map_err(|e| CoreError::Key(format!("write seed file: {e}")))?;
        std::fs::write(&key_path, key.to_jwk_string())
            .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;
        key
    };

    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// Path to the persisted seed root (the BIP39 mnemonic) — present on seed-first
/// wallets, absent on legacy (ADR 0001 Approach A) ones.
fn seed_path(storage_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(storage_dir).join("wallet_mnemonic.txt")
}

/// Derive the P-256 identity key from a BIP39 mnemonic via the seed (ADR 0008).
/// Errors on an invalid mnemonic before anything is written.
fn derive_identity_key(mnemonic: &str) -> Result<keys::software::SoftwareKey> {
    let seed = mnemonic::to_seed(mnemonic)?;
    let scalar = keys::hd::derive_identity_scalar(&seed);
    keys::software::SoftwareKey::from_scalar_bytes(&scalar)
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
    // Delete the seed root too (seed-first wallets).
    let seed = seed_path(storage_dir);
    if seed.exists() {
        std::fs::remove_file(&seed)
            .map_err(|e| CoreError::Key(format!("delete seed file: {e}")))?;
    }
    // Clear the phrase lock so a fresh identity can back up by phrase again.
    let marker = std::path::Path::new(storage_dir).join("phrase_locked");
    if marker.exists() {
        std::fs::remove_file(&marker)
            .map_err(|e| CoreError::Key(format!("clear phrase lock: {e}")))?;
    }
    Ok(())
}

/// Encrypt the on-device key into a passphrase-protected recovery file (M1
/// backup — PLAN.md D3). Returns the envelope JSON the UI saves to iCloud/Files.
pub fn wallet_export_backup(storage_dir: &str, passphrase: &str) -> Result<String> {
    // Seed-first: back up the SEED (mnemonic), so a restore re-derives every
    // facility, not just the identity key (ADR 0008). Legacy wallets back up the
    // raw key jwk as before.
    let seed = seed_path(storage_dir);
    let secret = if seed.exists() {
        std::fs::read_to_string(&seed)
            .map_err(|e| CoreError::Key(format!("read seed file: {e}")))?
    } else {
        let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
        std::fs::read_to_string(&key_path)
            .map_err(|e| CoreError::Key(format!("read key file: {e}")))?
    };
    recovery::encrypt_backup(secret.trim(), passphrase)
}

/// Restore a wallet from a recovery file + passphrase, writing the key to
/// `storage_dir` and returning the identity. Used by the onboarding restore flow.
pub fn wallet_import_backup(
    storage_dir: &str,
    envelope: &str,
    passphrase: &str,
) -> Result<did::WalletIdentity> {
    use keys::software::SoftwareKey;

    let plain = recovery::decrypt_backup(envelope, passphrase)?;

    std::fs::create_dir_all(storage_dir)
        .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");

    // Seed-first backups hold a mnemonic; legacy backups hold the raw key jwk.
    // A mnemonic parses via derive_identity_key; a jwk does not.
    let key = if let Ok(key) = derive_identity_key(plain.trim()) {
        std::fs::write(seed_path(storage_dir), plain.trim())
            .map_err(|e| CoreError::Key(format!("write seed file: {e}")))?;
        std::fs::write(&key_path, key.to_jwk_string())
            .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;
        key
    } else {
        let key = SoftwareKey::from_jwk(&plain)?;
        std::fs::write(&key_path, &plain)
            .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;
        key
    };

    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// Export the on-device identity as a 24-word BIP39 recovery phrase (ADR 0001,
/// approach A: the raw P-256 scalar IS the entropy — no seed, no passphrase).
/// This is an OPTIONAL second backup method beside the encrypted recovery file.
pub fn wallet_export_phrase(storage_dir: &str) -> Result<String> {
    use keys::software::SoftwareKey;

    if phrase_locked(storage_dir) {
        return Err(CoreError::Key("recovery phrase is locked on this device".into()));
    }
    // Seed-first wallet: the phrase IS the stored seed mnemonic (ADR 0008).
    let seed = seed_path(storage_dir);
    if seed.exists() {
        let mnemonic = std::fs::read_to_string(&seed)
            .map_err(|e| CoreError::Key(format!("read seed file: {e}")))?;
        return Ok(mnemonic.trim().to_string());
    }
    // Legacy (ADR 0001 Approach A): encode the raw scalar as the phrase.
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|e| CoreError::Key(format!("read key file: {e}")))?;
    let key = SoftwareKey::from_jwk(&jwk)?;
    mnemonic::encode_key(&key.to_scalar_bytes())
}

/// Restore a wallet from a 24-word recovery phrase, writing the key to
/// `storage_dir` and returning the identity. A bad word, wrong length, failed
/// checksum, or out-of-range scalar all fail before anything is written.
pub fn wallet_import_phrase(storage_dir: &str, phrase: &str) -> Result<did::WalletIdentity> {
    // Seed-first (ADR 0008): the phrase is the BIP39 seed; the identity key is
    // SLIP-0010 P-256 at m/1077'/0'/0'. Validates the phrase before writing.
    let phrase = phrase.trim();
    let key = derive_identity_key(phrase)?;

    std::fs::create_dir_all(storage_dir)
        .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
    std::fs::write(seed_path(storage_dir), phrase)
        .map_err(|e| CoreError::Key(format!("write seed file: {e}")))?;
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    std::fs::write(&key_path, key.to_jwk_string())
        .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;

    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// Split the identity key into `count` Shamir shares, any `threshold` of which
/// reconstruct it (ADR 0002, advanced backup). Returns the wrapped share
/// strings the UI hands to custodians. Gated by the same key-export lock as the
/// recovery phrase — both export raw key material.
pub fn wallet_split_shares(storage_dir: &str, threshold: u8, count: u8) -> Result<Vec<String>> {
    use keys::software::SoftwareKey;

    if phrase_locked(storage_dir) {
        return Err(CoreError::Key("key export is locked on this device".into()));
    }
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|e| CoreError::Key(format!("read key file: {e}")))?;
    let key = SoftwareKey::from_jwk(&jwk)?;
    shamir::split(&key.to_scalar_bytes(), threshold, count)
}

/// Reconstruct a wallet from Shamir shares, writing the key to `storage_dir`.
/// The share envelopes carry a checksum, so wrong or insufficient shares fail
/// before anything is written.
pub fn wallet_recover_from_shares(
    storage_dir: &str,
    shares: &[String],
) -> Result<did::WalletIdentity> {
    use keys::software::SoftwareKey;

    let secret = shamir::reconstruct(shares)?;
    let scalar: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Key("reconstructed key has the wrong size".into()))?;
    let key = SoftwareKey::from_scalar_bytes(&scalar)?;

    std::fs::create_dir_all(storage_dir)
        .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    std::fs::write(&key_path, key.to_jwk_string())
        .map_err(|e| CoreError::Key(format!("write key file: {e}")))?;

    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// Build the holder proof JWT for an OID4VCI credential request (pre-authorized
/// code flow, ADR 0004). Loads the on-device identity key, then produces the
/// ES256-signed `openid4vci-proof+jwt` that binds the holder to `issuer` (the
/// `aud`) over the token response `c_nonce`, embedding the holder public JWK
/// inline so the issuer copies it into the credential's `cnf.jwk`.
///
/// Returns the compact `header.payload.signature` string; Dart drops it into the
/// Credential Request `proof.jwt`. Network-free — Dart runs the token and
/// credential HTTP calls around this crypto step.
pub fn wallet_build_proof_jwt(
    storage_dir: &str,
    issuer: &str,
    c_nonce: &str,
    iat: i64,
) -> Result<String> {
    use keys::software::SoftwareKey;

    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|e| CoreError::Key(format!("read key file: {e}")))?;
    let key = SoftwareKey::from_jwk(&jwk)?;
    let holder_jwk = key.public_jwk()?;
    let proof = protocol::oid4vci::holder_proof(issuer, c_nonce, iat, holder_jwk, &key)?;
    Ok(proof.jwt)
}

/// Present a held SD-JWT VC to satisfy a Form's OID4VP ask (ADR 0003 form-gated
/// issuance). Loads the on-device identity key, then runs
/// [`credential::present`] over the stored issuer-signed `sd_jwt`, disclosing
/// exactly `disclose` (the claims the form's [`protocol::oid4vp::RequestedCredential`]
/// asks for) and appending a holder KB-JWT bound to `audience` (the form owner /
/// verifier) and `nonce` (the form's minted challenge).
///
/// Returns the compact KB-JWT-bearing presentation Dart puts in
/// [`protocol::oid4vp::SatisfyRequest::presentations`] — one call per required
/// credential. Network-free: Dart runs the presentation-request and satisfy HTTP
/// calls around this crypto step (ADR 0004).
pub fn wallet_present(
    storage_dir: &str,
    sd_jwt: &str,
    disclose: &[String],
    audience: &str,
    nonce: &str,
    iat: i64,
) -> Result<String> {
    use keys::software::SoftwareKey;

    let key_path = std::path::Path::new(storage_dir).join("wallet_key.jwk");
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|e| CoreError::Key(format!("read key file: {e}")))?;
    let key = SoftwareKey::from_jwk(&jwk)?;
    credential::present(sd_jwt, disclose, audience, nonce, &key, iat)
}

/// Ingest a received credential-response SD-JWT into a [`credential::StoredCredential`]:
/// verify it against the issuer's `did:web` document (Dart fetched the doc, so
/// this stays network-free) and cache its display. `issuer_did_doc` is the raw
/// `did.json` body; `hints` come from the issuer's OID4VCI metadata; `now` is the
/// caller's Unix clock. Rejects a bad signature or an expired credential.
pub fn wallet_ingest_credential(
    id: &str,
    sd_jwt: &str,
    issuer_did_doc: &str,
    now: i64,
    hints: credential::DisplayHints,
) -> Result<credential::StoredCredential> {
    let doc: serde_json::Value = serde_json::from_str(issuer_did_doc)
        .map_err(|e| CoreError::Credential(format!("issuer did.json parse: {e}")))?;
    credential::ingest_with_did_document(id, sd_jwt, &doc, now, hints)
}

/// Whether the recovery phrase may be revealed for this wallet.
///
/// M1 software-key era: true whenever a wallet exists AND the user has not
/// permanently locked phrase export (see [lock_phrase]). This is the policy
/// seam: once hardware keys (M3, Secure Enclave/StrongBox) hold the scalar
/// non-extractably, and once org/remote policy can forbid phrase export, those
/// paths gate this to false too. This is the single place that policy grows.
pub fn can_reveal_phrase(storage_dir: &str) -> bool {
    wallet_exists(storage_dir) && !phrase_locked(storage_dir)
}

fn phrase_locked(storage_dir: &str) -> bool {
    std::path::Path::new(storage_dir)
        .join("phrase_locked")
        .exists()
}

/// Permanently disable revealing the recovery phrase on this device, for
/// security once the user has written it down. Irreversible for this identity
/// (cleared only by [wallet_reset], which starts a fresh identity). The key
/// itself is untouched — the identity keeps working and stays recoverable from
/// the already-written phrase or the recovery file.
pub fn lock_phrase(storage_dir: &str) -> Result<()> {
    if !wallet_exists(storage_dir) {
        return Err(CoreError::Key("no wallet to lock".into()));
    }
    let marker = std::path::Path::new(storage_dir).join("phrase_locked");
    std::fs::write(&marker, b"1").map_err(|e| CoreError::Key(format!("lock phrase: {e}")))
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
    fn backup_export_import_restores_same_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let original = wallet_init(path).unwrap();

        let envelope = wallet_export_backup(path, "hunter2").unwrap();
        wallet_reset(path).unwrap();
        assert!(!wallet_exists(path));

        let restored = wallet_import_backup(path, &envelope, "hunter2").unwrap();
        assert_eq!(original.did, restored.did); // same identity recovered
        assert!(wallet_exists(path));
    }

    #[test]
    fn backup_import_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        wallet_init(path).unwrap();
        let envelope = wallet_export_backup(path, "right").unwrap();
        wallet_reset(path).unwrap();

        assert!(wallet_import_backup(path, &envelope, "wrong").is_err());
        assert!(!wallet_exists(path)); // nothing written on failure
    }

    #[test]
    fn phrase_export_import_restores_same_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let original = wallet_init(path).unwrap();

        let phrase = wallet_export_phrase(path).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        wallet_reset(path).unwrap();
        assert!(!wallet_exists(path));

        let restored = wallet_import_phrase(path, &phrase).unwrap();
        assert_eq!(original.did, restored.did); // same identity recovered
        assert!(wallet_exists(path));
    }

    #[test]
    fn phrase_import_garbage_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();

        assert!(wallet_import_phrase(path, "totally not a valid phrase").is_err());
        assert!(wallet_import_phrase(path, "abandon abandon abandon").is_err()); // too short
        assert!(!wallet_exists(path)); // nothing written on failure
    }

    #[test]
    fn phrase_import_tampered_checksum_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        wallet_init(path).unwrap();
        let phrase = wallet_export_phrase(path).unwrap();

        // Flip the last word to another valid wordlist entry, breaking the checksum.
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        let last = *words.last().unwrap();
        let replacement = if last == "zoo" { "zone" } else { "zoo" };
        *words.last_mut().unwrap() = replacement;
        let tampered = words.join(" ");

        assert!(wallet_import_phrase(path, &tampered).is_err());
    }

    #[test]
    fn can_reveal_phrase_tracks_wallet_existence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        assert!(!can_reveal_phrase(path));
        wallet_init(path).unwrap();
        assert!(can_reveal_phrase(path));
    }

    #[test]
    fn lock_phrase_disables_reveal_permanently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        wallet_init(path).unwrap();
        assert!(can_reveal_phrase(path));
        assert!(wallet_export_phrase(path).is_ok());

        lock_phrase(path).unwrap();
        assert!(!can_reveal_phrase(path)); // gate closed
        assert!(wallet_export_phrase(path).is_err()); // export refused
        // Restore-by-phrase still works (the written-down phrase is unaffected).

        // Reset clears the lock so a fresh identity can back up by phrase again.
        wallet_reset(path).unwrap();
        wallet_init(path).unwrap();
        assert!(can_reveal_phrase(path));
    }

    #[test]
    fn shamir_split_recover_restores_same_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let original = wallet_init(path).unwrap();

        let shares = wallet_split_shares(path, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        wallet_reset(path).unwrap();
        assert!(!wallet_exists(path));

        // Any 2 of 3 shares restore the same identity.
        let restored = wallet_recover_from_shares(path, &shares[1..3]).unwrap();
        assert_eq!(original.did, restored.did);
        assert!(wallet_exists(path));
    }

    #[test]
    fn shamir_one_share_or_locked_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        wallet_init(path).unwrap();
        let shares = wallet_split_shares(path, 2, 3).unwrap();
        wallet_reset(path).unwrap();
        // A single share must not recover.
        assert!(wallet_recover_from_shares(path, &shares[0..1]).is_err());
        assert!(!wallet_exists(path));

        // Locking key export blocks splitting.
        wallet_init(path).unwrap();
        lock_phrase(path).unwrap();
        assert!(wallet_split_shares(path, 2, 3).is_err());
    }

    #[test]
    fn software_key_signs() {
        let key = keys::software::SoftwareKey::generate();
        let sig = key.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64); // raw ECDSA P-256 (r||s)
    }

    #[test]
    fn wallet_present_produces_verifiable_vp() {
        use serde_json::{json, Map};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        // The on-device wallet key is the holder; issuer is a separate key.
        let identity = wallet_init(path).unwrap();
        let issuer = keys::software::SoftwareKey::generate();

        let mut disclosable = Map::new();
        disclosable.insert("email".into(), json!("somchai@codefin.io"));
        let sd_jwt = credential::issue(
            credential::IssueParams {
                vct: "https://issuer.example/credential/verified_email".into(),
                iss: "did:web:issuer.example".into(),
                iat: 1_700_000_000,
                exp: 1_700_000_000 + 3600,
                holder_jwk: identity.public_jwk.clone(),
                disclosable,
                visible: Map::new(),
            },
            &issuer,
        )
        .unwrap();

        // Present the held VC through the storage-loading wallet path.
        let vp = wallet_present(
            path,
            &sd_jwt,
            &["email".into()],
            "https://issuer.example",
            "vp-nonce-123",
            1_700_000_100,
        )
        .unwrap();

        // The form owner verifies the VP against the issuer key + ask binding.
        let verified = credential::verify_presentation(
            &vp,
            &issuer.public_jwk().unwrap(),
            "https://issuer.example",
            "vp-nonce-123",
            1_700_000_200,
        )
        .unwrap();
        assert_eq!(verified.claims["email"], json!("somchai@codefin.io"));

        // Wrong nonce (replay) must be rejected by the verifier.
        assert!(credential::verify_presentation(
            &vp,
            &issuer.public_jwk().unwrap(),
            "https://issuer.example",
            "wrong-nonce",
            1_700_000_200,
        )
        .is_err());
    }
}
