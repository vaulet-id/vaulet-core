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
use zeroize::Zeroizing;

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
// Key storage & security (ADR 0008, seed-first + Keychain).
//
// The wallet SECRET is never persisted by the core. It lives only in platform
// secure storage (iOS Keychain, `ThisDeviceOnly` — encrypted at rest, excluded
// from backups, non-migratable = anti-clone). Dart reads it from the Keychain,
// holds the unlocked value in the FFI bridge session, and passes it into these
// pure functions per call. The core is stateless: given the same secret it
// derives the same identity, signs, backs up, and restores — and writes nothing
// sensitive to disk.
//
// A `secret` is one of:
//   * seed-first BIP39 mnemonic (ADR 0008) — the normal case; the identity key
//     is SLIP-0010 P-256 at m/1077'/0'/0' derived from its seed;
//   * legacy raw-key JWK (ADR 0001 Approach A) — the private scalar itself,
//     kept working for wallets created before the seed-first migration.
// The two are told apart by whether the string parses as a BIP39 mnemonic.
// ---------------------------------------------------------------------------

/// Load the P-256 identity key from a wallet secret (seed mnemonic or legacy jwk).
fn load_secret_key(secret: &str) -> Result<keys::software::SoftwareKey> {
    let s = secret.trim();
    if let Ok(key) = derive_identity_key(s) {
        return Ok(key); // seed-first mnemonic (ADR 0008)
    }
    keys::software::SoftwareKey::from_jwk(s) // legacy raw-key jwk (ADR 0001)
}

/// Derive the P-256 identity key from a BIP39 mnemonic via its seed (ADR 0008):
/// SLIP-0010 P-256 at m/1077'/0'/0'. Errors on an invalid mnemonic.
fn derive_identity_key(mnemonic: &str) -> Result<keys::software::SoftwareKey> {
    let seed = Zeroizing::new(mnemonic::to_seed(mnemonic)?);
    let scalar = Zeroizing::new(keys::hd::derive_identity_scalar(seed.as_slice()));
    keys::software::SoftwareKey::from_scalar_bytes(&scalar)
}

/// The public identity (did:jwk + public JWK) for an in-memory key.
fn identity_of(key: &keys::software::SoftwareKey) -> Result<did::WalletIdentity> {
    let public_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&public_jwk)?;
    Ok(did::WalletIdentity { did, public_jwk })
}

/// The wallet identity for a secret. Pure — the bridge calls this on unlock and
/// after any restore, then derives nothing else from disk.
pub fn wallet_identity(secret: &str) -> Result<did::WalletIdentity> {
    identity_of(&load_secret_key(secret)?)
}

/// Generate a fresh seed-first wallet secret: a 24-word BIP39 mnemonic (the seed
/// root, ADR 0008). The bridge stores it in the Keychain; it never hits disk.
pub fn wallet_generate_secret() -> Result<String> {
    mnemonic::generate()
}

/// Read a legacy PLAINTEXT wallet secret left by a pre-Keychain build, for a
/// one-time migration into the Keychain: the seed-first mnemonic file if present,
/// else the Approach-A raw-key jwk. `None` when there is nothing to migrate.
/// After the caller stores the returned secret in the Keychain it should call
/// [`wallet_reset`] to delete these files.
pub fn read_legacy_secret(storage_dir: &str) -> Option<String> {
    for name in ["wallet_mnemonic.txt", "wallet_key.jwk"] {
        let p = std::path::Path::new(storage_dir).join(name);
        if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Delete on-device wallet artifacts on reset: the phrase-lock marker and any
/// legacy plaintext key/seed files from pre-Keychain builds. The Keychain secret
/// itself is cleared by the platform side (Dart).
pub fn wallet_reset(storage_dir: &str) -> Result<()> {
    for name in ["phrase_locked", "wallet_key.jwk", "wallet_mnemonic.txt"] {
        let p = std::path::Path::new(storage_dir).join(name);
        if p.exists() {
            std::fs::remove_file(&p)
                .map_err(|e| CoreError::Key(format!("delete {name}: {e}")))?;
        }
    }
    Ok(())
}

/// Encrypt the wallet secret into a passphrase-protected recovery file (M1
/// backup, PLAN.md D3). Seed-first backups carry the mnemonic so a restore
/// re-derives every facility (ADR 0008); legacy backups carry the raw jwk.
pub fn wallet_export_backup(secret: &str, passphrase: &str) -> Result<String> {
    recovery::encrypt_backup(secret.trim(), passphrase)
}

/// Decrypt a recovery file to the wallet secret it holds. The bridge stores the
/// returned secret in the Keychain and derives the identity from it. A wrong
/// passphrase or corrupt/garbage envelope fails before anything is stored.
pub fn wallet_import_backup(envelope: &str, passphrase: &str) -> Result<String> {
    let plain = recovery::decrypt_backup(envelope, passphrase)?;
    let secret = plain.trim().to_string();
    load_secret_key(&secret)?; // validate: must load as a seed or legacy jwk
    Ok(secret)
}

/// Validate a 24-word recovery phrase and return it as the wallet secret
/// (seed-first, ADR 0008). A bad word, wrong length, or failed checksum errors.
pub fn wallet_import_phrase(phrase: &str) -> Result<String> {
    let secret = phrase.trim().to_string();
    derive_identity_key(&secret)?; // validates the mnemonic
    Ok(secret)
}

/// The human recovery phrase for a secret: seed-first returns the mnemonic
/// itself; legacy encodes the raw scalar as an Approach-A phrase (ADR 0001).
pub fn wallet_reveal_phrase(secret: &str) -> Result<String> {
    let s = secret.trim();
    if mnemonic::to_seed(s).is_ok() {
        return Ok(s.to_string()); // seed-first mnemonic
    }
    let key = keys::software::SoftwareKey::from_jwk(s)?;
    mnemonic::encode_key(&key.to_scalar_bytes()) // legacy scalar → Approach-A phrase
}

/// Whether phrase reveal is permanently locked on this device — a NON-secret
/// policy marker (the secret lives in the Keychain, untouched). This is the
/// policy seam: hardware-key and org-policy gates grow here (see [`lock_phrase`]).
pub fn is_phrase_locked(storage_dir: &str) -> bool {
    std::path::Path::new(storage_dir).join("phrase_locked").exists()
}

/// Permanently disable revealing the recovery phrase on this device, once the
/// user has written it down. Irreversible until [`wallet_reset`]. Touches only a
/// non-secret marker file — the secret is never read or written here.
pub fn lock_phrase(storage_dir: &str) -> Result<()> {
    std::fs::create_dir_all(storage_dir)
        .map_err(|e| CoreError::Key(format!("create storage dir: {e}")))?;
    let marker = std::path::Path::new(storage_dir).join("phrase_locked");
    std::fs::write(&marker, b"1").map_err(|e| CoreError::Key(format!("lock phrase: {e}")))
}

/// The 32-byte BIP39 entropy behind a seed-first mnemonic — the secret Shamir
/// splits, so recovery rebuilds the mnemonic (not just the derived scalar).
fn mnemonic_entropy(secret: &str) -> Result<[u8; 32]> {
    use bip39::Mnemonic;
    let m = Mnemonic::parse(secret.trim())
        .map_err(|_| CoreError::Key("advanced backup needs a seed-first wallet".into()))?;
    let (entropy, len) = m.to_entropy_array();
    if len != 32 {
        return Err(CoreError::Key("advanced backup needs a 24-word seed".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&entropy[..32]);
    Ok(out)
}

/// Split the wallet secret into `count` Shamir shares, any `threshold` of which
/// reconstruct it (ADR 0002, advanced backup). Seed-first splits the 32-byte
/// BIP39 entropy; [`wallet_recover_from_shares`] rebuilds the mnemonic from it.
pub fn wallet_split_shares(secret: &str, threshold: u8, count: u8) -> Result<Vec<String>> {
    let entropy = mnemonic_entropy(secret)?;
    shamir::split(&entropy, threshold, count)
}

/// Reconstruct the wallet secret (seed mnemonic) from Shamir shares. The share
/// envelopes carry a checksum, so wrong or insufficient shares fail cleanly.
pub fn wallet_recover_from_shares(shares: &[String]) -> Result<String> {
    let secret = shamir::reconstruct(shares)?;
    let entropy: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Key("reconstructed seed has the wrong size".into()))?;
    mnemonic::encode_key(&entropy) // 32-byte entropy → the 24-word seed mnemonic
}

/// Build the ES256 holder proof JWT (`openid4vci-proof+jwt`) for an OID4VCI
/// Credential Request (ADR 0004): binds the on-device identity key to `issuer`
/// (the `aud`) over the token response `c_nonce`, embedding the holder public
/// JWK inline for the issuer to copy into `cnf.jwk`. Network-free; `iat` is Unix
/// seconds from the caller.
pub fn wallet_build_proof_jwt(
    secret: &str,
    issuer: &str,
    c_nonce: &str,
    iat: i64,
) -> Result<String> {
    let key = load_secret_key(secret)?;
    let holder_jwk = key.public_jwk()?;
    let proof = protocol::oid4vci::holder_proof(issuer, c_nonce, iat, holder_jwk, &key)?;
    Ok(proof.jwt)
}

/// Present a held SD-JWT VC to satisfy a Form's OID4VP ask (ADR 0003 form-gated
/// issuance): disclose exactly `disclose` from the stored issuer-signed `sd_jwt`
/// and append a holder KB-JWT bound to `audience` (verifier) and `nonce` (the
/// form's challenge). Returns the compact KB-JWT-bearing presentation. Network-
/// free; `iat` is Unix seconds from the caller.
pub fn wallet_present(
    secret: &str,
    sd_jwt: &str,
    disclose: &[String],
    audience: &str,
    nonce: &str,
    iat: i64,
) -> Result<String> {
    let key = load_secret_key(secret)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh seed-first wallet: (secret mnemonic, its identity).
    fn new_wallet() -> (String, did::WalletIdentity) {
        let secret = wallet_generate_secret().unwrap();
        let id = wallet_identity(&secret).unwrap();
        (secret, id)
    }

    #[test]
    fn generate_creates_did_jwk() {
        let (_secret, id) = new_wallet();
        assert!(id.did.starts_with("did:jwk:"));
        assert_eq!(id.public_jwk["kty"], "EC");
        assert_eq!(id.public_jwk["crv"], "P-256");
    }

    #[test]
    fn identity_is_stable_for_a_secret() {
        let (secret, id) = new_wallet();
        assert_eq!(wallet_identity(&secret).unwrap().did, id.did);
    }

    #[test]
    fn distinct_secrets_give_distinct_identities() {
        let (_s1, a) = new_wallet();
        let (_s2, b) = new_wallet();
        assert_ne!(a.did, b.did);
    }

    #[test]
    fn backup_export_import_restores_same_secret_and_did() {
        let (secret, id) = new_wallet();
        let envelope = wallet_export_backup(&secret, "hunter2").unwrap();
        let restored = wallet_import_backup(&envelope, "hunter2").unwrap();
        assert_eq!(restored, secret);
        assert_eq!(wallet_identity(&restored).unwrap().did, id.did);
    }

    #[test]
    fn backup_import_wrong_passphrase_fails() {
        let (secret, _) = new_wallet();
        let envelope = wallet_export_backup(&secret, "right").unwrap();
        assert!(wallet_import_backup(&envelope, "wrong").is_err());
    }

    #[test]
    fn phrase_export_import_restores_same_did() {
        let (secret, id) = new_wallet();
        let phrase = wallet_reveal_phrase(&secret).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let restored = wallet_import_phrase(&phrase).unwrap();
        assert_eq!(wallet_identity(&restored).unwrap().did, id.did);
    }

    #[test]
    fn phrase_import_garbage_fails() {
        assert!(wallet_import_phrase("totally not a valid phrase").is_err());
        assert!(wallet_import_phrase("abandon abandon abandon").is_err()); // too short
    }

    #[test]
    fn phrase_import_tampered_checksum_fails() {
        let (secret, _) = new_wallet();
        let phrase = wallet_reveal_phrase(&secret).unwrap();
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        let last = *words.last().unwrap();
        let replacement = if last == "zoo" { "zone" } else { "zoo" };
        *words.last_mut().unwrap() = replacement;
        assert!(wallet_import_phrase(&words.join(" ")).is_err());
    }

    #[test]
    fn shamir_split_recover_restores_same_did() {
        let (secret, id) = new_wallet();
        let shares = wallet_split_shares(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        // Any 2 of 3 shares rebuild the exact seed mnemonic → same identity.
        let recovered = wallet_recover_from_shares(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);
        assert_eq!(wallet_identity(&recovered).unwrap().did, id.did);
    }

    #[test]
    fn shamir_one_share_fails() {
        let (secret, _) = new_wallet();
        let shares = wallet_split_shares(&secret, 2, 3).unwrap();
        assert!(wallet_recover_from_shares(&shares[0..1]).is_err());
    }

    #[test]
    fn phrase_lock_marker_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        assert!(!is_phrase_locked(path));
        lock_phrase(path).unwrap();
        assert!(is_phrase_locked(path));
        wallet_reset(path).unwrap();
        assert!(!is_phrase_locked(path)); // reset clears the lock
    }

    #[test]
    fn legacy_jwk_secret_still_works() {
        // A legacy Approach-A wallet stores a raw-key jwk as its secret.
        let key = keys::software::SoftwareKey::generate();
        let jwk = key.to_jwk_string();
        let id = wallet_identity(&jwk).unwrap();
        assert!(id.did.starts_with("did:jwk:"));
        // Reveal returns the Approach-A phrase encoding (24 words), no panic.
        let phrase = wallet_reveal_phrase(&jwk).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn read_legacy_secret_prefers_mnemonic_then_jwk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let p = path.to_str().unwrap();
        assert!(read_legacy_secret(p).is_none());
        std::fs::write(path.join("wallet_key.jwk"), "jwk-content").unwrap();
        assert_eq!(read_legacy_secret(p).as_deref(), Some("jwk-content"));
        std::fs::write(path.join("wallet_mnemonic.txt"), "seed words").unwrap();
        assert_eq!(read_legacy_secret(p).as_deref(), Some("seed words"));
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

        // The on-device wallet key is the holder; issuer is a separate key.
        let (secret, identity) = new_wallet();
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

        // Present the held VC through the secret-loading wallet path.
        let vp = wallet_present(
            &secret,
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
