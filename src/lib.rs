//! Vaulet identity core — structured per PLAN.md D2–D5.
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
pub mod vouching;
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
            std::fs::remove_file(&p).map_err(|e| CoreError::Key(format!("delete {name}: {e}")))?;
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
    Ok(wallet_import_vault(envelope, passphrase)?.secret)
}

/// Marks a backup that carries more than the key. Checked by name rather than
/// by shape, because a legacy backup holds a JWK — which is also JSON, and
/// would be misread by anything that guessed from the first character.
const VAULT_MARKER: &str = "vaulet_backup";

/// What a recovery file restores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    /// The seed (or, for old files, the legacy JWK).
    pub secret: String,
    /// Everything else the wallet held, as the platform wrote it. Opaque here
    /// on purpose: the core has no opinion about credential storage, and a
    /// backup format that had to be taught about each new kind of card would go
    /// stale the first time one was added.
    ///
    /// Empty for a file written before backups carried anything but the key.
    pub contents: String,
}

/// Encrypt the wallet **and what it holds** into one recovery file (PLAN.md D3).
///
/// A seed restores an identity. It does not restore credentials: those were
/// issued to it, are held only on the device, and are gone when the app is
/// deleted — which is a wallet that loses everything in it while insisting the
/// keys are safe. So a backup carries them too.
///
/// The envelope is the same one [`wallet_export_backup`] writes, with a
/// structured payload inside, so **an older build still opens a newer file** as
/// far as the key is concerned. That matters: a recovery file is opened on the
/// worst day somebody has, often on a device that has not been updated.
pub fn wallet_export_vault(secret: &str, contents: &str, passphrase: &str) -> Result<String> {
    let payload = serde_json::json!({
        VAULT_MARKER: 1,
        "secret": secret.trim(),
        "contents": contents,
    });
    recovery::encrypt_backup(&payload.to_string(), passphrase)
}

/// Open a recovery file of either shape.
pub fn wallet_import_vault(envelope: &str, passphrase: &str) -> Result<Vault> {
    let plain = recovery::decrypt_backup(envelope, passphrase)?;

    let vault = match serde_json::from_str::<serde_json::Value>(&plain) {
        Ok(doc) if doc.get(VAULT_MARKER).is_some() => Vault {
            secret: doc
                .get("secret")
                .and_then(|s| s.as_str())
                .ok_or_else(|| CoreError::Key("backup has no secret".into()))?
                .trim()
                .to_string(),
            contents: doc
                .get("contents")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_string(),
        },
        // Anything else is a file from before this format — including a legacy
        // JWK, which parses as JSON and must not be mistaken for a vault.
        _ => Vault {
            secret: plain.trim().to_string(),
            contents: String::new(),
        },
    };

    // Validated before anything is stored: a file that does not hold a usable
    // seed must fail here rather than half-restore a wallet.
    load_secret_key(&vault.secret)?;
    Ok(vault)
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
    std::path::Path::new(storage_dir)
        .join("phrase_locked")
        .exists()
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
/// The same, for the Simple Recovery module (ADR 0019), which splits the very
/// same 32 bytes rather than a second secret derived from them.
pub(crate) fn mnemonic_entropy_public(secret: &str) -> Result<[u8; 32]> {
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
///
/// `cb` is the channel-binding token the server issued with the session, echoed
/// back as the `cb` claim (liveness-pad-spec §5.1 E). Pass `None` where the
/// server issued none: the JWT is then exactly the one this call produced before
/// the parameter existed.
pub fn wallet_build_proof_jwt(
    secret: &str,
    issuer: &str,
    c_nonce: &str,
    iat: i64,
    cb: Option<&str>,
) -> Result<String> {
    let key = load_secret_key(secret)?;
    let holder_jwk = key.public_jwk()?;
    let proof = protocol::oid4vci::holder_proof_bound(issuer, c_nonce, iat, cb, holder_jwk, &key)?;
    Ok(proof.jwt)
}

/// `typ` of a Studio sign-in JWT.
///
/// Shared with the server (`studio_auth::SIGNIN_JWT_TYP`) rather than written
/// twice: they have to agree or every sign-in fails with "wrong proof typ" and
/// nothing anywhere says why.
pub const STUDIO_SIGNIN_JWT_TYP: &str = "vaulet-studio-signin+jwt";

/// Sign a Studio sign-in challenge.
///
/// The same ES256 signature over the same `aud` + `nonce` as an issuance proof,
/// under a **different `typ`**. Audience and nonce already stop either being
/// replayed as the other; the separate typ means a reader learns what a
/// signature was for from one field rather than three, and lets the server
/// refuse an issuance proof offered as a sign-in.
pub fn wallet_build_signin_jwt(
    secret: &str,
    audience: &str,
    nonce: &str,
    iat: i64,
) -> Result<String> {
    use protocol::oid4vci::{build_proof_jwt, ProofJwtClaims, ProofJwtHeader};
    let key = load_secret_key(secret)?;
    let header = ProofJwtHeader {
        typ: STUDIO_SIGNIN_JWT_TYP.to_string(),
        alg: "ES256".to_string(),
        jwk: Some(key.public_jwk()?),
        kid: None,
    };
    let claims = ProofJwtClaims {
        iss: None,
        aud: audience.to_string(),
        iat,
        nonce: nonce.to_string(),
        cb: None,
    };
    build_proof_jwt(&header, &claims, &key)
}

/// `typ` of the JWT that starts connecting an outside account (ADR 0024).
///
/// Its own `typ` for the same reason the sign-in has one: a signature says what
/// it was for in one field, and a Studio sign-in must not be spendable as
/// permission to attach somebody's Google account to a wallet.
pub const SOCIAL_CONNECT_JWT_TYP: &str = "vaulet-connect-account+jwt";

/// Sign the challenge that begins a Google or Facebook connection.
///
/// The provider redirects to the issuer, not to the phone, so the issuer has to
/// know which wallet asked before it sends anybody anywhere. This signature is
/// that answer, and the credential at the end is issued to this key alone.
pub fn wallet_build_connect_jwt(
    secret: &str,
    audience: &str,
    nonce: &str,
    iat: i64,
) -> Result<String> {
    use protocol::oid4vci::{build_proof_jwt, ProofJwtClaims, ProofJwtHeader};
    let key = load_secret_key(secret)?;
    let header = ProofJwtHeader {
        typ: SOCIAL_CONNECT_JWT_TYP.to_string(),
        alg: "ES256".to_string(),
        jwk: Some(key.public_jwk()?),
        kid: None,
    };
    let claims = ProofJwtClaims {
        iss: None,
        aud: audience.to_string(),
        iat,
        nonce: nonce.to_string(),
        cb: None,
    };
    build_proof_jwt(&header, &claims, &key)
}

/// `typ` of the JWT that joins an organisation's key list (ADR 0020).
///
/// Its own `typ`, like the others, and here the reason is concrete: a Studio
/// sign-in and a join are both "this phone signed a nonce Vaulet minted". If
/// they shared a `typ`, a sign-in proof captured anywhere could be presented as
/// consent to put that phone in somebody's organisation — and the person would
/// find out by appearing in a company's public identity document.
pub const ORG_JOIN_JWT_TYP: &str = "vaulet-org-join+jwt";

/// Sign the invitation that adds this phone to an organisation.
pub fn wallet_build_join_jwt(
    secret: &str,
    audience: &str,
    nonce: &str,
    iat: i64,
) -> Result<String> {
    use protocol::oid4vci::{build_proof_jwt, ProofJwtClaims, ProofJwtHeader};
    let key = load_secret_key(secret)?;
    let header = ProofJwtHeader {
        typ: ORG_JOIN_JWT_TYP.to_string(),
        alg: "ES256".to_string(),
        jwk: Some(key.public_jwk()?),
        kid: None,
    };
    let claims = ProofJwtClaims {
        iss: None,
        aud: audience.to_string(),
        iat,
        nonce: nonce.to_string(),
        cb: None,
    };
    build_proof_jwt(&header, &claims, &key)
}

/// Sign the fields a holder typed into a form (ADR 0014).
///
/// `claims` is the JSON object of answers, keyed by the form's JSON Schema
/// property names. Signed rather than sent plain so the submission is
/// non-repudiable (PLAN D7), and bound to the form owner and the presentation
/// nonce so answers cannot be moved between requests.
pub fn wallet_sign_form_claims(
    secret: &str,
    audience: &str,
    nonce: &str,
    iat: i64,
    claims_json: &str,
) -> Result<String> {
    let key = load_secret_key(secret)?;
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(claims_json)
        .map_err(|e| CoreError::Protocol(format!("form claims json: {e}")))?;
    protocol::oid4vp::sign_form_claims(audience, nonce, iat, claims, key.public_jwk()?, &key)
}

/// Verify an ePassport read (ADR 0009): data-group integrity against EF.SOD, plus
/// SOD signature / DSC→CSCA chain / Active Authentication (staged). `dgs` maps DG
/// number → raw EF bytes; `csca` is the trust store (may be empty); `aa` is
/// `(dg15, challenge, signature)` when supported.
pub fn wallet_verify_passport(
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

/// Self-issue an SD-JWT VC signed by the identity key — the issuer and holder are
/// both the user's own did:jwk (a self-asserted credential, ADR: self-asserted =
/// lowest assurance). `claims_json` is a JSON object of always-visible (Z2)
/// claims. Used e.g. to store a liveness scan result in the wallet.
pub fn wallet_self_issue(secret: &str, vct: &str, claims_json: &str, iat: i64) -> Result<String> {
    let key = load_secret_key(secret)?;
    let holder_jwk = key.public_jwk()?;
    let did = did::did_jwk_from_public(&holder_jwk)?;
    let visible: serde_json::Map<String, serde_json::Value> = serde_json::from_str(claims_json)
        .map_err(|e| CoreError::Credential(format!("self-issue claims json: {e}")))?;
    let params = credential::IssueParams {
        vct: vct.to_string(),
        iss: did,
        iat,
        exp: iat + 315_360_000, // ~10 years
        holder_jwk,
        disclosable: serde_json::Map::new(),
        member_disclosable: Default::default(),
        visible,
    };
    credential::issue(params, &key)
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

/// Read what somebody is being asked to sign, without signing it (ADR 0029).
///
/// **Rendered from the bytes that will be signed**, not from a catalogue the
/// app fetched separately — the template arrives inside the ask and its hash
/// goes inside the signature, so what a person reads on the consent screen is
/// what they put their name to. A wallet that rendered from anywhere else would
/// be showing a sentence nobody signed.
pub fn wallet_read_statement_ask(ask_json: &str, lang: &str) -> Result<String> {
    let ask: statement::Ask = serde_json::from_str(ask_json)
        .map_err(|e| CoreError::Protocol(format!("statement ask: {e}")))?;
    let act = statement::Act::parse(&ask.act)
        .ok_or_else(|| CoreError::Protocol(format!("unknown act {}", ask.act)))?;
    // Through `seal`, so the consent screen refuses exactly what the issuer
    // would refuse — a missing value, a term on an act that takes none — rather
    // than showing a sentence with a hole in it and failing at the far end.
    statement::Statement {
        act,
        subject: ask.subject,
        fields: ask.fields,
        template: ask.template,
        lang: lang.to_string(),
    }
    .seal()
    .map(|signed| signed.text)
}

/// Sign what was asked, with the holder's own key.
///
/// `holder_jwk` is whoever will hold the statement — the party it was made out
/// to. The signer is this wallet, and the two are different by design: a
/// statement about somebody else is held by that somebody else.
#[allow(clippy::too_many_arguments)]
pub fn wallet_sign_statement(
    secret: &str,
    ask_json: &str,
    lang: &str,
    vct: &str,
    holder_jwk: &str,
    iat: i64,
    exp: i64,
) -> Result<String> {
    let ask: statement::Ask = serde_json::from_str(ask_json)
        .map_err(|e| CoreError::Protocol(format!("statement ask: {e}")))?;
    let act = statement::Act::parse(&ask.act)
        .ok_or_else(|| CoreError::Protocol(format!("unknown act {}", ask.act)))?;
    let key = load_secret_key(secret)?;
    let signer_did = did::did_jwk_from_public(&key.public_jwk()?)?;
    let holder: serde_json::Value = serde_json::from_str(holder_jwk)
        .map_err(|e| CoreError::Protocol(format!("holder jwk: {e}")))?;
    statement::issue_statement(
        statement::Statement {
            act,
            subject: ask.subject,
            fields: ask.fields,
            template: ask.template,
            lang: lang.to_string(),
        },
        vct,
        &signer_did,
        holder,
        iat,
        exp,
    &key,
    )
}

/// Ingest a received credential-response SD-JWT into a [`credential::StoredCredential`]:
/// verify it against the issuer's `did:web` document (Dart fetched the doc, so
/// this stays network-free) and cache its display. `issuer_did_doc` is the raw
/// `did.json` body; `hints` come from the issuer's OID4VCI metadata; `now` is the
/// caller's Unix clock. `pinned` are the RFC 7638 thumbprints the trust registry
/// pins for this issuer (empty = not pinned): when set, the verifying key must
/// match one — anchoring trust in the issuer KEY, not the TLS transport. Rejects
/// a bad signature, an expired credential, or an unpinned issuer key.
pub fn wallet_ingest_credential(
    id: &str,
    sd_jwt: &str,
    issuer_did_doc: &str,
    now: i64,
    hints: credential::DisplayHints,
    pinned: &[String],
) -> Result<credential::StoredCredential> {
    let doc: serde_json::Value = serde_json::from_str(issuer_did_doc)
        .map_err(|e| CoreError::Credential(format!("issuer did.json parse: {e}")))?;
    credential::ingest_with_did_document(id, sd_jwt, &doc, now, hints, pinned)
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

    /// The whole point: a restore that returns the identity but not what was
    /// issued to it is a wallet that lost everything in it.
    #[test]
    fn a_backup_carries_the_credentials_as_well_as_the_key() {
        let (secret, id) = new_wallet();
        let held = r#"{"credentials":[{"vct":"employee-badge"}]}"#;

        let envelope = wallet_export_vault(&secret, held, "hunter2").unwrap();
        let vault = wallet_import_vault(&envelope, "hunter2").unwrap();

        assert_eq!(vault.secret, secret);
        assert_eq!(vault.contents, held);
        assert_eq!(wallet_identity(&vault.secret).unwrap().did, id.did);
    }

    /// A recovery file is opened on the worst day somebody has, often on a
    /// device that has not been updated — so both directions have to work.
    #[test]
    fn an_old_backup_still_opens_and_a_new_one_still_yields_its_key() {
        let (secret, _) = new_wallet();

        let old = wallet_export_backup(&secret, "pw").unwrap();
        let vault = wallet_import_vault(&old, "pw").unwrap();
        assert_eq!(vault.secret, secret);
        assert!(vault.contents.is_empty(), "there was nothing else in it");

        let new = wallet_export_vault(&secret, "anything at all", "pw").unwrap();
        assert_eq!(wallet_import_backup(&new, "pw").unwrap(), secret);
    }

    /// A legacy backup holds a JWK, which is also JSON. Guessing the format
    /// from the first character would restore the string `{"kty":…}` as a
    /// secret and lose the wallet.
    #[test]
    fn a_legacy_jwk_backup_is_not_mistaken_for_a_vault() {
        let jwk = keys::software::SoftwareKey::generate().to_jwk_string();

        let envelope = wallet_export_backup(&jwk, "pw").unwrap();
        let vault = wallet_import_vault(&envelope, "pw").unwrap();
        assert_eq!(vault.secret, jwk);
        assert!(vault.contents.is_empty());
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
                member_disclosable: Default::default(),
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
