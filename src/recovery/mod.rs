//! Recovery-file encryption.
//!
//! Encrypts the private-key JWK with a user passphrase so it can be exported to
//! a file (iCloud Drive / Files) and restored on another device. Non-custodial:
//! the passphrase never leaves the device and we never see the key — losing the
//! passphrase means the backup is unrecoverable.
//!
//! Scheme: Argon2id(passphrase, salt) -> 32-byte key -> XChaCha20-Poly1305 seal.
//! The M3 Shamir path (2-of-3) will split this same JWK instead of encrypting it.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{CoreError, Result};

pub mod simple;

// Argon2id parameters — kept in the envelope so a future decrypt can reproduce
// the derivation even if these defaults change.
// Hardened for an offline-attackable backup file protecting a root seed: well
// above the OWASP Argon2id minimum (19 MiB / t=2). ~64 MiB / t=3 costs an
// attacker far more per passphrase guess while staying ~sub-second on a phone.
const KDF_MEM_KIB: u32 = 65_536; // 64 MiB
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 1;
// PIN seal (app unlock): the sealed seed already sits behind the Secure Enclave
// (ThisDeviceOnly) + a failed-attempt backoff, so the KDF is a defence-in-depth
// layer, not the sole barrier. Lighter params (OWASP interactive minimum) keep
// every unlock snappy instead of the ~1s a 64 MiB derive costs.
const PIN_KDF_MEM_KIB: u32 = 19_456; // 19 MiB
const PIN_KDF_ITERS: u32 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20 nonce
const KEY_LEN: usize = 32;

/// Seal bytes under a 32-byte key, returning `nonce || ciphertext`.
///
/// For things the **server** holds on somebody's behalf for a while — a
/// companion's presentation waiting for the applicant to finish (ADR 0027).
/// Not a recovery file: there is no passphrase and no key derivation, because
/// the key here is one the caller already has and keeps somewhere the ciphertext
/// is not.
///
/// XChaCha20-Poly1305 with a random 24-byte nonce, which is wide enough that
/// random generation needs no counter and no coordination between processes.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| CoreError::Key("seal failed".into()))?,
    );
    Ok(out)
}

/// Open what [`seal`] produced. Fails on a wrong key or a changed byte —
/// there is no partial success, which is the point of an AEAD.
pub fn unseal(key: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() <= NONCE_LEN {
        return Err(CoreError::Key("sealed value is truncated".into()));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| CoreError::Key("wrong key, or the sealed value was altered".into()))
}

/// On-disk recovery-file envelope. Everything but the plaintext key.
#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    kdf: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,  // base64
    nonce: String, // base64
    ct: String,    // base64 (ciphertext + AEAD tag)
}

/// Derive the AEAD key from the passphrase and salt with Argon2id.
fn derive_key(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(m, t, p, Some(KEY_LEN))
        .map_err(|e| CoreError::Key(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CoreError::Key(format!("argon2 derive: {e}")))?;
    Ok(key)
}

/// The same derivation, for the Simple Recovery module (ADR 0019). It masks a
/// share rather than sealing one, so it needs the key and not the envelope.
pub(crate) fn derive_key_public(
    passphrase: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<[u8; KEY_LEN]> {
    derive_key(passphrase, salt, m, t, p)
}

/// Seal bytes under a key that was derived elsewhere — the wallet contents in a
/// Simple Recovery file, whose key comes from the seed rather than a passphrase.
pub(crate) fn seal_with_key(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| CoreError::Key(format!("encrypt: {e}")))?;
    Ok(format!(
        "{}.{}",
        STANDARD.encode(nonce),
        STANDARD.encode(ct)
    ))
}

/// Open what [`seal_with_key`] produced.
pub(crate) fn open_with_key(key: &[u8; KEY_LEN], sealed: &str) -> Result<String> {
    let (nonce_b64, ct_b64) = sealed
        .trim()
        .split_once('.')
        .ok_or_else(|| CoreError::Key("malformed sealed contents".into()))?;
    let nonce = STANDARD
        .decode(nonce_b64)
        .map_err(|_| CoreError::Key("malformed sealed contents".into()))?;
    let ct = STANDARD
        .decode(ct_b64)
        .map_err(|_| CoreError::Key("malformed sealed contents".into()))?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| CoreError::Key("could not open the backup contents".into()))?;
    String::from_utf8(plain).map_err(|_| CoreError::Key("backup contents are not text".into()))
}

/// Encrypt a secret into an envelope with the given Argon2id memory/iterations.
/// The params are stored in the envelope, so `decrypt_backup` reproduces them.
fn encrypt_with(secret: &str, passphrase: &str, m: u32, t: u32) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    rand_core::OsRng.fill_bytes(&mut nonce);

    let mut key = derive_key(passphrase, &salt, m, t, KDF_LANES)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    key.zeroize();

    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), secret.as_bytes())
        .map_err(|e| CoreError::Key(format!("encrypt: {e}")))?;

    let envelope = Envelope {
        v: 1,
        kdf: "argon2id".to_string(),
        m,
        t,
        p: KDF_LANES,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ct: STANDARD.encode(ct),
    };
    serde_json::to_string(&envelope).map_err(|e| CoreError::Key(format!("serialize envelope: {e}")))
}

/// Whether a stored value is a sealed envelope rather than a bare secret.
///
/// **The wallet must not record this fact anywhere else.** It once lived in
/// `SharedPreferences` while the sealed seed lived in the iOS Keychain, and the
/// two have different lifetimes: deleting the app takes the flag and leaves the
/// seed. The app then believed a wallet existed with no PIN on it, offered to
/// create one, and tried to read a sealed envelope as a raw seed. Asking the
/// data what it is cannot drift from the data.
pub fn is_sealed(value: &str) -> bool {
    serde_json::from_str::<Envelope>(value.trim())
        .map(|e| e.v == 1 && e.kdf == "argon2id")
        .unwrap_or(false)
}

/// Encrypt a JWK/seed into a recovery-FILE envelope — strong params, because the
/// file is offline-attackable (the user saves/shares it).
pub fn encrypt_backup(jwk: &str, passphrase: &str) -> Result<String> {
    encrypt_with(jwk, passphrase, KDF_MEM_KIB, KDF_ITERS)
}

/// Seal a seed under the app PIN — lighter params for fast unlock (see the
/// PIN_KDF constants). Same envelope format, so [`decrypt_backup`] opens both.
pub fn encrypt_pin(secret: &str, pin: &str) -> Result<String> {
    encrypt_with(secret, pin, PIN_KDF_MEM_KIB, PIN_KDF_ITERS)
}

/// Decrypt a recovery-file envelope back into the JWK string.
/// A wrong passphrase or tampered file fails the AEAD check here.
pub fn decrypt_backup(envelope: &str, passphrase: &str) -> Result<String> {
    let env: Envelope = serde_json::from_str(envelope)
        .map_err(|e| CoreError::Key(format!("parse backup file: {e}")))?;
    if env.v != 1 {
        return Err(CoreError::Key(format!(
            "unsupported backup version: {}",
            env.v
        )));
    }

    let salt = STANDARD
        .decode(&env.salt)
        .map_err(|e| CoreError::Key(format!("bad salt: {e}")))?;
    let nonce = STANDARD
        .decode(&env.nonce)
        .map_err(|e| CoreError::Key(format!("bad nonce: {e}")))?;
    let ct = STANDARD
        .decode(&env.ct)
        .map_err(|e| CoreError::Key(format!("bad ciphertext: {e}")))?;
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Key("bad nonce length".into()));
    }

    let mut key = derive_key(passphrase, &salt, env.m, env.t, env.p)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    key.zeroize();

    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| CoreError::Key("wrong passphrase or corrupt backup file".into()))?;
    // Move `pt` into the String (no extra un-wiped copy). The returned secret is
    // the caller's to protect — the bridge holds it in a Zeroizing session.
    String::from_utf8(pt).map_err(|e| CoreError::Key(format!("decrypted backup not utf8: {e}")))
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    /// What was sealed comes back, and nothing else does.
    #[test]
    fn a_sealed_value_opens_with_its_key_and_no_other() {
        let key = [7u8; KEY_LEN];
        let sealed = seal(&key, b"her passport, waiting for him").unwrap();
        assert_eq!(unseal(&key, &sealed).unwrap(), b"her passport, waiting for him");

        let mut other = key;
        other[0] ^= 1;
        assert!(unseal(&other, &sealed).is_err());
    }

    /// **One byte changed is a failure, not a slightly different answer.** A
    /// caller that got plaintext back from a tampered record would act on it.
    #[test]
    fn a_changed_byte_fails_rather_than_decoding() {
        let key = [3u8; KEY_LEN];
        let sealed = seal(&key, b"approval").unwrap();
        for i in [0, NONCE_LEN, sealed.len() - 1] {
            let mut broken = sealed.clone();
            broken[i] ^= 1;
            assert!(unseal(&key, &broken).is_err(), "byte {i} went unnoticed");
        }
        assert!(unseal(&key, &sealed[..NONCE_LEN]).is_err());
        assert!(unseal(&key, b"").is_err());
    }

    /// Sealing the same bytes twice must not produce the same record, or two
    /// identical waiting contributions would be visible as identical to anybody
    /// reading the table.
    #[test]
    fn the_same_plaintext_seals_differently_each_time() {
        let key = [11u8; KEY_LEN];
        assert_ne!(seal(&key, b"same").unwrap(), seal(&key, b"same").unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reinstall bug in one assertion: a PIN-sealed seed must be
    /// recognisable as sealed from the value alone, because the flag that used
    /// to say so lived in storage the app deletes while the seed lives in a
    /// Keychain it does not.
    #[test]
    fn a_sealed_value_is_recognisable_without_being_told() {
        let sealed = encrypt_pin("test test test", "123456").unwrap();
        assert!(is_sealed(&sealed));
    }

    #[test]
    fn a_bare_seed_is_not_mistaken_for_a_sealed_one() {
        assert!(!is_sealed(
            "legal winner thank year wave sausage worth useful"
        ));
        assert!(!is_sealed("{\"kty\":\"EC\",\"crv\":\"P-256\"}"));
        assert!(!is_sealed(""));
        assert!(!is_sealed("enc:v1:AAAA"));
    }

    #[test]
    fn round_trips() {
        let jwk = r#"{"kty":"EC","crv":"P-256","x":"aaa","y":"bbb","d":"ccc"}"#;
        let env = encrypt_backup(jwk, "correct horse").unwrap();
        assert_eq!(decrypt_backup(&env, "correct horse").unwrap(), jwk);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let env = encrypt_backup("secret-jwk", "right").unwrap();
        assert!(decrypt_backup(&env, "wrong").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let env = encrypt_backup("secret-jwk", "pw").unwrap();
        let corrupt = env.replace("\"ct\":\"", "\"ct\":\"A");
        assert!(decrypt_backup(&corrupt, "pw").is_err());
    }
}
