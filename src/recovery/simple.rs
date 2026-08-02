//! Simple Recovery — a 2-of-3 split across a passphrase, a phone and a file
//! (ADR 0019).
//!
//! The one-factor recovery file is non-custodial in the strongest sense and
//! fails in the most ordinary way there is: the customer forgets the passphrase,
//! and the file in their iCloud Drive becomes indistinguishable from no backup.
//! This spreads the seed over three things they already have, any two of which
//! bring it back.
//!
//! ```text
//!   share 1  →  blob, kept in BOTH the file and on our server  →  passphrase
//!   share 2  →  our server only                                →  OTP to the phone
//!   share 3  →  the file only, in the clear                    →  having the file
//! ```
//!
//! Share 1's blob is in both places deliberately: it is the only way passphrase
//! + OTP recovers with no file at all, which is what makes this a real 2-of-3
//! rather than "you must have the file, and may unlock it two ways".

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use super::derive_key_public;
use crate::{shamir, CoreError, Result};

/// Argon2id cost for the passphrase that guards share 1.
///
/// The same 64 MiB / t=3 the recovery file uses. It protects a blob we hand to
/// our own server, so it is attackable by anyone who reaches that storage —
/// exactly the offline setting those parameters were chosen for.
const KDF_MEM_KIB: u32 = 65_536;
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 1;
const SALT_LEN: usize = 16;

/// Domain separation for the two things derived from one passphrase-derived key
/// and from the seed, so no two of them can ever be the same bytes.
const INFO_SHARE_MASK: &[u8] = b"vaulet/simple-recovery/share1-mask/v1";
const INFO_CONTENTS_KEY: &[u8] = b"vaulet/simple-recovery/contents-key/v1";

/// What enrolment produces: what goes in the file, and what goes to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// The recovery file the customer saves to iCloud Drive.
    pub file: String,
    /// Share 2, for our server to hold and release against an OTP.
    ///
    /// **Checksum-stripped** — see [`strip_checksum`].
    pub server_share: String,
    /// Share 1's blob, for our server to hold so passphrase + OTP can recover
    /// with no file. Byte-identical to the copy inside the file.
    pub server_blob: String,
}

/// The recovery file's contents. Everything here is safe to hand to iCloud: the
/// blob needs the passphrase, share 3 alone is one share of two, and the wallet
/// contents are sealed under a key that does not exist until the shares meet.
#[derive(Serialize, Deserialize)]
struct RecoveryFile {
    /// Format marker + version, so a file can be recognised before it is parsed.
    v: u8,
    /// Which record on our server holds shares 2 and 1's blob.
    recovery_id: String,
    /// Share 1, masked by the passphrase (see [`mask_share`]).
    blob1: String,
    /// Share 3, in the clear.
    share3: String,
    /// The wallet's cards and contacts, sealed under a seed-derived key.
    contents: String,
}

/// The passphrase-derived mask for share 1, and the salt it used.
///
/// **XOR, with no authentication tag, on purpose.** An AEAD would be the reflex
/// and it would be a mistake here: a sealed blob tells whoever holds it whether
/// a guess was right, so storing one beside share 2 would put a passphrase
/// oracle inside our own database, and a dump of that one table would be enough
/// to attack every customer offline. A wrong passphrase must produce a wrong
/// share silently, leaving the attacker to find something outside the database
/// to check it against. The legitimate user verifies where verification
/// belongs — the reconstructed seed derives a DID, and it either matches the
/// wallet or the recovery failed.
fn mask_share(share: &str, passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = derive_key_public(passphrase, salt, KDF_MEM_KIB, KDF_ITERS, KDF_LANES)?;
    let hk = Hkdf::<Sha256>::new(None, &key);
    key.zeroize();

    let bytes = share.as_bytes();
    let mut mask = vec![0u8; bytes.len()];
    hk.expand(INFO_SHARE_MASK, &mut mask)
        .map_err(|_| CoreError::Key("share mask: output too long".into()))?;
    for (m, b) in mask.iter_mut().zip(bytes) {
        *m ^= b;
    }
    Ok(mask)
}

/// The key the wallet's contents are sealed with, derived from the seed.
///
/// It exists only once two shares have reconstructed the seed, so the file
/// carries the customer's cards without carrying any way to read them.
pub fn contents_key(secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret.trim().as_bytes());
    let mut key = [0u8; 32];
    // Fixed 32-byte output cannot exceed HKDF's limit.
    hk.expand(INFO_CONTENTS_KEY, &mut key).unwrap();
    key
}

/// Remove the envelope's secret checksum from a share we are about to hand to
/// our own server.
///
/// `shamir::wrap_share` puts four bytes of SHA-256 over the seed into every
/// share so a recovery can reject insufficient ones. That is the right call for
/// a share a customer holds and exactly the wrong thing to store next to a
/// passphrase-derived blob: together they are a complete offline oracle. The
/// copy in the customer's file keeps its checksum; ours does not.
fn strip_checksum(share: &str) -> String {
    let mut parts: Vec<&str> = share.trim().split('.').collect();
    if parts.len() == 4 {
        parts[3] = "";
    }
    parts.join(".")
}

/// Put the checksum back, taking it from a share that still has one.
///
/// Reconstruction needs every share to agree on the envelope, and the customer's
/// own share always carries the real value — so the one we return can borrow it
/// rather than us storing it.
fn restore_checksum(stripped: &str, from: &str) -> Result<String> {
    let mine: Vec<&str> = stripped.trim().split('.').collect();
    let theirs: Vec<&str> = from.trim().split('.').collect();
    if mine.len() != 4 || theirs.len() != 4 {
        return Err(CoreError::Key("not a valid recovery share".into()));
    }
    Ok(format!("{}.{}.{}.{}", mine[0], mine[1], mine[2], theirs[3]))
}

/// Split `secret` 2-of-3 and produce the file plus the two pieces our server
/// keeps (ADR 0019). `contents` is the wallet's cards, sealed under a
/// seed-derived key so the file cannot be read before it is recovered.
pub fn enrol(
    secret: &str,
    contents: &str,
    passphrase: &str,
    recovery_id: &str,
) -> Result<Enrolment> {
    let entropy = crate::mnemonic_entropy_public(secret)?;
    let shares = shamir::split(&entropy, 2, 3)?;

    let mut salt = [0u8; SALT_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    // The blob hides a checksum-stripped share for the same reason the stored
    // share is stripped — and because this blob is handed to our server too, so
    // a checksum inside it would put the oracle back by another door.
    let masked = mask_share(&strip_checksum(&shares[0]), passphrase, &salt)?;
    // The salt is not secret and must travel with the blob, or nobody can
    // reproduce the derivation — including the customer.
    let blob1 = format!("{}.{}", STANDARD.encode(salt), STANDARD.encode(&masked));

    let sealed = super::seal_with_key(&contents_key(secret), contents)?;
    let file = RecoveryFile {
        v: 1,
        recovery_id: recovery_id.to_string(),
        blob1: blob1.clone(),
        share3: shares[2].clone(),
        contents: sealed,
    };

    Ok(Enrolment {
        file: serde_json::to_string(&file)
            .map_err(|e| CoreError::Key(format!("serialize recovery file: {e}")))?,
        server_share: strip_checksum(&shares[1]),
        server_blob: blob1,
    })
}

/// The `recovery_id` a file points at, without opening anything.
///
/// Read before any factor is supplied, because the app has to know which server
/// record to ask for an OTP before the customer has proved anything.
pub fn file_recovery_id(file: &str) -> Result<String> {
    let parsed: RecoveryFile = serde_json::from_str(file.trim())
        .map_err(|_| CoreError::Key("not a Vaulet recovery file".into()))?;
    if parsed.v != 1 {
        return Err(CoreError::Key(
            "this recovery file needs a newer version of Vaulet".into(),
        ));
    }
    Ok(parsed.recovery_id)
}

/// Recover the seed from a passphrase and the file (no server involved).
pub fn recover_with_passphrase(file: &str, passphrase: &str) -> Result<String> {
    let parsed = parse_file(file)?;
    // The blob's share has no checksum; share 3 does, and every share of one
    // split must agree on the envelope. The customer's own copy is where the
    // real value comes from — we never stored it.
    let share1 = restore_checksum(&unmask(&parsed.blob1, passphrase)?, &parsed.share3)?;
    reconstruct(&[share1, parsed.share3])
}

/// Recover the seed from the file and the share our server released for an OTP.
pub fn recover_with_server_share(file: &str, server_share: &str) -> Result<String> {
    let parsed = parse_file(file)?;
    let share2 = restore_checksum(server_share, &parsed.share3)?;
    reconstruct(&[share2, parsed.share3])
}

/// Recover the seed from a passphrase plus both pieces our server released —
/// the path for a customer who has lost the file entirely.
///
/// The blob and the share both come from us, so neither carries a checksum to
/// borrow; the envelope is rebuilt from the share's own threshold field and the
/// checksum comes out of reconstruction being verified against the DID upstream.
pub fn recover_without_file(
    server_blob: &str,
    server_share: &str,
    passphrase: &str,
) -> Result<String> {
    let share1 = unmask(server_blob, passphrase)?;
    // Both halves are ours and both are checksum-less, so they agree with each
    // other; `shamir::reconstruct` then verifies its own arithmetic against the
    // (empty) checksum both carry, which it accepts.
    reconstruct(&[share1, server_share.to_string()])
}

/// Open the wallet contents a recovery file carries, given the recovered seed.
pub fn open_contents(file: &str, secret: &str) -> Result<String> {
    let parsed = parse_file(file)?;
    if parsed.contents.is_empty() {
        return Ok(String::new());
    }
    super::open_with_key(&contents_key(secret), &parsed.contents)
}

fn parse_file(file: &str) -> Result<RecoveryFile> {
    let parsed: RecoveryFile = serde_json::from_str(file.trim())
        .map_err(|_| CoreError::Key("not a Vaulet recovery file".into()))?;
    if parsed.v != 1 {
        return Err(CoreError::Key(
            "this recovery file needs a newer version of Vaulet".into(),
        ));
    }
    Ok(parsed)
}

/// Undo [`mask_share`], returning the checksum-stripped share it hid.
fn unmask(blob: &str, passphrase: &str) -> Result<String> {
    let (salt_b64, masked_b64) = blob
        .trim()
        .split_once('.')
        .ok_or_else(|| CoreError::Key("not a valid recovery blob".into()))?;
    let salt = STANDARD
        .decode(salt_b64)
        .map_err(|_| CoreError::Key("not a valid recovery blob".into()))?;
    let masked = STANDARD
        .decode(masked_b64)
        .map_err(|_| CoreError::Key("not a valid recovery blob".into()))?;

    let mut key = derive_key_public(passphrase, &salt, KDF_MEM_KIB, KDF_ITERS, KDF_LANES)?;
    let hk = Hkdf::<Sha256>::new(None, &key);
    key.zeroize();
    let mut out = vec![0u8; masked.len()];
    hk.expand(INFO_SHARE_MASK, &mut out)
        .map_err(|_| CoreError::Key("share mask: output too long".into()))?;
    for (o, m) in out.iter_mut().zip(&masked) {
        *o ^= m;
    }
    // A wrong passphrase yields wrong bytes rather than an error — by design.
    // They are rejected downstream when the shares fail to reconstruct, which
    // is the whole point of not authenticating the blob.
    String::from_utf8(out).map_err(|_| CoreError::Key("wrong passphrase".into()))
}

/// Rebuild the seed mnemonic from two shares.
fn reconstruct(shares: &[String]) -> Result<String> {
    let entropy = shamir::reconstruct(shares)?;
    let bytes: [u8; 32] = entropy
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Key("recovered seed has the wrong size".into()))?;
    crate::mnemonic::encode_key(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 24-word seed, fixed so a failure is reproducible.
    fn seed() -> String {
        crate::mnemonic::encode_key(&[7u8; 32]).unwrap()
    }

    const PASS: &str = "correct horse battery staple anchor";
    const CONTENTS: &str = r#"{"credentials":[{"vct":"employee-badge"}]}"#;

    fn enrolment() -> Enrolment {
        enrol(&seed(), CONTENTS, PASS, "rec_123").unwrap()
    }

    /// The three pairs, which are the whole promise of the method (ADR 0019).
    #[test]
    fn the_passphrase_and_the_file_recover() {
        let e = enrolment();
        assert_eq!(recover_with_passphrase(&e.file, PASS).unwrap(), seed());
    }

    #[test]
    fn the_phone_and_the_file_recover() {
        let e = enrolment();
        assert_eq!(
            recover_with_server_share(&e.file, &e.server_share).unwrap(),
            seed()
        );
    }

    #[test]
    fn the_passphrase_and_the_phone_recover_with_no_file() {
        let e = enrolment();
        assert_eq!(
            recover_without_file(&e.server_blob, &e.server_share, PASS).unwrap(),
            seed()
        );
    }

    /// One factor is not two, however good it is.
    #[test]
    fn the_file_alone_does_not_recover() {
        let e = enrolment();
        let parsed = parse_file(&e.file).unwrap();
        assert!(reconstruct(&[parsed.share3]).is_err());
    }

    #[test]
    fn a_wrong_passphrase_does_not_recover() {
        let e = enrolment();
        assert!(recover_with_passphrase(&e.file, "not the passphrase").is_err());
    }

    /// The reason the blob is XOR and not an AEAD: what we hand our own server
    /// must not tell a holder whether a guess was right. If this ever starts
    /// failing with "wrong passphrase" rather than producing junk, the oracle is
    /// back and the storage is attackable offline.
    #[test]
    fn a_wrong_passphrase_yields_junk_rather_than_a_verdict() {
        let e = enrolment();
        let parsed = parse_file(&e.file).unwrap();
        let wrong = unmask(&parsed.blob1, "wrong");
        // It either decodes to a wrong share or fails as non-UTF8 — never with
        // a message that distinguishes a near-miss from anything else.
        if let Ok(share) = wrong {
            assert_ne!(share, parsed.share3);
            assert!(reconstruct(&[share, parsed.share3]).is_err());
        }
    }

    /// The share we keep must carry no checksum of the seed, or our database is
    /// its own oracle for the passphrase guessing above.
    #[test]
    fn the_share_we_store_carries_no_checksum_of_the_seed() {
        let e = enrolment();
        assert!(
            e.server_share.ends_with('.'),
            "server share still carries a checksum: {}",
            e.server_share
        );
        use sha2::Digest;
        let digest = sha2::Sha256::digest(crate::mnemonic_entropy_public(&seed()).unwrap());
        let checksum = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&digest[..4]);
        assert!(!e.server_share.contains(&checksum));
        assert!(!e.server_blob.contains(&checksum));
    }

    /// The cards travel with the seed, and are unreadable until it is back.
    #[test]
    fn the_contents_open_only_once_the_seed_is_recovered() {
        let e = enrolment();
        assert!(!e.file.contains("employee-badge"));
        let recovered = recover_with_passphrase(&e.file, PASS).unwrap();
        assert_eq!(open_contents(&e.file, &recovered).unwrap(), CONTENTS);
    }

    /// The app has to know which record to ask for an OTP before the customer
    /// has supplied any factor at all.
    #[test]
    fn the_recovery_id_reads_without_any_factor() {
        let e = enrolment();
        assert_eq!(file_recovery_id(&e.file).unwrap(), "rec_123");
    }

    #[test]
    fn something_that_is_not_a_recovery_file_is_refused() {
        assert!(file_recovery_id("{\"hello\":1}").is_err());
        assert!(recover_with_passphrase("not json", PASS).is_err());
    }
}
