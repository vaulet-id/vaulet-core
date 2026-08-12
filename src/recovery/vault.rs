//! The wallet's contents, sealed under a key the seed unwraps (ADR 0043).
//!
//! **This file carries no secret.** The seed lives in the `.vkey` recovery file
//! and nowhere else; a `.vlt` holds credentials, profile and chat history sealed
//! under a data key that only the seed can unwrap. That is what lets a vault be
//! synced to iCloud or a drive while the key stays offline — and it is why the
//! two are separate artefacts at all: the seed is written once, and this is
//! rewritten every time a credential arrives, so bundling them would put another
//! copy of the seed in cloud version history on every backup.
//!
//! ```text
//! DK          = 32 random bytes
//! KEK         = HKDF-SHA256(ikm = seed, info = "vaulet/vault/dk/v1")
//! wrapped_dk  = XChaCha20-Poly1305(KEK, DK)          one shot, 32 bytes
//! body        = STREAM(DK, zip), 64 KiB chunks       AAD = the header bytes
//! ```
//!
//! No Argon2 anywhere here. The input is a 256-bit seed rather than a passphrase
//! somebody invented, so stretching it buys nothing and would charge 64 MiB on
//! the file written most often.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{CoreError, Result};

/// Wrapping-key derivation. Bound to a purpose string so the same seed used
/// elsewhere — Simple Recovery derives its own contents key from it — can never
/// produce this one.
const INFO_DK: &[u8] = b"vaulet/vault/dk/v1";

/// `VLTV1`, so a reader tells this from the JSON recovery envelope by its first
/// bytes rather than by the file extension. `.vlt` now names two formats, and
/// `recovery::is_sealed` already set the rule: asking the data what it is cannot
/// drift from the data.
const MAGIC: &[u8; 5] = b"VLTV1";

/// Plaintext per chunk. The whole point of chunking is that neither side ever
/// holds the container twice: a vault with chat history and photographs in it is
/// tens of megabytes, and a phone is where it gets opened.
const CHUNK: usize = 64 * 1024;

const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// The random half of every chunk nonce. The rest is the counter and the
/// last-chunk flag — see [`chunk_nonce`].
const PREFIX_LEN: usize = 15;

/// A header a reader can act on before it has any key at all.
#[derive(Serialize, Deserialize)]
struct Header {
    v: u8,
    kind: String,
    /// RFC 7638 thumbprint of the wallet this vault belongs to. Readable without
    /// the seed on purpose: *this vault belongs to a different key* is a
    /// different problem from *this file is damaged*, and they have different
    /// answers. Authenticated all the same — the header is the AAD of every
    /// chunk, so it cannot be swapped between two files.
    kid: String,
    wrap: Wrapped,
    /// Base64 [`PREFIX_LEN`] bytes.
    stream: String,
}

#[derive(Serialize, Deserialize)]
struct Wrapped {
    nonce: String,
    ct: String,
}

/// The nonce for chunk `index`, and whether it is the last one.
///
/// `prefix || counter || flag`. The flag is what makes truncation detectable:
/// cutting the file short removes the chunk that says it is final, and the
/// remaining chunks all authenticate as not-final, so the reader knows it has a
/// piece rather than a vault. Without it a truncated download opens cleanly and
/// hands back a wallet missing whatever was at the end.
fn chunk_nonce(prefix: &[u8; PREFIX_LEN], index: u64, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..PREFIX_LEN + 8].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(last);
    nonce
}

fn kek(secret: &str) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, secret.trim().as_bytes());
    let mut key = [0u8; KEY_LEN];
    // A fixed 32-byte output cannot exceed HKDF's length limit.
    hk.expand(INFO_DK, &mut key).unwrap();
    key
}

/// Seal `zip` into a `.vlt` for the wallet identified by `kid`.
pub fn seal_vault(secret: &str, kid: &str, zip: &[u8]) -> Result<Vec<u8>> {
    let mut dk = [0u8; KEY_LEN];
    let mut prefix = [0u8; PREFIX_LEN];
    let mut wrap_nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut dk);
    rand_core::OsRng.fill_bytes(&mut prefix);
    rand_core::OsRng.fill_bytes(&mut wrap_nonce);

    let mut wrapping = kek(secret);
    let wrapped = XChaCha20Poly1305::new(wrapping.as_ref().into())
        .encrypt(XNonce::from_slice(&wrap_nonce), dk.as_slice())
        .map_err(|e| CoreError::Key(format!("wrap vault key: {e}")))?;
    wrapping.zeroize();

    let header = serde_json::to_vec(&Header {
        v: 1,
        kind: "vault".into(),
        kid: kid.to_string(),
        wrap: Wrapped {
            nonce: STANDARD.encode(wrap_nonce),
            ct: STANDARD.encode(&wrapped),
        },
        stream: STANDARD.encode(prefix),
    })
    .map_err(|e| CoreError::Key(format!("serialize vault header: {e}")))?;

    let cipher = XChaCha20Poly1305::new(dk.as_ref().into());
    dk.zeroize();

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header.len() + zip.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(
        &u32::try_from(header.len())
            .map_err(|_| CoreError::Key("vault header is too long".into()))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&header);

    // An empty vault still writes one final chunk. Otherwise "no chunks" and
    // "every chunk removed" are the same file, which is the truncation this
    // format is supposed to notice.
    let mut index: u64 = 0;
    let mut rest = zip;
    loop {
        let take = rest.len().min(CHUNK);
        let (piece, tail) = rest.split_at(take);
        let last = tail.is_empty();
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&chunk_nonce(&prefix, index, last)),
                Payload {
                    msg: piece,
                    aad: &header,
                },
            )
            .map_err(|e| CoreError::Key(format!("seal vault chunk: {e}")))?;
        out.extend_from_slice(&sealed);
        if last {
            break;
        }
        rest = tail;
        index += 1;
    }
    Ok(out)
}

/// The wallet a vault belongs to, without needing the seed.
pub fn vault_kid(file: &[u8]) -> Result<String> {
    Ok(parse(file)?.0.kid)
}

/// Whether these bytes are a vault container rather than a recovery envelope.
pub fn is_vault(file: &[u8]) -> bool {
    file.len() >= MAGIC.len() && &file[..MAGIC.len()] == MAGIC
}

/// Split a file into its header (parsed and raw) and its chunk stream.
fn parse(file: &[u8]) -> Result<(Header, &[u8], &[u8])> {
    if !is_vault(file) {
        return Err(CoreError::Key("not a vault file".into()));
    }
    let after_magic = &file[MAGIC.len()..];
    if after_magic.len() < 4 {
        return Err(CoreError::Key("vault file is truncated".into()));
    }
    let len = u32::from_be_bytes([
        after_magic[0],
        after_magic[1],
        after_magic[2],
        after_magic[3],
    ]) as usize;
    let rest = &after_magic[4..];
    if rest.len() < len {
        return Err(CoreError::Key("vault file is truncated".into()));
    }
    let (raw, body) = rest.split_at(len);
    let header: Header = serde_json::from_slice(raw)
        .map_err(|_| CoreError::Key("vault header is malformed".into()))?;
    if header.v != 1 || header.kind != "vault" {
        return Err(CoreError::Key("unsupported vault version".into()));
    }
    Ok((header, raw, body))
}

/// Open a `.vlt` with the seed that owns it.
pub fn open_vault(file: &[u8], secret: &str) -> Result<Vec<u8>> {
    let (header, raw, body) = parse(file)?;

    let wrap_nonce = STANDARD
        .decode(&header.wrap.nonce)
        .map_err(|_| CoreError::Key("vault header is malformed".into()))?;
    let wrapped = STANDARD
        .decode(&header.wrap.ct)
        .map_err(|_| CoreError::Key("vault header is malformed".into()))?;
    let prefix_bytes = STANDARD
        .decode(&header.stream)
        .map_err(|_| CoreError::Key("vault header is malformed".into()))?;
    if wrap_nonce.len() != NONCE_LEN || prefix_bytes.len() != PREFIX_LEN {
        return Err(CoreError::Key("vault header is malformed".into()));
    }
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&prefix_bytes);

    let mut wrapping = kek(secret);
    let mut dk = XChaCha20Poly1305::new(wrapping.as_ref().into())
        .decrypt(XNonce::from_slice(&wrap_nonce), wrapped.as_slice())
        // The seed is the only door. Say so, rather than "decryption failed".
        .map_err(|_| CoreError::Key("this vault does not belong to that key".into()))?;
    wrapping.zeroize();
    if dk.len() != KEY_LEN {
        dk.zeroize();
        return Err(CoreError::Key("vault header is malformed".into()));
    }
    let cipher = XChaCha20Poly1305::new(dk.as_slice().into());
    dk.zeroize();

    let sealed_chunk = CHUNK + TAG_LEN;
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    let mut index: u64 = 0;
    loop {
        if rest.is_empty() {
            // Every chunk opened and none of them said it was the last.
            return Err(CoreError::Key("vault file is truncated".into()));
        }
        let take = rest.len().min(sealed_chunk);
        let (piece, tail) = rest.split_at(take);
        let last = tail.is_empty();
        let plain = match cipher.decrypt(
            XNonce::from_slice(&chunk_nonce(&prefix, index, last)),
            Payload {
                msg: piece,
                aad: raw,
            },
        ) {
            Ok(plain) => plain,
            // The last piece we have does not authenticate AS the last one. If
            // it authenticates as a middle chunk, the file is not damaged — it
            // is incomplete, which is a download to retry rather than a backup
            // to mourn. The distinction is only ever used to say so: the data is
            // refused either way.
            Err(_) if last
                && cipher
                    .decrypt(
                        XNonce::from_slice(&chunk_nonce(&prefix, index, false)),
                        Payload {
                            msg: piece,
                            aad: raw,
                        },
                    )
                    .is_ok() =>
            {
                return Err(CoreError::Key("vault file is truncated".into()))
            }
            Err(_) => return Err(CoreError::Key("the vault file is damaged".into())),
        };
        out.extend_from_slice(&plain);
        if last {
            break;
        }
        rest = tail;
        index += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "b6f8c0b1a3f24d2f9c1e7a4d8b5e0c3a7f2d9b6e1c4a8f0d3b7e2c5a9f1d4b8e";
    const KID: &str = "7Xb3Qm1kJ0zR9wYt2LpNfA6sVhE4cDuG8oIyKxTnMbQ";

    fn sealed(bytes: &[u8]) -> Vec<u8> {
        seal_vault(SEED, KID, bytes).unwrap()
    }

    /// **Pinned from another implementation, per the fixture rule.** Python's
    /// `hmac`/`hashlib` computing RFC 5869 HKDF-SHA256 over the same ikm and
    /// info, so this cannot pass by agreeing with itself:
    ///
    /// ```text
    /// python3 - <<'PY'
    /// import hmac, hashlib
    /// ikm  = b"b6f8c0b1a3f24d2f9c1e7a4d8b5e0c3a7f2d9b6e1c4a8f0d3b7e2c5a9f1d4b8e"
    /// info = b"vaulet/vault/dk/v1"
    /// prk  = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    /// print(hmac.new(prk, info + b"\x01", hashlib.sha256).hexdigest())
    /// PY
    /// ```
    #[test]
    fn the_wrapping_key_is_the_hkdf_another_implementation_computes() {
        let hex: String = kek(SEED).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "21f35bf885c3d3ed49e45aa9a0ead8a79b09fc83bbc9304a527c18f987db18ea"
        );
    }

    #[test]
    fn what_was_sealed_comes_back() {
        for size in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 3 + 7] {
            let zip: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            assert_eq!(open_vault(&sealed(&zip), SEED).unwrap(), zip, "size {size}");
        }
    }

    #[test]
    fn the_file_carries_no_seed() {
        let file = sealed(b"cards");
        assert!(
            !String::from_utf8_lossy(&file).contains(SEED),
            "the seed must never appear in a vault"
        );
    }

    #[test]
    fn another_wallets_key_does_not_open_it() {
        let err = open_vault(&sealed(b"cards"), "some other seed").unwrap_err();
        assert!(
            err.to_string().contains("does not belong to that key"),
            "got {err}"
        );
    }

    #[test]
    fn the_owner_is_readable_without_the_key() {
        assert_eq!(vault_kid(&sealed(b"cards")).unwrap(), KID);
    }

    /// The reason the last chunk carries a flag.
    #[test]
    fn a_truncated_file_is_refused_rather_than_opened_short() {
        let zip: Vec<u8> = (0..CHUNK * 2 + 9).map(|i| (i % 251) as u8).collect();
        let file = sealed(&zip);
        // Drop the final chunk. Everything before it still authenticates.
        let cut = file.len() - (9 + TAG_LEN);
        let err = open_vault(&file[..cut], SEED).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got {err}");
    }

    /// The header is the AAD, so editing it cannot go unnoticed even though it
    /// is in the clear.
    #[test]
    fn a_header_edited_in_place_fails_the_body() {
        let file = sealed(b"cards");
        let mut edited = file.clone();
        let at = edited
            .windows(KID.len())
            .position(|w| w == KID.as_bytes())
            .expect("the kid is in the header");
        edited[at] = b'0';
        let err = open_vault(&edited, SEED).unwrap_err();
        assert!(err.to_string().contains("damaged"), "got {err}");
    }

    #[test]
    fn a_recovery_envelope_is_not_mistaken_for_a_vault() {
        let envelope = crate::recovery::encrypt_backup("{\"kty\":\"EC\"}", "pw").unwrap();
        assert!(!is_vault(envelope.as_bytes()));
        assert!(is_vault(&sealed(b"cards")));
    }
}
