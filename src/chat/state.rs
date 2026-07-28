//! Sealing MLS state so it can live on disk (ADR 0013).
//!
//! MLS state is the one part of the wallet that *must* be written down and
//! cannot be re-derived: it holds the ratchet, and losing it loses every
//! conversation. It also cannot live in the Secure Enclave, because MLS needs
//! a key schedule the Enclave has no operations for.
//!
//! So it follows the pattern [`crate::recovery`] already uses for the seed:
//! the core seals it and hands back opaque bytes, and the platform stores them
//! and keeps the key. **The core still writes nothing to disk itself** — which
//! is the property that lets the same code serve mobile, the backend and WASM.
//!
//! The key here comes straight from the platform (an Enclave-wrapped 32-byte
//! key), so there is no KDF: unlike a passphrase, it is not guessable and has
//! no offline-attack surface to slow down.

use std::collections::HashMap;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::RngCore as _;

use super::{ChatError, Result};

/// XChaCha20 nonce, matching [`crate::recovery`] so the wallet has one AEAD.
const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Bumped only if the plaintext layout changes. A sealed blob from a future
/// version is refused **by name** rather than misparsed — the same courtesy the
/// belt extends to a stale app (ADR 0011).
const VERSION: u8 = 1;

/// Everything needed to rebuild a session: who we are, which signature key is
/// ours, and the provider's whole key-value store.
pub struct Snapshot {
    pub identity: Vec<u8>,
    pub signer_public: Vec<u8>,
    pub values: HashMap<Vec<u8>, Vec<u8>>,
}

/// Length-prefixed, because the alternative encodings each cost more than they
/// are worth here: JSON would inflate every byte string roughly fourfold, and
/// this blob is written on every message. It is only ever parsed *after* the
/// AEAD has authenticated it, so it never sees hostile input.
fn encode(snapshot: &Snapshot) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    let mut out = Vec::new();
    put(&mut out, &snapshot.identity);
    put(&mut out, &snapshot.signer_public);
    out.extend_from_slice(&(snapshot.values.len() as u64).to_be_bytes());
    for (k, v) in &snapshot.values {
        put(&mut out, k);
        put(&mut out, v);
    }
    out
}

fn decode(mut bytes: &[u8]) -> Result<Snapshot> {
    fn take<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
        let (len, rest) = bytes
            .split_at_checked(8)
            .ok_or(ChatError::Malformed("state"))?;
        let len = u64::from_be_bytes(len.try_into().unwrap()) as usize;
        let (value, rest) = rest
            .split_at_checked(len)
            .ok_or(ChatError::Malformed("state"))?;
        *bytes = rest;
        Ok(value)
    }

    let identity = take(&mut bytes)?.to_vec();
    let signer_public = take(&mut bytes)?.to_vec();

    let (count, rest) = bytes
        .split_at_checked(8)
        .ok_or(ChatError::Malformed("state"))?;
    let count = u64::from_be_bytes(count.try_into().unwrap());
    bytes = rest;

    let mut values = HashMap::new();
    for _ in 0..count {
        let key = take(&mut bytes)?.to_vec();
        let value = take(&mut bytes)?.to_vec();
        values.insert(key, value);
    }
    if !bytes.is_empty() {
        return Err(ChatError::Malformed("trailing state"));
    }
    Ok(Snapshot {
        identity,
        signer_public,
        values,
    })
}

pub fn seal(key: &[u8; KEY_LEN], snapshot: &Snapshot) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), encode(snapshot).as_slice())
        .map_err(|e| ChatError::Mls(format!("seal: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(key: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Snapshot> {
    let (&version, rest) = sealed
        .split_first()
        .ok_or(ChatError::Malformed("sealed state"))?;
    if version != VERSION {
        return Err(ChatError::UnsupportedStateVersion(version));
    }
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(ChatError::Malformed("sealed state"))?;

    let plaintext = XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| ChatError::WrongStateKey)?;

    decode(&plaintext)
}
