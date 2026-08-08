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
use hkdf::Hkdf;
use rand_core::RngCore as _;
use sha2::Sha256;

use super::{ChatError, Result};

/// Domain separation for the chat-state key. Any other key derived from the
/// same seed must use a different label, so that compromising one never
/// compromises another; the version suffix leaves room to rotate without
/// colliding with keys already in the field.
const STATE_KEY_INFO: &[u8] = b"vaulet/chat/state/v1";

/// Message history is sealed under its own key, so a mistake that exposes one
/// store does not hand over the other.
const HISTORY_KEY_INFO: &[u8] = b"vaulet/chat/history/v1";

/// XChaCha20 nonce, matching [`crate::recovery`] so the wallet has one AEAD.
const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Bumped only if the plaintext layout changes. A sealed blob from a future
/// version is refused **by name** rather than misparsed — the same courtesy the
/// capture layer extends to a stale app (ADR 0011).
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

/// Derive the chat-state key from the wallet seed (RFC 5869 HKDF-SHA256).
///
/// The platform therefore manages **no new key material**: the seed already
/// lives in the Keychain as `ThisDeviceOnly` under ADR 0008, and this key
/// inherits that protection rather than inventing a second thing to lose. It is
/// derived per call and never stored — losing the seed loses the conversations,
/// which is the same trade the rest of the wallet already makes.
pub fn derive_key_from_seed(seed: &[u8]) -> [u8; KEY_LEN] {
    derive(seed, STATE_KEY_INFO)
}

/// The key for stored messages. Plaintext chat history on disk would be the
/// same mistake the credential store is already flagged for, so it is sealed
/// with the rest — under a separate label from the MLS state.
pub fn derive_history_key_from_seed(seed: &[u8]) -> [u8; KEY_LEN] {
    derive(seed, HISTORY_KEY_INFO)
}

fn derive(seed: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, seed)
        .expand(info, &mut key)
        // Only fails for absurd output lengths; 32 bytes from SHA-256 cannot.
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
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

/// Seal arbitrary bytes under a derived key. Used for message history, which
/// is not MLS state and has no snapshot structure — just bytes the platform
/// stores.
pub fn seal_bytes(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| ChatError::Mls(format!("seal: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_bytes(key: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>> {
    let (&version, rest) = sealed
        .split_first()
        .ok_or(ChatError::Malformed("sealed bytes"))?;
    if version != VERSION {
        return Err(ChatError::UnsupportedStateVersion(version));
    }
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(ChatError::Malformed("sealed bytes"))?;

    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| ChatError::WrongStateKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"a seed for the history key tests";

    #[test]
    fn history_round_trips() {
        let key = derive_history_key_from_seed(SEED);
        let sealed = seal_bytes(&key, b"[{\"text\":\"hello\"}]").unwrap();
        assert_eq!(
            open_bytes(&key, &sealed).unwrap(),
            b"[{\"text\":\"hello\"}]"
        );
    }

    #[test]
    fn history_is_not_readable_at_rest() {
        let key = derive_history_key_from_seed(SEED);
        let sealed = seal_bytes(&key, b"meet at six").unwrap();
        assert!(!sealed.windows(11).any(|w| w == b"meet at six"));
    }

    /// Reusing the MLS state key for history would mean one mistake exposed
    /// both stores.
    #[test]
    fn history_and_state_use_different_keys() {
        assert_ne!(
            derive_history_key_from_seed(SEED),
            derive_key_from_seed(SEED)
        );
    }

    #[test]
    fn the_state_key_cannot_open_history() {
        let sealed = seal_bytes(&derive_history_key_from_seed(SEED), b"private").unwrap();
        assert!(matches!(
            open_bytes(&derive_key_from_seed(SEED), &sealed),
            Err(ChatError::WrongStateKey)
        ));
    }
}
