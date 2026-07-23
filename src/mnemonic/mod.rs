//! Recovery-phrase (BIP39) encoding of the P-256 identity scalar.
//!
//! Approach A (ADR 0001): the raw 32-byte private scalar IS the BIP39 256-bit
//! entropy. There is NO seed derivation and NO BIP39 passphrase — the English
//! wordlist maps the 32 bytes to 24 words and back, one-to-one, with the usual
//! 8-bit checksum. This is a reversible encoding of the existing key, not a new
//! key-generation scheme.

use bip39::Mnemonic;
use rand_core::{OsRng, RngCore};

use crate::{CoreError, Result};

/// Generate a fresh 24-word BIP39 mnemonic from 256 bits of OS entropy. This is
/// the seed root of the seed-first key model (ADR 0008) — NOT a scalar encoding.
pub fn generate() -> Result<String> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| CoreError::Key(format!("mnemonic generate: {e}")))?;
    Ok(mnemonic.to_string())
}

/// The BIP39 512-bit seed for `phrase` (empty passphrase). Validates the phrase.
pub fn to_seed(phrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse(phrase.trim())
        .map_err(|_| CoreError::Key("invalid recovery phrase".into()))?;
    Ok(mnemonic.to_seed(""))
}

/// Encode a 32-byte scalar as a 24-word English BIP39 mnemonic.
pub fn encode_key(scalar: &[u8; 32]) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy(scalar)
        .map_err(|e| CoreError::Key(format!("mnemonic encode: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Parse and checksum-validate a 24-word phrase back into the 32-byte scalar.
/// Returns `CoreError::Key("invalid recovery phrase")` on any failure (bad
/// word, wrong length, or failed checksum).
pub fn decode_key(phrase: &str) -> Result<[u8; 32]> {
    let mnemonic =
        Mnemonic::parse(phrase.trim()).map_err(|_| CoreError::Key("invalid recovery phrase".into()))?;
    let (entropy, len) = mnemonic.to_entropy_array();
    if len != 32 {
        return Err(CoreError::Key("invalid recovery phrase".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&entropy[..32]);
    Ok(out)
}

/// Up to `limit` English BIP39 words that start with `prefix` (for restore-time
/// autosuggestion). Empty prefix returns nothing. Same wordlist as encode/decode.
pub fn suggest(prefix: &str, limit: usize) -> Vec<String> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        return Vec::new();
    }
    bip39::Language::English
        .words_by_prefix(&prefix)
        .iter()
        .take(limit)
        .map(|w| w.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_returns_prefix_matches_capped() {
        let s = suggest("aba", 5);
        assert!(s.contains(&"abandon".to_string()));
        assert!(s.iter().all(|w| w.starts_with("aba")));
        assert!(s.len() <= 5);
        assert!(suggest("", 5).is_empty());
    }

    #[test]
    fn encode_decode_round_trips() {
        let scalar = [7u8; 32];
        let phrase = encode_key(&scalar).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(decode_key(&phrase).unwrap(), scalar);
    }

    #[test]
    fn garbage_phrase_fails() {
        assert!(decode_key("not actually a real mnemonic phrase").is_err());
        assert!(decode_key("abandon abandon").is_err()); // too short
    }

    #[test]
    fn tampered_checksum_fails() {
        let phrase = encode_key(&[9u8; 32]).unwrap();
        // Swap the last word for a different valid wordlist entry, breaking the checksum.
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        let last = *words.last().unwrap();
        let replacement = if last == "zoo" { "zone" } else { "zoo" };
        *words.last_mut().unwrap() = replacement;
        let tampered = words.join(" ");
        assert!(decode_key(&tampered).is_err());
    }
}
