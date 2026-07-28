//! Inbox keys: how a device is addressed at a mediator (ADR 0013).
//!
//! One inbox per contact, which is what confines an abusive party to a single
//! channel and makes blocking them a deletion rather than a policy. Each
//! inbox's key is **derived from the wallet seed** and an index, so:
//!
//! - the platform stores no key material for chat — restoring the seed restores
//!   every inbox, the same bargain the rest of the wallet already makes;
//! - the addresses are unlinkable to anyone who does not hold the seed, because
//!   they are hashes of independent public keys.
//!
//! The identifier is `base64url(sha256(public_key))`, which is the mediator's
//! definition too. It has to be: a client that derives it differently addresses
//! a box nobody is holding, so the two are checked against each other in
//! `mediator/tests/chat_over_mediator.rs`.
//!
//! This is a **different key from the MLS signature key**. That one authenticates
//! what you say inside a conversation; this one only proves you may empty a
//! box. Conflating them would let the mediator link a sender to a group member.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use super::{ChatError, Result};

/// Domain separation, distinct from the chat-state key's label so that the two
/// derivations can never collide.
const INBOX_KEY_INFO: &[u8] = b"vaulet/chat/inbox/v1";

/// Derive the P-256 key for one inbox. `index` numbers the contact.
fn derive(seed: &[u8], index: u32) -> Result<SigningKey> {
    let mut info = INBOX_KEY_INFO.to_vec();
    info.extend_from_slice(&index.to_be_bytes());

    let mut scalar = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(&info, &mut scalar)
        .map_err(|_| ChatError::Mls("inbox key derivation".into()))?;

    // A uniformly random 32-byte string is out of range for P-256 with
    // negligible probability, but "negligible" is not "never" and a silent
    // panic here would be a wallet that cannot open one specific conversation.
    SigningKey::from_slice(&scalar).map_err(|_| ChatError::Mls("inbox scalar out of range".into()))
}

/// The public key to register with a mediator, SEC1-uncompressed.
pub fn public_key(seed: &[u8], index: u32) -> Result<Vec<u8>> {
    Ok(derive(seed, index)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// The mediator's address for this inbox. Must match the server's derivation
/// exactly; see the module docs.
pub fn id(public_key: &[u8]) -> String {
    B64.encode(Sha256::digest(public_key))
}

/// Sign a mediator's collection challenge. DER-encoded, which is what the
/// mediator accepts and what Apple's Secure Enclave would emit if this key ever
/// moves there.
pub fn sign_challenge(seed: &[u8], index: u32, challenge: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = derive(seed, index)?.sign(challenge);
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    const SEED: &[u8] = b"a wallet seed, sixty four bytes in real life but any length here";

    #[test]
    fn each_contact_gets_a_different_inbox() {
        let a = public_key(SEED, 0).unwrap();
        let b = public_key(SEED, 1).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            id(&a),
            id(&b),
            "addresses must not be linkable to each other"
        );
    }

    #[test]
    fn the_same_seed_and_index_always_give_the_same_inbox() {
        // This is what makes restoring the seed restore the conversations
        // rather than merely the identity.
        assert_eq!(public_key(SEED, 7).unwrap(), public_key(SEED, 7).unwrap());
    }

    #[test]
    fn a_different_seed_gives_a_different_inbox() {
        let other: &[u8] = b"a completely different wallet seed than the one above";
        assert_ne!(public_key(SEED, 0).unwrap(), public_key(other, 0).unwrap());
    }

    #[test]
    fn the_signature_verifies_against_the_published_public_key() {
        let challenge = b"a nonce the mediator issued";
        let signature = sign_challenge(SEED, 3, challenge).unwrap();

        // Verified through the *published* key, the way the mediator does it —
        // not through the private key we happen to hold here.
        let key = VerifyingKey::from_sec1_bytes(&public_key(SEED, 3).unwrap()).unwrap();
        let signature = Signature::from_der(&signature).unwrap();
        assert!(key.verify(challenge, &signature).is_ok());
    }

    #[test]
    fn a_signature_from_the_wrong_inbox_does_not_verify() {
        let challenge = b"a nonce the mediator issued";
        let signature = Signature::from_der(&sign_challenge(SEED, 4, challenge).unwrap()).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&public_key(SEED, 5).unwrap()).unwrap();
        assert!(key.verify(challenge, &signature).is_err());
    }
}
