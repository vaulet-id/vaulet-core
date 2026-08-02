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

/// The key naming this device's set of inboxes (ADR 0017).
///
/// **One per device, not per contact**, and that is the whole point: it is the
/// thing the mediator is now told, so that a device can ask about every inbox it
/// owns in one request instead of one per contact.
const GROUP_KEY_INFO: &[u8] = b"vaulet/chat/group/v1";

/// The key for **this device's inbox in one room** (ADR 0022).
///
/// A per-contact inbox cannot address a room: in a room of A, B and C, B must
/// reach C, and B and C may never have met — there is no inbox between them and
/// none may be invented out of a relationship that does not exist.
///
/// So each member derives one box per room and announces it *inside* the room,
/// which is encrypted, so the mediator is never told who told whom. That is N
/// boxes for a room of N rather than N², and it keeps what the per-contact box
/// was chosen for: leaving is deleting your own box, and the per-inbox cap
/// confines a flood to the one room it came from.
const ROOM_KEY_INFO: &[u8] = b"vaulet/chat/room/v1";

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

/// Derive the P-256 key for this device's inbox in one room.
///
/// Keyed by the **room id**, which every member already holds and nobody
/// allocates — the same self-authenticating idiom as every other identifier
/// here, so a room needs no registration step and no coordinator.
fn derive_room(seed: &[u8], room_id: &[u8]) -> Result<SigningKey> {
    let mut info = ROOM_KEY_INFO.to_vec();
    // Length-prefixed, so that two different room ids cannot produce the same
    // info string by running into each other — the ids are variable length and
    // concatenation alone would let one room address another's box.
    info.extend_from_slice(&(room_id.len() as u32).to_be_bytes());
    info.extend_from_slice(room_id);

    let mut scalar = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(&info, &mut scalar)
        .map_err(|_| ChatError::Mls("room key derivation".into()))?;

    SigningKey::from_slice(&scalar).map_err(|_| ChatError::Mls("room scalar out of range".into()))
}

/// The public key of this device's box in a room, SEC1-uncompressed.
pub fn room_public_key(seed: &[u8], room_id: &[u8]) -> Result<Vec<u8>> {
    Ok(derive_room(seed, room_id)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// Prove possession of a room box's key, to collect from it or delete it.
pub fn sign_room_challenge(seed: &[u8], room_id: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = derive_room(seed, room_id)?.sign(challenge);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// The public key to register with a mediator, SEC1-uncompressed.
pub fn public_key(seed: &[u8], index: u32) -> Result<Vec<u8>> {
    Ok(derive(seed, index)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// Derive the key that names this device's group of inboxes (ADR 0017).
///
/// Its own label, so the group id cannot be worked back to any inbox and a
/// leaked group key does not authorise emptying any box. What it authorises is
/// asking about all of them at once, which is a different and lesser thing.
fn derive_group(seed: &[u8]) -> Result<SigningKey> {
    let mut scalar = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(GROUP_KEY_INFO, &mut scalar)
        .map_err(|_| ChatError::Mls("group key derivation".into()))?;
    SigningKey::from_slice(&scalar).map_err(|_| ChatError::Mls("group scalar out of range".into()))
}

/// The public half of the group key, SEC1-uncompressed. Its hash is the group's
/// address, exactly as an inbox's is.
pub fn group_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(derive_group(seed)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// Prove the group is ours, for a collection across all of its inboxes.
pub fn sign_group_challenge(seed: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = derive_group(seed)?.sign(challenge);
    Ok(signature.to_der().as_bytes().to_vec())
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

    /// The group names a device; an inbox names one conversation with it. A
    /// derivation that produced the same key for both would mean the address
    /// somebody publishes to a contact also identifies the whole device.
    #[test]
    fn the_group_key_is_not_any_inbox_key() {
        let group = group_public_key(SEED).unwrap();
        for index in 0..8 {
            assert_ne!(group, public_key(SEED, index).unwrap());
        }
    }

    #[test]
    fn a_group_belongs_to_one_seed_and_survives_restoring_it() {
        let other: &[u8] = b"a completely different wallet seed than the one above";
        assert_eq!(
            group_public_key(SEED).unwrap(),
            group_public_key(SEED).unwrap()
        );
        assert_ne!(
            group_public_key(SEED).unwrap(),
            group_public_key(other).unwrap()
        );
    }

    #[test]
    fn a_group_signature_verifies_against_its_published_key() {
        let challenge = b"a nonce the mediator issued";
        let signature =
            Signature::from_der(&sign_group_challenge(SEED, challenge).unwrap()).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&group_public_key(SEED).unwrap()).unwrap();
        assert!(key.verify(challenge, &signature).is_ok());
    }

    /// Holding the group key must not be enough to empty a box. It authorises
    /// asking about all of them at once, which is a different and lesser thing.
    #[test]
    fn a_group_signature_does_not_open_an_inbox() {
        let challenge = b"a nonce the mediator issued";
        let signature =
            Signature::from_der(&sign_group_challenge(SEED, challenge).unwrap()).unwrap();
        let inbox = VerifyingKey::from_sec1_bytes(&public_key(SEED, 0).unwrap()).unwrap();
        assert!(inbox.verify(challenge, &signature).is_err());
    }

    #[test]
    fn a_signature_from_the_wrong_inbox_does_not_verify() {
        let challenge = b"a nonce the mediator issued";
        let signature = Signature::from_der(&sign_challenge(SEED, 4, challenge).unwrap()).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&public_key(SEED, 5).unwrap()).unwrap();
        assert!(key.verify(challenge, &signature).is_err());
    }

    /// Two rooms must not share a box, and the interesting way for that to fail
    /// is not a hash collision — it is the ids running into each other.
    ///
    /// Without the length prefix, room `b"ab"` + `b"c"` and room `b"a"` +
    /// `b"bc"` produce the same info string. Ids are variable length here, so
    /// that is reachable rather than theoretical, and the result would be one
    /// room able to read and delete another's inbox.
    #[test]
    fn room_ids_that_run_into_each_other_still_get_different_boxes() {
        let one = room_public_key(SEED, b"abc").unwrap();
        let other = room_public_key(SEED, b"ab").unwrap();
        assert_ne!(one, other);

        // The concatenation case stated outright, since it is the one the
        // length prefix exists for.
        let ab_c = room_public_key(SEED, &[b"ab".as_slice(), b"c"].concat()).unwrap();
        let a_bc = room_public_key(SEED, &[b"a".as_slice(), b"bc"].concat()).unwrap();
        assert_eq!(ab_c, a_bc, "same id, same box — this pair IS the same room");
    }

    #[test]
    fn a_room_box_is_the_same_every_time_and_not_the_contact_box() {
        let room = b"a room id";
        assert_eq!(
            room_public_key(SEED, room).unwrap(),
            room_public_key(SEED, room).unwrap(),
            "derivation must be stable or the box is lost on the next launch"
        );

        // A room box and a contact box are different keys even for a device
        // that has exactly one of each: they answer different challenges and
        // deleting one must not touch the other.
        assert_ne!(
            room_public_key(SEED, room).unwrap(),
            public_key(SEED, 0).unwrap()
        );
        assert_ne!(
            room_public_key(SEED, room).unwrap(),
            group_public_key(SEED).unwrap()
        );
    }

    /// Another seed is another person, and must not land on the same box even
    /// in the same room — that box is where their copy of the room arrives.
    #[test]
    fn two_members_of_one_room_have_different_boxes() {
        let room = b"a room id";
        let theirs = room_public_key(b"a different wallet seed entirely", room).unwrap();
        assert_ne!(room_public_key(SEED, room).unwrap(), theirs);
    }

    #[test]
    fn a_room_box_signs_something_its_own_key_verifies() {
        let room = b"a room id";
        let challenge = b"a nonce from the mediator";
        let signature = sign_room_challenge(SEED, room, challenge).unwrap();

        let key = VerifyingKey::from_sec1_bytes(&room_public_key(SEED, room).unwrap()).unwrap();
        let parsed = p256::ecdsa::Signature::from_der(&signature).unwrap();
        assert!(key.verify(challenge, &parsed).is_ok());

        // And not one from another room, which is what stops a member of one
        // room collecting from a box in another.
        let elsewhere =
            VerifyingKey::from_sec1_bytes(&room_public_key(SEED, b"another room").unwrap())
                .unwrap();
        assert!(elsewhere.verify(challenge, &parsed).is_err());
    }
}
