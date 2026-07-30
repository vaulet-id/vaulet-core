//! Being woken when the app is closed, without anybody holding the linkage
//! (ADR 0016).
//!
//! APNs issues one token per install, and whoever pushes must hold it — so
//! pushing means somebody learns that these N inboxes belong to one device,
//! which is the linkage per-contact inboxes exist to deny. This module is how
//! that party is made to be somebody who never sees an inbox, a contact, or a
//! message.
//!
//! Three pieces:
//!
//! - a **push id** derived from the seed, the same idiom as an inbox id: the
//!   identifier is the hash of a key its owner can prove they hold, so
//!   registration needs no account and survives reinstall and restore;
//! - a **ticket** each contact is given once — the push id sealed to the
//!   relay's key — which they cannot read and cannot compare with anybody
//!   else's, because HPKE is randomised;
//! - a **relay** holding nothing but `push id → APNs token`, as a cache it may
//!   lose at any time, because every device re-registers on every launch.
//!
//! The mediator forwards the ticket and holds no key that opens it. **No party
//! ends up with both the linkage and the traffic**, which is the whole point of
//! the arrangement and the reason it is worth three moving parts instead of
//! one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

use super::{envelope, inbox, ChatError, Result};

/// Distinct from every other label the seed feeds, so a push id cannot be
/// worked back to an inbox, a handle, or the identity key.
const PUSH_KEY_INFO: &[u8] = b"vaulet/push/v1";

/// Covers the ticket in HPKE's key schedule, so a ticket cannot be replayed as
/// any other thing sealed to the same relay key.
const TICKET_INFO: &[u8] = b"vaulet/push/ticket/v1";

/// A ticket is `[version][key_id: 4 bytes big-endian][sealed push id]`.
///
/// The key id is **outside** the ciphertext on purpose: the relay has to know
/// which of its keys to try before it can open anything, and during a rotation
/// it holds two.
const TICKET_VERSION: u8 = 1;

/// Which relay key a ticket was made for.
pub type KeyId = u32;

fn derive(seed: &[u8]) -> Result<SigningKey> {
    let mut scalar = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(PUSH_KEY_INFO, &mut scalar)
        .map_err(|_| ChatError::Mls("push key derivation".into()))?;
    SigningKey::from_slice(&scalar).map_err(|_| ChatError::Mls("push scalar out of range".into()))
}

/// The key a device registers with, SEC1-uncompressed.
pub fn public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(derive(seed)?
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// The push id: `base64url(sha256(public key))`.
///
/// **One per device, not one per contact.** Per-contact ids would need a row
/// and an update at the relay for every contact each time Apple issues a new
/// token — which is every reinstall — so it moves the N problem onto the event
/// that happens to everybody rather than solving it. One id costs one row, and
/// the linkage it exposes is exposed to a party that sees nothing else.
pub fn id(public_key: &[u8]) -> String {
    // The same construction as an inbox address, deliberately: two ways of
    // hashing a public key is one way too many.
    inbox::id(public_key)
}

/// Prove the push id is ours, by signing the relay's challenge — the same
/// challenge-and-signature the mediator already uses, so this introduces no new
/// cryptography anywhere.
pub fn sign_challenge(seed: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = derive(seed)?.sign(challenge);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Build the ticket to hand to one contact.
///
/// Given away once, with the introduction, and never refreshed — it carries the
/// push id, which never changes, rather than the token, which changes often.
pub fn ticket(key_id: KeyId, relay_public: &[u8], push_public_key: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(37);
    out.push(TICKET_VERSION);
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(&envelope::seal_to(
        relay_public,
        TICKET_INFO,
        push_public_key,
    )?);
    Ok(out)
}

/// Which key a ticket needs, readable without being able to open it — which is
/// what lets a relay in the middle of a rotation pick the right one, and what
/// lets it tell "made for a key I retired" from "not a ticket".
pub fn ticket_key_id(ticket: &[u8]) -> Result<KeyId> {
    let (&version, rest) = ticket
        .split_first()
        .ok_or(ChatError::Malformed("empty ticket"))?;
    if version != TICKET_VERSION {
        return Err(ChatError::UnsupportedEnvelopeVersion(version));
    }
    let id: [u8; 4] = rest
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or(ChatError::Malformed("ticket key id"))?;
    Ok(KeyId::from_be_bytes(id))
}

/// Open a ticket, returning the push id it names.
///
/// **Everything the relay learns, and all it may ever learn.** It gets an
/// identifier and a device to wake; it never sees an inbox, a contact, a
/// sender, or a byte of anything anybody said.
pub fn open_ticket(relay_private: &[u8], ticket: &[u8]) -> Result<String> {
    ticket_key_id(ticket)?;
    let sealed = ticket.get(5..).ok_or(ChatError::Malformed("ticket body"))?;
    let public_key = envelope::open_from(relay_private, TICKET_INFO, sealed)?;
    Ok(id(&public_key))
}

/// A relay's own keypair, from key material it holds.
///
/// Given rather than generated so that it can be **the same across restarts**:
/// a relay that minted a fresh key on boot would invalidate every ticket every
/// deploy, which is an emergency rotation performed by accident, weekly.
pub fn relay_keypair(ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    envelope::keypair_from_ikm(ikm)
}

/// The public half of a relay key, worked out from the private half.
///
/// So that a deployment configures **one** secret rather than a pair that can
/// be set to keys which do not belong together — a mismatch nobody would notice
/// until every ticket in the world stopped opening.
pub fn relay_public_key(private: &[u8]) -> Result<Vec<u8>> {
    let secret = p256::SecretKey::from_slice(private)
        .map_err(|_| ChatError::Malformed("relay private key"))?;
    Ok(secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// How a relay key is written down in configuration, and read back.
pub fn encode_key(key: &[u8]) -> String {
    B64.encode(key)
}

pub fn decode_key(text: &str) -> Result<Vec<u8>> {
    B64.decode(text.trim())
        .map_err(|_| ChatError::Malformed("relay key encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    const SEED: &[u8] = b"a wallet seed, sixty four bytes in real life but any length here";
    const RELAY_IKM: &[u8] = b"whatever the relay was configured with";

    #[test]
    fn the_push_id_survives_everything_apple_does() {
        // It comes from the seed, not from Apple, which is why a reinstall
        // costs one row at the relay rather than a ticket reissued to every
        // contact.
        assert_eq!(
            id(&public_key(SEED).unwrap()),
            id(&public_key(SEED).unwrap())
        );
    }

    #[test]
    fn a_different_seed_is_a_different_device() {
        let other: &[u8] = b"somebody else's wallet entirely";
        assert_ne!(
            id(&public_key(SEED).unwrap()),
            id(&public_key(other).unwrap())
        );
    }

    #[test]
    fn the_push_key_is_not_any_other_key_the_seed_produces() {
        // If it were, registering for notifications would publish something
        // that also addresses an inbox.
        assert_ne!(
            public_key(SEED).unwrap(),
            inbox::public_key(SEED, 0).unwrap()
        );
    }

    #[test]
    fn registration_is_authenticated_by_the_published_key() {
        let challenge = b"a nonce the relay issued";
        let signature = sign_challenge(SEED, challenge).unwrap();

        let key = VerifyingKey::from_sec1_bytes(&public_key(SEED).unwrap()).unwrap();
        let signature = Signature::from_der(&signature).unwrap();
        assert!(key.verify(challenge, &signature).is_ok());
    }

    #[test]
    fn a_ticket_names_the_device_to_the_relay_and_to_nobody_else() {
        let (relay_public, relay_private) = relay_keypair(RELAY_IKM).unwrap();
        let push = public_key(SEED).unwrap();

        let ticket = ticket(7, &relay_public, &push).unwrap();
        assert_eq!(ticket_key_id(&ticket).unwrap(), 7);
        assert_eq!(open_ticket(&relay_private, &ticket).unwrap(), id(&push));
    }

    /// The property that stops contacts pooling their tickets to work out which
    /// of them are talking to the same person.
    #[test]
    fn two_contacts_holding_tickets_for_one_device_cannot_tell() {
        let (relay_public, _) = relay_keypair(RELAY_IKM).unwrap();
        let push = public_key(SEED).unwrap();

        let one = ticket(1, &relay_public, &push).unwrap();
        let two = ticket(1, &relay_public, &push).unwrap();
        assert_ne!(one, two, "HPKE must be randomised, or the ticket is an id");
    }

    #[test]
    fn the_push_id_is_not_in_the_ticket_in_the_clear() {
        let (relay_public, _) = relay_keypair(RELAY_IKM).unwrap();
        let push = public_key(SEED).unwrap();
        let ticket = ticket(1, &relay_public, &push).unwrap();

        assert!(
            !ticket.windows(push.len()).any(|w| w == push),
            "the mediator forwards this and must not learn who it addresses"
        );
    }

    #[test]
    fn a_retired_relay_key_opens_nothing() {
        let (relay_public, _) = relay_keypair(RELAY_IKM).unwrap();
        let (_, other_private) = relay_keypair(b"the key that replaced it").unwrap();
        let ticket = ticket(1, &relay_public, &public_key(SEED).unwrap()).unwrap();

        assert!(matches!(
            open_ticket(&other_private, &ticket),
            Err(ChatError::NotForUs)
        ));
    }

    #[test]
    fn a_ticket_from_a_future_version_is_refused_by_name() {
        let (relay_public, _) = relay_keypair(RELAY_IKM).unwrap();
        let mut ticket = ticket(1, &relay_public, &public_key(SEED).unwrap()).unwrap();
        ticket[0] = 9;

        assert!(matches!(
            ticket_key_id(&ticket),
            Err(ChatError::UnsupportedEnvelopeVersion(9))
        ));
    }

    #[test]
    fn a_truncated_ticket_is_rejected_rather_than_panicking() {
        assert!(ticket_key_id(&[]).is_err());
        assert!(ticket_key_id(&[TICKET_VERSION, 0, 0]).is_err());
        assert!(open_ticket(b"anything", &[TICKET_VERSION, 0, 0, 0, 1]).is_err());
    }

    /// The check that lets a deployment hold one secret instead of a pair.
    #[test]
    fn the_public_half_can_be_worked_out_from_the_private_one() {
        let (public, private) = relay_keypair(RELAY_IKM).unwrap();
        assert_eq!(relay_public_key(&private).unwrap(), public);
    }

    #[test]
    fn a_configured_key_round_trips_through_its_text_form() {
        let (_, private) = relay_keypair(RELAY_IKM).unwrap();
        assert_eq!(decode_key(&encode_key(&private)).unwrap(), private);
    }
}
