//! A public chat handle — the address you can publish (ADR 0013).
//!
//! A contact card is private and per-person: you hand it to one person and
//! nobody else can link it to you. A handle is the opposite by design — one
//! string you give to anyone, so it can travel by email, on a business card, or
//! in a profile. That is its purpose and also its whole cost.
//!
//! **It resolves itself.** Everything needed to reach the owner is inside it:
//! the box is `sha256` of the signing key it carries, and envelopes are sealed
//! to the HPKE key it carries. Nobody allocates it, nobody looks it up, and it
//! keeps working if the people who wrote it down never speak to us again.
//!
//! That is why it is about ninety characters rather than the ten a LINE ID
//! spends. Ten characters is possible only when a server owns the namespace and
//! answers questions about it; the price of owning your own address is carrying
//! it. Session's identifiers are the same length for the same reason. It is a
//! string to copy, not to type.
//!
//! **It is not the wallet identity key.** Deriving it separately is what keeps
//! a published chat address from revealing which credentials belong to you, and
//! from letting anyone who has seen your credentials message you.
//!
//! Everything a handle reaches is quarantined: see [`super::invitation`] for why
//! a knock is only ever a request, never a conversation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::Sha256;

use super::{envelope, inbox, ChatError, Result};

/// Distinct from every other label, so a published handle cannot be worked back
/// to any other key the seed produces.
const HANDLE_INFO: &[u8] = b"vaulet/chat/handle/v1";

/// `vlt:h:` marks a handle rather than an invitation, so a paste box can tell
/// which one it was given without guessing.
const PREFIX: &str = "vlt:h:";

/// Rotating means picking a new number here. Existing contacts are unaffected —
/// they moved to their own boxes when they were accepted and never use the
/// handle again — so only people holding the old string lose the ability to
/// knock, which is exactly who rotation is meant to shed.
pub type Rotation = u32;

/// The two public halves someone needs to knock on this handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    /// Addresses the knock box: its identifier is this key's hash.
    pub inbox_public_key: Vec<u8>,
    /// Seals the knock, so the mediator carries a request it cannot read.
    pub envelope_public_key: Vec<u8>,
}

impl Handle {
    /// Where knocks are deposited. Derived, never looked up.
    pub fn knock_inbox_id(&self) -> String {
        inbox::id(&self.inbox_public_key)
    }
}

/// Split so the two keys are independent: one signs, one decrypts, and reusing
/// a single key for both is the kind of economy that turns one weakness into
/// two.
fn ikm(seed: &[u8], rotation: Rotation, purpose: u8) -> Result<[u8; 32]> {
    let mut info = HANDLE_INFO.to_vec();
    info.extend_from_slice(&rotation.to_be_bytes());
    info.push(purpose);

    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed)
        .expand(&info, &mut out)
        .map_err(|_| ChatError::Mls("handle derivation".into()))?;
    Ok(out)
}

/// The signing key that owns the knock box, so only we can empty it.
pub fn signing_key(seed: &[u8], rotation: Rotation) -> Result<SigningKey> {
    SigningKey::from_slice(&ikm(seed, rotation, 0)?)
        .map_err(|_| ChatError::Mls("handle scalar out of range".into()))
}

/// Answer the mediator's challenge for the knock box. A different key from
/// every per-contact inbox, so emptying the public box says nothing about the
/// private ones.
pub fn sign_challenge(seed: &[u8], rotation: Rotation, challenge: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = signing_key(seed, rotation)?.sign(challenge);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// The private half that opens knocks sealed to this handle.
pub fn envelope_private_key(seed: &[u8], rotation: Rotation) -> Result<Vec<u8>> {
    Ok(envelope::keypair_from_ikm(&ikm(seed, rotation, 1)?)?.1)
}

/// Our own handle at a given rotation.
pub fn mine(seed: &[u8], rotation: Rotation) -> Result<Handle> {
    Ok(Handle {
        inbox_public_key: signing_key(seed, rotation)?
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        envelope_public_key: envelope::keypair_from_ikm(&ikm(seed, rotation, 1)?)?.0,
    })
}

fn compress(public_key: &[u8]) -> Result<Vec<u8>> {
    let key =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| ChatError::Malformed("public key"))?;
    Ok(key.to_encoded_point(true).as_bytes().to_vec())
}

fn decompress(public_key: &[u8]) -> Result<Vec<u8>> {
    let key =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| ChatError::Malformed("public key"))?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

/// Both points compressed, so the string stays as short as carrying two keys
/// allows.
pub fn encode(handle: &Handle) -> Result<String> {
    let mut body = compress(&handle.inbox_public_key)?;
    body.extend_from_slice(&compress(&handle.envelope_public_key)?);
    Ok(format!("{PREFIX}{}", B64.encode(body)))
}

/// Read a handle somebody gave us. Input from a stranger, so every length is
/// checked and both points must actually be on the curve.
pub fn decode(text: &str) -> Result<Handle> {
    let body = B64
        .decode(
            super::invitation::unwrap_link(text)
                .strip_prefix(PREFIX)
                .ok_or(ChatError::Malformed("not a vaulet handle"))?,
        )
        .map_err(|_| ChatError::Malformed("handle encoding"))?;

    let (inbox_key, envelope_key) = body
        .split_at_checked(33)
        .ok_or(ChatError::Malformed("handle"))?;
    if envelope_key.len() != 33 {
        return Err(ChatError::Malformed("handle"));
    }

    Ok(Handle {
        inbox_public_key: decompress(inbox_key)?,
        envelope_public_key: decompress(envelope_key)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"a wallet seed for the handle tests, any length";

    #[test]
    fn a_handle_survives_the_round_trip() {
        let handle = mine(SEED, 0).unwrap();
        assert_eq!(decode(&encode(&handle).unwrap()).unwrap(), handle);
    }

    #[test]
    fn the_same_seed_and_rotation_always_give_the_same_handle() {
        // Nothing about a handle is stored, so this is what makes a published
        // address survive reinstalling the app.
        assert_eq!(mine(SEED, 0).unwrap(), mine(SEED, 0).unwrap());
    }

    /// Rotating sheds whoever held the old string and nobody else: accepted
    /// contacts moved to their own boxes and never touch the handle again.
    #[test]
    fn rotating_gives_a_completely_different_address() {
        let before = mine(SEED, 0).unwrap();
        let after = mine(SEED, 1).unwrap();

        assert_ne!(before, after);
        assert_ne!(before.knock_inbox_id(), after.knock_inbox_id());
    }

    /// A published chat address must not reveal which credentials are ours, nor
    /// let anyone who has seen our credentials write to us.
    #[test]
    fn the_handle_is_not_any_other_key_the_seed_produces() {
        let handle = mine(SEED, 0).unwrap();
        assert_ne!(
            handle.inbox_public_key,
            inbox::public_key(SEED, 0).unwrap(),
            "the handle must not collide with a per-contact inbox"
        );
        assert_ne!(
            handle.envelope_public_key,
            envelope::keypair(SEED, 0).unwrap().0
        );
    }

    #[test]
    fn its_two_keys_are_independent() {
        let handle = mine(SEED, 0).unwrap();
        assert_ne!(handle.inbox_public_key, handle.envelope_public_key);
    }

    #[test]
    fn the_signature_verifies_against_the_published_key() {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};

        let challenge = b"a nonce the mediator issued";
        let signature = Signature::from_der(&sign_challenge(SEED, 0, challenge).unwrap()).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&mine(SEED, 0).unwrap().inbox_public_key).unwrap();
        assert!(key.verify(challenge, &signature).is_ok());
    }

    /// Rotating must actually change who can empty the box, not just its name.
    #[test]
    fn a_signature_from_another_rotation_does_not_verify() {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};

        let challenge = b"a nonce the mediator issued";
        let signature = Signature::from_der(&sign_challenge(SEED, 1, challenge).unwrap()).unwrap();
        let key = VerifyingKey::from_sec1_bytes(&mine(SEED, 0).unwrap().inbox_public_key).unwrap();
        assert!(key.verify(challenge, &signature).is_err());
    }

    /// Shared as a link, scanned as a bare code — the same handle either way.
    #[test]
    fn a_handle_wrapped_in_a_link_decodes_the_same() {
        let handle = mine(SEED, 0).unwrap();
        let bare = encode(&handle).unwrap();
        let link = super::super::invitation::share_link(&bare);

        assert!(link.starts_with("https://"));
        assert_eq!(decode(&link).unwrap(), handle);
    }

    #[test]
    fn an_invitation_is_not_mistaken_for_a_handle() {
        assert!(matches!(
            decode("vlt:i:AgECGCCtEzKnBkLdEUXEszyq"),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_handle_is_refused_rather_than_half_read() {
        let full = encode(&mine(SEED, 0).unwrap()).unwrap();
        assert!(decode(&full[..full.len() - 10]).is_err());
    }

    #[test]
    fn garbage_that_is_not_on_the_curve_is_refused() {
        let text = format!("{PREFIX}{}", B64.encode([9u8; 66]));
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
    }
}
