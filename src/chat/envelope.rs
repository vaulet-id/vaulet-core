//! The envelope a blob travels in (ADR 0013).
//!
//! MLS already protects the content, so the envelope exists for two other
//! reasons:
//!
//! - **Sealed sender.** It is encrypted *to* the recipient and says nothing
//!   about who sent it. The mediator accepts deposits from anyone precisely so
//!   that it cannot learn who is depositing, and an envelope that authenticated
//!   its sender would hand that back. Authenticity is not lost: MLS
//!   authenticates the sender inside, where it belongs.
//! - **A type.** Without one the mediator could tell a Welcome from a message
//!   by size and position alone, and the recipient would have to guess which
//!   call to make.
//!
//! **HPKE (RFC 9180), not DIDComm framing, and not anything hand-rolled.**
//! ADR 0013 planned to vendor a DIDComm crate for this. On 2026-07-29 the only
//! maintained Rust DIDComm stack turned out not to compile: its own published
//! crates disagree on types, and it also requires a toolchain a year ahead of
//! this project's. HPKE gives exactly the property needed — encrypt to a public
//! key, sender anonymous — in one primitive that **openmls already ships and
//! that was audited with it**, so this costs no new dependency. The wire format
//! keeps a version byte and a type so that moving to DIDComm framing later is
//! mechanical rather than a redesign.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};

use super::{ChatError, Result};

/// Matched to the MLS ciphersuite so the wallet uses one curve throughout.
const HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKemP256,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

/// Binds the ciphertext to this use. HPKE's `info` is covered by the key
/// schedule, so a sealed envelope cannot be replayed into any other context
/// that happens to use the same key.
const INFO: &[u8] = b"vaulet/chat/envelope/v1";

const VERSION: u8 = 1;

/// What the payload is, so the recipient knows which call to make without
/// having to try one and see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An invitation to a group — hand it to `Session::join`.
    Welcome = 1,
    /// Anything inside an established group — hand it to `Session::receive`.
    MlsMessage = 2,
    /// The sender's own invitation, so the recipient can reply.
    ///
    /// A scanned QR is one-directional: the scanner learns where to send, the
    /// person scanned learns nothing. This is how the reply address gets back,
    /// and it travels sealed rather than in the clear so the mediator does not
    /// learn which two inboxes belong together.
    Introduction = 3,
    /// What the sender calls themselves, and their picture.
    ///
    /// Outside MLS because it has to work before a room exists — a knock
    /// answered with a profile, or a picture that arrives with an introduction.
    /// **So it is not MLS-authenticated**: it is attributed to whoever owns the
    /// inbox it landed in, the same trust the introduction beside it already
    /// rests on. That is enough for a label nobody checks anyway (ADR 0015),
    /// and is why nothing here may ever carry anything that is checked.
    Profile = 4,
    /// The sender's invitation again, because the room between us has stopped
    /// working.
    ///
    /// The payload is exactly an [`Kind::Introduction`], and the separate kind
    /// is the whole point: an introduction says "here is where to reach me",
    /// while this says "throw away the group we had and build another". A
    /// re-introduction happens for ordinary reasons — moving mediator — and
    /// must not tear a working room down.
    ///
    /// **A fresh key package is what makes this work at all.** MLS init keys are
    /// consumed on joining, so the one already used to open the broken room can
    /// never open a second: repair has to be an exchange, not a retry.
    Repair = 5,
}

impl Kind {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Kind::Welcome),
            2 => Ok(Kind::MlsMessage),
            3 => Ok(Kind::Introduction),
            4 => Ok(Kind::Profile),
            5 => Ok(Kind::Repair),
            _ => Err(ChatError::Malformed("unknown envelope kind")),
        }
    }
}

/// The HPKE keypair one contact uses to receive. Derived, so nothing about it
/// is stored: restoring the seed restores it.
///
/// **Deliberately not the inbox signing key.** That one proves the right to
/// empty a box; this one receives content. Using a single key for both ECDSA
/// and ECDH is the sort of reuse that turns one weakness into two.
pub fn keypair(seed: &[u8], index: u32) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ikm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
        .expand(&envelope_info(index), &mut ikm)
        .map_err(|_| ChatError::Mls("envelope key derivation".into()))?;
    keypair_from_ikm(&ikm)
}

/// The same construction from key material derived elsewhere — used by
/// [`super::handle`], whose keys hang off a different label but must be the
/// same kind of key, opened by the same [`open`].
pub fn keypair_from_ikm(ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pair = RustCrypto::default()
        .derive_hpke_keypair(HPKE, ikm)
        .map_err(|e| ChatError::Mls(format!("derive envelope key: {e}")))?;
    Ok((pair.public, pair.private.to_vec()))
}

fn envelope_info(index: u32) -> Vec<u8> {
    let mut info = INFO.to_vec();
    info.extend_from_slice(&index.to_be_bytes());
    info
}

/// Seal a payload to a recipient. Nothing here identifies the sender.
pub fn seal(recipient_public: &[u8], kind: Kind, payload: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(kind as u8);
    plaintext.extend_from_slice(payload);

    let sealed = RustCrypto::default()
        .hpke_seal(HPKE, recipient_public, INFO, &[], &plaintext)
        .map_err(|e| ChatError::Mls(format!("seal envelope: {e}")))?;

    let mut out = vec![VERSION];
    out.extend_from_slice(
        &sealed
            .tls_serialize_detached()
            .map_err(|e| ChatError::Mls(format!("serialize envelope: {e}")))?,
    );
    Ok(out)
}

/// Open an envelope addressed to us. Fails for anything addressed to somebody
/// else, which is what a wrong-inbox delivery looks like.
pub fn open(recipient_private: &[u8], sealed: &[u8]) -> Result<(Kind, Vec<u8>)> {
    let (&version, rest) = sealed
        .split_first()
        .ok_or(ChatError::Malformed("empty envelope"))?;
    if version != VERSION {
        return Err(ChatError::UnsupportedEnvelopeVersion(version));
    }

    let ciphertext = HpkeCiphertext::tls_deserialize_exact(rest)
        .map_err(|_| ChatError::Malformed("envelope"))?;

    let plaintext = RustCrypto::default()
        .hpke_open(HPKE, &ciphertext, recipient_private, INFO, &[])
        .map_err(|_| ChatError::NotForUs)?;

    let (&kind, payload) = plaintext
        .split_first()
        .ok_or(ChatError::Malformed("empty envelope body"))?;
    Ok((Kind::from_byte(kind)?, payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"a wallet seed for the envelope tests, any length will do";

    #[test]
    fn a_sealed_payload_comes_back_with_its_kind() {
        let (public, private) = keypair(SEED, 0).unwrap();
        let sealed = seal(&public, Kind::Welcome, b"an mls welcome").unwrap();

        assert_eq!(
            open(&private, &sealed).unwrap(),
            (Kind::Welcome, b"an mls welcome".to_vec())
        );
    }

    #[test]
    fn the_envelope_reveals_neither_payload_nor_kind() {
        let (public, _) = keypair(SEED, 0).unwrap();
        let sealed = seal(&public, Kind::MlsMessage, b"the quick brown fox").unwrap();

        assert!(
            !sealed.windows(19).any(|w| w == b"the quick brown fox"),
            "the mediator must not see the payload"
        );
        // The kind is inside the ciphertext, so a Welcome and a message are not
        // distinguishable by anything the mediator can read.
        assert!(!sealed[1..].starts_with(&[Kind::MlsMessage as u8]));
    }

    #[test]
    fn an_envelope_for_someone_else_does_not_open() {
        let (theirs, _) = keypair(SEED, 1).unwrap();
        let (_, ours) = keypair(SEED, 2).unwrap();

        let sealed = seal(&theirs, Kind::MlsMessage, b"not for us").unwrap();
        assert!(matches!(open(&ours, &sealed), Err(ChatError::NotForUs)));
    }

    #[test]
    fn tampering_is_caught_rather_than_half_read() {
        let (public, private) = keypair(SEED, 0).unwrap();
        let mut sealed = seal(&public, Kind::MlsMessage, b"intact").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;

        assert!(matches!(open(&private, &sealed), Err(ChatError::NotForUs)));
    }

    #[test]
    fn a_future_envelope_version_is_refused_by_name() {
        let (public, private) = keypair(SEED, 0).unwrap();
        let mut sealed = seal(&public, Kind::MlsMessage, b"hello").unwrap();
        sealed[0] = 42;

        assert!(matches!(
            open(&private, &sealed),
            Err(ChatError::UnsupportedEnvelopeVersion(42))
        ));
    }

    #[test]
    fn each_contact_receives_on_a_different_key() {
        let (a, _) = keypair(SEED, 0).unwrap();
        let (b, _) = keypair(SEED, 1).unwrap();
        assert_ne!(a, b, "receiving keys must not link two conversations");
    }

    #[test]
    fn the_same_seed_and_index_always_derive_the_same_key() {
        assert_eq!(keypair(SEED, 5).unwrap(), keypair(SEED, 5).unwrap());
    }

    /// Two envelopes with identical content must not look identical, or the
    /// mediator could tell that the same thing was sent twice.
    #[test]
    fn sealing_the_same_payload_twice_gives_different_bytes() {
        let (public, _) = keypair(SEED, 0).unwrap();
        let once = seal(&public, Kind::MlsMessage, b"same").unwrap();
        let twice = seal(&public, Kind::MlsMessage, b"same").unwrap();
        assert_ne!(once, twice);
    }
}
