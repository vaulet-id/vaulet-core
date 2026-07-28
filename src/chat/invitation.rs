//! The invitation that starts a conversation (ADR 0013).
//!
//! There is no directory to look anyone up in — deliberately, since a lookup
//! surface is what a DHT would have been and what `user-initiated contact only`
//! forbids. So everything needed to reach a person travels in the one exchange
//! that has to happen anyway: a QR code or a link.
//!
//! It carries, all of it public:
//!
//! - **where** — the mediator, and the inbox at it;
//! - **how to seal to them** — the HPKE receiving key for this contact;
//! - **how to add them to a group while they sleep** — an MLS key package;
//! **Not** who they are. That is in the MLS credential inside the key package
//! and must be read from there: carrying it as a field of its own would let an
//! invitation claim one identity while presenting a key package for another,
//! which is the impersonation D9 exists to stop.
//!
//! Nothing here is secret, and none of it needs to be: it is the set of public
//! facts required to send someone a first sealed message. It *is* linkable —
//! anyone who photographs the code learns that inbox belongs to whoever showed
//! it — which is why an invitation is per-contact and not a public handle.
//!
//! **Both sides need one.** A scanner learns where to send but the person
//! scanned learns nothing, so the reply address travels back in an
//! [`super::envelope::Kind::Introduction`] envelope alongside the Welcome.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

use super::{ChatError, Result};

/// `vaulet://invite?d=…` so the same string works as a QR code and as a link.
const SCHEME: &str = "vaulet://invite?d=";
const VERSION: u8 = 1;

/// Everything one device needs to start talking to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// Base URL of the mediator holding their inbox. Carried rather than
    /// assumed, because a user who moves mediators must stay reachable.
    pub mediator: String,
    /// SEC1 public key whose hash is the inbox address.
    pub inbox_public_key: Vec<u8>,
    /// HPKE key to seal envelopes to. Distinct from the inbox key on purpose.
    pub envelope_public_key: Vec<u8>,
    /// MLS key package, so they can be added to a group while asleep.
    pub key_package: Vec<u8>,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (len, rest) = bytes
        .split_at_checked(4)
        .ok_or(ChatError::Malformed("invitation"))?;
    let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let (value, rest) = rest
        .split_at_checked(len)
        .ok_or(ChatError::Malformed("invitation"))?;
    *bytes = rest;
    Ok(value)
}

/// Encode for display as a QR code or a link.
pub fn encode(invitation: &Invitation) -> String {
    let mut body = vec![VERSION];
    put(&mut body, invitation.mediator.as_bytes());
    put(&mut body, &invitation.inbox_public_key);
    put(&mut body, &invitation.envelope_public_key);
    put(&mut body, &invitation.key_package);

    format!("{SCHEME}{}", B64.encode(body))
}

/// Decode a scanned or pasted invitation.
///
/// This is the one place in the chat code that meets input chosen by a
/// stranger, so every length is checked and nothing is trusted to be
/// well-formed.
pub fn decode(text: &str) -> Result<Invitation> {
    let encoded = text
        .trim()
        .strip_prefix(SCHEME)
        .ok_or(ChatError::Malformed("not a vaulet invitation"))?;
    let body = B64
        .decode(encoded)
        .map_err(|_| ChatError::Malformed("invitation encoding"))?;

    let (&version, mut rest) = body
        .split_first()
        .ok_or(ChatError::Malformed("empty invitation"))?;
    if version != VERSION {
        return Err(ChatError::UnsupportedInvitationVersion(version));
    }

    let mediator = String::from_utf8(take(&mut rest)?.to_vec())
        .map_err(|_| ChatError::Malformed("invitation mediator"))?;
    let inbox_public_key = take(&mut rest)?.to_vec();
    let envelope_public_key = take(&mut rest)?.to_vec();
    let key_package = take(&mut rest)?.to_vec();

    if !rest.is_empty() {
        return Err(ChatError::Malformed("trailing invitation data"));
    }
    // A mediator that is not an absolute URL would send the first message
    // somewhere unintended, so it is refused here rather than at send time.
    if !mediator.starts_with("https://") && !mediator.starts_with("http://") {
        return Err(ChatError::Malformed("invitation mediator is not a url"));
    }

    Ok(Invitation {
        mediator,
        inbox_public_key,
        envelope_public_key,
        key_package,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invitation {
        Invitation {
            mediator: "https://mediator.example".into(),
            inbox_public_key: vec![4, 1, 2, 3],
            envelope_public_key: vec![4, 9, 8, 7],
            key_package: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn an_invitation_survives_the_round_trip() {
        assert_eq!(decode(&encode(&sample())).unwrap(), sample());
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        // Pasted text picks up newlines; refusing it would be a papercut with
        // no security value, since the payload is checked either way.
        let text = format!("  {}\n", encode(&sample()));
        assert_eq!(decode(&text).unwrap(), sample());
    }

    #[test]
    fn a_credential_offer_is_not_mistaken_for_an_invitation() {
        assert!(matches!(
            decode("openid-credential-offer://?credential_offer=%7B%7D"),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_invitation_is_refused_rather_than_half_read() {
        let full = encode(&sample());
        let cut = &full[..full.len() - 8];
        assert!(decode(cut).is_err());
    }

    #[test]
    fn trailing_junk_is_refused() {
        let mut body = vec![VERSION];
        put(&mut body, b"https://mediator.example");
        put(&mut body, &[4, 1, 2, 3]);
        put(&mut body, &[4, 9, 8, 7]);
        put(&mut body, &[0xde]);
        body.extend_from_slice(b"extra");

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
    }

    /// A length field claiming more than the buffer holds must not panic.
    #[test]
    fn a_lying_length_is_refused_rather_than_panicking() {
        let mut body = vec![VERSION];
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(b"short");

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
    }

    #[test]
    fn a_mediator_that_is_not_a_url_is_refused() {
        // Otherwise the first message of a conversation goes somewhere the
        // sender did not choose.
        let mut invitation = sample();
        invitation.mediator = "mediator.example".into();
        assert!(matches!(
            decode(&encode(&invitation)),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_future_invitation_version_is_refused_by_name() {
        let mut body = encode(&sample())
            .strip_prefix(SCHEME)
            .map(|b| B64.decode(b).unwrap())
            .unwrap();
        body[0] = 7;

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(
            decode(&text),
            Err(ChatError::UnsupportedInvitationVersion(7))
        ));
    }
}
