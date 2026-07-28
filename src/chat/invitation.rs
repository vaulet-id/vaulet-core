//! The invitation that starts a conversation (ADR 0013).
//!
//! There is no directory to look anyone up in — deliberately, since a lookup
//! surface is what a DHT would have been and what `user-initiated contact only`
//! forbids. So everything needed to reach a person travels in the one exchange
//! that has to happen anyway: a QR code or a link.
//!
//! **Scanning adds a contact; it does not open a room.** The code carries only
//! what is needed to send that person one sealed message:
//!
//! - **where** — the mediator, and the inbox at it;
//! - **how to seal to them** — the HPKE receiving key for this contact.
//!
//! The MLS key package is *optional here on purpose*. In a QR it is left out,
//! which takes the code from about 990 characters to 260 — the difference
//! between a dense grid a camera has to work at and one that reads instantly.
//! It is filled in for the sealed introduction the two sides exchange
//! afterwards, where size costs nothing.
//!
//! That split also earns something better than size: a key package contains the
//! holder's DID and signature key, so while it rode in the QR **anyone who
//! photographed the screen learned who you were.** Now a photograph yields an
//! inbox address and an encryption key, and identity reaches only the person
//! who actually answers.
//!
//! **Who they are** is never a field of its own. It lives in the MLS credential
//! inside the key package and must be read from there, or an introduction could
//! claim one identity while presenting a key package for another — the
//! impersonation D9 exists to stop.
//!
//! **Both sides need one.** A scanner learns where to send but the person
//! scanned learns nothing, so the reply address travels back in an
//! [`super::envelope::Kind::Introduction`] envelope alongside the Welcome.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use super::{ChatError, Result};

/// Short on purpose: every character of it is modules in the QR code, and it
/// buys nothing but a scheme a phone can route.
const SCHEME: &str = "vlt:i:";

/// The host universal links are anchored to. **Changing it breaks every link
/// already shared**, because a universal link names its own host — so this is
/// the one place it is written, and it is written once.
///
/// A subdomain rather than the apex, and deliberately: `vaulet.id` is the
/// website, and a second app is expected. One host means one
/// `apple-app-site-association` file shared by every app on it, with their path
/// patterns partitioned inside it — so two apps would have to coordinate a
/// single file across two release cycles, and a mistake there routes links to
/// the wrong app or breaks both. A host per app removes that entirely, and
/// keeps a website deploy from silently breaking app links.
pub const LINK_HOST: &str = "app.vaulet.id";
const VERSION: u8 = 2;

/// Compressed P-256 points are always this long, so carrying a length for them
/// spends four bytes saying what the version already says.
const POINT_LEN: usize = 33;

/// `flags` bit 0: the mediator is the default one, and its URL is omitted.
/// A card for any other mediator still spells it out — the flag compresses the
/// common case without making the uncommon one unrepresentable.
const FLAG_DEFAULT_MEDIATOR: u8 = 1 << 0;
/// `flags` bit 1: a key package follows. Absent in a QR code, present in the
/// sealed introduction.
const FLAG_HAS_KEY_PACKAGE: u8 = 1 << 1;

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
    /// MLS key package, so they can be added to a group while asleep. Empty in
    /// a QR code, present in the sealed introduction — see the module docs.
    pub key_package: Vec<u8>,

    /// True when this carries enough to open a room, not merely to write once.
    pub has_key_package: bool,
}

/// P-256 points ride compressed: 33 bytes instead of 65, for the same key.
/// Two of them are half the card, so this is most of what keeps the code
/// sparse enough to read at a glance.
fn compress(public_key: &[u8]) -> Result<Vec<u8>> {
    let key =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| ChatError::Malformed("public key"))?;
    Ok(key.to_encoded_point(true).as_bytes().to_vec())
}

/// Back to the uncompressed form everything else expects, so the saving lives
/// entirely inside this module.
fn decompress(public_key: &[u8]) -> Result<Vec<u8>> {
    let key =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| ChatError::Malformed("public key"))?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_point<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (point, rest) = bytes
        .split_at_checked(POINT_LEN)
        .ok_or(ChatError::Malformed("invitation"))?;
    *bytes = rest;
    Ok(point)
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
///
/// `default_mediator` is the URL this build ships with. When the card names
/// that one, it is replaced by a single bit — which is most of what separates a
/// code you have to hold still for from one that reads at a glance.
pub fn encode(invitation: &Invitation, default_mediator: &str) -> Result<String> {
    let mut flags = 0u8;
    if invitation.mediator == default_mediator {
        flags |= FLAG_DEFAULT_MEDIATOR;
    }
    if invitation.has_key_package {
        flags |= FLAG_HAS_KEY_PACKAGE;
    }

    let mut body = vec![VERSION, flags];
    if flags & FLAG_DEFAULT_MEDIATOR == 0 {
        put(&mut body, invitation.mediator.as_bytes());
    }
    body.extend_from_slice(&compress(&invitation.inbox_public_key)?);
    body.extend_from_slice(&compress(&invitation.envelope_public_key)?);
    if invitation.has_key_package {
        put(&mut body, &invitation.key_package);
    }

    Ok(format!("{SCHEME}{}", B64.encode(body)))
}

/// Strip a link wrapper if there is one.
///
/// A code travels two ways and they are deliberately different. A **QR holds
/// the short form**, because every character is modules a camera has to
/// resolve. A **shared link holds the same string after a `#`**, so it is
/// tappable in any messenger — and the fragment is the point: browsers never
/// send it, so somebody without the app who taps the link does not hand our
/// server the card they were given.
pub fn unwrap_link(text: &str) -> &str {
    let text = text.trim();
    match text.rsplit_once('#') {
        Some((_, payload)) => payload,
        None => text,
    }
}

/// Wrap a code as a link to share as text. The QR keeps the short form.
pub fn share_link(code: &str) -> String {
    format!("https://{LINK_HOST}/c#{code}")
}

/// Decode a scanned or pasted invitation.
///
/// This is the one place in the chat code that meets input chosen by a
/// stranger, so every length is checked and nothing is trusted to be
/// well-formed.
pub fn decode(text: &str, default_mediator: &str) -> Result<Invitation> {
    let encoded = unwrap_link(text)
        .strip_prefix(SCHEME)
        .ok_or(ChatError::Malformed("not a vaulet invitation"))?;
    let body = B64
        .decode(encoded)
        .map_err(|_| ChatError::Malformed("invitation encoding"))?;

    let (&version, rest) = body
        .split_first()
        .ok_or(ChatError::Malformed("empty invitation"))?;
    if version != VERSION {
        return Err(ChatError::UnsupportedInvitationVersion(version));
    }
    let (&flags, mut rest) = rest
        .split_first()
        .ok_or(ChatError::Malformed("invitation flags"))?;

    let mediator = if flags & FLAG_DEFAULT_MEDIATOR != 0 {
        default_mediator.to_string()
    } else {
        String::from_utf8(take(&mut rest)?.to_vec())
            .map_err(|_| ChatError::Malformed("invitation mediator"))?
    };

    let inbox_public_key = decompress(take_point(&mut rest)?)?;
    let envelope_public_key = decompress(take_point(&mut rest)?)?;

    let has_key_package = flags & FLAG_HAS_KEY_PACKAGE != 0;
    let key_package = if has_key_package {
        take(&mut rest)?.to_vec()
    } else {
        Vec::new()
    };

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
        has_key_package,
        key_package,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real P-256 points, generated with openssl — compression is arithmetic
    /// on the curve, so placeholder bytes cannot exercise it.
    const POINT_A: &str = concat!(
        "0427a88cbee10bfd805945e934a80abcea2bc0869f6e01221230a3aa21a67aa9f7",
        "a42146f18f72efacac29104f554b239761f5607891765bd2b876bbc0e1322785",
    );
    const DEFAULT_MEDIATOR: &str = "https://vaulet-mediator.fly.dev";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn card() -> Invitation {
        Invitation {
            mediator: DEFAULT_MEDIATOR.to_string(),
            inbox_public_key: hex(POINT_A),
            envelope_public_key: hex(POINT_A),
            key_package: Vec::new(),
            has_key_package: false,
        }
    }

    fn introduction() -> Invitation {
        Invitation {
            key_package: vec![0xde, 0xad, 0xbe, 0xef],
            has_key_package: true,
            ..card()
        }
    }

    fn round_trip(invitation: &Invitation) -> Invitation {
        decode(
            &encode(invitation, DEFAULT_MEDIATOR).unwrap(),
            DEFAULT_MEDIATOR,
        )
        .unwrap()
    }

    #[test]
    fn a_card_survives_the_round_trip() {
        assert_eq!(round_trip(&card()), card());
    }

    #[test]
    fn an_introduction_survives_with_its_key_package() {
        assert_eq!(round_trip(&introduction()), introduction());
    }

    /// The default mediator is a bit rather than a URL, which is most of what
    /// separates a code you hold still for from one that reads at a glance.
    #[test]
    fn the_default_mediator_costs_almost_nothing_and_others_still_work() {
        let mut elsewhere = card();
        elsewhere.mediator = "https://someone-elses-mediator.example".into();

        assert_eq!(round_trip(&elsewhere), elsewhere);
        assert!(
            encode(&card(), DEFAULT_MEDIATOR).unwrap().len()
                < encode(&elsewhere, DEFAULT_MEDIATOR).unwrap().len()
        );
    }

    /// A card read by a build pointing somewhere else must not silently inherit
    /// that build's mediator for a sender who never chose it.
    #[test]
    fn a_default_flagged_card_resolves_to_the_readers_default() {
        let text = encode(&card(), DEFAULT_MEDIATOR).unwrap();
        let elsewhere = decode(&text, "https://another.example").unwrap();
        assert_eq!(elsewhere.mediator, "https://another.example");
    }

    #[test]
    fn a_card_is_much_shorter_than_an_introduction() {
        assert!(
            encode(&card(), DEFAULT_MEDIATOR).unwrap().len()
                < encode(&introduction(), DEFAULT_MEDIATOR).unwrap().len()
        );
    }

    /// The two ways a code travels must mean the same thing.
    #[test]
    fn a_card_wrapped_in_a_link_decodes_the_same() {
        let bare = encode(&card(), DEFAULT_MEDIATOR).unwrap();
        let link = share_link(&bare);

        assert!(link.starts_with("https://app.vaulet.id/"));
        assert!(link.contains('#'), "the payload must sit in the fragment");
        assert_eq!(decode(&link, DEFAULT_MEDIATOR).unwrap(), card());
    }

    /// The fragment is not decoration: browsers never send it, so a link tapped
    /// by somebody without the app tells our server nothing about the card.
    #[test]
    fn the_link_keeps_the_payload_out_of_the_path() {
        let link = share_link(&encode(&card(), DEFAULT_MEDIATOR).unwrap());
        let (before, _) = link.split_once('#').unwrap();
        assert!(!before.contains("vlt:i:"));
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        // Pasted text picks up newlines; refusing it would be a papercut with
        // no security value, since the payload is checked either way.
        let text = format!("  {}\n", encode(&card(), DEFAULT_MEDIATOR).unwrap());
        assert_eq!(decode(&text, DEFAULT_MEDIATOR).unwrap(), card());
    }

    #[test]
    fn a_credential_offer_is_not_mistaken_for_an_invitation() {
        assert!(matches!(
            decode(
                "openid-credential-offer://?credential_offer=%7B%7D",
                DEFAULT_MEDIATOR
            ),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_invitation_is_refused_rather_than_half_read() {
        let full = encode(&card(), DEFAULT_MEDIATOR).unwrap();
        assert!(decode(&full[..full.len() - 8], DEFAULT_MEDIATOR).is_err());
    }

    #[test]
    fn trailing_junk_is_refused() {
        let mut body = vec![VERSION, FLAG_DEFAULT_MEDIATOR];
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(b"extra");

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(
            decode(&text, DEFAULT_MEDIATOR),
            Err(ChatError::Malformed(_))
        ));
    }

    /// A length field claiming more than the buffer holds must not panic.
    #[test]
    fn a_lying_length_is_refused_rather_than_panicking() {
        let mut body = vec![VERSION, FLAG_HAS_KEY_PACKAGE];
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(b"short");

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(
            decode(&text, DEFAULT_MEDIATOR),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_mediator_that_is_not_a_url_is_refused() {
        // Otherwise the first message of a conversation goes somewhere the
        // sender did not choose.
        let mut invitation = card();
        invitation.mediator = "mediator.example".into();
        let text = encode(&invitation, DEFAULT_MEDIATOR).unwrap();
        assert!(matches!(
            decode(&text, DEFAULT_MEDIATOR),
            Err(ChatError::Malformed(_))
        ));
    }

    #[test]
    fn a_future_invitation_version_is_refused_by_name() {
        let mut body = B64
            .decode(
                encode(&card(), DEFAULT_MEDIATOR)
                    .unwrap()
                    .strip_prefix(SCHEME)
                    .unwrap(),
            )
            .unwrap();
        body[0] = 7;

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(
            decode(&text, DEFAULT_MEDIATOR),
            Err(ChatError::UnsupportedInvitationVersion(7))
        ));
    }
}
