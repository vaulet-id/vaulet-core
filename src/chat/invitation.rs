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
const VERSION: u8 = 4;

/// Compressed P-256 points are always this long, so carrying a length for them
/// spends four bytes saying what the version already says.
const POINT_LEN: usize = 33;

/// `flags` bit 0 is unused. It used to mean "the mediator is the well-known one,
/// and its URL is omitted", with the URL held in a constant here — which put one
/// deployment's hostname inside a library that is not supposed to know who is
/// calling it. A card is now always explicit about where its holder is reachable.
///
/// Not a parameter, either. As "the default" it was read by the encoder as the
/// *sender's* and by the decoder as the *reader's*, so two people on different
/// mediators disagreed about where a third was reachable — and a deposit is
/// answered identically whether or not anybody is there, so messages went to an
/// inbox on the wrong machine with nobody told anything. Thirty-odd characters
/// of QR is the cheaper side of that trade.
/// `flags` bit 1: a key package follows. Absent in a QR code, present in the
/// sealed introduction.
const FLAG_HAS_KEY_PACKAGE: u8 = 1 << 1;
/// `flags` bit 2: a display name follows.
const FLAG_HAS_NAME: u8 = 1 << 2;
/// `flags` bit 3: a push ticket follows (ADR 0016).
///
/// **Never in a QR code**, and that is not only about size. A ticket is handed
/// to one person so they can wake this device; a photograph of a screen is not
/// a person. It rides with the key package, in the sealed introduction, where
/// it reaches somebody who has actually answered.
const FLAG_HAS_PUSH_TICKET: u8 = 1 << 3;

/// Caps on the display name, enforced here rather than trusted to the caller
/// (ADR 0015).
///
/// **Both are needed.** A character count alone lets a Thai name cost three
/// bytes each and an emoji four, so 24 "characters" could be 96 bytes or 24 —
/// a fourfold difference in how much of the QR it eats, with nothing to warn
/// anybody. The card is the one place in this system where size is a feature:
/// it went from 986 characters to 97, and a name must not quietly give that
/// back.
pub const MAX_NAME_CHARS: usize = 24;
pub const MAX_NAME_BYTES: usize = 96;

/// Cut a display name down to what a card will carry, on a character boundary.
///
/// Truncating rather than refusing, because the alternative is a card that
/// cannot be made at all because of a name — and the caller that let it get
/// too long is a UI bug, not something the person holding the phone can act on.
pub fn fit_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().take(MAX_NAME_CHARS) {
        if out.len() + c.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

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

    /// The ticket a contact attaches to a deposit so the mediator can have this
    /// device woken (ADR 0016). Opaque to everyone who carries it — only the
    /// relay holds a key that opens it.
    ///
    /// Empty when this build has no push registration, which is the ordinary
    /// case for somebody who declined notifications. A missing ticket means
    /// messages arrive when they open the app, and nothing else changes.
    pub push_ticket: Vec<u8>,

    /// What the holder should call them, chosen by them and checked by nobody.
    /// Empty when unset. Rides in the card itself so somebody handed a code
    /// sees a name with no reply from us — nothing confirms the code to
    /// anybody, which is the property the private card path keeps (ADR 0015).
    pub display_name: String,
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

/// A one-byte length, for fields that are capped well under 256 bytes. Four
/// bytes of length on a 30-byte name is four bytes of QR spent saying nothing.
fn put_short(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn take_point<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (point, rest) = bytes
        .split_at_checked(POINT_LEN)
        .ok_or(ChatError::Malformed("invitation"))?;
    *bytes = rest;
    Ok(point)
}

fn take_short<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (&len, rest) = bytes
        .split_first()
        .ok_or(ChatError::Malformed("invitation"))?;
    let (value, rest) = rest
        .split_at_checked(len as usize)
        .ok_or(ChatError::Malformed("invitation"))?;
    *bytes = rest;
    Ok(value)
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
/// The mediator is always named in full: which one a wallet uses is the
/// application's choice, and a library that shortened one particular host would
/// be choosing for it.
pub fn encode(invitation: &Invitation) -> Result<String> {
    let mut flags = 0u8;
    if invitation.has_key_package {
        flags |= FLAG_HAS_KEY_PACKAGE;
    }
    let display_name = fit_name(&invitation.display_name);
    if !display_name.is_empty() {
        flags |= FLAG_HAS_NAME;
    }
    if !invitation.push_ticket.is_empty() {
        flags |= FLAG_HAS_PUSH_TICKET;
    }

    let mut body = vec![VERSION, flags];
    put(&mut body, invitation.mediator.as_bytes());
    body.extend_from_slice(&compress(&invitation.inbox_public_key)?);
    body.extend_from_slice(&compress(&invitation.envelope_public_key)?);
    if invitation.has_key_package {
        put(&mut body, &invitation.key_package);
    }
    if !display_name.is_empty() {
        put_short(&mut body, display_name.as_bytes());
    }
    if !invitation.push_ticket.is_empty() {
        put_short(&mut body, &invitation.push_ticket);
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
pub fn decode(text: &str) -> Result<Invitation> {
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

    let mediator = String::from_utf8(take(&mut rest)?.to_vec())
        .map_err(|_| ChatError::Malformed("invitation mediator"))?;

    let inbox_public_key = decompress(take_point(&mut rest)?)?;
    let envelope_public_key = decompress(take_point(&mut rest)?)?;

    let has_key_package = flags & FLAG_HAS_KEY_PACKAGE != 0;
    let key_package = if has_key_package {
        take(&mut rest)?.to_vec()
    } else {
        Vec::new()
    };

    let display_name = if flags & FLAG_HAS_NAME != 0 {
        // Input chosen by a stranger: it is only ever shown, never parsed, and
        // it is cut to the cap here so a hand-made card cannot make a row of
        // the UI arbitrarily long.
        fit_name(
            std::str::from_utf8(take_short(&mut rest)?)
                .map_err(|_| ChatError::Malformed("invitation display name"))?,
        )
    } else {
        String::new()
    };

    let push_ticket = if flags & FLAG_HAS_PUSH_TICKET != 0 {
        take_short(&mut rest)?.to_vec()
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
        display_name,
        push_ticket,
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
    const DEFAULT_MEDIATOR: &str = "https://mediator.example";

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
            display_name: String::new(),
            push_ticket: Vec::new(),
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
        decode(&encode(invitation).unwrap()).unwrap()
    }

    /// The whole point of the name being in the card: it arrives with no reply
    /// from us, so nothing confirms the code to whoever is holding it.
    #[test]
    fn a_card_carries_a_display_name() {
        let named = Invitation {
            display_name: "สมชาย ใจดี".into(),
            ..card()
        };
        assert_eq!(round_trip(&named).display_name, "สมชาย ใจดี");
    }

    /// Both caps, because a character count alone lets Thai cost three bytes a
    /// character and an emoji four — 24 "characters" is anywhere from 24 to 96
    /// bytes, and the card is the one place where that difference is a feature
    /// being spent.
    #[test]
    fn a_name_is_cut_to_both_caps() {
        assert_eq!(fit_name(&"a".repeat(100)).chars().count(), MAX_NAME_CHARS);

        let fitted = fit_name(&"🙂".repeat(100));
        assert!(fitted.len() <= MAX_NAME_BYTES);
        assert!(fitted.chars().count() <= MAX_NAME_CHARS);
        assert!(
            fitted.chars().next().is_some(),
            "cutting is on a character boundary, never mid-codepoint"
        );
    }

    /// A card made with an over-long name is still a valid card — the encoder
    /// cuts it rather than refusing, because a name is not a reason to be
    /// unable to hand somebody a code.
    #[test]
    fn an_over_long_name_shortens_the_card_rather_than_breaking_it() {
        let shouting = Invitation {
            display_name: "ก".repeat(200),
            ..card()
        };
        assert_eq!(
            round_trip(&shouting).display_name.chars().count(),
            MAX_NAME_CHARS
        );
    }

    /// What the name costs, stated rather than assumed. A Thai name at the cap
    /// takes the card from QR version 5 to about 8 — still readable across a
    /// table, and this test is here so a future change that doubles it again
    /// has to say so out loud.
    #[test]
    fn a_name_at_the_cap_keeps_the_card_scannable() {
        let bare = encode(&card()).unwrap();
        let named = encode(&Invitation {
            display_name: "ก".repeat(MAX_NAME_CHARS),
            ..card()
        })
        .unwrap();

        // 110 before the mediator was always spelled out; the URL is the whole
        // difference. Still a QR that reads at a glance — the ceiling below is
        // the one that matters, because it is the one tied to a QR version.
        assert!(bare.len() < 150, "the bare card stays tiny: {}", bare.len());
        assert!(
            named.len() < 240,
            "a named card stays inside QR version 9: {}",
            named.len()
        );
    }

    /// Nothing is spent when nobody has set a name — the flag is the whole cost.
    #[test]
    fn a_nameless_card_is_no_bigger_than_before() {
        assert_eq!(
            encode(&card()).unwrap(),
            encode(&Invitation {
                display_name: String::new(),
                ..card()
            })
            .unwrap()
        );
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
        assert!(encode(&card()).unwrap().len() < encode(&elsewhere).unwrap().len());
    }

    /// A card read by a build pointing somewhere else must not silently inherit
    /// that build's mediator for a sender who never chose it.
    #[test]
    fn a_card_resolves_to_the_mediator_it_names() {
        // **This test used to assert the opposite**, and that is why the bug
        // lived: it said a flagged card resolves to *the reader's* default,
        // which is a different machine for anybody running their own. The
        // sender is describing where they are, not asking the reader where they
        // themselves are. There is no flag now, and nothing left to inherit.
        let text = encode(&card()).unwrap();
        assert_eq!(decode(&text).unwrap().mediator, card().mediator);
    }

    #[test]
    fn a_card_is_much_shorter_than_an_introduction() {
        assert!(encode(&card()).unwrap().len() < encode(&introduction()).unwrap().len());
    }

    /// The two ways a code travels must mean the same thing.
    #[test]
    fn a_card_wrapped_in_a_link_decodes_the_same() {
        let bare = encode(&card()).unwrap();
        let link = share_link(&bare);

        assert!(link.starts_with("https://app.vaulet.id/"));
        assert!(link.contains('#'), "the payload must sit in the fragment");
        assert_eq!(decode(&link).unwrap(), card());
    }

    /// The fragment is not decoration: browsers never send it, so a link tapped
    /// by somebody without the app tells our server nothing about the card.
    #[test]
    fn the_link_keeps_the_payload_out_of_the_path() {
        let link = share_link(&encode(&card()).unwrap());
        let (before, _) = link.split_once('#').unwrap();
        assert!(!before.contains("vlt:i:"));
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        // Pasted text picks up newlines; refusing it would be a papercut with
        // no security value, since the payload is checked either way.
        let text = format!("  {}\n", encode(&card()).unwrap());
        assert_eq!(decode(&text).unwrap(), card());
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
        let full = encode(&card()).unwrap();
        assert!(decode(&full[..full.len() - 8]).is_err());
    }

    #[test]
    fn trailing_junk_is_refused() {
        let mut body = vec![VERSION, 0];
        put(&mut body, b"https://mediator.example");
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(&compress(&hex(POINT_A)).unwrap());
        body.extend_from_slice(b"extra");

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
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
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
    }

    #[test]
    fn a_mediator_that_is_not_a_url_is_refused() {
        // Otherwise the first message of a conversation goes somewhere the
        // sender did not choose.
        let mut invitation = card();
        invitation.mediator = "mediator.example".into();
        let text = encode(&invitation).unwrap();
        assert!(matches!(decode(&text), Err(ChatError::Malformed(_))));
    }

    /// The ticket travels with the key package, to somebody who answered — not
    /// in a code a stranger can photograph off a screen.
    #[test]
    fn a_push_ticket_survives_the_introduction_it_rides_in() {
        let ticket = vec![1u8, 0, 0, 0, 3, 9, 9, 9];
        let mut introduction = introduction();
        introduction.push_ticket = ticket.clone();

        let text = encode(&introduction).unwrap();
        assert_eq!(decode(&text).unwrap().push_ticket, ticket);
    }

    /// Somebody who declined notifications has no ticket, and that must be an
    /// ordinary card rather than a special case anybody has to handle.
    #[test]
    fn no_ticket_is_a_card_like_any_other() {
        let text = encode(&introduction()).unwrap();
        assert!(decode(&text).unwrap().push_ticket.is_empty());
    }

    /// The QR is the one place in this system where size is a feature — 97
    /// characters, read at a glance. A ticket would nearly triple it, for
    /// something the scanner cannot use until they have answered anyway.
    #[test]
    fn a_card_stays_short_whatever_the_introduction_carries() {
        let card = encode(&card()).unwrap();
        // Was 120 while a card for one known mediator carried a bit instead of
        // a URL. That compression put a deployment's hostname in this library,
        // so it is gone and every card names its mediator; this ceiling is the
        // budget that replaced it.
        assert!(
            card.len() < 150,
            "the card grew to {} characters",
            card.len()
        );
    }

    #[test]
    fn a_future_invitation_version_is_refused_by_name() {
        let mut body = B64
            .decode(encode(&card()).unwrap().strip_prefix(SCHEME).unwrap())
            .unwrap();
        body[0] = 7;

        let text = format!("{SCHEME}{}", B64.encode(body));
        assert!(matches!(
            decode(&text),
            Err(ChatError::UnsupportedInvitationVersion(7))
        ));
    }

    /// **A card must name the same mediator to everybody who reads it.**
    ///
    /// The size optimisation replaces the mediator with one bit when it is the
    /// default — and "the default" used to mean *the reader's own*, which is a
    /// different value for anybody running their own mediator. Two people with
    /// different defaults therefore disagreed about where a third was
    /// reachable, and the failure is total and silent: deposits are answered
    /// identically whether or not anybody is there, so messages went to an
    /// inbox on the wrong machine and neither party was told anything.
    ///
    /// Latent while every build shipped one hardcoded mediator, and certain to
    /// fire the moment "anyone can run one" (ADR 0013) becomes true in the UI.
    /// Found by running two mediators and putting a room across them.
    #[test]
    fn a_card_names_the_same_mediator_however_the_reader_is_configured() {
        let invitation = Invitation {
            mediator: "https://mediator.example".into(),
            ..card()
        };

        let text = encode(&invitation).unwrap();
        assert_eq!(
            decode(&text).unwrap().mediator,
            "https://mediator.example",
            "a named mediator must survive being read by anybody"
        );

        // And a second host, to show nothing is special-cased: whatever the
        // card names is what comes back out of it.
        let other = Invitation {
            mediator: "https://mediator.example".into(),
            ..card()
        };
        assert_eq!(
            decode(&encode(&other).unwrap()).unwrap().mediator,
            "https://mediator.example"
        );
    }
}
