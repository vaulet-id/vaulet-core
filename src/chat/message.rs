//! What travels inside an MLS application message (ADR 0013,
//! `docs/didcomm-over-mls-spec.md` §3 and §11).
//!
//! The payload used to be the message text as bare UTF-8, which is enough for
//! chat and enough for nothing else: a "they are typing" signal would arrive as
//! somebody saying the word, and a read receipt would arrive as a chat bubble.
//! Everything a conversation needs beyond the words themselves needs a field
//! saying what it is.
//!
//! **The shape is DIDComm's plaintext message; the encryption is not.** MLS has
//! already done confidentiality, sender authentication, forward secrecy and
//! post-compromise security by the time anything gets here, so wrapping it in
//! JWE would buy nothing and cost a crypto implementation. What is borrowed is
//! the envelope — an id, a type URI, a thread — which is the part that is
//! genuinely hard to get right alone.
//!
//! **`from` and `to` are deliberately absent.** MLS states who sent a message
//! and to whom. A DID in the body would be a second, weaker answer to a question
//! already answered, and the kind of field somebody eventually validates instead
//! of the real one. Anything here that reads a sender identity out of `body` is
//! a bug.
//!
//! The type URIs are ours, under `vaulet.id`, and not `didcomm.org`'s: we are
//! not implementing their protocols, so we must not claim their names.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{ChatError, Result};

/// Something somebody said.
pub const CHAT: &str = "https://vaulet.id/chat/1.0/message";
/// They are typing. Ephemeral — see [`Message::is_stale`].
pub const TYPING: &str = "https://vaulet.id/chat/1.0/typing";
/// Delivered, or read. Batched: one carries many ids.
pub const RECEIPT: &str = "https://vaulet.id/chat/1.0/receipt";
/// Take back messages that were sent — by id, batched like a receipt.
///
/// **A request, not a deletion.** It reaches the recipient's device and asks it
/// to forget; a client that ignores it keeps the message, and nothing here can
/// tell. The sender's own copy goes immediately, which is the only part either
/// end controls.
///
/// It is worth offering anyway, because the case it is for is the one where the
/// message is still sitting undelivered in an inbox: the retract arrives behind
/// it in the same queue, and both are read in order, so the message is dropped
/// before it was ever shown to anybody.
pub const RETRACT: &str = "https://vaulet.id/chat/1.0/retract";

/// What somebody calls themselves, and what they look like.
///
/// **Self-asserted, and nothing here checks it.** Anyone can send any name, so
/// a recipient must never present this as an identity — it is a label its
/// subject chose, and the thing that says who they are is still the key. The UI
/// that shows it is responsible for keeping that distinction visible, and for
/// letting the reader override it with a name they chose themselves.
pub const PROFILE: &str = "https://vaulet.id/chat/1.0/profile";

/// "Something you sent never reached me — send it again."
///
/// A gap is the one failure this protocol cannot repair by waiting. A blob that
/// could not be decrypted is dropped and confirmed, because not dropping it
/// jams every conversation on the device behind one bad message — so the
/// mediator forgets it, and nothing anywhere will produce it a second time. The
/// reader is left with a hole and the sender with a bubble that never gets its
/// tick.
///
/// **It names a time, not a message.** The whole point is that the receiver
/// never saw what it lost, so it cannot name it: what it can say is when it
/// last read something, which bounds what the sender needs to repeat.
///
/// Answering is a courtesy and not an obligation. A sender that no longer has
/// the message, or is talking to somebody asking too often, simply does not —
/// and the gap stays a gap, which is still better than a silence nobody
/// noticed.
pub const RESEND: &str = "https://vaulet.id/chat/1.0/resend";

/// "This is the box to write to for me, in this room."
///
/// A room's members may never have met, so there is no per-contact inbox
/// between them and none may be invented from a relationship that does not
/// exist (ADR 0022). Each member derives one box per room and says so here.
///
/// **Sent inside the room**, which is why it is a message kind rather than an
/// envelope kind: it is encrypted to the members, so the mediator is never told
/// which addresses belong to one room. It would learn that from a fan-out
/// endpoint, which is exactly the endpoint ADR 0018 forbids.
///
/// Sent on joining, and repeated whenever the membership changes — a member who
/// joined after somebody's announcement would otherwise never learn where to
/// write to them, and would silently leave them out of every message.
pub const ROOM_ADDRESS: &str = "https://vaulet.id/chat/1.0/room-address";

/// What a room is called, decided by whoever created it.
///
/// Self-asserted like a display name (ADR 0015) and carried in the room so that
/// everybody sees the same thing. A member may still keep a private name for
/// the room; that one never leaves their device.
pub const ROOM_NAME: &str = "https://vaulet.id/chat/1.0/room-name";

/// "I am applying for something that needs you too" (ADR 0027).
///
/// A request with more than one role — a family travel credential, a guarantee
/// letter — is answered by several people, and this is one of them being asked.
/// The body names the request, the role, and the attempt to join; nothing
/// secret is in it, because what it grants is the chance to *contribute*, not to
/// read anything.
///
/// **Sent in the room rather than as a link, wherever there is a room.** The
/// message is *"send me your passport"*, which is the exact shape of the fraud
/// running in Thailand every day — and MLS states who sent it, so the receiver
/// is told who is asking by the protocol rather than by a claim in the body. A
/// link carries no sender identity at all, which is why it is the fallback and
/// why the wallet has to say so when it opens one.
///
/// The issuer never sees this. The wallets do the inviting; the issuer only
/// ever sees presentations arrive, each naming which role it answers.
pub const REQUEST_INVITE: &str = "https://vaulet.id/requests/1.0/invitation";

/// Most a sender will repeat in answer to one request.
///
/// A bound rather than a judgement about conversations: the request names a
/// time, and a time can name an afternoon. Repeating an afternoon into a
/// conversation that only lost one message would be a worse outcome than the
/// gap.
pub const MAX_RESEND: usize = 20;

/// How old a typing signal may be before it is ignored.
///
/// The mediator queues, so a signal sent by somebody who then went offline is
/// delivered when the *recipient* next collects — which could be hours later,
/// and would draw three animated dots for a person who typed last night.
pub const TYPING_TTL_SECS: i64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique to this message. What a `thid` points at.
    pub id: String,

    /// The type URI: which protocol, which version, which step.
    #[serde(rename = "type")]
    pub kind: String,

    /// Unix seconds, from the sender's clock.
    ///
    /// **Never usable for a security decision** — it is a number the sender
    /// chose. [`Message::is_stale`] is the single exception in the codebase, and
    /// the exception is about drawing dots, not about trusting anybody.
    pub created_time: i64,

    /// The `id` of the message that opened this exchange. Absent on the opener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    /// Whatever this type carries.
    pub body: serde_json::Value,
}

impl Message {
    pub fn new(kind: &str, created_time: i64, body: serde_json::Value) -> Self {
        Self {
            id: fresh_id(),
            kind: kind.to_string(),
            created_time,
            thid: None,
            body,
        }
    }

    /// Whether a *typing* signal has been overtaken by events.
    ///
    /// The receiver decides this, not the sender: only the receiver knows when
    /// it actually arrived, and a sender that went offline mid-word cannot
    /// retract anything. This is the one place `created_time` may be read, and
    /// nothing else may follow the precedent — it is cosmetic, and being lied
    /// to about it costs a pair of animated dots.
    pub fn is_stale(&self, now: i64) -> bool {
        now - self.created_time > TYPING_TTL_SECS
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| ChatError::Mls(format!("encode message: {e}")))
    }

    /// Anything that is not one of ours fails here rather than being guessed at.
    /// Callers drop what they do not recognise **without answering**: an error
    /// sent back would tell whoever probed us which versions we run.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|_| ChatError::Malformed("chat message"))
    }
}

/// The body of [`CHAT`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatBody {
    pub content: String,
}

/// The body of [`ROOM_ADDRESS`] — where to write to one member of a room.
///
/// The key travels with the address for the same reason a deposit carries it
/// (ADR 0018): the box may not exist yet, and a sender holding the key can make
/// it on the deposit that needs it rather than in a request of its own. It
/// authorises nothing — the address is its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomAddressBody {
    /// `base64url(sha256(public_key))`, the same construction as every other
    /// identifier here.
    pub inbox: String,
    /// The box's **signing** key, SEC1-uncompressed, base64url. What creates the
    /// box on the deposit that needs it (ADR 0018); authorises nothing, since
    /// the address is its hash.
    pub inbox_key: String,
    /// The **sealing** key, SEC1-uncompressed, base64url. A different key from
    /// the one above on purpose: signing challenges and agreeing HPKE secrets
    /// with one key is reuse across two algorithms.
    pub sealing_key: String,
    /// Which mediator holds it. Members may be on different ones.
    pub mediator: String,
    /// Their wake ticket, base64url, or empty when they have no push
    /// registration.
    ///
    /// **Opaque to everyone who carries it** — only the relay holds a key that
    /// opens it (ADR 0016) — which is why it can travel in a room without
    /// telling the room's members anything about each other's devices.
    pub push_ticket: String,

    /// What this member calls themselves, for the others to show.
    ///
    /// **A room had no way to learn anybody's name.** It was recorded once, by
    /// whoever did the inviting, from the private nickname *they* had for that
    /// person — so the inviter saw names and everybody else saw none, and
    /// changing your name reached your contacts and never the rooms you were
    /// in. It belongs here because this is the one thing each member says about
    /// themselves inside the room, where MLS says who is speaking.
    ///
    /// Self-asserted, like every other display name (ADR 0015): a label chosen
    /// by the person, never an identity. Empty from a build that predates it.
    #[serde(default)]
    pub name: String,

    /// Whether this member is leaving, and their address is about to stop
    /// existing.
    ///
    /// **Walking out used to be invisible to everybody else.** Leaving destroys
    /// the box the room writes to and sends no commit — there is no way for a
    /// member to commit their own removal — so the others went on addressing a
    /// box that was gone, and every message any of them typed was reported as
    /// reaching one fewer than everybody, for ever, with nothing saying why.
    #[serde(default)]
    pub leaving: bool,
}

/// The body of [`ROOM_NAME`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomNameBody {
    pub name: String,
}

/// The body of [`RECEIPT`].
///
/// It carries a list because a receipt per message doubles the traffic of a
/// two-person conversation, and in a group of N is N messages for every one
/// sent. Batching is the design, not an optimisation to add later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub status: ReceiptStatus,
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    /// Decrypted and stored. Discloses almost nothing the channel does not
    /// already imply.
    Delivered,
    /// Actually on somebody's screen. Opt-out, and symmetric — see the app's
    /// setting, not this file.
    Read,
}

/// 128 bits from the OS, base64url. Long enough that two devices never collide
/// without any coordination, which is the only property an id needs here.
fn fresh_id() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;

    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chat_message_round_trips() {
        let body = serde_json::to_value(ChatBody {
            content: "สวัสดี".into(),
        })
        .unwrap();
        let sent = Message::new(CHAT, 1_753_800_000, body);
        let got = Message::decode(&sent.encode().unwrap()).unwrap();

        assert_eq!(got.kind, CHAT);
        assert_eq!(got.id, sent.id);
        assert_eq!(got.body["content"], "สวัสดี");
        assert!(got.thid.is_none(), "an opener has no thread to point at");
    }

    /// The wire field is `type`, not `kind`. A rename that only this crate
    /// knows about is a rename nobody else can parse, so it is pinned against
    /// the JSON rather than against the struct.
    #[test]
    fn the_type_field_is_called_type_on_the_wire() {
        let json: serde_json::Value = serde_json::from_slice(
            &Message::new(TYPING, 1, serde_json::json!({}))
                .encode()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(json["type"], TYPING);
        assert!(json.get("kind").is_none());
    }

    /// The rule from the spec, as a test rather than a paragraph: a sender
    /// identity in the body is a second answer to a question MLS has already
    /// answered, and the weaker of the two.
    #[test]
    fn nothing_carries_a_sender_identity() {
        let json: serde_json::Value = serde_json::from_slice(
            &Message::new(CHAT, 1, serde_json::json!({"content": "hi"}))
                .encode()
                .unwrap(),
        )
        .unwrap();
        assert!(json.get("from").is_none());
        assert!(json.get("to").is_none());
    }

    #[test]
    fn typing_expires_at_the_receiver() {
        let typed = Message::new(TYPING, 1_000, serde_json::json!({}));
        assert!(!typed.is_stale(1_000 + TYPING_TTL_SECS));
        assert!(typed.is_stale(1_000 + TYPING_TTL_SECS + 1));
    }

    #[test]
    fn two_ids_do_not_collide() {
        assert_ne!(fresh_id(), fresh_id());
    }

    #[test]
    fn bare_text_is_not_a_message() {
        assert!(Message::decode(b"hello").is_err());
    }

    #[test]
    fn a_receipt_carries_many_ids_at_once() {
        let body = serde_json::to_value(ReceiptBody {
            status: ReceiptStatus::Read,
            ids: vec!["a".into(), "b".into()],
        })
        .unwrap();
        let got = Message::decode(&Message::new(RECEIPT, 5, body).encode().unwrap()).unwrap();
        let read: ReceiptBody = serde_json::from_value(got.body).unwrap();
        assert_eq!(read.status, ReceiptStatus::Read);
        assert_eq!(read.ids.len(), 2);
    }

    /// `status` is a lowercase string on the wire, not a Rust variant name.
    #[test]
    fn receipt_status_is_lowercase_on_the_wire() {
        let json = serde_json::to_value(ReceiptStatus::Delivered).unwrap();
        assert_eq!(json, serde_json::json!("delivered"));
    }
}
