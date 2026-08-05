//! Being asked to take part in somebody else's request (ADR 0027).
//!
//! A request that needs more than one person has to reach the other people. Two
//! ways, and they are not equivalent:
//!
//! - **In the conversation**, as a [`crate::chat::message::REQUEST_INVITE`]
//!   message. MLS states who sent it, so the receiver knows who is asking
//!   before they read a word of it.
//! - **As a link**, when there is no conversation — sent by LINE, SMS or email.
//!   It reaches anybody, and it proves nothing about who sent it.
//!
//! Both carry the same four facts, which is why they are one type here. What
//! differs is entirely what the receiver may conclude, and the wallet has to say
//! so: *"tap here and send your passport"* is the exact shape of the fraud
//! running in Thailand every day.
//!
//! **Nothing in an invitation is secret.** It names a request, a role and an
//! attempt to join. What it grants is the chance to contribute something of your
//! own — never to read what anybody else contributed, which stays sealed with
//! the issuer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// Where a link lands. A path the app claims, and a fragment browsers never
/// send — so a link tapped by somebody without the app tells our server
/// nothing about who they were asked to be.
pub const INVITE_LINK_PREFIX: &str = "https://app.vaulet.id/r#";

/// One person being asked to answer one role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    /// The request, as its publisher's id.
    pub manifest_id: String,
    /// Which role the receiver is being asked to answer.
    pub role: String,
    /// The attempt to join, so their answer lands beside the asker's rather
    /// than starting a second application nobody is waiting on.
    pub session: String,
    /// What the request is called, so the invitation reads as something rather
    /// than as an id. Self-asserted by the sender like a display name, and the
    /// wallet re-reads the real title from the issuer before anybody presents
    /// anything.
    #[serde(default)]
    pub title: String,
    /// Whose issuer serves it. Absent means ours.
    ///
    /// Here because a self-hosted request must be answerable through the same
    /// invitation — otherwise multi-party works only for requests we issue,
    /// which is precisely the outcome ADR 0027 exists to avoid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_url: Option<String>,
}

impl Invitation {
    /// The body of the chat message that carries it.
    pub fn to_body(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    pub fn from_body(body: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(body.clone())
            .map_err(|e| CoreError::Protocol(format!("invitation body: {e}")))
    }

    /// A link for somebody who is not in a conversation with us.
    pub fn to_link(&self) -> Result<String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| CoreError::Protocol(format!("invitation json: {e}")))?;
        Ok(format!("{INVITE_LINK_PREFIX}{}", B64URL.encode(json)))
    }

    /// Read one back. Accepts the whole link or just the fragment, because the
    /// app receives the fragment alone from the platform.
    pub fn from_link(link: &str) -> Result<Self> {
        let payload = link.rsplit('#').next().unwrap_or_default();
        if payload.is_empty() {
            return Err(CoreError::Protocol("invitation link is empty".into()));
        }
        let json = B64URL
            .decode(payload)
            .map_err(|e| CoreError::Protocol(format!("invitation link b64: {e}")))?;
        serde_json::from_slice(&json)
            .map_err(|e| CoreError::Protocol(format!("invitation link json: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invitation {
        Invitation {
            manifest_id: "family-dtc".into(),
            role: "companion".into(),
            session: "a1b2c3".into(),
            title: "Family travel credential".into(),
            service_url: None,
        }
    }

    #[test]
    fn a_link_round_trips() {
        let link = sample().to_link().unwrap();
        assert!(link.starts_with(INVITE_LINK_PREFIX));
        assert_eq!(Invitation::from_link(&link).unwrap(), sample());
    }

    /// The app is handed the fragment alone, never the whole URL.
    #[test]
    fn the_fragment_alone_is_enough() {
        let link = sample().to_link().unwrap();
        let fragment = link.rsplit('#').next().unwrap();
        assert_eq!(Invitation::from_link(fragment).unwrap(), sample());
    }

    /// **What the receiver is asked for must not travel in the path.** The
    /// whole payload sits after the `#`, which browsers do not send — so
    /// somebody who taps the link without the app has not told our server which
    /// request they were invited to or as whom.
    #[test]
    fn nothing_about_the_request_is_in_the_part_a_browser_sends() {
        let link = sample().to_link().unwrap();
        let before_fragment = link.split('#').next().unwrap();
        assert!(!before_fragment.contains("family-dtc"), "{link}");
        assert!(!before_fragment.contains("companion"), "{link}");
        assert!(!before_fragment.contains("a1b2c3"), "{link}");
    }

    #[test]
    fn a_link_that_is_not_one_is_refused_rather_than_guessed_at() {
        assert!(Invitation::from_link("https://app.vaulet.id/r#").is_err());
        assert!(Invitation::from_link("not a link").is_err());
        assert!(Invitation::from_link(&format!("{INVITE_LINK_PREFIX}bm90LWpzb24")).is_err());
    }

    /// The chat body and the link say the same thing, or a request answered
    /// through one would behave differently than through the other.
    #[test]
    fn the_chat_body_and_the_link_carry_the_same_invitation() {
        let from_body = Invitation::from_body(&sample().to_body()).unwrap();
        let from_link = Invitation::from_link(&sample().to_link().unwrap()).unwrap();
        assert_eq!(from_body, from_link);
    }
}
