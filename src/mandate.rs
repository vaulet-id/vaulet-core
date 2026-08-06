//! What an organisation's directors authorised us to sign (ADR 0029, ADR 0030).
//!
//! A manifest is the organisation acting, so its rule decides whether it may be
//! published. The rule counts signatures, and this is where the signatures come
//! from: an `authorise` statement per director, each naming the exact manifest
//! being published.
//!
//! ## Nothing here needs Vaulet
//!
//! **That is the requirement, not a nice property.** An organisation that moves
//! to its own server keeps this working unchanged, and a court reading a
//! mandate years from now does not have to ask us anything. So:
//!
//! - **A mandate is an artefact, not a session.** It is a list of signed
//!   statements. Nothing is half-held anywhere; there is no state on a server
//!   that has to be alive for it to mean something.
//! - **Every signature carries its own key.** A director signs as `did:jwk`,
//!   which *is* the public key, so verifying needs no directory, no lookup and
//!   no network.
//! - **Collecting them is somebody's job, not ours.** Whoever publishes gathers
//!   the statements and submits them together. We may offer a place to leave
//!   one — that is a convenience, and the day it goes away nothing here breaks.
//! - **Verification lives in the core**, so the issuer we run and an issuer a
//!   customer runs reach the same verdict by running the same code rather than
//!   by agreeing to.
//!
//! ## What binds a signature to one manifest
//!
//! The statement's subject is a digest of the manifest **exactly as it was
//! submitted, byte for byte**. Not a canonical form of it: a canonicalisation
//! is a second specification that Studio, the issuer and every future client
//! would each have to implement identically, and this repository has spent the
//! week paying for pairs of implementations that agreed with themselves.
//!
//! The cost is that re-serialising a manifest changes its digest, so whoever
//! publishes must send the bytes the directors were shown. That is a client's
//! job and it is a visible failure when it is got wrong, which is the kind of
//! failure to prefer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::rule::Rule;
use crate::statement::{Act, SignedStatement};
use crate::{CoreError, Result};

/// The sentence a director reads before authorising us.
///
/// **It lives here and nowhere else.** The wording is hashed into every
/// signature (ADR 0029), so a second copy anywhere — a catalogue entry, a
/// string in Studio, a translation file — is a second hash and a mandate that
/// verifies against one and not the other.
///
/// Not the act catalogue's generic `authorise`: that one says nothing about on
/// whose behalf, and a mandate has to, or an authorisation gathered by one
/// company is presentable by another submitting the same manifest.
pub fn template() -> crate::statement::Template {
    crate::statement::Template {
        act: "authorise".into(),
        version: 1,
        wording: std::collections::BTreeMap::from([
            (
                "th".to_string(),
                "ข้าพเจ้ามอบอำนาจให้ Vaulet {scope} สำหรับ {about} ในนามของ {org} \
                 ภายในขอบเขต {limit} จนถึงวันที่ {until}"
                    .to_string(),
            ),
            (
                "en".to_string(),
                "I authorise Vaulet to {scope} for {about} on behalf of {org}, \
                 limited to {limit}, until {until}"
                    .to_string(),
            ),
        ]),
    }
}

/// The digest a director's signature names: SHA-256 of the manifest bytes as
/// they were submitted.
pub fn digest(manifest_bytes: &[u8]) -> String {
    B64.encode(Sha256::digest(manifest_bytes))
}

/// One director's authorisation, verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorisation {
    /// Who signed, as `did:jwk` — which is also the key that verified it.
    pub signer: String,
    pub statement: SignedStatement,
}

/// Read a mandate: verify every statement in it and return who signed.
///
/// `statements` are SD-JWT VCs, each signed by one director. Returns the
/// signers in the order given, with duplicates left in — deciding whether they
/// are enough is [`Rule::satisfied_by`]'s job, and it counts a repeated signer
/// once.
///
/// **One bad statement fails the whole mandate.** A signature that does not
/// verify is a forgery attempt or a mix-up, and quietly dropping it would let
/// either become "not quite enough signatures" — a message that sends somebody
/// looking for another director rather than for the problem.
pub fn read(
    statements: &[String],
    org_did: &str,
    manifest_digest: &str,
    now: i64,
) -> Result<Vec<Authorisation>> {
    statements
        .iter()
        .map(|sd_jwt| one(sd_jwt, org_did, manifest_digest, now))
        .collect()
}

fn one(sd_jwt: &str, org_did: &str, manifest_digest: &str, now: i64) -> Result<Authorisation> {
    let signer = issuer_of(sd_jwt)?;
    let jwk = jwk_in(&signer)?;
    let (act, statement) = crate::statement::verify_statement(sd_jwt, &jwk, now)?;

    if act != Act::Authorise {
        return Err(CoreError::Protocol(format!(
            "a mandate is an authorisation, and this is a {}",
            statement.act
        )));
    }
    // **The manifest, exactly.** Without this a director's signature is a
    // blank one: gathered for a harmless manifest and replayed against
    // whatever somebody publishes next.
    if statement.subject != manifest_digest {
        return Err(CoreError::Protocol(
            "this authorisation was signed for a different manifest".into(),
        ));
    }
    // And the organisation, so an authorisation to publish for one company
    // cannot be presented as one for another.
    match statement.fields.get("org") {
        Some(o) if o == org_did => {}
        _ => {
            return Err(CoreError::Protocol(
                "this authorisation does not name this organisation".into(),
            ))
        }
    }

    Ok(Authorisation { signer, statement })
}

/// Whether these authorisations, plus whoever else has already signed, satisfy
/// the organisation's rule.
pub fn enough(rule: &Rule, signers: &[String]) -> bool {
    rule.satisfied_by(signers)
}

/// The `iss` of an SD-JWT, read without verifying — only to learn which key to
/// verify with, which is then checked by the verification itself.
fn issuer_of(sd_jwt: &str) -> Result<String> {
    let jwt = sd_jwt.split('~').next().unwrap_or_default();
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| CoreError::Protocol("not a 3-part JWS".into()))?;
    let bytes = B64
        .decode(payload)
        .map_err(|e| CoreError::Protocol(format!("payload b64: {e}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| CoreError::Protocol(format!("payload json: {e}")))?;
    value
        .get("iss")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| CoreError::Protocol("the statement says who it is about but not who signed it".into()))
}

/// The public key inside a `did:jwk`.
///
/// A director signs as a key, not as a name in a directory — which is what
/// makes a mandate verifiable by somebody who has never heard of us.
fn jwk_in(did: &str) -> Result<Value> {
    let b64 = did
        .strip_prefix("did:jwk:")
        .ok_or_else(|| CoreError::Protocol(format!("a mandate is signed by a did:jwk, not {did}")))?;
    let raw = B64
        .decode(b64)
        .map_err(|e| CoreError::Protocol(format!("did:jwk b64: {e}")))?;
    serde_json::from_slice(&raw).map_err(|e| CoreError::Protocol(format!("did:jwk json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::software::SoftwareKey;
    use crate::statement::{issue_statement, Statement};
    use std::collections::BTreeMap;

    const NOW: i64 = 1_700_000_000;
    const ORG: &str = "did:web:org.vaulet.id:acme";

    /// One director's authorisation, signed by their own key.
    fn signed_by(key: &SoftwareKey, subject: &str, org: &str) -> (String, String) {
        let jwk = key.public_jwk().unwrap();
        let did = crate::did::did_jwk_from_public(&jwk).unwrap();
        let statement = Statement {
            act: Act::Authorise,
            subject: subject.into(),
            // `scope` and `limit` are the act's own requirements (ADR 0029),
            // and they are what stops a mandate being a blank cheque: an
            // authority that said "sign anything we publish" is one nobody
            // could bound.
            fields: BTreeMap::from([
                ("about".to_string(), "the membership request".to_string()),
                ("scope".to_string(), "issue credentials".to_string()),
                ("limit".to_string(), "this request only".to_string()),
                ("org".to_string(), org.to_string()),
                ("until".to_string(), "2027-12-31".to_string()),
            ]),
            template: super::template(),
            lang: "en".into(),
        };
        let sd_jwt = issue_statement(
            statement,
            "https://vaulet.id/credential/mandate",
            &did,
            jwk,
            NOW - 10,
            // Ten years: the artefact must outlast the obligation, or the
            // statement stops verifying while it still binds — a rule the
            // primitive enforces and this test tripped over first time.
            NOW + 10 * 365 * 24 * 3600,
            key,
        )
        .unwrap();
        (did, sd_jwt)
    }

    /// A mandate is a list of signed statements and nothing else — no session,
    /// no server, no lookup. This test verifies one with what is in it.
    #[test]
    fn a_mandate_verifies_with_nothing_but_itself() {
        let key = SoftwareKey::generate();
        let (did, sd_jwt) = signed_by(&key, "digest-of-the-manifest", ORG);

        let read = read(&[sd_jwt], ORG, "digest-of-the-manifest", NOW).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].signer, did);
        assert_eq!(read[0].statement.act, "authorise");
    }

    /// The signature is for one manifest. Gathered for a harmless one and
    /// replayed against whatever is published next, it would be a blank
    /// authorisation — which is what a director thinks they are not signing.
    #[test]
    fn an_authorisation_for_another_manifest_is_refused() {
        let key = SoftwareKey::generate();
        let (_, sd_jwt) = signed_by(&key, "one-manifest", ORG);

        let e = read(&[sd_jwt], ORG, "a-different-manifest", NOW).unwrap_err();
        assert!(e.to_string().contains("different manifest"), "{e}");
    }

    /// And for one organisation.
    #[test]
    fn an_authorisation_for_another_organisation_is_refused() {
        let key = SoftwareKey::generate();
        let (_, sd_jwt) = signed_by(&key, "m", "did:web:org.vaulet.id:somebody-else");

        let e = read(&[sd_jwt], ORG, "m", NOW).unwrap_err();
        assert!(e.to_string().contains("does not name this organisation"), "{e}");
    }

    /// A tampered statement fails the whole mandate rather than being dropped:
    /// "not quite enough signatures" would send somebody looking for another
    /// director instead of for the forgery.
    #[test]
    fn one_broken_signature_fails_the_mandate() {
        let (a, b) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (_, good) = signed_by(&a, "m", ORG);
        let (_, other) = signed_by(&b, "m", ORG);

        // b's payload under a's signature: both halves are real, together they
        // are not.
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged_payload = other.split('.').nth(1).unwrap();
        parts[1] = forged_payload;
        let forged = parts.join(".");

        assert!(read(&[forged], ORG, "m", NOW).is_err());
    }

    /// Two directors, and the rule that needs both. The whole point of the
    /// mandate is reached here: signatures gathered separately, weighed
    /// together, by code that asked nobody anything.
    #[test]
    fn two_directors_satisfy_a_rule_that_needs_two() {
        use crate::rule::{Alternative, Group, Need};

        let (a, b) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (did_a, sd_a) = signed_by(&a, "m", ORG);
        let (did_b, sd_b) = signed_by(&b, "m", ORG);

        let rule = Rule {
            groups: vec![Group {
                id: "board".into(),
                members: vec![did_a.clone(), did_b.clone(), "did:jwk:absent".into()],
            }],
            alternatives: vec![Alternative { needs: vec![Need::count("board", 2)] }],
        };

        let one = read(&[sd_a.clone()], ORG, "m", NOW).unwrap();
        let signers: Vec<String> = one.iter().map(|a| a.signer.clone()).collect();
        assert!(!enough(&rule, &signers));

        let both = read(&[sd_a, sd_b], ORG, "m", NOW).unwrap();
        let signers: Vec<String> = both.iter().map(|a| a.signer.clone()).collect();
        assert!(enough(&rule, &signers));
    }

    /// The same director twice is one director, however the statements were
    /// gathered.
    #[test]
    fn the_same_director_signing_twice_is_not_two() {
        use crate::rule::{Alternative, Group, Need};

        let a = SoftwareKey::generate();
        let (did_a, sd_1) = signed_by(&a, "m", ORG);
        let (_, sd_2) = signed_by(&a, "m", ORG);

        let rule = Rule {
            groups: vec![Group {
                id: "board".into(),
                members: vec![did_a, "did:jwk:absent".into()],
            }],
            alternatives: vec![Alternative { needs: vec![Need::count("board", 2)] }],
        };

        let read = read(&[sd_1, sd_2], ORG, "m", NOW).unwrap();
        let signers: Vec<String> = read.iter().map(|a| a.signer.clone()).collect();
        assert_eq!(signers.len(), 2);
        assert!(!enough(&rule, &signers));
    }

    /// The digest is of the bytes as sent. Reformatting the same manifest is a
    /// different manifest, deliberately: the alternative is a canonicalisation
    /// every client would have to implement identically.
    #[test]
    fn the_digest_is_of_the_bytes_and_not_of_the_meaning() {
        assert_eq!(digest(b"{\"a\":1}"), digest(b"{\"a\":1}"));
        assert_ne!(digest(b"{\"a\":1}"), digest(b"{ \"a\": 1 }"));
    }
}
