//! Reading Vaulet's signed word about an issuer (ADR 0030).
//!
//! A wallet pins one key and meets many issuers. The pin cannot be the list —
//! an organisation created this morning has a key nobody pinned, and a wallet
//! installed last month cannot learn it. So the organisation's document carries
//! a statement signed by the key the wallet **does** pin, saying this key
//! belongs to this organisation and how much is known about them.
//!
//! This module is the reading half. It answers one question, and the answer is
//! three-valued, which is the part that matters:
//!
//! - `Ok(Some(_))` — vouched, and here is what was vouched
//! - `Ok(None)` — nobody has vouched, which is **not** an error
//! - `Err(_)` — there is a vouching and it does not hold up
//!
//! **The middle case is a design decision, not laziness.** We vouch for
//! organisations; we do not licence them, and nobody needs our permission to
//! issue. A wallet that refused an unvouched issuer would make us the
//! gatekeeper in practice while claiming not to be. It accepts, and says
//! plainly that nobody has vouched — which is more useful to a person than a
//! credential that silently never appears.
//!
//! The last case is not the middle one. A statement that is present and wrong
//! is a forgery attempt or a bug, and treating it as "no statement" would let
//! an attacker turn a failed forgery into a silent downgrade.

use serde_json::Value;

use crate::credential::{jwk_thumbprint, verifying_key_from_jwk};
use crate::{CoreError, Result};

/// Where the statement lives in the issuer's DID document.
const FIELD: &str = "https://vaulet.id/ns#keyVouching";

/// What Vaulet said about an issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vouching {
    /// The organisation's name **as Vaulet signed it**. This is what belongs on
    /// the card: the display name in the issuer's own metadata is written by
    /// the issuer, and an issuer that could name itself could name anyone.
    pub name: String,
    /// `hosted name`, `domain-proved` or `audited` — `CONTEXT.md`'s words, and
    /// carried through as the string that was signed rather than parsed into an
    /// enum. A wallet meeting a word it does not know must show something
    /// honest, not fail; a wallet older than a new standing is the normal case,
    /// not an error.
    pub standing: String,
}

/// A minute either way, for clocks that disagree.
const SKEW: i64 = 60;

/// Read the vouching in `org_doc`, if there is one, and check it holds.
///
/// `voucher_doc` is Vaulet's own DID document, and `pinned` the thumbprints the
/// wallet trusts for it. The signature is checked against a key that is in both
/// — being published is not enough, because publication is what a forged
/// document also does.
pub fn read(
    sd_jwt: &str,
    org_doc: &Value,
    voucher_doc: &Value,
    pinned: &[String],
    now: i64,
) -> Result<Option<Vouching>> {
    let jws = match org_doc.get(FIELD) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s,
        Some(_) => return Err(CoreError::Credential("vouching is not a string".into())),
    };

    let payload = verify_against_pinned(jws, voucher_doc, pinned)?;

    // Whose word is being read. Without this the statement is one Vaulet made
    // about somebody else, lifted into a document it was not written for.
    let subject = payload.get("sub").and_then(Value::as_str);
    let about = org_doc.get("id").and_then(Value::as_str);
    if subject.is_none() || subject != about {
        return Err(CoreError::Credential(format!(
            "the vouching is about {}, not {}",
            subject.unwrap_or("nobody"),
            about.unwrap_or("nobody"),
        )));
    }

    // **The key that actually signed this credential must be one of the keys
    // vouched for.** Everything else here would still pass if a forged document
    // kept Vaulet's signature and published its own key underneath it; this is
    // the check that makes the forgery useless.
    let issuer_jwk = crate::credential::issuer_jwk_for(sd_jwt, org_doc)?;
    let tp = jwk_thumbprint(&issuer_jwk)?;
    let covered = payload
        .get("keys")
        .and_then(Value::as_object)
        .is_some_and(|keys| keys.values().any(|v| v.as_str() == Some(tp.as_str())));
    if !covered {
        return Err(CoreError::Credential(
            "the key that signed this credential is not one Vaulet vouched for".into(),
        ));
    }

    // Expiry last, so a stale statement about the wrong subject still reports
    // the subject: "expired" would send somebody looking at clocks.
    match payload.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp + SKEW >= now => {}
        Some(_) => return Err(CoreError::Credential("the vouching has expired".into())),
        None => return Err(CoreError::Credential("the vouching has no expiry".into())),
    }

    Ok(Some(Vouching {
        name: payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        standing: payload
            .get("standing")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }))
}

/// Verify the statement against a voucher key that is both published and
/// pinned, and return its payload.
fn verify_against_pinned(jws: &str, voucher_doc: &Value, pinned: &[String]) -> Result<Value> {
    let methods = voucher_doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::Credential("voucher document has no keys".into()))?;

    let mut tried = 0;
    for method in methods {
        let Some(jwk) = method.get("publicKeyJwk") else {
            continue;
        };
        // An empty pin set is a deployment that has not pinned anything — the
        // dev backend, whose key rotates. It must not silently mean "trust
        // every key in the document" on a build that meant to pin, which is why
        // the caller passes the set rather than this module deciding.
        if !pinned.is_empty() {
            let Ok(tp) = jwk_thumbprint(jwk) else { continue };
            if !pinned.iter().any(|p| p == &tp) {
                continue;
            }
        }
        tried += 1;
        let Ok(vk) = verifying_key_from_jwk(jwk) else {
            continue;
        };
        if let Ok(payload) = crate::credential::verify_compact_jws(jws, &vk) {
            return Ok(payload);
        }
    }

    Err(CoreError::Credential(if tried == 0 {
        "no key Vaulet publishes is one this wallet pins".into()
    } else {
        "the vouching was not signed by a key this wallet pins".into()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{issue, IssueParams};
    use crate::keys::software::SoftwareKey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const ORG: &str = "did:web:org.vaulet.id:acme";

    fn sign(key: &SoftwareKey, payload: &Value) -> String {
        use crate::credential::Es256Signer;
        let h = B64.encode(json!({"alg": "ES256", "typ": "vaulet-vouching+jwt"}).to_string());
        let p = B64.encode(payload.to_string());
        let input = format!("{h}.{p}");
        let sig = key.sign_es256(input.as_bytes()).unwrap();
        format!("{input}.{}", B64.encode(sig))
    }

    /// A credential really signed by `key`, with `iss` naming the organisation.
    fn credential(key: &SoftwareKey) -> String {
        let holder = SoftwareKey::generate();
        issue(
            IssueParams {
                vct: "https://org.vaulet.id/acme/credential/staff".into(),
                iss: ORG.into(),
                iat: NOW - 10,
                exp: NOW + 10_000,
                holder_jwk: holder.public_jwk().unwrap(),
                disclosable: Default::default(),
                member_disclosable: Default::default(),
                visible: Default::default(),
            },
            key,
        )
        .unwrap()
    }

    fn doc(id: &str, jwk: &Value) -> Value {
        json!({
            "id": id,
            "verificationMethod": [{
                "id": format!("{id}#key-1"),
                "type": "JsonWebKey2020",
                "publicKeyJwk": jwk,
            }],
        })
    }

    /// (org document with a vouching, Vaulet's document, the pins)
    fn world(org_key: &SoftwareKey, vaulet: &SoftwareKey) -> (Value, Value, Vec<String>) {
        let org_jwk = org_key.public_jwk().unwrap();
        let vaulet_jwk = vaulet.public_jwk().unwrap();
        let mut org = doc(ORG, &org_jwk);
        org[FIELD] = json!(sign(
            vaulet,
            &json!({
                "iss": "did:web:vaulet.id",
                "sub": ORG,
                "name": "Acme Co., Ltd.",
                "standing": "hosted name",
                "keys": { "main": jwk_thumbprint(&org_jwk).unwrap() },
                "iat": NOW - 100,
                "exp": NOW + 86_400,
            })
        ));
        let pins = vec![jwk_thumbprint(&vaulet_jwk).unwrap()];
        (org, doc("did:web:vaulet.id", &vaulet_jwk), pins)
    }

    #[test]
    fn a_vouched_issuer_reads_back_what_vaulet_signed() {
        let (org_key, vaulet) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (org, voucher, pins) = world(&org_key, &vaulet);

        let v = read(&credential(&org_key), &org, &voucher, &pins, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(v.name, "Acme Co., Ltd.");
        assert_eq!(v.standing, "hosted name");
    }

    /// Nobody has vouched is a fact about the issuer, not a failure. A wallet
    /// that refused here would make Vaulet the gatekeeper it says it is not.
    #[test]
    fn an_issuer_nobody_vouched_for_is_not_an_error() {
        let org_key = SoftwareKey::generate();
        let org = doc(ORG, &org_key.public_jwk().unwrap());
        let voucher = doc("did:web:vaulet.id", &SoftwareKey::generate().public_jwk().unwrap());
        assert_eq!(
            read(&credential(&org_key), &org, &voucher, &[], NOW).unwrap(),
            None
        );
    }

    /// The attack the thumbprints exist for: a forged document keeps Vaulet's
    /// real signature and publishes its own key underneath it. Everything else
    /// checks out — the statement is genuine, current, and about this exact
    /// organisation.
    #[test]
    fn a_vouching_does_not_cover_a_key_it_never_named() {
        let (org_key, vaulet) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (mut org, voucher, pins) = world(&org_key, &vaulet);

        let attacker = SoftwareKey::generate();
        org["verificationMethod"][0]["publicKeyJwk"] = attacker.public_jwk().unwrap();

        let e = read(&credential(&attacker), &org, &voucher, &pins, NOW).unwrap_err();
        assert!(e.to_string().contains("not one Vaulet vouched for"), "{e}");
    }

    /// Signed by a key Vaulet publishes but this wallet does not pin — which is
    /// what a rogue certificate authority serving a forged `vaulet.id` document
    /// looks like from inside the wallet.
    #[test]
    fn a_voucher_key_that_is_not_pinned_signs_nothing() {
        let (org_key, stranger) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (org, _, _) = world(&org_key, &stranger);
        let voucher = doc("did:web:vaulet.id", &stranger.public_jwk().unwrap());

        let e = read(
            &credential(&org_key),
            &org,
            &voucher,
            &["a-thumbprint-of-something-else".to_string()],
            NOW,
        )
        .unwrap_err();
        assert!(e.to_string().contains("pins"), "{e}");
    }

    /// A statement Vaulet really made, about a different company, moved into
    /// this document. The signature is genuine and proves nothing here.
    #[test]
    fn a_vouching_about_somebody_else_is_refused() {
        let (org_key, vaulet) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (mut org, voucher, pins) = world(&org_key, &vaulet);
        org["id"] = json!("did:web:org.vaulet.id:other");

        let e = read(&credential(&org_key), &org, &voucher, &pins, NOW).unwrap_err();
        assert!(e.to_string().contains("not did:web:org.vaulet.id:other"), "{e}");
    }

    /// Expiry is what bounds a copy kept by somebody else and replayed later —
    /// an audit we withdrew this morning must stop being quotable.
    #[test]
    fn a_vouching_past_its_expiry_is_refused() {
        let (org_key, vaulet) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (org, voucher, pins) = world(&org_key, &vaulet);

        let e = read(&credential(&org_key), &org, &voucher, &pins, NOW + 86_400 + 3600)
            .unwrap_err();
        assert!(e.to_string().contains("expired"), "{e}");
    }

    /// A present-and-broken statement must not read as "no statement": that
    /// would let a failed forgery become a silent downgrade to unvouched.
    #[test]
    fn a_tampered_vouching_is_an_error_and_not_a_silence() {
        let (org_key, vaulet) = (SoftwareKey::generate(), SoftwareKey::generate());
        let (mut org, voucher, pins) = world(&org_key, &vaulet);
        let jws = org[FIELD].as_str().unwrap().to_string();
        let mut parts: Vec<&str> = jws.split('.').collect();
        let forged = B64.encode(
            json!({
                "sub": ORG, "name": "Acme Co., Ltd.", "standing": "audited",
                "keys": {}, "exp": NOW + 86_400,
            })
            .to_string(),
        );
        parts[1] = &forged;
        org[FIELD] = json!(parts.join("."));

        assert!(read(&credential(&org_key), &org, &voucher, &pins, NOW).is_err());
    }
}
