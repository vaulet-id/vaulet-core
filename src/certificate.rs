//! Reading Vaulet's certificate over a Micro App package (ADR 0048).
//!
//! A package carries a signed statement from Vaulet saying what was checked
//! about it: the bytes, who published it, and the capability report a person
//! consented to. The mechanism is `vouching.rs`'s exactly — a JWS by the one
//! key every wallet pins — because an organisation's own key verifying its own
//! package is the thing this exists to prevent.
//!
//! The answer is three-valued, like a vouching, and for the same reason:
//!
//! - `Ok(Some(_))` — verified, and here is the level Vaulet claimed
//! - `Ok(None)` — no certificate, which is **not** an error: a package reaches
//!   somebody through its publisher's own hosting with no Vaulet word about it,
//!   and the honest thing is to say nobody checked rather than to refuse
//! - `Err(_)` — a certificate is present and does not hold up, which is a
//!   forgery attempt or a bug and must never be shown as silence
//!
//! What a certificate covers is what a forgery would otherwise change. The
//! **code hash**, because that is the artefact and a certificate that travelled
//! to another package would say Vaulet checked something it did not. The
//! **publisher, application and version**, because that is what a person is
//! told. The **report**, because that is what they consented to — a certificate
//! over bytes alone would let a report be restated beside it, and the sheet a
//! person read would no longer be the one Vaulet signed.

use serde_json::Value;

use crate::{CoreError, Result};

/// A minute either way, for clocks that disagree.
const SKEW: i64 = 60;

/// What Vaulet said it checked about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// `measured`, `reproduced` or `reviewed` — carried as the signed string
    /// rather than parsed into an enum, so a wallet older than a new level
    /// shows something honest instead of failing (ADR 0048, ADR 0012).
    pub level: String,
    /// `machine` or a name — who stood behind the level. A level without this
    /// asserts something nobody signed for.
    pub assessed_by: String,
}

/// Read the certificate a package carries, if it carries one.
///
/// `voucher_doc` is `did:web:vaulet.id`'s document and `pinned` the thumbprints
/// this build trusts for it; the signature must be by a key in both, because
/// being published is what a forged document also manages.
///
/// `report` is the report the wallet **measured from the module it holds**,
/// canonicalised the same way the certificate carries it — a map of line to
/// values. Passing the measured report rather than trusting the one in the
/// statement is the point: the certificate is checked against the bytes on the
/// phone, not against its own description of them.
#[allow(clippy::too_many_arguments)]
pub fn read(
    jws: &str,
    voucher_doc: &Value,
    pinned: &[String],
    code_hash: &str,
    publisher: &str,
    app: &str,
    version: &str,
    report: &Value,
    now: i64,
) -> Result<Option<Certificate>> {
    if jws.trim().is_empty() {
        return Ok(None);
    }

    let payload = crate::vouching::verify_by_pinned_key(jws, voucher_doc, pinned)?;

    let want = |field: &str, is: &str| -> Result<()> {
        let said = payload.get(field).and_then(Value::as_str).unwrap_or_default();
        if said == is {
            Ok(())
        } else {
            Err(CoreError::Credential(format!(
                "the certificate is for {field} {said:?}, not {is:?}"
            )))
        }
    };

    // The bytes first: a certificate lifted onto another package fails here,
    // whatever else it says.
    want("sub", code_hash)?;
    want("publisher", publisher)?;
    want("app", app)?;
    want("version", version)?;

    // **The report is the consent.** A certificate whose report is not the one
    // the module produces is one where the sheet a person read was restated
    // after Vaulet signed it. Compared canonically, because both sides are the
    // same `report_rows` map and a difference in it is a difference in what was
    // agreed to.
    let signed = payload
        .get("report")
        .ok_or_else(|| CoreError::Credential("the certificate says nothing about the report".into()))?;
    if !same_report(signed, report) {
        return Err(CoreError::Credential(
            "the certificate's report is not the one this module produces".into(),
        ));
    }

    // Expiry last, so a stale certificate about the wrong bytes still reports
    // the bytes rather than sending somebody to look at clocks. A withdrawn
    // verification stops being claimed by expiring, which is why one is
    // required.
    match payload.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp + SKEW >= now => {}
        Some(_) => return Err(CoreError::Credential("the certificate has expired".into())),
        None => return Err(CoreError::Credential("the certificate has no expiry".into())),
    }

    let review = payload.get("review");
    Ok(Some(Certificate {
        level: review
            .and_then(|r| r.get("level"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        assessed_by: review
            .and_then(|r| r.get("assessed_by"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }))
}

/// Two reports are the same when the same lines carry the same values, however
/// each side happened to order its keys. `report_rows` sorts both, so this is
/// belt and braces — but a report is what was consented to, and "close enough"
/// is not a thing to say about consent.
fn same_report(a: &Value, b: &Value) -> bool {
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else {
        return a == b;
    };
    if a.len() != b.len() {
        return false;
    }
    a.iter().all(|(line, av)| {
        b.get(line).is_some_and(|bv| {
            let mut a: Vec<&str> = av.as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let mut b: Vec<&str> = bv.as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            a.sort_unstable();
            b.sort_unstable();
            a == b
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::software::SoftwareKey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const HASH: &str = "e0e4d216979a55d3a4af97fa9ac868fb";
    const PUB: &str = "did:web:org.vaulet.id:acme";
    const APP: &str = "th.co.acme.staff";
    const VER: &str = "1.11.0";

    fn report() -> Value {
        json!({
            "checks": ["EmployeeBadge under EmployedByAcme"],
            "shows": ["EmployeeBadge"],
            "reads": [],
            "writes state": ["shift"],
        })
    }

    fn sign(key: &SoftwareKey, payload: &Value) -> String {
        use crate::credential::Es256Signer;
        let h = B64.encode(json!({"alg": "ES256", "typ": "vaulet-app-certificate+jwt"}).to_string());
        let p = B64.encode(payload.to_string());
        let input = format!("{h}.{p}");
        let sig = key.sign_es256(input.as_bytes()).unwrap();
        format!("{input}.{}", B64.encode(sig))
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

    /// (a real certificate, Vaulet's document, the pins), for whatever payload.
    fn world(vaulet: &SoftwareKey, payload: &Value) -> (String, Value, Vec<String>) {
        let jwk = vaulet.public_jwk().unwrap();
        let pins = vec![crate::credential::jwk_thumbprint(&jwk).unwrap()];
        (sign(vaulet, payload), doc("did:web:vaulet.id", &jwk), pins)
    }

    fn payload() -> Value {
        json!({
            "iss": "did:web:vaulet.id",
            "sub": HASH,
            "publisher": PUB,
            "app": APP,
            "version": VER,
            "report": report(),
            "review": { "level": "measured", "assessed_by": "machine" },
            "iat": NOW - 100,
            "exp": NOW + 86_400,
        })
    }

    fn check(jws: &str, voucher: &Value, pins: &[String]) -> Result<Option<Certificate>> {
        read(jws, voucher, pins, HASH, PUB, APP, VER, &report(), NOW)
    }

    #[test]
    fn a_certified_package_reads_back_the_level_vaulet_signed() {
        let vaulet = SoftwareKey::generate();
        let (jws, voucher, pins) = world(&vaulet, &payload());
        let c = check(&jws, &voucher, &pins).unwrap().unwrap();
        assert_eq!(c.level, "measured");
        assert_eq!(c.assessed_by, "machine");
    }

    /// No certificate is a fact about the package, not a failure: it reaches
    /// somebody through the publisher's own hosting and nobody checked it.
    #[test]
    fn no_certificate_is_not_an_error() {
        let voucher = doc("did:web:vaulet.id", &SoftwareKey::generate().public_jwk().unwrap());
        assert_eq!(check("", &voucher, &[]).unwrap(), None);
        assert_eq!(check("   ", &voucher, &[]).unwrap(), None);
    }

    /// **The bytes are the point.** A real certificate Vaulet signed for one
    /// package, moved onto another, is what the `sub` check exists to catch.
    #[test]
    fn a_certificate_does_not_travel_to_other_bytes() {
        let vaulet = SoftwareKey::generate();
        let (jws, voucher, pins) = world(&vaulet, &payload());
        let e = read(&jws, &voucher, &pins, "a-different-hash", PUB, APP, VER, &report(), NOW)
            .unwrap_err();
        assert!(e.to_string().contains("sub"), "{e}");
    }

    /// The report is what a person consented to. A certificate whose report is
    /// not the one the module produces is a sheet restated after signing.
    #[test]
    fn a_certificate_whose_report_was_restated_is_refused() {
        let vaulet = SoftwareKey::generate();
        let (jws, voucher, pins) = world(&vaulet, &payload());
        let understated = json!({
            "checks": ["EmployeeBadge under EmployedByAcme"],
            "shows": ["EmployeeBadge"],
            "reads": ["the amount on your receipts"],
            "writes state": ["shift"],
        });
        let e = read(&jws, &voucher, &pins, HASH, PUB, APP, VER, &understated, NOW)
            .unwrap_err();
        assert!(e.to_string().contains("report"), "{e}");
    }

    /// Signed by a key Vaulet publishes but this wallet does not pin — a rogue
    /// authority serving a forged `vaulet.id` document, from inside the wallet.
    #[test]
    fn a_key_this_wallet_does_not_pin_certifies_nothing() {
        let stranger = SoftwareKey::generate();
        let (jws, voucher, _) = world(&stranger, &payload());
        let e = check(&jws, &voucher, &["a-thumbprint-of-something-else".to_string()])
            .unwrap_err();
        assert!(e.to_string().contains("pins"), "{e}");
    }

    /// A withdrawn verification stops being claimed by expiring, so an expired
    /// certificate is refused rather than shown.
    #[test]
    fn an_expired_certificate_is_refused() {
        let vaulet = SoftwareKey::generate();
        let mut p = payload();
        p["exp"] = json!(NOW - 1000);
        let (jws, voucher, pins) = world(&vaulet, &p);
        let e = check(&jws, &voucher, &pins).unwrap_err();
        assert!(e.to_string().contains("expired"), "{e}");
    }

    /// Key order in the report differs between two runs and means nothing; the
    /// report is the same and the certificate holds.
    #[test]
    fn the_report_is_the_same_however_its_values_are_ordered() {
        let vaulet = SoftwareKey::generate();
        let (jws, voucher, pins) = world(&vaulet, &payload());
        let reordered = json!({
            "writes state": ["shift"],
            "shows": ["EmployeeBadge"],
            "reads": [],
            "checks": ["EmployeeBadge under EmployedByAcme"],
        });
        assert!(read(&jws, &voucher, &pins, HASH, PUB, APP, VER, &reordered, NOW)
            .unwrap()
            .is_some());
    }
}
