//! Checking reference data before believing it (ADR 0031).
//!
//! The tree of provinces, districts and sub-localities arrives over the
//! network, and nothing in this system trusts the network. A dataset that
//! mapped a sub-locality to the wrong postcode would put a wrong address on a
//! credential that is then true for years, and it would look exactly like the
//! right one.
//!
//! Two things are checked and they are different questions:
//!
//! - **are these the bytes that were signed** — a digest of the data exactly as
//!   it arrived, never of a re-serialised copy of it
//! - **did we sign them** — against a key the wallet already pins, so no new
//!   trust is introduced for a list of place names

use serde_json::Value;

use crate::{CoreError, Result};

/// What the attestation said, once it held up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The country, for a country's tree — or the dataset's name, for data that
    /// is not about one country. See [`verify_dataset`].
    pub country: String,
    /// Moves when the data does. A wallet compares it against what it has
    /// rather than downloading a country to find out whether it needed to.
    pub version: String,
}

/// Verify a country's data against the attestation served with it.
///
/// `data` is the exact text received, not a parsed copy: the digest is over the
/// bytes as sent, which is why the server sends the tree as a string. Parsing
/// and re-serialising first would compare our spelling to theirs, and the two
/// agree until the day a library orders a key differently.
pub fn verify(
    country: &str,
    data: &str,
    attestation: &str,
    voucher_doc: &Value,
    pinned: &[String],
) -> Result<Attested> {
    check("country", country, data, attestation, voucher_doc, pinned)
}

/// The same check for reference data that is not one country's.
///
/// The country list is the first: it is about every country and belongs to
/// none, so there is no country field to match. What is matched instead is the
/// dataset's name, and for the same reason — a signature over the address tree,
/// served as the country list, is a real signature over the wrong thing.
pub fn verify_dataset(
    dataset: &str,
    data: &str,
    attestation: &str,
    voucher_doc: &Value,
    pinned: &[String],
) -> Result<Attested> {
    check("dataset", dataset, data, attestation, voucher_doc, pinned)
}

/// **What the attestation is about is named in it, and checked.** Which field
/// carries that name is the only difference between the two callers above;
/// everything that makes this safe — the digest first, then the key — is one
/// piece of code, because two copies of it would drift.
fn check(
    field: &str,
    name: &str,
    data: &str,
    attestation: &str,
    voucher_doc: &Value,
    pinned: &[String],
) -> Result<Attested> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let payload = crate::vouching::verify_by_pinned_key(attestation, voucher_doc, pinned)?;

    // **The digest before anything else it says.** A signed statement about
    // some other bytes is a genuine signature that proves nothing about these.
    let expected = payload
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Credential("the attestation names no digest".into()))?;
    let actual = B64.encode(Sha256::digest(data.as_bytes()));
    if actual != expected {
        return Err(CoreError::Credential(
            "the reference data is not what was signed".into(),
        ));
    }

    // And that it is the thing that was asked for. Otherwise Thailand's tree
    // could be served under another country's name — or as the country list —
    // with a signature that checks out.
    match payload.get(field).and_then(Value::as_str) {
        Some(c) if c.eq_ignore_ascii_case(name) => {}
        Some(c) => {
            return Err(CoreError::Credential(format!(
                "this is {c}'s data, not {name}'s"
            )))
        }
        None => {
            return Err(CoreError::Credential(format!(
                "the attestation names no {field}"
            )))
        }
    }

    Ok(Attested {
        country: name.to_uppercase(),
        version: payload
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::Credential("the attestation names no version".into()))?
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Es256Signer;
    use crate::keys::software::SoftwareKey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn signed(key: &SoftwareKey, payload: &Value) -> String {
        let h = B64.encode(json!({"alg": "ES256", "typ": "vaulet-address-data+jwt"}).to_string());
        let p = B64.encode(payload.to_string());
        let input = format!("{h}.{p}");
        format!("{input}.{}", B64.encode(key.sign_es256(input.as_bytes()).unwrap()))
    }

    fn doc(jwk: &Value) -> Value {
        json!({
            "id": "did:web:vaulet.id",
            "verificationMethod": [{
                "id": "did:web:vaulet.id#key-1",
                "type": "JsonWebKey2020",
                "publicKeyJwk": jwk,
            }],
        })
    }

    const DATA: &str = r#"{"country":"TH","version":"TH-abc","regions":[]}"#;

    fn world() -> (SoftwareKey, Value, Vec<String>) {
        let key = SoftwareKey::generate();
        let jwk = key.public_jwk().unwrap();
        let pins = vec![crate::credential::jwk_thumbprint(&jwk).unwrap()];
        (key, doc(&jwk), pins)
    }

    fn attestation(key: &SoftwareKey, data: &str, country: &str) -> String {
        signed(
            key,
            &json!({
                "country": country,
                "version": "TH-abc",
                "digest": B64.encode(Sha256::digest(data.as_bytes())),
            }),
        )
    }

    #[test]
    fn data_that_was_signed_is_accepted() {
        let (key, voucher, pins) = world();
        let a = verify("TH", DATA, &attestation(&key, DATA, "TH"), &voucher, &pins).unwrap();
        assert_eq!(a.country, "TH");
        assert_eq!(a.version, "TH-abc");
    }

    /// The attack the digest exists for: a real signature over some other
    /// bytes, served beside bytes nobody signed. A postcode edited in transit
    /// looks like every other postcode.
    #[test]
    fn a_genuine_signature_over_other_bytes_is_refused() {
        let (key, voucher, pins) = world();
        let good = attestation(&key, DATA, "TH");
        let tampered = DATA.replace("TH-abc", "TH-xyz");
        let e = verify("TH", &tampered, &good, &voucher, &pins).unwrap_err();
        assert!(e.to_string().contains("not what was signed"), "{e}");
    }

    /// One country's tree under another country's name, signed correctly for
    /// the country it really is.
    #[test]
    fn another_countrys_data_is_refused() {
        let (key, voucher, pins) = world();
        let a = attestation(&key, DATA, "TH");
        let e = verify("JP", DATA, &a, &voucher, &pins).unwrap_err();
        assert!(e.to_string().contains("not JP"), "{e}");
    }

    /// Signed by somebody this wallet does not pin — which is what a rogue
    /// certificate authority serving our own hostname looks like from inside.
    #[test]
    fn an_unpinned_signer_is_refused() {
        let (_, voucher, _) = world();
        let stranger = SoftwareKey::generate();
        let a = attestation(&stranger, DATA, "TH");
        assert!(verify("TH", DATA, &a, &voucher, &["not-this-one".to_string()]).is_err());
    }

    /// A dataset that belongs to no country is checked by its name instead.
    #[test]
    fn a_dataset_that_was_signed_is_accepted() {
        let (key, voucher, pins) = world();
        const LIST: &str = r#"{"dataset":"countries","countries":[]}"#;
        let a = signed(
            &key,
            &json!({
                "dataset": "countries",
                "version": "iso3166-1-cldr48.2.0",
                "digest": B64.encode(Sha256::digest(LIST.as_bytes())),
            }),
        );
        let out = verify_dataset("countries", LIST, &a, &voucher, &pins).unwrap();
        assert_eq!(out.version, "iso3166-1-cldr48.2.0");
    }

    /// **The two do not substitute for each other.** An attestation naming a
    /// country is a real signature by the right key over the right bytes, and
    /// accepting it as the country list would mean the name in it was never
    /// read — which is the whole reason it is in there.
    #[test]
    fn an_attestation_for_a_country_is_not_one_for_a_dataset() {
        let (key, voucher, pins) = world();
        let a = attestation(&key, DATA, "TH");
        let err = verify_dataset("countries", DATA, &a, &voucher, &pins).unwrap_err();
        assert!(
            err.to_string().contains("names no dataset"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn an_attestation_for_a_dataset_is_not_one_for_a_country() {
        let (key, voucher, pins) = world();
        let a = signed(
            &key,
            &json!({
                "dataset": "countries",
                "version": "v1",
                "digest": B64.encode(Sha256::digest(DATA.as_bytes())),
            }),
        );
        let err = verify("TH", DATA, &a, &voucher, &pins).unwrap_err();
        assert!(
            err.to_string().contains("names no country"),
            "unexpected: {err}"
        );
    }
}
