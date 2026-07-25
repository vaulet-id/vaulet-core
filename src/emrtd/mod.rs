//! ePassport (eMRTD) passive + active authentication (ADR 0009).
//!
//! Passive Authentication (PA): the read data groups hash into the country-signed
//! Document Security Object (EF.SOD); the SOD's signer (DSC) chains to a trusted
//! country CA (CSCA). Active Authentication (AA): the chip signs a fresh
//! challenge with a key it never discloses. This module is the verdict engine —
//! it decides genuineness from raw bytes and is called from both the app (FFI)
//! and the backend issuer, per the hybrid split in ADR 0009.

use crate::{CoreError, Result};
use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::Decode;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;

/// DSC → CSCA trust-chain outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStatus {
    /// DSC verified against a CSCA in the trust store.
    Trusted,
    /// No CSCA anchor available (empty trust store) — integrity holds but the
    /// issuing country isn't proven.
    NoAnchor,
    /// DSC did not verify against any provided CSCA.
    Failed,
}

/// The genuineness verdict for a passport read.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PassportVerdict {
    /// Every read DG's hash matched the SOD's LDSSecurityObject.
    pub dg_integrity: bool,
    /// The SOD signature verified against the embedded DSC.
    pub sod_signature: bool,
    /// DSC → CSCA chain result.
    pub chain: ChainStatus,
    /// Active Authentication result; None when the chip has no AA key.
    pub active_auth: Option<bool>,
    /// The SOD digest algorithm (e.g. "SHA-256").
    pub hash_algo: String,
    /// DG numbers whose hash was checked.
    pub checked_dgs: Vec<u8>,
    /// Human-readable notes (unsupported algorithm, etc.).
    pub notes: Vec<String>,
}

impl PassportVerdict {
    /// Genuine document: integrity + signature + a trusted chain. (AA, when
    /// present, must also hold.)
    pub fn is_genuine(&self) -> bool {
        self.dg_integrity
            && self.sod_signature
            && self.chain == ChainStatus::Trusted
            && self.active_auth != Some(false)
    }
}

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Verify a passport read. `sod` is EF.SOD (with or without the outer `0x77`
/// wrapper); `dgs` maps DG number → raw EF bytes; `csca` is the CSCA trust store
/// (DER certs, may be empty); `aa` is `(dg15_ef, challenge, signature)` when the
/// chip supports Active Authentication.
pub fn verify_passport(
    sod: &[u8],
    dgs: &BTreeMap<u8, Vec<u8>>,
    csca: &[Vec<u8>],
    aa: Option<(&[u8], &[u8], &[u8])>,
) -> Result<PassportVerdict> {
    let mut notes = Vec::new();

    let ci = strip_sod_wrapper(sod);
    let lds = parse_lds_security_object(ci)?;

    // 1) Data-group integrity: hash each read DG and compare to the SOD.
    let mut dg_integrity = true;
    let mut checked = Vec::new();
    for (num, expected) in &lds.hashes {
        if let Some(bytes) = dgs.get(num) {
            checked.push(*num);
            if digest(&lds.hash_algo, bytes) != *expected {
                dg_integrity = false;
                notes.push(format!("DG{num} hash mismatch"));
            }
        }
    }
    if checked.is_empty() {
        dg_integrity = false;
        notes.push("no read DG matched the SOD".into());
    }
    checked.sort_unstable();

    // 2) SOD signature + 3) chain (staged — see verify_sod_signature).
    let (sod_signature, chain) = verify_sod_signature(ci, csca, &mut notes);

    // 4) Active Authentication.
    let active_auth = aa.map(|(dg15, challenge, sig)| {
        verify_active_auth(dg15, challenge, sig).unwrap_or_else(|e| {
            notes.push(format!("AA: {e}"));
            false
        })
    });

    Ok(PassportVerdict {
        dg_integrity,
        sod_signature,
        chain,
        active_auth,
        hash_algo: lds.hash_algo.clone(),
        checked_dgs: checked,
        notes,
    })
}

// ---------------------------------------------------------------------------
// EF.SOD → LDSSecurityObject
// ---------------------------------------------------------------------------

struct LdsSecurityObject {
    hash_algo: String,
    hashes: BTreeMap<u8, Vec<u8>>,
}

/// One DER TLV element (single-byte tag, short/long length).
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    rest: &'a [u8],
}

fn read_tlv(data: &[u8]) -> Result<Tlv<'_>> {
    if data.len() < 2 {
        return Err(CoreError::Credential("DER: truncated".into()));
    }
    let tag = data[0];
    let mut i = 1;
    let b = data[i];
    i += 1;
    let len = if b < 0x80 {
        b as usize
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < i + n {
            return Err(CoreError::Credential("DER: bad length".into()));
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | data[i] as usize;
            i += 1;
        }
        l
    };
    if data.len() < i + len {
        return Err(CoreError::Credential("DER: length exceeds buffer".into()));
    }
    Ok(Tlv {
        tag,
        value: &data[i..i + len],
        rest: &data[i + len..],
    })
}

/// Strip the EF.SOD application wrapper (`0x77` tag) if present, returning the
/// inner CMS `ContentInfo` DER.
fn strip_sod_wrapper(sod: &[u8]) -> &[u8] {
    if sod.first() == Some(&0x77) {
        if let Ok(tlv) = read_tlv(sod) {
            return tlv.value;
        }
    }
    sod
}

/// Parse the CMS SignedData in `ci` down to the LDSSecurityObject and extract the
/// digest algorithm + per-DG hashes (hand-rolled TLV walk — eMRTD SODs vary and
/// this SEQUENCE is simple).
fn parse_lds_security_object(ci: &[u8]) -> Result<LdsSecurityObject> {
    let content = signed_data_econtent(ci)?;
    parse_lds_econtent(&content)
}

/// Parse a bare LDSSecurityObject DER (the SOD eContent) — split out so the
/// hash logic is unit-testable without a full CMS SOD.
fn parse_lds_econtent(content: &[u8]) -> Result<LdsSecurityObject> {
    let bad = |m: &str| CoreError::Credential(format!("LDSSecurityObject: {m}"));

    // SEQUENCE { version INTEGER, hashAlgorithm SEQUENCE, dataGroupHashValues SEQUENCE OF ... }
    let outer = read_tlv(&content)?;
    if outer.tag != 0x30 {
        return Err(bad("not a SEQUENCE"));
    }
    let version = read_tlv(outer.value)?; // INTEGER
    if version.tag != 0x02 {
        return Err(bad("no version"));
    }
    let algo_seq = read_tlv(version.rest)?; // AlgorithmIdentifier SEQUENCE
    if algo_seq.tag != 0x30 {
        return Err(bad("no hashAlgorithm"));
    }
    let algo_oid = read_tlv(algo_seq.value)?; // OID
    if algo_oid.tag != 0x06 {
        return Err(bad("no algorithm oid"));
    }
    let oid = ObjectIdentifier::from_der(&der_tlv_bytes(0x06, algo_oid.value))
        .map_err(|_| bad("bad oid"))?;

    let dgh_seq = read_tlv(algo_seq.rest)?; // SEQUENCE OF DataGroupHash
    if dgh_seq.tag != 0x30 {
        return Err(bad("no dataGroupHashValues"));
    }
    let mut hashes = BTreeMap::new();
    let mut cur = dgh_seq.value;
    while !cur.is_empty() {
        let entry = read_tlv(cur)?; // SEQUENCE { number INTEGER, hash OCTET STRING }
        if entry.tag != 0x30 {
            return Err(bad("bad DataGroupHash"));
        }
        let num_tlv = read_tlv(entry.value)?;
        if num_tlv.tag != 0x02 || num_tlv.value.is_empty() {
            return Err(bad("bad DG number"));
        }
        let num = *num_tlv.value.last().unwrap();
        let hash_tlv = read_tlv(num_tlv.rest)?;
        if hash_tlv.tag != 0x04 {
            return Err(bad("bad DG hash"));
        }
        hashes.insert(num, hash_tlv.value.to_vec());
        cur = entry.rest;
    }

    Ok(LdsSecurityObject {
        hash_algo: hash_name(&oid),
        hashes,
    })
}

/// Re-wrap a value as a DER TLV so a typed decoder can parse it.
fn der_tlv_bytes(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let n = bytes.len() - start;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(value);
    out
}

/// Navigate ContentInfo → SignedData → encapContentInfo.eContent (the DER of the
/// LDSSecurityObject).
fn signed_data_econtent(ci: &[u8]) -> Result<Vec<u8>> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    let info = ContentInfo::from_der(ci)
        .map_err(|e| CoreError::Credential(format!("ContentInfo: {e}")))?;
    if info.content_type != OID_SIGNED_DATA {
        return Err(CoreError::Credential("SOD is not signedData".into()));
    }
    let sd: SignedData = info
        .content
        .decode_as()
        .map_err(|e| CoreError::Credential(format!("SignedData: {e}")))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| CoreError::Credential("SOD has no eContent".into()))?;
    let os = econtent
        .decode_as::<OctetStringRef>()
        .map_err(|e| CoreError::Credential(format!("eContent: {e}")))?;
    Ok(os.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// SOD signature + chain, Active Authentication (staged — see notes)
// ---------------------------------------------------------------------------

const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// Verify the SOD signer's signature (SignerInfo over signedAttrs, with the
/// messageDigest attribute bound to the LDS eContent) against the embedded DSC,
/// then chain the DSC to a trusted CSCA. Errors surface as notes and a `false`
/// verdict rather than aborting the whole read.
fn verify_sod_signature(
    ci: &[u8],
    csca: &[Vec<u8>],
    notes: &mut Vec<String>,
) -> (bool, ChainStatus) {
    match verify_sod_inner(ci, csca, notes) {
        Ok(v) => v,
        Err(e) => {
            notes.push(format!("SOD signature: {e}"));
            (false, ChainStatus::NoAnchor)
        }
    }
}

fn verify_sod_inner(
    ci: &[u8],
    csca: &[Vec<u8>],
    notes: &mut Vec<String>,
) -> Result<(bool, ChainStatus)> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::Encode;

    let bad = |m: String| CoreError::Credential(m);
    let info = ContentInfo::from_der(ci).map_err(|e| bad(format!("ContentInfo: {e}")))?;
    let sd: SignedData = info
        .content
        .decode_as()
        .map_err(|e| bad(format!("SignedData: {e}")))?;

    // Document Signer Certificate (first embedded X.509).
    let dsc = sd
        .certificates
        .as_ref()
        .and_then(|set| {
            set.0.iter().find_map(|c| match c {
                CertificateChoices::Certificate(cert) => Some(cert.clone()),
                _ => None,
            })
        })
        .ok_or_else(|| bad("SOD has no DSC certificate".into()))?;

    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| bad("SOD has no signerInfo".into()))?;
    let hash_algo = hash_name(&si.digest_alg.oid);

    // The LDS eContent bytes — what messageDigest is taken over.
    let lds_der = signed_data_econtent(ci)?;

    // Message the signature actually covers: the re-encoded signedAttrs (SET OF),
    // after checking its messageDigest binds to the eContent. If there are no
    // signedAttrs, the signature is directly over the eContent.
    let signed_msg: Vec<u8> = if let Some(attrs) = &si.signed_attrs {
        let md_attr = attrs
            .iter()
            .find(|a| a.oid == OID_MESSAGE_DIGEST)
            .ok_or_else(|| bad("no messageDigest attribute".into()))?;
        let md_any = md_attr
            .values
            .iter()
            .next()
            .ok_or_else(|| bad("empty messageDigest".into()))?;
        let md = md_any
            .decode_as::<OctetStringRef>()
            .map_err(|e| bad(format!("messageDigest: {e}")))?;
        if md.as_bytes() != digest(&hash_algo, &lds_der).as_slice() {
            return Err(bad("messageDigest does not match eContent".into()));
        }
        // to_der() on the SignedAttributes (SET OF) emits the 0x31 SET tag that
        // RFC 5652 §5.4 requires for the signature, not the [0] IMPLICIT tag.
        attrs.to_der().map_err(|e| bad(format!("signedAttrs: {e}")))?
    } else {
        lds_der.clone()
    };

    let spki_der = dsc
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| bad(format!("DSC SPKI: {e}")))?;
    let sod_ok = verify_signature(
        &spki_der,
        &si.signature_algorithm.oid,
        &hash_algo,
        &signed_msg,
        si.signature.as_bytes(),
    )
    .unwrap_or_else(|e| {
        notes.push(format!("SOD signature verify: {e}"));
        false
    });
    if !sod_ok {
        notes.push("SOD signature did not verify against the DSC".into());
    }

    // DSC → CSCA chain: the DSC's own signature must verify under a trusted CSCA.
    let chain = if csca.is_empty() {
        ChainStatus::NoAnchor
    } else {
        verify_dsc_chain(&dsc, csca, notes)
    };
    Ok((sod_ok, chain))
}

/// Try to verify the DSC's certificate signature under each provided CSCA's
/// public key. Trusted on the first match, else Failed.
fn verify_dsc_chain(
    dsc: &x509_cert::Certificate,
    csca: &[Vec<u8>],
    notes: &mut Vec<String>,
) -> ChainStatus {
    use der::Encode;
    let tbs = match dsc.tbs_certificate.to_der() {
        Ok(b) => b,
        Err(e) => {
            notes.push(format!("DSC tbs: {e}"));
            return ChainStatus::Failed;
        }
    };
    let sig = dsc.signature.raw_bytes();
    let sig_hash = hash_name(&dsc.signature_algorithm.oid);
    for ca_der in csca {
        let ca = match x509_cert::Certificate::from_der(ca_der) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ca_spki = match ca.tbs_certificate.subject_public_key_info.to_der() {
            Ok(b) => b,
            Err(_) => continue,
        };
        if verify_signature(
            &ca_spki,
            &dsc.signature_algorithm.oid,
            &sig_hash,
            &tbs,
            sig,
        )
        .unwrap_or(false)
        {
            return ChainStatus::Trusted;
        }
    }
    ChainStatus::Failed
}

/// Verify `signature` over `msg` using the SPKI public key and the signature
/// algorithm OID. Supports RSA PKCS#1 v1.5, RSA-PSS, and ECDSA (P-256/P-384).
fn verify_signature(
    spki_der: &[u8],
    sig_alg: &ObjectIdentifier,
    hash_algo: &str,
    msg: &[u8],
    sig: &[u8],
) -> Result<bool> {
    let bad = |m: String| CoreError::Credential(m);
    let oid = sig_alg.to_string();
    let hashed = digest(hash_algo, msg);

    // ECDSA (X9.62): 1.2.840.10045.4.3.x
    if oid.starts_with("1.2.840.10045.4.3") {
        // Curve comes from the key; try P-256 then P-384 with prehashed digest.
        use ecdsa::signature::hazmat::PrehashVerifier;
        use spki::DecodePublicKey;
        if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
            let s = p256::ecdsa::Signature::from_der(sig)
                .map_err(|e| bad(format!("ECDSA sig: {e}")))?;
            return Ok(vk.verify_prehash(&hashed, &s).is_ok());
        }
        if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
            let s = p384::ecdsa::Signature::from_der(sig)
                .map_err(|e| bad(format!("ECDSA sig: {e}")))?;
            return Ok(vk.verify_prehash(&hashed, &s).is_ok());
        }
        // Unknown curve (named OID we don't support, or explicit domain params).
        // Dump the SPKI so the exact curve/encoding can be identified offline.
        let curve = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
            .ok()
            .and_then(|s| s.algorithm.parameters_oid().ok())
            .map(|o| o.to_string())
            .unwrap_or_else(|| "explicit-or-unknown".into());
        let hex: String = spki_der.iter().map(|b| format!("{b:02x}")).collect();
        return Err(bad(format!("unsupported ECDSA curve {curve}; spki={hex}")));
    }

    // RSA: rsaEncryption / sha*WithRSAEncryption (PKCS#1 v1.5) or RSASSA-PSS.
    if oid.starts_with("1.2.840.113549.1.1") {
        use rsa::pkcs8::DecodePublicKey;
        let key = rsa::RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| bad(format!("RSA key: {e}")))?;
        if oid == "1.2.840.113549.1.1.10" {
            // RSASSA-PSS (params default to the digest's own MGF1/salt for eMRTD).
            let ok = match hash_algo {
                "SHA-1" => key.verify(rsa::pss::Pss::new::<Sha1>(), &hashed, sig).is_ok(),
                "SHA-224" => key.verify(rsa::pss::Pss::new::<Sha224>(), &hashed, sig).is_ok(),
                "SHA-384" => key.verify(rsa::pss::Pss::new::<Sha384>(), &hashed, sig).is_ok(),
                "SHA-512" => key.verify(rsa::pss::Pss::new::<Sha512>(), &hashed, sig).is_ok(),
                _ => key.verify(rsa::pss::Pss::new::<Sha256>(), &hashed, sig).is_ok(),
            };
            return Ok(ok);
        }
        let ok = match hash_algo {
            "SHA-1" => key.verify(rsa::Pkcs1v15Sign::new::<Sha1>(), &hashed, sig).is_ok(),
            "SHA-224" => key.verify(rsa::Pkcs1v15Sign::new::<Sha224>(), &hashed, sig).is_ok(),
            "SHA-384" => key.verify(rsa::Pkcs1v15Sign::new::<Sha384>(), &hashed, sig).is_ok(),
            "SHA-512" => key.verify(rsa::Pkcs1v15Sign::new::<Sha512>(), &hashed, sig).is_ok(),
            _ => key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, sig).is_ok(),
        };
        return Ok(ok);
    }

    Err(bad(format!("unsupported signature algorithm {oid}")))
}

/// Verify the chip's Active Authentication signature over the challenge. Staged.
fn verify_active_auth(_dg15: &[u8], _challenge: &[u8], _sig: &[u8]) -> Result<bool> {
    Err(CoreError::Credential("AA verify staged".into()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest(algo: &str, data: &[u8]) -> Vec<u8> {
    match algo {
        "SHA-1" => Sha1::digest(data).to_vec(),
        "SHA-224" => Sha224::digest(data).to_vec(),
        "SHA-384" => Sha384::digest(data).to_vec(),
        "SHA-512" => Sha512::digest(data).to_vec(),
        _ => Sha256::digest(data).to_vec(), // SHA-256 default
    }
}

fn hash_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.4" => "SHA-224",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => "SHA-256",
    }
    .to_string()
}

#[cfg(test)]
mod tests;
