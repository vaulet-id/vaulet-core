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
    /// Active Authentication result. `Some(false)` means the chip answered the
    /// challenge and the answer did not verify. `None` means the check did not
    /// happen at all — no AA material was supplied, the material was ignored
    /// because the SOD does not cover the DG15 that carries the answering key
    /// (the reason is in `notes`), or the key type is one we cannot verify (see
    /// `aa_unverifiable`).
    pub active_auth: Option<bool>,
    /// AA material *was* supplied but its key type is not implemented (RSA
    /// ISO/IEC 9796-2 DSS1) or its EC curve is one this verifier cannot parse
    /// (named-OID brainpool, P-521), so the challenge-response was neither proved nor
    /// disproved. `active_auth` is `None` in that case, exactly as for a chip
    /// with no AA key at all; this flag is what tells the two apart, so a caller
    /// can say "not verified" instead of "not supplied" and never read the
    /// absence as success. The reason is also in `notes`.
    ///
    /// It is a *diagnosis*, never a credit: an unverified answer is not a proof,
    /// so this flag never buys genuineness back ([`Self::active_auth_ok`]). The
    /// key type is read off DG15 alone — the signature bytes are never looked at
    /// — so treating it as an excuse would let anyone who once read a genuine
    /// RSA-AA chip (EF.SOD, DG1, DG2 and EF.DG15 are all public, only the AA
    /// private key is not) replay that material with a junk signature and be
    /// called genuine.
    pub aa_unverifiable: bool,
    /// The SOD digest algorithm (e.g. "SHA-256").
    pub hash_algo: String,
    /// DG numbers whose hash was checked.
    pub checked_dgs: Vec<u8>,
    /// Every DG number the SOD's LDSSecurityObject lists — what the *document*
    /// says it carries, independent of what the caller happened to read. A
    /// number here but not in `checked_dgs` was simply not supplied.
    pub sod_dgs: Vec<u8>,
    /// Human-readable notes (unsupported algorithm, etc.).
    pub notes: Vec<String>,
}

impl PassportVerdict {
    /// Genuine document: integrity + signature + a trusted chain, and an Active
    /// Authentication result that does not stand in the way ([`Self::active_auth_ok`]).
    pub fn is_genuine(&self) -> bool {
        self.dg_integrity
            && self.sod_signature
            && self.chain == ChainStatus::Trusted
            && self.active_auth_ok()
    }

    /// Whether Active Authentication lets this document be called genuine.
    ///
    /// A chip that answered wrongly never passes. A document whose SOD lists a
    /// DG15 ([`Self::supports_active_auth`]) owes an anti-clone proof, so
    /// anything short of a *verified* answer does not pass either. There is no
    /// exemption for a proof this verifier could not check (`aa_unverifiable`:
    /// RSA ISO/IEC 9796-2 DSS1, an unparseable curve): "we cannot check this key
    /// type" must not be worth more than "no proof at all", or a clone would buy
    /// genuineness back for free by sending junk instead of nothing — the flag is
    /// set from the DG15 key type alone, without ever looking at the signature,
    /// and DG15 is public data anyone who read the chip once can replay.
    ///
    /// Which of the two happened still matters to a relying party, and the
    /// verdict keeps saying it — `active_auth`, `aa_unverifiable` and `sod_dgs`
    /// separate "answered wrongly" from "answered with a key type we do not
    /// implement" from "did not answer" — but none of them is a proof, so none of
    /// them reaches this far.
    ///
    /// A document whose SOD lists no DG15 has nothing to prove, so it is genuine
    /// without an AA result, exactly as before.
    fn active_auth_ok(&self) -> bool {
        if self.supports_active_auth() {
            return self.active_auth == Some(true);
        }
        self.active_auth != Some(false)
    }

    /// Which of `required` the SOD did **not** cover, in the order given.
    ///
    /// `dg_integrity` only speaks for the data groups the SOD's
    /// LDSSecurityObject lists: one the caller supplied but the SOD never
    /// covered is not hashed, does not appear in `checked_dgs`, and cannot make
    /// integrity fail. So a caller that *relies* on a data group (builds claims
    /// from it, hashes it, trusts a key it carries) must also require that the
    /// group was actually covered — otherwise the bytes are attacker-chosen.
    /// Which groups those are is the caller's business; the check lives here so
    /// every caller asks the question the same way.
    pub fn uncovered_dgs(&self, required: &[u8]) -> Vec<u8> {
        required
            .iter()
            .copied()
            .filter(|num| !self.checked_dgs.contains(num))
            .collect()
    }

    /// Whether the *document* supports Active Authentication, i.e. the SOD lists
    /// a DG15 (the data group that carries the chip's AA public key).
    ///
    /// `active_auth` is `None` both when the chip has no AA key and when the
    /// caller simply did not send the proof, so it cannot tell the two apart —
    /// and "no proof" is what a cloned chip would send. The SOD can: a document
    /// whose SOD lists DG15 has an AA key, so a caller that treats a missing
    /// proof as acceptable must first check this and demand one.
    pub fn supports_active_auth(&self) -> bool {
        self.sod_dgs.contains(&15)
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

    // 2) SOD signature (verified against the DSC embedded in the SOD) +
    //    3) the DSC → CSCA chain. Both are real checks; the chain can only reach
    //    `Trusted` when the caller supplied an anchor for the issuing country.
    let (sod_signature, chain) = verify_sod_signature(ci, csca, &mut notes);

    // 4) Active Authentication. Only a chip that answered *and* answered wrongly
    //    is `Some(false)`: a key type or curve we cannot verify is not evidence of
    //    a clone, it is a gap in this verifier, and accusing every genuine RSA-AA
    //    and brainpool-AA chip of failing its anti-clone check would be a lie
    //    about what happened. It is not a proof either — `aa_unverifiable` is a
    //    diagnosis a caller reads, and `is_genuine` does not forgive it.
    //
    //    The answer is only worth checking when the SOD covers the DG15 that
    //    carries the answering key. Otherwise that key is simply whatever the
    //    caller handed us, and a signature from it proves possession of a key no
    //    issuing state ever vouched for. Such material is *unusable*, not
    //    incriminating: it is ignored — noted, and reported exactly as if none had
    //    been supplied — so that a caller can never read `active_auth = true` off
    //    a key the SOD does not cover, while a genuine but non-conformant document
    //    whose SOD omits DG15 (an EF.COM/SOD data-group-list mismatch) is still
    //    judged on its Passive Authentication, not disqualified by it.
    let mut active_auth = None;
    let mut aa_unverifiable = false;
    if let Some((dg15, challenge, sig)) = aa {
        // Hashed against the SOD directly rather than via `checked`, so the key
        // that answers is the covered one even when the caller left DG15 out of
        // `dgs` (where a substitution could not touch `dg_integrity`).
        let covered = lds
            .hashes
            .get(&15)
            .is_some_and(|expected| digest(&lds.hash_algo, dg15) == *expected);
        if !covered {
            notes.push(if lds.hashes.contains_key(&15) {
                "AA ignored: the supplied DG15 is not the one the SOD covers".into()
            } else {
                "AA ignored: the SOD does not cover DG15".to_string()
            });
        } else {
            match verify_active_auth(dg15, challenge, sig) {
                Ok(AaCheck::Verified) => active_auth = Some(true),
                Ok(AaCheck::Failed) => active_auth = Some(false),
                Ok(AaCheck::Unsupported(why)) => {
                    aa_unverifiable = true;
                    notes.push(format!("AA not verified: {why}"));
                }
                // Malformed material (DG15 that is not an SPKI, unreadable
                // signature): the chip's own answer is unusable, which is a failed
                // check. The bytes are chip-authentic — the SOD covers them — so
                // this is the document's own defect, not a substituted key.
                Err(e) => {
                    active_auth = Some(false);
                    notes.push(format!("AA: {e}"));
                }
            }
        }
    }

    Ok(PassportVerdict {
        dg_integrity,
        sod_signature,
        chain,
        active_auth,
        aa_unverifiable,
        hash_algo: lds.hash_algo.clone(),
        checked_dgs: checked,
        sod_dgs: lds.hashes.keys().copied().collect(),
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
// SOD signature + chain, Active Authentication
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
        // Explicit domain parameters (brainpool in Thai passports, etc.): the
        // NIST crates can't parse these, so verify generically with bignum.
        if let (Some((p, a, n, gx, gy, qx, qy)), Some((r, s))) =
            (parse_ec_explicit_spki(spki_der), parse_ecdsa_sig(sig))
        {
            // e = the leftmost bit_len(n) bits of the hash.
            let mut e = num_bigint::BigUint::from_bytes_be(&hashed);
            let hbits = (hashed.len() * 8) as u64;
            let nbits = n.bits();
            if hbits > nbits {
                e >>= (hbits - nbits) as usize;
            }
            return Ok(ecdsa_verify_generic(&p, &a, &n, &gx, &gy, &qx, &qy, &e, &r, &s));
        }
        let hex: String = spki_der.iter().map(|b| format!("{b:02x}")).collect();
        return Err(bad(format!("unsupported ECDSA curve; spki={hex}")));
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

// --- Generic ECDSA over explicit Weierstrass domain parameters ---------------
// Passports (e.g. Thailand's, brainpoolP256r1) embed the full curve in the DSC
// rather than a named-curve OID; the NIST-specific crates can't parse those and
// RustCrypto has no stable brainpool curve. We verify with big-integer math.
// Verification touches only public data — no key material, no timing surface.

type BigU = num_bigint::BigUint;

/// Parse a SubjectPublicKeyInfo with **explicit** EC parameters, returning
/// (prime p, curve a, order n, Gx, Gy, Qx, Qy). Reuses the module `read_tlv`.
#[allow(clippy::type_complexity)]
fn parse_ec_explicit_spki(spki: &[u8]) -> Option<(BigU, BigU, BigU, BigU, BigU, BigU, BigU)> {
    let outer = read_tlv(spki).ok()?; // SPKI SEQUENCE
    let alg = read_tlv(outer.value).ok()?; // algorithm SEQUENCE
    let bitstr = read_tlv(alg.rest).ok()?; // subjectPublicKey BIT STRING
    if bitstr.tag != 0x03 {
        return None;
    }
    let oid = read_tlv(alg.value).ok()?; // id-ecPublicKey
    let ecparams = read_tlv(oid.rest).ok()?; // ECParameters
    if ecparams.tag != 0x30 {
        return None; // named-curve (OID) params handled elsewhere
    }
    let ver = read_tlv(ecparams.value).ok()?;
    let fieldid = read_tlv(ver.rest).ok()?; // SEQUENCE { OID, prime INTEGER }
    let curve = read_tlv(fieldid.rest).ok()?; // SEQUENCE { a OCTET, b OCTET, [seed] }
    let base = read_tlv(curve.rest).ok()?; // OCTET STRING 04||Gx||Gy
    let order = read_tlv(base.rest).ok()?; // INTEGER n

    let ft = read_tlv(fieldid.value).ok()?;
    let prime = read_tlv(ft.rest).ok()?;
    let a_oct = read_tlv(curve.value).ok()?;

    if base.value.first() != Some(&0x04) {
        return None;
    }
    let clen = (base.value.len() - 1) / 2;
    let gx = BigU::from_bytes_be(&base.value[1..1 + clen]);
    let gy = BigU::from_bytes_be(&base.value[1 + clen..]);

    // BIT STRING: first byte is the unused-bit count (0), then 04||Qx||Qy.
    let pk = bitstr.value.get(1..)?;
    if pk.first() != Some(&0x04) {
        return None;
    }
    let qlen = (pk.len() - 1) / 2;
    let qx = BigU::from_bytes_be(&pk[1..1 + qlen]);
    let qy = BigU::from_bytes_be(&pk[1 + qlen..]);

    Some((
        BigU::from_bytes_be(prime.value),
        BigU::from_bytes_be(a_oct.value),
        BigU::from_bytes_be(order.value),
        gx,
        gy,
        qx,
        qy,
    ))
}

/// Parse an X9.62 ECDSA signature `SEQUENCE { r INTEGER, s INTEGER }`.
fn parse_ecdsa_sig(sig: &[u8]) -> Option<(BigU, BigU)> {
    let seq = read_tlv(sig).ok()?;
    if seq.tag != 0x30 {
        return None;
    }
    let r = read_tlv(seq.value).ok()?;
    let s = read_tlv(r.rest).ok()?;
    Some((BigU::from_bytes_be(r.value), BigU::from_bytes_be(s.value)))
}

/// `a - b (mod p)` for non-negative values.
fn mod_sub(a: &BigU, b: &BigU, p: &BigU) -> BigU {
    let a = a % p;
    let b = b % p;
    if a >= b {
        (a - b) % p
    } else {
        (a + p - b) % p
    }
}

/// Modular inverse via Fermat's little theorem (`p` is a prime field modulus).
fn mod_inv(a: &BigU, p: &BigU) -> BigU {
    a.modpow(&(p - 2u32), p)
}

type Pt = Option<(BigU, BigU)>; // None = point at infinity

/// Affine point addition/doubling on `y² = x³ + a·x + b (mod p)`.
fn pt_add(p1: &Pt, p2: &Pt, a: &BigU, p: &BigU) -> Pt {
    match (p1, p2) {
        (None, _) => p2.clone(),
        (_, None) => p1.clone(),
        (Some((x1, y1)), Some((x2, y2))) => {
            let two = BigU::from(2u32);
            if x1 == x2 {
                if (y1 + y2) % p == BigU::from(0u32) {
                    return None; // P + (−P)
                }
                // doubling
                let three = BigU::from(3u32);
                let num = (&three * x1 * x1 + a) % p;
                let den = mod_inv(&((&two * y1) % p), p);
                let lam = (num * den) % p;
                let x3 = mod_sub(&((&lam * &lam) % p), &((&two * x1) % p), p);
                let y3 = mod_sub(&((&lam * mod_sub(x1, &x3, p)) % p), y1, p);
                Some((x3, y3))
            } else {
                let num = mod_sub(y2, y1, p);
                let den = mod_inv(&mod_sub(x2, x1, p), p);
                let lam = (num * den) % p;
                let x3 = mod_sub(&mod_sub(&((&lam * &lam) % p), x1, p), x2, p);
                let y3 = mod_sub(&((&lam * mod_sub(x1, &x3, p)) % p), y1, p);
                Some((x3, y3))
            }
        }
    }
}

/// `k·P` by double-and-add.
fn pt_mul(k: &BigU, base: &Pt, a: &BigU, p: &BigU) -> Pt {
    let mut result: Pt = None;
    let mut addend = base.clone();
    let mut kk = k.clone();
    let one = BigU::from(1u32);
    let zero = BigU::from(0u32);
    while kk > zero {
        if (&kk & &one) == one {
            result = pt_add(&result, &addend, a, p);
        }
        addend = pt_add(&addend, &addend, a, p);
        kk >>= 1u32;
    }
    result
}

/// ECDSA verification with explicit parameters.
#[allow(clippy::too_many_arguments)]
fn ecdsa_verify_generic(
    p: &BigU,
    a: &BigU,
    n: &BigU,
    gx: &BigU,
    gy: &BigU,
    qx: &BigU,
    qy: &BigU,
    e: &BigU,
    r: &BigU,
    s: &BigU,
) -> bool {
    let zero = BigU::from(0u32);
    if r <= &zero || r >= n || s <= &zero || s >= n {
        return false;
    }
    let w = mod_inv(s, n);
    let u1 = (e * &w) % n;
    let u2 = (r * &w) % n;
    let g: Pt = Some((gx.clone(), gy.clone()));
    let q: Pt = Some((qx.clone(), qy.clone()));
    let point = pt_add(&pt_mul(&u1, &g, a, p), &pt_mul(&u2, &q, a, p), a, p);
    match point {
        None => false,
        Some((x, _)) => (x % n) == *r,
    }
}

#[cfg(test)]
mod ecdsa_generic_tests {
    use super::*;

    fn hx(s: &[u8]) -> BigU {
        BigU::parse_bytes(s, 16).unwrap()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // brainpoolP256r1 (RFC 5639).
    #[test]
    fn order_times_generator_is_infinity() {
        let p = hx(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");
        let a = hx(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9");
        let n = hx(b"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");
        let gx = hx(b"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
        let gy = hx(b"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997");
        let g = Some((gx, gy));
        // n·G must be the point at infinity — validates pt_add (add + double) and pt_mul.
        assert!(pt_mul(&n, &g, &a, &p).is_none());
    }

    // The real Thai passport DSC SPKI (explicit brainpoolP256r1 params).
    #[test]
    fn parses_explicit_brainpool_spki() {
        let spki = unhex("308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a702010103420004648cad39a585841d16d98cb2cf0d1a4dd0d987ec709630182fcd6970149e3c5d1dc215968bf364048146cb44ea6510bd0dc05036f98b6d0434c00cba6ff406dc");
        let (p, a, n, gx, gy, qx, qy) = parse_ec_explicit_spki(&spki).unwrap();
        assert_eq!(p, hx(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"));
        assert_eq!(a, hx(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"));
        assert_eq!(n, hx(b"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"));
        assert_eq!(gx, hx(b"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"));
        // Public key point.
        assert_eq!(qx, hx(b"648CAD39A585841D16D98CB2CF0D1A4DD0D987EC709630182FCD6970149E3C5D"));
        assert_eq!(qy, hx(b"1DC215968BF364048146CB44EA6510BD0DC05036F98B6D0434C00CBA6FF406DC"));
        // Q must lie on the curve: y² == x³ + a·x + b (mod p).  b from the SPKI.
        let b = hx(b"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6");
        let lhs = (&qy * &qy) % &p;
        let rhs = (&qx * &qx % &p * &qx + &a * &qx + &b) % &p;
        assert_eq!(lhs, rhs, "public key not on curve");
    }
}

// ---------------------------------------------------------------------------
// Active Authentication (ICAO Doc 9303 Part 11 §6.1)
// ---------------------------------------------------------------------------

/// id-ecPublicKey — an AA key we can verify with ECDSA.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// Digest algorithms tried for ECDSA-AA. The chip's choice is announced in
/// DG14's ActiveAuthenticationInfo, which the reader does not pass us, so we
/// accept the signature under any ICAO-permitted digest. Trying several is safe:
/// a forged signature must still verify under the DG15 key, whose own hash is
/// covered by the SOD.
const AA_HASHES: [&str; 5] = ["SHA-256", "SHA-1", "SHA-224", "SHA-384", "SHA-512"];

/// Strip the EF.DG15 file wrapper (`0x6F` tag) if present, returning the inner
/// SubjectPublicKeyInfo DER. Readers hand us the whole EF, not the bare key.
fn strip_dg15_wrapper(dg15: &[u8]) -> &[u8] {
    if dg15.first() == Some(&0x6f) {
        if let Ok(tlv) = read_tlv(dg15) {
            return tlv.value;
        }
    }
    dg15
}

/// The algorithm OID of a SubjectPublicKeyInfo (hand-rolled so SPKIs with
/// explicit EC domain parameters parse the same as named-curve ones).
fn spki_algorithm_oid(spki: &[u8]) -> Option<ObjectIdentifier> {
    let outer = read_tlv(spki).ok()?; // SPKI SEQUENCE
    if outer.tag != 0x30 {
        return None;
    }
    let alg = read_tlv(outer.value).ok()?; // AlgorithmIdentifier SEQUENCE
    if alg.tag != 0x30 {
        return None;
    }
    let oid = read_tlv(alg.value).ok()?;
    if oid.tag != 0x06 {
        return None;
    }
    ObjectIdentifier::from_der(&der_tlv_bytes(0x06, oid.value)).ok()
}

/// Encode a non-negative integer as a DER INTEGER TLV.
fn der_integer_bytes(v: &BigU) -> Vec<u8> {
    let mut b = v.to_bytes_be();
    if b.is_empty() {
        b = vec![0];
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    der_tlv_bytes(0x02, &b)
}

/// Re-encode `(r, s)` as an X9.62 `SEQUENCE { r, s }` for the typed verifiers.
fn der_ecdsa_sig_bytes(r: &BigU, s: &BigU) -> Vec<u8> {
    let mut inner = der_integer_bytes(r);
    inner.extend_from_slice(&der_integer_bytes(s));
    der_tlv_bytes(0x30, &inner)
}

/// Candidate `(r, s)` readings of an AA signature. INTERNAL AUTHENTICATE returns
/// the plain `r || s` concatenation, but some stacks hand back X9.62 DER, so we
/// offer both readings and let verification decide.
fn aa_ecdsa_sig_candidates(sig: &[u8]) -> Vec<(BigU, BigU)> {
    let mut out = Vec::new();
    if sig.first() == Some(&0x30) {
        if let Some(rs) = parse_ecdsa_sig(sig) {
            out.push(rs);
        }
    }
    if !sig.is_empty() && sig.len() % 2 == 0 {
        let half = sig.len() / 2;
        out.push((
            BigU::from_bytes_be(&sig[..half]),
            BigU::from_bytes_be(&sig[half..]),
        ));
    }
    out
}

/// Human-readable name for a named-curve OID, for the notes.
fn ec_curve_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    Some(match oid.to_string().as_str() {
        "1.2.840.10045.3.1.1" => "P-192",
        "1.3.132.0.33" => "P-224",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        "1.3.36.3.3.2.8.1.1.1" => "brainpoolP160r1",
        "1.3.36.3.3.2.8.1.1.3" => "brainpoolP192r1",
        "1.3.36.3.3.2.8.1.1.5" => "brainpoolP224r1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.9" => "brainpoolP320r1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        _ => return None,
    })
}

/// Name the EC curve of a SubjectPublicKeyInfo for a note: the named curve if
/// the parameters carry an OID, otherwise "explicit parameters" plus the SPKI
/// hex, which is the only way to identify a curve we could not parse.
fn ec_curve_label(spki: &[u8]) -> String {
    let params = (|| {
        let outer = read_tlv(spki).ok()?; // SPKI SEQUENCE
        let alg = read_tlv(outer.value).ok()?; // AlgorithmIdentifier SEQUENCE
        let oid = read_tlv(alg.value).ok()?; // id-ecPublicKey
        read_tlv(oid.rest).ok().map(|p| (p.tag, p.value.to_vec()))
    })();
    if let Some((0x06, bytes)) = &params {
        if let Ok(oid) = ObjectIdentifier::from_der(&der_tlv_bytes(0x06, bytes)) {
            return match ec_curve_name(&oid) {
                Some(name) => format!("{name} ({oid})"),
                None => format!("named curve {oid}"),
            };
        }
    }
    let hex: String = spki.iter().map(|b| format!("{b:02x}")).collect();
    format!("explicit parameters; spki={hex}")
}

/// Verify an ECDSA Active Authentication signature over the challenge.
///
/// A curve this verifier cannot parse yields `Unsupported`, never `Failed`:
/// not being able to read the key says nothing about the chip's answer.
fn verify_aa_ecdsa(spki: &[u8], challenge: &[u8], sig: &[u8]) -> Result<AaCheck> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use spki::DecodePublicKey;

    let k256 = p256::ecdsa::VerifyingKey::from_public_key_der(spki).ok();
    let k384 = p384::ecdsa::VerifyingKey::from_public_key_der(spki).ok();
    let explicit = if k256.is_none() && k384.is_none() {
        parse_ec_explicit_spki(spki)
    } else {
        None
    };
    if k256.is_none() && k384.is_none() && explicit.is_none() {
        // A gap in this verifier, not a wrong answer from the chip.
        return Ok(AaCheck::Unsupported(format!(
            "unsupported ECDSA curve {}",
            ec_curve_label(spki)
        )));
    }

    let candidates = aa_ecdsa_sig_candidates(sig);
    if candidates.is_empty() {
        return Err(CoreError::Credential("AA: bad ECDSA signature".into()));
    }

    for algo in AA_HASHES {
        let hashed = digest(algo, challenge);
        for (r, s) in &candidates {
            if let Some(vk) = &k256 {
                if let Ok(s2) = p256::ecdsa::Signature::from_der(&der_ecdsa_sig_bytes(r, s)) {
                    if vk.verify_prehash(&hashed, &s2).is_ok() {
                        return Ok(AaCheck::Verified);
                    }
                }
            }
            if let Some(vk) = &k384 {
                if let Ok(s2) = p384::ecdsa::Signature::from_der(&der_ecdsa_sig_bytes(r, s)) {
                    if vk.verify_prehash(&hashed, &s2).is_ok() {
                        return Ok(AaCheck::Verified);
                    }
                }
            }
            if let Some((p, a, n, gx, gy, qx, qy)) = &explicit {
                // e = the leftmost bit_len(n) bits of the hash.
                let mut e = BigU::from_bytes_be(&hashed);
                let hbits = (hashed.len() * 8) as u64;
                let nbits = n.bits();
                if hbits > nbits {
                    e >>= (hbits - nbits) as usize;
                }
                if ecdsa_verify_generic(p, a, n, gx, gy, qx, qy, &e, r, s) {
                    return Ok(AaCheck::Verified);
                }
            }
        }
    }
    // Parsed the key, tried every reading of the answer: the chip answered wrongly.
    Ok(AaCheck::Failed)
}

/// The outcome of an Active Authentication check.
///
/// `Unsupported` is deliberately *not* an error and *not* `Failed`: "this
/// verifier cannot check that key type" says nothing about the chip, whereas
/// `Failed` accuses it of being a clone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AaCheck {
    /// The chip's signature over the challenge verified.
    Verified,
    /// The chip answered and the answer did not verify.
    Failed,
    /// The key type or curve is not implemented here; carries the reason for
    /// the notes.
    Unsupported(String),
}

/// Verify the chip's Active Authentication signature over the challenge.
///
/// `dg15` is EF.DG15 (with or without its `0x6F` file wrapper), carrying the AA
/// public key as a SubjectPublicKeyInfo. ECDSA keys are verified with the same
/// P-256/P-384/explicit-parameter dispatch used for the SOD; an EC curve that
/// dispatch cannot parse (named-OID brainpool, P-521, secp256k1) reports
/// `Unsupported` naming the curve, just as an unimplemented key type does. RSA
/// AA uses ISO/IEC 9796-2 Digital Signature Scheme 1 with message recovery —
/// not a PKCS#1 verify — and is not implemented yet; it reports `Unsupported`
/// too. `verify_passport` surfaces `Unsupported` as `active_auth = None` +
/// `aa_unverifiable` plus a note, never as a failed check.
fn verify_active_auth(dg15: &[u8], challenge: &[u8], sig: &[u8]) -> Result<AaCheck> {
    let spki = strip_dg15_wrapper(dg15);
    let oid = spki_algorithm_oid(spki)
        .ok_or_else(|| CoreError::Credential("AA: DG15 is not a SubjectPublicKeyInfo".into()))?;
    if oid == OID_EC_PUBLIC_KEY {
        return verify_aa_ecdsa(spki, challenge, sig);
    }
    if oid.to_string().starts_with("1.2.840.113549.1.1") {
        return Ok(AaCheck::Unsupported(
            "RSA DSS1 unsupported (ISO/IEC 9796-2 not implemented)".into(),
        ));
    }
    Ok(AaCheck::Unsupported(format!(
        "unsupported AA key type {oid}"
    )))
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

/// Reading EF.DG1 — always compiled: the issuer reads the MRZ on every
/// issuance, it is not a test facility.
pub mod dg1;

/// Synthetic SOD/DSC/CSCA builders for tests (see `fixtures`). Enabled for this
/// crate's own tests and, via the `test-fixtures` feature, for the backend's.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;

#[cfg(test)]
mod tests;
