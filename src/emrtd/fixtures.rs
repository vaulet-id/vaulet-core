//! Synthetic eMRTD fixtures for tests — **never** real chip data.
//!
//! Builds a self-signed CSCA, a DSC signed by it, and a full CMS SignedData
//! EF.SOD over fabricated data groups, so both this crate and the backend can
//! exercise Passive Authentication end to end (trusted chain, missing anchor,
//! unrelated anchor, tampered DG) without any passport ever being read.
//!
//! Test-only: compiled under `cfg(test)` here, and behind the `test-fixtures`
//! feature for downstream crates (the backend enables it in dev-dependencies).

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier,
    SignerInfo, SignerInfos,
};
use der::asn1::{Any, BitString, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Tag};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_LDS_SECURITY_OBJECT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// A complete synthetic passport read: the raw material a chip would yield plus
/// the trust anchors that do (and do not) authenticate it.
pub struct SyntheticPassport {
    /// EF.SOD (a bare CMS ContentInfo, no `0x77` wrapper).
    pub sod: Vec<u8>,
    /// Raw data groups, DG number → EF bytes (opaque to the verifier).
    pub dgs: BTreeMap<u8, Vec<u8>>,
    /// The CSCA (DER) that signed this passport's DSC → `ChainStatus::Trusted`.
    pub csca: Vec<u8>,
    /// An unrelated CSCA (DER) that did not → `ChainStatus::Failed`.
    pub unrelated_csca: Vec<u8>,
}

impl SyntheticPassport {
    /// The raw EF.DG1 bytes (synthetic, not an MRZ).
    pub fn dg1(&self) -> &[u8] {
        &self.dgs[&1]
    }

    /// The raw EF.DG2 bytes (synthetic, not a face image).
    pub fn dg2(&self) -> &[u8] {
        &self.dgs[&2]
    }
}

/// The MRZ inside the fixture's EF.DG1: ANNA MARIA ERIKSSON, Utopian, born
/// 1974-08-12, passport L898902C3 expiring 2035-04-15.
///
/// ICAO 9303's own worked example, with the expiry moved into the future and
/// its check digits recomputed — the issuer refuses an expired document, and a
/// fixture that expired in 2012 would only ever exercise that refusal.
pub const SYNTHETIC_MRZ: &str = concat!(
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F3504152ZE184226B<<<<<16",
);

/// Build a synthetic passport with the default DG1/DG2 payloads.
pub fn synthetic_passport() -> SyntheticPassport {
    let mut dgs = BTreeMap::new();
    // A real TD3 zone, every check digit correct. It used to be a placeholder
    // string, which was fine while nothing read DG1 — but the issuer now reads
    // it, and a fixture that cannot be read is a fixture that only exercises
    // the failure path (ICAO 9303 part 3's own worked example, "Utopia").
    dgs.insert(1u8, crate::emrtd::dg1::wrap_dg1(SYNTHETIC_MRZ));
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    synthetic_passport_with_dgs(dgs)
}

/// Build a synthetic passport whose SOD covers exactly `dgs`.
pub fn synthetic_passport_with_dgs(dgs: BTreeMap<u8, Vec<u8>>) -> SyntheticPassport {
    // Deterministic keys: fixtures must be reproducible and need no RNG.
    let csca_key = SigningKey::from_bytes(&[7u8; 32].into()).expect("csca key");
    let dsc_key = SigningKey::from_bytes(&[9u8; 32].into()).expect("dsc key");
    let other_key = SigningKey::from_bytes(&[11u8; 32].into()).expect("other csca key");

    let csca = make_cert(
        "CN=Vaulet Test CSCA",
        "CN=Vaulet Test CSCA",
        1,
        &csca_key,
        &csca_key,
    );
    let dsc = make_cert(
        "CN=Vaulet Test DSC",
        "CN=Vaulet Test CSCA",
        2,
        &dsc_key,
        &csca_key,
    );
    let unrelated = make_cert(
        "CN=Vaulet Other CSCA",
        "CN=Vaulet Other CSCA",
        1,
        &other_key,
        &other_key,
    );

    let entries: Vec<(u8, Vec<u8>)> = dgs
        .iter()
        .map(|(num, bytes)| (*num, Sha256::digest(bytes).to_vec()))
        .collect();
    let lds = lds_security_object(&entries);

    let encap = EncapsulatedContentInfo {
        econtent_type: OID_LDS_SECURITY_OBJECT,
        econtent: Some(Any::new(Tag::OctetString, lds.clone()).expect("econtent")),
    };

    // signedAttrs: contentType + messageDigest over the eContent (RFC 5652 §5.3).
    let message_digest = Sha256::digest(&lds).to_vec();
    let signed_attrs: SignedAttributes = SetOfVec::try_from(vec![
        attribute(
            OID_CONTENT_TYPE,
            Any::encode_from(&OID_LDS_SECURITY_OBJECT).unwrap(),
        ),
        attribute(
            OID_MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(message_digest).unwrap()).unwrap(),
        ),
    ])
    .expect("signed attrs");

    // The DSC signs the DER SET OF signedAttrs (RFC 5652 §5.4).
    let sig: Signature = dsc_key.sign(&signed_attrs.to_der().unwrap());

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: dsc.tbs_certificate.issuer.clone(),
            serial_number: dsc.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: alg_sha256(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: alg_ecdsa_sha256(),
        signature: OctetString::new(sig.to_der().as_bytes().to_vec()).unwrap(),
        unsigned_attrs: None,
    };

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::try_from(vec![alg_sha256()]).unwrap(),
        encap_content_info: encap,
        certificates: Some(CertificateSet(
            SetOfVec::try_from(vec![CertificateChoices::Certificate(dsc)]).unwrap(),
        )),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info]).unwrap()),
    };

    let content_info = ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).unwrap(),
    };

    SyntheticPassport {
        sod: content_info.to_der().unwrap(),
        dgs,
        csca: csca.to_der().unwrap(),
        unrelated_csca: unrelated.to_der().unwrap(),
    }
}

/// Wrap bytes in one DER TLV (single-byte tag, short/long length).
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(value);
    out
}

/// LDSSecurityObject (SHA-256, version 0) over `(dg number, dg hash)` entries.
fn lds_security_object(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut body = tlv(0x02, &[0x00]); // version 0
    body.extend_from_slice(&tlv(0x30, &OID_SHA256.to_der().unwrap())); // digest algorithm
    let mut hashes = Vec::new();
    for (num, hash) in entries {
        let mut inner = tlv(0x02, &[*num]);
        inner.extend_from_slice(&tlv(0x04, hash));
        hashes.extend_from_slice(&tlv(0x30, &inner));
    }
    body.extend_from_slice(&tlv(0x30, &hashes));
    tlv(0x30, &body)
}

fn alg_ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA256,
        parameters: None,
    }
}

fn alg_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: Some(Any::null()),
    }
}

fn attribute(oid: ObjectIdentifier, value: AttributeValue) -> Attribute {
    Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).unwrap(),
    }
}

/// Issue a certificate for `subject_key`, signed by `issuer_key` (ECDSA/SHA-256).
fn make_cert(
    subject: &str,
    issuer: &str,
    serial: u8,
    subject_key: &SigningKey,
    issuer_key: &SigningKey,
) -> Certificate {
    let spki_der = subject_key.verifying_key().to_public_key_der().unwrap();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).unwrap(),
        signature: alg_ecdsa_sha256(),
        issuer: Name::from_str(issuer).unwrap(),
        validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
        subject: Name::from_str(subject).unwrap(),
        subject_public_key_info: Decode::from_der(spki_der.as_bytes()).unwrap(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let sig: Signature = issuer_key.sign(&tbs.to_der().unwrap());
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg_ecdsa_sha256(),
        signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
    }
}
