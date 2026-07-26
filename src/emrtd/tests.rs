use super::*;
use der::Encode;

/// Build `SEQUENCE OF` a DataGroupHash entry: SEQUENCE { INTEGER num, OCTET STRING hash }.
fn dg_hash_entry(num: u8, hash: &[u8]) -> Vec<u8> {
    let mut inner = der_tlv_bytes(0x02, &[num]);
    inner.extend_from_slice(&der_tlv_bytes(0x04, hash));
    der_tlv_bytes(0x30, &inner)
}

/// Build a synthetic LDSSecurityObject (SHA-256) over the given DG hashes.
fn lds_econtent(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let sha256 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let mut body = der_tlv_bytes(0x02, &[0x00]); // version 0
    body.extend_from_slice(&der_tlv_bytes(0x30, &sha256.to_der().unwrap())); // algo SEQUENCE
    let mut dghashes = Vec::new();
    for (num, hash) in entries {
        dghashes.extend_from_slice(&dg_hash_entry(*num, hash));
    }
    body.extend_from_slice(&der_tlv_bytes(0x30, &dghashes));
    der_tlv_bytes(0x30, &body)
}

#[test]
fn parses_hash_algo_and_dg_hashes() {
    let dg1 = b"dg1-bytes";
    let dg2 = b"dg2-bytes";
    let content = lds_econtent(&[
        (1, digest("SHA-256", dg1)),
        (2, digest("SHA-256", dg2)),
    ]);
    let lds = parse_lds_econtent(&content).unwrap();
    assert_eq!(lds.hash_algo, "SHA-256");
    assert_eq!(lds.hashes.len(), 2);
    assert_eq!(lds.hashes[&1], digest("SHA-256", dg1));
    assert_eq!(lds.hashes[&2], digest("SHA-256", dg2));
}

#[test]
fn dg_integrity_matches_and_detects_tamper() {
    let dg1 = b"dg1-bytes".to_vec();
    let dg2 = b"dg2-bytes".to_vec();
    let lds = parse_lds_econtent(&lds_econtent(&[
        (1, digest("SHA-256", &dg1)),
        (2, digest("SHA-256", &dg2)),
    ]))
    .unwrap();

    // Genuine: every read DG matches.
    let ok = lds
        .hashes
        .iter()
        .all(|(_, h)| *h == digest("SHA-256", &dg1) || *h == digest("SHA-256", &dg2));
    assert!(ok);

    // Tampered DG2 no longer matches its SOD hash.
    let tampered = b"dg2-TAMPERED".to_vec();
    assert_ne!(digest("SHA-256", &tampered), lds.hashes[&2]);
}

// ---------------------------------------------------------------------------
// End-to-end Passive Authentication over a fully synthetic passport. These pin
// today's verdicts; no real chip data is involved (see `emrtd::fixtures`).
// ---------------------------------------------------------------------------

#[test]
fn synthetic_passport_with_its_csca_is_trusted() {
    let p = fixtures::synthetic_passport();
    let v = verify_passport(&p.sod, &p.dgs, &[p.csca.clone()], None).unwrap();
    assert!(v.dg_integrity, "{:?}", v.notes);
    assert!(v.sod_signature, "{:?}", v.notes);
    assert_eq!(v.chain, ChainStatus::Trusted);
    assert_eq!(v.active_auth, None);
    assert_eq!(v.hash_algo, "SHA-256");
    assert_eq!(v.checked_dgs, vec![1, 2]);
    assert!(v.is_genuine());

    // The same SOD inside the optional 0x77 application wrapper.
    let wrapped = fixtures::tlv(0x77, &p.sod);
    let v = verify_passport(&wrapped, &p.dgs, &[p.csca], None).unwrap();
    assert!(v.is_genuine(), "{:?}", v.notes);
}

#[test]
fn synthetic_passport_without_anchor_is_no_anchor_but_intact() {
    let p = fixtures::synthetic_passport();
    let v = verify_passport(&p.sod, &p.dgs, &[], None).unwrap();
    // Integrity and the SOD signature still hold — only the chain is unproven.
    assert!(v.dg_integrity);
    assert!(v.sod_signature);
    assert_eq!(v.chain, ChainStatus::NoAnchor);
    assert!(!v.is_genuine());
}

#[test]
fn synthetic_passport_with_unrelated_anchor_fails_the_chain() {
    let p = fixtures::synthetic_passport();
    let v = verify_passport(&p.sod, &p.dgs, &[p.unrelated_csca.clone()], None).unwrap();
    assert!(v.dg_integrity);
    assert!(v.sod_signature);
    assert_eq!(v.chain, ChainStatus::Failed);
    assert!(!v.is_genuine());
}

#[test]
fn tampered_dg_breaks_integrity_but_not_the_chain() {
    let p = fixtures::synthetic_passport();
    let mut dgs = p.dgs.clone();
    dgs.insert(2, b"TAMPERED".to_vec());
    let v = verify_passport(&p.sod, &dgs, &[p.csca], None).unwrap();
    assert!(!v.dg_integrity);
    assert!(v.sod_signature);
    assert_eq!(v.chain, ChainStatus::Trusted);
    assert!(v.notes.iter().any(|n| n == "DG2 hash mismatch"), "{:?}", v.notes);
    assert!(!v.is_genuine());
}

#[test]
fn strips_sod_application_wrapper() {
    let inner = b"content-info-bytes";
    let wrapped = der_tlv_bytes(0x77, inner);
    assert_eq!(strip_sod_wrapper(&wrapped), inner);
    // No wrapper → returned unchanged.
    assert_eq!(strip_sod_wrapper(inner), inner);
}
