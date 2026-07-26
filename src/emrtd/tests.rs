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

// ---------------------------------------------------------------------------
// Active Authentication over a synthetic chip key. The key, challenge and
// signature are all generated here; no real chip material is involved.
// ---------------------------------------------------------------------------

/// A synthetic AA chip: EF.DG15 (`0x6F`-wrapped SubjectPublicKeyInfo) plus the
/// signing key it would keep to itself.
fn synthetic_aa_chip() -> (Vec<u8>, p256::ecdsa::SigningKey) {
    use p256::pkcs8::EncodePublicKey;
    let key = p256::ecdsa::SigningKey::from_bytes(&[13u8; 32].into()).unwrap();
    let spki = key.verifying_key().to_public_key_der().unwrap();
    (der_tlv_bytes(0x6f, spki.as_bytes()), key)
}

/// Sign `challenge` the way a chip does: ECDSA over its digest, raw `r || s`.
fn aa_sign(key: &p256::ecdsa::SigningKey, algo: &str, challenge: &[u8]) -> Vec<u8> {
    use ecdsa::signature::hazmat::PrehashSigner;
    let sig: p256::ecdsa::Signature = key.sign_prehash(&digest(algo, challenge)).unwrap();
    sig.to_bytes().to_vec()
}

#[test]
fn aa_ecdsa_signature_over_the_challenge_verifies() {
    let (dg15, key) = synthetic_aa_chip();
    let challenge = [0x01u8, 2, 3, 4, 5, 6, 7, 8];
    let sig = aa_sign(&key, "SHA-256", &challenge);
    assert!(verify_active_auth(&dg15, &challenge, &sig).unwrap());

    // The reader may hand us the bare SPKI instead of the whole EF.
    let spki = strip_dg15_wrapper(&dg15).to_vec();
    assert!(verify_active_auth(&spki, &challenge, &sig).unwrap());

    // X9.62 DER is accepted alongside the raw r || s concatenation.
    let der_sig = der_ecdsa_sig_bytes(
        &BigU::from_bytes_be(&sig[..32]),
        &BigU::from_bytes_be(&sig[32..]),
    );
    assert!(verify_active_auth(&dg15, &challenge, &der_sig).unwrap());

    // A chip that hashed with SHA-1 still verifies (DG14 isn't passed to us).
    let sha1_sig = aa_sign(&key, "SHA-1", &challenge);
    assert!(verify_active_auth(&dg15, &challenge, &sha1_sig).unwrap());
}

#[test]
fn aa_rejects_a_signature_over_another_challenge() {
    let (dg15, key) = synthetic_aa_chip();
    let sig = aa_sign(&key, "SHA-256", &[1u8, 2, 3, 4, 5, 6, 7, 8]);
    assert!(!verify_active_auth(&dg15, &[9u8, 9, 9, 9, 9, 9, 9, 9], &sig).unwrap());

    // A different chip's key must not validate this signature either.
    let (other_dg15, _) = {
        use p256::pkcs8::EncodePublicKey;
        let k = p256::ecdsa::SigningKey::from_bytes(&[17u8; 32].into()).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        (der_tlv_bytes(0x6f, spki.as_bytes()), k)
    };
    assert!(!verify_active_auth(&other_dg15, &[1u8, 2, 3, 4, 5, 6, 7, 8], &sig).unwrap());
}

#[test]
fn aa_rsa_key_reports_unsupported() {
    // rsaEncryption SPKI (the key bits are irrelevant — dispatch is by OID).
    let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    let mut alg = der_tlv_bytes(0x06, rsa_oid.as_bytes());
    alg.extend_from_slice(&der_tlv_bytes(0x05, &[])); // NULL parameters
    let mut spki = der_tlv_bytes(0x30, &alg);
    spki.extend_from_slice(&der_tlv_bytes(0x03, &[0x00, 0xde, 0xad]));
    let dg15 = der_tlv_bytes(0x6f, &der_tlv_bytes(0x30, &spki));

    let e = verify_active_auth(&dg15, &[0u8; 8], &[0u8; 8]).unwrap_err();
    assert!(format!("{e}").contains("unsupported AA key type: RSA"), "{e}");
}

#[test]
fn aa_result_flows_into_the_verdict() {
    let p = fixtures::synthetic_passport();
    let (dg15, key) = synthetic_aa_chip();
    let challenge = [0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];
    let sig = aa_sign(&key, "SHA-256", &challenge);

    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((&dg15, &challenge, &sig)),
    )
    .unwrap();
    assert_eq!(v.active_auth, Some(true), "{:?}", v.notes);
    assert!(v.is_genuine(), "{:?}", v.notes);

    // A replayed signature over a different challenge fails AA and genuineness,
    // while PA still holds.
    let v = verify_passport(&p.sod, &p.dgs, &[p.csca], Some((&dg15, &[0u8; 8], &sig))).unwrap();
    assert_eq!(v.active_auth, Some(false));
    assert!(v.dg_integrity && v.sod_signature);
    assert_eq!(v.chain, ChainStatus::Trusted);
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
