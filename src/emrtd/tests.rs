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

/// An AA-capable synthetic passport: its SOD covers DG1, DG2 *and* the DG15 of
/// [`synthetic_aa_chip`], so the key that answers the challenge is one the
/// issuing state signed — the only shape in which an AA answer is checked at all.
fn synthetic_aa_passport() -> (fixtures::SyntheticPassport, Vec<u8>, p256::ecdsa::SigningKey) {
    let (dg15, key) = synthetic_aa_chip();
    let mut dgs = BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, dg15.clone());
    (fixtures::synthetic_passport_with_dgs(dgs), dg15, key)
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
    assert_eq!(
        verify_active_auth(&dg15, &challenge, &sig).unwrap(),
        AaCheck::Verified
    );

    // The reader may hand us the bare SPKI instead of the whole EF.
    let spki = strip_dg15_wrapper(&dg15).to_vec();
    assert_eq!(
        verify_active_auth(&spki, &challenge, &sig).unwrap(),
        AaCheck::Verified
    );

    // X9.62 DER is accepted alongside the raw r || s concatenation.
    let der_sig = der_ecdsa_sig_bytes(
        &BigU::from_bytes_be(&sig[..32]),
        &BigU::from_bytes_be(&sig[32..]),
    );
    assert_eq!(
        verify_active_auth(&dg15, &challenge, &der_sig).unwrap(),
        AaCheck::Verified
    );

    // A chip that hashed with SHA-1 still verifies (DG14 isn't passed to us).
    let sha1_sig = aa_sign(&key, "SHA-1", &challenge);
    assert_eq!(
        verify_active_auth(&dg15, &challenge, &sha1_sig).unwrap(),
        AaCheck::Verified
    );
}

#[test]
fn aa_rejects_a_signature_over_another_challenge() {
    let (dg15, key) = synthetic_aa_chip();
    let sig = aa_sign(&key, "SHA-256", &[1u8, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        verify_active_auth(&dg15, &[9u8, 9, 9, 9, 9, 9, 9, 9], &sig).unwrap(),
        AaCheck::Failed
    );

    // A different chip's key must not validate this signature either.
    let (other_dg15, _) = {
        use p256::pkcs8::EncodePublicKey;
        let k = p256::ecdsa::SigningKey::from_bytes(&[17u8; 32].into()).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        (der_tlv_bytes(0x6f, spki.as_bytes()), k)
    };
    assert_eq!(
        verify_active_auth(&other_dg15, &[1u8, 2, 3, 4, 5, 6, 7, 8], &sig).unwrap(),
        AaCheck::Failed
    );
}

/// An EF.DG15 carrying an rsaEncryption SubjectPublicKeyInfo. The key bits are
/// irrelevant — dispatch is by algorithm OID, and RSA AA is never verified.
fn rsa_aa_chip() -> Vec<u8> {
    let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    let mut alg = der_tlv_bytes(0x06, rsa_oid.as_bytes());
    alg.extend_from_slice(&der_tlv_bytes(0x05, &[])); // NULL parameters
    let mut spki = der_tlv_bytes(0x30, &alg);
    spki.extend_from_slice(&der_tlv_bytes(0x03, &[0x00, 0xde, 0xad]));
    der_tlv_bytes(0x6f, &der_tlv_bytes(0x30, &spki))
}

/// An EF.DG15 carrying an id-ecPublicKey SubjectPublicKeyInfo on a *named*
/// curve, given by OID. The point bytes are arbitrary — dispatch happens on the
/// curve, before any point arithmetic.
fn named_curve_aa_chip(curve_oid: &str, coord_len: usize) -> Vec<u8> {
    let ec = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let curve = ObjectIdentifier::new(curve_oid).unwrap();
    let mut alg = der_tlv_bytes(0x06, ec.as_bytes());
    alg.extend_from_slice(&der_tlv_bytes(0x06, curve.as_bytes()));
    let mut point = vec![0x00, 0x04]; // unused-bit count, then uncompressed point
    point.extend(vec![0x11u8; coord_len]); // Qx
    point.extend(vec![0x22u8; coord_len]); // Qy
    let mut spki = der_tlv_bytes(0x30, &alg);
    spki.extend_from_slice(&der_tlv_bytes(0x03, &point));
    der_tlv_bytes(0x6f, &der_tlv_bytes(0x30, &spki))
}

/// THE FIX: an EC curve this verifier cannot parse is a gap here, exactly like
/// an RSA AA key — `Unsupported`, naming the curve, never `Failed`. Reporting it
/// as a failed check accused every genuine brainpool/P-521 chip of being a clone.
#[test]
fn aa_unsupported_ec_curve_reports_unsupported_naming_the_curve() {
    // brainpoolP256r1 by OID (the named-curve form of Thailand's curve).
    let dg15 = named_curve_aa_chip("1.3.36.3.3.2.8.1.1.7", 32);
    match verify_active_auth(&dg15, &[0xA5u8; 8], &[0u8; 64]).unwrap() {
        AaCheck::Unsupported(why) => {
            assert!(why.contains("unsupported ECDSA curve"), "{why}");
            assert!(why.contains("brainpoolP256r1"), "{why}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }

    // P-521 and secp256k1 are the same story.
    let p521 = named_curve_aa_chip("1.3.132.0.35", 66);
    match verify_active_auth(&p521, &[0xA5u8; 8], &[0u8; 64]).unwrap() {
        AaCheck::Unsupported(why) => assert!(why.contains("P-521"), "{why}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
    let k256 = named_curve_aa_chip("1.3.132.0.10", 32);
    match verify_active_auth(&k256, &[0xA5u8; 8], &[0u8; 64]).unwrap() {
        AaCheck::Unsupported(why) => assert!(why.contains("secp256k1"), "{why}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// ...and it reaches the verdict as "not checked" rather than as a failed
/// anti-clone check, so the evidence says what actually happened. The document
/// still owes a proof it did not deliver — see
/// `junk_aa_signature_on_an_rsa_key_does_not_buy_genuineness` for why the
/// distinction is a diagnosis and not an exemption.
#[test]
fn unsupported_ec_curve_is_not_reported_as_a_failed_check() {
    let mut dgs = std::collections::BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, named_curve_aa_chip("1.3.36.3.3.2.8.1.1.7", 32));
    let p = fixtures::synthetic_passport_with_dgs(dgs);

    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((&p.dgs[&15], &[0xA5u8; 8], &[0u8; 64])),
    )
    .unwrap();
    assert_eq!(v.active_auth, None, "{:?}", v.notes);
    assert!(v.aa_unverifiable, "{:?}", v.notes);
    assert!(
        v.notes
            .iter()
            .any(|n| n.starts_with("AA not verified:") && n.contains("brainpoolP256r1")),
        "{:?}",
        v.notes
    );
    // Passive Authentication is untouched, and the document still owes a proof —
    // which an answer we could not check does not pay, so the headline verdict
    // does not call it genuine.
    assert!(v.dg_integrity && v.sod_signature, "{:?}", v.notes);
    assert!(v.supports_active_auth());
    assert!(!v.is_genuine(), "{:?}", v.notes);
}

/// The other half of the split, pinned: a curve we *can* parse whose signature
/// does not verify stays a failed check. "Cannot parse this curve" and "parsed
/// fine, the answer was wrong" must never collapse into one another.
#[test]
fn a_wrong_signature_on_a_supported_curve_stays_a_failed_check() {
    let (dg15, key) = synthetic_aa_chip();
    let challenge = [0x0au8, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];

    // A well-formed ECDSA signature over a different challenge: the chip answered,
    // and answered wrongly.
    let replayed = aa_sign(&key, "SHA-256", &[0u8; 8]);
    assert_eq!(
        verify_active_auth(&dg15, &challenge, &replayed).unwrap(),
        AaCheck::Failed
    );

    let mut dgs = std::collections::BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, dg15.clone());
    let p = fixtures::synthetic_passport_with_dgs(dgs);

    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((&dg15, &challenge, &replayed)),
    )
    .unwrap();
    assert_eq!(v.active_auth, Some(false), "{:?}", v.notes);
    assert!(!v.aa_unverifiable, "{:?}", v.notes);
    assert!(!v.is_genuine(), "{:?}", v.notes);
}

/// RSA AA (ISO/IEC 9796-2 DSS1 with message recovery) is not implemented, and
/// that is a gap in this verifier — not a failed challenge-response.
#[test]
fn aa_rsa_key_reports_unsupported() {
    let dg15 = rsa_aa_chip();
    let out = verify_active_auth(&dg15, &[0u8; 8], &[0u8; 8]).unwrap();
    match out {
        AaCheck::Unsupported(why) => assert!(why.contains("RSA DSS1 unsupported"), "{why}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Material we cannot parse at all is still a failed check: the chip's own
/// answer is unusable, which is not the same as a key type we chose not to
/// implement. The SOD covers these bytes, so they really are the document's own
/// DG15 — a substituted one is ignored instead (see the uncovered-DG15 tests).
#[test]
fn aa_material_that_is_not_a_public_key_is_a_failed_check() {
    let mut dgs = std::collections::BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, b"not-an-spki".to_vec());
    let p = fixtures::synthetic_passport_with_dgs(dgs);

    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((b"not-an-spki", &[0u8; 8], &[0u8; 8])),
    )
    .unwrap();
    assert_eq!(v.active_auth, Some(false), "{:?}", v.notes);
    assert!(!v.aa_unverifiable, "{:?}", v.notes);
    assert!(!v.is_genuine(), "{:?}", v.notes);
}

/// THE FIX (M1): an RSA AA key reaches the verdict as "not checked"
/// (`active_auth = None` + `aa_unverifiable`), never as `Some(false)`. RSA AA
/// keys are the majority of eMRTDs in the field; stamping them as a failed
/// anti-clone check accused every genuine one of being a clone.
#[test]
fn unsupported_aa_key_is_not_reported_as_a_failed_check() {
    let mut dgs = std::collections::BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, rsa_aa_chip());
    let p = fixtures::synthetic_passport_with_dgs(dgs);

    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((&p.dgs[&15], &[0xA5u8; 8], &[0u8; 8])),
    )
    .unwrap();
    // Not a failed challenge-response — the check simply did not happen.
    assert_eq!(v.active_auth, None, "{:?}", v.notes);
    assert!(v.aa_unverifiable, "{:?}", v.notes);
    // ...and the reason is on the record rather than silently swallowed.
    assert!(
        v.notes.iter().any(|n| n.starts_with("AA not verified:")),
        "{:?}",
        v.notes
    );
    // Passive Authentication is untouched: the RSA DG15 is covered by the SOD.
    assert!(v.dg_integrity && v.sod_signature, "{:?}", v.notes);
    assert_eq!(v.checked_dgs, vec![1, 2, 15]);
    // The document is AA-capable, so a proof is still owed — `aa_unverifiable`
    // is how a caller tells "unverified" from "absent".
    assert!(v.supports_active_auth());
    // ...and that distinction is a diagnosis, not a credit: the proof was not
    // delivered, so the headline verdict is the same as for an omitted one (E6).
    assert!(!v.is_genuine(), "{:?}", v.notes);
}

/// THE FIX (E6): an unverifiable key type is worth no more than no proof at all.
/// `aa_unverifiable` is decided by the DG15 key type alone — the signature bytes
/// are never read — so forgiving it handed a cloner a free pass: EF.SOD, DG1,
/// DG2 and EF.DG15 are public data anyone who reads a genuine RSA-AA chip once
/// walks away with, while the AA private key stays on the chip. Replaying that
/// material with any junk signature used to be stamped `passport_authentic:
/// true`; now the document owes a proof it did not deliver, and says so.
#[test]
fn junk_aa_signature_on_an_rsa_key_does_not_buy_genuineness() {
    // A genuine RSA-AA document, read once by the attacker: everything here is
    // public chip data, all of it covered by the issuing state's SOD.
    let mut dgs = std::collections::BTreeMap::new();
    dgs.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    dgs.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    dgs.insert(15u8, rsa_aa_chip());
    let p = fixtures::synthetic_passport_with_dgs(dgs);

    // The clone replays it with a signature it could not possibly have produced.
    let junk = [0xFFu8; 64];
    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca.clone()],
        Some((&p.dgs[&15], &[0xA5u8; 8], &junk)),
    )
    .unwrap();

    // Passive Authentication is perfect and the chain is trusted — the whole
    // point of Active Authentication is that this is not enough.
    assert!(v.dg_integrity && v.sod_signature, "{:?}", v.notes);
    assert_eq!(v.chain, ChainStatus::Trusted);
    assert_eq!(v.checked_dgs, vec![1, 2, 15]);

    // The junk is not called a failed check — we never looked at it — but the
    // document listed a DG15 and no verified answer arrived.
    assert_eq!(v.active_auth, None, "{:?}", v.notes);
    assert!(v.aa_unverifiable, "{:?}", v.notes);
    assert!(v.supports_active_auth());
    assert!(!v.is_genuine(), "{:?}", v.notes);

    // ...and the evidence still tells this apart from an omitted proof, which
    // reaches the same verdict with `aa_unverifiable` false.
    let omitted = verify_passport(&p.sod, &p.dgs, &[p.csca], None).unwrap();
    assert_eq!(omitted.active_auth, None, "{:?}", omitted.notes);
    assert!(!omitted.aa_unverifiable, "{:?}", omitted.notes);
    assert!(!omitted.is_genuine(), "{:?}", omitted.notes);
    assert!(
        v.notes.iter().any(|n| n.starts_with("AA not verified:")),
        "{:?}",
        v.notes
    );
    assert!(
        !omitted.notes.iter().any(|n| n.starts_with("AA not verified:")),
        "{:?}",
        omitted.notes
    );
}

/// The verified case, for contrast: an ECDSA AA key is checked for real, and
/// `aa_unverifiable` stays false whether it passes or fails.
#[test]
fn a_supported_aa_key_is_always_verified_for_real() {
    let (p, dg15, key) = synthetic_aa_passport();
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
    assert!(!v.aa_unverifiable);

    let v = verify_passport(&p.sod, &p.dgs, &[p.csca], Some((&dg15, &[0u8; 8], &sig))).unwrap();
    assert_eq!(v.active_auth, Some(false), "{:?}", v.notes);
    assert!(!v.aa_unverifiable);
}

/// The AA result reaching the verdict, on its own: this document's SOD covers
/// the DG15 that answered, so the answer is checked for real.
#[test]
fn aa_result_flows_into_the_verdict() {
    let (p, dg15, key) = synthetic_aa_passport();
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

// ---------------------------------------------------------------------------
// Holes the enforcement work has to close (issue #1). These tests assert the
// CURRENT, WRONG behaviour so the fixes visibly flip them. Every byte here is
// synthetic (see `emrtd::fixtures`).
//
// H1 (closed): `verify_passport` only walks the DGs the SOD's LDSSecurityObject
//     LISTS. A DG the caller supplies but the SOD never covered is still
//     silently ignored by `dg_integrity` — so `uncovered_dgs` now names it, and
//     a caller that relies on that group refuses to issue. For DG15 the engine
//     no longer leaves the question to the caller: AA material the SOD does not
//     cover is ignored in here (E3), so an uncovered key can neither earn an
//     `active_auth = true` nor disqualify an otherwise-authentic document.
// H2 (closed): omitting the AA material still means `active_auth = None`, which
//     on its own cannot be told apart from a chip with no AA key — so the verdict
//     now also carries `sod_dgs`, and `supports_active_auth` says when the
//     document had a key and therefore owed a proof.
// ---------------------------------------------------------------------------

/// A passport whose SOD covers DG1/DG2 and an AA key it never signed: the SOD
/// lists no DG15, so the key answering the challenge is the caller's own.
/// `dg_integrity` cannot see this — `uncovered_dgs` is what names the uncovered
/// group.
///
/// THE FIX (E3): the unusable material is *ignored* rather than allowed to drive
/// the check. `active_auth` stays `None` — the caller can no longer be shown a
/// `true` earned by a key nobody vouched for — and the reason is in `notes`.
/// The document itself is untouched: Passive Authentication still holds, so a
/// genuine passport whose SOD omits DG15 is not disqualified by material we
/// could not use.
#[test]
fn an_aa_key_the_sod_does_not_cover_is_ignored_not_credited() {
    let p = fixtures::synthetic_passport();
    // The SOD covers DG1 and DG2 only — no DG15 hash.
    assert_eq!(p.dgs.keys().copied().collect::<Vec<_>>(), vec![1, 2]);

    // An AA key the issuing state never signed + a signature over a challenge of
    // the caller's choosing. (The same shape either way: an attacker's invented
    // key, or a non-conformant chip whose real DG15 the SOD forgot to list.)
    let (uncovered_dg15, uncovered_key) = synthetic_aa_chip();
    let challenge = [0x5au8, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a];
    let sig = aa_sign(&uncovered_key, "SHA-256", &challenge);

    // The caller hands DG15 in alongside the genuine DGs, exactly as the backend
    // does before calling us.
    let mut dgs = p.dgs.clone();
    dgs.insert(15, uncovered_dg15.clone());

    let v = verify_passport(&p.sod, &dgs, &[p.csca], Some((&uncovered_dg15, &challenge, &sig)))
        .unwrap();
    // The answer verifies against the supplied key — and is thrown away, because
    // nothing binds that key to the document.
    assert_eq!(v.active_auth, None, "{:?}", v.notes);
    // Not "unverifiable" either: that is reserved for a covered key whose *type*
    // we cannot check, which a caller may reasonably forgive.
    assert!(!v.aa_unverifiable, "{:?}", v.notes);
    assert!(
        v.notes
            .iter()
            .any(|n| n == "AA ignored: the SOD does not cover DG15"),
        "{:?}",
        v.notes
    );
    // Passive Authentication is untouched: DG15 never entered the integrity
    // check, and the document is as genuine as it was without any AA material.
    assert!(v.dg_integrity, "{:?}", v.notes);
    assert!(v.sod_signature, "{:?}", v.notes);
    assert_eq!(v.chain, ChainStatus::Trusted);
    assert_eq!(v.checked_dgs, vec![1, 2]);
    assert!(!v.supports_active_auth());
    assert!(v.is_genuine(), "{:?}", v.notes);

    // ...and a caller that relies on the AA key can still ask whether the SOD
    // covered it, and be told that it did not.
    assert_eq!(v.uncovered_dgs(&[1, 2, 15]), vec![15]);
    // The groups the SOD did cover are not flagged.
    assert!(v.uncovered_dgs(&[1, 2]).is_empty());
}

/// The other substitution, on an AA-capable document: the SOD *does* list a
/// DG15, and the caller answers with a different key. Hashing the supplied DG15
/// against the SOD is what catches it, so the substitution is ignored even when
/// the caller keeps the swapped group out of `dgs` (where `dg_integrity` would
/// never see it).
#[test]
fn an_aa_key_that_is_not_the_one_the_sod_covers_is_ignored() {
    let (p, _dg15, _key) = synthetic_aa_passport();
    let substitute_key = p256::ecdsa::SigningKey::from_bytes(&[19u8; 32].into()).unwrap();
    let substitute_dg15 = {
        use p256::pkcs8::EncodePublicKey;
        der_tlv_bytes(
            0x6f,
            substitute_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    };
    let challenge = [0x5au8; 8];
    let sig = aa_sign(&substitute_key, "SHA-256", &challenge);

    // Only the genuine DG1/DG2 are read, so integrity has nothing to complain
    // about — the swapped key arrives through the AA material alone.
    let mut dgs = p.dgs.clone();
    dgs.remove(&15);
    let v = verify_passport(&p.sod, &dgs, &[p.csca], Some((&substitute_dg15, &challenge, &sig)))
        .unwrap();
    assert!(v.dg_integrity, "{:?}", v.notes);
    assert_eq!(v.active_auth, None, "{:?}", v.notes);
    assert!(
        v.notes
            .iter()
            .any(|n| n == "AA ignored: the supplied DG15 is not the one the SOD covers"),
        "{:?}",
        v.notes
    );
    // The document owes a proof, and none of the material we could use answered
    // it — so the headline verdict does not call it genuine.
    assert!(v.supports_active_auth());
    assert!(!v.is_genuine(), "{:?}", v.notes);
}

/// The same shape for DG2: a SOD that covers DG1 only lets the caller invent a
/// DG2 without breaking integrity. The backend hashes that DG2 into
/// `portrait_hash` and discloses it as the `dg2` claim the face-verification
/// issuer matches against, so it must ask whether DG2 was covered.
#[test]
fn dg2_absent_from_the_sod_is_reported_as_uncovered() {
    let mut covered = BTreeMap::new();
    covered.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    let p = fixtures::synthetic_passport_with_dgs(covered);

    let mut dgs = p.dgs.clone();
    dgs.insert(2, b"ATTACKER-CHOSEN-FACE-NOT-IN-THE-SOD".to_vec());

    let v = verify_passport(&p.sod, &dgs, &[p.csca], None).unwrap();
    // Integrity holds — the uncovered DG2 was simply never hashed.
    assert!(v.dg_integrity, "{:?}", v.notes);
    assert_eq!(v.checked_dgs, vec![1]);
    // THE FIX: the group the credential is built from is named as uncovered,
    // in the order asked for.
    assert_eq!(v.uncovered_dgs(&[1, 2]), vec![2]);
}

/// A fully covered read has nothing uncovered — including the DG15 of an
/// AA-capable document.
#[test]
fn every_covered_dg_is_reported_as_covered() {
    let (dg15, _key) = synthetic_aa_chip();
    let mut covered = BTreeMap::new();
    covered.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    covered.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    covered.insert(15u8, dg15);
    let p = fixtures::synthetic_passport_with_dgs(covered);

    let v = verify_passport(&p.sod, &p.dgs, &[p.csca], None).unwrap();
    assert_eq!(v.checked_dgs, vec![1, 2, 15]);
    assert!(v.uncovered_dgs(&[1, 2, 15]).is_empty());
    // A group neither read nor covered is still uncovered.
    assert_eq!(v.uncovered_dgs(&[3]), vec![3]);
}

/// THE FIX (H2): the SOD lists a DG15, so this document supports Active
/// Authentication. Omitting the AA material still yields `active_auth = None` —
/// indistinguishable, on that field alone, from a chip that has no AA key — so
/// the verdict now also reports what the SOD claims, and `supports_active_auth`
/// is what tells a caller a proof was owed. (The gate is the caller's: the
/// backend refuses issuance in strict mode on exactly this.)
#[test]
fn a_sod_that_lists_dg15_reports_the_document_as_aa_capable() {
    let (dg15, _key) = synthetic_aa_chip();
    let mut covered = BTreeMap::new();
    covered.insert(1u8, b"SYNTHETIC-DG1-NOT-A-REAL-MRZ".to_vec());
    covered.insert(2u8, b"SYNTHETIC-DG2-NOT-A-REAL-FACE".to_vec());
    covered.insert(15u8, dg15);
    let p = fixtures::synthetic_passport_with_dgs(covered);

    // The chip's DG15 is read and hashes correctly; no challenge is answered.
    let v = verify_passport(&p.sod, &p.dgs, &[p.csca.clone()], None).unwrap();
    assert!(v.dg_integrity, "{:?}", v.notes);
    assert_eq!(v.checked_dgs, vec![1, 2, 15]);
    assert_eq!(v.active_auth, None);
    // THE FIX: the document itself says it has an AA key, whatever was uploaded.
    assert_eq!(v.sod_dgs, vec![1, 2, 15]);
    assert!(v.supports_active_auth());

    // The DG15 need not even be read for the SOD to say the key exists — this is
    // the shape a client that drops the AA fields produces.
    let mut without_dg15 = p.dgs.clone();
    without_dg15.remove(&15);
    let v = verify_passport(&p.sod, &without_dg15, &[p.csca], None).unwrap();
    assert_eq!(v.checked_dgs, vec![1, 2]);
    assert_eq!(v.sod_dgs, vec![1, 2, 15]);
    assert!(v.supports_active_auth());
}

/// THE FIX (E5): the headline verdict answers the question `supports_active_auth`
/// asks. A cloned chip copies the SOD, DG1 and DG2 — all of which chain to a
/// trusted CSCA — and simply omits the anti-clone proof it cannot produce. The
/// verdict already knew better (`sod_dgs` lists 15, `checked_dgs` does not);
/// now `is_genuine` says so instead of reading identically to a chip that really
/// proved possession.
#[test]
fn an_owed_but_missing_aa_proof_is_not_genuine() {
    let (p, _dg15, key) = synthetic_aa_passport();

    // The clone sends everything except the challenge-response.
    let mut cloned = p.dgs.clone();
    cloned.remove(&15);
    let v = verify_passport(&p.sod, &cloned, &[p.csca.clone()], None).unwrap();
    // Passive Authentication is perfect, and the chain is trusted...
    assert!(v.dg_integrity && v.sod_signature, "{:?}", v.notes);
    assert_eq!(v.chain, ChainStatus::Trusted);
    // ...but the document said it had an AA key, and no proof arrived.
    assert!(v.supports_active_auth());
    assert_eq!(v.active_auth, None);
    assert!(!v.aa_unverifiable);
    assert!(!v.is_genuine(), "{:?}", v.notes);

    // Reading the DG15 itself changes nothing: the proof is the answer, not the key.
    let v = verify_passport(&p.sod, &p.dgs, &[p.csca.clone()], None).unwrap();
    assert_eq!(v.checked_dgs, vec![1, 2, 15]);
    assert!(!v.is_genuine(), "{:?}", v.notes);

    // The same document *with* its proof is genuine — nothing else changed.
    let challenge = [0xC1u8; 8];
    let sig = aa_sign(&key, "SHA-256", &challenge);
    let v = verify_passport(
        &p.sod,
        &p.dgs,
        &[p.csca],
        Some((&p.dgs[&15], &challenge, &sig)),
    )
    .unwrap();
    assert_eq!(v.active_auth, Some(true), "{:?}", v.notes);
    assert!(v.is_genuine(), "{:?}", v.notes);
}

/// The other side: a SOD with no DG15 belongs to a document that cannot do
/// Active Authentication at all, so a missing proof is not a missing answer.
#[test]
fn a_sod_without_dg15_reports_the_document_as_not_aa_capable() {
    let p = fixtures::synthetic_passport();
    let v = verify_passport(&p.sod, &p.dgs, &[p.csca], None).unwrap();
    assert_eq!(v.sod_dgs, vec![1, 2]);
    assert!(!v.supports_active_auth());
    assert_eq!(v.active_auth, None);
    assert!(v.is_genuine(), "{:?}", v.notes);
}

#[test]
fn strips_sod_application_wrapper() {
    let inner = b"content-info-bytes";
    let wrapped = der_tlv_bytes(0x77, inner);
    assert_eq!(strip_sod_wrapper(&wrapped), inner);
    // No wrapper → returned unchanged.
    assert_eq!(strip_sod_wrapper(inner), inner);
}
