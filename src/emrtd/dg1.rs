//! EF.DG1 — the machine-readable zone, read from the chip bytes themselves.
//!
//! Passive Authentication establishes that the DG1 BYTES are genuine: their
//! hash appears in an SOD signed by the issuing state. It says nothing about
//! what those bytes MEAN, because nothing ever reads them. That gap is what
//! this module closes: the values an issued credential asserts should come out
//! of the verified bytes, not out of a field the caller filled in.
//!
//! The MRZ grammar itself — field offsets, filler handling, check digits, the
//! two-digit-year century rule — is ICAO 9303 and is left to the `mrz` crate.
//! Only the container is unwrapped here.

use crate::{CoreError, Result};

pub use mrz::MrzData;

/// Parse the MRZ out of raw EF.DG1.
///
/// Accepts either the wrapped elementary file (`61 L 5F1F L <mrz>`) or bare MRZ
/// characters, because both reach this code: chips deliver the former and test
/// vectors are commonly written as the latter.
pub fn parse_dg1(dg1: &[u8]) -> Result<MrzData> {
    let mrz = unwrap_dg1(dg1)?;
    // Length alone identifies the document format — the three ICAO layouts have
    // no overlapping total lengths — so the caller never has to declare which
    // kind of document it holds, and cannot declare it wrongly.
    let lines: Vec<&str> = match mrz.len() {
        88 => vec![&mrz[0..44], &mrz[44..88]],
        72 => vec![&mrz[0..36], &mrz[36..72]],
        90 => vec![&mrz[0..30], &mrz[30..60], &mrz[60..90]],
        n => {
            return Err(CoreError::Credential(format!(
                "DG1: {n} MRZ characters is no ICAO layout"
            )))
        }
    };
    let parsed = match lines.as_slice() {
        [l1, l2] if l1.len() == 44 => mrz::parse_td3(l1, l2),
        [l1, l2] => mrz::parse_td2(l1, l2),
        [l1, l2, l3] => mrz::parse_td1(l1, l2, l3),
        _ => unreachable!("the match above produces two or three lines"),
    };
    parsed.map_err(|e| CoreError::Credential(format!("DG1: {e}")))
}

/// The MRZ characters inside EF.DG1.
fn unwrap_dg1(dg1: &[u8]) -> Result<String> {
    let bytes = if dg1.first() == Some(&0x61) {
        // `61 L { 5F1F L <mrz> }` — a two-byte tag, which the module's DER
        // reader (single-byte tags, built for the SOD) would misread, so the
        // container is walked here rather than borrowed.
        let outer = value_of(dg1, 1)?;
        if outer.starts_with(&[0x5f, 0x1f]) {
            value_of(outer, 2)?
        } else {
            outer
        }
    } else {
        dg1
    };
    // The MRZ is a fixed-width character grid; a chip that returned bytes
    // outside it is not returning an MRZ, and guessing at an encoding here
    // would invent identity fields out of noise.
    std::str::from_utf8(bytes)
        .map(|s| s.trim().to_string())
        .map_err(|_| CoreError::Credential("DG1: MRZ is not text".into()))
}

/// The value of a BER TLV whose tag occupies `tag_len` bytes.
fn value_of(data: &[u8], tag_len: usize) -> Result<&[u8]> {
    let mut i = tag_len;
    let b = *data
        .get(i)
        .ok_or_else(|| CoreError::Credential("DG1: truncated".into()))?;
    i += 1;
    let len = if b < 0x80 {
        b as usize
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < i + n {
            return Err(CoreError::Credential("DG1: bad length".into()));
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | data[i] as usize;
            i += 1;
        }
        l
    };
    data.get(i..i + len)
        .ok_or_else(|| CoreError::Credential("DG1: length exceeds buffer".into()))
}

/// Wrap MRZ characters as an EF.DG1 elementary file — for building fixtures.
pub fn wrap_dg1(mrz: &str) -> Vec<u8> {
    let mrz = mrz.as_bytes();
    let mut inner = vec![0x5f, 0x1f];
    push_len(&mut inner, mrz.len());
    inner.extend_from_slice(mrz);
    let mut out = vec![0x61];
    push_len(&mut out, inner.len());
    out.extend_from_slice(&inner);
    out
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        out.push(0x81);
        out.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid TD3 zone: every check digit correct, so a parse failure here is
    /// this module's fault and not the vector's.
    const TD3: &str = concat!(
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
    );

    #[test]
    fn a_wrapped_elementary_file_yields_the_fields_the_chip_holds() {
        let m = parse_dg1(&wrap_dg1(TD3)).expect("DG1 parses");
        assert_eq!(m.surname, "ERIKSSON");
        assert_eq!(m.given_names, "ANNA MARIA");
        assert_eq!(m.nationality, "UTO");
        assert_eq!(m.document_number, "L898902C3");
        assert_eq!(m.date_of_birth, "1974-08-12");
        assert_eq!(m.date_of_expiry, "2012-04-15");
        assert_eq!(m.sex, "F");
        assert!(m.valid(), "every check digit should verify: {:?}", m.checks);
    }

    /// The same zone unwrapped. Both forms reach this code, and they must not
    /// disagree — a fixture written one way and a chip reading the other would
    /// otherwise be two different documents.
    #[test]
    fn bare_characters_parse_to_the_same_fields() {
        assert_eq!(
            parse_dg1(TD3.as_bytes()).expect("bare MRZ parses"),
            parse_dg1(&wrap_dg1(TD3)).expect("wrapped MRZ parses")
        );
    }

    /// Bytes that are not an MRZ are refused rather than guessed at. An issuer
    /// that treated a parse failure as "no fields" would sign the caller's
    /// values instead — the exact behaviour being removed.
    #[test]
    fn bytes_that_are_not_an_mrz_are_refused() {
        assert!(parse_dg1(b"SYNTHETIC-DG1-NOT-A-REAL-MRZ").is_err());
        assert!(parse_dg1(&[]).is_err());
        assert!(parse_dg1(&[0x61, 0x7f]).is_err());
    }

    /// A tampered zone is caught by its own check digits: the MRZ carries them
    /// precisely so a single edited character does not read as a valid
    /// document.
    #[test]
    fn an_edited_zone_fails_its_check_digits() {
        let mut edited = TD3.to_string();
        // 7408122 -> 7508122 in the date of birth, leaving its check digit
        // stale. Line 2 starts at offset 44; the date of birth at 44 + 13.
        edited.replace_range(57..58, "5");
        match parse_dg1(edited.as_bytes()) {
            Err(_) => {}
            Ok(m) => assert!(!m.valid(), "an edited date of birth verified: {m:?}"),
        }
    }
}
