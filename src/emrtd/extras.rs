//! EF.DG7, EF.DG11 and EF.DG12 — the fields beside the MRZ, read from the chip.
//!
//! DG1 carries the machine-readable zone and nothing else. Everything a
//! passport shows that the MRZ does not — place of birth, the holder's name in
//! full, the issuing authority, the date of issue, the handwritten signature —
//! lives in these data groups. Their hashes are in the same SOD, so they are
//! exactly as verifiable as DG1 is; what was missing was anyone reading them.
//!
//! Layout is ICAO 9303 part 10: a constructed outer tag, an optional tag list,
//! and then one BER TLV per field. Values are Latin-1 text with `<` as filler
//! and `<<` as a separator between repeated values.

use std::collections::BTreeMap;

/// The additional personal details in EF.DG11.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Dg11 {
    /// The holder's full name as printed, which can differ from the MRZ's
    /// truncated and transliterated form — the MRZ name field is 39 characters
    /// and long names are cut to fit.
    pub name_of_holder: Option<String>,
    pub other_names: Vec<String>,
    pub personal_number: Option<String>,
    pub place_of_birth: Option<String>,
    pub permanent_address: Option<String>,
    pub telephone: Option<String>,
    pub profession: Option<String>,
    pub title: Option<String>,
}

/// The document details in EF.DG12.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Dg12 {
    pub issuing_authority: Option<String>,
    /// ISO 8601, from the chip's `YYYYMMDD`.
    pub date_of_issue: Option<String>,
}

/// Parse EF.DG11.
pub fn parse_dg11(dg11: &[u8]) -> Dg11 {
    let f = fields(dg11, 0x6b);
    Dg11 {
        name_of_holder: f.get(&0x5f0e).and_then(|v| text(v)).map(join_name),
        other_names: f
            .get(&0x5f0f)
            .and_then(|v| text(v))
            .map(|s| {
                s.split("<<")
                    .map(join_name)
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        personal_number: f.get(&0x5f10).and_then(|v| text(v)),
        // Address and place of birth are multi-line: `<` separates the lines,
        // and joining them with a comma is how they are read aloud.
        place_of_birth: f.get(&0x5f11).and_then(|v| text(v)).map(join_lines),
        permanent_address: f.get(&0x5f42).and_then(|v| text(v)).map(join_lines),
        telephone: f.get(&0x5f12).and_then(|v| text(v)),
        profession: f.get(&0x5f13).and_then(|v| text(v)),
        title: f.get(&0x5f14).and_then(|v| text(v)),
    }
}

/// Parse EF.DG12.
pub fn parse_dg12(dg12: &[u8]) -> Dg12 {
    let f = fields(dg12, 0x6c);
    Dg12 {
        issuing_authority: f.get(&0x5f19).and_then(|v| text(v)),
        date_of_issue: f.get(&0x5f26).and_then(|v| text(v)).and_then(|s| {
            // `YYYYMMDD` on the chip; some issuers write it as BCD-packed
            // digits, which arrive here as four bytes rather than eight
            // characters and are not text at all — those are simply skipped
            // rather than turned into a plausible-looking wrong date.
            (s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()))
                .then(|| format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]))
        }),
    }
}

/// The holder's handwritten signature image from EF.DG7, if it carries one.
pub fn parse_dg7_image(dg7: &[u8]) -> Option<Vec<u8>> {
    fields(dg7, 0x67).get(&0x5f43).cloned()
}

/// Every BER TLV inside a constructed data group, by tag.
///
/// Unwraps the outer tag when present and skips the tag-list element (`5C`),
/// which enumerates what follows and carries no value of its own.
fn fields(data: &[u8], outer: u8) -> BTreeMap<u32, Vec<u8>> {
    let body = if data.first() == Some(&outer) {
        match read_tlv(data) {
            Some((_, value, _)) => value,
            None => return BTreeMap::new(),
        }
    } else {
        data
    };
    let mut out = BTreeMap::new();
    let mut rest = body;
    while let Some((tag, value, next)) = read_tlv(rest) {
        rest = next;
        if tag == 0x5c {
            continue;
        }
        // Constructed elements (`A0` holds the repeated other-names) contain
        // more TLVs; their contents are what the caller is after. The
        // constructed bit lives in the FIRST tag byte, and every two-byte
        // `5Fxx` tag here is primitive — testing the whole tag value instead
        // makes 5F26 (date of issue) look constructed because its second byte
        // happens to have that bit set.
        if tag <= 0xff && tag & 0x20 != 0 {
            let mut inner = value;
            while let Some((t, v, n)) = read_tlv(inner) {
                out.entry(t).or_insert_with(|| v.to_vec());
                inner = n;
            }
        } else {
            out.entry(tag).or_insert_with(|| value.to_vec());
        }
        if rest.is_empty() {
            break;
        }
    }
    out
}

/// One BER TLV: `(tag, value, rest)`. Handles the one- and two-byte tags and
/// the short and long length forms that appear in these data groups.
fn read_tlv(data: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    let first = *data.first()?;
    // A two-byte tag is marked by the low five bits of the first byte being
    // set, which is how `5F0E` is told from `5C`.
    let (tag, mut i) = if first & 0x1f == 0x1f {
        ((first as u32) << 8 | *data.get(1)? as u32, 2)
    } else {
        (first as u32, 1)
    };
    let b = *data.get(i)?;
    i += 1;
    let len = if b < 0x80 {
        b as usize
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | *data.get(i)? as usize;
            i += 1;
        }
        l
    };
    let value = data.get(i..i + len)?;
    Some((tag, value, &data[i + len..]))
}

/// A chip field as text, or nothing when it is empty or not text.
///
/// Latin-1, because that is what 9303 specifies; decoding it as UTF-8 would
/// reject a name with an accent in it, and guessing at some other encoding
/// would put invented characters in someone's name.
fn text(v: &[u8]) -> Option<String> {
    let s: String = v.iter().map(|&b| b as char).collect();
    let s = s.trim_matches(|c| c == '<' || c == '\0' || c == ' ').trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// `SURNAME<<GIVEN<NAMES` as it is written and read.
fn join_name(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    let mut parts = s.splitn(2, "<<");
    let surname = parts.next().unwrap_or_default().replace('<', " ");
    match parts.next() {
        Some(given) => format!("{} {}", given.replace('<', " "), surname),
        None => surname,
    }
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ")
}

/// Multi-line fields, whose lines are separated by the filler character.
fn join_lines(s: impl AsRef<str>) -> String {
    s.as_ref()
        .split('<')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a data group the way a chip lays one out, so the tests exercise
    /// the parser rather than a convenient shape.
    fn dg(outer: u8, fields: &[(u32, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in fields {
            if *tag > 0xff {
                body.push((tag >> 8) as u8);
                body.push(*tag as u8);
            } else {
                body.push(*tag as u8);
            }
            if value.len() < 0x80 {
                body.push(value.len() as u8);
            } else {
                body.push(0x81);
                body.push(value.len() as u8);
            }
            body.extend_from_slice(value);
        }
        let mut out = vec![outer];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn dg11_yields_the_details_the_mrz_does_not_carry() {
        let bytes = dg(
            0x6b,
            &[
                (0x5c, b"\x5f\x0e\x5f\x11"), // the tag list, which carries no value
                (0x5f0e, b"ERIKSSON<<ANNA<MARIA"),
                (0x5f11, b"UTOPIA<CITY<OF<BIRTH"),
                (0x5f10, b"1234567890123"),
                (0x5f13, b"ENGINEER"),
            ],
        );
        let d = parse_dg11(&bytes);
        assert_eq!(d.name_of_holder.as_deref(), Some("ANNA MARIA ERIKSSON"));
        assert_eq!(d.place_of_birth.as_deref(), Some("UTOPIA, CITY, OF, BIRTH"));
        assert_eq!(d.personal_number.as_deref(), Some("1234567890123"));
        assert_eq!(d.profession.as_deref(), Some("ENGINEER"));
        assert_eq!(d.title, None);
    }

    #[test]
    fn dg12_yields_the_issuing_authority_and_a_dated_issue() {
        let d = parse_dg12(&dg(
            0x6c,
            &[(0x5f19, b"MINISTRY OF UTOPIA"), (0x5f26, b"20250114")],
        ));
        assert_eq!(d.issuing_authority.as_deref(), Some("MINISTRY OF UTOPIA"));
        assert_eq!(d.date_of_issue.as_deref(), Some("2025-01-14"));
    }

    /// A date the chip did not write as eight digits is left out rather than
    /// reshaped into something that looks like a date. A wrong issue date on a
    /// signed credential is worse than a missing one.
    #[test]
    fn an_unreadable_issue_date_is_omitted_not_guessed() {
        let d = parse_dg12(&dg(0x6c, &[(0x5f26, b"\x20\x25\x01\x14")]));
        assert_eq!(d.date_of_issue, None);
    }

    #[test]
    fn dg7_yields_the_signature_image() {
        let img = b"\xff\xd8\xff-not-really-a-jpeg";
        let bytes = dg(0x67, &[(0x02, b"\x01"), (0x5f43, img)]);
        assert_eq!(parse_dg7_image(&bytes).as_deref(), Some(&img[..]));
    }

    /// Bytes that are not a data group yield nothing, rather than fields
    /// assembled out of whatever the buffer happened to contain.
    #[test]
    fn nonsense_yields_no_fields() {
        assert_eq!(parse_dg11(b"not a data group"), Dg11::default());
        assert_eq!(parse_dg12(&[]), Dg12::default());
        assert_eq!(parse_dg7_image(b"\x67"), None);
    }
}
