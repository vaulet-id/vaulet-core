//! Deterministic CBOR — the frozen `belt_v1` canonicalization (RFC 8949 §4.2).
//!
//! This is how the liveness belt bundle is hashed (see
//! `app/lib/features/liveness_belt/belt_bundle.dart`), and this module is the
//! Rust half of it. Its Dart twin is
//! `app/lib/features/liveness_belt/dcbor.dart`; the two are pinned against the
//! same test vectors so a bundle hashed on device recomputes to the same bytes
//! on the server (`backend/src/belt_envelope.rs` is the typed envelope that
//! feeds this encoder at `/api/v1/liveness/verify`).
//!
//! Encoding rules (RFC 8949 §4.2.1, "core deterministic"):
//!   * definite-length encoding for every string, array and map;
//!   * integers, string lengths and array/map counts in the shortest head that
//!     fits (preferred serialization);
//!   * map keys sorted by their *encoded bytes*, compared bytewise — so `"a"` <
//!     `"b"` < `"aa"` (length first), which is NOT the plain string ordering the
//!     canonical-JSON path uses;
//!   * duplicate map keys rejected rather than silently collapsed.
//!
//! DELIBERATE DEVIATION — floats. RFC 8949 §4.2.2's preferred float
//! serialization shortens a double to float32/float16 whenever the value round
//! trips. We always emit float64 (`0xfb`) instead. Half-precision has no native
//! representation in Dart, and hand-rolling the shortening ladder on both sides
//! is exactly the kind of subtle divergence this format exists to prevent: a
//! one-bit disagreement turns into a 100% verify-failure rate on device. Always
//! emitting float64 is unambiguous, trivially identical in both languages, and
//! still fully deterministic. Revisit only with a byte-vector test proving both
//! ladders agree.
//!
//! Non-finite floats (NaN, ±Infinity) are rejected: they carry no meaning in the
//! envelope and NaN has no single canonical encoding.

use std::fmt;

/// A CBOR data item, restricted to the types the belt envelope uses.
///
/// Integers and floats are separate variants on purpose: CBOR distinguishes
/// them and Dart distinguishes `int` from `double`, so the two ends must agree
/// per field. Never build this from an untyped JSON round-trip when the source
/// of truth is a typed struct.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    /// Major type 0 (non-negative) or 1 (negative), chosen by sign.
    Int(i64),
    /// Major type 7, always encoded as float64 (see the module note).
    Float(f64),
    /// Major type 2, a byte string.
    Bytes(Vec<u8>),
    /// Major type 3, a UTF-8 text string.
    Text(String),
    /// Major type 4, a definite-length array (order is preserved as given).
    Array(Vec<Cbor>),
    /// Major type 5, a definite-length map. Entry order here is irrelevant —
    /// [`encode`] sorts by encoded key bytes.
    Map(Vec<(Cbor, Cbor)>),
    /// Major type 7, `false` (0xf4) / `true` (0xf5).
    Bool(bool),
    /// Major type 7, `null` (0xf6).
    Null,
}

/// Why an envelope could not be canonicalized.
#[derive(Debug, Clone, PartialEq)]
pub enum DcborError {
    /// NaN or ±Infinity appeared in the envelope.
    NonFiniteFloat(f64),
    /// Two map keys encoded to the same bytes (hex of the encoded key).
    DuplicateKey(String),
    /// A JSON number that fits in neither i64 nor f64.
    UnrepresentableNumber(String),
}

impl fmt::Display for DcborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DcborError::NonFiniteFloat(v) => write!(f, "non-finite float in envelope: {v}"),
            DcborError::DuplicateKey(k) => write!(f, "duplicate map key: 0x{k}"),
            DcborError::UnrepresentableNumber(n) => write!(f, "unrepresentable number: {n}"),
        }
    }
}

impl std::error::Error for DcborError {}

impl Cbor {
    /// Convert a `serde_json::Value` tree, mapping integral JSON numbers to
    /// [`Cbor::Int`] and fractional ones to [`Cbor::Float`].
    ///
    /// Use this only for fixtures and for values that were already typed on the
    /// way in. A JSON *transport* destroys the int/float distinction (`1.0`
    /// arrives as a float, `1` as an integer), so a server recomputing a bundle
    /// hash must deserialize into an explicitly typed struct first.
    pub fn from_json(v: &serde_json::Value) -> Result<Cbor, DcborError> {
        Ok(match v {
            serde_json::Value::Null => Cbor::Null,
            serde_json::Value::Bool(b) => Cbor::Bool(*b),
            serde_json::Value::String(s) => Cbor::Text(s.clone()),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Cbor::Int(i)
                } else if let Some(f) = n.as_f64() {
                    Cbor::Float(f)
                } else {
                    return Err(DcborError::UnrepresentableNumber(n.to_string()));
                }
            }
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(Cbor::from_json(it)?);
                }
                Cbor::Array(out)
            }
            serde_json::Value::Object(map) => {
                let mut out = Vec::with_capacity(map.len());
                for (k, val) in map {
                    out.push((Cbor::Text(k.clone()), Cbor::from_json(val)?));
                }
                Cbor::Map(out)
            }
        })
    }
}

/// Encode a data item as deterministic CBOR.
pub fn encode(value: &Cbor) -> Result<Vec<u8>, DcborError> {
    let mut out = Vec::new();
    write_item(value, &mut out)?;
    Ok(out)
}

/// Lowercase hex of `bytes` — the form the shared test vectors are written in.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write the type head: the 3-bit major type plus the shortest argument that
/// fits (RFC 8949 §3, preferred serialization).
fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn write_item(value: &Cbor, out: &mut Vec<u8>) -> Result<(), DcborError> {
    match value {
        Cbor::Int(i) => {
            if *i >= 0 {
                write_head(0, *i as u64, out);
            } else {
                // Major type 1 encodes -1 - n, so -1 is argument 0.
                //
                // The subtraction is exact across the whole range, including
                // i64::MIN, where it lands on i64::MAX — the largest value it
                // can produce, and still an i64. So there is no overflow to
                // guard here, with or without overflow checks, and the Dart
                // twin computes the same thing. `integers_span_the_whole_i64_range`
                // pins both ends, in both languages.
                write_head(1, (-1 - *i) as u64, out);
            }
        }
        Cbor::Float(f) => {
            if !f.is_finite() {
                return Err(DcborError::NonFiniteFloat(*f));
            }
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Cbor::Bytes(b) => {
            write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Cbor::Text(s) => {
            let b = s.as_bytes();
            write_head(3, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Cbor::Array(items) => {
            write_head(4, items.len() as u64, out);
            for it in items {
                write_item(it, out)?;
            }
        }
        Cbor::Map(entries) => {
            // Sort by encoded key bytes, compared bytewise (RFC 8949 §4.2.1).
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kb = Vec::new();
                write_item(k, &mut kb)?;
                let mut vb = Vec::new();
                write_item(v, &mut vb)?;
                pairs.push((kb, vb));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for w in pairs.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(DcborError::DuplicateKey(to_hex(&w[0].0)));
                }
            }
            write_head(5, pairs.len() as u64, out);
            for (kb, vb) in pairs {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Cbor::Null => out.push(0xf6),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn hex_of(v: &Cbor) -> String {
        to_hex(&encode(v).unwrap())
    }

    fn json_hex(v: &serde_json::Value) -> String {
        hex_of(&Cbor::from_json(v).unwrap())
    }

    /// RFC 8949 Appendix A vectors for integers — shortest head that fits.
    #[test]
    fn integers_use_the_shortest_head() {
        assert_eq!(hex_of(&Cbor::Int(0)), "00");
        assert_eq!(hex_of(&Cbor::Int(1)), "01");
        assert_eq!(hex_of(&Cbor::Int(10)), "0a");
        assert_eq!(hex_of(&Cbor::Int(23)), "17");
        assert_eq!(hex_of(&Cbor::Int(24)), "1818");
        assert_eq!(hex_of(&Cbor::Int(255)), "18ff");
        assert_eq!(hex_of(&Cbor::Int(256)), "190100");
        assert_eq!(hex_of(&Cbor::Int(65535)), "19ffff");
        assert_eq!(hex_of(&Cbor::Int(1000000)), "1a000f4240");
        assert_eq!(hex_of(&Cbor::Int(1700000000000)), "1b0000018bcfe56800");
        assert_eq!(hex_of(&Cbor::Int(-1)), "20");
        assert_eq!(hex_of(&Cbor::Int(-24)), "37");
        assert_eq!(hex_of(&Cbor::Int(-25)), "3818");
        assert_eq!(hex_of(&Cbor::Int(-1000)), "3903e7");
    }

    /// The ends of the i64 range. Every integer in the envelope is an i64 an
    /// unauthenticated caller chooses (`clock_base`, `captured_at`, `t_ms`,
    /// `w`, `h`, `dataset.consent.ts`), so the encoder has to encode all of
    /// them — including `i64::MIN`, where computing the major-type-1 argument
    /// as `-1 - i` overflows: a panic with overflow checks on (the dev profile
    /// `cargo test` and a plain `cargo run` use), a wrapped encoding without.
    ///
    /// app/test/dcbor_test.dart asserts these same vectors against the Dart
    /// encoder, so a divergence at the boundary turns one of the two suites red.
    #[test]
    fn integers_span_the_whole_i64_range() {
        assert_eq!(hex_of(&Cbor::Int(4294967295)), "1affffffff");
        assert_eq!(hex_of(&Cbor::Int(4294967296)), "1b0000000100000000");
        assert_eq!(hex_of(&Cbor::Int(i64::MAX)), "1b7fffffffffffffff");
        assert_eq!(hex_of(&Cbor::Int(-4294967296)), "3affffffff");
        assert_eq!(hex_of(&Cbor::Int(-4294967297)), "3b0000000100000000");
        assert_eq!(hex_of(&Cbor::Int(i64::MIN + 1)), "3b7ffffffffffffffe");
        assert_eq!(hex_of(&Cbor::Int(i64::MIN)), "3b7fffffffffffffff");

        // The same two boundaries arriving through a JSON body, which is how a
        // caller actually reaches this encoder.
        assert_eq!(json_hex(&json!(i64::MAX)), "1b7fffffffffffffff");
        assert_eq!(json_hex(&json!(i64::MIN)), "3b7fffffffffffffff");
    }

    /// Floats are ALWAYS float64 — the deliberate deviation from §4.2.2.
    #[test]
    fn floats_are_always_float64() {
        assert_eq!(hex_of(&Cbor::Float(1.0)), "fb3ff0000000000000");
        assert_eq!(hex_of(&Cbor::Float(0.0)), "fb0000000000000000");
        assert_eq!(hex_of(&Cbor::Float(-0.0)), "fb8000000000000000");
        assert_eq!(hex_of(&Cbor::Float(-1.0)), "fbbff0000000000000");
        assert_eq!(hex_of(&Cbor::Float(0.5)), "fb3fe0000000000000");
        assert_eq!(hex_of(&Cbor::Float(0.9)), "fb3feccccccccccccd");
        assert_eq!(hex_of(&Cbor::Float(1.5)), "fb3ff8000000000000");
    }

    #[test]
    fn non_finite_floats_are_rejected() {
        // Matched rather than compared: NaN != NaN, so the error values would
        // never be equal even though they are the right variant.
        assert!(matches!(
            encode(&Cbor::Float(f64::NAN)),
            Err(DcborError::NonFiniteFloat(_))
        ));
        assert!(matches!(
            encode(&Cbor::Float(f64::NEG_INFINITY)),
            Err(DcborError::NonFiniteFloat(_))
        ));
        assert!(matches!(
            encode(&Cbor::Float(f64::INFINITY)),
            Err(DcborError::NonFiniteFloat(_))
        ));
    }

    #[test]
    fn simple_values_strings_and_arrays() {
        assert_eq!(hex_of(&Cbor::Bool(false)), "f4");
        assert_eq!(hex_of(&Cbor::Bool(true)), "f5");
        assert_eq!(hex_of(&Cbor::Null), "f6");
        assert_eq!(hex_of(&Cbor::Text(String::new())), "60");
        assert_eq!(hex_of(&Cbor::Text("a".into())), "6161");
        assert_eq!(hex_of(&Cbor::Text("IETF".into())), "6449455446");
        // Text length is the UTF-8 BYTE count, not the character count.
        assert_eq!(hex_of(&Cbor::Text("ü".into())), "62c3bc");
        assert_eq!(hex_of(&Cbor::Bytes(vec![])), "40");
        assert_eq!(hex_of(&Cbor::Bytes(vec![1, 2, 3, 4])), "4401020304");
        assert_eq!(hex_of(&Cbor::Array(vec![])), "80");
        assert_eq!(
            hex_of(&Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)])),
            "83010203"
        );
    }

    /// Map keys sort by ENCODED bytes, so shorter keys come first: "a" < "b" <
    /// "aa". Plain string ordering (what the canonical-JSON path uses) would put
    /// "aa" before "b" — this vector is what makes the difference visible.
    #[test]
    fn map_keys_sort_by_encoded_bytes_length_first() {
        let m = Cbor::Map(vec![
            (Cbor::Text("b".into()), Cbor::Int(1)),
            (Cbor::Text("aa".into()), Cbor::Int(3)),
            (Cbor::Text("a".into()), Cbor::Int(2)),
        ]);
        assert_eq!(hex_of(&m), "a361610261620162616103");

        // Entry order in the input must not matter.
        let reordered = Cbor::Map(vec![
            (Cbor::Text("aa".into()), Cbor::Int(3)),
            (Cbor::Text("a".into()), Cbor::Int(2)),
            (Cbor::Text("b".into()), Cbor::Int(1)),
        ]);
        assert_eq!(hex_of(&reordered), hex_of(&m));

        // Integer keys sort before text keys (major type 0 head < major type 3).
        let mixed = Cbor::Map(vec![
            (Cbor::Text("b".into()), Cbor::Int(2)),
            (Cbor::Int(1), Cbor::Text("a".into())),
        ]);
        assert_eq!(hex_of(&mixed), "a2016161616202");

        assert_eq!(hex_of(&Cbor::Map(vec![])), "a0");
    }

    #[test]
    fn duplicate_map_keys_are_rejected() {
        let m = Cbor::Map(vec![
            (Cbor::Text("a".into()), Cbor::Int(1)),
            (Cbor::Text("a".into()), Cbor::Int(2)),
        ]);
        assert_eq!(
            encode(&m).unwrap_err(),
            DcborError::DuplicateKey("6161".into())
        );
    }

    #[test]
    fn from_json_keeps_integers_and_floats_apart() {
        assert_eq!(json_hex(&json!(1)), "01");
        assert_eq!(json_hex(&json!(1.0)), "fb3ff0000000000000");
        assert_eq!(json_hex(&json!(-1)), "20");
        assert_eq!(json_hex(&json!(-1.0)), "fbbff0000000000000");
        assert_eq!(json_hex(&json!(null)), "f6");
        assert_eq!(
            json_hex(&json!({"a": 1, "b": [2, 3]})),
            "a26161016162820203"
        );
    }

    // -----------------------------------------------------------------------
    // THE SHARED VECTORS. The envelope, the encoded length and the hash all come
    // from vectors/belt/*.json, which backend/src/belt_envelope.rs and
    // app/test/belt_bundle_test.dart assert against too. Nothing here restates a
    // number: a vector this encoder could regenerate would only prove that the
    // encoder agrees with itself. See vectors/README.md.
    // -----------------------------------------------------------------------

    /// One shared vector: the envelope, the byte length of its canonical CBOR,
    /// and the sha256 of those bytes.
    fn shared_vector(name: &str) -> (serde_json::Value, usize, String) {
        let raw = match name {
            "base" => include_str!("../../vectors/belt/base.json"),
            "documented" => include_str!("../../vectors/belt/documented.json"),
            "boundary" => include_str!("../../vectors/belt/boundary.json"),
            "frame-bound" => include_str!("../../vectors/belt/frame-bound.json"),
            "depth-bound" => include_str!("../../vectors/belt/depth-bound.json"),
            other => panic!("no shared vector named {other}"),
        };
        let v: serde_json::Value = serde_json::from_str(raw).expect("vector parses");
        (
            v["envelope"].clone(),
            v["cbor_len"].as_u64().expect("cbor_len") as usize,
            v["sha256"].as_str().expect("sha256").to_string(),
        )
    }

    /// Every shared vector encodes to the length and hash the file records.
    ///
    /// One test over all five rather than one test each: they differ only in
    /// which fields the envelope carries, and a per-vector test tempts the next
    /// person to add a vector without a reader.
    #[test]
    fn every_shared_vector_encodes_to_its_recorded_bytes() {
        for name in ["base", "documented", "boundary", "frame-bound", "depth-bound"] {
            let (envelope, len, sha256) = shared_vector(name);
            let bytes = encode(&Cbor::from_json(&envelope).unwrap()).unwrap();
            assert_eq!(bytes.len(), len, "{name}: encoded length");
            assert_eq!(to_hex(&Sha256::digest(&bytes)), sha256, "{name}: sha256");
        }
    }
}
