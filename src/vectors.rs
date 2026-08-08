//! The shared cross-language capture vectors, embedded at compile time.
//!
//! A vector is one capture envelope with the byte length of its deterministic
//! CBOR encoding and the sha256 of those bytes — a worked example with its
//! answer written down. Three implementations in two languages are pinned to
//! them: the encoder in [`crate::dcbor`], the typed envelope the issuer
//! recomputes from, and the Dart encoder and bundle assembly in the wallet.
//!
//! They live here, in the crate that owns the encoding, because they are that
//! encoding's contract. Every consumer therefore reaches them through the one
//! dependency it already has, and no repository needs the files sitting at a
//! fixed relative path.
//!
//! The Dart side reads the same `vectors/capture/*.json` through this directory's
//! `pubspec.yaml`, so a single set of files backs both languages rather than a
//! copy in each — a copy per language being precisely the failure a vector
//! exists to catch.
//!
//! See `core/vectors/README.md` for the rule that makes them worth having: a
//! vector is never regenerated from an implementation it checks.

/// Every vector, by name, as the raw JSON recorded in `vectors/capture/`.
///
/// A consumer loops over this rather than naming vectors one at a time. A
/// vector added to the directory but reaching nobody's assertions would look
/// like coverage and be none; iterating makes that impossible to do quietly.
pub const ALL: &[(&str, &str)] = &[
    ("base", include_str!("../vectors/capture/base.json")),
    ("documented", include_str!("../vectors/capture/documented.json")),
    ("boundary", include_str!("../vectors/capture/boundary.json")),
    ("frame-bound", include_str!("../vectors/capture/frame-bound.json")),
    ("depth-bound", include_str!("../vectors/capture/depth-bound.json")),
];

/// One vector's raw JSON.
///
/// Panics on an unknown name: every caller is a test, and a typo there should
/// stop the run rather than quietly skip an assertion.
pub fn raw(name: &str) -> &'static str {
    ALL.iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no shared vector named {name}"))
        .1
}
