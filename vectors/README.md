# Shared cross-language vectors

A vector is one capture envelope with the byte length of its deterministic CBOR
encoding and the sha256 of those bytes — a worked example with its answer
written down. Each file under `capture/` holds all three.

Three implementations in two languages are pinned to them:

- `core/src/dcbor.rs` — the Rust encoder, through `vaulet_core::vectors`
- `backend/src/capture_envelope.rs` — the typed envelope the issuer recomputes
  from, through the same module
- `app/test/capture_bundle_test.dart` — the Dart encoder **and** the bundle
  assembly, through this directory's `pubspec.yaml`

## Why they live in the core crate

They are the encoding's contract, and the encoding lives here. Every consumer
already depends on this crate, so each reaches the vectors through the one
dependency it has rather than through a relative path — and a relative path was
never going to survive the tree being split across repositories.

Both languages read **these files**, not a copy each. A copy per language is
precisely the failure a vector exists to catch.

## The rule

They used to be literals, copy-pasted: five hashes across thirteen places. In
one repository that is merely untidy — a `grep` finds all of them. Once they are
apart they drift, and each suite stays green while the wire breaks: the shape of
the three bugs `CLAUDE.md` records, where two implementations agreed with each
other and were both wrong.

A vector is only worth anything if it is an **independent witness**. So:

- **Never regenerate a vector from an implementation it checks.** If a change
  makes one fail, find out which side is wrong. A regenerated vector proves only
  that the code agrees with itself.
- A vector changes only when the *format* deliberately changes — and then
  `belt_version` changes with it, and the old vector is kept beside the new one
  rather than edited.

## Adding one

Add the envelope, its length and its hash from whichever implementation you did
*not* write the change in, then add its name to `ALL` in `src/vectors.rs` and to
`vectorNames` in `lib/vaulet_core.dart`. Both readers loop over those lists, so a
vector reaching neither cannot hide: a vector nobody asserts looks like coverage
and is none.
