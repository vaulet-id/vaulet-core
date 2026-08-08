# vaulet-core

The cryptographic core of [Vaulet](https://vaulet.id), a personal identity
wallet: keys, DIDs, verifiable credentials and presentations, deterministic
encoding, recovery, and the protocols built on top of them.

It is a library. It holds no state, opens no sockets, and — with the exceptions
noted below — knows nothing about the applications that call it. The same crate
runs inside an iOS wallet over FFI, inside an issuer as a normal dependency,
and is intended to run in a browser through WebAssembly.

```toml
[dependencies]
vaulet_core = { git = "https://github.com/vaulet-id/vaulet-core.git", rev = "…" }
```

Pin a revision. See [Stability](#stability).

## What is in here

| module | what it does |
|---|---|
| `keys` | P-256 identity keys, SLIP-0010 derivation, a storage-agnostic signer trait |
| `mnemonic` | BIP-39 encoding of the wallet secret |
| `shamir`, `recovery` | secret splitting, and passphrase-encrypted recovery files |
| `did` | `did:key`, `did:jwk` and `did:web` resolution |
| `credential` | SD-JWT verifiable credentials: issue, present, verify, selective disclosure |
| `protocol` | the OID4VCI / OID4VP flows the wallet and issuer speak |
| `statement` | a signed statement that says one thing to a program and another to the person signing it |
| `dcbor` | deterministic CBOR (RFC 8949 §4.2), the canonicalization every signature covers |
| `emrtd` | ePassport chip verification — Passive and Active Authentication (ICAO 9303) |
| `chat` | MLS group messaging inside DIDComm |
| `rule`, `mandate`, `vouching` | who may act for an organisation, and on what authority |

`vectors/` holds shared cross-language test vectors: one capture envelope with
the byte length of its deterministic CBOR encoding and the sha256 of those
bytes. The Rust encoder here and a Dart encoder elsewhere are both pinned to
them, so an envelope hashed on a phone recomputes to the same bytes on a server.
`vectors/README.md` states the one rule that makes them worth having.

## Stability

**There is no API stability promise yet.** The public surface changes most
weeks; `chat` in particular is moving. Pin a revision and read the diff before
moving it.

The crate is public because its consumers are separate repositories and a
private dependency makes every build a credentials problem. Public is not the
same as released: there is no version on crates.io and no deprecation policy.

## Known debt

Two things in here do not belong in a library that knows nothing about its
callers, and are recorded rather than hidden:

- **`lib.rs` carries the wallet's FFI facade** — 22 `wallet_*` functions shaped
  around one application's screens, nine of which take a `storage_dir` and read
  and write real files. They are moving to the application that needs them.
- **Some templates carry Thai wording.** The statement layer's whole point is
  that a person signs a sentence they can read, so the wording is bilingual data
  rather than a hardcoded string — but a country's legal phrasing is product,
  not protocol, and it is leaving the crate with the facade.

Neither affects a consumer that does not call them. Both are why the filesystem
functions fail to compile for `wasm32-unknown-unknown` today.

## Building

```
cargo test
```

The `test-fixtures` feature exposes `emrtd::fixtures` — synthetic CSCA, DSC and
EF.SOD builders — so a downstream crate can exercise Passive Authentication
without any real passport. **There is no real chip data in this repository**;
every passport fixture is constructed from generated keys.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
