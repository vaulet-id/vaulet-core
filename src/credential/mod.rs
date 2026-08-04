//! Credential layer (PLAN.md D2, D13).
//! Stored format-agnostic: SD-JWT VC first, dual-rail with BBS+ later (Z3).
//!
//! SD-JWT VC / KB-JWT mechanics run on `sd-jwt-payload` (ADR 0004) with
//! [`SoftwareKey`] plugged in as the external ES256 `JwsSigner` — the crate
//! never owns key material, which is the seam the future `HardwareSigner`
//! (Secure Enclave/StrongBox) path reuses unchanged.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sd_jwt_payload::{
    Hasher, JsonObject, JwsSigner, KeyBindingJwt, RequiredKeyBinding, SdJwt, SdJwtBuilder,
    Sha256Hasher,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::Read as _;

use crate::did::{signing_jwk_for_kid, DidResolver};
use crate::keys::software::SoftwareKey;
use crate::{CoreError, Result};

/// One credential in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    /// e.g. "sd-jwt-vc" — never hardcode format-specific logic outside this module.
    pub format: String,
    /// Raw credential (encrypted at rest by the storage layer).
    pub raw: String,
    /// Display data cached for fast rendering (title, issuer, color, logo).
    pub display: CredentialDisplay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub title: String,
    pub issuer_name: String,
    pub issuer_did: String,
    /// Hex like "#0E7C66" — from the issuer's credential template.
    pub color: Option<String>,
}

/// Display fields the issuer's OID4VCI metadata carries but the credential body
/// does not (title, human issuer name, card color). Dart pulls these from the
/// credential-configuration display block and hands them to [`ingest`]; each is
/// optional and falls back to a value derived from the trusted `vct`/`iss`.
#[derive(Debug, Clone, Default)]
pub struct DisplayHints {
    pub title: Option<String>,
    pub issuer_name: Option<String>,
    pub color: Option<String>,
}

/// Input to [`issue`]. Splits the two claim rails of ADR 0003 / PLAN §3:
/// `disclosable` are per-claim selectively-disclosable (Z1), `visible` are
/// issuer-supplied always-visible derived claims (Z2, e.g. `is_current_employee`).
#[derive(Debug, Clone)]
pub struct IssueParams {
    /// Credential type (`vct`), e.g. `https://vaulet.example/credential/employee-badge`.
    pub vct: String,
    /// Issuer identifier (`iss`), e.g. a `did:web`.
    pub iss: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expiry (`exp`), seconds since the Unix epoch.
    pub exp: i64,
    /// Holder public JWK, embedded as `cnf.jwk` to bind the credential.
    pub holder_jwk: Value,
    /// Z1: selectively-disclosable claims, name -> value.
    pub disclosable: Map<String, Value>,
    /// Z2: always-visible derived claims, name -> value.
    pub visible: Map<String, Value>,
}

/// Result of [`verify`]: the trusted, resolved view of a credential.
#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    /// Credential type (`vct`).
    pub vct: String,
    /// Issuer identifier (`iss`).
    pub issuer: String,
    /// Content claims that were disclosed (Z1 disclosed subset + Z2 visible);
    /// registered JWT claims (`iss`/`vct`/`iat`/`exp`/`cnf`) are stripped out.
    pub claims: Map<String, Value>,
    /// Holder public JWK from `cnf.jwk` — the key a KB-JWT must be signed with.
    pub holder_jwk: Value,
    /// Expiry (`exp`), seconds since the Unix epoch.
    pub exp: i64,
}

/// Whatever holds the key that signs a credential.
///
/// A trait rather than [`SoftwareKey`] because the key that matters most is the
/// one nobody can hold: an organisation's key lives in an HSM and is used by
/// asking it to sign (ADR 0020). Everything above this line is the same either
/// way — the signature is ES256 over the same bytes, and this crate never sees
/// a private scalar in either case (ADR 0004).
/// `Sync` because the SD-JWT builder signs inside an async block that has to be
/// sendable; a signer reached from several requests must be shareable anyway.
pub trait Es256Signer: Sync {
    fn sign_es256(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

impl Es256Signer for SoftwareKey {
    fn sign_es256(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.sign(payload)
    }
}

/// Adapts an [`Es256Signer`] to `sd-jwt-payload`'s external signer. `sign`
/// returns the FULL compact JWS, so the crate only ever receives a finished
/// signature.
struct ExternalEs256Signer<'a>(&'a dyn Es256Signer);

#[async_trait::async_trait]
impl JwsSigner for ExternalEs256Signer<'_> {
    type Error = String;
    async fn sign(
        &self,
        header: &JsonObject,
        payload: &JsonObject,
    ) -> std::result::Result<Vec<u8>, String> {
        let h = B64.encode(serde_json::to_vec(header).map_err(|e| e.to_string())?);
        let p = B64.encode(serde_json::to_vec(payload).map_err(|e| e.to_string())?);
        let signing_input = format!("{h}.{p}");
        let sig = self
            .0
            .sign_es256(signing_input.as_bytes())
            .map_err(|e| e.to_string())?;
        let s = B64.encode(sig);
        Ok(format!("{signing_input}.{s}").into_bytes())
    }
}

/// Issue an SD-JWT VC. Produces the compact issuer-signed SD-JWT with every
/// disclosure attached (no KB-JWT — that is added at presentation time).
///
/// Sets `iss`, `vct`, `iat`, `exp` and `cnf.jwk` (holder binding); makes each
/// `disclosable` claim selectively-disclosable (Z1) and leaves each `visible`
/// claim in the clear (Z2).
pub fn issue(params: IssueParams, issuer_key: &dyn Es256Signer) -> Result<String> {
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(params.iss));
    claims.insert("vct".into(), Value::String(params.vct));
    claims.insert("iat".into(), Value::Number(params.iat.into()));
    claims.insert("exp".into(), Value::Number(params.exp.into()));
    for (k, v) in params.visible {
        claims.insert(k, v);
    }
    let disclosable_keys: Vec<String> = params.disclosable.keys().cloned().collect();
    for (k, v) in params.disclosable {
        claims.insert(k, v);
    }

    let holder_jwk: JsonObject = serde_json::from_value(params.holder_jwk)
        .map_err(|e| CoreError::Credential(format!("holder jwk not an object: {e}")))?;

    let mut builder = SdJwtBuilder::new(Value::Object(claims))
        .map_err(|e| CoreError::Credential(format!("sd-jwt builder: {e}")))?;
    for key in &disclosable_keys {
        builder = builder
            .make_concealable(&format!("/{key}"))
            .map_err(|e| CoreError::Credential(format!("make_concealable /{key}: {e}")))?;
    }
    let signer = ExternalEs256Signer(issuer_key);
    let sd_jwt = pollster::block_on(
        builder
            .require_key_binding(RequiredKeyBinding::Jwk(holder_jwk))
            .finish(&signer, "ES256"),
    )
    .map_err(|e| CoreError::Credential(format!("sign sd-jwt: {e}")))?;

    Ok(sd_jwt.presentation())
}

/// Verify an issuer-signed SD-JWT: ES256 signature against `issuer_jwk`, `exp`
/// not in the past (`exp >= now`), then recover the disclosed claims.
///
/// `now` is injected (seconds since the Unix epoch) so the caller owns the
/// clock — the FFI core stays side-effect free.
pub fn verify(sd_jwt: &str, issuer_jwk: &Value, now: i64) -> Result<VerifiedCredential> {
    let issuer_vk = verifying_key_from_jwk(issuer_jwk)?;

    // (1) Issuer signature over the SD-JWT body (the JWT part before the first '~').
    let jwt_part = sd_jwt
        .split('~')
        .next()
        .ok_or_else(|| CoreError::Credential("empty sd-jwt".into()))?;
    let payload = verify_compact_es256(jwt_part, &issuer_vk)?;

    // (2) Expiry.
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| CoreError::Credential("missing exp".into()))?;
    if exp < now {
        return Err(CoreError::Credential("credential expired".into()));
    }

    // (3) Recover disclosed claims.
    let hasher = Sha256Hasher::new();
    let parsed =
        SdJwt::parse(sd_jwt).map_err(|e| CoreError::Credential(format!("parse sd-jwt: {e}")))?;
    let disclosed = parsed
        .into_disclosed_object(&hasher)
        .map_err(|e| CoreError::Credential(format!("disclose: {e}")))?;

    let vct = payload
        .get("vct")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Credential("missing vct".into()))?
        .to_string();
    let issuer = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Credential("missing iss".into()))?
        .to_string();
    let holder_jwk = payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .cloned()
        .ok_or_else(|| CoreError::Credential("missing cnf.jwk".into()))?;

    // Content claims only: drop the registered JWT claims.
    let mut claims: Map<String, Value> = disclosed.into_iter().collect();
    for reg in ["iss", "vct", "iat", "exp", "cnf"] {
        claims.remove(reg);
    }

    Ok(VerifiedCredential {
        vct,
        issuer,
        claims,
        holder_jwk,
        exp,
    })
}

/// Build a presentation from a stored issuer-signed SD-JWT: keep only the named
/// disclosures (Z1 subset), then append a KB-JWT signed by the holder key with
/// `aud`, `nonce`, `iat` and the correct `sd_hash` binding it to this exact
/// presentation.
pub fn present(
    stored_sd_jwt: &str,
    disclose: &[String],
    audience: &str,
    nonce: &str,
    holder_key: &SoftwareKey,
    iat: i64,
) -> Result<String> {
    let hasher = Sha256Hasher::new();

    let parsed = SdJwt::parse(stored_sd_jwt)
        .map_err(|e| CoreError::Credential(format!("parse sd-jwt: {e}")))?;
    let mut builder = parsed
        .into_presentation(&hasher)
        .map_err(|e| CoreError::Credential(format!("into_presentation: {e}")))?
        .conceal_all();
    for name in disclose {
        builder = builder
            .disclose(&format!("/{name}"))
            .map_err(|e| CoreError::Credential(format!("disclose /{name}: {e}")))?;
    }
    let (presented, _removed) = builder.finish();

    let signer = ExternalEs256Signer(holder_key);
    let kb_jwt: KeyBindingJwt = pollster::block_on(
        KeyBindingJwt::builder()
            .nonce(nonce)
            .aud(audience)
            .iat(iat)
            .finish(&presented, &hasher, "ES256", &signer),
    )
    .map_err(|e| CoreError::Credential(format!("sign kb-jwt: {e}")))?;

    let mut with_kb = presented;
    with_kb.attach_key_binding_jwt(kb_jwt);
    Ok(with_kb.presentation())
}

/// Verify a KB-JWT-bearing presentation: issuer signature + `exp`, then the
/// holder's KB-JWT against the credential's own `cnf.jwk`, checking `aud`,
/// `nonce` and `sd_hash`. Returns the disclosed view on success.
///
/// Sprint 1 keeps this beside [`verify`] because presentation verification is
/// what the Sprint 3 verifier web page needs; the wire/DCQL layer lands later.
pub fn verify_presentation(
    presentation: &str,
    issuer_jwk: &Value,
    audience: &str,
    nonce: &str,
    now: i64,
) -> Result<VerifiedCredential> {
    // Issuer signature + exp + claims (shares the credential path).
    let verified = verify(presentation, issuer_jwk, now)?;

    let hasher = Sha256Hasher::new();
    let parsed = SdJwt::parse(presentation)
        .map_err(|e| CoreError::Credential(format!("parse presentation: {e}")))?;
    let kb = parsed
        .key_binding_jwt()
        .ok_or_else(|| CoreError::Credential("no KB-JWT attached".into()))?;

    // KB-JWT must be signed by the holder key advertised in cnf.jwk.
    let holder_vk = verifying_key_from_jwk(&verified.holder_jwk)?;
    let kb_payload = verify_compact_es256(&kb.to_string(), &holder_vk)?;

    if kb_payload.get("aud").and_then(Value::as_str) != Some(audience) {
        return Err(CoreError::Credential("KB-JWT audience mismatch".into()));
    }
    if kb_payload.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err(CoreError::Credential("KB-JWT nonce mismatch".into()));
    }

    // sd_hash binds the KB-JWT to THIS exact presentation body.
    let body = presentation
        .rsplit_once('~')
        .map(|(a, _)| a)
        .ok_or_else(|| CoreError::Credential("malformed presentation".into()))?;
    let expected_sd_hash = hasher.encoded_digest(&format!("{body}~"));
    if kb_payload.get("sd_hash") != Some(&Value::String(expected_sd_hash)) {
        return Err(CoreError::Credential("KB-JWT sd_hash mismatch".into()));
    }

    Ok(verified)
}

/// Verify an issuer-signed SD-JWT after resolving the issuer's `did:web` to its
/// signing JWK. Chains [`DidResolver`] (fetch injected by the host — the backend
/// or a test) → [`signing_jwk_for_kid`] → [`verify`], so the caller never has to
/// hand-pick the issuer key. The issuer identifier is read from the SD-JWT `iss`.
///
/// The FFI wallet path uses [`verify_with_did_document`] instead (Dart fetches
/// `did.json`, the cdylib stays network-free); this variant is for hosts that
/// own a resolver, e.g. the axum issuer/verifier.
pub fn verify_via_resolver<R: DidResolver>(
    sd_jwt: &str,
    resolver: &R,
    now: i64,
) -> Result<VerifiedCredential> {
    let iss = extract_iss(sd_jwt)?;
    let doc = resolver.resolve(&iss)?;
    verify_with_did_document(sd_jwt, &doc, now)
}

/// Where a credential says its revocation status lives, and which bit in it —
/// or None when it carries no status at all.
///
/// Pure, because the fetch belongs to whoever has a network (ADR 0004). The
/// caller reads this, fetches that URL, and hands the result to
/// [`status_is_revoked`].
pub fn status_reference(sd_jwt: &str) -> Result<Option<(String, u64)>> {
    let jwt_part = sd_jwt
        .split('~')
        .next()
        .ok_or_else(|| CoreError::Credential("empty sd-jwt".into()))?;
    let parts: Vec<&str> = jwt_part.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::Credential("not a 3-part JWS".into()));
    }
    let payload: Value = serde_json::from_slice(
        &B64.decode(parts[1])
            .map_err(|e| CoreError::Credential(format!("payload b64: {e}")))?,
    )
    .map_err(|e| CoreError::Credential(format!("payload json: {e}")))?;
    let Some(sl) = payload.get("status").and_then(|s| s.get("status_list")) else {
        return Ok(None);
    };
    match (
        sl.get("uri").and_then(Value::as_str),
        sl.get("idx").and_then(Value::as_u64),
    ) {
        (Some(uri), Some(idx)) => Ok(Some((uri.to_string(), idx))),
        // Half a reference is not a reference. Treating it as "no status" would
        // quietly accept a credential whose issuer meant it to be revocable.
        _ => Err(CoreError::Credential("malformed status reference".into())),
    }
}

/// Whether `idx` is revoked according to a fetched Token Status List token.
///
/// `list_jwt` is the `statuslist+jwt` served at the credential's status uri and
/// `issuer_jwk` is the key that signed the CREDENTIAL — the two must be the
/// same issuer, or anyone could serve a list saying whatever they liked about
/// somebody else's credentials.
pub fn status_is_revoked(
    list_jwt: &str,
    issuer_jwk: &Value,
    idx: u64,
    expected_uri: &str,
) -> Result<bool> {
    let vk = verifying_key_from_jwk(issuer_jwk)?;
    let payload = verify_compact_es256(list_jwt, &vk)?;

    // The list must say it is the list we went looking for. Without this, a
    // list legitimately signed by the issuer for one purpose could be served in
    // place of another.
    let sub = payload
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Credential("status list has no sub".into()))?;
    if sub != expected_uri {
        return Err(CoreError::Credential(
            "status list is not the one the credential names".into(),
        ));
    }

    let sl = payload
        .get("status_list")
        .ok_or_else(|| CoreError::Credential("not a status list".into()))?;
    let bits = sl.get("bits").and_then(Value::as_u64).unwrap_or(1);
    if bits != 1 {
        // 2, 4 and 8 are legal and mean more states than valid/revoked. Reading
        // one as if it were one bit would report the wrong state rather than no
        // state, so it is refused until something needs it.
        return Err(CoreError::Credential(
            "only 1-bit status lists are understood".into(),
        ));
    }
    let encoded = sl
        .get("lst")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Credential("status list has no lst".into()))?;

    let compressed = B64
        .decode(encoded)
        .map_err(|_| CoreError::Credential("status list is not base64url".into()))?;
    let mut bytes = Vec::new();
    flate2::read::ZlibDecoder::new(&compressed[..])
        .read_to_end(&mut bytes)
        .map_err(|_| CoreError::Credential("status list is not deflate-compressed".into()))?;

    let byte = (idx / 8) as usize;
    // Past the end is not "valid": the issuer meant this index to be in there.
    let b = bytes
        .get(byte)
        .ok_or_else(|| CoreError::Credential("status index is past the end of the list".into()))?;
    Ok(b >> (idx % 8) & 1 == 1)
}

/// Verify an issuer-signed SD-JWT against an already-resolved DID document.
///
/// Selects the issuer key by the SD-JWT header `kid` (falling back to the first
/// `verificationMethod` when the header omits `kid`, as our own [`issue`] does),
/// then delegates to [`verify`]. Network-free: the caller supplies `did_doc`
/// (Dart fetches it over HTTP), which is the seam keeping the FFI sync (ADR 0004).
pub fn verify_with_did_document(
    sd_jwt: &str,
    did_doc: &Value,
    now: i64,
) -> Result<VerifiedCredential> {
    let issuer_jwk = issuer_jwk_from_did_doc(sd_jwt, did_doc)?;
    verify(sd_jwt, &issuer_jwk, now)
}

/// Turn a received credential-response SD-JWT into a [`StoredCredential`], with
/// the issuer key resolved via a [`DidResolver`] (fetch injected). Convenience
/// wrapper over [`verify_via_resolver`] + [`build_stored`] for resolver-owning
/// hosts; the FFI wallet uses [`ingest_with_did_document`].
pub fn ingest_via_resolver<R: DidResolver>(
    id: impl Into<String>,
    sd_jwt: &str,
    resolver: &R,
    now: i64,
    hints: DisplayHints,
) -> Result<StoredCredential> {
    let verified = verify_via_resolver(sd_jwt, resolver, now)?;
    Ok(build_stored(id.into(), sd_jwt, &verified, hints))
}

/// Turn a received credential-response SD-JWT into a [`StoredCredential`]:
/// verify it against the issuer's already-resolved `did_doc`, then cache a
/// [`CredentialDisplay`] built from the trusted `vct`/`iss` (overlaid with any
/// [`DisplayHints`] Dart carried from issuer metadata). `id` is a caller-owned
/// stable identifier for the wallet store. This is the wallet FFI ingest path.
pub fn ingest_with_did_document(
    id: impl Into<String>,
    sd_jwt: &str,
    did_doc: &Value,
    now: i64,
    hints: DisplayHints,
    pinned: &[String],
) -> Result<StoredCredential> {
    let issuer_jwk = issuer_jwk_from_did_doc(sd_jwt, did_doc)?;
    // Issuer key pinning (SSI trust registry, ADR 0008 / SECURITY-REVIEW): when
    // the caller pins expected key thumbprint(s) for this issuer, the key that
    // actually verifies the credential must be one of them. This anchors trust
    // in the DID's KEY, not the TLS transport — so a MITM/rogue-CA serving a
    // fake did.json (even for a did:web issuer) is rejected. Empty = not pinned.
    if !pinned.is_empty() {
        let tp = jwk_thumbprint(&issuer_jwk)?;
        if !pinned.iter().any(|p| p == &tp) {
            return Err(CoreError::Credential(
                "issuer signing key does not match the pinned key for this issuer".into(),
            ));
        }
    }
    let verified = verify(sd_jwt, &issuer_jwk, now)?;
    Ok(build_stored(id.into(), sd_jwt, &verified, hints))
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url) for an EC public key — the
/// stable key identifier the issuer trust registry pins. Only the required
/// members (`crv`, `kty`, `x`, `y`) in lexicographic order, no whitespace.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    let member = |k: &str| {
        jwk.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::Credential(format!("jwk missing {k} for thumbprint")))
    };
    let kty = member("kty")?;
    if kty != "EC" {
        return Err(CoreError::Credential(
            "thumbprint supports EC keys only".into(),
        ));
    }
    let (crv, x, y) = (member("crv")?, member("x")?, member("y")?);
    let canonical = format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#);
    Ok(B64.encode(Sha256::digest(canonical.as_bytes())))
}

/// Assemble a [`StoredCredential`] from a verified view. Display falls back to a
/// title derived from the `vct` and the raw `iss` for the issuer name when the
/// hints don't provide friendlier values.
fn build_stored(
    id: String,
    sd_jwt: &str,
    verified: &VerifiedCredential,
    hints: DisplayHints,
) -> StoredCredential {
    let title = hints.title.unwrap_or_else(|| title_from_vct(&verified.vct));
    let issuer_name = hints.issuer_name.unwrap_or_else(|| verified.issuer.clone());
    StoredCredential {
        id,
        format: "sd-jwt-vc".to_string(),
        raw: sd_jwt.to_string(),
        display: CredentialDisplay {
            title,
            issuer_name,
            issuer_did: verified.issuer.clone(),
            color: hints.color,
        },
    }
}

/// Derive a human title from a `vct`: take the last path/`:` segment and turn
/// `-`/`_` separators into spaces (e.g.
/// `https://vaulet.example/credential/employee-badge` -> `employee badge`).
fn title_from_vct(vct: &str) -> String {
    let last = vct.rsplit(['/', ':']).next().unwrap_or(vct);
    let cleaned = last.replace(['-', '_'], " ");
    if cleaned.is_empty() {
        vct.to_string()
    } else {
        cleaned
    }
}

/// Pick the issuer signing JWK out of a resolved DID document for the key named
/// in the SD-JWT JOSE header `kid`; when the header omits `kid` (our [`issue`]
/// path), fall back to the first `verificationMethod`'s `publicKeyJwk`.
fn issuer_jwk_from_did_doc(sd_jwt: &str, did_doc: &Value) -> Result<Value> {
    let header = decode_jwt_header(sd_jwt)?;
    if let Some(kid) = header.get("kid").and_then(Value::as_str) {
        return signing_jwk_for_kid(did_doc, kid);
    }
    did_doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| methods.first())
        .and_then(|m| m.get("publicKeyJwk"))
        .cloned()
        .ok_or_else(|| {
            CoreError::Credential("did doc has no verificationMethod to verify with".into())
        })
}

/// Decode the JOSE header (first `.`-segment of the JWT part before the first
/// `~`) of an SD-JWT to JSON, without verifying anything.
fn decode_jwt_header(sd_jwt: &str) -> Result<Value> {
    let jwt = sd_jwt.split('~').next().unwrap_or_default();
    let header_b64 = jwt
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CoreError::Credential("empty sd-jwt header".into()))?;
    let bytes = B64
        .decode(header_b64)
        .map_err(|e| CoreError::Credential(format!("header b64: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| CoreError::Credential(format!("header json: {e}")))
}

/// Read the `iss` (issuer identifier, a `did:web` in M1) from an SD-JWT payload
/// without verifying the signature — used only to know which DID to resolve; the
/// signature is checked afterwards in [`verify`].
fn extract_iss(sd_jwt: &str) -> Result<String> {
    let jwt = sd_jwt.split('~').next().unwrap_or_default();
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::Credential("not a 3-part JWS".into()));
    }
    let payload = B64
        .decode(parts[1])
        .map_err(|e| CoreError::Credential(format!("payload b64: {e}")))?;
    let value: Value = serde_json::from_slice(&payload)
        .map_err(|e| CoreError::Credential(format!("payload json: {e}")))?;
    value
        .get("iss")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| CoreError::Credential("missing iss".into()))
}

/// Build a p256 ES256 verifying key from a public JWK.
pub(crate) fn verifying_key_from_jwk(jwk: &Value) -> Result<VerifyingKey> {
    let public = p256::PublicKey::from_jwk_str(&jwk.to_string())
        .map_err(|e| CoreError::Credential(format!("issuer jwk parse: {e}")))?;
    Ok(VerifyingKey::from(&public))
}

/// Verify a compact ES256 JWS and return its decoded JSON payload.
fn verify_compact_es256(jws: &str, vk: &VerifyingKey) -> Result<Value> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::Credential("not a 3-part JWS".into()));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = B64
        .decode(parts[2])
        .map_err(|e| CoreError::Credential(format!("bad signature b64: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| CoreError::Credential(format!("bad signature: {e}")))?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| CoreError::Credential("issuer signature invalid".into()))?;
    let payload = B64
        .decode(parts[1])
        .map_err(|e| CoreError::Credential(format!("bad payload b64: {e}")))?;
    serde_json::from_slice(&payload)
        .map_err(|e| CoreError::Credential(format!("payload not json: {e}")))
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use crate::keys::software::SoftwareKey;
    use std::io::Write as _;

    /// Build a status list token the way the issuer does.
    fn list_token(key: &SoftwareKey, sub: &str, revoked: &[u64], bits: u64) -> String {
        let mut bytes = vec![0u8; 512];
        for idx in revoked {
            bytes[(*idx / 8) as usize] |= 1 << (idx % 8);
        }
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&bytes).unwrap();
        let lst = B64.encode(enc.finish().unwrap());

        let header = serde_json::json!({"alg": "ES256", "typ": "statuslist+jwt"});
        let payload = serde_json::json!({
            "iss": "did:web:example",
            "sub": sub,
            "iat": 1,
            "status_list": { "bits": bits, "lst": lst },
        });
        let h = B64.encode(serde_json::to_vec(&header).unwrap());
        let p = B64.encode(serde_json::to_vec(&payload).unwrap());
        let signing = format!("{h}.{p}");
        let sig = key.sign(signing.as_bytes()).unwrap();
        format!("{signing}.{}", B64.encode(sig))
    }

    const URI: &str = "https://api.example/status/1";

    #[test]
    fn a_revoked_bit_reads_revoked_and_its_neighbours_do_not() {
        let key = SoftwareKey::generate();
        let jwk = key.public_jwk().unwrap();
        let token = list_token(&key, URI, &[9], 1);

        assert!(status_is_revoked(&token, &jwk, 9, URI).unwrap());
        assert!(!status_is_revoked(&token, &jwk, 8, URI).unwrap());
        assert!(!status_is_revoked(&token, &jwk, 10, URI).unwrap());
    }

    /// A list signed by somebody else says nothing about this issuer's
    /// credentials — otherwise anyone could publish a list revoking everybody.
    #[test]
    fn a_list_signed_by_the_wrong_key_is_refused() {
        let issuer = SoftwareKey::generate();
        let stranger = SoftwareKey::generate();
        let token = list_token(&stranger, URI, &[9], 1);
        assert!(status_is_revoked(&token, &issuer.public_jwk().unwrap(), 9, URI).is_err());
    }

    /// And a list the issuer really did sign, served in place of the one the
    /// credential names, is still the wrong list.
    #[test]
    fn a_list_for_a_different_uri_is_refused() {
        let key = SoftwareKey::generate();
        let token = list_token(&key, "https://api.example/status/2", &[9], 1);
        assert!(status_is_revoked(&token, &key.public_jwk().unwrap(), 9, URI).is_err());
    }

    /// Past the end is not "valid": the issuer put this index in a list, so a
    /// list too short to hold it is a list we cannot answer from.
    #[test]
    fn an_index_past_the_end_is_an_error_not_a_pass() {
        let key = SoftwareKey::generate();
        let token = list_token(&key, URI, &[], 1);
        assert!(status_is_revoked(&token, &key.public_jwk().unwrap(), 99_999, URI).is_err());
    }

    /// Wider lists are legal and mean more states. Reading one as a single bit
    /// would report the wrong state rather than no state.
    #[test]
    fn a_wider_list_is_refused_rather_than_misread() {
        let key = SoftwareKey::generate();
        let token = list_token(&key, URI, &[9], 2);
        assert!(status_is_revoked(&token, &key.public_jwk().unwrap(), 9, URI).is_err());
    }

    /// Half a reference is not a reference — a credential its issuer meant to
    /// be revocable must not be read as one that carries no status.
    #[test]
    fn a_malformed_status_reference_is_an_error_not_an_absence() {
        let key = SoftwareKey::generate();
        let params = IssueParams {
            vct: "https://example/credential/x".into(),
            iss: "did:web:example".into(),
            iat: 1,
            exp: 9_999_999_999,
            holder_jwk: SoftwareKey::generate().public_jwk().unwrap(),
            disclosable: Map::new(),
            visible: serde_json::from_value(serde_json::json!({
                "status": { "status_list": { "uri": URI } }
            }))
            .unwrap(),
        };
        let sd_jwt = issue(params, &key).unwrap();
        assert!(status_reference(&sd_jwt).is_err());
    }

    #[test]
    fn a_credential_with_no_status_has_no_reference() {
        let key = SoftwareKey::generate();
        let params = IssueParams {
            vct: "https://example/credential/x".into(),
            iss: "did:web:example".into(),
            iat: 1,
            exp: 9_999_999_999,
            holder_jwk: SoftwareKey::generate().public_jwk().unwrap(),
            disclosable: Map::new(),
            visible: Map::new(),
        };
        let sd_jwt = issue(params, &key).unwrap();
        assert_eq!(status_reference(&sd_jwt).unwrap(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOUR: i64 = 3600;

    fn sample_params(holder: &SoftwareKey) -> IssueParams {
        let mut disclosable = Map::new();
        disclosable.insert("given_name".into(), json!("Somchai"));
        disclosable.insert("family_name".into(), json!("Prasit"));
        disclosable.insert("department".into(), json!("Engineering"));
        let mut visible = Map::new();
        visible.insert("is_current_employee".into(), json!(true));

        IssueParams {
            vct: "https://vaulet.example/credential/employee-badge".into(),
            iss: "did:web:issuer.example".into(),
            iat: 1_700_000_000,
            exp: 1_700_000_000 + 365 * 24 * HOUR,
            holder_jwk: holder.public_jwk().unwrap(),
            disclosable,
            visible,
        }
    }

    #[test]
    fn self_issue_verify_roundtrip() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        let v = verify(&sd_jwt, &issuer.public_jwk().unwrap(), 1_700_000_000).unwrap();
        assert_eq!(v.vct, "https://vaulet.example/credential/employee-badge");
        assert_eq!(v.issuer, "did:web:issuer.example");
        // Z1 disclosed + Z2 visible are all present in the issuer-signed form.
        assert_eq!(v.claims["given_name"], json!("Somchai"));
        assert_eq!(v.claims["family_name"], json!("Prasit"));
        assert_eq!(v.claims["department"], json!("Engineering"));
        assert_eq!(v.claims["is_current_employee"], json!(true));
        // Holder binding survived.
        assert_eq!(v.holder_jwk["crv"], json!("P-256"));
    }

    #[test]
    fn wrong_issuer_key_fails() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let attacker = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        assert!(verify(&sd_jwt, &attacker.public_jwk().unwrap(), 1_700_000_000).is_err());
    }

    #[test]
    fn expired_credential_fails() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        // now past exp.
        let now = 1_700_000_000 + 366 * 24 * HOUR;
        assert!(verify(&sd_jwt, &issuer.public_jwk().unwrap(), now).is_err());
    }

    #[test]
    fn tampered_sd_jwt_fails() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        // Flip a character in the JWT payload segment.
        let (jwt, rest) = sd_jwt.split_once('~').unwrap();
        let mut segs: Vec<&str> = jwt.split('.').collect();
        let mut payload = segs[1].to_string();
        let last = payload.pop().unwrap();
        payload.push(if last == 'A' { 'B' } else { 'A' });
        segs[1] = &payload;
        let tampered = format!("{}~{}", segs.join("."), rest);

        assert!(verify(&tampered, &issuer.public_jwk().unwrap(), 1_700_000_000).is_err());
    }

    #[test]
    fn selective_disclosure_hides_withheld_claims() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        // Present only given_name + department; family_name withheld.
        let presentation = present(
            &sd_jwt,
            &["given_name".into(), "department".into()],
            "https://verifier.example",
            "n-0S6_WzA2Mj",
            &holder,
            1_700_000_100,
        )
        .unwrap();

        let v = verify_presentation(
            &presentation,
            &issuer.public_jwk().unwrap(),
            "https://verifier.example",
            "n-0S6_WzA2Mj",
            1_700_000_200,
        )
        .unwrap();

        assert_eq!(v.claims["given_name"], json!("Somchai"));
        assert_eq!(v.claims["department"], json!("Engineering"));
        assert!(!v.claims.contains_key("family_name")); // withheld -> absent
                                                        // Z2 always-visible claim survives selective disclosure.
        assert_eq!(v.claims["is_current_employee"], json!(true));
    }

    #[test]
    fn kb_jwt_wrong_audience_fails() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        let presentation = present(
            &sd_jwt,
            &["given_name".into()],
            "https://verifier.example",
            "nonce-123",
            &holder,
            1_700_000_100,
        )
        .unwrap();

        assert!(verify_presentation(
            &presentation,
            &issuer.public_jwk().unwrap(),
            "https://attacker.example", // wrong aud
            "nonce-123",
            1_700_000_200,
        )
        .is_err());
    }

    #[test]
    fn kb_jwt_wrong_nonce_fails() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        let presentation = present(
            &sd_jwt,
            &["given_name".into()],
            "https://verifier.example",
            "nonce-123",
            &holder,
            1_700_000_100,
        )
        .unwrap();

        assert!(verify_presentation(
            &presentation,
            &issuer.public_jwk().unwrap(),
            "https://verifier.example",
            "wrong-nonce", // replay guard
            1_700_000_200,
        )
        .is_err());
    }

    /// Build a minimal did:web document that publishes `issuer_jwk` as its sole
    /// verification method (mirrors what the backend serves at /.well-known).
    fn did_doc_for(issuer_jwk: &Value) -> Value {
        json!({
            "id": "did:web:issuer.example",
            "verificationMethod": [{
                "id": "did:web:issuer.example#key-0",
                "type": "JsonWebKey2020",
                "publicKeyJwk": issuer_jwk,
            }],
        })
    }

    #[test]
    fn verify_via_resolver_resolves_issuer_key() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        let doc = did_doc_for(&issuer.public_jwk().unwrap()).to_string();
        let resolver = crate::did::DidWebResolver::new(|url: &str| {
            assert_eq!(url, "https://issuer.example/.well-known/did.json");
            Ok(doc.clone())
        });

        let v = verify_via_resolver(&sd_jwt, &resolver, 1_700_000_000).unwrap();
        assert_eq!(v.issuer, "did:web:issuer.example");
        assert_eq!(v.claims["given_name"], json!("Somchai"));
    }

    #[test]
    fn verify_with_did_document_rejects_wrong_key() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let attacker = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        // The published doc carries the attacker's key, not the real signer's.
        let doc = did_doc_for(&attacker.public_jwk().unwrap());
        assert!(verify_with_did_document(&sd_jwt, &doc, 1_700_000_000).is_err());
    }

    #[test]
    fn ingest_builds_stored_credential_with_display() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        let doc = did_doc_for(&issuer.public_jwk().unwrap());

        // No hints: title derived from vct, issuer name falls back to iss.
        let bare = ingest_with_did_document(
            "cred-1",
            &sd_jwt,
            &doc,
            1_700_000_000,
            DisplayHints::default(),
            &[],
        )
        .unwrap();
        assert_eq!(bare.id, "cred-1");
        assert_eq!(bare.format, "sd-jwt-vc");
        assert_eq!(bare.raw, sd_jwt);
        assert_eq!(bare.display.title, "employee badge");
        assert_eq!(bare.display.issuer_name, "did:web:issuer.example");
        assert_eq!(bare.display.issuer_did, "did:web:issuer.example");
        assert_eq!(bare.display.color, None);

        // Hints from issuer metadata override the derived fields.
        let hinted = ingest_with_did_document(
            "cred-2",
            &sd_jwt,
            &doc,
            1_700_000_000,
            DisplayHints {
                title: Some("Employee Badge".into()),
                issuer_name: Some("Codefin Co., Ltd.".into()),
                color: Some("#0E7C66".into()),
            },
            &[],
        )
        .unwrap();
        assert_eq!(hinted.display.title, "Employee Badge");
        assert_eq!(hinted.display.issuer_name, "Codefin Co., Ltd.");
        assert_eq!(hinted.display.color.as_deref(), Some("#0E7C66"));
    }

    #[test]
    fn ingest_enforces_pinned_issuer_key() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        let doc = did_doc_for(&issuer.public_jwk().unwrap());
        let now = 1_700_000_000;
        let tp = jwk_thumbprint(&issuer.public_jwk().unwrap()).unwrap();

        // Correct pin → accepted.
        assert!(ingest_with_did_document(
            "c",
            &sd_jwt,
            &doc,
            now,
            DisplayHints::default(),
            &[tp.clone()]
        )
        .is_ok());
        // Wrong pin → rejected even though the issuer signature is valid (this is
        // the MITM/rogue-did.json defence).
        assert!(ingest_with_did_document(
            "c",
            &sd_jwt,
            &doc,
            now,
            DisplayHints::default(),
            &["not-the-key".to_string()]
        )
        .is_err());
        // No pins → allowed (issuer not pinned in the registry).
        assert!(
            ingest_with_did_document("c", &sd_jwt, &doc, now, DisplayHints::default(), &[]).is_ok()
        );
    }

    #[test]
    fn jwk_thumbprint_is_stable_and_key_specific() {
        let a = SoftwareKey::generate();
        let b = SoftwareKey::generate();
        let ta = jwk_thumbprint(&a.public_jwk().unwrap()).unwrap();
        assert_eq!(ta, jwk_thumbprint(&a.public_jwk().unwrap()).unwrap()); // stable
        assert_ne!(ta, jwk_thumbprint(&b.public_jwk().unwrap()).unwrap()); // per-key
    }

    #[test]
    fn ingest_rejects_expired_credential() {
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();
        let doc = did_doc_for(&issuer.public_jwk().unwrap());
        let now = 1_700_000_000 + 366 * 24 * HOUR;
        assert!(
            ingest_with_did_document("c", &sd_jwt, &doc, now, DisplayHints::default(), &[])
                .is_err()
        );
    }

    #[test]
    fn kb_jwt_bound_to_holder_key() {
        // A KB-JWT forged by a different holder key must not verify against the
        // credential's cnf.jwk. We present with the real holder, then re-sign a
        // KB-JWT with an attacker key over the same body.
        let issuer = SoftwareKey::generate();
        let holder = SoftwareKey::generate();
        let attacker = SoftwareKey::generate();
        let sd_jwt = issue(sample_params(&holder), &issuer).unwrap();

        let hasher = Sha256Hasher::new();
        let parsed = SdJwt::parse(&sd_jwt).unwrap();
        let (presented, _) = parsed
            .into_presentation(&hasher)
            .unwrap()
            .conceal_all()
            .disclose("/given_name")
            .unwrap()
            .finish();
        let attacker_signer = ExternalEs256Signer(&attacker);
        let kb = pollster::block_on(
            KeyBindingJwt::builder()
                .nonce("nonce-123")
                .aud("https://verifier.example")
                .iat(1_700_000_100)
                .finish(&presented, &hasher, "ES256", &attacker_signer),
        )
        .unwrap();
        let mut with_kb = presented;
        with_kb.attach_key_binding_jwt(kb);
        let forged = with_kb.presentation();

        assert!(verify_presentation(
            &forged,
            &issuer.public_jwk().unwrap(),
            "https://verifier.example",
            "nonce-123",
            1_700_000_200,
        )
        .is_err());
    }
}
