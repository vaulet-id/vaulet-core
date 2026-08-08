//! DID layer
//! - holder binding: did:jwk
//! - chat peers (phase M2): did:peer
//! - issuers: did:web — the resolver must stay pluggable

use serde::{Deserialize, Serialize};

/// The primary identity of a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletIdentity {
    /// did:jwk derived from the public key in secure hardware.
    pub did: String,
    /// JWK public key (the private key never leaves Secure Enclave/StrongBox).
    pub public_jwk: serde_json::Value,
}

/// Pluggable resolver — phase one supports did:jwk / did:key / did:web only
/// (no blockchain DIDs — see D4).
pub trait DidResolver {
    fn resolve(&self, did: &str) -> crate::Result<serde_json::Value>;
}

/// Build a did:jwk from a public JWK per spec:
/// did:jwk:<base64url(public JWK JSON, no padding)>
pub fn did_jwk_from_public(public_jwk: &serde_json::Value) -> crate::Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let canonical = serde_json::to_string(public_jwk)
        .map_err(|e| crate::CoreError::Key(format!("jwk serialize: {e}")))?;
    Ok(format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(canonical)))
}

/// Map a `did:web` identifier to the URL its `did.json` document lives at
/// (per the did:web method spec):
/// - `did:web:host` → `https://host/.well-known/did.json`
/// - `did:web:host:a:b` → `https://host/a/b/did.json`
///
/// A percent-encoded port in the host segment (`%3A` → `:`) is decoded.
pub fn did_web_url(did: &str) -> crate::Result<String> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or_else(|| crate::CoreError::Key(format!("not a did:web: {did}")))?;
    if rest.is_empty() {
        return Err(crate::CoreError::Key("empty did:web identifier".into()));
    }

    let mut segments = rest.split(':');
    let host = segments
        .next()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| crate::CoreError::Key("did:web missing host".into()))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    let path: Vec<&str> = segments.collect();

    if path.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!("https://{host}/{}/did.json", path.join("/")))
    }
}

/// Pull the signing public JWK for a given `kid` out of a resolved DID document.
///
/// Matches a `verificationMethod` entry whose `id` equals `kid` exactly, or
/// whose fragment matches (`#<kid>`) so a bare fragment resolves too. Returns
/// its `publicKeyJwk`.
pub fn signing_jwk_for_kid(doc: &serde_json::Value, kid: &str) -> crate::Result<serde_json::Value> {
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| crate::CoreError::Key("did doc has no verificationMethod".into()))?;

    // Compare on the fragment (the part after '#') so a bare `#kid` and a fully
    // qualified `did#kid` both resolve.
    let fragment = |s: &str| s.rsplit_once('#').map(|(_, f)| f.to_string());
    let want = fragment(kid);
    for m in methods {
        let id = m.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        if id == kid || (want.is_some() && fragment(id) == want) {
            return m
                .get("publicKeyJwk")
                .cloned()
                .ok_or_else(|| crate::CoreError::Key(format!("no publicKeyJwk for kid {kid}")));
        }
    }
    Err(crate::CoreError::Key(format!(
        "kid not found in did doc: {kid}"
    )))
}

/// A `did:web` resolver with the HTTP fetch **injected** by the host app, so the
/// FFI `cdylib` stays sync and network-free (ADR 0004). `fetch(url)` returns the
/// `did.json` body.
pub struct DidWebResolver<F>
where
    F: Fn(&str) -> crate::Result<String>,
{
    fetch: F,
}

impl<F> DidWebResolver<F>
where
    F: Fn(&str) -> crate::Result<String>,
{
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

impl<F> DidResolver for DidWebResolver<F>
where
    F: Fn(&str) -> crate::Result<String>,
{
    fn resolve(&self, did: &str) -> crate::Result<serde_json::Value> {
        let url = did_web_url(did)?;
        let body = (self.fetch)(&url)?;
        serde_json::from_str(&body)
            .map_err(|e| crate::CoreError::Key(format!("did.json parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn did_web_url_root_and_path() {
        assert_eq!(
            did_web_url("did:web:issuer.example").unwrap(),
            "https://issuer.example/.well-known/did.json"
        );
        assert_eq!(
            did_web_url("did:web:issuer.example:users:alice").unwrap(),
            "https://issuer.example/users/alice/did.json"
        );
        assert_eq!(
            did_web_url("did:web:localhost%3A3000").unwrap(),
            "https://localhost:3000/.well-known/did.json"
        );
        assert!(did_web_url("did:jwk:abc").is_err());
    }

    #[test]
    fn did_web_resolver_extracts_jwk_by_kid() {
        let kid = "did:web:issuer.example#key-1";
        let doc = json!({
            "id": "did:web:issuer.example",
            "verificationMethod": [
                {
                    "id": "did:web:issuer.example#key-0",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "AAA", "y": "BBB" }
                },
                {
                    "id": kid,
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "XXX", "y": "YYY" }
                }
            ]
        });
        let body = doc.to_string();

        // Injected fetch returns the fixed did.json for the expected URL.
        let resolver = DidWebResolver::new(|url: &str| {
            assert_eq!(url, "https://issuer.example/.well-known/did.json");
            Ok(body.clone())
        });
        let resolved = resolver.resolve("did:web:issuer.example").unwrap();
        let jwk = signing_jwk_for_kid(&resolved, kid).unwrap();
        assert_eq!(jwk["x"], "XXX");

        // A bare fragment resolves too.
        let jwk2 = signing_jwk_for_kid(&resolved, "#key-0").unwrap();
        assert_eq!(jwk2["x"], "AAA");

        assert!(signing_jwk_for_kid(&resolved, "#nope").is_err());
    }
}
