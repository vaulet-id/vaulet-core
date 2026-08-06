//! Protocol layer (PLAN.md D2)
//! M1: OID4VCI (claim) + OID4VP (present) only — deliberately no DIDComm in M1.
//! M2: adds a didcomm module for chat.
//!
//! These wire types are the pinned M1 OID4VCI contract (see
//! `docs/oid4vci-m1-contract.md`, ADR 0004). They are shared by BOTH the axum
//! backend (issuer) and the wallet FFI, so they live in `core`. Everything here
//! is pure serde + signing — network-free and sync, honoring the
//! Rust-crypto / Dart-HTTP boundary: Dart makes the HTTP calls, the FFI only
//! parses/produces these JSON structs and signs the holder proof JWT.

pub mod oid4vci {
    //! Claiming, pre-authorized_code flow (OID4VCI 1.0 Final):
    //! Credential Offer (§4.1) → Token (§6, pre-auth grant) → Credential (§8),
    //! where the Credential Request carries a holder-signed proof JWT (§F.1)
    //! over the `c_nonce`. Metadata is served at §12.2.

    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value};

    use crate::keys::software::SoftwareKey;
    use crate::{CoreError, Result};

    /// Pre-authorized_code grant identifier (OID4VCI §3.5 / §4.1.1).
    pub const PRE_AUTHORIZED_CODE_GRANT: &str =
        "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    /// `typ` header value of the holder proof JWT (OID4VCI §F.1).
    pub const PROOF_JWT_TYP: &str = "openid4vci-proof+jwt";
    /// Credential-offer custom URI scheme the wallet scans (OID4VCI §4.1).
    pub const OFFER_SCHEME: &str = "openid-credential-offer://";

    // ---------------------------------------------------------------------
    // Credential Offer — OID4VCI §4.1
    // ---------------------------------------------------------------------

    /// The Credential Offer object (OID4VCI §4.1.1). Carried in the QR either
    /// by value (`credential_offer=<url-encoded JSON>`) or by reference
    /// (`credential_offer_uri=<url>` that returns this JSON).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CredentialOffer {
        /// Issuer identifier; also the base for metadata discovery. For M1 this
        /// is the backend's HTTPS origin (and matches the `did:web` host).
        pub credential_issuer: String,
        /// Which credential configuration(s) from issuer metadata are on offer
        /// (M1: `["codefin-identity"]` or `["employee-badge"]`).
        pub credential_configuration_ids: Vec<String>,
        /// Grants the issuer pre-authorizes. M1 always sets the pre-auth grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Grants>,
    }

    /// The `grants` map (OID4VCI §4.1.1). M1 only ever populates the
    /// pre-authorized_code grant.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Grants {
        #[serde(
            rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    }

    /// The pre-authorized_code grant body (OID4VCI §4.1.1).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct PreAuthorizedCodeGrant {
        /// The pre-authorized code the wallet redeems at the token endpoint.
        #[serde(rename = "pre-authorized_code")]
        pub pre_authorized_code: String,
        /// Present when the issuer wants a transaction code (M1: the fixed mock
        /// contact-OTP where a sub-credential needs one — no real SMS/email).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<TxCode>,
    }

    /// Transaction-code descriptor (OID4VCI §4.1.1). Tells the wallet how to
    /// prompt; the value itself travels in the token request.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct TxCode {
        /// `"numeric"` or `"text"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    /// The two transports of a Credential Offer QR (OID4VCI §4.1.2 / §4.1.3):
    /// inline by value, or a `credential_offer_uri` the wallet must GET.
    #[derive(Debug, Clone, PartialEq)]
    pub enum ParsedOffer {
        /// Offer embedded in the QR (`credential_offer=`), ready to use.
        ByValue(CredentialOffer),
        /// Reference (`credential_offer_uri=`); Dart GETs this URL, then feeds
        /// the returned JSON to [`CredentialOffer`] via serde.
        ByReference(String),
    }

    impl CredentialOffer {
        /// Convenience: the pre-authorized code, if this offer carries the
        /// pre-auth grant (it always does in M1).
        pub fn pre_authorized_code(&self) -> Option<&str> {
            self.grants
                .as_ref()?
                .pre_authorized_code
                .as_ref()
                .map(|g| g.pre_authorized_code.as_str())
        }

        /// Build the by-value offer QR string:
        /// `openid-credential-offer://?credential_offer=<url-encoded JSON>`.
        pub fn to_offer_uri(&self) -> Result<String> {
            let json = serde_json::to_string(self)
                .map_err(|e| CoreError::Protocol(format!("serialize offer: {e}")))?;
            Ok(format!(
                "{OFFER_SCHEME}?credential_offer={}",
                percent_encode(&json)
            ))
        }
    }

    /// Parse a scanned Credential Offer QR into [`ParsedOffer`]. Accepts either
    /// `credential_offer` (inline JSON) or `credential_offer_uri` (reference),
    /// with or without the `openid-credential-offer://` scheme prefix.
    pub fn parse_offer(uri: &str) -> Result<ParsedOffer> {
        let query = uri
            .strip_prefix(OFFER_SCHEME)
            .unwrap_or(uri)
            .trim_start_matches('?')
            .trim_start_matches('/')
            .trim_start_matches('?');
        for pair in query.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match k {
                "credential_offer" => {
                    let json = percent_decode(v)?;
                    let offer = serde_json::from_str(&json)
                        .map_err(|e| CoreError::Protocol(format!("credential_offer json: {e}")))?;
                    return Ok(ParsedOffer::ByValue(offer));
                }
                "credential_offer_uri" => {
                    return Ok(ParsedOffer::ByReference(percent_decode(v)?));
                }
                _ => {}
            }
        }
        Err(CoreError::Protocol(
            "offer has neither credential_offer nor credential_offer_uri".into(),
        ))
    }

    // ---------------------------------------------------------------------
    // Token Endpoint — OID4VCI §6
    // ---------------------------------------------------------------------

    /// Token Request (OID4VCI §6.1). Sent to the token endpoint as
    /// `application/x-www-form-urlencoded` by Dart; this struct names the
    /// fields both sides agree on.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct TokenRequest {
        /// Always [`PRE_AUTHORIZED_CODE_GRANT`] in M1.
        pub grant_type: String,
        #[serde(rename = "pre-authorized_code")]
        pub pre_authorized_code: String,
        /// The transaction code value, when the offer's grant asked for one
        /// (M1 mock OTP).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<String>,
    }

    impl TokenRequest {
        /// A pre-authorized_code token request with the grant_type prefilled.
        pub fn pre_authorized(code: impl Into<String>, tx_code: Option<String>) -> Self {
            Self {
                grant_type: PRE_AUTHORIZED_CODE_GRANT.to_string(),
                pre_authorized_code: code.into(),
                tx_code,
            }
        }
    }

    /// Token Response (OID4VCI §6.2). M1 profile folds the §7 Nonce Endpoint
    /// `c_nonce` into this response so the wallet gets its proof challenge in
    /// one round-trip (see the contract doc); a later sprint can split it out.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct TokenResponse {
        pub access_token: String,
        /// `"Bearer"`.
        pub token_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<i64>,
        /// Challenge the holder proof JWT must echo as its `nonce` (OID4VCI §7).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub c_nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub c_nonce_expires_in: Option<i64>,
    }

    // ---------------------------------------------------------------------
    // Credential Endpoint — OID4VCI §8
    // ---------------------------------------------------------------------

    /// Credential Request (OID4VCI §8.2). Authenticated by the bearer
    /// `access_token` (an HTTP header Dart sets, not a body field). Names the
    /// requested configuration and carries the holder proof of possession.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CredentialRequest {
        /// Which configuration from issuer metadata to issue (M1 required).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_configuration_id: Option<String>,
        /// Holder proof of possession of the binding key (OID4VCI §8.2.1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof: Option<Proof>,
    }

    /// The `proof` object of a Credential Request (OID4VCI §8.2.1). M1 only
    /// uses `proof_type = "jwt"`.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Proof {
        /// `"jwt"`.
        pub proof_type: String,
        /// The compact holder proof JWT (see [`ProofJwtHeader`] / [`ProofJwtClaims`]).
        pub jwt: String,
    }

    impl Proof {
        pub fn jwt(compact: impl Into<String>) -> Self {
            Self {
                proof_type: "jwt".to_string(),
                jwt: compact.into(),
            }
        }
    }

    /// Credential Response (OID4VCI §8.3). M1 profile: exactly one credential
    /// per request, returned as the compact SD-JWT VC string.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CredentialResponse {
        /// The issued SD-JWT VC (feed straight to `credential::verify`).
        pub credential: String,
    }

    // ---------------------------------------------------------------------
    // Holder proof JWT — OID4VCI §F.1
    // ---------------------------------------------------------------------

    /// JOSE header of the holder proof JWT (OID4VCI §F.1). `typ` is fixed to
    /// [`PROOF_JWT_TYP`], `alg` is `ES256` for M1; the key is advertised as an
    /// inline `jwk` (M1 default) or a `kid` reference.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ProofJwtHeader {
        pub typ: String,
        pub alg: String,
        /// Inline holder public JWK — the issuer copies this into the
        /// credential's `cnf.jwk` (M1 default binding path).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<Value>,
        /// Alternative to `jwk`: a key id the issuer can resolve.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
    }

    impl ProofJwtHeader {
        /// The M1 default: ES256 with the holder key inline as `jwk`.
        pub fn es256_jwk(holder_jwk: Value) -> Self {
            Self {
                typ: PROOF_JWT_TYP.to_string(),
                alg: "ES256".to_string(),
                jwk: Some(holder_jwk),
                kid: None,
            }
        }
    }

    /// Payload claims of the holder proof JWT (OID4VCI §F.1). `aud` is the
    /// Credential Issuer identifier, `nonce` echoes the token response
    /// `c_nonce`, `iat` is the signing time.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ProofJwtClaims {
        /// Wallet's own identifier (`did:jwk`); OPTIONAL per spec.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        /// The Credential Issuer identifier the proof is bound to.
        pub aud: String,
        /// Issued-at, seconds since the Unix epoch.
        pub iat: i64,
        /// The `c_nonce` from the token response.
        pub nonce: String,
        /// Channel-binding token (liveness-pad-spec §5.1 E): the per-session
        /// value the server issued alongside the nonce, echoed back inside the
        /// signature so the server can tell the proof was made for the session
        /// it handed the token to, rather than relayed in from another one.
        ///
        /// `None` — and omitted from the JWT entirely — for the flows that were
        /// never issued one, so those proofs stay byte-identical to before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cb: Option<String>,
    }

    /// Assemble and ES256-sign a holder proof JWT (OID4VCI §F.1) with
    /// [`SoftwareKey`]. Network-free and sync — this is the crypto step the
    /// wallet FFI runs between Dart's token and credential HTTP calls. Returns
    /// the compact `header.payload.signature` string to drop into [`Proof::jwt`].
    pub fn build_proof_jwt(
        header: &ProofJwtHeader,
        claims: &ProofJwtClaims,
        holder_key: &SoftwareKey,
    ) -> Result<String> {
        let h = B64.encode(
            serde_json::to_vec(header)
                .map_err(|e| CoreError::Protocol(format!("proof header: {e}")))?,
        );
        let p = B64.encode(
            serde_json::to_vec(claims)
                .map_err(|e| CoreError::Protocol(format!("proof claims: {e}")))?,
        );
        let signing_input = format!("{h}.{p}");
        let sig = holder_key
            .sign(signing_input.as_bytes())
            .map_err(|e| CoreError::Protocol(format!("sign proof jwt: {e}")))?;
        Ok(format!("{signing_input}.{}", B64.encode(sig)))
    }

    /// One-shot wallet helper: build the M1 holder proof JWT (ES256, inline
    /// `jwk`) binding `holder_jwk` to `issuer` over `c_nonce`, and wrap it as a
    /// [`Proof`]. This is what the FFI hands back for the Credential Request.
    pub fn holder_proof(
        issuer: &str,
        c_nonce: &str,
        iat: i64,
        holder_jwk: Value,
        holder_key: &SoftwareKey,
    ) -> Result<Proof> {
        holder_proof_bound(issuer, c_nonce, iat, None, holder_jwk, holder_key)
    }

    /// Same as [`holder_proof`], additionally echoing the server's
    /// channel-binding token as the `cb` claim (liveness-pad-spec §5.1 E).
    /// `cb: None` produces exactly the JWT [`holder_proof`] produces.
    pub fn holder_proof_bound(
        issuer: &str,
        c_nonce: &str,
        iat: i64,
        cb: Option<&str>,
        holder_jwk: Value,
        holder_key: &SoftwareKey,
    ) -> Result<Proof> {
        let header = ProofJwtHeader::es256_jwk(holder_jwk);
        let claims = ProofJwtClaims {
            iss: None,
            aud: issuer.to_string(),
            iat,
            nonce: c_nonce.to_string(),
            cb: cb.map(|s| s.to_string()),
        };
        Ok(Proof::jwt(build_proof_jwt(&header, &claims, holder_key)?))
    }

    /// Decode the header + claims of a received proof JWT WITHOUT verifying the
    /// signature (the issuer verifies ES256 against the header `jwk` separately,
    /// via `credential`-layer primitives). Lets the backend read `nonce`/`aud`
    /// and pull the binding key to set `cnf.jwk`.
    pub fn decode_proof_jwt(compact: &str) -> Result<(ProofJwtHeader, ProofJwtClaims)> {
        let mut parts = compact.split('.');
        let h = parts
            .next()
            .ok_or_else(|| CoreError::Protocol("proof jwt: missing header".into()))?;
        let p = parts
            .next()
            .ok_or_else(|| CoreError::Protocol("proof jwt: missing payload".into()))?;
        if parts.next().is_none() {
            return Err(CoreError::Protocol("proof jwt: not a 3-part JWS".into()));
        }
        let header = serde_json::from_slice(
            &B64.decode(h)
                .map_err(|e| CoreError::Protocol(format!("proof header b64: {e}")))?,
        )
        .map_err(|e| CoreError::Protocol(format!("proof header json: {e}")))?;
        let claims = serde_json::from_slice(
            &B64.decode(p)
                .map_err(|e| CoreError::Protocol(format!("proof claims b64: {e}")))?,
        )
        .map_err(|e| CoreError::Protocol(format!("proof claims json: {e}")))?;
        Ok((header, claims))
    }

    // ---------------------------------------------------------------------
    // Credential Issuer Metadata — OID4VCI §12.2
    // ---------------------------------------------------------------------

    /// Credential Issuer Metadata served at
    /// `/.well-known/openid-credential-issuer` (OID4VCI §12.2). Kept minimal
    /// for M1; `credential_configurations_supported` stays an open JSON map so
    /// the issuer can shape per-credential display/claims freely.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct IssuerMetadata {
        pub credential_issuer: String,
        pub credential_endpoint: String,
        /// The OAuth token endpoint (M1 profile: the backend is its own AS).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        /// §7 Nonce Endpoint. M1 folds `c_nonce` into the token response, so
        /// this is optional for now.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nonce_endpoint: Option<String>,
        /// Keyed by credential configuration id (e.g. `"employee-badge"`).
        pub credential_configurations_supported: Map<String, Value>,
    }

    // ---------------------------------------------------------------------
    // Minimal percent-encoding for the offer query (no url crate dependency).
    // ---------------------------------------------------------------------

    /// Percent-encode everything that is not an RFC 3986 unreserved character,
    /// so JSON (with `{`, `}`, `"`, `:`) survives inside the offer query.
    fn percent_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for b in s.bytes() {
            let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
            if unreserved {
                out.push(b as char);
            } else {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
        out
    }

    /// Reverse [`percent_encode`], also treating `+` as a space (form-style).
    fn percent_decode(s: &str) -> Result<String> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    if i + 2 >= bytes.len() {
                        return Err(CoreError::Protocol("truncated percent-escape".into()));
                    }
                    let hi = (bytes[i + 1] as char)
                        .to_digit(16)
                        .ok_or_else(|| CoreError::Protocol("bad percent-escape".into()))?;
                    let lo = (bytes[i + 2] as char)
                        .to_digit(16)
                        .ok_or_else(|| CoreError::Protocol("bad percent-escape".into()))?;
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|e| CoreError::Protocol(format!("offer utf8: {e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        fn sample_offer() -> CredentialOffer {
            CredentialOffer {
                credential_issuer: "https://issuer.example".into(),
                credential_configuration_ids: vec!["employee-badge".into()],
                grants: Some(Grants {
                    pre_authorized_code: Some(PreAuthorizedCodeGrant {
                        pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                        tx_code: Some(TxCode {
                            input_mode: Some("numeric".into()),
                            length: Some(6),
                            description: Some("Enter the code from HR".into()),
                        }),
                    }),
                }),
            }
        }

        #[test]
        fn offer_grant_uses_spec_key() {
            let json = serde_json::to_value(sample_offer()).unwrap();
            assert!(
                json["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
                    ["pre-authorized_code"]
                    .is_string()
            );
        }

        #[test]
        fn offer_uri_roundtrip_by_value() {
            let offer = sample_offer();
            let uri = offer.to_offer_uri().unwrap();
            assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
            match parse_offer(&uri).unwrap() {
                ParsedOffer::ByValue(got) => assert_eq!(got, offer),
                other => panic!("expected by-value, got {other:?}"),
            }
            assert_eq!(offer.pre_authorized_code(), Some("SplxlOBeZQQYbYS6WxSbIA"));
        }

        #[test]
        fn offer_uri_by_reference() {
            let uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fapi%2Fv1%2Foffers%2Fabc";
            match parse_offer(uri).unwrap() {
                ParsedOffer::ByReference(url) => {
                    assert_eq!(url, "https://issuer.example/api/v1/offers/abc")
                }
                other => panic!("expected by-reference, got {other:?}"),
            }
        }

        #[test]
        fn token_request_prefills_grant() {
            let req = TokenRequest::pre_authorized("code-123", Some("654321".into()));
            assert_eq!(req.grant_type, PRE_AUTHORIZED_CODE_GRANT);
            let v = serde_json::to_value(&req).unwrap();
            assert_eq!(v["pre-authorized_code"], json!("code-123"));
            assert_eq!(v["tx_code"], json!("654321"));
        }

        #[test]
        fn token_response_parses_with_c_nonce() {
            let body = json!({
                "access_token": "abc",
                "token_type": "Bearer",
                "expires_in": 300,
                "c_nonce": "nonce-xyz",
                "c_nonce_expires_in": 120
            });
            let tr: TokenResponse = serde_json::from_value(body).unwrap();
            assert_eq!(tr.c_nonce.as_deref(), Some("nonce-xyz"));
        }

        #[test]
        fn proof_jwt_build_decode_roundtrip() {
            let holder = SoftwareKey::generate();
            let jwk = holder.public_jwk().unwrap();
            let proof = holder_proof(
                "https://issuer.example",
                "nonce-xyz",
                1_700_000_000,
                jwk.clone(),
                &holder,
            )
            .unwrap();
            assert_eq!(proof.proof_type, "jwt");

            let (header, claims) = decode_proof_jwt(&proof.jwt).unwrap();
            assert_eq!(header.typ, PROOF_JWT_TYP);
            assert_eq!(header.alg, "ES256");
            assert_eq!(header.jwk, Some(jwk));
            assert_eq!(claims.aud, "https://issuer.example");
            assert_eq!(claims.nonce, "nonce-xyz");
            assert_eq!(claims.iat, 1_700_000_000);
            // No channel-binding token was issued, so the claim is absent.
            assert_eq!(claims.cb, None);
        }

        /// The `cb` claim is carried inside the signature when the server issued
        /// a channel-binding token, and the payload is unchanged when it did
        /// not — the two calls must not differ for `cb: None`.
        #[test]
        fn proof_jwt_carries_the_channel_binding_token() {
            let holder = SoftwareKey::generate();
            let jwk = holder.public_jwk().unwrap();
            let bound = holder_proof_bound(
                "https://issuer.example",
                "nonce-xyz",
                1_700_000_000,
                Some("cb-token-1"),
                jwk.clone(),
                &holder,
            )
            .unwrap();
            let (_, claims) = decode_proof_jwt(&bound.jwt).unwrap();
            assert_eq!(claims.cb.as_deref(), Some("cb-token-1"));

            let plain = holder_proof(
                "https://issuer.example",
                "nonce-xyz",
                1_700_000_000,
                jwk.clone(),
                &holder,
            )
            .unwrap();
            let unbound = holder_proof_bound(
                "https://issuer.example",
                "nonce-xyz",
                1_700_000_000,
                None,
                jwk,
                &holder,
            )
            .unwrap();
            let payload = |jwt: &str| jwt.split('.').nth(1).unwrap().to_string();
            assert_eq!(payload(&plain.jwt), payload(&unbound.jwt));
        }

        #[test]
        fn credential_request_response_serde() {
            let req = CredentialRequest {
                credential_configuration_id: Some("employee-badge".into()),
                proof: Some(Proof::jwt("h.p.s")),
            };
            let v = serde_json::to_value(&req).unwrap();
            assert_eq!(v["credential_configuration_id"], json!("employee-badge"));
            assert_eq!(v["proof"]["proof_type"], json!("jwt"));

            let resp: CredentialResponse =
                serde_json::from_value(json!({ "credential": "eyJ...~" })).unwrap();
            assert_eq!(resp.credential, "eyJ...~");
        }
    }
}

pub mod oid4vp {
    //! Presenting (OID4VP), M1 form-satisfy profile — the pinned wire contract in
    //! `docs/oid4vp-m1-contract.md` (ADR 0003 form-gated recursive issuance).
    //!
    //! A **Form** asks the holder to *present* the credentials it requires before
    //! the form owner *issues* the form's output (present → verify → issue). M1
    //! chains OID4VP → OID4VCI: the wallet satisfies the ask, then claims the
    //! result through the existing Sprint-2 flow.
    //!
    //! The three-round dance (all HTTP in Dart; the FFI only runs
    //! `credential::present` / `verify_presentation`, network-free per ADR 0004):
    //!   1. Wallet asks for the ask + a fresh nonce:
    //!      `POST /api/v1/manifests/{manifest_id}/request` → [`PresentationRequest`].
    //!   2. Wallet presents one VP per required credential:
    //!      `POST /api/v1/manifests/{manifest_id}/satisfy` body [`SatisfyRequest`].
    //!   3. Form owner verifies each VP and returns an OID4VCI offer for the
    //!      output: [`SatisfyResponse`]; the wallet claims it (chain).
    //!
    //! These serde types are shared by BOTH the axum backend (form owner /
    //! verifier) and the wallet FFI — the same rule as `oid4vci` above.

    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    /// One credential the form asks the holder to present, plus which of its
    /// claims must be disclosed. The minimal M1 stand-in for a DCQL credential
    /// query (full DCQL is deferred — ADR 0004): match a held credential by
    /// `vct`, then present it disclosing exactly `claims`.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct RequestedCredential {
        /// The exact `vct` the presented credential must carry, e.g.
        /// `https://<issuer-host>/credential/verified_email`. The wallet matches
        /// this against held credentials to decide reuse vs. obtain-first.
        pub vct: String,
        /// Claims the presentation must disclose (passed straight to
        /// `credential::present` as `disclose`). For the M1 sub-credentials this
        /// is the single carried claim (`["email"]` / `["phone"]`). Empty means
        /// disclose nothing beyond the always-visible (Z2) claims.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub claims: Vec<String>,
    }

    /// A DCQL query — the standard way to ask for credentials (OID4VP 1.0 §6).
    ///
    /// DCQL is the only query language OID4VP 1.0 supports: Presentation
    /// Exchange was removed at Draft 26, so a `presentation_definition` today
    /// speaks a dialect the specification has left behind. Everything the form
    /// engine asks for is expressed here so a verifier or wallet built against
    /// the standard reads it without knowing anything about Vaulet.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct DcqlQuery {
        /// Non-empty; one entry per credential the form requires.
        pub credentials: Vec<DcqlCredentialQuery>,
    }

    /// One credential the query asks for (OID4VP 1.0 §6.1).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct DcqlCredentialQuery {
        /// Identifies this credential in the response. Alphanumerics, `_` and
        /// `-` only, per the specification.
        pub id: String,
        /// `dc+sd-jwt` for everything issued here — the identifier OID4VP 1.0
        /// uses for SD-JWT VC.
        pub format: String,
        /// Format-specific matching rules; for SD-JWT VC, which `vct` values are
        /// acceptable.
        pub meta: DcqlMeta,
        /// The claims that must be disclosed. Each `path` is a claims path
        /// pointer: for a JSON credential, the property names to walk.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub claims: Vec<DcqlClaim>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct DcqlMeta {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub vct_values: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct DcqlClaim {
        pub path: Vec<String>,
    }

    impl DcqlQuery {
        /// Build the query for a set of (vct, claims) requirements.
        ///
        /// The `id` is derived from the vct's last segment because DCQL restricts
        /// it to alphanumerics, `_` and `-` — a vct is a URL and cannot be used
        /// as one.
        pub fn for_credentials(reqs: &[RequestedCredential]) -> Self {
            DcqlQuery {
                credentials: reqs
                    .iter()
                    .map(|r| DcqlCredentialQuery {
                        id: r
                            .vct
                            .rsplit('/')
                            .next()
                            .unwrap_or(&r.vct)
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .collect(),
                        format: "dc+sd-jwt".to_string(),
                        meta: DcqlMeta {
                            vct_values: vec![r.vct.clone()],
                        },
                        claims: r
                            .claims
                            .iter()
                            .map(|c| DcqlClaim {
                                path: vec![c.clone()],
                            })
                            .collect(),
                    })
                    .collect(),
            }
        }
    }

    /// What a Form asks for before it will issue its output (the OID4VP ask).
    /// The request owner mints it at `POST /api/v1/manifests/{manifest_id}/request`
    /// (minting a fresh single-use `nonce` the way the token endpoint mints
    /// `c_nonce`); it is returned to the wallet and also drives the wallet's
    /// present step and the D13 consent sheet.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct PresentationRequest {
        /// The form this ask belongs to (echoes the URL path segment).
        pub manifest_id: String,
        /// Each required input credential + the claims to disclose. The wallet
        /// returns exactly one VP per entry (see [`SatisfyRequest::presentations`]).
        ///
        /// **Superseded by [`Self::dcql_query`]**, which says the same thing in
        /// the standard's language. Kept while a shipped wallet still reads it;
        /// new readers should use the query.
        pub required: Vec<RequestedCredential>,
        /// The same ask as a DCQL query (OID4VP 1.0 §6) — the standard shape,
        /// readable by any wallet built against the specification rather than
        /// against this server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dcql_query: Option<DcqlQuery>,
        /// Fresh, single-use challenge the form owner minted and stored server
        /// side with a short TTL. Every VP's KB-JWT must echo it as `nonce`, and
        /// it is replayed in [`SatisfyRequest::nonce`] so the verifier can bind
        /// the whole batch to one mint (replay + freshness).
        pub nonce: String,
        /// The verifier (form owner) identifier every VP's KB-JWT must set as its
        /// `aud`, and which `verify_presentation` checks. M1: the backend origin,
        /// identical to the OID4VCI `credential_issuer`, so one identity both
        /// issues and verifies.
        pub audience: String,
        /// Everybody this request needs, when it needs more than one person
        /// (ADR 0027). **Absent for every request with a single role**, which is
        /// every request published so far — a wallet or a self-hosted issuer
        /// that has never heard of roles keeps working unchanged, which is the
        /// test the protocol was designed to pass.
        ///
        /// The first entry is the role whoever asked for this is answering; the
        /// rest are the people they have to bring.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub roles: Vec<PresentationRole>,
        /// The attempt these roles are answering together, minted with the
        /// nonce. Whoever starts passes it to the people they invite, and every
        /// [`SatisfyRequest`] for the same attempt carries it back.
        ///
        /// Absent alongside [`Self::roles`], and for the same reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<String>,
    }

    /// One person's part of a request that needs more than one (ADR 0027).
    ///
    /// What each must present is here rather than referred to elsewhere, so the
    /// wallet can show an invitation — *"send your passport"* — without first
    /// fetching the whole request it is a part of.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct PresentationRole {
        /// Stable within the request: `applicant`, `companion`, `guarantor`.
        pub id: String,
        /// What to call this part when somebody is invited to it.
        #[serde(default)]
        pub title: String,
        /// What this role must present, in the same shape as
        /// [`PresentationRequest::required`].
        #[serde(default)]
        pub required: Vec<RequestedCredential>,
        /// The same ask in the standard's language.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dcql_query: Option<DcqlQuery>,
        /// Roles this one may not be answered by the same key as — published so
        /// a verifier reads the rule rather than trusting it was enforced.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub distinct_from: Vec<String>,
        /// Whether the request completes without this role answering.
        #[serde(default)]
        pub optional: bool,
        /// Whether answering this role earns a credential. **False is a real
        /// answer**: a guarantor signs and wants no card in their wallet saying
        /// so, and the person being invited should be told which it is before
        /// they hand over a passport.
        #[serde(default)]
        pub issues: bool,
    }

    impl PresentationRequest {
        /// The full list of `vct`s this form requires — convenience for the
        /// wallet's reuse-or-obtain matching.
        pub fn required_vcts(&self) -> impl Iterator<Item = &str> {
            self.required.iter().map(|r| r.vct.as_str())
        }
    }

    /// The wallet's answer to a [`PresentationRequest`]: one compact
    /// KB-JWT-bearing SD-JWT presentation per required credential, plus the nonce
    /// they were all bound to. POSTed to `POST /api/v1/manifests/{manifest_id}/satisfy`.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SatisfyRequest {
        /// One presentation per [`PresentationRequest::required`] entry, each
        /// built by `credential::present` (audience = the request's `audience`,
        /// nonce = the request's `nonce`). Order-independent — the verifier
        /// matches each VP to a requirement by its `vct`.
        pub presentations: Vec<String>,
        /// The [`PresentationRequest::nonce`] these presentations were signed
        /// against; the verifier looks it up to find the live ask and confirms
        /// every KB-JWT carries the same value.
        pub nonce: String,
        /// The fields the holder TYPED, as a compact JWS they signed
        /// themselves — see [`sign_form_claims`].
        ///
        /// Typed values are not credentials and cannot be presented, so a form
        /// with fields cannot answer with presentations alone (ADR 0014). They
        /// are signed rather than sent plain for the reason PLAN D7 gives:
        /// a submission is non-repudiable, so a form owner can show afterwards
        /// who wrote what.
        ///
        /// Absent on a form that collects no input, which is every form
        /// published so far.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims_jws: Option<String>,
        /// Which [`PresentationRole`] this answers. Absent means the only one,
        /// so a request with a single role is answered exactly as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        /// The attempt this joins — [`PresentationRequest::session`], passed on
        /// by whoever did the inviting. Absent means "on its own", which is
        /// every request with one role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<String>,
        /// The statement this role signed, as a credential they issued
        /// (ADR 0029). Present exactly when the role was asked for one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub statement: Option<String>,
    }

    /// The payload of a signed form submission.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct FormClaims {
        /// The form owner this was written for.
        pub aud: String,
        /// The presentation request's nonce — the same one the KB-JWTs carry,
        /// which is what stops typed values from one request being paired with
        /// presentations from another.
        pub nonce: String,
        pub iat: i64,
        /// The typed fields, by JSON Schema property name.
        pub claims: serde_json::Map<String, serde_json::Value>,
    }

    /// Sign the typed half of a form submission with the holder's key.
    pub fn sign_form_claims(
        audience: &str,
        nonce: &str,
        iat: i64,
        claims: serde_json::Map<String, serde_json::Value>,
        holder_jwk: serde_json::Value,
        holder_key: &crate::keys::software::SoftwareKey,
    ) -> crate::Result<String> {
        let header = super::oid4vci::ProofJwtHeader::es256_jwk(holder_jwk);
        let h = B64.encode(
            serde_json::to_vec(&header)
                .map_err(|e| crate::CoreError::Protocol(format!("claims header: {e}")))?,
        );
        let payload = FormClaims {
            aud: audience.to_string(),
            nonce: nonce.to_string(),
            iat,
            claims,
        };
        let p = B64.encode(
            serde_json::to_vec(&payload)
                .map_err(|e| crate::CoreError::Protocol(format!("claims payload: {e}")))?,
        );
        let signing_input = format!("{h}.{p}");
        let sig = holder_key
            .sign(signing_input.as_bytes())
            .map_err(|e| crate::CoreError::Protocol(format!("sign form claims: {e}")))?;
        Ok(format!("{signing_input}.{}", B64.encode(sig)))
    }

    /// The key a signed submission names as its own, from the JWS header.
    ///
    /// **Only for a submission that presents no credential**, where there is no
    /// other key to check against and the typed answers are the entire
    /// contribution. Anywhere a presentation exists, the presentations' key is
    /// the one that counts — see [`verify_form_claims`] for why.
    pub fn form_claims_key(compact: &str) -> crate::Result<serde_json::Value> {
        let h = compact
            .split('.')
            .next()
            .ok_or_else(|| crate::CoreError::Protocol("form claims: empty".into()))?;
        let header: serde_json::Value = serde_json::from_slice(
            &B64.decode(h)
                .map_err(|e| crate::CoreError::Protocol(format!("form claims b64: {e}")))?,
        )
        .map_err(|e| crate::CoreError::Protocol(format!("form claims header: {e}")))?;
        header
            .get("jwk")
            .cloned()
            .ok_or_else(|| crate::CoreError::Protocol("form claims: no key in the header".into()))
    }

    /// Verify a signed form submission and return the typed fields.
    ///
    /// `holder_jwk` is the key that signed the PRESENTATIONS in the same
    /// submission. Checking against it rather than against the JWS's own inline
    /// key is the whole point: without it, one party could present credentials
    /// and a second party sign the typed answers, and the form owner would have
    /// a submission no single person stands behind.
    pub fn verify_form_claims(
        compact: &str,
        audience: &str,
        nonce: &str,
        holder_jwk: &serde_json::Value,
    ) -> crate::Result<serde_json::Map<String, serde_json::Value>> {
        use p256::ecdsa::signature::Verifier;

        let mut parts = compact.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => {
                return Err(crate::CoreError::Protocol(
                    "form claims: not a 3-part JWS".into(),
                ))
            }
        };
        let payload: FormClaims = serde_json::from_slice(
            &B64.decode(p)
                .map_err(|e| crate::CoreError::Protocol(format!("form claims b64: {e}")))?,
        )
        .map_err(|e| crate::CoreError::Protocol(format!("form claims json: {e}")))?;

        if payload.aud != audience {
            return Err(crate::CoreError::Protocol(
                "form claims: wrong audience".into(),
            ));
        }
        if payload.nonce != nonce {
            return Err(crate::CoreError::Protocol(
                "form claims: wrong nonce".into(),
            ));
        }

        let vk = crate::credential::verifying_key_from_jwk(holder_jwk)?;
        let sig = p256::ecdsa::Signature::from_slice(
            &B64.decode(s)
                .map_err(|e| crate::CoreError::Protocol(format!("form claims sig b64: {e}")))?,
        )
        .map_err(|e| crate::CoreError::Protocol(format!("form claims sig: {e}")))?;
        vk.verify(format!("{h}.{p}").as_bytes(), &sig)
            .map_err(|_| {
                crate::CoreError::Protocol("form claims: signature does not verify".into())
            })?;

        Ok(payload.claims)
    }

    /// The form owner's response once every required presentation verifies: an
    /// OID4VCI credential offer for the form's OUTPUT credential. The wallet
    /// claims it through the existing Sprint-2 flow (`runClaimFlow`), chaining
    /// OID4VP → OID4VCI (ADR 0003).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SatisfyResponse {
        /// A scannable `openid-credential-offer://…?credential_offer_uri=…` URI
        /// for the output credential (by reference, same transport as HR offers).
        /// **Pre-gated**: the verified presentation WAS the gate, so this offer
        /// carries no `tx_code` and its token exchange skips the OTP check. Feed
        /// straight to the wallet claim flow.
        ///
        /// **Absent when there is nothing yet**, which only happens on a request
        /// with more than one role: the others have not answered, or this role
        /// earns nothing by design. Read [`Self::waiting_for`] to tell those two
        /// apart.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_offer_uri: Option<String>,
        /// Roles still to answer before anything is issued. Empty on every
        /// single-role request, so nothing that reads only the offer changes.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub waiting_for: Vec<String>,
        /// The receipt for a contribution parked while others finish: it
        /// collects the offer once the request completes, and takes the
        /// contribution back until it does.
        ///
        /// Handed only to whoever just answered, over the connection that
        /// carried their presentation. A bearer string rather than a signature
        /// because the alternative — a fresh proof of the holder's key for a
        /// poll — is a second protocol for somebody else to implement, and this
        /// one is a `HashMap` lookup.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub collect_token: Option<String>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        /// The query the form engine builds is a legal DCQL query.
        ///
        /// Pinned here because the parts the specification constrains are the
        /// parts easiest to get subtly wrong: the id alphabet, the SD-JWT VC
        /// format identifier (`dc+sd-jwt`, not the drafts' `vc+sd-jwt`), and
        /// claims as path pointers rather than bare names.
        #[test]
        fn a_dcql_query_is_built_the_way_the_specification_describes() {
            let q = DcqlQuery::for_credentials(&[RequestedCredential {
                vct: "https://issuer.example/credential/verified_email".into(),
                claims: vec!["email".into()],
            }]);
            let c = &q.credentials[0];

            assert_eq!(c.format, "dc+sd-jwt");
            assert_eq!(
                c.meta.vct_values,
                ["https://issuer.example/credential/verified_email"]
            );
            assert_eq!(c.claims[0].path, ["email"]);
            // A vct is a URL and cannot be an id, so one is derived that fits
            // the alphabet DCQL allows.
            assert_eq!(c.id, "verified_email");
            assert!(c
                .id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'));
        }

        /// A vct whose last segment carries characters DCQL forbids still
        /// yields a legal id, rather than one a conformant verifier rejects.
        #[test]
        fn an_awkward_vct_still_yields_a_legal_identifier() {
            let q = DcqlQuery::for_credentials(&[RequestedCredential {
                vct: "https://issuer.example/credential/org.icao.epassport".into(),
                claims: vec![],
            }]);
            assert_eq!(q.credentials[0].id, "org_icao_epassport");
        }

        #[test]
        fn presentation_request_serde_and_required_vcts() {
            let req = PresentationRequest {
                manifest_id: "codefin-identity".into(),
                required: vec![
                    RequestedCredential {
                        vct: "https://issuer.example/credential/verified_email".into(),
                        claims: vec!["email".into()],
                    },
                    RequestedCredential {
                        vct: "https://issuer.example/credential/verified_phone".into(),
                        claims: vec!["phone".into()],
                    },
                ],
                dcql_query: None,
                nonce: "vp-nonce-123".into(),
                audience: "https://issuer.example".into(),
                roles: vec![],
                session: None,
            };
            let v = serde_json::to_value(&req).unwrap();
            assert_eq!(v["manifest_id"], json!("codefin-identity"));
            // A request one person answers says nothing about roles at all —
            // the shape a shipped wallet and a self-hosted issuer already read.
            assert!(v.get("roles").is_none(), "{v}");
            assert!(v.get("session").is_none(), "{v}");
            assert_eq!(
                v["required"][0]["vct"],
                json!("https://issuer.example/credential/verified_email")
            );
            assert_eq!(v["required"][0]["claims"][0], json!("email"));
            assert_eq!(v["nonce"], json!("vp-nonce-123"));
            assert_eq!(v["audience"], json!("https://issuer.example"));

            let back: PresentationRequest = serde_json::from_value(v).unwrap();
            assert_eq!(back, req);
            let vcts: Vec<&str> = back.required_vcts().collect();
            assert_eq!(
                vcts,
                vec![
                    "https://issuer.example/credential/verified_email",
                    "https://issuer.example/credential/verified_phone",
                ]
            );
        }

        #[test]
        fn satisfy_request_response_serde() {
            let req = SatisfyRequest {
                presentations: vec!["eyJ...~kb1".into(), "eyJ...~kb2".into()],
                nonce: "vp-nonce-123".into(),
                claims_jws: None,
                role: None,
                session: None,
                statement: None,
            };
            let v = serde_json::to_value(&req).unwrap();
            assert_eq!(v["presentations"].as_array().unwrap().len(), 2);
            assert_eq!(v["nonce"], json!("vp-nonce-123"));
            let back: SatisfyRequest = serde_json::from_value(v).unwrap();
            assert_eq!(back, req);

            let resp: SatisfyResponse = serde_json::from_value(json!({
                "credential_offer_uri":
                    "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fapi%2Fv1%2Foffers%2Fabc"
            }))
            .unwrap();
            assert!(resp
                .credential_offer_uri
                .unwrap()
                .starts_with("openid-credential-offer://"));
        }

        #[test]
        fn requested_credential_omits_empty_claims() {
            let rc = RequestedCredential {
                vct: "https://issuer.example/credential/codefin-identity".into(),
                claims: vec![],
            };
            let v = serde_json::to_value(&rc).unwrap();
            assert!(
                v.get("claims").is_none(),
                "empty claims must be skipped on the wire"
            );
        }

        use crate::keys::software::SoftwareKey;

        fn typed(pairs: &[(&str, &str)]) -> serde_json::Map<String, serde_json::Value> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect()
        }

        #[test]
        fn the_typed_half_of_a_submission_round_trips() {
            let holder = SoftwareKey::generate();
            let jwk = holder.public_jwk().unwrap();
            let jws = sign_form_claims(
                "https://issuer.example",
                "n-1",
                1_700_000_000,
                typed(&[("address", "12 Sukhumvit Rd")]),
                jwk.clone(),
                &holder,
            )
            .unwrap();

            let claims = verify_form_claims(&jws, "https://issuer.example", "n-1", &jwk).unwrap();
            assert_eq!(claims["address"], "12 Sukhumvit Rd");
        }

        /// THE binding: the typed half must be signed by the same holder who
        /// signed the presentations.
        ///
        /// Without this check one party could present the credentials and a
        /// second party write the answers, and the form owner would hold a
        /// submission that no single person stands behind — while every
        /// signature in it verified.
        #[test]
        fn claims_signed_by_a_different_holder_are_refused() {
            let holder = SoftwareKey::generate();
            let someone_else = SoftwareKey::generate();
            let jws = sign_form_claims(
                "https://issuer.example",
                "n-1",
                1_700_000_000,
                typed(&[("address", "12 Sukhumvit Rd")]),
                someone_else.public_jwk().unwrap(),
                &someone_else,
            )
            .unwrap();

            // Verified against the key that signed the PRESENTATIONS, which is
            // not the key that signed this.
            assert!(verify_form_claims(
                &jws,
                "https://issuer.example",
                "n-1",
                &holder.public_jwk().unwrap()
            )
            .is_err());
        }

        /// Typed answers from one request cannot be paired with presentations
        /// from another: both halves name the same nonce, and it is checked.
        #[test]
        fn claims_written_for_another_request_are_refused() {
            let holder = SoftwareKey::generate();
            let jwk = holder.public_jwk().unwrap();
            let jws = sign_form_claims(
                "https://issuer.example",
                "n-1",
                1_700_000_000,
                typed(&[("address", "12 Sukhumvit Rd")]),
                jwk.clone(),
                &holder,
            )
            .unwrap();

            assert!(verify_form_claims(&jws, "https://issuer.example", "n-2", &jwk).is_err());
            assert!(verify_form_claims(&jws, "https://elsewhere.example", "n-1", &jwk).is_err());
        }

        /// An edited answer invalidates the signature — which is what makes the
        /// submission non-repudiable rather than merely transmitted (PLAN D7).
        #[test]
        fn an_answer_edited_in_transit_does_not_verify() {
            let holder = SoftwareKey::generate();
            let jwk = holder.public_jwk().unwrap();
            let jws = sign_form_claims(
                "https://issuer.example",
                "n-1",
                1_700_000_000,
                typed(&[("address", "12 Sukhumvit Rd")]),
                jwk.clone(),
                &holder,
            )
            .unwrap();

            let mut parts: Vec<&str> = jws.split('.').collect();
            let edited = B64.encode(
                serde_json::to_vec(&FormClaims {
                    aud: "https://issuer.example".into(),
                    nonce: "n-1".into(),
                    iat: 1_700_000_000,
                    claims: typed(&[("address", "99 Somewhere Else")]),
                })
                .unwrap(),
            );
            parts[1] = &edited;
            assert!(
                verify_form_claims(&parts.join("."), "https://issuer.example", "n-1", &jwk)
                    .is_err()
            );
        }

        /// A submission with no typed fields carries no claims block at all, so
        /// every form published today serializes exactly as it did before.
        #[test]
        fn a_submission_without_typed_fields_is_unchanged_on_the_wire() {
            let v = serde_json::to_value(SatisfyRequest {
                presentations: vec!["vp".into()],
                nonce: "n-1".into(),
                claims_jws: None,
                role: None,
                session: None,
                statement: None,
            })
            .unwrap();
            assert!(v.get("claims_jws").is_none(), "{v}");
        }
    }
}
