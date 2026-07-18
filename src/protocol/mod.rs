//! Protocol layer (PLAN.md D2)
//! M1: OID4VCI (claim) + OID4VP (present) only — deliberately no DIDComm in M1.
//! M2: adds a didcomm module for chat.

pub mod oid4vci {
    //! Claiming: user scans a credential-offer QR → token exchange → credential.

    /// Result of parsing the QR the user scanned.
    #[derive(Debug, Clone)]
    pub struct CredentialOffer {
        pub issuer_url: String,
        pub credential_types: Vec<String>,
    }

    pub fn parse_offer(_uri: &str) -> crate::Result<CredentialOffer> {
        Err(crate::CoreError::Todo("oid4vci::parse_offer — M1 sprint 2"))
    }
}

pub mod oid4vp {
    //! Presenting: verifier requests a presentation → user consents → signed and returned.

    /// The verifier's request — translated to plain language ("the shop will
    /// only learn: of age ✓") and always shown on a consent sheet (D13).
    #[derive(Debug, Clone)]
    pub struct PresentationRequest {
        pub verifier_name: String,
        pub requested_claims: Vec<String>,
    }

    pub fn parse_request(_uri: &str) -> crate::Result<PresentationRequest> {
        Err(crate::CoreError::Todo("oid4vp::parse_request — M1 sprint 3"))
    }
}
