//! Chat message protection with MLS (RFC 9420), per ADR 0013.
//!
//! MLS carries the **content**: forward secrecy and post-compromise security
//! for one-to-one and for groups, with add/remove as protocol operations so a
//! removed member is cryptographically unable to read what follows. DIDComm
//! sits outside this module as the envelope and routing; the mediator sees
//! only what those layers expose, and never anything produced here.
//!
//! Two things this module deliberately does not do:
//!
//! - **It does not touch the Secure Enclave.** MLS needs a key schedule —
//!   continuous derivation, HPKE operations, ephemeral keys per epoch — none of
//!   which the Enclave can express, on any current hardware. MLS state is held
//!   in software and belongs encrypted at rest under an Enclave-wrapped key,
//!   exactly as [`crate::keys`] already treats the seed (ADR 0008). The
//!   question "why isn't the chat key in the Enclave like everything else?"
//!   has a permanent answer, not a pending one.
//! - **It does not order commits.** The mediator has no ordering authority
//!   (ADR 0013), so concurrent commits are resolved by clients under a
//!   deterministic rule. That rule is not chosen yet, which is why this module
//!   supports groups of two and leaves larger groups to follow.

pub mod envelope;
pub mod handle;
pub mod inbox;
pub mod invitation;
pub mod message;
mod state;

pub use state::{
    derive_history_key_from_seed, derive_key_from_seed, open_bytes, seal_bytes,
    KEY_LEN as STATE_KEY_LEN,
};

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use thiserror::Error;

/// P-256 throughout, matching every other key in Vaulet (ADR 0008) so a client
/// needs one signature scheme rather than two.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP256R1_SHA256;

/// Application messages are padded to a multiple of this. It costs a little
/// bandwidth to stop the one thing the mediator can still measure — length —
/// from describing what was said.
const PADDING: usize = 64;

#[derive(Debug, Error)]
pub enum ChatError {
    #[error("mls: {0}")]
    Mls(String),
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error("no such group")]
    NoSuchGroup,
    /// Named rather than reported as corruption, so an older build tells the
    /// user to update instead of telling them their data is broken.
    #[error("sealed state is version {0}, which this build cannot read")]
    UnsupportedStateVersion(u8),
    #[error("wrong key for this sealed state")]
    WrongStateKey,
    #[error("envelope is version {0}, which this build cannot read")]
    UnsupportedEnvelopeVersion(u8),
    /// Sealed to somebody else's key, or altered on the way. The two are
    /// indistinguishable to the recipient and neither is actionable.
    #[error("this envelope was not addressed to us")]
    NotForUs,
    #[error("invitation is version {0}, which this build cannot read")]
    UnsupportedInvitationVersion(u8),
}

pub type Result<T> = std::result::Result<T, ChatError>;

fn mls<E: std::fmt::Display>(e: E) -> ChatError {
    ChatError::Mls(e.to_string())
}

/// What arrived, once MLS has authenticated and decrypted it.
#[derive(Debug)]
pub enum Received {
    /// A message someone sent to the group.
    Application {
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    },
    /// A membership or key change that has been applied. The epoch has moved,
    /// so any key an ex-member held is now useless.
    GroupChanged { group_id: Vec<u8> },
    /// A proposal awaiting a commit. Kept distinct from `GroupChanged` because
    /// nothing has taken effect yet.
    ProposalQueued { group_id: Vec<u8> },

    /// The message could not be read, and **this is data rather than an
    /// error**.
    ///
    /// Returning it as a failure meant one unreadable blob stopped the whole
    /// catch-up: the caller never confirmed the delivery, the mediator handed
    /// the same blob back next time, and every message behind it — in every
    /// other conversation too — waited behind it forever, in silence.
    ///
    /// The epochs say which of two very different things happened, and they are
    /// readable without decrypting anything:
    ///
    /// - **theirs > ours** — we missed a commit. Nothing they send from here on
    ///   can be read, and no amount of waiting fixes it.
    /// - **theirs == ours** — the ratchet disagrees within an epoch: a sender
    ///   whose state rolled back, or a gap too wide for the key window.
    /// - **theirs < ours** — an old message arriving late. Ordinary, and the
    ///   only one of the three that is not a problem.
    Undecryptable {
        group_id: Vec<u8>,
        theirs: u64,
        ours: u64,
    },
}

/// A commit plus the Welcome that lets the new member join. Both must reach
/// their recipients: the commit goes to existing members, the Welcome to the
/// person being added.
#[derive(Debug)]
pub struct Invitation {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// One device's MLS state.
///
/// Groups are not held in a map here — they are loaded from the provider's
/// storage by group id on each operation. That keeps *all* durable state in one
/// place, which is what a persistent storage backend has to replace and what
/// encryption at rest has to cover.
pub struct Session {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

impl Session {
    /// `identity` is what other members see in the credential — the holder's
    /// DID. A basic credential is a placeholder: ADR 0013 puts an SD-JWT VC
    /// here so group membership can be conditioned on holding an unrevoked
    /// credential, which is the point where our issuer becomes MLS's
    /// Authentication Service.
    pub fn new(identity: &[u8]) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SIGNATURE_SCHEME).map_err(mls)?;
        signer.store(provider.storage()).map_err(mls)?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
        })
    }

    /// Seal this session's whole state for the platform to store.
    ///
    /// Unlike the seed, MLS state **cannot be re-derived** — it holds the
    /// ratchet, so losing it loses every conversation. The core still writes
    /// nothing itself: it returns opaque bytes, and the platform holds both
    /// them and the key (an Enclave-wrapped one, per ADR 0008/0013).
    ///
    /// Called after any operation that changes state, which in practice is
    /// every send, receive and membership change.
    pub fn export(&self, key: &[u8; STATE_KEY_LEN]) -> Result<Vec<u8>> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| ChatError::Mls("storage lock poisoned".into()))?
            .clone();

        state::seal(
            key,
            &state::Snapshot {
                identity: self.identity.clone(),
                signer_public: self.signer.to_public_vec(),
                values,
            },
        )
    }

    /// Rebuild a session from sealed bytes. The conversation resumes at exactly
    /// the epoch it was sealed at — messages that arrived meanwhile still open.
    pub fn restore(key: &[u8; STATE_KEY_LEN], sealed: &[u8]) -> Result<Self> {
        let snapshot = state::open(key, sealed)?;

        let provider = OpenMlsRustCrypto::default();
        *provider
            .storage()
            .values
            .write()
            .map_err(|_| ChatError::Mls("storage lock poisoned".into()))? = snapshot.values;

        // The signature key is read back out of the restored store rather than
        // carried separately, so there is one copy of it and no way for the two
        // to drift apart.
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &snapshot.signer_public,
            SIGNATURE_SCHEME,
        )
        .ok_or(ChatError::Malformed("signature key missing from state"))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(snapshot.identity.clone()).into(),
            signature_key: snapshot.signer_public.into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            identity: snapshot.identity,
        })
    }

    /// A published key package is what lets someone add this device to a group
    /// while it is asleep — the reason inboxes can hold an invitation at all.
    ///
    /// Takes `&mut self` because it **writes**: the matching private init key
    /// goes into the store, and a caller who publishes the package without
    /// persisting the state afterwards will be unable to open the Welcome that
    /// comes back. Interior mutability would have let this compile as `&self`
    /// and hidden that.
    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls)?;
        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Create a group containing only this device. A one-to-one conversation is
    /// a group of two, so there is no separate pairwise code path to keep in
    /// step with the group one.
    pub fn create_group(&mut self) -> Result<Vec<u8>> {
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                // Quantise ciphertext lengths. The mediator sees sizes even
                // though it sees nothing else, and unpadded sizes distinguish
                // "ok" from a paragraph.
                .padding_size(PADDING)
                // Without this the joiner needs the ratchet tree out of band;
                // carrying it in the Welcome is what makes an invitation a
                // single self-contained blob the mediator can hold.
                .use_ratchet_tree_extension(true)
                .build(),
            self.credential.clone(),
        )
        .map_err(mls)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    pub fn add_member(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<Invitation> {
        let body = MlsMessageIn::tls_deserialize_exact(key_package)
            .map_err(|_| ChatError::Malformed("key package"))?
            .extract();
        let MlsMessageBodyIn::KeyPackage(key_package) = body else {
            return Err(ChatError::Malformed("not a key package"));
        };
        // Validated rather than merely decoded: this checks the key package's
        // own signature, its leaf node's signature and its lifetime. Skipping
        // it would let anyone add a member whose key they do not hold.
        let key_package = key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;

        let mut group = self.load(group_id)?;
        let (commit, welcome, _) = group
            .add_members(
                &self.provider,
                &self.signer,
                core::slice::from_ref(&key_package),
            )
            .map_err(mls)?;

        // Merged immediately: the adder moves to the new epoch as it sends, so
        // its own next message is already encrypted to the enlarged group.
        group.merge_pending_commit(&self.provider).map_err(mls)?;

        Ok(Invitation {
            commit: commit.tls_serialize_detached().map_err(mls)?,
            welcome: welcome.tls_serialize_detached().map_err(mls)?,
        })
    }

    /// Join from a Welcome, returning the group joined.
    pub fn join(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        let body = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| ChatError::Malformed("welcome"))?
            .extract();
        let MlsMessageBodyIn::Welcome(welcome) = body else {
            return Err(ChatError::Malformed("not a welcome"));
        };

        let group = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .padding_size(PADDING)
                .build(),
            welcome,
            None,
        )
        .map_err(mls)?
        .into_group(&self.provider)
        .map_err(mls)?;

        Ok(group.group_id().as_slice().to_vec())
    }

    pub fn send(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Authenticate and decrypt whatever arrived. The group is identified by
    /// the message itself, so a caller draining an inbox does not have to know
    /// which conversation a blob belongs to before opening it.
    pub fn receive(&mut self, message: &[u8]) -> Result<Received> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|_| ChatError::Malformed("mls message"))?
            .try_into_protocol_message()
            .map_err(|_| ChatError::Malformed("not a protocol message"))?;

        let group_id = message.group_id().as_slice().to_vec();
        let theirs = message.epoch().as_u64();
        let mut group = self.load(&group_id)?;
        let ours = group.epoch().as_u64();

        let processed = match group.process_message(&self.provider, message) {
            Ok(processed) => processed,
            // Reported rather than raised: see `Received::Undecryptable`. The
            // epochs are captured above, from the message header, which is
            // readable whether or not the body can be opened.
            Err(_) => {
                return Ok(Received::Undecryptable {
                    group_id,
                    theirs,
                    ours,
                })
            }
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Received::Application {
                group_id,
                plaintext: m.into_bytes(),
            }),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Applying the commit is what advances the epoch — and what
                // makes a Remove take effect rather than merely be announced.
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(mls)?;
                Ok(Received::GroupChanged { group_id })
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(Received::ProposalQueued { group_id })
            }
        }
    }

    /// Remove a member by the identity in their credential.
    ///
    /// This is the operation the whole design rests on: merging the resulting
    /// commit advances the epoch, and the removed member's keys stop working —
    /// they cannot read what follows, as a matter of arithmetic rather than of
    /// the application declining to show it to them. ADR 0013 wires credential
    /// revocation to this.
    pub fn remove_member(&mut self, group_id: &[u8], identity: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let leaf = group
            .members()
            .find(|m| m.credential.serialized_content() == identity)
            .ok_or(ChatError::Malformed("no such member"))?
            .index;

        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        commit.tls_serialize_detached().map_err(mls)
    }

    /// The identity inside a key package, after validating it.
    ///
    /// The **only** honest source for "who sent this invitation": an invitation
    /// carrying a name of its own could present a key package belonging to
    /// somebody else, and that name is what a user reads before deciding to
    /// trust the conversation.
    pub fn identity_in_key_package(key_package: &[u8]) -> Result<Vec<u8>> {
        let body = MlsMessageIn::tls_deserialize_exact(key_package)
            .map_err(|_| ChatError::Malformed("key package"))?
            .extract();
        let MlsMessageBodyIn::KeyPackage(key_package) = body else {
            return Err(ChatError::Malformed("not a key package"));
        };
        let key_package = key_package
            .validate(OpenMlsRustCrypto::default().crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;
        Ok(key_package
            .leaf_node()
            .credential()
            .serialized_content()
            .to_vec())
    }

    /// What this device presents to other members — its DID today.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Members' identities, in leaf order.
    pub fn members(&self, group_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let group = self.load(group_id)?;
        Ok(group
            .members()
            .map(|m| m.credential.serialized_content().to_vec())
            .collect())
    }

    fn load(&self, group_id: &[u8]) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or(ChatError::NoSuchGroup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a whole conversation between two independent sessions. Nothing is
    /// shared between them except the bytes that would cross the wire, so a
    /// mistake that only works in-process cannot pass.
    fn pair() -> (Session, Session, Vec<u8>) {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        let mut bob = Session::new(b"did:peer:bob").unwrap();

        let group = alice.create_group().unwrap();
        let invitation = alice
            .add_member(&group, &bob.key_package().unwrap())
            .unwrap();
        let joined = bob.join(&invitation.welcome).unwrap();

        assert_eq!(joined, group, "both sides must agree on the group id");
        (alice, bob, group)
    }

    /// The premise repair rests on, pinned against OpenMLS rather than against
    /// our reading of it: **a key package opens one room and no more.**
    ///
    /// Joining consumes the private init key, so a second Welcome built from
    /// the same package is one the far end cannot open — and it fails at the
    /// far end, silently, long after the sender thinks it worked. This is why
    /// repairing a desynced conversation has to be an exchange of fresh
    /// invitations and can never be a retry with what we already hold.
    #[test]
    fn a_key_package_cannot_open_a_second_room() {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        let mut bob = Session::new(b"did:peer:bob").unwrap();
        let key_package = bob.key_package().unwrap();

        let first = alice.create_group().unwrap();
        let to_first = alice.add_member(&first, &key_package).unwrap();
        bob.join(&to_first.welcome).unwrap();

        let second = alice.create_group().unwrap();
        let to_second = alice.add_member(&second, &key_package).unwrap();

        assert!(
            bob.join(&to_second.welcome).is_err(),
            "reusing a key package must fail here rather than produce a room \
             one side cannot read"
        );
    }

    #[test]
    fn two_devices_exchange_messages_in_both_directions() {
        let (mut alice, mut bob, group) = pair();

        let wire = alice.send(&group, b"prachum 6 mong").unwrap();
        match bob.receive(&wire).unwrap() {
            Received::Application {
                plaintext,
                group_id,
            } => {
                assert_eq!(plaintext, b"prachum 6 mong");
                assert_eq!(group_id, group);
            }
            other => panic!("expected an application message, got {other:?}"),
        }

        let wire = bob.send(&group, b"rap sap").unwrap();
        match alice.receive(&wire).unwrap() {
            Received::Application { plaintext, .. } => assert_eq!(plaintext, b"rap sap"),
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    #[test]
    fn both_sides_see_the_same_membership() {
        let (alice, bob, group) = pair();
        let expected = vec![b"did:peer:alice".to_vec(), b"did:peer:bob".to_vec()];
        assert_eq!(alice.members(&group).unwrap(), expected);
        assert_eq!(bob.members(&group).unwrap(), expected);
    }

    /// The property the whole design rests on (ADR 0013): after a Remove, the
    /// departed member cannot read what follows. Not "is not shown" — cannot.
    #[test]
    fn a_removed_member_cannot_read_later_messages() {
        let (mut alice, mut bob, group) = pair();

        // Before the removal Bob reads normally, so the failure afterwards is
        // the removal doing its work rather than the pair never having worked.
        let wire = alice.send(&group, b"before").unwrap();
        assert!(matches!(
            bob.receive(&wire),
            Ok(Received::Application { .. })
        ));

        let commit = alice.remove_member(&group, b"did:peer:bob").unwrap();
        bob.receive(&commit).unwrap();

        let wire = alice.send(&group, b"after").unwrap();
        // Unreadable is now reported rather than raised, so the assertion is on
        // what came back rather than on it having failed — and it is the
        // stronger statement: there is no plaintext, whatever the shape of the
        // answer.
        assert!(
            matches!(
                bob.receive(&wire),
                Ok(Received::Undecryptable { .. }) | Err(_)
            ),
            "a removed member must not be able to decrypt a later message"
        );
    }

    #[test]
    fn a_stranger_cannot_open_the_conversation() {
        let (mut alice, _bob, group) = pair();
        let mut mallory = Session::new(b"did:peer:mallory").unwrap();

        let wire = alice.send(&group, b"private").unwrap();
        assert!(matches!(
            mallory.receive(&wire),
            Err(ChatError::NoSuchGroup)
        ));
    }

    #[test]
    fn a_tampered_key_package_is_refused() {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        let mut bob = Session::new(b"did:peer:bob").unwrap();
        let group = alice.create_group().unwrap();

        // Corrupt the last byte, which lands in the signature. Validation must
        // reject it: accepting an unverified key package would let anyone add
        // a "member" whose key they do not actually hold.
        let mut key_package = bob.key_package().unwrap();
        *key_package.last_mut().unwrap() ^= 0xff;

        assert!(alice.add_member(&group, &key_package).is_err());
    }

    #[test]
    fn sending_to_an_unknown_group_fails_rather_than_inventing_one() {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        assert!(matches!(
            alice.send(b"not-a-group", b"hello"),
            Err(ChatError::NoSuchGroup)
        ));
    }

    const KEY: &[u8; STATE_KEY_LEN] = b"an enclave-wrapped 32 byte key!!";

    /// The point of sealing: a device that was closed and reopened resumes the
    /// same conversation. Bob speaks *after* the export, so the ratchet state
    /// has to have survived — merely restoring old messages would not do it.
    #[test]
    fn a_restored_session_continues_the_same_conversation() {
        let (alice, mut bob, group) = pair();

        let sealed = alice.export(KEY).unwrap();
        drop(alice); // the app was closed

        let mut alice = Session::restore(KEY, &sealed).unwrap();

        let wire = bob
            .send(&group, b"sent after alice closed the app")
            .unwrap();
        match alice.receive(&wire).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"sent after alice closed the app")
            }
            other => panic!("expected an application message, got {other:?}"),
        }

        // And she can still speak, which needs her signature key back too.
        let wire = alice.send(&group, b"still here").unwrap();
        assert!(matches!(
            bob.receive(&wire),
            Ok(Received::Application { .. })
        ));
    }

    #[test]
    fn restoring_keeps_the_group_and_its_membership() {
        let (alice, _bob, group) = pair();
        let restored = Session::restore(KEY, &alice.export(KEY).unwrap()).unwrap();
        assert_eq!(
            restored.members(&group).unwrap(),
            alice.members(&group).unwrap()
        );
    }

    #[test]
    fn sealed_state_does_not_leak_the_identity_it_holds() {
        let (alice, _bob, _group) = pair();
        let sealed = alice.export(KEY).unwrap();
        assert!(
            !sealed.windows(14).any(|w| w == b"did:peer:alice"),
            "state at rest must reveal nothing without the key"
        );
    }

    #[test]
    fn the_wrong_key_opens_nothing() {
        let (alice, _bob, _group) = pair();
        let sealed = alice.export(KEY).unwrap();
        let wrong = b"0123456789abcdef0123456789abcdef";
        assert!(matches!(
            Session::restore(wrong, &sealed),
            Err(ChatError::WrongStateKey)
        ));
    }

    #[test]
    fn tampered_sealed_state_is_refused_rather_than_half_loaded() {
        let (alice, _bob, _group) = pair();
        let mut sealed = alice.export(KEY).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        // The AEAD catches this before a single byte reaches the decoder, so a
        // corrupt store can never be partially applied.
        assert!(matches!(
            Session::restore(KEY, &sealed),
            Err(ChatError::WrongStateKey)
        ));
    }

    /// A blob written by a newer build must say so, not read as corruption —
    /// the user is told to update rather than told their data is broken.
    #[test]
    fn a_future_state_version_is_refused_by_name() {
        let (alice, _bob, _group) = pair();
        let mut sealed = alice.export(KEY).unwrap();
        sealed[0] = 99;
        assert!(matches!(
            Session::restore(KEY, &sealed),
            Err(ChatError::UnsupportedStateVersion(99))
        ));
    }
}
