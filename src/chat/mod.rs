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
pub mod push;
mod state;

pub use state::{
    derive_history_key_from_seed, derive_key_from_seed, open_bytes, seal_bytes,
    KEY_LEN as STATE_KEY_LEN,
};

use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
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

/// How many epochs back an application message can still be read.
///
/// **Zero is the OpenMLS default and it loses messages here.** A commit and the
/// messages around it are not ordered by anything: the mediator promises no
/// order, and in a room a commit is fanned out one deposit at a time, so a
/// message sent just before it routinely arrives just after. With no past
/// epochs kept, that message fails to decrypt with the same error a replayed
/// one gives — and a replay is ordinary, so it is dropped in silence and no gap
/// is drawn.
///
/// Three, not more: each retained epoch keeps a secret tree alive, and the
/// point of the ratchet is that old keys stop existing. Three covers a message
/// overtaken by a couple of membership changes, which is as far as reordering
/// realistically goes when everything crosses one mediator.
const MAX_PAST_EPOCHS: usize = 3;

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
    /// The answer describes the room we are already in, or one older. Every
    /// member answers an anonymous ask, so this is the ordinary outcome rather
    /// than a failure — see `rejoin`.
    #[error("that room info is not ahead of us")]
    NotAhead,
}

pub type Result<T> = std::result::Result<T, ChatError>;

fn mls<E: std::fmt::Display>(e: E) -> ChatError {
    ChatError::Mls(e.to_string())
}

/// Whether a message failed because we have already been past it.
///
/// Three distinct errors mean the same thing — the generation is behind the
/// receiving ratchet — and all three are what a **second copy of a message we
/// already read** looks like. That is not a rare event here: delivery is
/// at-least-once, so the mediator hands a blob over again whenever a receiver
/// has not confirmed storing it.
///
/// `TooDistantInTheFuture` is deliberately **not** in this list. It means
/// messages between this one and the last are gone for good, which is a real
/// loss and belongs in front of somebody.
fn is_replay<S>(error: &ProcessMessageError<S>) -> bool {
    matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::GenerationOutOfBound
                | MessageDecryptionError::SecretTreeError(
                    SecretTreeError::TooDistantInThePast | SecretTreeError::SecretReuseError
                )
        ))
    )
}

/// What arrived, once MLS has authenticated and decrypted it.
#[derive(Debug)]
pub enum Received {
    /// A message someone sent to the group.
    Application {
        room_id: Vec<u8>,
        plaintext: Vec<u8>,
        /// Who sent it, **authenticated by MLS** — this is not a field anybody
        /// filled in, it is the credential the ratchet verified.
        ///
        /// In a room of two, `mine` answers the same question and this adds
        /// nothing. In a room of more, it is the only thing that says who spoke,
        /// and it must never be confused with the display name beside it, which
        /// its owner chose and may change (ADR 0015).
        sender: Vec<u8>,
    },
    /// A membership or key change that has been applied. The epoch has moved,
    /// so any key an ex-member held is now useless.
    RoomChanged { room_id: Vec<u8> },
    /// A proposal awaiting a commit. Kept distinct from `RoomChanged` because
    /// nothing has taken effect yet.
    ProposalQueued { room_id: Vec<u8> },

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
        room_id: Vec<u8>,
        theirs: u64,
        ours: u64,
        /// The same message a second time, or one older than the ratchet's
        /// window — **within the current epoch**, where the epochs alone
        /// cannot tell it from a genuine break.
        ///
        /// **This is the common case, not an edge case.** Delivery is
        /// at-least-once by design: the mediator hands a blob over again
        /// whenever a receiver has not confirmed storing it, and MLS refusing
        /// the second copy is the ratchet doing its job. Reporting it as a
        /// broken conversation put a red banner over a room that was working
        /// perfectly, on the first message anybody sent.
        replayed: bool,
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
    pub fn create_room(&mut self) -> Result<Vec<u8>> {
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &MlsGroupCreateConfig::builder()
                // **A message that merely crossed a commit is not a replay.**
                // OpenMLS keeps no past epochs by default, so the moment a
                // commit merges, the previous epoch's secret tree is thrown
                // away — and a message sent a moment before that commit, its
                // first and only copy, then fails to decrypt with the same
                // error a genuine replay gives. This client reads that error as
                // "at-least-once doing its job" and drops it without a gap,
                // which is exactly right for a replay and silent loss for this.
                // A room fans a commit out one deposit at a time, so a message
                // overtaking one is ordinary rather than rare.
                .max_past_epochs(MAX_PAST_EPOCHS)
                .ciphersuite(CIPHERSUITE)
                // Quantise ciphertext lengths. The mediator sees sizes even
                // though it sees nothing else, and unpadded sizes distinguish
                // "ok" from a paragraph.
                .padding_size(PADDING)
                // Without this the joiner needs the ratchet tree out of band;
                // carrying it in the Welcome is what makes an invitation a
                // single self-contained blob the mediator can hold.
                .use_ratchet_tree_extension(true)
                // **Commits are framed in the clear; messages are not.** The
                // policy governs handshake messages only — `create_message`
                // encrypts directly and never consults it — so what this
                // exposes is who committed and what they changed, never a word
                // anybody said.
                //
                // It is what makes the tie-break possible at all. Resolving two
                // commits at one epoch means ranking their senders, and by the
                // time a competing commit arrives we have moved to our own
                // epoch and can no longer decrypt one framed privately. The
                // header of a public one stays readable.
                //
                // It costs nothing here: every commit travels sealed to one
                // recipient (HPKE), so the mediator sees none of it, and the
                // only readers are members who are in the room already.
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
            self.credential.clone(),
        )
        .map_err(mls)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// Add several people in **one** commit.
    ///
    /// Not a convenience. Adding them one at a time means each commit has to
    /// reach everybody already in the room — including the person added a
    /// moment ago, who has announced no address yet and so cannot be reached at
    /// all. They are left an epoch behind, permanently, and the first thing
    /// they say is unreadable to everybody else.
    ///
    /// One commit puts every newcomer at the same epoch as everybody else, and
    /// there is no window in which somebody is a member and unreachable.
    pub fn add_members(&mut self, room_id: &[u8], key_packages: &[Vec<u8>]) -> Result<Invitation> {
        let mut validated = Vec::with_capacity(key_packages.len());
        for raw in key_packages {
            let body = MlsMessageIn::tls_deserialize_exact(raw)
                .map_err(|_| ChatError::Malformed("key package"))?
                .extract();
            let MlsMessageBodyIn::KeyPackage(key_package) = body else {
                return Err(ChatError::Malformed("not a key package"));
            };
            validated.push(
                key_package
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(mls)?,
            );
        }

        let mut group = self.load(room_id)?;
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &validated)
            .map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;

        Ok(Invitation {
            commit: commit.tls_serialize_detached().map_err(mls)?,
            welcome: welcome.tls_serialize_detached().map_err(mls)?,
        })
    }

    pub fn add_member(&mut self, room_id: &[u8], key_package: &[u8]) -> Result<Invitation> {
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

        let mut group = self.load(room_id)?;
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

        // **A group we already hold cannot be staged over**, and OpenMLS says so
        // before the Welcome can be read far enough to learn which group it is
        // — so this cannot clear the way itself. What makes re-adding work is
        // that an eviction drops the group when it is applied; see `receive`.
        //
        // The clear below is the belt to that brace: a Welcome is authority to
        // be in the room, since it is encrypted to an init key only we hold and
        // whoever sent it has committed us into the group. Only the group is
        // discarded, never history.
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::builder()
                // See `create_room`: without this, a message from the epoch we
                // have just left is indistinguishable from a replay.
                .max_past_epochs(MAX_PAST_EPOCHS)
                .use_ratchet_tree_extension(true)
                .padding_size(PADDING)
                // The joiner has to accept the framing the room uses, or every
                // commit after the one that let them in is refused and they sit
                // an epoch behind for ever. See `create_room` for what it is
                // and what it does not expose.
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
            welcome,
            None,
        )
        .map_err(mls)?;

        let id = staged.group_context().group_id().clone();
        if let Ok(Some(mut old)) = MlsGroup::load(self.provider.storage(), &id) {
            old.delete(self.provider.storage()).map_err(mls)?;
        }

        let group = staged.into_group(&self.provider).map_err(mls)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    pub fn send(&mut self, room_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(room_id)?;
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

        let room_id = message.group_id().as_slice().to_vec();
        let theirs = message.epoch().as_u64();
        let mut group = self.load(&room_id)?;
        let ours = group.epoch().as_u64();

        let processed = match group.process_message(&self.provider, message) {
            Ok(processed) => processed,
            // Reported rather than raised: see `Received::Undecryptable`. The
            // epochs are captured above, from the message header, which is
            // readable whether or not the body can be opened.
            Err(e) => {
                return Ok(Received::Undecryptable {
                    room_id,
                    theirs,
                    ours,
                    replayed: is_replay(&e),
                })
            }
        };

        // Taken before the content is consumed, because `into_content` moves it.
        let sender = processed.credential().serialized_content().to_vec();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Received::Application {
                room_id,
                plaintext: m.into_bytes(),
                sender,
            }),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Applying the commit is what advances the epoch — and what
                // makes a Remove take effect rather than merely be announced.
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(mls)?;

                // **A room we have been evicted from is dropped, not kept.**
                //
                // It can do nothing: sending raises "used after being evicted"
                // and nothing further decrypts. Keeping it is not merely tidy —
                // it is what made being *re-added* impossible, because OpenMLS
                // refuses to stage a Welcome for a group id it already holds,
                // and refuses it before the id can even be read to clear it. So
                // remove-then-add failed at the invitee's end, after the
                // inviter had committed and spent their key package: they never
                // joined, never republished a package, and every later
                // invitation to them queued behind one that could not succeed.
                //
                // Only the group goes. History lives above this layer and is
                // not keyed by epoch, so what was said stays readable.
                if !group.is_active() {
                    group.delete(self.provider.storage()).map_err(mls)?;
                }
                Ok(Received::RoomChanged { room_id })
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(Received::ProposalQueued { room_id })
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
    pub fn remove_member(&mut self, room_id: &[u8], identity: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(room_id)?;
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

    /// Which room a piece of group info is for, without acting on it.
    ///
    /// **Nothing calls this yet, and it is kept deliberately.** Group info can
    /// arrive on a channel that is not the room's own: the member who cannot be
    /// addressed inside a room — the case ADR 0022 leaves open — can only be
    /// reached through the conversation that invited them. Any fix there has to
    /// check the info names a room we are actually in before letting it move our
    /// state anywhere, and reading the id without applying it is the piece that
    /// cannot be done from outside. Two attempts are written up in the ADR; both
    /// failed for reasons that have nothing to do with this.
    /// Which epoch a piece of group info describes.
    ///
    /// **The guard on healing.** An external commit is not a repair when we are
    /// not the broken party: it moves the room for everybody and cannot be
    /// ranked, so several of them at one epoch fragment the room instead of
    /// mending it. Rejoining is only ever right when the answer is *ahead* of
    /// where we are.
    pub fn epoch_in_group_info(room_info: &[u8]) -> Result<u64> {
        let body = MlsMessageIn::tls_deserialize_exact(room_info)
            .map_err(|_| ChatError::Malformed("room info"))?
            .extract();
        let MlsMessageBodyIn::GroupInfo(info) = body else {
            return Err(ChatError::Malformed("not a room info"));
        };
        Ok(info.epoch().as_u64())
    }

    pub fn room_in_group_info(room_info: &[u8]) -> Result<Vec<u8>> {
        let body = MlsMessageIn::tls_deserialize_exact(room_info)
            .map_err(|_| ChatError::Malformed("room info"))?
            .extract();
        let MlsMessageBodyIn::GroupInfo(info) = body else {
            return Err(ChatError::Malformed("not a room info"));
        };
        Ok(info.group_id().as_slice().to_vec())
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
            .validate(
                OpenMlsRustCrypto::default().crypto(),
                ProtocolVersion::Mls10,
            )
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
    pub fn members(&self, room_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let group = self.load(room_id)?;
        Ok(group
            .members()
            .map(|m| m.credential.serialized_content().to_vec())
            .collect())
    }

    /// Read a commit's header without applying it, or touching any state.
    ///
    /// **The tie-break has to happen before anything is applied**, and by the
    /// time a competing commit arrives we have already moved to our own epoch —
    /// so `receive` would reject it as stale and tell us nothing about who sent
    /// it. This reads what the header says, which is readable whether or not
    /// the body can be opened: the epoch it was built at, and the leaf that
    /// built it.
    ///
    /// `None` for anything that is not a member's commit — an external sender,
    /// or a message that is not a commit at all. Neither can win a race.
    /// Returns the room, the epoch and the leaf.
    ///
    /// **The room matters as much as the other two.** A commit arrives in a
    /// box, and the box says only which key opens the envelope — every member
    /// of that room holds it. Ranking on epoch and leaf alone let a commit from
    /// one room be weighed against a change made in another, and the epochs
    /// collide often, because every room starts at zero.
    pub fn peek_commit(&self, message: &[u8]) -> Option<(Vec<u8>, u64, u32)> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .ok()?
            .try_into_protocol_message()
            .ok()?;
        let epoch = message.epoch().as_u64();
        let room = message.group_id().as_slice().to_vec();
        // Only a publicly framed commit can be read from outside its epoch, and
        // that is why rooms are created asking for one. A room made before that
        // — or by another client — frames commits privately, and this says so
        // by answering nothing rather than by guessing.
        let ProtocolMessage::PublicMessage(public) = message else {
            return None;
        };
        if public.content_type() != ContentType::Commit {
            return None;
        }
        match public.sender() {
            Sender::Member(leaf) => Some((room, epoch, leaf.u32())),
            _ => None,
        }
    }

    /// Where a leaf stands in the order for this room's current epoch. **Lowest
    /// wins**, and the order rotates every epoch.
    ///
    /// `(leaf - epoch) mod size`. The usual rule is the lowest hash of the
    /// commit bytes, and it is **grindable**: a member who wants to can search
    /// for a commit that hashes low and win every race, which is a quiet veto
    /// over everybody else's membership changes. A leaf index and an epoch are
    /// known to every member and chosen by none of them, so rotating by epoch
    /// moves the order under everyone and costs one subtraction.
    ///
    /// Every member computes this from the same two numbers, which is what
    /// makes them agree without anybody to ask.
    /// **The order is total: two members never tie.** This matters more than it
    /// looks. Both sides of a race yield to a lower rank, so a tie is not a
    /// coin toss — it is both of them concluding they lost, both rolling back,
    /// both re-applying, and the two branches swapping places for ever. The
    /// room never converges and no error is raised anywhere, because each side
    /// is following the rule correctly.
    ///
    /// Ties were reachable two ways. The rotation was written as
    /// `leaf.wrapping_sub(epoch) % size`, which is arithmetic modulo 2^64 and
    /// only agrees with a rotation modulo `size` when `size` divides 2^64 — so
    /// it was right for 2, 4, 8 members and wrong for 3, 5, 6, where two leaves
    /// collided. And leaf indices outlive the members in them: a tree that has
    /// had removals holds blanks, so a leaf index can exceed `size` and two
    /// live leaves can land on the same rotation however it is computed.
    ///
    /// So the rotation decides, and the leaf index — unique to a member by
    /// construction — breaks what is left. Both are known to everybody and
    /// chosen by nobody.
    pub fn rank(&self, room_id: &[u8], leaf: u32) -> Result<u64> {
        let group = self.load(room_id)?;
        let size = group.members().count() as u64;
        if size == 0 {
            return Ok(u64::MAX);
        }
        let epoch = group.epoch().as_u64() % size;
        let rotated = (u64::from(leaf) % size + size - epoch) % size;
        // Room to hold every leaf index below the rotation, so comparing the
        // one number compares the pair.
        Ok(rotated << 32 | u64::from(leaf))
    }

    /// What a member needs to let themselves back into a room (ADR 0022).
    ///
    /// Handed to somebody whose ratchet has fallen behind, over the room inbox
    /// — which is HPKE and owes nothing to MLS, so it still works for a member
    /// who can decrypt nothing. This is the channel Signal heals over, and it
    /// was already here.
    ///
    /// It carries the ratchet tree, because rooms are created asking for it, so
    /// the rejoiner needs nothing else.
    pub fn room_info(&self, room_id: &[u8]) -> Result<Vec<u8>> {
        self.load(room_id)?
            .export_group_info(self.provider.crypto(), &self.signer, true)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Let ourselves back into a room we can no longer read.
    ///
    /// **Nobody has to be awake for this.** An external commit is made by the
    /// joiner, so healing does not wait on whoever created the room — which
    /// would make a person the single point of failure for everybody else's
    /// broken ratchet.
    ///
    /// Our old leaf goes with it: OpenMLS removes any member holding the same
    /// signature key in the same commit, so this replaces us rather than
    /// seating us twice.
    ///
    /// The commit must reach every member, or they stay at the old epoch and
    /// nothing we say afterwards can be read — which would be the same failure
    /// pointed the other way.
    pub fn rejoin(&mut self, room_info: &[u8]) -> Result<Invitation> {
        let info = MlsMessageIn::tls_deserialize_exact(room_info)
            .map_err(|_| ChatError::Malformed("room info"))?
            .extract();
        let MlsMessageBodyIn::GroupInfo(info) = info else {
            return Err(ChatError::Malformed("not a room info"));
        };

        // **The answer has to come from somebody in the room.**
        //
        // A room info is a whole group state, and joining by external commit
        // builds the group out of the blob's own ratchet tree and checks its
        // signature against a credential in that same tree — self-consistent by
        // construction, and therefore no evidence of anything. The blob arrives
        // in a room inbox, which is HPKE and anonymous: anybody holding the
        // address may deposit, and everybody who was ever in the room keeps
        // every address that was announced inside it. So a member who was
        // removed could answer an ask — or manufacture one — with a group of
        // their own making, and this device would replace the real room with it
        // and commit into it, taking the whole room along or leaving it behind.
        //
        // What makes an answer evidence is the signature over it belonging to a
        // member of the group we currently hold. Their leaf index in the
        // offered tree means nothing to us, so the key is what is checked, not
        // the position.
        {
            let ours = self.load(info.group_id().as_slice())?;
            let scheme = ours.ciphersuite().signature_algorithm();
            let crypto = self.provider.crypto();
            let vouched = ours.members().find_map(|member| {
                let key = OpenMlsSignaturePublicKey::new(
                    member.signature_key.into(),
                    scheme,
                )
                .ok()?;
                info.clone().verify(crypto, &key).ok()
            });
            let Some(vouched) = vouched else {
                return Err(ChatError::Malformed("room info from outside the room"));
            };

            // **Ahead of us, or beside us — but never the room we are already
            // in.**
            //
            // An external commit moves the whole room, and it cannot be ranked,
            // so several at one epoch fragment the room rather than mend it.
            // The rule was therefore "only when the answer is ahead", and an
            // ask is answered by every member at *their* epoch — which is right
            // for the healthy majority and exactly inverted for the one member
            // that is broken. A ratchet that disagrees inside one epoch is the
            // case this machinery exists for, and every answer to it carries
            // the same epoch number, so every answer was refused and the room
            // stayed split for good: both sides shown lost messages, neither
            // shown anything wrong, and nothing but somebody joining or leaving
            // could ever have unstuck it.
            //
            // The epoch alone cannot tell the two apart. The transcript hash
            // can: two devices on the same branch of the same epoch agree on
            // it, and two devices on different branches do not.
            let theirs = vouched.group_context();
            // **The tree is what tells the two apart.** Two devices on the same
            // branch of an epoch hold the same ratchet tree; two devices on
            // different branches of it do not, because each applied a different
            // commit. The group context itself is not readable from outside the
            // library, and the epoch number alone says nothing here.
            let mine = ours
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(mls)?;
            let same_branch = vouched.extensions().ratchet_tree().is_some_and(
                |tree| {
                    tree.ratchet_tree()
                        .tls_serialize_detached()
                        .is_ok_and(|theirs| theirs == mine)
                },
            );
            let behind = theirs.epoch().as_u64() < ours.epoch().as_u64();
            if same_branch || behind {
                return Err(ChatError::NotAhead);
            }
        }

        let (mut group, commit, _) = MlsGroup::join_by_external_commit(
            &self.provider,
            &self.signer,
            None,
            info,
            &MlsGroupJoinConfig::builder()
                // See `create_room`: without this, a message from the epoch we
                // have just left is indistinguishable from a replay.
                .max_past_epochs(MAX_PAST_EPOCHS)
                .use_ratchet_tree_extension(true)
                .padding_size(PADDING)
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
            None,
            None,
            b"",
            self.credential.clone(),
        )
        .map_err(mls)?;

        // Merged here, unlike an add: an external commit cannot lose a race it
        // is not in. It carries its own epoch forward from the group info, and
        // a member who has fallen behind has nothing anybody could be racing.
        group.merge_pending_commit(&self.provider).map_err(mls)?;

        Ok(Invitation {
            commit: commit.tls_serialize_detached().map_err(mls)?,
            // An external commit invites nobody, so there is no Welcome. The
            // field stays for one shape across both ways into a room.
            welcome: Vec::new(),
        })
    }

    /// Which epoch a room is at.
    pub fn epoch(&self, room_id: &[u8]) -> Result<u64> {
        Ok(self.load(room_id)?.epoch().as_u64())
    }

    /// This device's own leaf in a room, to rank against somebody else's.
    pub fn own_leaf(&self, room_id: &[u8]) -> Result<u32> {
        Ok(self.load(room_id)?.own_leaf_index().u32())
    }

    fn load(&self, room_id: &[u8]) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(room_id))
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

        let group = alice.create_room().unwrap();
        let invitation = alice
            .add_member(&group, &bob.key_package().unwrap())
            .unwrap();
        let joined = bob.join(&invitation.welcome).unwrap();

        assert_eq!(joined, group, "both sides must agree on the group id");
        (alice, bob, group)
    }

    /// **Removed from a room, and put back into it.**
    ///
    /// The Welcome for the second invitation arrives at a device that still
    /// holds the room it was evicted from, and OpenMLS refuses to build a group
    /// whose id it already has. That failed at the invitee's end, after the
    /// inviter had committed and spent their key package — so the invitee never
    /// joined, never republished a package, and every later invitation to them
    /// queued behind one that could not succeed. Removed, re-added, and
    /// silently outside the room for good.
    #[test]
    fn somebody_removed_from_a_room_can_be_put_back_into_it() {
        let (mut alice, mut bob, room) = pair();

        let eviction = alice.remove_member(&room, b"did:peer:bob").unwrap();
        // Bob applies his own eviction: that is what leaves the dead group in
        // his storage, and without it there is nothing to collide with.
        bob.receive(&eviction).unwrap();

        let back = alice
            .add_members(&room, &[bob.key_package().unwrap()])
            .unwrap();
        assert_eq!(
            bob.join(&back.welcome).unwrap(),
            room,
            "a Welcome for a room we were removed from must be joinable"
        );

        let said = alice.send(&room, b"welcome back").unwrap();
        match bob.receive(&said).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"welcome back");
            }
            other => panic!("re-added and still cannot read: {other:?}"),
        }
    }

    /// **A message overtaken by a commit is still readable.**
    ///
    /// Nothing orders a commit against the messages around it: the mediator
    /// promises no order, and a room fans a commit out one deposit at a time,
    /// so a message sent just before one routinely arrives just after. With no
    /// past epochs kept — the OpenMLS default — that message fails to decrypt
    /// with the same error a replay gives, and a replay is ordinary traffic
    /// that this client drops in silence without drawing a gap.
    #[test]
    fn a_message_sent_before_a_commit_survives_arriving_after_it() {
        let (mut alice, mut bob, room) = pair();

        // Bob says something, then Alice changes the room, and the two cross.
        let overtaken = bob.send(&room, b"sent before the commit").unwrap();
        let mut carol = Session::new(b"did:peer:carol").unwrap();
        let invited = alice
            .add_members(&room, &[carol.key_package().unwrap()])
            .unwrap();
        carol.join(&invited.welcome).unwrap();

        // Bob applies the commit first, so the message he sent is now from an
        // epoch he has left.
        bob.receive(&invited.commit).unwrap();
        alice.receive(&invited.commit).unwrap();

        match alice.receive(&overtaken).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"sent before the commit");
            }
            other => panic!("the message was lost: {other:?}"),
        }
    }

    /// Group info says which room it is for, before anybody acts on it.
    #[test]
    fn a_rooms_group_info_names_the_room() {
        let (alice, _bob, room) = pair();
        let info = alice.room_info(&room).unwrap();

        assert_eq!(
            Session::room_in_group_info(&info).unwrap(),
            room,
            "the id read without applying it must be the room it came from"
        );

        // And it refuses anything else rather than guessing.
        assert!(Session::room_in_group_info(b"not group info at all").is_err());
        let key_package = Session::new(b"did:peer:carol").unwrap().key_package().unwrap();
        assert!(
            Session::room_in_group_info(&key_package).is_err(),
            "a well-formed MLS message of another kind is not group info"
        );
    }

    /// A room of three, which is the size the rank arithmetic was wrong at.
    fn trio() -> (Session, Session, Session, Vec<u8>) {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        let mut bob = Session::new(b"did:peer:bob").unwrap();
        let mut carol = Session::new(b"did:peer:carol").unwrap();

        let room = alice.create_room().unwrap();
        let invitation = alice
            .add_members(
                &room,
                &[
                    bob.key_package().unwrap(),
                    carol.key_package().unwrap(),
                ],
            )
            .unwrap();
        bob.join(&invitation.welcome).unwrap();
        carol.join(&invitation.welcome).unwrap();
        (alice, bob, carol, room)
    }

    /// **No two members may ever rank the same.**
    ///
    /// A tie is not a coin toss. Both sides of a race yield to a lower rank, so
    /// equal ranks mean both roll back, both re-apply, and the two branches
    /// swap places for ever — a room that never converges, with no error
    /// anywhere, because each side is obeying the rule.
    ///
    /// This is asserted over a real three-member group rather than by
    /// recomputing the formula, because recomputing it is how the bug survived:
    /// `leaf.wrapping_sub(epoch) % size` is arithmetic modulo 2^64, which
    /// agrees with a rotation modulo `size` only when `size` divides 2^64. It
    /// was therefore correct for two members and wrong for three.
    #[test]
    fn no_two_members_of_a_room_ever_rank_the_same() {
        let (alice, _bob, _carol, room) = trio();

        let ranks: Vec<u64> = (0..3).map(|leaf| alice.rank(&room, leaf).unwrap()).collect();
        assert_eq!(
            {
                let mut sorted = ranks.clone();
                sorted.sort_unstable();
                sorted.dedup();
                sorted.len()
            },
            3,
            "three members produced fewer than three ranks: {ranks:?}"
        );

        // And exactly one of any pair wins, which is what the caller relies on.
        for a in 0..3u32 {
            for b in 0..3u32 {
                if a == b {
                    continue;
                }
                let (x, y) = (
                    alice.rank(&room, a).unwrap(),
                    alice.rank(&room, b).unwrap(),
                );
                assert!(
                    (x < y) != (y < x),
                    "leaves {a} and {b} did not settle: {x} vs {y}"
                );
            }
        }
    }

    /// Everybody must reach the same verdict from their own copy of the room,
    /// because there is nobody to ask.
    #[test]
    fn every_member_agrees_on_who_wins_a_race() {
        let (alice, bob, carol, room) = trio();

        for a in 0..3u32 {
            for b in 0..3u32 {
                let verdict = |s: &Session| s.rank(&room, a).unwrap() < s.rank(&room, b).unwrap();
                assert_eq!(
                    verdict(&alice),
                    verdict(&bob),
                    "alice and bob disagreed about leaves {a} and {b}"
                );
                assert_eq!(
                    verdict(&alice),
                    verdict(&carol),
                    "alice and carol disagreed about leaves {a} and {b}"
                );
            }
        }
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

        let first = alice.create_room().unwrap();
        let to_first = alice.add_member(&first, &key_package).unwrap();
        bob.join(&to_first.welcome).unwrap();

        let second = alice.create_room().unwrap();
        let to_second = alice.add_member(&second, &key_package).unwrap();

        assert!(
            bob.join(&to_second.welcome).is_err(),
            "reusing a key package must fail here rather than produce a room \
             one side cannot read"
        );
    }

    /// **The bug this exists to stop from coming back.** Delivery is
    /// at-least-once: the mediator hands a blob over again whenever the
    /// receiver has not confirmed storing it, so the same message arriving
    /// twice is ordinary, expected, and by design.
    ///
    /// MLS refuses the second copy — which is the ratchet working — and the
    /// refusal is indistinguishable, by epoch alone, from a conversation that
    /// has genuinely broken. Reporting it as the latter put a red "this
    /// conversation can no longer be read" banner over a working room on the
    /// **first message anybody sent**.
    ///
    /// Which error OpenMLS returns is its decision, not ours: this asks it.
    #[test]
    fn the_same_message_twice_is_a_replay_and_not_a_broken_conversation() {
        let (mut alice, mut bob, group) = pair();
        let wire = alice.send(&group, b"hello").unwrap();

        assert!(matches!(
            bob.receive(&wire).unwrap(),
            Received::Application { .. }
        ));

        match bob.receive(&wire).unwrap() {
            Received::Undecryptable {
                replayed,
                theirs,
                ours,
                ..
            } => {
                assert!(replayed, "a second copy must not read as a break");
                assert_eq!(
                    theirs, ours,
                    "and the epochs cannot tell it apart, which is the point"
                );
            }
            other => panic!("expected the replay to be reported, got {other:?}"),
        }
    }

    #[test]
    fn two_devices_exchange_messages_in_both_directions() {
        let (mut alice, mut bob, group) = pair();

        let wire = alice.send(&group, b"prachum 6 mong").unwrap();
        match bob.receive(&wire).unwrap() {
            Received::Application {
                plaintext, room_id, ..
            } => {
                assert_eq!(plaintext, b"prachum 6 mong");
                assert_eq!(room_id, group);
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
        let group = alice.create_room().unwrap();

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

    /// A room of more than two is only a room if you can tell who spoke, and
    /// the answer has to come from MLS rather than from anything a sender
    /// filled in — a self-reported name in a group is a name anybody can wear.
    ///
    /// Pinned against what OpenMLS actually puts in the credential, with three
    /// real sessions and only wire bytes between them.
    #[test]
    fn a_room_says_who_spoke_and_mls_is_what_says_it() {
        let mut alice = Session::new(b"did:peer:alice").unwrap();
        let mut bob = Session::new(b"did:peer:bob").unwrap();
        let mut carol = Session::new(b"did:peer:carol").unwrap();

        let room = alice.create_room().unwrap();
        let to_bob = alice
            .add_member(&room, &bob.key_package().unwrap())
            .unwrap();
        bob.join(&to_bob.welcome).unwrap();

        let to_carol = alice
            .add_member(&room, &carol.key_package().unwrap())
            .unwrap();
        carol.join(&to_carol.welcome).unwrap();
        // Bob has to see the commit that added Carol, or he stays an epoch
        // behind and reads nothing after it.
        bob.receive(&to_carol.commit).unwrap();

        // Bob speaks; Carol must be able to say it was Bob and not Alice.
        let wire = bob.send(&room, b"raw six").unwrap();
        match carol.receive(&wire).unwrap() {
            Received::Application {
                plaintext, sender, ..
            } => {
                assert_eq!(plaintext, b"raw six");
                assert_eq!(
                    sender, b"did:peer:bob",
                    "the sender must be the member MLS authenticated"
                );
            }
            other => panic!("expected an application message, got {other:?}"),
        }

        // And Alice, in the same room, agrees about who it was.
        match alice.receive(&wire).unwrap() {
            Received::Application { sender, .. } => assert_eq!(sender, b"did:peer:bob"),
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    /// **Two people change the room in the same moment, and both end up in the
    /// same room.** The rule that decides it is ADR 0022's, and this is the
    /// test the ADR asked for: real sessions, real commits, only wire bytes
    /// between them, and the outcome read out of OpenMLS rather than out of our
    /// reading of it.
    ///
    /// The rollback is done the way the app does it — by keeping the sealed
    /// state from before the change and restoring it — because a pending commit
    /// cannot be held across the boundary the app works over.
    #[test]
    fn two_commits_at_one_epoch_leave_everybody_in_the_same_room() {
        let key = [7u8; STATE_KEY_LEN];
        let (mut alice, mut bob, room) = pair();

        let carol = Session::new(b"did:peer:carol").unwrap();
        let dave = Session::new(b"did:peer:dave").unwrap();

        // Both keep what they were before touching anything. This is the whole
        // mechanism: MLS cannot un-apply a commit, so the loser goes back to
        // the blob it had and replays the winner's.
        let alice_before = alice.export(&key).unwrap();
        let bob_before = bob.export(&key).unwrap();

        let from_alice = alice.add_member(&room, &mut carol_package(carol)).unwrap();
        let from_bob = bob.add_member(&room, &mut carol_package(dave)).unwrap();

        // Neither has seen the other's yet, so both believe they moved.
        assert_eq!(alice.members(&room).unwrap().len(), 3);
        assert_eq!(bob.members(&room).unwrap().len(), 3);

        // Each ranks the other's commit against its own. Both compute it from
        // the same two numbers, so they must reach opposite conclusions.
        let (their_room, their_epoch, their_leaf) =
            alice.peek_commit(&from_bob.commit).unwrap();
        assert_eq!(their_room, room, "a peek must say which room it is for");
        let alice_wins = {
            let mine = Session::restore(&key, &alice_before).unwrap();
            mine.rank(&room, mine.own_leaf(&room).unwrap()).unwrap()
                < mine.rank(&room, their_leaf).unwrap()
        };
        assert_eq!(their_epoch, 1, "both were built at the epoch they shared");

        let (_, _, alices_leaf) = bob.peek_commit(&from_alice.commit).unwrap();
        let bob_wins = {
            let mine = Session::restore(&key, &bob_before).unwrap();
            mine.rank(&room, mine.own_leaf(&room).unwrap()).unwrap()
                < mine.rank(&room, alices_leaf).unwrap()
        };
        assert_ne!(
            alice_wins, bob_wins,
            "the rule must pick exactly one winner, or both roll back and the \
             room splits anyway"
        );

        // The loser goes back and replays the winner's commit.
        if alice_wins {
            bob = Session::restore(&key, &bob_before).unwrap();
            bob.receive(&from_alice.commit).unwrap();
        } else {
            alice = Session::restore(&key, &alice_before).unwrap();
            alice.receive(&from_bob.commit).unwrap();
        }

        let mut theirs = alice.members(&room).unwrap();
        let mut ours = bob.members(&room).unwrap();
        theirs.sort();
        ours.sort();
        assert_eq!(theirs, ours, "both sides must be in the same room");
        assert_eq!(theirs.len(), 3, "the winner's addition, and only that one");

        // And the room still works: the winner can speak and the loser reads it.
        let wire = alice.send(&room, b"still here").unwrap();
        match bob.receive(&wire).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"still here")
            }
            other => panic!("the room stopped working: {other:?}"),
        }
    }

    fn carol_package(mut session: Session) -> Vec<u8> {
        session.key_package().unwrap()
    }

    /// **A room split inside one epoch can be rejoined.**
    ///
    /// The rule was "only when the answer is ahead of us", which is right for
    /// the healthy majority — an ask is anonymous, so everybody answers, and
    /// most answers describe the epoch the asker is already at. It is exactly
    /// inverted for the one member whose ratchet disagrees *inside* an epoch:
    /// every answer to that member carries the same epoch number, so every
    /// answer was refused and the room stayed split for good, with both sides
    /// shown lost messages and neither shown anything wrong.
    #[test]
    fn a_room_split_inside_one_epoch_can_be_rejoined() {
        let (mut alice, mut bob, room) = pair();

        // Two commits at the same epoch. Each applies their own and never sees
        // the other's, which is the fork.
        let carol = Session::new(b"did:peer:carol").unwrap();
        let dave = Session::new(b"did:peer:dave").unwrap();
        alice
            .add_member(&room, &carol_package(carol))
            .unwrap();
        bob.add_member(&room, &carol_package(dave)).unwrap();
        assert_eq!(
            alice.epoch(&room).unwrap(),
            bob.epoch(&room).unwrap(),
            "the split has to be inside one epoch, or this proves nothing"
        );

        let wire = alice.send(&room, b"can you hear me").unwrap();
        assert!(
            matches!(bob.receive(&wire).unwrap(), Received::Undecryptable { .. }),
            "the break has to be real"
        );

        // Alice answers Bob's ask with a room info at the epoch he is already
        // at — the only kind of answer this case can produce.
        let info = alice.room_info(&room).unwrap();
        let back = bob.rejoin(&info).expect("the one answer that could heal it");
        alice.receive(&back.commit).unwrap();

        let after = alice.send(&room, b"there you are").unwrap();
        match bob.receive(&after).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"there you are");
            }
            other => panic!("the room is still split: {other:?}"),
        }
    }

    /// And the answer that describes the room we are already in is still
    /// refused, which is what stops an anonymous ask fragmenting the room.
    #[test]
    fn a_room_info_for_the_room_we_are_in_is_refused() {
        let (alice, mut bob, room) = pair();
        let info = alice.room_info(&room).unwrap();
        assert!(
            matches!(bob.rejoin(&info), Err(ChatError::NotAhead)),
            "a healthy member acted on an answer describing its own room"
        );
    }

    /// **A rejoin answer has to come from somebody still in the room.**
    ///
    /// The answer is a whole group state, and joining by external commit builds
    /// the group out of the blob's own ratchet tree and checks its signature
    /// against a credential in that same tree — self-consistent by
    /// construction, and so no evidence of anything. The blob travels in a room
    /// inbox, which is anonymous and open to anybody holding the address, and
    /// everybody who was ever in a room keeps every address announced inside
    /// it. So without a check, somebody who had been removed could answer an
    /// ask with a room of their own making and take the asker into it.
    #[test]
    fn a_room_info_from_somebody_no_longer_in_the_room_is_refused() {
        let (mut alice, mut bob, room) = pair();

        let mut carol = Session::new(b"did:peer:carol").unwrap();
        let adding = alice
            .add_member(&room, &carol.key_package().unwrap())
            .unwrap();
        bob.receive(&adding.commit).unwrap();
        carol.join(&adding.welcome).unwrap();

        // Carol is taken out. She never sees it, so she keeps a live group with
        // this room's id — which is exactly the state an attacker has.
        let removing = alice.remove_member(&room, b"did:peer:carol").unwrap();
        bob.receive(&removing).unwrap();

        let hers = carol.room_info(&room).unwrap();
        assert_eq!(
            Session::room_in_group_info(&hers).unwrap(),
            room,
            "the blob has to name the real room, or this proves nothing"
        );

        let refused = bob.rejoin(&hers);
        assert!(
            refused.is_err(),
            "a room info signed by somebody the group no longer holds was taken"
        );

        // And the room bob holds is untouched by the attempt.
        assert!(
            bob.members(&room)
                .unwrap()
                .iter()
                .all(|m| m != b"did:peer:carol"),
            "the refused answer must not have moved this device anywhere"
        );
    }

    /// **A member whose ratchet has fallen behind lets themselves back in**,
    /// and nobody had to be awake to allow it (ADR 0022).
    ///
    /// The break is staged the way it really happens: a member goes back to a
    /// state from before a commit they never received, so their epoch is behind
    /// and nothing anybody says decrypts. Signal heals this over the pairwise
    /// channel it always has; the room inbox is ours, and it owes nothing to
    /// MLS, so it still works for somebody who can read nothing.
    #[test]
    fn a_member_who_fell_behind_lets_themselves_back_in() {
        let key = [9u8; STATE_KEY_LEN];
        let (mut alice, mut bob, room) = pair();

        // Bob's state from before he sees what comes next.
        let bob_behind = bob.export(&key).unwrap();

        let carol = Session::new(b"did:peer:carol").unwrap();
        let adding = alice.add_member(&room, &carol_package(carol)).unwrap();
        bob.receive(&adding.commit).unwrap();

        // Bob is restored to before that commit: an epoch behind, exactly as if
        // it had expired out of the queue while he was away.
        let mut bob = Session::restore(&key, &bob_behind).unwrap();
        let wire = alice.send(&room, b"can you hear me").unwrap();
        assert!(
            matches!(bob.receive(&wire).unwrap(), Received::Undecryptable { .. }),
            "the break has to be real, or this proves nothing"
        );

        // Alice hands over what he needs, over a channel that is not MLS.
        let info = alice.room_info(&room).unwrap();
        let back = bob.rejoin(&info).unwrap();

        // Everybody else applies his commit, and the room converges.
        alice.receive(&back.commit).unwrap();

        let mut hers = alice.members(&room).unwrap();
        let mut his = bob.members(&room).unwrap();
        hers.sort();
        his.sort();
        assert_eq!(hers, his, "the room has to agree about who is in it");
        assert_eq!(
            his.iter().filter(|m| *m == b"did:peer:bob").count(),
            1,
            "rejoining must replace the old leaf, not sit beside it"
        );

        // And it works in both directions afterwards, which is the point.
        let after = alice.send(&room, b"there you are").unwrap();
        match bob.receive(&after).unwrap() {
            Received::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"there you are")
            }
            other => panic!("still broken after healing: {other:?}"),
        }

        let reply = bob.send(&room, b"back now").unwrap();
        match alice.receive(&reply).unwrap() {
            Received::Application {
                plaintext, sender, ..
            } => {
                assert_eq!(plaintext, b"back now");
                assert_eq!(sender, b"did:peer:bob");
            }
            other => panic!("the healed member cannot be heard: {other:?}"),
        }
    }
}
