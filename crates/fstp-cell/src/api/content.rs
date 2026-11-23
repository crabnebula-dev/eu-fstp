//! Content beside the ledger (ADR-026 "Pending actions" and "Workspaces",
//! I-21, I-85, ADR-007).
//!
//! - `TextStore` keeps each text in the cell's erasure task, under a data
//!   key of its own, with its class and owner sealed in front of it. A
//!   read checks the class and owner against the read's clearance before
//!   it releases the text, as the test kit's store does.
//! - `Sealer` seals a workspace value under the current ledger key
//!   generation, bound to the cell and the proposal
//!   (`fstp_pgstore::seal_workspace`). `Workspaces` keeps the sealed bytes
//!   in `workspace.drafts` and opens nothing.
//! - `PendingActions` keeps each action in `api.pending_actions`, its
//!   request sealed. A confirmation is the `api.pending_confirmed` row the
//!   engine writes in the executing append.
//! - `BlobStore` keeps each blob in `doc.blob` under the SHA-256 of its
//!   bytes, sealed under a data key of its own in a group of its own, so
//!   erasing the group erases it (R-CR-01, ADR-007, ADR-026 record of lane
//!   L5). Its owner is sealed in front of the bytes.

use std::sync::Arc;

use fstp_access::ReadClearance;
use fstp_api_core::ActionDigest;
use fstp_api_core::pending::{
    OPEN_PER_ACCOUNT, PENDING_RETENTION_MICROS, PendingAction, PendingStatus,
};
use fstp_api_core::port::{
    AgentClientId, BlobOwner, BlobRef, BlobStore, DisplayNameSet, ErasureCause, ErasureKind,
    ErasureRow, PendingActions, PendingFuture, PendingId, PendingInsertError, PortError,
    PublicTextRef, SealOwner, Sealed, Sealer, TextClass, TextOwner, TextRef, TextStore,
    WorkspaceSlot, Workspaces,
};
use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_pgstore::{PendingRow, StoredPendingStatus};
use fstp_rt::Runtime;

use super::Inner;

/// The header of a stored text: its class, its owner kind and the owner
/// id, 18 bytes in front of the text.
const HEADER: usize = 18;

fn header(class: TextClass, owner: TextOwner) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0] = match class {
        TextClass::Confidential => 1,
        TextClass::Public => 2,
    };
    let (kind, id) = match owner {
        TextOwner::Proposal(p) => (1, p.raw()),
        TextOwner::Programme(p) => (2, p.raw()),
        TextOwner::Tenant => (3, 0),
        TextOwner::Account(a) => (4, a.raw()),
    };
    h[1] = kind;
    h[2..].copy_from_slice(&id.to_be_bytes());
    h
}

fn parse(text: &[u8]) -> Option<(TextClass, TextOwner, &[u8])> {
    let (h, body) = text.split_first_chunk::<HEADER>()?;
    let class = match h[0] {
        1 => TextClass::Confidential,
        2 => TextClass::Public,
        _ => return None,
    };
    let id = u128::from_be_bytes(<[u8; 16]>::try_from(&h[2..]).ok()?);
    let owner = match h[1] {
        1 => TextOwner::Proposal(ProposalId::from_raw(id)),
        2 => TextOwner::Programme(ProgrammeId::from_raw(id)),
        3 => TextOwner::Tenant,
        4 => TextOwner::Account(AccountId::from_raw(id)),
        _ => return None,
    };
    Some((class, owner, body))
}

/// Whether `clearance` opens a text of `class` and `owner`: the rule of
/// the test kit's text store, so the two stores release the same texts
/// (I-17, I-21, I-27, SA-11).
fn clears(class: TextClass, owner: TextOwner, clearance: &ReadClearance) -> bool {
    use fstp_access::ReadTarget;
    match (class, owner, clearance.op().target) {
        (TextClass::Public, _, _) => true,
        (_, TextOwner::Proposal(p), _) => clearance.proposal() == Some(p),
        (_, TextOwner::Programme(p), ReadTarget::Programme(_) | ReadTarget::Call(_)) => {
            clearance.programme() == Some(p)
        }
        (_, TextOwner::Account(a), _) => match clearance.op().kind {
            fstp_access::ReadKind::ListTeam | fstp_access::ReadKind::ListMembers => true,
            fstp_access::ReadKind::GetMyDisplayName => clearance.account() == Some(a),
            _ => false,
        },
        // ADR-007 (Daniel, 2026-11-23; lane L39): the reason a tenant
        // admin stated for an erasure opens to the erasure log read only,
        // which the read rule admits for tenant admins.
        (_, TextOwner::Tenant, _) => clearance.op().kind == fstp_access::ReadKind::ListErasures,
        _ => false,
    }
}

/// The text store.
pub(crate) struct CellTexts<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> CellTexts<R, V> {
    async fn open(&self, id: u128) -> Result<(TextClass, TextOwner, Vec<u8>), PortError> {
        let plain = self
            .0
            .erasure
            .open_text(id.to_be_bytes())
            .await
            .map_err(|_| PortError::Refused)?;
        let (class, owner, body) = parse(&plain).ok_or(PortError::Refused)?;
        Ok((class, owner, body.to_vec()))
    }
}

impl<R: Runtime, V: Send + Sync> TextStore for CellTexts<R, V> {
    async fn put(
        &self,
        class: TextClass,
        owner: TextOwner,
        bytes: &[u8],
    ) -> Result<TextRef, PortError> {
        let id: [u8; 16] = fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        let group: [u8; 16] = fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        let mut plain = Vec::with_capacity(HEADER.saturating_add(bytes.len()));
        plain.extend_from_slice(&header(class, owner));
        plain.extend_from_slice(bytes);
        self.0
            .erasure
            .add_group(group)
            .await
            .map_err(|_| PortError::Unavailable)?;
        self.0
            .erasure
            .put_text(group, id, plain)
            .await
            .map_err(|_| PortError::Unavailable)?;
        Ok(TextRef(u128::from_be_bytes(id)))
    }

    async fn get(&self, r: TextRef, clearance: &ReadClearance) -> Result<Vec<u8>, PortError> {
        match self.open(r.0).await? {
            (class, owner, body) if clears(class, owner, clearance) => Ok(body),
            _ => Err(PortError::Refused),
        }
    }

    /// F-079, ADR-038: one bit for a confidential text of a proposal,
    /// such as a team invitation's address. No text leaves the store.
    async fn text_equals(&self, r: TextRef, candidate: &[u8]) -> Result<bool, PortError> {
        match self.open(r.0).await? {
            (TextClass::Confidential, TextOwner::Proposal(_), body) => {
                Ok(fstp_api_core::salted::holds(&body, candidate))
            }
            _ => Ok(false),
        }
    }

    async fn get_public(&self, r: PublicTextRef) -> Result<Vec<u8>, PortError> {
        match self.open(r.0).await? {
            (TextClass::Public, _, body) => Ok(body),
            _ => Err(PortError::Refused),
        }
    }

    /// The cell's erasure log (ADR-007 section "Built by lane L33"): every
    /// entry of the ledger, oldest request first. A completion is the
    /// destruction of the key's root epoch once the erasure runner recorded
    /// it, and the `TextsErased` instant of a ledger text before. An entry
    /// whose cause or kind code is outside its closed list fails the read closed.
    async fn erasures(&self) -> Result<Vec<ErasureRow>, PortError> {
        let state = self.0.engine.state();
        crate::tasks::erasure::erasure_log(&state)
            .into_iter()
            .map(|(id, e)| {
                Ok(ErasureRow {
                    text: TextRef(u128::from_be_bytes(id)),
                    cause: ErasureCause::from_code(e.cause).ok_or(PortError::Unavailable)?,
                    grant: None,
                    requested_at: e.requested_at,
                    completed_at: e.destroyed_at.or(e.completed_at),
                    // Lane L37: every kind code maps, and any other
                    // fails the read closed.
                    kind: match e.kind {
                        fstp_cell_core::ERASURE_KIND_LEDGER_TEXT => ErasureKind::Text,
                        fstp_cell_core::ERASURE_KIND_DISPLAY_NAME => ErasureKind::DisplayName,
                        fstp_cell_core::ERASURE_KIND_DOCUMENT => ErasureKind::Document,
                        _ => return Err(PortError::Unavailable),
                    },
                    destroyed_epoch: e.destroyed_epoch,
                    // Lane L39: the system or an account, and the
                    // stated reason's text.
                    by_system: fstp_cell_core::is_system_authoriser(e.by),
                    reason: e.reason.map(|r| TextRef(u128::from_be_bytes(r))),
                })
            })
            .collect()
    }

    /// SA-11, SA-11 amendment (lane L26, ADR-004 section "Written by lane
    /// L26"): the erasure task seals the name as a text of its own, checks
    /// its fingerprint under the key derived from `Lookup` and writes it,
    /// in one request. A replaced or cleared name is erased at once.
    async fn set_display_name(
        &self,
        a: AccountId,
        name: Option<String>,
        at: Timestamp,
    ) -> Result<DisplayNameSet, PortError> {
        let _ = at;
        self.0
            .erasure
            .set_display_name(a, name)
            .await
            .map_err(|_| PortError::Unavailable)
    }

    /// SA-11 (lane L26): the names under `clearance`, which must open each
    /// account's texts, as the test kit's store asks ([`clears`]). Only
    /// the team read, the member read and the account's own read pass,
    /// so no applicant or Judging read shows a name (I-17, P-11, R-AN-01).
    /// Otherwise the whole read is refused.
    async fn display_names(
        &self,
        accounts: Vec<AccountId>,
        clearance: &ReadClearance,
    ) -> Result<std::collections::BTreeMap<AccountId, String>, PortError> {
        if !accounts
            .iter()
            .all(|a| clears(TextClass::Confidential, TextOwner::Account(*a), clearance))
        {
            return Err(PortError::Refused);
        }
        self.0
            .erasure
            .display_names(accounts)
            .await
            .map_err(|_| PortError::Unavailable)
    }
}

/// The sealer of workspace values.
pub(crate) struct CellSealer<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> Sealer for CellSealer<R, V> {
    async fn seal(&self, owner: SealOwner, plaintext: &[u8]) -> Result<Sealed, PortError> {
        let SealOwner::Workspace(p) = owner;
        fstp_pgstore::seal_workspace(
            &self.0.keys,
            &self.0.cell,
            &p.raw().to_be_bytes(),
            plaintext,
        )
        .map(Sealed)
        .map_err(|_| PortError::Unavailable)
    }

    /// Opens a value sealed for the same proposal. The AAD binds it, so a
    /// value of another proposal does not open. The clearance is the
    /// read's, which the API core checked before it asked.
    async fn open(
        &self,
        owner: SealOwner,
        sealed: &Sealed,
        clearance: &ReadClearance,
    ) -> Result<Vec<u8>, PortError> {
        let _ = clearance;
        let SealOwner::Workspace(p) = owner;
        fstp_pgstore::open_workspace(
            &self.0.keys,
            &self.0.cell,
            &p.raw().to_be_bytes(),
            &sealed.0,
        )
        .map_err(|_| PortError::Refused)
    }
}

/// The `workspace.drafts` slot name of `slot`.
fn slot_name(slot: WorkspaceSlot) -> String {
    match slot {
        WorkspaceSlot::Draft => "draft".to_owned(),
        WorkspaceSlot::Submitted(plan) => format!("submitted:{:032x}", plan.raw()),
    }
}

/// The workspace store.
pub(crate) struct CellWorkspaces<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> Workspaces for CellWorkspaces<R, V> {
    async fn put(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
        sealed: Sealed,
    ) -> Result<(), PortError> {
        self.0
            .store
            .put_workspace(
                proposal.raw().to_be_bytes(),
                &slot_name(slot),
                &sealed.0,
                self.0.now().micros(),
            )
            .await
            .map_err(|_| PortError::Unavailable)
    }

    async fn get(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
    ) -> Result<Option<Sealed>, PortError> {
        self.0
            .store
            .workspace(proposal.raw().to_be_bytes(), &slot_name(slot))
            .await
            .map(|o| o.map(Sealed))
            .map_err(|_| PortError::Unavailable)
    }
}

/// The stored request of an action: `be32(len(request)) || request ||
/// shown`, both canonical texts.
fn encode_request(a: &PendingAction) -> Vec<u8> {
    let r = a.request.as_bytes();
    let len = u32::try_from(r.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(r.len().saturating_add(a.shown.len()).saturating_add(4));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(r);
    out.extend_from_slice(a.shown.as_bytes());
    out
}

fn decode_request(b: &[u8]) -> Option<(String, String)> {
    let (len, rest) = b.split_first_chunk::<4>()?;
    let n = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    let request = rest.get(..n)?;
    let shown = rest.get(n..)?;
    Some((
        String::from_utf8(request.to_vec()).ok()?,
        String::from_utf8(shown.to_vec()).ok()?,
    ))
}

fn action_of(row: PendingRow) -> Option<PendingAction> {
    let (request, shown) = decode_request(&row.request)?;
    let status = match (row.confirmed, row.status) {
        (Some(_), _) => PendingStatus::Confirmed,
        (None, StoredPendingStatus::Open) => PendingStatus::Open,
        (None, StoredPendingStatus::Expired) => PendingStatus::Expired,
        (None, StoredPendingStatus::Discarded) => PendingStatus::Discarded,
    };
    Some(PendingAction {
        id: PendingId::from_raw(u128::from_be_bytes(row.id)),
        account: AccountId::from_raw(u128::from_be_bytes(row.account)),
        agent: AgentClientId::from_raw(u128::from_be_bytes(row.client)),
        op: row.op,
        request,
        shown,
        digest: ActionDigest(row.digest),
        created: Timestamp::from_micros(row.created),
        expires: Timestamp::from_micros(row.expires),
        status,
        closed: row.closed.map(Timestamp::from_micros),
    })
}

/// The pending actions of the cell, in `api.pending_actions`.
pub(crate) struct CellPending<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> PendingActions for CellPending<R, V> {
    fn insert(
        &self,
        a: PendingAction,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<(), PendingInsertError>> {
        Box::pin(async move {
            let store = &self.0.store;
            let account = a.account.raw().to_be_bytes();
            // Ended actions leave after their retention (pending.rs).
            let floor = now.micros().saturating_sub(PENDING_RETENTION_MICROS);
            let _ = store.sweep_pending(floor).await;
            let open = store
                .open_count(account, now.micros())
                .await
                .map_err(|_| PendingInsertError::Port(PortError::Unavailable))?;
            if open >= u64::try_from(OPEN_PER_ACCOUNT).unwrap_or(u64::MAX) {
                return Err(PendingInsertError::Full);
            }
            let row = PendingRow {
                id: a.id.raw().to_be_bytes(),
                account,
                client: a.agent.raw().to_be_bytes(),
                op: a.op.clone(),
                request: encode_request(&a),
                digest: a.digest.0,
                created: a.created.micros(),
                expires: a.expires.micros(),
                status: StoredPendingStatus::Open,
                closed: None,
                confirmed: None,
            };
            store
                .insert_pending(&row)
                .await
                .map_err(|_| PendingInsertError::Port(PortError::Unavailable))
        })
    }

    fn get(
        &self,
        id: PendingId,
        account: AccountId,
    ) -> PendingFuture<'_, Result<Option<PendingAction>, PortError>> {
        Box::pin(async move {
            let row = self
                .0
                .store
                .pending(id.raw().to_be_bytes())
                .await
                .map_err(|_| PortError::Unavailable)?;
            // I-85: another account's action is not found.
            Ok(row
                .filter(|r| r.account == account.raw().to_be_bytes())
                .and_then(action_of))
        })
    }

    fn list(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<Vec<PendingAction>, PortError>> {
        let _ = now;
        Box::pin(async move {
            let rows = self
                .0
                .store
                .pending_of(account.raw().to_be_bytes())
                .await
                .map_err(|_| PortError::Unavailable)?;
            Ok(rows.into_iter().filter_map(action_of).collect())
        })
    }

    fn close(
        &self,
        id: PendingId,
        to: PendingStatus,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<bool, PortError>> {
        Box::pin(async move {
            let to = match to {
                PendingStatus::Expired => StoredPendingStatus::Expired,
                PendingStatus::Discarded => StoredPendingStatus::Discarded,
                PendingStatus::Open | PendingStatus::Confirmed => return Ok(false),
            };
            self.0
                .store
                .close_pending(id.raw().to_be_bytes(), to, now.micros())
                .await
                .map_err(|_| PortError::Unavailable)
        })
    }

    fn remove(&self, id: PendingId) -> PendingFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            self.0
                .store
                .delete_pending(id.raw().to_be_bytes())
                .await
                .map(|_| ())
                .map_err(|_| PortError::Unavailable)
        })
    }

    /// The engine wrote the confirmation row in the executing append, so
    /// this reads it.
    fn confirmed(
        &self,
        id: PendingId,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<bool, PortError>> {
        let _ = now;
        Box::pin(async move {
            let row = self
                .0
                .store
                .pending(id.raw().to_be_bytes())
                .await
                .map_err(|_| PortError::Unavailable)?;
            Ok(row.is_some_and(|r| r.confirmed.is_some()))
        })
    }
}

/// The largest blob the store keeps: 16 MiB. The import limits of the API
/// core are lower, so this bounds a caller that skips them.
const MAX_BLOB: usize = 16 * 1024 * 1024;

/// The `doc.blob` kinds of an import document and a brand asset, as the
/// retention sweep reads them (lane L39).
use crate::tasks::retention::{KIND_BRAND_ASSET, KIND_IMPORT_DOCUMENT};

/// The `doc.blob.kind` of a blob of `owner`.
const fn kind_of(owner: BlobOwner) -> i16 {
    match owner {
        BlobOwner::Programme(_) => KIND_IMPORT_DOCUMENT,
        BlobOwner::Brand => KIND_BRAND_ASSET,
    }
}

/// The owner kind byte and id sealed in front of a blob of `owner`: 1
/// and the programme id, or 2 and zero for the brand assets.
fn owner_tag(owner: BlobOwner) -> (u8, u128) {
    match owner {
        BlobOwner::Programme(p) => (1, p.raw()),
        BlobOwner::Brand => (2, 0),
    }
}

/// The form label sealed in front of a blob's owner and bytes.
const BLOB_FORM: &[u8; 8] = b"fstpblb1";

/// The sealed plaintext of a blob of `owner`: the form label, the owner
/// kind and id, then the bytes.
fn blob_plain(owner: BlobOwner, bytes: &[u8]) -> Vec<u8> {
    let (kind, id) = owner_tag(owner);
    let mut out = Vec::with_capacity(bytes.len().saturating_add(25));
    out.extend_from_slice(BLOB_FORM);
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// The bytes of `plain` when it is a blob of `owner`.
fn blob_body(owner: BlobOwner, plain: &[u8]) -> Option<&[u8]> {
    let (kind, want) = owner_tag(owner);
    let rest = plain.strip_prefix(BLOB_FORM.as_slice())?;
    let rest = rest.strip_prefix(&[kind][..])?;
    let id: [u8; 16] = rest.get(..16)?.try_into().ok()?;
    (u128::from_be_bytes(id) == want).then(|| rest.get(16..))?
}

/// The blob store over `doc.blob` (module documentation).
pub(crate) struct CellBlobs<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> CellBlobs<R, V> {
    /// The bytes of the blob `digest` of `owner`, or a refusal when it is
    /// another owner's, does not open, or does not hash to its address.
    async fn open(&self, owner: BlobOwner, digest: [u8; 32]) -> Result<Vec<u8>, PortError> {
        let (dek, envelope) = self
            .0
            .store
            .document(digest)
            .await
            .map_err(|_| PortError::Unavailable)?
            .ok_or(PortError::Refused)?;
        let plain = self
            .0
            .erasure
            .open_document(dek, envelope)
            .await
            .map_err(|_| PortError::Refused)?;
        let body = blob_body(owner, &plain).ok_or(PortError::Refused)?;
        if fstp_crypto::sha256(body) != digest {
            return Err(PortError::Refused);
        }
        Ok(body.to_vec())
    }
}

impl<R: Runtime, V: Send + Sync> BlobStore for CellBlobs<R, V> {
    /// Stores `bytes` of `owner` once under their SHA-256. The same bytes
    /// of the same owner give the same address and store nothing new. The
    /// same bytes of another owner are refused, since one digest holds one
    /// row (I-30). Interim, pending Daniel.
    async fn put(&self, owner: BlobOwner, bytes: &[u8]) -> Result<BlobRef, PortError> {
        if bytes.len() > MAX_BLOB {
            return Err(PortError::Refused);
        }
        let digest = fstp_crypto::sha256(bytes);
        let stored = self
            .0
            .store
            .document(digest)
            .await
            .map_err(|_| PortError::Unavailable)?;
        if stored.is_some() {
            return self.open(owner, digest).await.map(|_| BlobRef(digest));
        }
        let id: [u8; 16] = fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        let group: [u8; 16] = fstp_crypto::random_array().map_err(|_| PortError::Unavailable)?;
        self.0
            .erasure
            .add_group(group)
            .await
            .map_err(|_| PortError::Unavailable)?;
        let envelope = self
            .0
            .erasure
            .seal_document(group, id, blob_plain(owner, bytes))
            .await
            .map_err(|_| PortError::Unavailable)?;
        let inserted = self
            .0
            .store
            .put_document(digest, kind_of(owner), id, &envelope, self.0.now().micros())
            .await
            .map_err(|_| PortError::Unavailable)?;
        if !inserted {
            // Another call stored the same bytes first.
            self.open(owner, digest).await?;
        }
        Ok(BlobRef(digest))
    }

    /// The bytes of blob `r` of `owner`. The API core checked the read's
    /// clearance before it asked, as for the sealer.
    async fn get(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        clearance: &ReadClearance,
    ) -> Result<Vec<u8>, PortError> {
        let _ = clearance;
        self.open(owner, r.0).await
    }

    /// The bytes of brand asset `r` (ADR-030). The owner sealed in front
    /// of the bytes must be the brand, so no other blob is served.
    async fn get_brand(&self, r: BlobRef) -> Result<Vec<u8>, PortError> {
        self.open(BlobOwner::Brand, r.0).await
    }

    /// ADR-007 (Daniel, 2026-11-23, decisions 1c and 2; lane L39): erases
    /// an import document by its data key id, as tenant admin `by` asked
    /// with the reason text `reason`. A brand asset is refused, and so is
    /// a blob of another owner. A blob already erased, or whose row the
    /// runner deleted, is a no-op.
    async fn erase(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        by: AccountId,
        reason: TextRef,
    ) -> Result<(), PortError> {
        if matches!(owner, BlobOwner::Brand) {
            return Err(PortError::Refused);
        }
        let Some((dek, _)) = self
            .0
            .store
            .document(r.0)
            .await
            .map_err(|_| PortError::Unavailable)?
        else {
            // The row is gone: its erasure completed.
            return Ok(());
        };
        if self.0.engine.state().erasure(dek).is_some() {
            return Ok(());
        }
        // The owner sealed in front of the bytes must be `owner`.
        self.open(owner, r.0).await?;
        self.0
            .erasure
            .erase_document(
                dek,
                ErasureCause::ErasureRequest.code(),
                by,
                Some(reason.0.to_be_bytes()),
            )
            .await
            .map_err(|_| PortError::Unavailable)
    }

    /// Whether blob `r` is erased or under erasure: its row is gone, or
    /// the log has an entry for its data key (lane L39).
    async fn erased(&self, r: BlobRef) -> Result<bool, PortError> {
        Ok(
            match self
                .0
                .store
                .document(r.0)
                .await
                .map_err(|_| PortError::Unavailable)?
            {
                None => true,
                Some((dek, _)) => self.0.engine.state().erasure(dek).is_some(),
            },
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// I-85: the stored request decodes to the request a confirmation
    /// replays and the request the user was shown, unchanged.
    #[test]
    fn i85_stored_request_round_trips() {
        let a = PendingAction {
            id: PendingId::from_raw(1),
            account: AccountId::from_raw(2),
            agent: AgentClientId::from_raw(3),
            op: "programme.prepare_draft".to_owned(),
            request: "{\"op\":\"x\",\"request\":{}}".to_owned(),
            shown: "{\"name\":\"synthetic\"}".to_owned(),
            digest: ActionDigest([4; 32]),
            created: Timestamp::from_micros(5),
            expires: Timestamp::from_micros(6),
            status: PendingStatus::Open,
            closed: None,
        };
        let b = encode_request(&a);
        assert_eq!(
            decode_request(&b),
            Some((a.request.clone(), a.shown.clone()))
        );
        assert_eq!(decode_request(&b[..3]), None);
    }

    /// I-21, I-27: a text's class and owner travel with it, and a public
    /// text opens to any read while a proposal's text needs its clearance.
    #[test]
    fn i21_text_header_round_trips() {
        for owner in [
            TextOwner::Proposal(ProposalId::from_raw(9)),
            TextOwner::Programme(ProgrammeId::from_raw(8)),
            TextOwner::Tenant,
            TextOwner::Account(AccountId::from_raw(7)),
        ] {
            for class in [TextClass::Confidential, TextClass::Public] {
                let mut t = header(class, owner).to_vec();
                t.extend_from_slice(b"body");
                let (c, o, b) = parse(&t).unwrap();
                assert_eq!((c, o, b), (class, owner, &b"body"[..]));
            }
        }
        assert!(parse(&[0; 5]).is_none());
    }
}
