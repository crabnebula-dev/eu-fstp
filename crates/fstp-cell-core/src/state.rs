//! The cell state and its fold (I-23, design sections 2.2 and 5.1).
//!
//! - The M2 part is `fstp_engine::EngineState`, folded by
//!   `fstp_engine::apply` record for record. A ledger of M2 records alone
//!   folds to the M2 state and is refused exactly where M2 refuses it.
//! - The cell parts fold the auth, tenant, text, key, release and ops
//!   records. Each fold is structural: it checks ids and references, never
//!   a guard.
//! - The fold keeps the ledger head and the latest recorded time across
//!   every member, so sequence numbers run from 1 without gaps and the
//!   ledger stays time-monotone (design section 2.2).
//! - It also indexes, from the M2 records, what the gate needs and the M2
//!   projection does not keep: the end instants of bindings, recorded or
//!   scheduled, the instants of their suspensions and voidings, and the
//!   call and lead of each proposal. It indexes the reactions to vault
//!   epochs by their reserved command ids (NOTE 4), and every committed
//!   command id, so a crash retry finds its stored result (ADR-007).
//!
//! On a refusal the state may be partly folded, as with
//! `fstp_engine::apply`, so callers fold into a copy.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::FoldError as DomainFold;
use fstp_domain::id::{AccountId, BindingId, CallId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;

use crate::ops::OpsRecord;
use crate::release::ReleaseRecord;
use crate::tenant::{TenantLoginPolicy, TenantRecord};
use crate::text::TextRecord;
use crate::{CellRecord, FoldError, KeyRecord};

/// The first bytes of every command id the driver issues itself: a
/// reaction to a vault epoch is this prefix followed by the epoch,
/// big-endian (`fstp_engine::RESERVED_COMMAND_PREFIX`).
pub const RESERVED_PREFIX: [u8; 8] = fstp_engine::RESERVED_COMMAND_PREFIX;

/// The first bytes of every command id of a system task
/// ([`crate::SystemTask`]). `DriverCore` refuses an account command under
/// such an id, and a system task's command under any other. So an account
/// can never commit first under an id a task will use, and a task's crash
/// retry finds only its own entry (ADR-007, design section 5.2).
///
/// Interim, for Daniel's review: the tasks have no id scheme yet. This
/// namespace keeps the two kinds of caller apart until one exists.
pub const SYSTEM_PREFIX: [u8; 8] = *b"fstp:st:";

/// Whether `command` is in the system task namespace [`SYSTEM_PREFIX`].
pub fn is_system_command_id(command: [u8; 16]) -> bool {
    command.starts_with(&SYSTEM_PREFIX)
}

/// The system task command id with `suffix` after [`SYSTEM_PREFIX`].
pub fn system_command_id(suffix: [u8; 8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    let (head, tail) = id.split_at_mut(SYSTEM_PREFIX.len());
    head.copy_from_slice(&SYSTEM_PREFIX);
    tail.copy_from_slice(&suffix);
    id
}

/// The epoch a reserved reaction command id names, or `None` for any
/// other id.
pub fn reaction_epoch(command: [u8; 16]) -> Option<u64> {
    let (head, tail) = command.split_at(RESERVED_PREFIX.len());
    if head != RESERVED_PREFIX {
        return None;
    }
    <[u8; 8]>::try_from(tail).ok().map(u64::from_be_bytes)
}

/// The reserved command id of the reaction to `epoch`.
pub fn reaction_command_id(epoch: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    let (head, tail) = id.split_at_mut(RESERVED_PREFIX.len());
    head.copy_from_slice(&RESERVED_PREFIX);
    tail.copy_from_slice(&epoch.to_be_bytes());
    id
}

/// The auth part: credentials, step-ups and ended sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthState {
    credentials: BTreeSet<(AccountId, Vec<u8>)>,
    stepups: BTreeMap<[u8; 16], [u8; 32]>,
    consumed: BTreeSet<[u8; 16]>,
    ended_sessions: BTreeSet<[u8; 16]>,
}

impl AuthState {
    /// Whether `account` registered `credential`.
    pub fn has_credential(&self, account: AccountId, credential: &[u8]) -> bool {
        self.credentials.contains(&(account, credential.to_vec()))
    }

    /// Whether `account` holds any credential.
    pub fn has_any_credential(&self, account: AccountId) -> bool {
        self.credentials.iter().any(|(a, _)| *a == account)
    }

    /// The action digest step-up `id` was granted for.
    pub fn stepup(&self, id: [u8; 16]) -> Option<[u8; 32]> {
        self.stepups.get(&id).copied()
    }

    /// Whether a batch consumed step-up `id`.
    pub fn consumed(&self, id: [u8; 16]) -> bool {
        self.consumed.contains(&id)
    }

    /// Whether a record ended session `id`.
    pub fn session_ended(&self, id: [u8; 16]) -> bool {
        self.ended_sessions.contains(&id)
    }
}

/// A SoD-07 approval of one self-grant digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Approval {
    /// The approving tenant admin.
    pub approver: AccountId,
    /// UTC microseconds of its last valid instant.
    pub expires_at: i64,
    /// Whether a grant used it.
    pub used: bool,
}

/// The tenant part: tenant admins, SoD-07 approvals and the login policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TenantState {
    admins: BTreeMap<AccountId, Timestamp>,
    ever_admin: bool,
    admin_ends: Vec<(AccountId, Timestamp)>,
    approvals: BTreeMap<[u8; 32], Approval>,
    policy: TenantLoginPolicy,
}

impl TenantState {
    /// Whether `a` is a current tenant admin.
    pub fn is_admin(&self, a: AccountId) -> bool {
        self.admins.contains_key(&a)
    }

    /// Whether the cell ever had a tenant admin, current or ended.
    pub fn ever_had_admin(&self) -> bool {
        self.ever_admin
    }

    /// The current tenant admins, in id order.
    pub fn admins(&self) -> Vec<AccountId> {
        self.admins.keys().copied().collect()
    }

    /// The approval of `digest`, if any.
    pub fn approval(&self, digest: &[u8; 32]) -> Option<Approval> {
        self.approvals.get(digest).copied()
    }

    /// The tenant login policy, the defaults until one is set.
    pub fn policy(&self) -> TenantLoginPolicy {
        self.policy
    }

    /// Whether a tenant admin grant of `a` ended at an instant after
    /// `after` and at or before `upto`.
    pub fn admin_ended_between(&self, a: AccountId, after: Timestamp, upto: Timestamp) -> bool {
        self.admin_ends
            .iter()
            .any(|(x, at)| *x == a && after < *at && *at <= upto)
    }
}

/// Whether a text is live or erased.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextStatus {
    /// Stored and readable.
    Live,
    /// Erased: its reference resolves to its erasure-log entry.
    Erased,
}

/// The erasure-log entry of one text (ADR-007, design section 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErasureEntry {
    /// When the erasure was requested.
    pub requested_at: Timestamp,
    /// When the erasure completed, once it did.
    pub completed_at: Option<Timestamp>,
    /// The cause, as a closed code.
    pub cause: u16,
    /// The account that authorised the erasure.
    pub by: AccountId,
}

/// What the gate needs of one binding that the M2 roster does not keep.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BindingFacts {
    account: AccountId,
    recorded_end: Option<Timestamp>,
    scheduled_end: Option<Timestamp>,
    /// The instants of the binding's suspensions and of its voiding.
    lapses: Vec<Timestamp>,
}

impl BindingFacts {
    /// The end instant: the recorded end, or else the scheduled one.
    fn end(&self) -> Option<Timestamp> {
        self.recorded_end.or(self.scheduled_end)
    }

    /// Every instant at which the binding stopped counting for a session:
    /// its end, recorded or scheduled, and each suspension or voiding
    /// (design section 5.1 "Reactions", Q16 A).
    fn stops(&self) -> impl Iterator<Item = Timestamp> + '_ {
        self.end().into_iter().chain(self.lapses.iter().copied())
    }
}

/// The state of a cell, folded from its ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CellState {
    pub(crate) engine: fstp_engine::EngineState,
    pub(crate) head: Seq,
    pub(crate) floor: Timestamp,
    pub(crate) auth: AuthState,
    pub(crate) tenant: TenantState,
    pub(crate) texts: BTreeMap<[u8; 16], TextStatus>,
    erasures: BTreeMap<[u8; 16], ErasureEntry>,
    pub(crate) key_ops: u64,
    pub(crate) destroyed_epochs: BTreeSet<u64>,
    pub(crate) tickets: BTreeSet<[u8; 16]>,
    pub(crate) break_glass: BTreeMap<[u8; 16], bool>,
    bindings: BTreeMap<BindingId, BindingFacts>,
    proposals: BTreeMap<ProposalId, (CallId, AccountId)>,
    reactions: BTreeMap<u64, Seq>,
    commands: BTreeMap<[u8; 16], Seq>,
}

impl CellState {
    /// The state before any record.
    pub fn genesis() -> CellState {
        CellState {
            engine: fstp_engine::EngineState::genesis(),
            head: Seq::ZERO,
            floor: Timestamp::from_micros(0),
            auth: AuthState::default(),
            tenant: TenantState::default(),
            texts: BTreeMap::new(),
            erasures: BTreeMap::new(),
            key_ops: 0,
            destroyed_epochs: BTreeSet::new(),
            tickets: BTreeSet::new(),
            break_glass: BTreeMap::new(),
            bindings: BTreeMap::new(),
            proposals: BTreeMap::new(),
            reactions: BTreeMap::new(),
            commands: BTreeMap::new(),
        }
    }

    /// The M2 engine state.
    pub fn engine(&self) -> &fstp_engine::EngineState {
        &self.engine
    }

    /// The sequence number of the last entry folded.
    pub fn head(&self) -> Seq {
        self.head
    }

    /// The latest recorded time of any member (design section 2.2).
    pub fn now_floor(&self) -> Timestamp {
        self.floor
    }

    /// The auth part.
    pub fn auth(&self) -> &AuthState {
        &self.auth
    }

    /// The tenant part.
    pub fn tenant(&self) -> &TenantState {
        &self.tenant
    }

    /// The status of text `id`, if it was stored.
    pub fn text(&self, id: [u8; 16]) -> Option<TextStatus> {
        self.texts.get(&id).copied()
    }

    /// The erasure-log entry of text `id`, once its erasure was requested.
    /// A text with an entry resolves to the entry, never to the text.
    pub fn erasure(&self, id: [u8; 16]) -> Option<ErasureEntry> {
        self.erasures.get(&id).copied()
    }

    /// Whether root epoch `epoch` was recorded as destroyed.
    pub fn epoch_destroyed(&self, epoch: u64) -> bool {
        self.destroyed_epochs.contains(&epoch)
    }

    /// Whether ticket `id` was issued.
    pub fn ticket_issued(&self, id: [u8; 16]) -> bool {
        self.tickets.contains(&id)
    }

    /// Whether break-glass grant `grant` was ever approved.
    pub fn break_glass_known(&self, grant: [u8; 16]) -> bool {
        self.break_glass.contains_key(&grant)
    }

    /// Whether break-glass grant `grant` was approved and has not ended.
    pub fn break_glass_active(&self, grant: [u8; 16]) -> bool {
        self.break_glass.get(&grant).copied().unwrap_or(false)
    }

    /// The last sequence number of the committed reaction to vault epoch
    /// `epoch`, found by its reserved command id (NOTE 4, design section
    /// 5.2).
    pub fn reaction_to(&self, epoch: u64) -> Option<Seq> {
        self.reactions.get(&epoch).copied()
    }

    /// The sequence number of the last entry committed under `command`,
    /// if any. A crash retry under the same id finds its stored result
    /// here once the driver caught up (ADR-007, design section 5.2).
    pub fn committed(&self, command: [u8; 16]) -> Option<Seq> {
        self.commands.get(&command).copied()
    }

    /// The call a proposal was created in and its lead, from its
    /// `ProposalCreated` record.
    pub fn proposal(&self, p: ProposalId) -> Option<(CallId, AccountId)> {
        self.proposals.get(&p).copied()
    }

    /// Whether any binding of `a` ended at an instant after `after` and at
    /// or before `upto`, by a recorded end, a scheduled one, a suspension
    /// or a voiding. A tenant admin grant of `a` that ended then counts too
    /// (design sections 5.1, 5.4 and 8.2, Q16 A).
    ///
    /// Every group counts, Receiving too, since the rule names "any
    /// binding of the account" and "by any cause". A later recorded end
    /// replaces a scheduled one, and a later schedule replaces an earlier
    /// one. A reinstatement does not undo a suspension for a session that
    /// started before the suspension.
    pub fn binding_ended_between(&self, a: AccountId, after: Timestamp, upto: Timestamp) -> bool {
        self.bindings
            .values()
            .filter(|b| b.account == a)
            .flat_map(BindingFacts::stops)
            .any(|e| after < e && e <= upto)
            || self.tenant.admin_ended_between(a, after, upto)
    }

    /// Whether a binding of `a` has an end instant at or before `now`
    /// that a record has not ended yet: a scheduled end that is due
    /// (design section 5.1, `EndSessionsAtBindingEnd`).
    pub fn binding_end_due(&self, a: AccountId, now: Timestamp) -> bool {
        self.bindings.values().any(|b| {
            b.account == a && b.recorded_end.is_none() && b.scheduled_end.is_some_and(|e| e <= now)
        })
    }
}

/// Folds one record at `seq` and `at`, appended under `command`.
pub(crate) fn fold(
    s: &mut CellState,
    seq: Seq,
    at: Timestamp,
    command: [u8; 16],
    record: &CellRecord,
) -> Result<(), FoldError> {
    let expected = s
        .head
        .raw()
        .checked_add(1)
        .ok_or(FoldError::Engine(DomainFold::OutOfOrder))?;
    if seq.raw() != expected {
        return Err(FoldError::Engine(DomainFold::OutOfOrder));
    }
    if at < s.floor {
        return Err(FoldError::Engine(DomainFold::TimeBackwards));
    }
    match record {
        CellRecord::Engine(r) => {
            fstp_engine::apply(&mut s.engine, seq, at, r).map_err(FoldError::Engine)?;
            index_engine(s, at, r);
        }
        CellRecord::Auth(r) => fold_auth(&mut s.auth, r)?,
        CellRecord::Tenant(r) => fold_tenant(&mut s.tenant, at, r)?,
        CellRecord::Text(r) => fold_text(s, at, r)?,
        CellRecord::Key(r) => fold_key(s, r)?,
        CellRecord::Release(r) => fold_release(&mut s.tickets, r)?,
        CellRecord::Ops(r) => fold_ops(&mut s.break_glass, r)?,
    }
    if let Some(epoch) = reaction_epoch(command) {
        s.reactions.insert(epoch, seq);
    }
    s.commands.insert(command, seq);
    s.head = seq;
    s.floor = s.floor.max(at);
    Ok(())
}

fn duplicate() -> FoldError {
    FoldError::Engine(DomainFold::DuplicateId)
}

fn unknown() -> FoldError {
    FoldError::Engine(DomainFold::UnknownEntity)
}

fn inconsistent() -> FoldError {
    FoldError::Engine(DomainFold::Inconsistent)
}

/// Indexes the binding ends and proposals of an M2 record that folded.
fn index_engine(s: &mut CellState, at: Timestamp, r: &fstp_engine::Record) {
    use fstp_domain::Record as R;
    let fstp_engine::Record::Core(core) = r else {
        return;
    };
    match core {
        R::BindingGranted(g) => {
            s.bindings.insert(
                g.binding,
                BindingFacts {
                    account: g.account,
                    recorded_end: None,
                    scheduled_end: None,
                    lapses: Vec::new(),
                },
            );
        }
        R::BindingEnded(e) => {
            if let Some(b) = s.bindings.get_mut(&e.binding) {
                b.recorded_end = Some(e.at);
            }
        }
        R::BindingEndScheduled { binding, at } => {
            if let Some(b) = s.bindings.get_mut(binding) {
                b.scheduled_end = Some(*at);
            }
        }
        // A suspension or a voiding takes effect at the instant of its
        // entry, the reaction to the vault epoch that caused it.
        R::BindingSuspended(fstp_domain::record::BindingSuspended { binding, .. })
        | R::BindingVoided(fstp_domain::record::BindingVoided { binding, .. }) => {
            if let Some(b) = s.bindings.get_mut(binding) {
                b.lapses.push(at);
            }
        }
        R::ProposalCreated {
            proposal,
            call,
            lead,
            ..
        } => {
            s.proposals.insert(*proposal, (*call, *lead));
        }
        _ => {}
    }
}

fn fold_auth(a: &mut AuthState, r: &fstp_auth::AuthRecord) -> Result<(), FoldError> {
    use fstp_auth::AuthRecord as R;
    match r {
        R::CredentialRegistered {
            account,
            credential,
        } => {
            if !a.credentials.insert((*account, credential.clone())) {
                return Err(duplicate());
            }
        }
        R::StepUpGranted { id, action_digest } => {
            if a.stepups.insert(*id, *action_digest).is_some() {
                return Err(duplicate());
            }
        }
        R::SessionEnded { session } => {
            a.ended_sessions.insert(*session);
        }
    }
    Ok(())
}

fn fold_tenant(t: &mut TenantState, at: Timestamp, r: &TenantRecord) -> Result<(), FoldError> {
    match r {
        // Grants and ends are idempotent: a grant to a current admin keeps
        // the first grant, and an end of an account that is no admin ends
        // nothing. The fold checks structure, never a guard.
        TenantRecord::TenantAdminGranted { account } => {
            t.admins.entry(*account).or_insert(at);
            t.ever_admin = true;
        }
        TenantRecord::TenantAdminEnded { account } => {
            if t.admins.remove(account).is_some() {
                t.admin_ends.push((*account, at));
            }
        }
        TenantRecord::SelfGrantApproved {
            approver,
            grant_digest,
            expires_at,
        } => {
            if t.approvals.get(grant_digest).is_some_and(|a| a.used) {
                return Err(duplicate());
            }
            t.approvals.insert(
                *grant_digest,
                Approval {
                    approver: *approver,
                    expires_at: *expires_at,
                    used: false,
                },
            );
        }
        TenantRecord::SelfGrantApprovalUsed { grant_digest } => {
            let a = t.approvals.get_mut(grant_digest).ok_or_else(unknown)?;
            if a.used {
                return Err(duplicate());
            }
            a.used = true;
        }
        TenantRecord::LoginPolicySet { policy } => {
            // Structure only: "may only shorten" applies where a value is
            // used, so replay does not depend on this build's defaults
            // (I-23, Q37).
            t.policy = TenantLoginPolicy::decode_stored(policy).map_err(|_| inconsistent())?;
        }
    }
    Ok(())
}

fn fold_text(s: &mut CellState, at: Timestamp, r: &TextRecord) -> Result<(), FoldError> {
    let texts = &mut s.texts;
    match r {
        TextRecord::TextPut { id } => {
            if texts.contains_key(id) {
                return Err(duplicate());
            }
            texts.insert(*id, TextStatus::Live);
        }
        TextRecord::TextsErased { ids } => {
            if ids.is_empty() {
                return Err(inconsistent());
            }
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(*id) {
                    return Err(duplicate());
                }
                if texts.get(id) != Some(&TextStatus::Live) {
                    return Err(unknown());
                }
            }
            for id in ids {
                texts.insert(*id, TextStatus::Erased);
                if let Some(e) = s.erasures.get_mut(id) {
                    e.completed_at = Some(at);
                }
            }
        }
        TextRecord::ErasureRequested { ids, cause, by } => {
            if ids.is_empty() {
                return Err(inconsistent());
            }
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(*id) || s.erasures.contains_key(id) {
                    return Err(duplicate());
                }
                if texts.get(id) != Some(&TextStatus::Live) {
                    return Err(unknown());
                }
            }
            for id in ids {
                s.erasures.insert(
                    *id,
                    ErasureEntry {
                        requested_at: at,
                        completed_at: None,
                        cause: *cause,
                        by: *by,
                    },
                );
            }
        }
    }
    Ok(())
}

fn fold_key(s: &mut CellState, r: &KeyRecord) -> Result<(), FoldError> {
    match r {
        KeyRecord::KeyOpRecorded { .. } => {
            s.key_ops = s.key_ops.checked_add(1).ok_or_else(inconsistent)?;
        }
        KeyRecord::EpochDestroyed { epoch, .. } => {
            if !s.destroyed_epochs.insert(*epoch) {
                return Err(duplicate());
            }
        }
    }
    Ok(())
}

fn fold_release(tickets: &mut BTreeSet<[u8; 16]>, r: &ReleaseRecord) -> Result<(), FoldError> {
    match r {
        ReleaseRecord::TicketIssued { id, .. }
        | ReleaseRecord::IdentityReleaseIssued { id, .. } => {
            if !tickets.insert(*id) {
                return Err(duplicate());
            }
        }
    }
    Ok(())
}

fn fold_ops(grants: &mut BTreeMap<[u8; 16], bool>, r: &OpsRecord) -> Result<(), FoldError> {
    match r {
        OpsRecord::BreakGlassApproved { grant } => {
            if grants.contains_key(grant) {
                return Err(duplicate());
            }
            grants.insert(*grant, true);
        }
        OpsRecord::BreakGlassEnded { grant } => match grants.get_mut(grant) {
            Some(active) if *active => *active = false,
            _ => return Err(unknown()),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NOTE 4, design section 5.2: a reaction's reserved command id names
    /// its epoch, and no other id names one.
    #[test]
    fn adr007_reaction_command_id_names_its_epoch() {
        for epoch in [0, 1, 7, u64::MAX] {
            assert_eq!(reaction_epoch(reaction_command_id(epoch)), Some(epoch));
        }
        assert_eq!(reaction_epoch([0x5A; 16]), None);
        let mut id = reaction_command_id(3);
        id[0] = b'g';
        assert_eq!(reaction_epoch(id), None);
    }
}
