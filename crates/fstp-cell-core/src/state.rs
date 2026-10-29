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
use std::hash::{Hash, Hasher};

use fstp_auth::{CoseKey, RecoveryPath};

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

/// One registered credential, as its `CredentialRegistered` record names
/// it, with what later records say of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// The owning account.
    pub account: AccountId,
    /// The verified public key. A replay rebuilds the stored credential
    /// from it (design section 4.2).
    pub key: CoseKey,
    /// Whether the registration gave user verification (ADR-008).
    pub user_verified: bool,
    /// Whether a `CredentialRevoked` record revoked it.
    pub revoked: bool,
    /// Whether a `CredentialSuspect` record marked its sign count as gone
    /// down (ADR-008 "Sign counts").
    pub suspect: bool,
}

impl Hash for Credential {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.account.hash(h);
        // `CoseKey` implements no `Hash`. Its canonical COSE bytes name
        // it alone (`fstp_auth::codec::cose_key_bytes`).
        fstp_auth::codec::cose_key_bytes(&self.key).hash(h);
        self.user_verified.hash(h);
        self.revoked.hash(h);
        self.suspect.hash(h);
    }
}

/// A step-up as its `StepUpGranted` record names it, with the entry
/// instant of that record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StepUpGrant {
    /// The action digest it authorises (design section 8.4).
    pub action_digest: [u8; 32],
    /// The session it was made in. It authorises a command of that
    /// session only.
    pub session: [u8; 16],
    /// The entry instant of the `StepUpGranted` record. `POST
    /// /auth/stepup` records it once the assertion verified, so it is the
    /// logged assertion time. The gate checks P-71 against it as well as
    /// against the caller's view (design section 8.4).
    pub granted_at: Timestamp,
}

/// One recovery case, as its records name it (I-79, design section 8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoveryCase {
    /// The account to recover.
    pub account: AccountId,
    /// The path computed at request time. A completion recomputes it.
    pub requested: RecoveryPath,
    /// Whether the email proof was given.
    pub email_proven: bool,
    /// The second tenant admin who approved the case, if any.
    pub approver: Option<AccountId>,
    /// The path the case completed by, once it completed.
    pub completed: Option<RecoveryPath>,
}

/// One invitation, as its records name it (design section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Invitation {
    /// The invited account.
    pub account: AccountId,
    /// The SHA-256 digest of the token. The token itself is never stored.
    pub token_digest: [u8; 32],
    /// Whether it is the first tenant admin's invitation.
    pub first_admin: bool,
    /// Whether the token is drawn as two halves (Q35).
    pub split: bool,
    /// Whether an enrolment used it.
    pub consumed: bool,
}

/// The auth part: credentials, step-ups, ended sessions, recovery cases
/// and invitations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthState {
    credentials: BTreeMap<Vec<u8>, Credential>,
    stepups: BTreeMap<[u8; 16], StepUpGrant>,
    consumed: BTreeSet<[u8; 16]>,
    ended_sessions: BTreeSet<[u8; 16]>,
    recoveries: BTreeMap<[u8; 16], RecoveryCase>,
    invitations: BTreeMap<[u8; 16], Invitation>,
    first_admins: BTreeSet<AccountId>,
    recovered: BTreeMap<AccountId, Timestamp>,
}

impl AuthState {
    /// Whether `account` holds the live credential `credential`:
    /// registered to it and not revoked.
    pub fn has_credential(&self, account: AccountId, credential: &[u8]) -> bool {
        self.credentials
            .get(credential)
            .is_some_and(|c| c.account == account && !c.revoked)
    }

    /// Whether `account` holds any live credential.
    pub fn has_any_credential(&self, account: AccountId) -> bool {
        self.credentials
            .values()
            .any(|c| c.account == account && !c.revoked)
    }

    /// Whether a credential with id `credential` was ever registered, to
    /// any account and revoked or not. A new registration must not reuse
    /// it (WebAuthn Level 2 section 7.1 step 22,
    /// `fstp_auth::ceremony::check_new_id`).
    pub fn is_registered(&self, credential: &[u8]) -> bool {
        self.credentials.contains_key(credential)
    }

    /// The credential with id `credential`, if it was registered.
    pub fn credential(&self, credential: &[u8]) -> Option<&Credential> {
        self.credentials.get(credential)
    }

    /// The ids of the live credentials of `account`, in id order.
    ///
    /// A recovery completion revokes exactly these, as the credentials of
    /// `fstp_auth::recovery::Revocation` (I-79, design section 8.5). The
    /// fold refuses a second revocation of one credential, so a completion
    /// that also names a credential revoked earlier does not fold.
    pub fn live_credentials(&self, account: AccountId) -> Vec<Vec<u8>> {
        self.credentials
            .iter()
            .filter(|(_, c)| c.account == account && !c.revoked)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The owner and the stored credential of the live credential
    /// `credential`, with the sign count `sign_count` from the
    /// operational row (`AuthRecord::stored_credential`). `None` for a
    /// revoked or unknown credential.
    pub fn stored_credential(
        &self,
        credential: &[u8],
        sign_count: u32,
    ) -> Option<(AccountId, fstp_auth::StoredCredential)> {
        let c = self.credentials.get(credential).filter(|c| !c.revoked)?;
        Some((
            c.account,
            fstp_auth::StoredCredential {
                id: credential.to_vec(),
                key: c.key.clone(),
                sign_count,
            },
        ))
    }

    /// The action digest step-up `id` was granted for.
    pub fn stepup(&self, id: [u8; 16]) -> Option<[u8; 32]> {
        self.stepups.get(&id).map(|g| g.action_digest)
    }

    /// The grant of step-up `id`: its action digest and its session.
    pub fn stepup_grant(&self, id: [u8; 16]) -> Option<StepUpGrant> {
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

    /// Recovery case `case`, once it was requested.
    pub fn recovery(&self, case: [u8; 16]) -> Option<RecoveryCase> {
        self.recoveries.get(&case).copied()
    }

    /// Invitation `id`, once it was issued.
    pub fn invitation(&self, id: [u8; 16]) -> Option<Invitation> {
        self.invitations.get(&id).copied()
    }

    /// Whether `account` enrolled as the first tenant admin.
    pub fn first_admin_enrolled(&self, account: AccountId) -> bool {
        self.first_admins.contains(&account)
    }

    /// Whether a session of `account` that started at `started` began at or
    /// before the entry instant of the account's latest completed
    /// recovery (I-79, design section 8.5).
    ///
    /// A completion "ends every session of the account". Its batch names
    /// the sessions its route read, and the gate refuses the others from
    /// this check on, as it does for a binding end (design section 5.4
    /// step 1). The entry instant is the batch time, which the driver
    /// takes at admission. A login with an old credential between that
    /// instant and the commit starts after it, so this check does not
    /// refuse it. Only the login route can close that window.
    pub fn ended_by_recovery(&self, account: AccountId, started: Timestamp) -> bool {
        self.recovered
            .get(&account)
            .is_some_and(|completed| started <= *completed)
    }
}

/// A SoD-07 approval of one self-grant digest. A digest may hold several
/// approvals, each from its own `SelfGrantApproved` record.
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
    approvals: BTreeMap<[u8; 32], Vec<Approval>>,
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

    /// The approvals of `digest`, in ledger order. Empty when no admin
    /// approved it.
    ///
    /// SoD-07, Q40: a digest may hold several approvals. An approval that
    /// can never admit the grant, such as the grantor's own, must not
    /// block a later approval by a second tenant admin. So each
    /// `SelfGrantApproved` record adds one approval, and the grant uses
    /// the first that admits it (`fstp_celltest::reference::auth::admit_self_grant`).
    pub fn approvals(&self, digest: &[u8; 32]) -> &[Approval] {
        self.approvals.get(digest).map_or(&[], Vec::as_slice)
    }

    /// Whether a grant used an approval of `digest`. The digest names one
    /// command id, so one grant at most can match it, and a used digest
    /// takes no further approval (TH-05).
    pub fn digest_used(&self, digest: &[u8; 32]) -> bool {
        self.approvals(digest).iter().any(|a| a.used)
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
        !self.due_binding_ends(a, now).is_empty()
    }

    /// The scheduled end instants of `a`'s bindings that are due at `now`
    /// and that no record has ended yet, in instant order (design section
    /// 5.1, `EndSessionsAtBindingEnd`).
    pub fn due_binding_ends(&self, a: AccountId, now: Timestamp) -> Vec<Timestamp> {
        let mut out: Vec<Timestamp> = self
            .bindings
            .values()
            .filter(|b| b.account == a && b.recorded_end.is_none())
            .filter_map(|b| b.scheduled_end.filter(|e| *e <= now))
            .collect();
        out.sort();
        out.dedup();
        out
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
        CellRecord::Auth(r) => fold_auth(&mut s.auth, &s.tenant, at, r)?,
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

/// Folds an auth record. Structural, as every cell fold: ids must be new
/// where a record creates them and known where a record names them.
///
/// - A credential id is registered once, to one account, for good. A
///   revocation or a suspect mark names a credential of that account, and
///   a credential is revoked once. So a recovery completion revokes the
///   live credentials only, [`AuthState::live_credentials`]. A batch that
///   revokes a credential again does not fold.
/// - A step-up is granted once, at the entry instant `at`, and consumed
///   once. A consumption names a granted step-up: every step-up is
///   logged with the action it authorised (I-78, design section 8.4), so
///   a consumption with no grant is refused as unknown.
/// - A recovery case is requested once. Its email proof, its approval and
///   its completion each name an open case, once. An approval follows the
///   email proof (design section 8.5), and a completion names the case's
///   own account.
/// - A completion names a path whose recorded evidence the case holds
///   (I-79, design section 8.5): the email proof for every path but
///   `HostConsole`, and an approval as well for `SecondAdmin`. The fold
///   checks only what the records state. The approval's step-up outcome
///   and identity answers, the operator ticket and the host console
///   command are in no auth record, so `fstp_auth::recovery::complete`
///   on the completion route checks them (lane W3a).
/// - The path is taken from the completion record, which recomputes it,
///   so it may differ from the requested path. The fold refuses a path
///   that the current tenant admins rule out (`path_fits_admins`). It
///   cannot see the roster's management roles or the deployment mode. So
///   only the W3a completion route, through `fstp_auth::recovery::complete`,
///   tells `OperatorProcess` from `HostConsole`, and `EmailThenPasskey`
///   from a management path for an account that is no tenant admin. That
///   route builds its `TenantView` from this fold's tenant admins, as
///   `decide` does.
/// - An invitation is issued once and consumed once.
fn fold_auth(
    a: &mut AuthState,
    tenant: &TenantState,
    at: Timestamp,
    r: &fstp_auth::AuthRecord,
) -> Result<(), FoldError> {
    use fstp_auth::AuthRecord as R;
    match r {
        R::CredentialRegistered {
            account,
            credential,
            key,
            user_verified,
        } => {
            if a.credentials.contains_key(credential) {
                return Err(duplicate());
            }
            a.credentials.insert(
                credential.clone(),
                Credential {
                    account: *account,
                    key: key.clone(),
                    user_verified: *user_verified,
                    revoked: false,
                    suspect: false,
                },
            );
        }
        R::CredentialRevoked {
            account,
            credential,
        } => {
            let c = a.credentials.get_mut(credential).ok_or_else(unknown)?;
            if c.account != *account {
                return Err(inconsistent());
            }
            if c.revoked {
                return Err(duplicate());
            }
            c.revoked = true;
        }
        R::CredentialSuspect {
            account,
            credential,
        } => {
            let c = a.credentials.get_mut(credential).ok_or_else(unknown)?;
            if c.account != *account {
                return Err(inconsistent());
            }
            c.suspect = true;
        }
        R::StepUpGranted {
            id,
            action_digest,
            session,
        } => {
            if a.stepups.contains_key(id) {
                return Err(duplicate());
            }
            a.stepups.insert(
                *id,
                StepUpGrant {
                    action_digest: *action_digest,
                    session: *session,
                    granted_at: at,
                },
            );
        }
        R::StepUpConsumed { id } => {
            if !a.stepups.contains_key(id) {
                return Err(unknown());
            }
            if !a.consumed.insert(*id) {
                return Err(duplicate());
            }
        }
        R::SessionEnded { session } => {
            a.ended_sessions.insert(*session);
        }
        R::RecoveryRequested {
            case,
            account,
            path,
        } => {
            if a.recoveries.contains_key(case) {
                return Err(duplicate());
            }
            a.recoveries.insert(
                *case,
                RecoveryCase {
                    account: *account,
                    requested: *path,
                    email_proven: false,
                    approver: None,
                    completed: None,
                },
            );
        }
        R::RecoveryEmailProven { case } => {
            let c = open_case(a, case)?;
            if c.email_proven {
                return Err(duplicate());
            }
            c.email_proven = true;
        }
        R::RecoveryApproved { case, approver } => {
            let c = open_case(a, case)?;
            if !c.email_proven {
                return Err(inconsistent());
            }
            if c.approver.is_some() {
                return Err(duplicate());
            }
            c.approver = Some(*approver);
        }
        R::RecoveryCompleted {
            case,
            account,
            path,
            ..
        } => {
            let c = a.recoveries.get_mut(case).ok_or_else(unknown)?;
            if c.completed.is_some() {
                return Err(duplicate());
            }
            if c.account != *account {
                return Err(inconsistent());
            }
            if !path_fits_admins(tenant, *account, *path) || !recorded_evidence_completes(c, *path)
            {
                return Err(inconsistent());
            }
            c.completed = Some(*path);
            // The latest completion of the account, for the gate (I-79).
            let latest = a.recovered.entry(*account).or_insert(at);
            *latest = (*latest).max(at);
        }
        R::InvitationIssued {
            invitation,
            account,
            token_digest,
            first_admin,
            split,
        } => {
            if a.invitations.contains_key(invitation) {
                return Err(duplicate());
            }
            a.invitations.insert(
                *invitation,
                Invitation {
                    account: *account,
                    token_digest: *token_digest,
                    first_admin: *first_admin,
                    split: *split,
                    consumed: false,
                },
            );
        }
        R::InvitationConsumed { invitation } => {
            let i = a.invitations.get_mut(invitation).ok_or_else(unknown)?;
            if i.consumed {
                return Err(duplicate());
            }
            i.consumed = true;
        }
        R::FirstAdminEnrolled { account } => {
            if !a.first_admins.insert(*account) {
                return Err(duplicate());
            }
        }
    }
    Ok(())
}

/// Whether the recorded evidence of case `c` covers a completion by
/// `path`, as far as auth records state it (I-79, design section 8.5,
/// `fstp_auth::recovery::decide`). Every path but `HostConsole` needs the
/// email proof, and `SecondAdmin` needs an approval as well.
fn recorded_evidence_completes(c: &RecoveryCase, path: RecoveryPath) -> bool {
    match path {
        RecoveryPath::EmailThenPasskey | RecoveryPath::OperatorProcess => c.email_proven,
        RecoveryPath::SecondAdmin => c.email_proven && c.approver.is_some(),
        RecoveryPath::HostConsole => true,
    }
}

/// Whether the path table of `fstp_auth::recovery::path_of` can give
/// `path` for `account` with the current tenant admins of `tenant` (I-79,
/// design section 8.5). The fold sees the tenant admins but neither the
/// roster's management roles nor the deployment mode. So it tries every
/// holdings class that the admin set leaves open, and both modes.
///
/// A completion recomputes its path at completion, so the path may differ
/// from the requested one. This check refuses only a path that no roster
/// and no mode could give with these admins. For example, it refuses
/// `HostConsole` or `OperatorProcess` while another tenant admin exists,
/// and `SecondAdmin` while none does.
fn path_fits_admins(tenant: &TenantState, account: AccountId, path: RecoveryPath) -> bool {
    use fstp_auth::recovery::{Deployment, Holdings, path_of};
    let others = tenant.admins.keys().filter(|a| **a != account).count();
    let holdings: &[Holdings] = if tenant.is_admin(account) {
        &[Holdings::TenantAdmin]
    } else {
        &[Holdings::ReceivingOnly, Holdings::Management]
    };
    holdings.iter().any(|h| {
        [Deployment::Saas, Deployment::SelfHosted]
            .iter()
            .any(|m| path_of(*h, others, *m) == path)
    })
}

/// The open recovery case `case`: requested and not completed.
fn open_case<'a>(a: &'a mut AuthState, case: &[u8; 16]) -> Result<&'a mut RecoveryCase, FoldError> {
    let c = a.recoveries.get_mut(case).ok_or_else(unknown)?;
    if c.completed.is_some() {
        return Err(inconsistent());
    }
    Ok(c)
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
            // A used digest named one command, which committed, so no
            // later approval of it can admit anything (TH-05).
            if t.digest_used(grant_digest) {
                return Err(duplicate());
            }
            t.approvals
                .entry(*grant_digest)
                .or_default()
                .push(Approval {
                    approver: *approver,
                    expires_at: *expires_at,
                    used: false,
                });
        }
        TenantRecord::SelfGrantApprovalUsed { grant_digest } => {
            if t.digest_used(grant_digest) {
                return Err(duplicate());
            }
            let all = t.approvals.get_mut(grant_digest).ok_or_else(unknown)?;
            // Every approval of the digest is spent with it: the digest
            // holds the command id, so it names one grant only.
            for a in all.iter_mut() {
                a.used = true;
            }
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
