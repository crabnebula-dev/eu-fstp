//! Programmes and calls (design section 2.5, R-PC-01 to R-PC-03).
//!
//! Owned by lane L-POL (docs/handoff/m2-design.md section 10), with the M4
//! changes D1 to D3 and D12 of lane L-DOM (M4 design section 3.4).
//!
//! - A programme is DRAFT from `CreateProgramme` until the core
//!   `ActivateProgramme` makes it ACTIVE, once (D1, D2). On a draft only
//!   policy edits and programme manager grants run. `DraftCall`,
//!   `EditCall`, `ApproveCallPublication`, `PublishCall` and `CreateDraft`
//!   are refused with `RuleRef::I66` and `WrongState`, because the
//!   programme has not passed the activation that I-66 gates (D3,
//!   interim, pending Daniel). The projection keeps the core builder set
//!   of each draft for the I-67 guard in `crate::policy::activation`.
//! - A call is DRAFT, APPROVED or PUBLISHED. Open and closed derive from
//!   time (`SPEC/02-domain/state-machine.md` Call states, Q14 A).
//! - The drafters of a call are its authors plus the last authors of P-01
//!   and P-09 in the version it would freeze (R-PC-03 NOTE, Q14 A). The
//!   fold of `CallPublished` fixes that set for the published call.
//!   `ApproveCallPublication` needs a programme manager outside that set.
//! - An approval covers the call text and the criteria as they were. An
//!   edit of the call, or a policy edit that changes P-01 or P-09, ends it,
//!   and the call is DRAFT again.
//! - `PublishCall` freezes the programme head, assigns the next call
//!   sequence number of the programme and pins the LLM configuration. Its
//!   model must equal the frozen P-21 primary (R-LA-05, P-21 NOTE 10). The
//!   call budget is fixed from then on and is display-only (Q14 A).
//! - Each published call keeps an effective-limits record of P-05 and
//!   P-13: the publication snapshot plus one numbered tightening per later
//!   policy edit that lowers the effective P-05 or adds an effective P-13
//!   class (NOTE 7, O-52, D12, Q37 C interim, pending Daniel). Each
//!   tightening names its version and the effective values after it.
//! - After a tightening, a loosening of the live value raises the value
//!   that NOTE 7 enforcement reads, back towards the snapshot. Such an
//!   edit appends a numbered entry too, so the record's current values
//!   always equal the enforced ones, which I-51 needs (interim, pending
//!   Daniel). The other reading, an enforcement that never loosens again,
//!   would depart from the NOTE 7 enforcement rule.

use core::cmp::Ordering;
use core::num::NonZeroU32;
use std::collections::{BTreeMap, BTreeSet};

use fstp_money::NonNegAmount;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{
    AccountId, CallId, CallSeq, ContentDigest, DecisionId, LlmConfigId, PolicyVersionId,
    ProgrammeId, TextRef,
};
use crate::oracle::{Answers, Query};
use crate::policy::{
    ExclusionClasses, FrozenPolicy, LiveSnapshot, PolicyVersion, actor_account, require_holder,
};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::state::{State, UsedId};
use crate::time::{Timestamp, ZoneName};

/// The programme states (M4 change D1, interim, pending Daniel).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgrammeStatus {
    /// Created and being built. Only policy edits and programme manager
    /// grants run (D3).
    Draft,
    /// Activated by a second person who did not build it (I-66, I-67).
    Active,
}

/// One programme's status and core builder set, as the projection holds them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProgrammeView {
    status: ProgrammeStatus,
    /// The creator, every policy author and every grantor while the
    /// programme was a draft (I-67, Q1 A). Fixed at activation.
    builders: BTreeSet<AccountId>,
}

/// Whether a command meets the draft gate of D3. `GrantRole` previews run
/// the SoD guards without it (`crate::roles::preview_grant`, Q13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DraftGate {
    /// The command is refused on a draft programme.
    Enforce,
    /// The gate is skipped, for a preview that records nothing.
    Skip,
}

/// One numbered change of a published call's effective limits after its
/// publication (P-05 and P-13 NOTE 7, O-52, D12). It is a tightening, or a
/// loosening back towards the snapshot after an earlier tightening
/// (interim, pending Daniel). Comparing it with the entry before tells
/// which.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tightening {
    /// The corrigendum number, from 1 in edit order.
    pub corrigendum: NonZeroU32,
    /// The policy version whose live values changed the limits.
    pub version: PolicyVersionId,
    /// The effective P-05 after the edit: the lower of the snapshot and
    /// the live value.
    pub p05: NonNegAmount,
    /// The effective P-13 after the edit: every class of the snapshot or
    /// the live value.
    pub p13: ExclusionClasses,
}

/// The effective-limits record of one published call (NOTE 7, D12, I-51):
/// the publication snapshot and every later change, in order. Its current
/// values equal the values enforcement reads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EffectiveLimits {
    publication: LiveSnapshot,
    tightenings: Vec<Tightening>,
}

impl EffectiveLimits {
    /// The P-05 and P-13 snapshot at publication, which the Guide shows.
    pub fn publication(&self) -> &LiveSnapshot {
        &self.publication
    }

    /// Every change since publication, numbered from 1 in edit order.
    pub fn tightenings(&self) -> &[Tightening] {
        &self.tightenings
    }

    /// The current P-05 of the record: that of the latest change, or
    /// the snapshot without one.
    pub fn p05(&self) -> NonNegAmount {
        self.tightenings
            .last()
            .map_or(self.publication.p05, |t| t.p05)
    }

    /// The current P-13 of the record: that of the latest change, or
    /// the snapshot without one.
    pub fn p13(&self) -> &ExclusionClasses {
        self.tightenings
            .last()
            .map_or(&self.publication.p13, |t| &t.p13)
    }
}

/// The Guide version of a call's publication (R-GA-01). A correction
/// after publication is a numbered corrigendum of the effective-limits
/// record, never a new version (I-53, NOTE 7, Q37 C).
pub const GUIDE_VERSION: u32 = 1;

/// The Guide for Applicants of a published call, as its publication
/// stored it (R-GA-01, I-52, I-53). It never changes afterwards: the fold
/// refuses a second `GuidePublished` for the call. Its corrigenda are the
/// numbered entries of the call's [`EffectiveLimits`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoredGuide {
    version: u32,
    digest: ContentDigest,
    canonical: String,
    page: String,
}

impl StoredGuide {
    /// The Guide version, 1 at publication.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// SHA-256 of [`StoredGuide::canonical`], through `fstp-crypto`.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// The canonical document the digest is taken over.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The HTML page the public pages and `calls.guide` serve.
    pub fn page(&self) -> &str {
        &self.page
    }
}

/// The call states (`SPEC/02-domain/state-machine.md` Call states).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallStatus {
    /// Call text and criteria being drafted.
    Draft,
    /// Publication approved by a person other than its drafters (R-PC-03).
    Approved,
    /// Published with a frozen policy version (R-PC-02, I-12).
    Published,
}

/// The approval of a call's publication (R-PC-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Approval {
    /// The approval decision.
    pub decision: DecisionId,
    /// The approver.
    pub approver: AccountId,
}

/// One call as the projection holds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallView {
    id: CallId,
    programme: ProgrammeId,
    status: CallStatus,
    seq: Option<CallSeq>,
    opens: Timestamp,
    deadline: Timestamp,
    deadline_zone: ZoneName,
    budget: NonNegAmount,
    text: TextRef,
    authors: BTreeSet<AccountId>,
    approval: Option<Approval>,
    frozen: Option<FrozenPolicy>,
    llm_config: Option<LlmConfigId>,
    /// The drafter set fixed at publication: the authors plus the last
    /// authors of P-01 and P-09 in the frozen version (R-PC-03 NOTE).
    drafters_at_publication: Option<BTreeSet<AccountId>>,
    /// The effective-limits record, from publication on (D12).
    limits: Option<EffectiveLimits>,
    /// The Guide stored at publication (R-GA-01, I-53).
    guide: Option<StoredGuide>,
}

impl CallView {
    /// The call.
    pub fn id(&self) -> CallId {
        self.id
    }

    /// Its programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// Its state.
    pub fn status(&self) -> CallStatus {
        self.status
    }

    /// Its sequence number in the programme, set at publication.
    pub fn seq(&self) -> Option<CallSeq> {
        self.seq
    }

    /// The opening time.
    pub fn opens(&self) -> Timestamp {
        self.opens
    }

    /// The deadline as a UTC instant.
    pub fn deadline(&self) -> Timestamp {
        self.deadline
    }

    /// The deadline zone, kept as text.
    pub fn deadline_zone(&self) -> &ZoneName {
        &self.deadline_zone
    }

    /// The call budget. It is display-only once published (Q14 A).
    pub fn budget(&self) -> NonNegAmount {
        self.budget
    }

    /// The call text.
    pub fn text(&self) -> TextRef {
        self.text
    }

    /// Every account that drafted or edited the call text.
    pub fn authors(&self) -> &BTreeSet<AccountId> {
        &self.authors
    }

    /// The approval that publication would rely on, if any.
    pub fn approval(&self) -> Option<Approval> {
        self.approval
    }

    /// The frozen policy, once published (I-12, R-PC-02).
    pub fn frozen(&self) -> Option<&FrozenPolicy> {
        self.frozen.as_ref()
    }

    /// The Guide stored at publication, if any (R-GA-01, I-53).
    pub fn guide(&self) -> Option<&StoredGuide> {
        self.guide.as_ref()
    }

    /// The pinned LLM configuration, once published (I-11, R-LA-05).
    pub fn llm_config(&self) -> Option<LlmConfigId> {
        self.llm_config
    }

    /// Whether the call is published and open at `t`: from its opening
    /// time, inclusive, until its deadline, exclusive. The deadline instant
    /// is closed, because a submission must come before the deadline
    /// (`SPEC/02-domain/state-machine.md` SUBMITTED). This is a reading
    /// reported to Daniel.
    pub fn is_open_at(&self, t: Timestamp) -> bool {
        self.status == CallStatus::Published && self.opens <= t && t < self.deadline
    }
}

/// Call part of the projection: every call, and the published calls of
/// each programme by sequence number.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallState {
    calls: BTreeMap<CallId, CallView>,
    published: BTreeMap<(ProgrammeId, CallSeq), CallId>,
    /// The status and core builders of every programme (D1, D2).
    programmes: BTreeMap<ProgrammeId, ProgrammeView>,
    /// The cut-off rounds of the calls, which lane L-LIFE folds (D5).
    pub(crate) rounds: crate::decision::Rounds,
}

impl CallState {
    /// The call state before any record.
    pub(crate) const fn genesis() -> CallState {
        CallState {
            calls: BTreeMap::new(),
            published: BTreeMap::new(),
            programmes: BTreeMap::new(),
            rounds: crate::decision::Rounds::genesis(),
        }
    }

    /// The call `call`.
    pub fn get(&self, call: CallId) -> Option<&CallView> {
        self.calls.get(&call)
    }

    /// Every call, in id order. Proposed by lane W3b of M4, so the API
    /// can list the open calls (R-PB-01).
    pub fn iter(&self) -> impl Iterator<Item = (CallId, &CallView)> {
        self.calls.iter().map(|(id, v)| (*id, v))
    }

    /// The sequence number of the latest call published in `programme`, if any.
    /// Lane L-SOD reads it to pin cooling-off bars (P-12 NOTE 4).
    pub fn latest_published_seq(&self, programme: ProgrammeId) -> Option<CallSeq> {
        self.published_in(programme)
            .next_back()
            .map(|((_, seq), _)| *seq)
    }

    /// The published calls of `programme` in sequence order.
    fn published_in(
        &self,
        programme: ProgrammeId,
    ) -> std::collections::btree_map::Range<'_, (ProgrammeId, CallSeq), CallId> {
        self.published.range(
            (programme, CallSeq::FIRST)..=(programme, CallSeq::new(core::num::NonZeroU32::MAX)),
        )
    }

    /// Ends the approvals of every unpublished call of `programme`. The
    /// policy fold calls it when an edit changes P-01 or P-09 (R-PC-03).
    pub(crate) fn revoke_approvals(&mut self, programme: ProgrammeId) {
        for c in self.calls.values_mut() {
            if c.programme == programme && c.status == CallStatus::Approved {
                c.status = CallStatus::Draft;
                c.approval = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The read API
// ---------------------------------------------------------------------------

/// The call `call`.
pub fn call(state: &State, call: CallId) -> Option<&CallView> {
    state.calls.get(call)
}

/// The status of `programme`, or `None` for an unknown one (D1).
pub fn programme_status(state: &State, programme: ProgrammeId) -> Option<ProgrammeStatus> {
    state.calls.programmes.get(&programme).map(|p| p.status)
}

/// The core builder set of `programme` (I-67, Q1 A), or `None` for an
/// unknown one. [`crate::policy::activation::programme_builders`] reads it.
pub(crate) fn builders(state: &State, programme: ProgrammeId) -> Option<&BTreeSet<AccountId>> {
    state.calls.programmes.get(&programme).map(|p| &p.builders)
}

/// The effective-limits record of the published call `call` (D12, NOTE 7),
/// or `None` while it is unpublished or unknown.
pub fn effective_limits(state: &State, call: CallId) -> Option<&EffectiveLimits> {
    state.calls.get(call).and_then(|c| c.limits.as_ref())
}

/// The Guide stored at the publication of `call` (R-GA-01, I-53), or
/// `None` while it has none.
pub fn stored_guide(state: &State, call: CallId) -> Option<&StoredGuide> {
    state.calls.get(call).and_then(CallView::guide)
}

/// The refusal of a command on a draft programme (D3).
const fn on_draft() -> Refusal {
    Refusal::new(RuleRef::I66, RefusalReason::WrongState)
}

/// Refuses under `gate` when `programme` is a draft (D3). An unknown
/// programme passes, so the command's own check refuses it.
pub(crate) fn draft_gate(
    state: &State,
    programme: ProgrammeId,
    gate: DraftGate,
) -> Result<(), Refusal> {
    match (gate, programme_status(state, programme)) {
        (DraftGate::Enforce, Some(ProgrammeStatus::Draft)) => Err(on_draft()),
        _ => Ok(()),
    }
}

/// Folds the creation of `programme` by `by`: a draft built by its creator (D1).
pub(crate) fn fold_programme_created(
    state: &mut State,
    programme: ProgrammeId,
    by: AccountId,
) -> Result<(), FoldError> {
    if state.calls.programmes.contains_key(&programme) {
        return Err(FoldError::DuplicateId);
    }
    state.calls.programmes.insert(
        programme,
        ProgrammeView {
            status: ProgrammeStatus::Draft,
            builders: [by].into_iter().collect(),
        },
    );
    Ok(())
}

/// Notes `account` as a builder of `programme` while it is a draft: a
/// policy author or a grantor of a binding (I-67, Q1 A). It does nothing
/// once the programme is active.
pub(crate) fn note_builder(calls: &mut CallState, programme: ProgrammeId, account: AccountId) {
    if let Some(p) = calls.programmes.get_mut(&programme)
        && p.status == ProgrammeStatus::Draft
    {
        p.builders.insert(account);
    }
}

/// The lower of `a` and `b`, which share a currency.
fn lower(a: NonNegAmount, b: NonNegAmount) -> Result<NonNegAmount, FoldError> {
    match a.amount().cmp_same(b.amount()) {
        Ok(Ordering::Greater) => Ok(b),
        Ok(_) => Ok(a),
        Err(_) => Err(FoldError::Inconsistent),
    }
}

/// Appends a numbered entry to the effective-limits record of every
/// published call of `programme` whose effective P-05 or P-13 the live
/// values of `version` change (NOTE 7, D12, I-51). The effective P-05 is
/// the lower of the snapshot and the live value. The effective P-13 is
/// every class of either. An edit that tightens either limit appends a
/// tightening. An edit that loosens a limit after a tightening, back
/// towards the snapshot, appends an entry too, so the record's current
/// values always equal the values enforcement reads (I-51 outranks the
/// record's wording in NOTE 7; interim, pending Daniel). An edit that
/// leaves both effective limits as they are appends nothing.
pub(crate) fn fold_live_edit(
    calls: &mut CallState,
    programme: ProgrammeId,
    version: &PolicyVersion,
) -> Result<(), FoldError> {
    let after = &version.live;
    for view in calls.calls.values_mut() {
        if view.programme != programme {
            continue;
        }
        let Some(limits) = view.limits.as_mut() else {
            continue;
        };
        let snapshot = &limits.publication;
        let p05_after = lower(snapshot.p05, after.p05)?;
        let mut p13_after = snapshot.p13.clone();
        p13_after.0.extend(after.p13.0.iter().copied());
        let p05_same = matches!(
            p05_after.amount().cmp_same(limits.p05().amount()),
            Ok(Ordering::Equal)
        );
        if p05_same && &p13_after == limits.p13() {
            continue;
        }
        let next = u32::try_from(limits.tightenings.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .and_then(NonZeroU32::new)
            .ok_or(FoldError::Inconsistent)?;
        limits.tightenings.push(Tightening {
            corrigendum: next,
            version: version.id,
            p05: p05_after,
            p13: p13_after,
        });
    }
    Ok(())
}

/// The sequence number of the latest call published in `programme` (P-12 NOTE 4).
pub fn latest_published_seq(state: &State, programme: ProgrammeId) -> Option<CallSeq> {
    state.calls.latest_published_seq(programme)
}

/// Whether `call` is published and open at `t`. An unknown call is not open.
pub fn is_open_at(state: &State, call: CallId, t: Timestamp) -> bool {
    state.calls.get(call).is_some_and(|c| c.is_open_at(t))
}

/// The first call of the same programme published after `call`, if any.
/// This is the "future call exists" fact of the state machine (Q14 A).
pub fn next_published_call(state: &State, call: CallId) -> Option<CallId> {
    let view = state.calls.get(call)?;
    let seq = view.seq?;
    state
        .calls
        .published_in(view.programme)
        .find(|((_, s), _)| *s > seq)
        .map(|(_, c)| *c)
}

/// The drafters of `call`: its authors plus the last authors of P-01 and
/// P-09 in that call's policy (R-PC-03 NOTE). Before publication that
/// policy is the programme head, which is the version it would freeze.
/// After publication it is the set fixed when the call was published.
pub fn drafters(state: &State, call: CallId) -> Option<BTreeSet<AccountId>> {
    let view = state.calls.get(call)?;
    if let Some(fixed) = &view.drafters_at_publication {
        return Some(fixed.clone());
    }
    head_drafters(state, view)
}

/// The authors of `view` plus the last authors of P-01 and P-09 in the
/// head of its programme.
fn head_drafters(state: &State, view: &CallView) -> Option<BTreeSet<AccountId>> {
    let p = state.policy.programme(view.programme)?;
    let mut out = view.authors.clone();
    out.insert(p.last_author_p01());
    out.insert(p.last_author_p09());
    Some(out)
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// The roles that may draft and edit calls.
const WRITERS: [Role; 2] = [Role::CallDrafter, Role::ProgrammeManager];

/// The role that approves and publishes calls.
const MANAGER: [Role; 1] = [Role::ProgrammeManager];

/// The refusal for an unknown programme or call.
const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of any change to a published call (R-PC-02, I-12).
const fn published() -> Refusal {
    Refusal::new(RuleRef::Rpc02, RefusalReason::WrongState)
}

/// The refusal of an approval or publication that R-PC-03 forbids.
const fn rpc03() -> Refusal {
    Refusal::new(RuleRef::Rpc03, RefusalReason::GuardFailed)
}

/// Checks the call fields shared by `DraftCall` and `EditCall`: the budget
/// is in the programme currency and the deadline is after the opening.
fn check_call_fields(
    state: &State,
    programme: ProgrammeId,
    opens: Timestamp,
    deadline: Timestamp,
    budget: NonNegAmount,
) -> Result<(), Refusal> {
    let currency = crate::policy::programme_currency(state, programme).ok_or_else(unknown)?;
    if budget.amount().currency() != currency || deadline <= opens {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
    }
    Ok(())
}

/// The unpublished call `id` and its programme, or the refusal.
fn unpublished(state: &State, id: CallId) -> Result<&CallView, Refusal> {
    let view = state.calls.get(id).ok_or_else(unknown)?;
    if view.status == CallStatus::Published {
        return Err(published());
    }
    Ok(view)
}

/// Checks a call command and returns its records.
fn check(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let actor = actor_account(ctx)?;
    match cmd {
        Command::DraftCall {
            call,
            programme,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
        } => {
            if crate::policy::head(state, *programme).is_none() {
                return Err(unknown());
            }
            require_holder(state, actor, *programme, &WRITERS, ctx.now)?;
            draft_gate(state, *programme, DraftGate::Enforce)?;
            if state.used_ids.contains(UsedId::Call(*call)) || state.calls.get(*call).is_some() {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            check_call_fields(state, *programme, *opens, *deadline, *budget)?;
            Ok(vec![Record::CallDrafted {
                call: *call,
                programme: *programme,
                opens: *opens,
                deadline: *deadline,
                deadline_zone: deadline_zone.clone(),
                budget: *budget,
                text: *text,
                author: actor,
            }])
        }
        Command::EditCall {
            call,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
        } => {
            // The actor before the call's state (test plan, authorisation
            // matrix row): a denied actor is denied in every state.
            let view = state.calls.get(*call).ok_or_else(unknown)?;
            require_holder(state, actor, view.programme, &WRITERS, ctx.now)?;
            let view = unpublished(state, *call)?;
            draft_gate(state, view.programme, DraftGate::Enforce)?;
            check_call_fields(state, view.programme, *opens, *deadline, *budget)?;
            Ok(vec![Record::CallEdited {
                call: *call,
                opens: *opens,
                deadline: *deadline,
                deadline_zone: deadline_zone.clone(),
                budget: *budget,
                text: *text,
                author: actor,
            }])
        }
        Command::ApproveCallPublication { call, decision } => {
            // The actor and the R-PC-03 drafter rule before the call's
            // state (test plan, authorisation matrix row).
            let view = state.calls.get(*call).ok_or_else(unknown)?;
            require_holder(state, actor, view.programme, &MANAGER, ctx.now)?;
            let drafters = drafters(state, *call).ok_or_else(unknown)?;
            if drafters.contains(&actor) {
                return Err(rpc03());
            }
            let view = unpublished(state, *call)?;
            draft_gate(state, view.programme, DraftGate::Enforce)?;
            if state.used_ids.contains(UsedId::Decision(*decision)) {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            // A call already approved has no row to approval: a state
            // guard, never the R-PC-03 actor rule.
            if view.status != CallStatus::Draft {
                return Err(Refusal::new(RuleRef::Row, RefusalReason::WrongState));
            }
            Ok(vec![Record::CallApproved {
                call: *call,
                decision: *decision,
                approver: actor,
            }])
        }
        Command::PublishCall {
            call,
            config,
            config_model,
        } => {
            let view = state.calls.get(*call).ok_or_else(unknown)?;
            require_holder(state, actor, view.programme, &MANAGER, ctx.now)?;
            let view = unpublished(state, *call)?;
            draft_gate(state, view.programme, DraftGate::Enforce)?;
            let drafters = drafters(state, *call).ok_or_else(unknown)?;
            match view.approval {
                Some(a)
                    if view.status == CallStatus::Approved && !drafters.contains(&a.approver) => {}
                _ => return Err(rpc03()),
            }
            let head = crate::policy::head(state, view.programme).ok_or_else(unknown)?;
            if *config_model != head.frozen.p21.primary {
                return Err(Refusal::new(RuleRef::Rla05, RefusalReason::GuardFailed));
            }
            let seq = match state.calls.latest_published_seq(view.programme) {
                None => CallSeq::FIRST,
                Some(s) => s
                    .next()
                    .ok_or(Refusal::new(RuleRef::Ledger, RefusalReason::InvalidValue))?,
            };
            Ok(vec![Record::CallPublished {
                call: *call,
                policy: head.id,
                seq,
                config: *config,
                by: actor,
            }])
        }
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the programme and call commands. Only the
/// activation asks one, `SameIdentityAsAny` (I-67, Q2 B). The call
/// commands only run their guards, which refuse before any vault traffic.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    if let Command::ActivateProgramme { .. } = cmd {
        return crate::policy::activation::queries(state, cmd, ctx);
    }
    check(state, cmd, ctx)?;
    Ok(Vec::new())
}

/// The records of the programme and call commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    if let Command::ActivateProgramme { .. } = cmd {
        return crate::policy::activation::decide(state, cmd, ctx, answers);
    }
    check(state, cmd, ctx)
}

/// Folds a call record. The fold checks structure only.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::CallDrafted {
            call,
            programme,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
            author,
        } => {
            if crate::policy::head(state, *programme).is_none() {
                return Err(FoldError::UnknownEntity);
            }
            if state.calls.calls.contains_key(call) || !state.used_ids.insert(UsedId::Call(*call)) {
                return Err(FoldError::DuplicateId);
            }
            state.calls.calls.insert(
                *call,
                CallView {
                    id: *call,
                    programme: *programme,
                    status: CallStatus::Draft,
                    seq: None,
                    opens: *opens,
                    deadline: *deadline,
                    deadline_zone: deadline_zone.clone(),
                    budget: *budget,
                    text: *text,
                    authors: [*author].into_iter().collect(),
                    approval: None,
                    frozen: None,
                    llm_config: None,
                    drafters_at_publication: None,
                    limits: None,
                    guide: None,
                },
            );
            Ok(())
        }
        Record::CallEdited {
            call,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
            author,
        } => {
            let view = state
                .calls
                .calls
                .get_mut(call)
                .ok_or(FoldError::UnknownEntity)?;
            if view.status == CallStatus::Published {
                return Err(FoldError::Inconsistent);
            }
            view.opens = *opens;
            view.deadline = *deadline;
            view.deadline_zone = deadline_zone.clone();
            view.budget = *budget;
            view.text = *text;
            view.authors.insert(*author);
            view.status = CallStatus::Draft;
            view.approval = None;
            Ok(())
        }
        Record::CallApproved {
            call,
            decision,
            approver,
        } => {
            let view = state
                .calls
                .calls
                .get(call)
                .ok_or(FoldError::UnknownEntity)?;
            if view.status != CallStatus::Draft {
                return Err(FoldError::Inconsistent);
            }
            if !state.used_ids.insert(UsedId::Decision(*decision)) {
                return Err(FoldError::DuplicateId);
            }
            let view = state
                .calls
                .calls
                .get_mut(call)
                .ok_or(FoldError::UnknownEntity)?;
            view.status = CallStatus::Approved;
            view.approval = Some(Approval {
                decision: *decision,
                approver: *approver,
            });
            Ok(())
        }
        Record::GuidePublished {
            call,
            version,
            digest,
            canonical,
            page,
        } => {
            let view = state
                .calls
                .calls
                .get_mut(call)
                .ok_or(FoldError::UnknownEntity)?;
            if view.guide.is_some() {
                return Err(FoldError::DuplicateId);
            }
            if view.status != CallStatus::Published || *version != GUIDE_VERSION {
                return Err(FoldError::Inconsistent);
            }
            view.guide = Some(StoredGuide {
                version: *version,
                digest: *digest,
                canonical: canonical.clone(),
                page: page.clone(),
            });
            Ok(())
        }
        Record::CallPublished {
            call,
            seq: number,
            config,
            ..
        } => {
            let view = state
                .calls
                .calls
                .get(call)
                .ok_or(FoldError::UnknownEntity)?;
            if view.status != CallStatus::Approved {
                return Err(FoldError::Inconsistent);
            }
            let programme = view.programme;
            let expected = match state.calls.latest_published_seq(programme) {
                None => Some(CallSeq::FIRST),
                Some(s) => s.next(),
            };
            if expected != Some(*number) {
                return Err(FoldError::Inconsistent);
            }
            let frozen = crate::policy::freeze(&state.policy, programme, record)?;
            // `freeze` checked that the record names the head, so the head's
            // last authors are those of the frozen version.
            let fixed = head_drafters(state, view).ok_or(FoldError::UnknownEntity)?;
            let view = state
                .calls
                .calls
                .get_mut(call)
                .ok_or(FoldError::UnknownEntity)?;
            view.status = CallStatus::Published;
            view.seq = Some(*number);
            view.limits = Some(EffectiveLimits {
                publication: frozen.snapshot().clone(),
                tightenings: Vec::new(),
            });
            view.frozen = Some(frozen);
            view.llm_config = Some(*config);
            view.drafters_at_publication = Some(fixed);
            state.calls.published.insert((programme, *number), *call);
            Ok(())
        }
        Record::ProgrammeActivated(a) => {
            let view = state
                .calls
                .programmes
                .get(&a.programme())
                .ok_or(FoldError::UnknownEntity)?;
            if view.status != ProgrammeStatus::Draft {
                return Err(FoldError::Inconsistent);
            }
            if !state.used_ids.insert(UsedId::Decision(a.decision())) {
                return Err(FoldError::DuplicateId);
            }
            if let Some(view) = state.calls.programmes.get_mut(&a.programme()) {
                view.status = ProgrammeStatus::Active;
            }
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. The call lane contributes nothing.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns. The call lane contributes nothing in M2.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a call command through MCP (R-MC-05).
/// No published call governs these commands, so it is the head of the
/// call's programme. `PublishCall` and `ActivateProgramme` are high risk
/// and never complete through MCP (I-85).
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let programme = match cmd {
        Command::DraftCall { programme, .. } => *programme,
        Command::EditCall { call, .. } | Command::ApproveCallPublication { call, .. } => {
            state.calls.get(*call).ok_or_else(unknown)?.programme
        }
        Command::PublishCall { .. } | Command::ActivateProgramme { .. } => {
            return Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp));
        }
        _ => return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    };
    Ok(PolicyScope::Programme(programme))
}
