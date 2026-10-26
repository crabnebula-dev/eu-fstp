//! Programmes and calls (design section 2.5, R-PC-01 to R-PC-03).
//!
//! Owned by lane L-POL (docs/handoff/m2-design.md section 10).
//!
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

use std::collections::{BTreeMap, BTreeSet};

use fstp_money::NonNegAmount;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, CallId, CallSeq, DecisionId, LlmConfigId, ProgrammeId, TextRef};
use crate::oracle::{Answers, Query};
use crate::policy::{FrozenPolicy, actor_account, require_holder};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::state::{State, UsedId};
use crate::time::{Timestamp, ZoneName};

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
}

impl CallState {
    /// The call state before any record.
    pub(crate) const fn genesis() -> CallState {
        CallState {
            calls: BTreeMap::new(),
            published: BTreeMap::new(),
        }
    }

    /// The call `call`.
    pub fn get(&self, call: CallId) -> Option<&CallView> {
        self.calls.get(&call)
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
            let view = unpublished(state, *call)?;
            require_holder(state, actor, view.programme, &WRITERS, ctx.now)?;
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
            let view = unpublished(state, *call)?;
            require_holder(state, actor, view.programme, &MANAGER, ctx.now)?;
            if state.used_ids.contains(UsedId::Decision(*decision)) {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            let drafters = drafters(state, *call).ok_or_else(unknown)?;
            if drafters.contains(&actor) {
                return Err(rpc03());
            }
            if view.status != CallStatus::Draft {
                return Err(Refusal::new(RuleRef::Rpc03, RefusalReason::WrongState));
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
            let view = unpublished(state, *call)?;
            require_holder(state, actor, view.programme, &MANAGER, ctx.now)?;
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

/// The vault questions of the call commands. None of them asks one, so
/// this only runs the guards, which refuse before any vault traffic.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    check(state, cmd, ctx)?;
    Ok(Vec::new())
}

/// The records of the call commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let _ = answers;
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
            view.frozen = Some(frozen);
            view.llm_config = Some(*config);
            view.drafters_at_publication = Some(fixed);
            state.calls.published.insert((programme, *number), *call);
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
/// call's programme. `PublishCall` is high risk and never completes
/// through MCP (I-85).
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let programme = match cmd {
        Command::DraftCall { programme, .. } => *programme,
        Command::EditCall { call, .. } | Command::ApproveCallPublication { call, .. } => {
            state.calls.get(*call).ok_or_else(unknown)?.programme
        }
        Command::PublishCall { .. } => {
            return Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp));
        }
        _ => return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    };
    Ok(PolicyScope::Programme(programme))
}
