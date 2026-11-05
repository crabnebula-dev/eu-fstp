//! `proposal.journey` and `proposal.diary`: a proposal's route position
//! and its Passage Diary (`SPEC/12-journey-ui.md` sections 7 and 10,
//! ADR-015, lane j2).
//!
//! Both reads fold the cell's ledger with the pure projector of
//! `fstp-journey` (I-92) and write nothing. `fstp-access` admits the
//! proposal's team and the holders of a section 7.2 role in its
//! programme. This module then applies the visibility function per
//! request (I-93):
//!
//! - The route position and the legs are state transitions, so a caller
//!   sees them only where a state transition entry reaches them. A
//!   coordinator who has not declared on the proposal is refused with
//!   R-CF-02 (O-57), a conflicted caller with I-03, anyone else with
//!   R-AC-01.
//! - Each diary entry of the proposal, of its calls and of its grant's
//!   payment requests passes the visibility function, or is left out.
//! - A staff reader of a DRAFT is refused with I-21: drafts are the
//!   team's alone. So is a staff reader of a route that never reached
//!   SUBMITTED, such as a draft withdrawn before submission.
//! - Each leg shows where its own state transition entry would, so a
//!   "grants only" reader sees the legs of the grant alone.
//!
//! The caller reads through every role they hold on the proposal and in
//! its programme, and an entry shows when one of them admits it. The
//! relation of section 7.2 is computed from the engine state at read
//! time: team, assignment, declaration, conflict, and whether the entry
//! is the caller's own. No complaint or agent action exists yet, so no
//! caller reviews a complaint and SoD-13 bars every complaint entry
//! (fail closed).
//!
//! I-97: the replies hold ids, formal state names, times, codes,
//! catalogue keys, ADR-006 amounts and text references, never text.
//!
//! Interim, pending the lead (seams):
//!
//! - The ledger comes from `AsyncEngine::ledger`. A port without it
//!   answers unavailable.
//! - The cell's erasure log has no API port yet, so every text reference
//!   is served as a live reference. Resolving an erased one gives the
//!   placeholder of section 7.3 through the text store (ADR-007).

use std::collections::{BTreeMap, BTreeSet};

use fstp_access::ReadRule;
use fstp_domain::StateTag;
use fstp_domain::id::{AccountId, CallId, ProgrammeId, ProposalId};
use fstp_domain::policy::{McpBindingActions, PolicyVersion, ReadAccess, ReviewerAnonymity};
use fstp_domain::record::{Declared, Record as CoreRecord};
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::rules::ParamId;
use fstp_engine::Record;
use fstp_journey::diary::{self, DiaryItem, Param, TextSlot};
use fstp_journey::overlay::{IrcConcern, Overlay, OverlayInputs};
use fstp_journey::projector::{self, LegRow, Position, Rows, Subject};
use fstp_journey::summary::SummaryKey;
use fstp_journey::visibility::{self, EntryFacts, EntryKind, Relation, Viewer};
use fstp_json::{Array, Object, ToJson, Value};
use fstp_ledger::Entry;

use super::{Call, Seams};
use crate::port::AsyncEngine;
use crate::{ApiError, ErrorCode};

/// A decimal string.
fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// A JSON integer.
fn int(n: u64) -> Value {
    fstp_json::Number::from_lexeme(&n.to_string()).map_or(Value::Null, Value::from)
}

/// The `proposal.journey` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JourneyView {
    /// The proposal.
    pub proposal: ProposalId,
    /// Its current position.
    pub position: Position,
    /// Its completed legs, in route order.
    pub legs: Vec<LegRow>,
    /// Whether the caller's role gets the route strip (section 8.3, O-58).
    pub strip: bool,
    /// The overlay of the original call's frozen policy (R-JV-07, NOTE 8),
    /// `None` before that call is published.
    pub overlay: Option<Overlay>,
}

impl ToJson for JourneyView {
    fn to_json(&self) -> Value {
        let mut legs = Array::new();
        for l in &self.legs {
            let mut o = Object::new();
            let _ = o.insert("from", Value::from(l.from.spec_name()));
            let _ = o.insert("to", Value::from(l.to.spec_name()));
            let _ = o.insert("at", dec(l.at));
            let _ = o.insert("seq", dec(l.source_seq));
            legs.push(Value::Object(o));
        }
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("state", Value::from(self.position.node.spec_name()));
        let _ = o.insert("since", dec(self.position.since));
        let _ = o.insert("seq", dec(self.position.source_seq));
        let _ = o.insert("legs", Value::Array(legs));
        let _ = o.insert("strip", Value::Bool(self.strip));
        let _ = o.insert(
            "overlay",
            self.overlay.as_ref().map_or(Value::Null, overlay_json),
        );
        Value::Object(o)
    }
}

/// The overlay as the reply spells it. Opaque parameters by id only.
fn overlay_json(ov: &Overlay) -> Value {
    let mut o = Object::new();
    let _ = o.insert("policy", dec(ov.policy.raw()));
    let _ = o.insert("stage2_window_days", int(u64::from(ov.stage2_window.get())));
    let anonymity = match ov.anonymity {
        ReviewerAnonymity::Anonymous => "anonymous",
        ReviewerAnonymity::Named => "named",
    };
    let _ = o.insert("anonymity", Value::from(anonymity));
    let concern = match ov.irc_concern {
        IrcConcern::Deferred => "deferred",
        IrcConcern::Declined => "declined",
    };
    let _ = o.insert("irc_concern", Value::from(concern));
    let actions = match ov.agent_actions {
        McpBindingActions::DraftOnly => "draft_only",
        McpBindingActions::Allowed => "allowed",
    };
    let _ = o.insert("agent_actions", Value::from(actions));
    let wording: Array = ov
        .wording
        .iter()
        .map(|p| Value::from(p.spec_id()))
        .collect();
    let _ = o.insert("wording", Value::Array(wording));
    Value::Object(o)
}

/// One diary entry of the `proposal.diary` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiaryEntry {
    /// The item the diary read built.
    pub item: DiaryItem,
    /// The entry it corrects.
    pub supersedes: Option<[u8; 16]>,
}

/// The `proposal.diary` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiaryView {
    /// The proposal.
    pub proposal: ProposalId,
    /// The entries the caller may see, in ledger order.
    pub entries: Vec<DiaryEntry>,
}

/// The wire name of an entry kind (`fstp_access::ENTRY_KIND_NAMES`).
pub(crate) const fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::StateTransition => "state_transition",
        EntryKind::DeadlineSet => "deadline_set",
        EntryKind::NoticeSent => "notice_sent",
        EntryKind::Clarification => "clarification",
        EntryKind::ReviewerScore => "reviewer_score",
        EntryKind::Conflict => "conflict",
        EntryKind::VaultOutcome => "vault_outcome",
        EntryKind::Contract => "contract",
        EntryKind::MilestonePayment => "milestone_payment",
        EntryKind::Complaint => "complaint",
        EntryKind::AgentAction => "agent_action",
        EntryKind::GuardianStep => "guardian_step",
    }
}

fn param_json(p: &Param) -> Value {
    let mut o = Object::new();
    let _ = match p {
        Param::State(s) => o.insert("state", Value::from(s.spec_name())),
        Param::Amount(a) => o.insert("amount", Value::from(a.as_str())),
        Param::Sequence(n) => o.insert("seq", dec(n)),
        Param::Score(v) => o.insert(
            "score",
            Value::Array(v.0.iter().map(|x| int(u64::from(*x))).collect()),
        ),
        Param::Outcome(b) => o.insert("outcome", Value::Bool(*b)),
        Param::Time(t) => o.insert("time", dec(t)),
    };
    Value::Object(o)
}

fn text_json(t: &TextSlot) -> Value {
    let mut o = Object::new();
    match t {
        TextSlot::Live(r) => {
            let _ = o.insert("text", dec(r.id().raw()));
            let _ = o.insert(
                "digest",
                Value::String(crate::action::hex(&r.digest().bytes())),
            );
        }
        TextSlot::Erased(e) => {
            let _ = o.insert("erased_on", dec(e.on));
            let _ = o.insert("cause", int(u64::from(e.cause)));
        }
    }
    Value::Object(o)
}

impl ToJson for DiaryEntry {
    fn to_json(&self) -> Value {
        let i = &self.item;
        let (subject, id) = match i.subject {
            Subject::Proposal(p) => ("proposal", p.raw()),
            Subject::Call(c) => ("call", c.raw()),
            Subject::PaymentRequest(r) => ("payment_request", r.raw()),
        };
        let key = SummaryKey::from_code(i.summary_key).map_or("journey.unknown", SummaryKey::name);
        let mut o = Object::new();
        let _ = o.insert("entry", Value::String(crate::action::hex(&i.entry_id)));
        let _ = o.insert("seq", dec(i.source_seq));
        let _ = o.insert("kind", Value::from(kind_name(i.kind)));
        let _ = o.insert("subject", Value::from(subject));
        let _ = o.insert("subject_id", dec(id));
        let _ = o.insert("key", Value::from(key));
        let _ = o.insert("at", dec(i.occurred_at));
        if let Some(z) = i.deadline_zone.and_then(fstp_journey::zones::zone_at) {
            let _ = o.insert("zone", Value::from(z));
        }
        if let Some(s) = self.supersedes {
            let _ = o.insert("supersedes", Value::String(crate::action::hex(&s)));
        }
        let _ = o.insert(
            "params",
            Value::Array(i.params.iter().map(param_json).collect()),
        );
        let _ = o.insert(
            "texts",
            Value::Array(i.texts.iter().map(text_json).collect()),
        );
        Value::Object(o)
    }
}

impl ToJson for DiaryView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert(
            "entries",
            Value::Array(self.entries.iter().map(ToJson::to_json).collect()),
        );
        Value::Object(o)
    }
}

/// What both reads know of the proposal and the caller.
struct Scene {
    proposal: ProposalId,
    programme: ProgrammeId,
    /// The calls the proposal has been in: its first and its current one.
    calls: BTreeSet<CallId>,
    p10: ReadAccess,
    roles: BTreeSet<Role>,
    base: Relation,
    ledger: Vec<Entry<Record>>,
    rows: Rows,
}

impl Scene {
    /// The facts of an entry of `kind` on this proposal, with its own
    /// leg for a state transition entry.
    fn facts(&self, kind: EntryKind, transition: Option<(StateTag, StateTag)>) -> EntryFacts {
        EntryFacts {
            kind,
            programme: self.programme,
            path: self.rows.path(self.proposal),
            transition,
        }
    }

    /// The facts of the state transition entry of `leg`.
    fn leg_facts(&self, leg: &LegRow) -> EntryFacts {
        self.facts(EntryKind::StateTransition, Some((leg.from, leg.to)))
    }

    /// Whether one of the caller's roles admits the entry (I-93).
    fn visible(&self, relation: Relation, facts: &EntryFacts) -> bool {
        self.roles.iter().any(|role| {
            let v = Viewer {
                role: *role,
                programme: self.programme,
                relation,
            };
            visibility::visible(&v, self.p10, facts)
        })
    }

    /// The ledger entry at `seq`.
    fn source(&self, seq: u64) -> Option<&Entry<Record>> {
        self.ledger
            .binary_search_by_key(&seq, |e| e.seq.raw())
            .ok()
            .and_then(|i| self.ledger.get(i))
    }
}

/// The P-10 of a call: its frozen value, or the default "assigned
/// reviewers only" before publication, which is the most closed one for
/// a committee member.
fn p10_of<P: Seams>(call: &Call<'_, P>, c: Option<CallId>) -> ReadAccess {
    c.and_then(|c| call.state.core.calls().get(c))
        .and_then(|v| v.frozen())
        .map_or(ReadAccess::AssignedReviewersOnly, |f| f.values().p10)
}

/// The relation of `account` to `proposal` that holds for every entry.
fn base_relation<P: Seams>(call: &Call<'_, P>, account: AccountId, p: ProposalId) -> Relation {
    let core = &call.state.core;
    let team = core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.proposal() == Some(p)
            && matches!(b.role, Role::Applicant | Role::ApplicantTeamMember)
            && b.active_at(call.now)
    });
    let assigned = core
        .review()
        .assignments()
        .any(|(_, a)| a.reviewer == account && a.proposal == p && a.active());
    Relation {
        team,
        guardian_of: false,
        assigned,
        declared_no_conflict: core.review().cleared(account, p),
        conflicted: core.review().conflict_fact(account, p),
        own: false,
        complaint_reviewer: false,
        sod13_barred: true,
    }
}

/// The roles `account` reads through: each active binding on the
/// proposal, and each active programme binding in its programme.
fn roles_of<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    p: ProposalId,
    programme: ProgrammeId,
) -> BTreeSet<Role> {
    call.state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b)
        .filter(|b| b.account == account && b.active_at(call.now))
        .filter(|b| match b.scope {
            BindingScope::Proposal { proposal, .. } => proposal == p,
            BindingScope::Programme => b.programme == programme,
        })
        .map(|b| b.role)
        .collect()
}

/// The refusal of a caller whom no role admits to the position.
fn position_refusal(scene: &Scene) -> ApiError {
    if scene.base.conflicted {
        ApiError::refused(ErrorCode::Refused, "I-03")
    } else if scene.roles.contains(&Role::FstpCoordinator) && !scene.base.declared_no_conflict {
        ApiError::refused(ErrorCode::Refused, "R-CF-02")
    } else {
        ApiError::refused(ErrorCode::Refused, "R-AC-01")
    }
}

/// The scene of a read, or its refusal.
fn scene<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    admitted: ReadRule,
) -> Result<Scene, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let core = &call.state.core;
    let Some(state) = fstp_domain::view::proposal_state(core, p) else {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    };
    // I-21: drafts are the team's alone.
    if state == StateTag::Draft && admitted != ReadRule::Team {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-21")));
    }
    let ledger = call
        .ports
        .engine()
        .ledger()
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "journey")))?;
    let rows = projector::project(&ledger)
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "journey")))?;
    // I-21 on the route, not only the current state: a draft withdrawn
    // before submission never left the team, so its route stays theirs.
    if admitted != ReadRule::Team && !rows.path(p).contains(&StateTag::Submitted) {
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-21")));
    }
    let current = super::call_of(&call.state, p);
    let first = rows.start(p).map(|s| s.call);
    let programme = current
        .or(first)
        .and_then(|c| core.calls().get(c))
        .map(|v| v.programme())
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    let calls = current.into_iter().chain(first).collect();
    Ok(Scene {
        proposal: p,
        programme,
        calls,
        p10: p10_of(call, current),
        roles: roles_of(call, account, p, programme),
        base: base_relation(call, account, p),
        ledger,
        rows,
    })
}

/// The frozen policy version of `c` as the ledger recorded it.
fn frozen_version<'l>(
    call: &Call<'_, impl Seams>,
    ledger: &'l [Entry<Record>],
    c: CallId,
) -> Option<&'l PolicyVersion> {
    let id = call.state.core.calls().get(c)?.frozen()?.version();
    ledger.iter().rev().find_map(|e| match &e.record {
        Record::Core(CoreRecord::PolicyVersionRecorded { version, .. }) if version.id == id => {
            Some(version.as_ref())
        }
        _ => None,
    })
}

/// `proposal.journey` (section 10).
pub(super) fn journey<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    admitted: ReadRule,
) -> Result<JourneyView, ApiError> {
    let scene = scene(call, p, admitted)?;
    // The position shows where the leg that reached it would. A route
    // with no leg yet is the draft's start.
    let all_legs = scene.rows.legs_of(p);
    let facts = all_legs.last().map_or_else(
        || scene.facts(EntryKind::StateTransition, None),
        |l| scene.leg_facts(l),
    );
    if !scene.visible(scene.base, &facts) {
        return Err(call.refuse(position_refusal(&scene)));
    }
    // Each leg is a state transition entry: it shows where its own entry
    // would, so "grants only" readers see the grant's legs alone.
    let legs = all_legs
        .into_iter()
        .filter(|l| scene.visible(scene.base, &scene.leg_facts(l)))
        .collect();
    let position = scene
        .rows
        .position(p)
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")))?;
    // NOTE 8: the call the proposal was created in drives the overlay,
    // which is the original call of a deferred proposal.
    let first = scene.rows.start(p).map(|s| s.call);
    let overlay = first.and_then(|c| {
        let version = frozen_version(call, &scene.ledger, c)?;
        let mut tenant_params = BTreeSet::new();
        if call
            .state
            .tenant
            .state()
            .is_some_and(|ts| ts.settings().p20.is_some())
        {
            let _ = tenant_params.insert(ParamId::P20);
        }
        let inputs = OverlayInputs {
            later_call_published: fstp_domain::programme::next_published_call(&call.state.core, c)
                .is_some(),
            tenant_params,
        };
        Some(fstp_journey::overlay::compute(version, &inputs))
    });
    Ok(JourneyView {
        proposal: p,
        position,
        legs,
        strip: scene.roles.iter().any(|r| visibility::route_strip(*r)),
        overlay,
    })
}

/// The caller's own relation to the entry at `item`: their score,
/// declaration or conflict, and the guardian step that names them.
fn entry_relation(scene: &Scene, call: &Call<'_, impl Seams>, item: &DiaryItem) -> Relation {
    let mut r = scene.base;
    let Some(account) = call.account() else {
        return r;
    };
    let review = call.state.core.review();
    let reviewer_of = |a| review.get(a).map(|x| x.reviewer);
    let Some(Record::Core(rec)) = scene.source(item.source_seq).map(|e| &e.record) else {
        return r;
    };
    r.own = match rec {
        CoreRecord::ScoreRecorded(s) => reviewer_of(s.key.assignment) == Some(account),
        CoreRecord::ScoreVoided(s) => reviewer_of(s.key.assignment) == Some(account),
        CoreRecord::ConflictDeclared(c) => match c.subject {
            Declared::Assignment(a) => reviewer_of(a) == Some(account),
            Declared::Proposal { account: x, .. } => x == account,
        },
        CoreRecord::ConflictDetected(c) => c.account == account,
        CoreRecord::AssignmentReleased(a) => reviewer_of(a.assignment) == Some(account),
        _ => false,
    };
    r.guardian_of = matches!(rec, CoreRecord::BindingGranted(b) if b.account == account);
    r
}

/// The leg of a state transition item, read from its source record.
fn transition_of(scene: &Scene, item: &DiaryItem) -> Option<(StateTag, StateTag)> {
    match scene.source(item.source_seq).map(|e| &e.record) {
        Some(Record::Core(CoreRecord::Transitioned(t))) => Some((t.from, t.to)),
        _ => None,
    }
}

/// Whether the diary of the proposal holds an entry of `subject`.
fn of_proposal(scene: &Scene, call: &Call<'_, impl Seams>, subject: Subject) -> bool {
    match subject {
        Subject::Proposal(x) => x == scene.proposal,
        Subject::Call(c) => scene.calls.contains(&c),
        Subject::PaymentRequest(r) => {
            call.state.core.payments().grant_of(r) == Some(scene.proposal)
        }
    }
}

/// `proposal.diary` (section 10): every entry of the proposal that the
/// visibility function lets the caller see.
pub(super) fn diary<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
    admitted: ReadRule,
) -> Result<DiaryView, ApiError> {
    let scene = scene(call, p, admitted)?;
    let items = diary::items(&scene.rows, &scene.ledger, &BTreeMap::new())
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "journey")))?;
    let supersedes: BTreeMap<[u8; 16], [u8; 16]> = scene
        .rows
        .entries
        .iter()
        .filter_map(|r| r.supersedes.map(|s| (r.entry_id, s)))
        .collect();
    let mut entries = Vec::new();
    for item in items {
        if !of_proposal(&scene, call, item.subject) {
            continue;
        }
        let facts = scene.facts(item.kind, transition_of(&scene, &item));
        if !scene.visible(entry_relation(&scene, call, &item), &facts) {
            continue;
        }
        entries.push(DiaryEntry {
            supersedes: supersedes.get(&item.entry_id).copied(),
            item,
        });
    }
    Ok(DiaryView {
        proposal: p,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-93, section 7.2: the wire names of the entry kinds are the
    /// registry's, in the order of `EntryKind::ALL`.
    #[test]
    fn i93_entry_kind_wire_names_match_the_registry() {
        let names: Vec<&str> = EntryKind::ALL.iter().map(|k| kind_name(*k)).collect();
        assert_eq!(names, fstp_access::ENTRY_KIND_NAMES);
    }
}
