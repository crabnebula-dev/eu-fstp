//! Independent reference for diary visibility (I-93, R-JV-03, O-54, O-57,
//! O-58, O-60, I-27).
//!
//! Written from `SPEC/12-journey-ui.md` sections 7.2, 8.3 and 15, ADR-015
//! "Visibility" and the P-10 reading documented in
//! `fstp_domain::visibility`. It shares only the domain's role, state and
//! P-10 types with production code. Its own [`Kind`] and [`Facts`] mirror
//! the production entry kind and relation, and the tests map between
//! them field by field.
//!
//! The matrix is data: [`MATRIX`] holds one row per entry kind of
//! section 7.2, and each row holds the spec's cell phrase per column as a
//! [`Phrase`]. [`Phrase::holds`] says what each phrase means, one phrase
//! at a time. The table, as written in the spec:
//!
//! | Kind | Voyager | Reviewer, committee | Coordinator, programme manager | Finance and operations | Auditor |
//! | --- | --- | --- | --- | --- | --- |
//! | State transition | Own proposal | Assigned proposals, within P-10 | Programme | Grants only | All |
//! | Deadline set or moved | Yes | Own task | Yes | Own task | Yes |
//! | Notice sent | Yes | No | Yes | Yes | Yes |
//! | Clarification | Yes | Assigned | Yes | No | Yes |
//! | Reviewer score or comment | After final decision (O-54) | Own, and as P-10 allows | Per P-10 | No | Yes |
//! | Conflict declared, reassigned | No | Own | Boolean outcome only | No | Positive matches |
//! | Vault verification outcome | Own, as pass or fail | No | Operations roles from NEGOTIATION | Yes | Yes |
//! | Contract versions, signatures | Yes | No | Yes | Yes | Yes |
//! | Milestone and payment request | Own grant | Assigned grants | Yes | Yes | Yes |
//! | Complaint steps | Complainant only | Complaint reviewers | Per SoD-13 | No | Yes |
//! | MCP and agent actions | Own | Own | Own | Own | Yes, with client identity |
//!
//! General gates, applied before the matrix:
//!
//! - A viewer sees only entries of the programme of their binding.
//! - A conflicted viewer outside the Receiving group sees nothing of the
//!   subject, except their own conflict entry (I-03).
//! - An FSTP coordinator sees no entry of a proposal before declaring no
//!   conflict on it. Before that, only per-state counts (O-57, R-CF-02).
//!
//! Readings taken here, interim, pending Daniel
//! (`docs/handoff/m4-design.md` section 15.0, lane j2):
//!
//! - Columns: Applicant and ApplicantTeamMember are the voyager column.
//!   CommitteeMember and CommitteeChair are "Reviewer, committee".
//!   FstpCoordinator and ProgrammeManager are "Coordinator, programme
//!   manager". FinanceApprover, PaymentReleaser and ContractSignatory are
//!   "Finance and operations". Auditor is the auditor column.
//! - A voyager reads the diary of their own proposal only, so "Yes" and
//!   "Own grant" in the voyager column mean the viewer is on the team.
//! - The guardian sees guardian steps they are named in, and nothing else
//!   (O-60, fail closed). No column of the table sees a guardian step.
//! - IRC members see the state transitions of a proposal they are
//!   assigned to, and nothing else: "the nominated proposal and outcome
//!   only" (R-IR-03, O-58). They get no route strip.
//! - CallDrafter and TenantAdmin see no diary entry. Tenant admins open
//!   the erasure log and the synthetic role preview instead (sections 7.3
//!   and 8.6).
//! - FinancialSignatory and LegalSignatory see no diary entry. Section 7.2
//!   and the section 1 actor table name neither. Section 1 lists the
//!   harbour office as "Finance approver, payment releaser, contract
//!   signatory". Both bind tenant-wide, with no programme for the first
//!   gate (`SPEC/02-domain/roles-and-sod.md` NOTE 5). Fail closed.
//! - "Within P-10" and "as P-10 allows", per `fstp_domain::visibility`
//!   and P-10 NOTE 1: "assigned reviewers only" admits an assigned
//!   reviewer. "All committee members" also admits a committee member who
//!   declared no conflict. "Operator staff only" admits no committee
//!   member at all: only the FSTP coordinator reads (O-43).
//! - "Per P-10" for the programme column: only the FSTP coordinator, and
//!   only under "operator staff only" (O-43). The programme manager sees
//!   no score.
//! - "Grants only": the entry's own leg is a leg of the grant, the leg
//!   into GRANTED or a later one. Evaluation legs stay hidden.
//! - "Operations roles from NEGOTIATION": the proposal has reached
//!   NEGOTIATION.
//! - "After final decision": the proposal has reached NOT_SELECTED,
//!   DECLINED or GRANTED. GRANTED is a decision, so later states keep it.
//!   INELIGIBLE and WITHDRAWN never show scores (O-54).
//! - "Boolean outcome only" and "positive matches" restrict what an
//!   entry shows, not whether it shows, so those cells are visible.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::TRANSITIONS;
use fstp_domain::id::ProgrammeId;
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;
use fstp_prop::Gen;

/// The entry kinds of section 7.2 and the guardian step (O-60).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// State transition.
    StateTransition,
    /// Deadline set or moved.
    DeadlineSet,
    /// Notice sent (contractual).
    NoticeSent,
    /// Clarification question and answer (stage 2).
    Clarification,
    /// Reviewer score or comment.
    ReviewerScore,
    /// Conflict declared, reassigned.
    Conflict,
    /// Vault verification outcome.
    VaultOutcome,
    /// Contract versions, signatures.
    Contract,
    /// Milestone and payment request states.
    MilestonePayment,
    /// Complaint steps.
    Complaint,
    /// MCP and agent actions.
    AgentAction,
    /// Guardian consent step.
    GuardianStep,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Kind; 12] = [
        Kind::StateTransition,
        Kind::DeadlineSet,
        Kind::NoticeSent,
        Kind::Clarification,
        Kind::ReviewerScore,
        Kind::Conflict,
        Kind::VaultOutcome,
        Kind::Contract,
        Kind::MilestonePayment,
        Kind::Complaint,
        Kind::AgentAction,
        Kind::GuardianStep,
    ];
}

/// The column of section 7.2 a role reads through, or a special class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Column {
    /// Voyager (applicant, team).
    Voyager,
    /// Reviewer, committee.
    Judging,
    /// Coordinator, programme manager.
    Programme,
    /// Finance and operations.
    Operations,
    /// Auditor.
    Auditor,
    /// The guardian of a minor (O-60).
    Guardian,
    /// An IRC member (R-IR-03, O-58).
    Irc,
    /// A role that reads no diary.
    None,
}

/// The column of `role`.
pub const fn column_of(role: Role) -> Column {
    match role {
        Role::Applicant | Role::ApplicantTeamMember => Column::Voyager,
        Role::CommitteeMember | Role::CommitteeChair => Column::Judging,
        Role::FstpCoordinator | Role::ProgrammeManager => Column::Programme,
        Role::FinanceApprover | Role::PaymentReleaser | Role::ContractSignatory => {
            Column::Operations
        }
        Role::Auditor => Column::Auditor,
        Role::Guardian => Column::Guardian,
        Role::IrcMember => Column::Irc,
        // Section 7.2 and the section 1 actor table name neither
        // signatory. They bind tenant-wide (roles-and-sod.md NOTE 5), so no
        // programme of theirs passes the first gate. Fail closed.
        Role::CallDrafter | Role::TenantAdmin | Role::FinancialSignatory | Role::LegalSignatory => {
            Column::None
        }
    }
}

/// One viewer and one entry, as the reference sees them. The fields
/// mirror `fstp_journey::visibility::{Viewer, Relation, EntryFacts}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Facts {
    /// The viewer's role.
    pub role: Role,
    /// The programme of the viewer's binding.
    pub viewer_programme: ProgrammeId,
    /// The programme of the entry's subject.
    pub entry_programme: ProgrammeId,
    /// P-10 of the subject's call.
    pub p10: ReadAccess,
    /// The kind.
    pub kind: Kind,
    /// The subject's route from DRAFT to its current state.
    pub path: Vec<StateTag>,
    /// The entry's own leg, for a state transition entry.
    pub transition: Option<(StateTag, StateTag)>,
    /// The viewer is on the proposal's team.
    pub team: bool,
    /// The viewer is the guardian the entry names.
    pub guardian_of: bool,
    /// The viewer holds an active assignment on the subject.
    pub assigned: bool,
    /// The viewer declared no conflict on the subject.
    pub declared_no_conflict: bool,
    /// The viewer has a conflict on the subject.
    pub conflicted: bool,
    /// The entry is the viewer's own.
    pub own: bool,
    /// The viewer reviews the complaint.
    pub complaint_reviewer: bool,
    /// SoD-13 bars the viewer from the complaint.
    pub sod13_barred: bool,
}

/// A cell phrase of the section 7.2 table, as the spec words it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phrase {
    /// "No".
    No,
    /// "Yes", "All", "Programme", "Boolean outcome only", "Positive
    /// matches", "Yes, with client identity".
    Yes,
    /// The voyager's "Yes", "Own proposal" and "Own grant": their team's.
    Team,
    /// "Visible only after final decision (O-54)".
    TeamAfterFinalDecision,
    /// "Own", "Own task", "Own, as pass or fail", "Complainant only".
    Own,
    /// "Assigned", "Assigned grants".
    Assigned,
    /// "Assigned proposals, within P-10".
    WithinP10,
    /// "Own, and as P-10 allows".
    OwnOrP10,
    /// "Per P-10" for the programme column (O-43).
    PerP10Staff,
    /// "Operations roles from NEGOTIATION".
    FromNegotiation,
    /// "Grants only".
    GrantsOnly,
    /// "Complaint reviewers".
    ComplaintReviewers,
    /// "Per SoD-13".
    PerSod13,
}

/// The section 7.2 table: per kind, the phrases of the voyager, reviewer,
/// programme, operations and auditor columns, in that order.
pub const MATRIX: [(Kind, [Phrase; 5]); 11] = {
    use Phrase as P;
    [
        (
            Kind::StateTransition,
            [P::Team, P::WithinP10, P::Yes, P::GrantsOnly, P::Yes],
        ),
        (Kind::DeadlineSet, [P::Team, P::Own, P::Yes, P::Own, P::Yes]),
        (Kind::NoticeSent, [P::Team, P::No, P::Yes, P::Yes, P::Yes]),
        (
            Kind::Clarification,
            [P::Team, P::Assigned, P::Yes, P::No, P::Yes],
        ),
        (
            Kind::ReviewerScore,
            [
                P::TeamAfterFinalDecision,
                P::OwnOrP10,
                P::PerP10Staff,
                P::No,
                P::Yes,
            ],
        ),
        (Kind::Conflict, [P::No, P::Own, P::Yes, P::No, P::Yes]),
        (
            Kind::VaultOutcome,
            [P::Own, P::No, P::FromNegotiation, P::Yes, P::Yes],
        ),
        (Kind::Contract, [P::Team, P::No, P::Yes, P::Yes, P::Yes]),
        (
            Kind::MilestonePayment,
            [P::Team, P::Assigned, P::Yes, P::Yes, P::Yes],
        ),
        (
            Kind::Complaint,
            [P::Own, P::ComplaintReviewers, P::PerSod13, P::No, P::Yes],
        ),
        (Kind::AgentAction, [P::Own, P::Own, P::Own, P::Own, P::Yes]),
    ]
};

/// The states of a grant: GRANTED and the states after it in the state
/// machine (`SPEC/02-domain/state-machine.md`).
const GRANT_STATES: [StateTag; 4] = [
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// O-54: the final decisions. GRANTED is one, not a terminal state.
const FINAL_DECISIONS: [StateTag; 3] =
    [StateTag::NotSelected, StateTag::Declined, StateTag::Granted];

/// Whether P-10 lets a holder of `role` on the judging side read a
/// proposal, as `fstp_domain::visibility` documents it for STAGE1 and
/// STAGE2 (P-10 NOTE 1, O-43).
pub fn p10_admits(p10: ReadAccess, role: Role, assigned: bool, declared: bool) -> bool {
    match p10 {
        ReadAccess::AssignedReviewersOnly => assigned,
        ReadAccess::AllCommitteeMembers => assigned || (declared && role == Role::CommitteeMember),
        // "Admits only the FSTP coordinator".
        ReadAccess::OperatorStaffOnly => false,
    }
}

impl Phrase {
    /// Whether the phrase admits the viewer of `f`.
    pub fn holds(self, f: &Facts) -> bool {
        match self {
            Phrase::No => false,
            Phrase::Yes => true,
            Phrase::Team => f.team,
            Phrase::TeamAfterFinalDecision => {
                f.team && FINAL_DECISIONS.iter().any(|s| f.path.contains(s))
            }
            Phrase::Own => f.own,
            Phrase::Assigned => f.assigned,
            Phrase::WithinP10 => p10_admits(f.p10, f.role, f.assigned, f.declared_no_conflict),
            Phrase::OwnOrP10 => {
                f.own || p10_admits(f.p10, f.role, f.assigned, f.declared_no_conflict)
            }
            Phrase::PerP10Staff => {
                f.p10 == ReadAccess::OperatorStaffOnly && f.role == Role::FstpCoordinator
            }
            Phrase::FromNegotiation => f.path.contains(&StateTag::Negotiation),
            Phrase::GrantsOnly => {
                matches!(f.transition, Some((_, to)) if GRANT_STATES.contains(&to))
            }
            Phrase::ComplaintReviewers => f.complaint_reviewer,
            Phrase::PerSod13 => !f.sod13_barred,
        }
    }
}

/// The phrase of the table for `kind` in `column`, or `None` for a column
/// or kind the table has no cell for.
pub fn phrase(kind: Kind, column: Column) -> Option<Phrase> {
    let i = match column {
        Column::Voyager => 0,
        Column::Judging => 1,
        Column::Programme => 2,
        Column::Operations => 3,
        Column::Auditor => 4,
        Column::Guardian | Column::Irc | Column::None => return None,
    };
    let (_, row) = MATRIX.iter().find(|(k, _)| *k == kind)?;
    row.get(i).copied()
}

/// Whether the entry reaches the viewer (I-93): the gates, then the
/// table cell, or the readings for the columns outside the table.
pub fn visible(f: &Facts) -> bool {
    if f.viewer_programme != f.entry_programme {
        return false;
    }
    let column = column_of(f.role);
    let own_conflict = f.kind == Kind::Conflict && f.own;
    // I-03: the Receiving group, applicants, team and guardian, keep
    // seeing their own proposal.
    let receiving = matches!(
        f.role,
        Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
    );
    if f.conflicted && !receiving && !own_conflict {
        return false;
    }
    // O-57, R-CF-02.
    if f.role == Role::FstpCoordinator && !f.declared_no_conflict && !own_conflict {
        return false;
    }
    match column {
        // O-60: the named guardian, and nothing else.
        Column::Guardian => f.kind == Kind::GuardianStep && f.guardian_of,
        // R-IR-03, O-58: the outcome of the nominated proposal.
        Column::Irc => f.kind == Kind::StateTransition && f.assigned,
        Column::None => false,
        // O-60: no table column sees a guardian step; the table has no
        // row for it, so `phrase` gives `None`.
        _ => phrase(f.kind, column).is_some_and(|p| p.holds(f)),
    }
}

/// Whether `role` gets the route strip of section 8.3: the judging roles
/// except IRC members (O-58). `None` where the spec is silent.
pub const fn route_strip(role: Role) -> Option<bool> {
    match role {
        Role::CommitteeMember | Role::CommitteeChair | Role::FstpCoordinator => Some(true),
        Role::IrcMember => Some(false),
        _ => None,
    }
}

/// The per-state counts of O-57: how many proposals sit in each state.
pub fn state_counts(states: &[StateTag]) -> BTreeMap<StateTag, u64> {
    let mut out: BTreeMap<StateTag, u64> = BTreeMap::new();
    for s in states {
        let n = out.entry(*s).or_insert(0);
        *n = n.saturating_add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// Generators

/// The programmes the generator draws from.
pub const PROGRAMMES: [ProgrammeId; 2] = [ProgrammeId::from_raw(1), ProgrammeId::from_raw(2)];

/// The P-10 options.
pub const P10_OPTIONS: [ReadAccess; 3] = [
    ReadAccess::AssignedReviewersOnly,
    ReadAccess::AllCommitteeMembers,
    ReadAccess::OperatorStaffOnly,
];

/// A route from DRAFT along the domain's transition table, of at most
/// `max` legs. Withdrawal rows are taken from every state they leave.
pub fn route(g: &mut Gen, max: usize) -> Vec<StateTag> {
    let mut path = vec![StateTag::Draft];
    let legs = g.usize_in(0..=max);
    for _ in 0..legs {
        let Some(here) = path.last().copied() else {
            break;
        };
        let next: Vec<StateTag> = TRANSITIONS
            .iter()
            .filter(|r| r.from.contains(&here))
            .map(|r| r.to)
            .collect();
        if next.is_empty() {
            break;
        }
        path.push(*g.pick(&next));
    }
    path
}

/// A route that ends in `last`, found by a bounded search of the
/// transition table from DRAFT. `None` for a state the table cannot reach.
pub fn route_to(last: StateTag) -> Option<Vec<StateTag>> {
    let mut frontier: Vec<Vec<StateTag>> = vec![vec![StateTag::Draft]];
    for _ in 0..StateTag::ALL.len() {
        let mut next_frontier = Vec::new();
        for path in &frontier {
            let Some(here) = path.last().copied() else {
                continue;
            };
            if here == last {
                return Some(path.clone());
            }
            for r in TRANSITIONS.iter().filter(|r| r.from.contains(&here)) {
                if !path.contains(&r.to) {
                    let mut p = path.clone();
                    p.push(r.to);
                    next_frontier.push(p);
                }
            }
        }
        frontier = next_frontier;
    }
    None
}

/// Random facts for one viewer and one entry.
pub fn facts(g: &mut Gen) -> Facts {
    let role = *g.pick(&Role::ALL);
    let viewer_programme = *g.pick(&PROGRAMMES);
    // Mostly the same programme, so the matrix is exercised.
    let entry_programme = if g.u8_in(0..=7) == 0 {
        *g.pick(&PROGRAMMES)
    } else {
        viewer_programme
    };
    let kind = *g.pick(&Kind::ALL);
    let path = route(g, 9);
    let transition = if kind == Kind::StateTransition {
        leg_of(g, &path)
    } else {
        None
    };
    Facts {
        role,
        viewer_programme,
        entry_programme,
        p10: *g.pick(&P10_OPTIONS),
        kind,
        path,
        transition,
        team: g.bool(),
        guardian_of: g.bool(),
        assigned: g.bool(),
        declared_no_conflict: g.bool(),
        conflicted: g.u8_in(0..=3) == 0,
        own: g.bool(),
        complaint_reviewer: g.bool(),
        sod13_barred: g.bool(),
    }
}

/// One leg of `path`, as its source and target state, or `None` for a
/// route with no leg yet.
pub fn leg_of(g: &mut Gen, path: &[StateTag]) -> Option<(StateTag, StateTag)> {
    let legs: Vec<(StateTag, StateTag)> = path
        .windows(2)
        .filter_map(|w| match w {
            [a, b] => Some((*a, *b)),
            _ => None,
        })
        .collect();
    if legs.is_empty() {
        None
    } else {
        Some(*g.pick(&legs))
    }
}
