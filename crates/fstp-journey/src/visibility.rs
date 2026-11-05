//! The diary visibility function (I-93, `SPEC/12-journey-ui.md` section
//! 7.2, ADR-015 "Visibility").
//!
//! [`visible`] decides per request whether one diary entry reaches one
//! viewer. Its specification is the matrix of section 7.2, with O-54,
//! O-57, O-58 and O-60 (decided 2026-11-01). Nothing is stored once and
//! filtered in the browser.
//!
//! The caller computes the [`Relation`] of the viewer to the entry from
//! the cell's state at read time: team membership, assignments,
//! declarations, conflicts and whether the entry is the viewer's own.
//! The function itself reads no state, no clock and no vault.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::id::ProgrammeId;
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;

/// The entry kinds of section 7.2, plus the guardian step of O-60.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// A state transition.
    StateTransition,
    /// A deadline set or moved.
    DeadlineSet,
    /// A contractual notice sent.
    NoticeSent,
    /// A stage 2 clarification question or answer.
    Clarification,
    /// A reviewer score or comment.
    ReviewerScore,
    /// A conflict declared, or a reassignment after one.
    Conflict,
    /// A vault verification outcome.
    VaultOutcome,
    /// A contract version or signature.
    Contract,
    /// A milestone or payment request state.
    MilestonePayment,
    /// A complaint step.
    Complaint,
    /// An MCP or agent action.
    AgentAction,
    /// A minor's guardian consent step (O-60).
    GuardianStep,
}

impl EntryKind {
    /// Every kind, in the row order of section 7.2, the guardian step last.
    pub const ALL: [EntryKind; 12] = [
        EntryKind::StateTransition,
        EntryKind::DeadlineSet,
        EntryKind::NoticeSent,
        EntryKind::Clarification,
        EntryKind::ReviewerScore,
        EntryKind::Conflict,
        EntryKind::VaultOutcome,
        EntryKind::Contract,
        EntryKind::MilestonePayment,
        EntryKind::Complaint,
        EntryKind::AgentAction,
        EntryKind::GuardianStep,
    ];
}

/// What the cell knows, at read time, of the viewer's relation to one
/// entry and its subject.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Relation {
    /// The viewer holds an active Receiving binding on the subject
    /// proposal as its lead or a team member.
    pub team: bool,
    /// The viewer is the guardian the entry names.
    pub guardian_of: bool,
    /// The viewer holds an active assignment on the subject.
    pub assigned: bool,
    /// The viewer recorded a proposal-level declaration of no conflict on
    /// the subject (R-CF-02).
    pub declared_no_conflict: bool,
    /// A conflict fact exists for the viewer on the subject, or the vault
    /// answers `HasConflict` (I-03).
    pub conflicted: bool,
    /// The entry is the viewer's own: their score, declaration, task,
    /// verification, complaint or agent action.
    pub own: bool,
    /// The viewer reviews the complaint the entry belongs to.
    pub complaint_reviewer: bool,
    /// SoD-13 bars the viewer from the complaint: they took part in the
    /// contested decision.
    pub sod13_barred: bool,
}

/// The viewer of one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Viewer {
    /// The role the viewer reads through.
    pub role: Role,
    /// The programme of that role's binding.
    pub programme: ProgrammeId,
    /// The viewer's relation to the entry.
    pub relation: Relation,
}

/// The facts of one entry that visibility reads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntryFacts {
    /// The kind.
    pub kind: EntryKind,
    /// The programme of the subject.
    pub programme: ProgrammeId,
    /// The states the subject proposal has been in, in order, from DRAFT
    /// to its current state. Empty for a subject with no proposal.
    pub path: Vec<StateTag>,
    /// The entry's own leg, as its source and target state, for a state
    /// transition entry. `None` for every other kind.
    pub transition: Option<(StateTag, StateTag)>,
}

/// The states of a grant: GRANTED and every state after it.
const GRANT_STATES: [StateTag; 4] = [
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

impl EntryFacts {
    /// Whether the subject has been in `state`.
    fn reached(&self, state: StateTag) -> bool {
        self.path.contains(&state)
    }

    /// Whether the entry is a leg of the grant: the leg into GRANTED, or
    /// a later one. No leg leaves a grant state for a state before it.
    fn grant_leg(&self) -> bool {
        self.transition
            .is_some_and(|(_, to)| GRANT_STATES.contains(&to))
    }

    /// Whether a final decision was made: NOT_SELECTED, DECLINED or
    /// GRANTED. GRANTED is a decision, not a terminal state, so the states
    /// after it keep it (O-54). INELIGIBLE and WITHDRAWN are no decision.
    fn decided(&self) -> bool {
        self.reached(StateTag::NotSelected)
            || self.reached(StateTag::Declined)
            || self.reached(StateTag::Granted)
    }
}

/// The column of the section 7.2 matrix a role reads through, or a class
/// of its own.
///
/// Interim, pending Daniel (`docs/handoff/m4-design.md` section 15.0,
/// lane j2): the guardian and the IRC member have classes of their own
/// (O-60, O-58). The call drafter, the tenant admin and the financial
/// and legal signatories read no diary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Column {
    /// Voyager: applicant and team member.
    Voyager,
    /// Reviewer, committee: committee member and chair.
    Judging,
    /// Coordinator, programme manager.
    Programme,
    /// Finance and operations: finance approver, payment releaser and
    /// contract signatory.
    Operations,
    /// Auditor.
    Auditor,
    /// The guardian of a minor (O-60).
    Guardian,
    /// An IRC member: the nominated proposal and its outcome only
    /// (R-IR-03, O-58).
    Irc,
    /// A role that reads no diary entry.
    None,
}

impl Column {
    /// Every column, in declaration order.
    pub const ALL: [Column; 8] = [
        Column::Voyager,
        Column::Judging,
        Column::Programme,
        Column::Operations,
        Column::Auditor,
        Column::Guardian,
        Column::Irc,
        Column::None,
    ];

    /// The column of `role`.
    pub const fn of(role: Role) -> Column {
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
            // Interim, fail closed: section 7.2 and the section 1 actor table
            // name neither signatory, and both bind tenant-wide, with no
            // programme for the first gate (NOTE 5 of roles-and-sod.md).
            Role::CallDrafter
            | Role::TenantAdmin
            | Role::FinancialSignatory
            | Role::LegalSignatory => Column::None,
        }
    }

    /// The bit of the column in a `scope_mask` (section 11).
    pub const fn bit(self) -> u32 {
        match self {
            Column::Voyager => 1,
            Column::Judging => 2,
            Column::Programme => 4,
            Column::Operations => 8,
            Column::Auditor => 16,
            Column::Guardian => 32,
            Column::Irc => 64,
            Column::None => 0,
        }
    }

    /// Whether the column is the Receiving group, which a conflict never
    /// hides the subject from (I-03).
    const fn receiving(self) -> bool {
        matches!(self, Column::Voyager | Column::Guardian)
    }
}

/// The coarse `scope_mask` of an entry of `kind` (section 11): every
/// column whose matrix cell can hold for some viewer. It is a pre-filter
/// only. [`visible`] still decides per request (I-93).
pub const fn scope_mask(kind: EntryKind) -> u32 {
    use EntryKind as K;
    let v = Column::Voyager.bit();
    let j = Column::Judging.bit();
    let p = Column::Programme.bit();
    let o = Column::Operations.bit();
    let a = Column::Auditor.bit();
    match kind {
        K::StateTransition => v | j | p | o | a | Column::Irc.bit(),
        K::DeadlineSet | K::MilestonePayment | K::AgentAction => v | j | p | o | a,
        K::NoticeSent | K::VaultOutcome | K::Contract => v | p | o | a,
        K::Clarification | K::ReviewerScore | K::Complaint => v | j | p | a,
        K::Conflict => j | p | a,
        K::GuardianStep => Column::Guardian.bit(),
    }
}

/// Whether P-10 lets a judging viewer read the proposal, as
/// `fstp_domain::visibility` reads it (P-10 NOTE 1, O-43):
///
/// - "assigned reviewers only": an active assignment;
/// - "all committee members": an active assignment, or a committee
///   member's declaration of no conflict;
/// - "operator staff only": no committee member reads. The FSTP
///   coordinator reads through the programme column instead.
///
/// The domain's NEGOTIATION reading for assigned reviewers is about the
/// amount, not the diary, so it opens nothing here (fail closed).
fn p10_reader(role: Role, r: &Relation, p10: ReadAccess) -> bool {
    match p10 {
        ReadAccess::AssignedReviewersOnly => r.assigned,
        ReadAccess::AllCommitteeMembers => {
            r.assigned || (role == Role::CommitteeMember && r.declared_no_conflict)
        }
        ReadAccess::OperatorStaffOnly => false,
    }
}

/// The matrix cell of section 7.2, before the general gates.
fn cell(column: Column, role: Role, p10: ReadAccess, r: &Relation, e: &EntryFacts) -> bool {
    use EntryKind as K;
    match column {
        Column::Voyager => match e.kind {
            K::StateTransition
            | K::DeadlineSet
            | K::NoticeSent
            | K::Clarification
            | K::Contract
            | K::MilestonePayment => r.team,
            // O-54: only after a final decision. P-11 anonymity shapes the
            // sentence, not whether the entry shows.
            K::ReviewerScore => r.team && e.decided(),
            // "Own, as pass or fail", "Complainant only", "Own".
            K::VaultOutcome | K::Complaint | K::AgentAction => r.own,
            K::Conflict | K::GuardianStep => false,
        },
        Column::Judging => match e.kind {
            K::StateTransition => p10_reader(role, r, p10),
            K::DeadlineSet | K::Conflict | K::AgentAction => r.own,
            K::Clarification | K::MilestonePayment => r.assigned,
            K::ReviewerScore => r.own || p10_reader(role, r, p10),
            K::Complaint => r.complaint_reviewer,
            K::NoticeSent | K::VaultOutcome | K::Contract | K::GuardianStep => false,
        },
        Column::Programme => match e.kind {
            K::StateTransition
            | K::DeadlineSet
            | K::NoticeSent
            | K::Clarification
            | K::Conflict
            | K::Contract
            | K::MilestonePayment => true,
            // "Per P-10": the coordinator under "operator staff only"
            // (O-43). The programme manager sees no score.
            K::ReviewerScore => {
                role == Role::FstpCoordinator && p10 == ReadAccess::OperatorStaffOnly
            }
            // "Operations roles from NEGOTIATION".
            K::VaultOutcome => e.reached(StateTag::Negotiation),
            // "Per SoD-13": not to a person who took part in the decision.
            K::Complaint => !r.sod13_barred,
            K::AgentAction => r.own,
            K::GuardianStep => false,
        },
        Column::Operations => match e.kind {
            // "Grants only": the legs of the grant, never the evaluation
            // legs before it.
            K::StateTransition => e.grant_leg(),
            K::DeadlineSet | K::AgentAction => r.own,
            K::NoticeSent | K::VaultOutcome | K::Contract | K::MilestonePayment => true,
            K::Clarification | K::ReviewerScore | K::Conflict | K::Complaint | K::GuardianStep => {
                false
            }
        },
        // "Positive matches" and "with client identity" shape what the
        // entry shows, not whether it shows. O-60: never a guardian step.
        Column::Auditor => e.kind != K::GuardianStep,
        // O-60: the guardian a step names, and nothing else.
        Column::Guardian => e.kind == K::GuardianStep && r.guardian_of,
        // R-IR-03, O-58: the outcome of a proposal the member is assigned.
        Column::Irc => e.kind == K::StateTransition && r.assigned,
        Column::None => false,
    }
}

/// Whether the entry reaches the viewer under P-10 (I-93, section 7.2).
///
/// The general gates come first:
///
/// - only entries of the programme of the viewer's binding (I-82);
/// - a conflicted viewer outside the Receiving group sees nothing of the
///   subject but their own conflict entry (I-03);
/// - an FSTP coordinator sees no entry of a proposal before declaring no
///   conflict on it, but their own conflict entry (O-57, R-CF-02).
///
/// Then the matrix cell of the viewer's column decides.
pub fn visible(viewer: &Viewer, p10: ReadAccess, entry: &EntryFacts) -> bool {
    if viewer.programme != entry.programme {
        return false;
    }
    let column = Column::of(viewer.role);
    let r = &viewer.relation;
    let own_conflict = entry.kind == EntryKind::Conflict && r.own;
    if r.conflicted && !column.receiving() && !own_conflict {
        return false;
    }
    if viewer.role == Role::FstpCoordinator && !r.declared_no_conflict && !own_conflict {
        return false;
    }
    cell(column, viewer.role, p10, r, entry)
}

/// Whether a viewer reading through `role` gets the route strip of
/// section 8.3: committee members, committee chairs and FSTP
/// coordinators. IRC members get none (O-58). The Receiving roles get the
/// full route map instead, and other roles no strip.
pub const fn route_strip(role: Role) -> bool {
    matches!(
        role,
        Role::CommitteeMember | Role::CommitteeChair | Role::FstpCoordinator
    )
}

/// The aggregate per-state counts a coordinator may see before conflict
/// declaration (O-57): one count per state that holds a proposal, with no
/// id, title or applicant datum.
pub fn state_counts(states: &[StateTag]) -> BTreeMap<StateTag, u64> {
    let mut out: BTreeMap<StateTag, u64> = BTreeMap::new();
    for s in states {
        let n = out.entry(*s).or_insert(0);
        *n = n.saturating_add(1);
    }
    out
}
