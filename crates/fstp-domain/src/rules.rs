//! Transition rules, actor rules and the parameter catalogue as data (design sections 2.4 and 3.2).
//!
//! - [`TRANSITIONS`] holds every row of the transitions table in
//!   `SPEC/02-domain/state-machine.md`. The row that leaves DEFERRED for
//!   "STAGE2 or IRC_REVIEW" is split into one rule per target.
//! - [`ACTOR_RULES`] gives the actor rule of every command kind. It is the
//!   single source for the M4 authorisation matrix and MCP parity (I-84).
//! - [`CATALOGUE`] holds every policy parameter of
//!   `SPEC/02-domain/policy-parameters.md` with its frozen flag and level.
//!
//! The tests in `crates/fstp-domain/tests/` read the spec markdown at test
//! time and check each table against these constants in both directions.

use crate::command::CommandKind;
use crate::decision::NegotiationFailure;
use crate::refusal::RuleRef;
use crate::roles::Role;

// ---------------------------------------------------------------------------
// Policy parameter catalogue
// ---------------------------------------------------------------------------

/// A policy parameter of `SPEC/02-domain/policy-parameters.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamId {
    /// P-01.
    P01,
    /// P-02.
    P02,
    /// P-03.
    P03,
    /// P-04.
    P04,
    /// P-05.
    P05,
    /// P-06.
    P06,
    /// P-07.
    P07,
    /// P-08.
    P08,
    /// P-09.
    P09,
    /// P-10.
    P10,
    /// P-11.
    P11,
    /// P-12.
    P12,
    /// P-13.
    P13,
    /// P-14.
    P14,
    /// P-15.
    P15,
    /// P-16.
    P16,
    /// P-17.
    P17,
    /// P-18.
    P18,
    /// P-19.
    P19,
    /// P-20.
    P20,
    /// P-21.
    P21,
    /// P-22.
    P22,
    /// P-23.
    P23,
    /// P-24.
    P24,
    /// P-25.
    P25,
    /// P-26.
    P26,
    /// P-27.
    P27,
    /// P-28.
    P28,
    /// P-29.
    P29,
    /// P-30.
    P30,
    /// P-31.
    P31,
    /// P-32.
    P32,
    /// P-33.
    P33,
    /// P-34.
    P34,
    /// P-35.
    P35,
    /// P-36.
    P36,
    /// P-37.
    P37,
    /// P-38.
    P38,
    /// P-39.
    P39,
    /// P-40.
    P40,
    /// P-41.
    P41,
    /// P-42.
    P42,
    /// P-43.
    P43,
    /// P-44.
    P44,
    /// P-45.
    P45,
    /// P-46.
    P46,
    /// P-47.
    P47,
    /// P-48.
    P48,
    /// P-49.
    P49,
    /// P-50.
    P50,
    /// P-51.
    P51,
    /// P-52.
    P52,
    /// P-53.
    P53,
    /// P-54.
    P54,
    /// P-55.
    P55,
    /// P-56.
    P56,
    /// P-57.
    P57,
    /// P-58.
    P58,
    /// P-59.
    P59,
    /// P-60.
    P60,
    /// P-61.
    P61,
    /// P-62.
    P62,
    /// P-63.
    P63,
    /// P-64.
    P64,
    /// P-65.
    P65,
    /// P-66.
    P66,
    /// P-67.
    P67,
    /// P-68.
    P68,
    /// P-69.
    P69,
    /// P-70.
    P70,
    /// P-71.
    P71,
    /// P-72.
    P72,
    /// P-73.
    P73,
    /// P-74.
    P74,
    /// P-75.
    P75,
    /// P-76.
    P76,
    /// P-77.
    P77,
    /// P-78.
    P78,
}

impl ParamId {
    /// Every parameter, in id order.
    pub const ALL: [ParamId; 78] = [
        ParamId::P01,
        ParamId::P02,
        ParamId::P03,
        ParamId::P04,
        ParamId::P05,
        ParamId::P06,
        ParamId::P07,
        ParamId::P08,
        ParamId::P09,
        ParamId::P10,
        ParamId::P11,
        ParamId::P12,
        ParamId::P13,
        ParamId::P14,
        ParamId::P15,
        ParamId::P16,
        ParamId::P17,
        ParamId::P18,
        ParamId::P19,
        ParamId::P20,
        ParamId::P21,
        ParamId::P22,
        ParamId::P23,
        ParamId::P24,
        ParamId::P25,
        ParamId::P26,
        ParamId::P27,
        ParamId::P28,
        ParamId::P29,
        ParamId::P30,
        ParamId::P31,
        ParamId::P32,
        ParamId::P33,
        ParamId::P34,
        ParamId::P35,
        ParamId::P36,
        ParamId::P37,
        ParamId::P38,
        ParamId::P39,
        ParamId::P40,
        ParamId::P41,
        ParamId::P42,
        ParamId::P43,
        ParamId::P44,
        ParamId::P45,
        ParamId::P46,
        ParamId::P47,
        ParamId::P48,
        ParamId::P49,
        ParamId::P50,
        ParamId::P51,
        ParamId::P52,
        ParamId::P53,
        ParamId::P54,
        ParamId::P55,
        ParamId::P56,
        ParamId::P57,
        ParamId::P58,
        ParamId::P59,
        ParamId::P60,
        ParamId::P61,
        ParamId::P62,
        ParamId::P63,
        ParamId::P64,
        ParamId::P65,
        ParamId::P66,
        ParamId::P67,
        ParamId::P68,
        ParamId::P69,
        ParamId::P70,
        ParamId::P71,
        ParamId::P72,
        ParamId::P73,
        ParamId::P74,
        ParamId::P75,
        ParamId::P76,
        ParamId::P77,
        ParamId::P78,
    ];

    /// The spec identifier, such as `"P-12"`.
    pub const fn spec_id(self) -> &'static str {
        match self {
            ParamId::P01 => "P-01",
            ParamId::P02 => "P-02",
            ParamId::P03 => "P-03",
            ParamId::P04 => "P-04",
            ParamId::P05 => "P-05",
            ParamId::P06 => "P-06",
            ParamId::P07 => "P-07",
            ParamId::P08 => "P-08",
            ParamId::P09 => "P-09",
            ParamId::P10 => "P-10",
            ParamId::P11 => "P-11",
            ParamId::P12 => "P-12",
            ParamId::P13 => "P-13",
            ParamId::P14 => "P-14",
            ParamId::P15 => "P-15",
            ParamId::P16 => "P-16",
            ParamId::P17 => "P-17",
            ParamId::P18 => "P-18",
            ParamId::P19 => "P-19",
            ParamId::P20 => "P-20",
            ParamId::P21 => "P-21",
            ParamId::P22 => "P-22",
            ParamId::P23 => "P-23",
            ParamId::P24 => "P-24",
            ParamId::P25 => "P-25",
            ParamId::P26 => "P-26",
            ParamId::P27 => "P-27",
            ParamId::P28 => "P-28",
            ParamId::P29 => "P-29",
            ParamId::P30 => "P-30",
            ParamId::P31 => "P-31",
            ParamId::P32 => "P-32",
            ParamId::P33 => "P-33",
            ParamId::P34 => "P-34",
            ParamId::P35 => "P-35",
            ParamId::P36 => "P-36",
            ParamId::P37 => "P-37",
            ParamId::P38 => "P-38",
            ParamId::P39 => "P-39",
            ParamId::P40 => "P-40",
            ParamId::P41 => "P-41",
            ParamId::P42 => "P-42",
            ParamId::P43 => "P-43",
            ParamId::P44 => "P-44",
            ParamId::P45 => "P-45",
            ParamId::P46 => "P-46",
            ParamId::P47 => "P-47",
            ParamId::P48 => "P-48",
            ParamId::P49 => "P-49",
            ParamId::P50 => "P-50",
            ParamId::P51 => "P-51",
            ParamId::P52 => "P-52",
            ParamId::P53 => "P-53",
            ParamId::P54 => "P-54",
            ParamId::P55 => "P-55",
            ParamId::P56 => "P-56",
            ParamId::P57 => "P-57",
            ParamId::P58 => "P-58",
            ParamId::P59 => "P-59",
            ParamId::P60 => "P-60",
            ParamId::P61 => "P-61",
            ParamId::P62 => "P-62",
            ParamId::P63 => "P-63",
            ParamId::P64 => "P-64",
            ParamId::P65 => "P-65",
            ParamId::P66 => "P-66",
            ParamId::P67 => "P-67",
            ParamId::P68 => "P-68",
            ParamId::P69 => "P-69",
            ParamId::P70 => "P-70",
            ParamId::P71 => "P-71",
            ParamId::P72 => "P-72",
            ParamId::P73 => "P-73",
            ParamId::P74 => "P-74",
            ParamId::P75 => "P-75",
            ParamId::P76 => "P-76",
            ParamId::P77 => "P-77",
            ParamId::P78 => "P-78",
        }
    }

    /// The parameter's catalogue entry.
    pub fn spec(self) -> Option<ParamSpec> {
        CATALOGUE.iter().copied().find(|s| s.id == self)
    }
}

/// Whether a parameter freezes when a call publishes (I-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Freeze {
    /// "Yes" in the Frozen column: locked for a call at publication.
    Frozen,
    /// Every other entry: read live at decision time, never frozen per call.
    Live,
}

/// Where a parameter is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Per programme. The default, and "programme-level" in the Frozen column.
    Programme,
    /// Per tenant: "tenant-level" in the Frozen column. Tenant configuration in M3 and M4.
    Tenant,
    /// Not configurable: "Not tenant-configurable" in the Frozen column (P-68).
    Fixed,
}

/// One catalogue entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParamSpec {
    /// The parameter.
    pub id: ParamId,
    /// Whether it freezes at publication.
    pub freeze: Freeze,
    /// Where it is set.
    pub level: Level,
}

const fn spec(id: ParamId, freeze: Freeze, level: Level) -> ParamSpec {
    ParamSpec { id, freeze, level }
}

/// Every parameter of `SPEC/02-domain/policy-parameters.md`, in id order.
/// Transcribed from both tables there and checked against them by
/// `spec_catalogue_matches_policy_parameters`.
pub const CATALOGUE: [ParamSpec; 78] = [
    spec(ParamId::P01, Freeze::Frozen, Level::Programme),
    spec(ParamId::P02, Freeze::Frozen, Level::Programme),
    spec(ParamId::P03, Freeze::Frozen, Level::Programme),
    spec(ParamId::P04, Freeze::Frozen, Level::Programme),
    spec(ParamId::P05, Freeze::Live, Level::Programme),
    spec(ParamId::P06, Freeze::Live, Level::Programme),
    spec(ParamId::P07, Freeze::Frozen, Level::Programme),
    spec(ParamId::P08, Freeze::Frozen, Level::Programme),
    spec(ParamId::P09, Freeze::Frozen, Level::Programme),
    spec(ParamId::P10, Freeze::Frozen, Level::Programme),
    spec(ParamId::P11, Freeze::Frozen, Level::Programme),
    spec(ParamId::P12, Freeze::Live, Level::Programme),
    spec(ParamId::P13, Freeze::Live, Level::Programme),
    spec(ParamId::P14, Freeze::Frozen, Level::Programme),
    spec(ParamId::P15, Freeze::Frozen, Level::Programme),
    spec(ParamId::P16, Freeze::Frozen, Level::Programme),
    spec(ParamId::P17, Freeze::Frozen, Level::Programme),
    spec(ParamId::P18, Freeze::Live, Level::Programme),
    spec(ParamId::P19, Freeze::Live, Level::Programme),
    spec(ParamId::P20, Freeze::Live, Level::Tenant),
    spec(ParamId::P21, Freeze::Frozen, Level::Programme),
    spec(ParamId::P22, Freeze::Live, Level::Programme),
    spec(ParamId::P23, Freeze::Frozen, Level::Programme),
    spec(ParamId::P24, Freeze::Frozen, Level::Programme),
    spec(ParamId::P25, Freeze::Frozen, Level::Programme),
    spec(ParamId::P26, Freeze::Frozen, Level::Programme),
    spec(ParamId::P27, Freeze::Live, Level::Programme),
    spec(ParamId::P28, Freeze::Frozen, Level::Programme),
    spec(ParamId::P29, Freeze::Frozen, Level::Programme),
    spec(ParamId::P30, Freeze::Frozen, Level::Programme),
    spec(ParamId::P31, Freeze::Live, Level::Programme),
    spec(ParamId::P32, Freeze::Live, Level::Programme),
    spec(ParamId::P33, Freeze::Live, Level::Programme),
    spec(ParamId::P34, Freeze::Frozen, Level::Programme),
    spec(ParamId::P35, Freeze::Live, Level::Programme),
    spec(ParamId::P36, Freeze::Live, Level::Programme),
    spec(ParamId::P37, Freeze::Live, Level::Programme),
    spec(ParamId::P38, Freeze::Live, Level::Programme),
    spec(ParamId::P39, Freeze::Frozen, Level::Programme),
    spec(ParamId::P40, Freeze::Live, Level::Programme),
    spec(ParamId::P41, Freeze::Live, Level::Programme),
    spec(ParamId::P42, Freeze::Live, Level::Programme),
    spec(ParamId::P43, Freeze::Live, Level::Programme),
    spec(ParamId::P44, Freeze::Frozen, Level::Programme),
    spec(ParamId::P45, Freeze::Live, Level::Programme),
    spec(ParamId::P46, Freeze::Live, Level::Programme),
    spec(ParamId::P47, Freeze::Live, Level::Programme),
    spec(ParamId::P48, Freeze::Live, Level::Programme),
    spec(ParamId::P49, Freeze::Live, Level::Programme),
    spec(ParamId::P50, Freeze::Live, Level::Programme),
    spec(ParamId::P51, Freeze::Live, Level::Programme),
    spec(ParamId::P52, Freeze::Live, Level::Programme),
    spec(ParamId::P53, Freeze::Frozen, Level::Programme),
    spec(ParamId::P54, Freeze::Live, Level::Programme),
    spec(ParamId::P55, Freeze::Frozen, Level::Programme),
    spec(ParamId::P56, Freeze::Live, Level::Programme),
    spec(ParamId::P57, Freeze::Live, Level::Programme),
    spec(ParamId::P58, Freeze::Live, Level::Programme),
    spec(ParamId::P59, Freeze::Frozen, Level::Programme),
    spec(ParamId::P60, Freeze::Frozen, Level::Programme),
    spec(ParamId::P61, Freeze::Frozen, Level::Programme),
    spec(ParamId::P62, Freeze::Frozen, Level::Programme),
    spec(ParamId::P63, Freeze::Frozen, Level::Programme),
    spec(ParamId::P64, Freeze::Frozen, Level::Programme),
    spec(ParamId::P65, Freeze::Frozen, Level::Programme),
    spec(ParamId::P66, Freeze::Frozen, Level::Programme),
    spec(ParamId::P67, Freeze::Live, Level::Programme),
    spec(ParamId::P68, Freeze::Live, Level::Fixed),
    spec(ParamId::P69, Freeze::Live, Level::Tenant),
    spec(ParamId::P70, Freeze::Live, Level::Tenant),
    spec(ParamId::P71, Freeze::Live, Level::Tenant),
    spec(ParamId::P72, Freeze::Live, Level::Tenant),
    spec(ParamId::P73, Freeze::Live, Level::Tenant),
    spec(ParamId::P74, Freeze::Live, Level::Tenant),
    spec(ParamId::P75, Freeze::Frozen, Level::Programme),
    spec(ParamId::P76, Freeze::Live, Level::Programme),
    spec(ParamId::P77, Freeze::Frozen, Level::Programme),
    spec(ParamId::P78, Freeze::Live, Level::Tenant),
];

// ---------------------------------------------------------------------------
// Proposal states
// ---------------------------------------------------------------------------

/// The proposal states of `SPEC/02-domain/state-machine.md`, as fieldless tags.
/// Lane L-LIFE's proposal state carries the extra data of DEFERRED.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateTag {
    /// DRAFT.
    Draft,
    /// SUBMITTED.
    Submitted,
    /// INELIGIBLE. Terminal.
    Ineligible,
    /// STAGE1.
    Stage1,
    /// NOT_SELECTED. Terminal.
    NotSelected,
    /// STAGE2.
    Stage2,
    /// RANKED.
    Ranked,
    /// IRC_REVIEW.
    IrcReview,
    /// DEFERRED.
    Deferred,
    /// DECLINED. Terminal.
    Declined,
    /// NEGOTIATION.
    Negotiation,
    /// WITHDRAWN. Terminal.
    Withdrawn,
    /// GRANTED.
    Granted,
    /// IN_EXECUTION.
    InExecution,
    /// COMPLETED. Terminal.
    Completed,
    /// TERMINATED. Terminal.
    Terminated,
}

impl StateTag {
    /// Every state, in the order of the states table.
    pub const ALL: [StateTag; 16] = [
        StateTag::Draft,
        StateTag::Submitted,
        StateTag::Ineligible,
        StateTag::Stage1,
        StateTag::NotSelected,
        StateTag::Stage2,
        StateTag::Ranked,
        StateTag::IrcReview,
        StateTag::Deferred,
        StateTag::Declined,
        StateTag::Negotiation,
        StateTag::Withdrawn,
        StateTag::Granted,
        StateTag::InExecution,
        StateTag::Completed,
        StateTag::Terminated,
    ];

    /// The terminal states: the states table marks them "Terminal".
    pub const TERMINAL: [StateTag; 6] = [
        StateTag::Ineligible,
        StateTag::NotSelected,
        StateTag::Declined,
        StateTag::Withdrawn,
        StateTag::Completed,
        StateTag::Terminated,
    ];

    /// The states withdrawal is open from (NOTE 10): the non-terminal states before GRANTED.
    pub const WITHDRAWABLE: [StateTag; 8] = [
        StateTag::Draft,
        StateTag::Submitted,
        StateTag::Stage1,
        StateTag::Stage2,
        StateTag::Ranked,
        StateTag::IrcReview,
        StateTag::Deferred,
        StateTag::Negotiation,
    ];

    /// The state's name as the spec spells it, such as `"IRC_REVIEW"`.
    pub const fn spec_name(self) -> &'static str {
        match self {
            StateTag::Draft => "DRAFT",
            StateTag::Submitted => "SUBMITTED",
            StateTag::Ineligible => "INELIGIBLE",
            StateTag::Stage1 => "STAGE1",
            StateTag::NotSelected => "NOT_SELECTED",
            StateTag::Stage2 => "STAGE2",
            StateTag::Ranked => "RANKED",
            StateTag::IrcReview => "IRC_REVIEW",
            StateTag::Deferred => "DEFERRED",
            StateTag::Declined => "DECLINED",
            StateTag::Negotiation => "NEGOTIATION",
            StateTag::Withdrawn => "WITHDRAWN",
            StateTag::Granted => "GRANTED",
            StateTag::InExecution => "IN_EXECUTION",
            StateTag::Completed => "COMPLETED",
            StateTag::Terminated => "TERMINATED",
        }
    }

    /// Whether the state is terminal. Terminal states have no exits.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            StateTag::Ineligible
                | StateTag::NotSelected
                | StateTag::Declined
                | StateTag::Withdrawn
                | StateTag::Completed
                | StateTag::Terminated
        )
    }

    /// Whether withdrawal is open from the state (NOTE 10).
    pub const fn is_withdrawable(self) -> bool {
        matches!(
            self,
            StateTag::Draft
                | StateTag::Submitted
                | StateTag::Stage1
                | StateTag::Stage2
                | StateTag::Ranked
                | StateTag::IrcReview
                | StateTag::Deferred
                | StateTag::Negotiation
        )
    }
}

// ---------------------------------------------------------------------------
// Transition rows
// ---------------------------------------------------------------------------

/// A row of the transitions table, named by its endpoints. It introduces no spec identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Row {
    /// DRAFT to SUBMITTED.
    DraftToSubmitted,
    /// SUBMITTED to INELIGIBLE.
    SubmittedToIneligible,
    /// SUBMITTED to STAGE1.
    SubmittedToStage1,
    /// STAGE1 to NOT_SELECTED.
    Stage1ToNotSelected,
    /// STAGE1 to STAGE2.
    Stage1ToStage2,
    /// STAGE2 to RANKED.
    Stage2ToRanked,
    /// STAGE2 to DEFERRED.
    Stage2ToDeferred,
    /// RANKED to NOT_SELECTED.
    RankedToNotSelected,
    /// RANKED to IRC_REVIEW.
    RankedToIrcReview,
    /// IRC_REVIEW to NEGOTIATION.
    IrcReviewToNegotiation,
    /// IRC_REVIEW to DEFERRED.
    IrcReviewToDeferred,
    /// IRC_REVIEW to DECLINED.
    IrcReviewToDeclined,
    /// DEFERRED to STAGE2, half of the spec row "DEFERRED to STAGE2 or IRC_REVIEW".
    DeferredToStage2,
    /// DEFERRED to IRC_REVIEW, half of the spec row "DEFERRED to STAGE2 or IRC_REVIEW".
    DeferredToIrcReview,
    /// NEGOTIATION to GRANTED.
    NegotiationToGranted,
    /// NEGOTIATION to DECLINED.
    NegotiationToDeclined,
    /// Any non-terminal state before GRANTED to WITHDRAWN.
    Withdraw,
    /// GRANTED to IN_EXECUTION.
    GrantedToInExecution,
    /// GRANTED to TERMINATED.
    GrantedToTerminated,
    /// IN_EXECUTION to COMPLETED.
    InExecutionToCompleted,
    /// IN_EXECUTION to TERMINATED.
    InExecutionToTerminated,
}

/// Who may issue a command or take a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActorRule {
    /// The proposal's lead: an account with an active Applicant binding on it.
    Lead,
    /// Any account. Used only where the command creates the actor's first binding.
    AnyAccount,
    /// An account with an active binding of this role in the programme.
    Holder(Role),
    /// A tenant admin at tenant scope, as the shell attests in `Ctx::tenant_admin`
    /// from the M3 and M4 tenant configuration. It needs no programme binding,
    /// so a programme and its first roles can be created from genesis. SoD-07
    /// still applies to self-grants, with the approving admin attested in
    /// `Ctx::second_tenant_admin`.
    TenantAdmin,
    /// The holder of an active reviewer assignment on the proposal.
    AssignedReviewer,
    /// The assigned reviewers of the proposal, collectively.
    AssignedReviewers,
    /// The holder of any active assignment on the proposal, reviewer or IRC.
    Assignee,
    /// The holder of an active IRC assignment on the proposal.
    IrcMember,
    /// The proposal's IRC members collectively, at least P-15 of them.
    IrcMembers,
    /// The committee, recorded by a committee member with the ballots.
    Committee,
    /// A reader allowed by P-10 (R-AC-01).
    ContentReader,
    /// The platform.
    System,
    /// A computed outcome, recorded by a named holder of this role (R-LA-03).
    SystemRecordedBy(Role),
    /// The applicant lead and the programme manager together.
    LeadAndProgrammeManager,
    /// Any one of these rules.
    AnyOf(&'static [ActorRule]),
}

impl ActorRule {
    /// The actor as the transitions table spells it, after removing
    /// parenthesised NOTE references. `None` for rules no transition row uses.
    pub const fn transition_label(self) -> Option<&'static str> {
        let label = match self {
            ActorRule::Lead => "Applicant",
            ActorRule::Holder(Role::FstpCoordinator) => "FSTP coordinator",
            ActorRule::Holder(Role::ProgrammeManager) => "Programme manager",
            ActorRule::AssignedReviewers => "Assigned reviewers",
            ActorRule::IrcMember => "IRC member",
            ActorRule::IrcMembers => "IRC members (P-15)",
            ActorRule::Committee => "Committee",
            ActorRule::System => "System",
            ActorRule::SystemRecordedBy(Role::FstpCoordinator) => {
                "System, recorded by the FSTP coordinator"
            }
            ActorRule::LeadAndProgrammeManager => "Applicant and programme manager",
            _ => return None,
        };
        Some(label)
    }
}

/// A guard of a transition row. Each names the rule it enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Guard {
    /// The call is open (Call states).
    CallOpen,
    /// Required fields are present.
    RequiredFieldsPresent,
    /// No guardian record is needed to submit (R-SB-02).
    NoGuardianRecordNeeded,
    /// The ethics self-declaration is present (R-SB-05).
    EthicsDeclared,
    /// The data protection notice version is recorded (R-NG-06).
    NoticeRecorded,
    /// A knock-out criterion failed (R-EV-01).
    KnockOutFailed,
    /// All knock-out criteria passed (R-EV-01).
    AllKnockOutsPassed,
    /// A reason is recorded.
    ReasonRecorded,
    /// The acting person has no declared or detected conflict (I-03).
    ActorConflictFree,
    /// At least P-03 active, declared, conflict-free assignments (R-EV-02).
    ReviewersAssignedWithoutConflict,
    /// Assigned reviewers from at least P-39 organisations, when data exists (I-34).
    ReviewerOrganisations,
    /// No reviewer on a proposal declaring an affiliation on their proximity list (I-35).
    ProximityClear,
    /// Stage 1 closed with at least P-03 valid scores (NOTE 3, I-07).
    Stage1Closed,
    /// The weighted score is not above P-02 (I-08).
    ScoreNotAboveThreshold,
    /// The weighted score is strictly above P-02 (I-08).
    ScoreAboveThreshold,
    /// Revised plan scored by at least P-03 reviewers, window closed with
    /// answers, or "no questions" recorded (NOTE 4, R-EV-05).
    Stage2Concluded,
    /// The effective score follows P-24 and names one plan (I-09).
    EffectiveScoreFollowsP24,
    /// P-07 elapsed without answers and without "no questions" (NOTE 4, R-EV-07).
    Stage2WindowElapsed,
    /// Ranked below the cut-off (NOTE 6).
    BelowCutOff,
    /// Ranked within the cut-off (NOTE 6).
    WithinCutOff,
    /// Decided under P-16 (R-EV-09).
    DecidedUnderP16,
    /// Remaining budget visible and rationale recorded (R-EV-08).
    BudgetVisibleAndRationale,
    /// Conflicted committee members recused (I-03).
    ConflictedMembersRecused,
    /// A tie in the order is broken under P-17 and the tie-break is recorded (NOTE 6).
    TieBreakRecorded,
    /// All reviewing IRC members validate, at least P-15 (R-IR-01).
    AllIrcValidate,
    /// Verified guardian consent if minor (I-18).
    GuardianConsentIfMinor,
    /// The same consent check on entry to NEGOTIATION (R-NG-02, NOTE 9).
    GuardianConsentOnEntry,
    /// An IRC concern is raised and sent to the applicant (R-IR-02).
    ConcernRaised,
    /// A later call of the programme is published (NOTE 7).
    FutureCallExists,
    /// No later call of the programme is published (NOTE 7).
    NoFutureCall,
    /// The next call opens (NOTE 8).
    NextCallOpens,
    /// The proposal re-enters at the stage it left (NOTE 8).
    ReentersStageLeft,
    /// No former reviewer holds a Receiving role in a call evaluating the proposal (I-36).
    FormerReviewerBar,
    /// The applicant's identity is verified and SoD-09 passes.
    IdentityVerifiedSod09,
    /// The amount lies within P-04 after deductions (I-13).
    AmountWithinRange,
    /// P-05 is checked cumulatively (I-14).
    CumulativeCap,
    /// Granting keeps I-04.
    KeepsI04,
    /// Granting keeps I-06.
    KeepsI06,
    /// Prior deliverables are recorded as public under P-26 (I-15).
    RepeatRecordsComplete,
    /// The contract is EFFECTIVE.
    ContractEffective,
    /// The negotiation cannot reach GRANTED for this reason, which the row lists (NOTE 9).
    /// The `CannotGrant` guards of one row are alternatives: at least one holds.
    CannotGrant(NegotiationFailure),
    /// The earliest milestone start date is reached (NOTE 11).
    FirstMilestoneStartReached,
    /// Every milestone closed and every payment request terminal (NOTE 12).
    MilestonesClosedAndRequestsTerminal,
}

impl Guard {
    /// The rule this guard enforces. `RuleRef::Row` for guards the row alone states.
    pub const fn rule(self) -> RuleRef {
        match self {
            Guard::NoGuardianRecordNeeded => RuleRef::Rsb02,
            Guard::EthicsDeclared => RuleRef::Rsb05,
            Guard::NoticeRecorded => RuleRef::Rng06,
            Guard::KnockOutFailed | Guard::AllKnockOutsPassed => RuleRef::Rev01,
            Guard::ActorConflictFree | Guard::ConflictedMembersRecused => RuleRef::I03,
            Guard::ReviewersAssignedWithoutConflict => RuleRef::Rev02,
            Guard::ReviewerOrganisations => RuleRef::I34,
            Guard::ProximityClear => RuleRef::I35,
            Guard::Stage1Closed => RuleRef::I07,
            Guard::ScoreNotAboveThreshold | Guard::ScoreAboveThreshold => RuleRef::I08,
            Guard::Stage2Concluded => RuleRef::Rev05,
            Guard::EffectiveScoreFollowsP24 => RuleRef::I09,
            Guard::Stage2WindowElapsed => RuleRef::Rev07,
            Guard::DecidedUnderP16 => RuleRef::Rev09,
            Guard::BudgetVisibleAndRationale => RuleRef::Rev08,
            Guard::AllIrcValidate => RuleRef::Rir01,
            Guard::GuardianConsentIfMinor => RuleRef::I18,
            Guard::GuardianConsentOnEntry => RuleRef::Rng02,
            Guard::TieBreakRecorded => RuleRef::Param(ParamId::P17),
            Guard::CannotGrant(failure) => match failure {
                NegotiationFailure::IdentityNotVerified | NegotiationFailure::Sod09Refused => {
                    RuleRef::Sod09
                }
                NegotiationFailure::ReceivingVoidedUnderI04 => RuleRef::I04,
                NegotiationFailure::ReceivingVoidedUnderI06 => RuleRef::I06,
                NegotiationFailure::NoAmountWithinRange => RuleRef::I13,
                NegotiationFailure::NoAmountWithinCap => RuleRef::I14,
                NegotiationFailure::RepeatRecordIncomplete => RuleRef::I15,
                NegotiationFailure::GuardianConsentMissing => RuleRef::I18,
            },
            Guard::ConcernRaised => RuleRef::Rir02,
            Guard::FormerReviewerBar => RuleRef::I36,
            Guard::IdentityVerifiedSod09 => RuleRef::Sod09,
            Guard::AmountWithinRange => RuleRef::I13,
            Guard::CumulativeCap => RuleRef::I14,
            Guard::KeepsI04 => RuleRef::I04,
            Guard::KeepsI06 => RuleRef::I06,
            Guard::RepeatRecordsComplete => RuleRef::I15,
            Guard::CallOpen
            | Guard::RequiredFieldsPresent
            | Guard::ReasonRecorded
            | Guard::BelowCutOff
            | Guard::WithinCutOff
            | Guard::FutureCallExists
            | Guard::NoFutureCall
            | Guard::NextCallOpens
            | Guard::ReentersStageLeft
            | Guard::ContractEffective
            | Guard::FirstMilestoneStartReached
            | Guard::MilestonesClosedAndRequestsTerminal => RuleRef::Row,
        }
    }
}

/// One transition rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransitionRule {
    /// The row.
    pub row: Row,
    /// The states it leaves from. Only withdrawal has more than one.
    pub from: &'static [StateTag],
    /// The state it reaches.
    pub to: StateTag,
    /// Who takes the transition, as the row states it.
    pub actor: ActorRule,
    /// The commands whose `decide` may compute this transition.
    pub commands: &'static [CommandKind],
    /// The row's guards, plus those that higher-ranked sources add (design section 3.2).
    /// Every guard must hold, except the `CannotGrant` guards of NEGOTIATION to
    /// DECLINED. Those are alternatives, and at least one of them must hold.
    pub guards: &'static [Guard],
}

const fn rule(
    row: Row,
    from: &'static [StateTag],
    to: StateTag,
    actor: ActorRule,
    commands: &'static [CommandKind],
    guards: &'static [Guard],
) -> TransitionRule {
    TransitionRule {
        row,
        from,
        to,
        actor,
        commands,
        guards,
    }
}

use CommandKind as K;
use Guard as G;
use StateTag as S;

const CUT_OFF_GUARDS_BELOW: &[Guard] = &[
    G::BelowCutOff,
    G::DecidedUnderP16,
    G::BudgetVisibleAndRationale,
    G::ConflictedMembersRecused,
    G::TieBreakRecorded,
];
const CUT_OFF_GUARDS_WITHIN: &[Guard] = &[
    G::WithinCutOff,
    G::DecidedUnderP16,
    G::BudgetVisibleAndRationale,
    G::ConflictedMembersRecused,
    G::TieBreakRecorded,
];
const REENTRY_GUARDS: &[Guard] = &[G::NextCallOpens, G::ReentersStageLeft, G::FormerReviewerBar];
const NEGOTIATION_FAILURE_GUARDS: &[Guard] = &[
    G::CannotGrant(NegotiationFailure::IdentityNotVerified),
    G::CannotGrant(NegotiationFailure::Sod09Refused),
    G::CannotGrant(NegotiationFailure::ReceivingVoidedUnderI04),
    G::CannotGrant(NegotiationFailure::ReceivingVoidedUnderI06),
    G::CannotGrant(NegotiationFailure::NoAmountWithinRange),
    G::CannotGrant(NegotiationFailure::NoAmountWithinCap),
    G::CannotGrant(NegotiationFailure::RepeatRecordIncomplete),
    G::CannotGrant(NegotiationFailure::GuardianConsentMissing),
    G::ReasonRecorded,
];

/// Every row of the transitions table of `SPEC/02-domain/state-machine.md`,
/// in table order, with the DEFERRED row split by target.
pub const TRANSITIONS: &[TransitionRule] = &[
    rule(
        Row::DraftToSubmitted,
        &[S::Draft],
        S::Submitted,
        ActorRule::Lead,
        &[K::Submit],
        &[
            G::CallOpen,
            G::RequiredFieldsPresent,
            G::NoGuardianRecordNeeded,
            G::EthicsDeclared,
            G::NoticeRecorded,
        ],
    ),
    rule(
        Row::SubmittedToIneligible,
        &[S::Submitted],
        S::Ineligible,
        ActorRule::Holder(Role::FstpCoordinator),
        &[K::RecordKnockOut],
        &[G::KnockOutFailed, G::ReasonRecorded, G::ActorConflictFree],
    ),
    rule(
        Row::SubmittedToStage1,
        &[S::Submitted],
        S::Stage1,
        ActorRule::Holder(Role::FstpCoordinator),
        &[K::AdmitToStage1],
        &[
            G::AllKnockOutsPassed,
            G::ReviewersAssignedWithoutConflict,
            G::ReviewerOrganisations,
            G::ProximityClear,
            G::ActorConflictFree,
        ],
    ),
    rule(
        Row::Stage1ToNotSelected,
        &[S::Stage1],
        S::NotSelected,
        ActorRule::SystemRecordedBy(Role::FstpCoordinator),
        &[K::CloseStage1],
        &[G::Stage1Closed, G::ScoreNotAboveThreshold],
    ),
    rule(
        Row::Stage1ToStage2,
        &[S::Stage1],
        S::Stage2,
        ActorRule::SystemRecordedBy(Role::FstpCoordinator),
        &[K::CloseStage1],
        &[G::Stage1Closed, G::ScoreAboveThreshold],
    ),
    rule(
        Row::Stage2ToRanked,
        &[S::Stage2],
        S::Ranked,
        ActorRule::AssignedReviewers,
        &[K::RankAfterStage2, K::RecordNoQuestions],
        &[G::Stage2Concluded, G::EffectiveScoreFollowsP24],
    ),
    rule(
        Row::Stage2ToDeferred,
        &[S::Stage2],
        S::Deferred,
        ActorRule::System,
        &[K::ExpireStage2],
        &[G::Stage2WindowElapsed],
    ),
    rule(
        Row::RankedToNotSelected,
        &[S::Ranked],
        S::NotSelected,
        ActorRule::Committee,
        &[K::RecordCutOff],
        CUT_OFF_GUARDS_BELOW,
    ),
    rule(
        Row::RankedToIrcReview,
        &[S::Ranked],
        S::IrcReview,
        ActorRule::Committee,
        &[K::RecordCutOff],
        CUT_OFF_GUARDS_WITHIN,
    ),
    rule(
        Row::IrcReviewToNegotiation,
        &[S::IrcReview],
        S::Negotiation,
        ActorRule::IrcMembers,
        &[K::RecordIrcReview],
        &[
            G::AllIrcValidate,
            G::GuardianConsentIfMinor,
            G::GuardianConsentOnEntry,
            G::ActorConflictFree,
        ],
    ),
    rule(
        Row::IrcReviewToDeferred,
        &[S::IrcReview],
        S::Deferred,
        ActorRule::IrcMember,
        &[K::RecordIrcReview],
        &[G::ConcernRaised, G::FutureCallExists, G::ActorConflictFree],
    ),
    rule(
        Row::IrcReviewToDeclined,
        &[S::IrcReview],
        S::Declined,
        ActorRule::System,
        &[K::DeclineAfterConcern],
        &[G::ConcernRaised, G::NoFutureCall],
    ),
    rule(
        Row::DeferredToStage2,
        &[S::Deferred],
        S::Stage2,
        ActorRule::System,
        &[K::ReEnter],
        REENTRY_GUARDS,
    ),
    rule(
        Row::DeferredToIrcReview,
        &[S::Deferred],
        S::IrcReview,
        ActorRule::System,
        &[K::ReEnter],
        REENTRY_GUARDS,
    ),
    rule(
        Row::NegotiationToGranted,
        &[S::Negotiation],
        S::Granted,
        ActorRule::LeadAndProgrammeManager,
        &[K::AcceptGrant, K::ApproveGrant, K::ContractFact],
        &[
            G::IdentityVerifiedSod09,
            G::GuardianConsentIfMinor,
            G::AmountWithinRange,
            G::CumulativeCap,
            G::KeepsI04,
            G::KeepsI06,
            G::RepeatRecordsComplete,
            G::ContractEffective,
        ],
    ),
    rule(
        Row::NegotiationToDeclined,
        &[S::Negotiation],
        S::Declined,
        ActorRule::System,
        &[K::DeclineNegotiation],
        NEGOTIATION_FAILURE_GUARDS,
    ),
    rule(
        Row::Withdraw,
        &StateTag::WITHDRAWABLE,
        S::Withdrawn,
        ActorRule::Lead,
        &[K::Withdraw],
        &[],
    ),
    rule(
        Row::GrantedToInExecution,
        &[S::Granted],
        S::InExecution,
        ActorRule::System,
        &[K::StartExecution],
        &[G::FirstMilestoneStartReached],
    ),
    rule(
        Row::GrantedToTerminated,
        &[S::Granted],
        S::Terminated,
        ActorRule::Holder(Role::ProgrammeManager),
        &[K::Terminate],
        &[G::ReasonRecorded],
    ),
    rule(
        Row::InExecutionToCompleted,
        &[S::InExecution],
        S::Completed,
        ActorRule::System,
        &[K::Complete],
        &[G::MilestonesClosedAndRequestsTerminal],
    ),
    rule(
        Row::InExecutionToTerminated,
        &[S::InExecution],
        S::Terminated,
        ActorRule::Holder(Role::ProgrammeManager),
        &[K::Terminate],
        &[G::ReasonRecorded],
    ),
];

// ---------------------------------------------------------------------------
// Actor rules per command
// ---------------------------------------------------------------------------

const PM: ActorRule = ActorRule::Holder(Role::ProgrammeManager);
const COORDINATOR: ActorRule = ActorRule::Holder(Role::FstpCoordinator);

/// The actor rule of every command kind, in [`CommandKind::ALL`] order.
/// The single source for the M4 authorisation matrix and MCP parity (I-84).
///
/// Rules that the spec does not state are the design's interim readings.
/// A tenant admin at tenant scope creates programmes and grants, ends and
/// reinstates roles (O-47). The FSTP coordinator assigns reviewers, and the
/// programme manager routes amendments. PAID is confirmed by the System or
/// by finance (`SPEC/02-domain/payment-requests.md` States).
pub const ACTOR_RULES: &[(CommandKind, ActorRule)] = &[
    (K::CreateProgramme, ActorRule::TenantAdmin),
    (K::EditPolicy, PM),
    (
        K::DraftCall,
        ActorRule::AnyOf(&[ActorRule::Holder(Role::CallDrafter), PM]),
    ),
    (
        K::EditCall,
        ActorRule::AnyOf(&[ActorRule::Holder(Role::CallDrafter), PM]),
    ),
    (K::ApproveCallPublication, PM),
    (K::PublishCall, PM),
    (K::GrantRole, ActorRule::TenantAdmin),
    (K::EndRole, ActorRule::TenantAdmin),
    (K::ReinstateBinding, ActorRule::TenantAdmin),
    (K::VaultChanged, ActorRule::System),
    (K::CreateDraft, ActorRule::AnyAccount),
    (K::AddTeamMember, ActorRule::Lead),
    (K::AddGuardian, ActorRule::Lead),
    (K::RecordPlanVersion, ActorRule::Lead),
    (K::Submit, ActorRule::Lead),
    (
        K::DeclareConflict,
        ActorRule::AnyOf(&[
            ActorRule::Assignee,
            COORDINATOR,
            ActorRule::Holder(Role::CommitteeMember),
        ]),
    ),
    (K::Assign, COORDINATOR),
    (K::Unassign, COORDINATOR),
    (K::ReadContent, ActorRule::ContentReader),
    (K::RecordKnockOut, COORDINATOR),
    (K::AdmitToStage1, COORDINATOR),
    (K::RecordScore, ActorRule::AssignedReviewer),
    (K::CorrectScore, ActorRule::AssignedReviewer),
    (K::RecordRankingSummary, ActorRule::AssignedReviewer),
    (
        K::CloseStage1,
        ActorRule::SystemRecordedBy(Role::FstpCoordinator),
    ),
    (K::AskQuestion, ActorRule::AssignedReviewer),
    (K::RecordNoQuestions, ActorRule::AssignedReviewer),
    (K::AnswerQuestions, ActorRule::Lead),
    (K::SubmitRevision, ActorRule::Lead),
    (K::RankAfterStage2, ActorRule::AssignedReviewer),
    (K::ExpireStage2, ActorRule::System),
    (K::RecordCutOff, ActorRule::Committee),
    (K::RecordIrcReview, ActorRule::IrcMember),
    (K::DeclineAfterConcern, ActorRule::System),
    (K::ReEnter, ActorRule::System),
    (K::DetermineAmount, ActorRule::AssignedReviewer),
    (K::AcceptGrant, ActorRule::Lead),
    (K::ApproveGrant, PM),
    (K::ContractFact, ActorRule::System),
    (K::DeclineNegotiation, ActorRule::System),
    (K::Withdraw, ActorRule::Lead),
    (K::StartExecution, ActorRule::System),
    (K::Complete, ActorRule::System),
    (K::Terminate, PM),
    (K::RequestPayment, ActorRule::Lead),
    (K::AcceptLine, ActorRule::AssignedReviewer),
    (K::ApprovePayment, ActorRule::Holder(Role::FinanceApprover)),
    (K::ReleasePayment, ActorRule::Holder(Role::PaymentReleaser)),
    (
        K::ConfirmPaid,
        ActorRule::AnyOf(&[ActorRule::System, ActorRule::Holder(Role::FinanceApprover)]),
    ),
    (K::WithdrawPaymentRequest, ActorRule::Lead),
    (K::RequestPaymentChanges, ActorRule::AssignedReviewer),
    (K::RecordDeliverable, ActorRule::System),
    (
        K::ProposeAmendment,
        ActorRule::AnyOf(&[ActorRule::Lead, ActorRule::AssignedReviewer]),
    ),
    (K::RouteAmendment, PM),
    (K::ActivateAmendment, ActorRule::System),
];

/// The actor rule of `kind`, from [`ACTOR_RULES`].
pub fn actor_rule(kind: CommandKind) -> Option<ActorRule> {
    ACTOR_RULES
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, rule)| *rule)
}
