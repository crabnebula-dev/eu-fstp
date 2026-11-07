//! The independent authorisation reference (M4 design section 8.3). Lane
//! W3a owns this file.
//!
//! It judges one matrix cell: an operation, a principal, a state, a policy
//! row and a session. The answer is `Allow`, `Pending` or `Deny` with an
//! authorisation class. It judges authorisation only. A refusal by a
//! transition guard or a state rule is not an authorisation refusal, so
//! `Allow` means that no authorisation rule refuses.
//!
//! It is written from the spec text, never from production code:
//!
//! - the roles table and the rules of `SPEC/02-domain/roles-and-sod.md`;
//! - the actor column of `SPEC/02-domain/state-machine.md`;
//! - P-10 NOTE 1, P-74, P-75 and P-77 in `SPEC/02-domain/policy-parameters.md`;
//! - the capability table and rules of `SPEC/03-architecture/mcp-server.md`;
//! - the strong methods and the high-risk table of
//!   `SPEC/03-architecture/authentication.md`;
//! - I-03, I-17, I-21, I-65, I-67, I-77, I-78, I-84 and I-85;
//! - the decided readings that design section 15.0 builds as interim
//!   readings: Q1, Q9, Q10, Q16, Q32, Q39 and Q42.
//!
//! It shares only id and record types with production: `Role` and
//! `StateTag`. It reads neither `ACTOR_RULES` nor `READ_RULES`, and it
//! names no `fstp-access` item. Operations are keyed by the names the
//! journey tables of design section 2.2 use.
//!
//! Each place where the spec leaves a choice open carries a "Reading:"
//! note below. The matrix compares the system with this reference in both
//! directions, so each reading the production registry departs from shows
//! up as a mismatch for the lead to settle.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::roles::Role;

use crate::NotImplemented;

/// Why the reference expects a refusal (design section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthClass {
    /// The actor rule, separation of duties or a builder rule refuses.
    Actor,
    /// The read is not open to the caller in this state or under P-10 or
    /// P-75.
    Visibility,
    /// A declared or detected conflict, or a missing declaration (I-03,
    /// R-CF-02).
    Conflict,
    /// The MCP token lacks the operation's scope.
    Scope,
    /// The tenant disabled MCP, or limits it to roles the call acts under.
    P74,
    /// The session is not phishing-resistant (I-77, I-78).
    LoginStrength,
    /// A high-risk action without a fresh step-up (I-78).
    StepUp,
    /// The operation has no MCP tool.
    NotExposed,
    /// The programme is still a draft (change D3).
    Draft,
}

/// The reference outcome of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expected {
    /// No authorisation rule refuses.
    Allow,
    /// The call becomes a pending action for a web confirmation (I-85).
    Pending,
    /// An authorisation rule refuses.
    Deny(AuthClass),
}

/// A principal of the matrix, by its relation to the cell's target.
///
/// The target is the programme P, its call C, the proposal X of C, an
/// assignment on X, an IRC assignment on X or a cut-off round of C.
/// "Declared" means a recorded declaration of no conflict on X.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Who {
    /// No credential.
    Anonymous,
    /// An account with no binding and no admin role.
    Unbound,
    /// A tenant admin who built nothing in P. A second admin exists.
    TenantAdmin,
    /// A tenant admin who opened the draft P, so a builder (Q1).
    TenantAdminBuilder,
    /// The only tenant admin: no second admin exists yet. Reading: nothing
    /// in the spec makes a draft wait for onboarding to finish, so this
    /// admin may have opened the draft P and is then its builder (Q1).
    SoleTenantAdmin,
    /// A programme manager of P who is no drafter of C.
    ProgrammeManager,
    /// A programme manager of P who is a drafter of C (R-PC-03 NOTE).
    ProgrammeManagerDrafter,
    /// An account whose programme manager binding on P has ended.
    EndedProgrammeManager,
    /// A programme manager of another programme of the tenant.
    OtherProgrammeManager,
    /// A call drafter of P, an author of C.
    CallDrafter,
    /// The FSTP coordinator of P, declared on X where X can be declared on.
    Coordinator,
    /// The FSTP coordinator of P, not yet declared on X.
    CoordinatorUndeclared,
    /// The FSTP coordinator of P, with a conflict on X.
    CoordinatorConflicted,
    /// A committee member of P, not assigned to X, declared on X.
    CommitteeMember,
    /// The committee chair of P.
    CommitteeChair,
    /// The assigned reviewer of the target assignment, declared.
    AssignedReviewer,
    /// The assigned reviewer of the target assignment, not yet declared.
    AssignedReviewerUndeclared,
    /// The assigned reviewer of the target assignment, with a conflict on X.
    AssignedReviewerConflicted,
    /// A committee member whose assignment on X was released.
    ReleasedReviewer,
    /// An assigned reviewer whose committee binding the vault's identity
    /// discovery suspended as a conflict of interest (`roles-and-sod.md`
    /// Identity discovery): the account shares the identity of the call
    /// drafter. It scored stage 1 wherever stage 1 closed, so from the
    /// close on its scores carry a notifiable conflict (R-CF-04).
    SuspendedReviewer,
    /// A committee member recused from C's cut-off vote by a conflict on
    /// another ranked proposal of C. Once the cut-off is recorded no
    /// proposal of C is RANKED, so it is recused no longer.
    RecusedCommitteeMember,
    /// A committee member who delegated their vote in the round.
    DelegatingCommitteeMember,
    /// An IRC member of P with no IRC assignment on X.
    IrcMember,
    /// The IRC assignee of the target IRC assignment, declared.
    IrcAssignee,
    /// The IRC assignee, not yet declared.
    IrcAssigneeUndeclared,
    /// The IRC assignee, with a conflict on X.
    IrcAssigneeConflicted,
    /// The applicant lead of X.
    Lead,
    /// An applicant team member of X.
    TeamMember,
    /// The guardian on X.
    Guardian,
    /// A lead of X whose Receiving binding was voided (I-04, I-06).
    VoidedLead,
    /// A finance approver of P.
    FinanceApprover,
    /// A payment releaser of P.
    PaymentReleaser,
    /// A contract signatory of P.
    ContractSignatory,
    /// An auditor of P.
    Auditor,
}

impl Who {
    /// Every principal of the matrix.
    pub const ALL: [Who; 34] = [
        Who::Anonymous,
        Who::Unbound,
        Who::TenantAdmin,
        Who::TenantAdminBuilder,
        Who::SoleTenantAdmin,
        Who::ProgrammeManager,
        Who::ProgrammeManagerDrafter,
        Who::EndedProgrammeManager,
        Who::OtherProgrammeManager,
        Who::CallDrafter,
        Who::Coordinator,
        Who::CoordinatorUndeclared,
        Who::CoordinatorConflicted,
        Who::CommitteeMember,
        Who::CommitteeChair,
        Who::AssignedReviewer,
        Who::AssignedReviewerUndeclared,
        Who::AssignedReviewerConflicted,
        Who::ReleasedReviewer,
        Who::SuspendedReviewer,
        Who::RecusedCommitteeMember,
        Who::DelegatingCommitteeMember,
        Who::IrcMember,
        Who::IrcAssignee,
        Who::IrcAssigneeUndeclared,
        Who::IrcAssigneeConflicted,
        Who::Lead,
        Who::TeamMember,
        Who::Guardian,
        Who::VoidedLead,
        Who::FinanceApprover,
        Who::PaymentReleaser,
        Who::ContractSignatory,
        Who::Auditor,
    ];

    /// Whether the principal has an account.
    pub const fn account(self) -> bool {
        !matches!(self, Who::Anonymous)
    }

    /// The roles the account holds now, active bindings only, in any
    /// programme of the tenant (design section 3.6, `RoleSet`). `None`
    /// stands for an account acting with no binding yet.
    pub const fn roles(self) -> &'static [Option<Role>] {
        match self {
            Who::Anonymous => &[],
            Who::Unbound
            | Who::EndedProgrammeManager
            | Who::SuspendedReviewer
            | Who::VoidedLead => &[None],
            Who::TenantAdmin | Who::TenantAdminBuilder | Who::SoleTenantAdmin => {
                &[Some(Role::TenantAdmin)]
            }
            Who::ProgrammeManager | Who::ProgrammeManagerDrafter | Who::OtherProgrammeManager => {
                &[Some(Role::ProgrammeManager)]
            }
            Who::CallDrafter => &[Some(Role::CallDrafter)],
            Who::Coordinator | Who::CoordinatorUndeclared | Who::CoordinatorConflicted => {
                &[Some(Role::FstpCoordinator)]
            }
            Who::CommitteeMember
            | Who::AssignedReviewer
            | Who::AssignedReviewerUndeclared
            | Who::AssignedReviewerConflicted
            | Who::ReleasedReviewer
            | Who::RecusedCommitteeMember
            | Who::DelegatingCommitteeMember => &[Some(Role::CommitteeMember)],
            Who::CommitteeChair => &[Some(Role::CommitteeChair)],
            Who::IrcMember
            | Who::IrcAssignee
            | Who::IrcAssigneeUndeclared
            | Who::IrcAssigneeConflicted => &[Some(Role::IrcMember)],
            Who::Lead => &[Some(Role::Applicant)],
            Who::TeamMember => &[Some(Role::ApplicantTeamMember)],
            Who::Guardian => &[Some(Role::Guardian)],
            Who::FinanceApprover => &[Some(Role::FinanceApprover)],
            Who::PaymentReleaser => &[Some(Role::PaymentReleaser)],
            Who::ContractSignatory => &[Some(Role::ContractSignatory)],
            Who::Auditor => &[Some(Role::Auditor)],
        }
    }

    /// Whether I-77 covers the account: it holds a Drafting, Judging or
    /// Operations role or is a tenant admin. The suspended reviewer holds
    /// none: its conflict-of-interest suspension "never counts as held"
    /// (`roles-and-sod.md` Identity discovery), and a suspended binding
    /// "is inactive for every action" (Enforcement points NOTE).
    pub const fn management(self) -> bool {
        !matches!(
            self,
            Who::Anonymous
                | Who::Unbound
                | Who::EndedProgrammeManager
                | Who::SuspendedReviewer
                | Who::Lead
                | Who::TeamMember
                | Who::Guardian
                | Who::VoidedLead
        )
    }

    const fn tenant_admin(self) -> bool {
        matches!(
            self,
            Who::TenantAdmin | Who::TenantAdminBuilder | Who::SoleTenantAdmin
        )
    }

    const fn manager(self) -> bool {
        matches!(self, Who::ProgrammeManager | Who::ProgrammeManagerDrafter)
    }

    const fn coordinator(self) -> bool {
        matches!(
            self,
            Who::Coordinator | Who::CoordinatorUndeclared | Who::CoordinatorConflicted
        )
    }

    const fn team(self) -> bool {
        matches!(self, Who::Lead | Who::TeamMember | Who::Guardian)
    }

    /// A committee member or chair of P with an active binding.
    const fn committee(self) -> bool {
        matches!(
            self,
            Who::CommitteeMember
                | Who::CommitteeChair
                | Who::AssignedReviewer
                | Who::AssignedReviewerUndeclared
                | Who::AssignedReviewerConflicted
                | Who::ReleasedReviewer
                | Who::RecusedCommitteeMember
                | Who::DelegatingCommitteeMember
        )
    }

    /// A declared or detected conflict on X (I-03).
    const fn conflicted(self) -> bool {
        matches!(
            self,
            Who::CoordinatorConflicted
                | Who::AssignedReviewerConflicted
                | Who::IrcAssigneeConflicted
        )
    }

    /// A declared or detected conflict on X in state `x` (I-03). Besides
    /// the declared ones, the suspended reviewer's scores get a notifiable
    /// conflict once it scored, from the stage 1 close on
    /// (`roles-and-sod.md` Identity discovery, R-CF-04).
    fn conflicted_in(self, x: Option<StateTag>) -> bool {
        self.conflicted()
            || (self == Who::SuspendedReviewer
                && x.is_some_and(|s| {
                    among(s, &ASSIGNED) && !matches!(s, StateTag::Submitted | StateTag::Stage1)
                }))
    }

    /// An active committee member binding in P, the chair aside: the
    /// members who declare per proposal under P-10 "all committee
    /// members". The chair holds another role.
    const fn committee_member(self) -> bool {
        self.committee() && !matches!(self, Who::CommitteeChair)
    }
}

/// A login method of a session (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Login {
    /// A passkey: phishing-resistant.
    Passkey,
    /// A magic link: not phishing-resistant.
    MagicLink,
    /// OPAQUE: not phishing-resistant.
    Opaque,
}

impl Login {
    /// Whether the method is phishing-resistant.
    pub const fn strong(self) -> bool {
        matches!(self, Login::Passkey)
    }
}

/// The step-up state of a web call (I-78).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepUp {
    /// A proof for this call's digest within P-71.
    Fresh,
    /// A proof older than P-71 by one microsecond.
    Stale,
    /// No proof.
    Absent,
}

/// The channel of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    /// The web interface.
    Web,
    /// The MCP server, with or without the operation's scope on the token.
    /// Public tools need no token, so the flag is moot for them.
    Mcp {
        /// Whether the token carries the operation's scope.
        scope: bool,
    },
}

/// The session dimension of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session {
    /// The login method, or `None` without a credential.
    pub login: Option<Login>,
    /// The step-up state. Only high-risk web cells vary it.
    pub step_up: StepUp,
    /// The channel.
    pub channel: Channel,
}

/// A tenant onboarding step (design section 3.5), in the order the steps
/// validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "each variant is named after its onboarding step"
)]
pub enum OnboardStep {
    Organisation,
    Agreements,
    Branding,
    DomainsAndEmail,
    Identity,
    Inference,
    Payments,
    Channels,
    Administrators,
}

impl OnboardStep {
    /// Every step, in order.
    pub const ALL: [OnboardStep; 9] = [
        OnboardStep::Organisation,
        OnboardStep::Agreements,
        OnboardStep::Branding,
        OnboardStep::DomainsAndEmail,
        OnboardStep::Identity,
        OnboardStep::Inference,
        OnboardStep::Payments,
        OnboardStep::Channels,
        OnboardStep::Administrators,
    ];
}

/// The state dimension of one cell (design section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateProfile {
    /// The tenant is onboarding, and this step is the first one not yet
    /// validated. No programme exists.
    Onboarding(OnboardStep),
    /// P is a draft programme with no call.
    ProgrammeDraft,
    /// P is active with no call.
    ProgrammeActive,
    /// C is drafted.
    CallDrafted,
    /// C is approved for publication.
    CallApproved,
    /// C is published and open, with no proposal.
    CallOpen,
    /// C is published and closed, with no proposal.
    CallClosed,
    /// C is published and X is in this state. X is a draft only while C is
    /// open, and C is closed in every other state.
    Proposal(StateTag),
}

impl StateProfile {
    /// Every state profile: the nine onboarding steps, six programme and
    /// call states, then the 16 proposal states.
    pub fn all() -> Vec<StateProfile> {
        let mut out: Vec<StateProfile> = OnboardStep::ALL
            .iter()
            .map(|s| StateProfile::Onboarding(*s))
            .collect();
        out.extend([
            StateProfile::ProgrammeDraft,
            StateProfile::ProgrammeActive,
            StateProfile::CallDrafted,
            StateProfile::CallApproved,
            StateProfile::CallOpen,
            StateProfile::CallClosed,
        ]);
        out.extend(StateTag::ALL.iter().map(|s| StateProfile::Proposal(*s)));
        out
    }

    const fn proposal(self) -> Option<StateTag> {
        match self {
            StateProfile::Proposal(s) => Some(s),
            _ => None,
        }
    }
}

/// P-10 (NOTE 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P10 {
    /// Assigned reviewers only.
    AssignedOnly,
    /// All committee members.
    AllCommittee,
    /// Operator staff only: the FSTP coordinator reads after declaring.
    OperatorStaffOnly,
}

/// P-74, as the matrix varies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P74 {
    /// Enabled for all roles, plus the public research tools.
    AllRoles,
    /// Disabled.
    Disabled,
    /// Limited to the Receiving roles and accounts with no binding, plus
    /// the public research tools. The matrix's one role-limited row.
    ReceivingOnly,
}

/// One policy row of the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Policy {
    /// P-10.
    pub p10: P10,
    /// P-11 anonymous.
    pub p11_anonymous: bool,
    /// P-28 on.
    pub p28_on: bool,
    /// P-75 on.
    pub p75_on: bool,
    /// P-77 "draft only".
    pub p77_draft_only: bool,
    /// P-74.
    pub p74: P74,
}

impl Policy {
    /// The SuperSAFE column of `policy-parameters.md` for these six.
    pub const SUPERSAFE: Policy = Policy {
        p10: P10::AssignedOnly,
        p11_anonymous: true,
        p28_on: false,
        p75_on: false,
        p77_draft_only: true,
        p74: P74::AllRoles,
    };

    /// The covering array of 9 rows over P-10 and P-74 (three values each)
    /// and P-11, P-28, P-75 and P-77 (two each), design section 8.3. Every
    /// pair of values of every two parameters appears in some row. Row 0 is
    /// the SuperSAFE row.
    pub fn covering_rows() -> [Policy; 9] {
        const P10S: [P10; 3] = [P10::AssignedOnly, P10::AllCommittee, P10::OperatorStaffOnly];
        const P74S: [P74; 3] = [P74::AllRoles, P74::Disabled, P74::ReceivingOnly];
        // Columns P-11, P-28, P-75, P-77 of rows (a, b) in the order
        // (0,0), (0,1), ... (2,2). A bit of 0 is the SuperSAFE value.
        const BITS: [[bool; 4]; 9] = [
            [false, false, false, false],
            [true, false, true, true],
            [true, true, false, true],
            [true, false, false, true],
            [false, true, false, false],
            [false, false, true, false],
            [true, true, true, false],
            [false, false, false, true],
            [false, false, false, true],
        ];
        let mut out = [Policy::SUPERSAFE; 9];
        for (i, row) in out.iter_mut().enumerate() {
            let a = P10S.get(i / 3).copied().unwrap_or(P10::AssignedOnly);
            let b = P74S.get(i % 3).copied().unwrap_or(P74::AllRoles);
            let bits = BITS.get(i).copied().unwrap_or([false; 4]);
            *row = Policy {
                p10: a,
                p11_anonymous: !bits[0],
                p28_on: bits[1],
                p75_on: bits[2],
                p77_draft_only: !bits[3],
                p74: b,
            };
        }
        out
    }
}

/// What an operation acts on. A cell exists only in the states where its
/// target exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// Nothing of P: the caller's own objects or the tenant.
    None,
    /// The programme P.
    Programme,
    /// The call C, in any call state.
    Call,
    /// The published call C.
    PublishedCall,
    /// The published and open call C.
    OpenCall,
    /// The proposal X.
    Proposal,
    /// A reviewer assignment on X.
    Assignment,
    /// An IRC assignment on X.
    IrcAssignment,
    /// A cut-off round of C holding X.
    Round,
    /// A finding on X, seeded through the assessor's system path.
    Finding,
}

/// The states of X in which reviewer assignments exist: every state an
/// assignment can be made in or carried through. A knocked-out proposal
/// gets none (R-EV-01).
const ASSIGNED: [StateTag; 14] = [
    StateTag::Submitted,
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

/// The states of X reached through a cut-off round.
const ROUND: [StateTag; 11] = [
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::NotSelected,
    StateTag::Deferred,
    StateTag::Declined,
    StateTag::Negotiation,
    StateTag::Withdrawn,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// The states of X reached through IRC review.
const IRC: [StateTag; 9] = [
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

fn among(s: StateTag, set: &[StateTag]) -> bool {
    set.contains(&s)
}

/// Whether the target exists in the state.
pub fn target_exists(target: Target, state: StateProfile) -> bool {
    use StateProfile as S;
    match target {
        Target::None => true,
        Target::Programme => !matches!(state, S::Onboarding(_)),
        Target::Call => !matches!(
            state,
            S::Onboarding(_) | S::ProgrammeDraft | S::ProgrammeActive
        ),
        Target::PublishedCall => matches!(state, S::CallOpen | S::CallClosed | S::Proposal(_)),
        Target::OpenCall => matches!(state, S::CallOpen | S::Proposal(StateTag::Draft)),
        Target::Proposal => state.proposal().is_some(),
        Target::Assignment => state.proposal().is_some_and(|s| among(s, &ASSIGNED)),
        Target::IrcAssignment => state.proposal().is_some_and(|s| among(s, &IRC)),
        Target::Round => state.proposal().is_some_and(|s| among(s, &ROUND)),
        Target::Finding => state
            .proposal()
            .is_some_and(|s| among(s, &ASSIGNED) && s != StateTag::Submitted),
    }
}

/// Whether the principal can exist in the state. The generator builds
/// only cells it can reach from genesis.
pub fn feasible(who: Who, state: StateProfile) -> bool {
    use StateProfile as S;
    // While the tenant onboards, no programme exists, so only admins and
    // accounts with no binding do.
    if let S::Onboarding(_) = state {
        return matches!(
            who,
            Who::Anonymous | Who::Unbound | Who::TenantAdmin | Who::SoleTenantAdmin
        );
    }
    let x = state.proposal();
    let draft_programme = matches!(state, S::ProgrammeDraft);
    let declared_on_x = x.is_none_or(|s| s != StateTag::Draft);
    match who {
        Who::Anonymous
        | Who::Unbound
        | Who::TenantAdmin
        | Who::TenantAdminBuilder
        | Who::ProgrammeManager
        | Who::EndedProgrammeManager
        | Who::OtherProgrammeManager => true,
        // Onboarding finishes with two admins, and activation needs a second
        // admin (I-67), so a sole admin exists past onboarding only while P
        // is still the draft it opened.
        Who::SoleTenantAdmin => draft_programme,
        // A draft programme admits programme manager grants only (D3).
        Who::CallDrafter
        | Who::CommitteeMember
        | Who::CommitteeChair
        | Who::IrcMember
        | Who::FinanceApprover
        | Who::PaymentReleaser
        | Who::ContractSignatory
        | Who::Auditor => !draft_programme,
        Who::ProgrammeManagerDrafter => !matches!(state, S::ProgrammeDraft | S::ProgrammeActive),
        Who::Coordinator => !draft_programme && declared_on_x,
        Who::CoordinatorUndeclared => x.is_some(),
        Who::CoordinatorConflicted => x.is_some_and(|s| s != StateTag::Draft),
        Who::AssignedReviewer
        | Who::AssignedReviewerConflicted
        | Who::ReleasedReviewer
        | Who::SuspendedReviewer => x.is_some_and(|s| among(s, &ASSIGNED)),
        // Stage 1 closes only with a score from every active assignee, so
        // an undeclared assignee exists before the close or after a new
        // assignment in NEGOTIATION.
        Who::AssignedReviewerUndeclared => x.is_some_and(|s| {
            matches!(
                s,
                StateTag::Submitted | StateTag::Stage1 | StateTag::Negotiation
            )
        }),
        Who::RecusedCommitteeMember | Who::DelegatingCommitteeMember => {
            x.is_some_and(|s| among(s, &ROUND))
        }
        Who::IrcAssignee | Who::IrcAssigneeConflicted => x.is_some_and(|s| among(s, &IRC)),
        Who::IrcAssigneeUndeclared => x == Some(StateTag::IrcReview),
        Who::Lead | Who::TeamMember | Who::Guardian => x.is_some(),
        Who::VoidedLead => matches!(x, Some(StateTag::Negotiation | StateTag::Declined)),
    }
}

/// The authorisation rule of one operation, as the spec states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Anyone, with or without an account: public pages and open calls.
    Anyone,
    /// Anyone, with or without an account, once C is published. A drafted
    /// or approved call is confidential until publication, and its Guide
    /// exists only from then (R-AC-01, R-GA-01).
    PublishedCall,
    /// Any account, on its own objects.
    AnyAccount,
    /// A tenant admin (O-47, `roles-and-sod.md` Granting roles).
    TenantAdmin,
    /// A tenant admin outside the builder set (I-67, Q1 interim).
    ApproverAdmin,
    /// A tenant admin while a second tenant admin exists: approving a
    /// self-grant (SoD-07), and finishing onboarding, which needs two
    /// admins (design section 2.2, J0).
    SecondAdmin,
    /// A programme manager of P: the creator walks a programme manager
    /// through its steps (`programme-creator.md`), and I-65 names one.
    ProgrammeManager,
    /// A programme manager of P or a tenant admin. Reading: the approving
    /// admin needs the draft, its report and previews, and either may
    /// acknowledge a warning (design section 8.4, I-67 witnesses).
    DraftManager,
    /// A programme manager of P or a tenant admin. Reading: A1 invites the
    /// first programme manager, who invites the rest in step 9.
    Inviter,
    /// A tenant admin, or a programme manager of any programme of the
    /// tenant. Reading: the creator start page lists the tenant's
    /// programmes as clone sources and the template catalogue. A clone
    /// comes from "an existing programme in the same tenant"
    /// (`programme-creator.md` Starting points, R-PG-02), and a programme
    /// manager chooses the starting point (J1). An ended binding holds no
    /// role, so it lists nothing.
    CreatorStart,
    /// A call drafter or programme manager of P. Reading: the decided M2
    /// actor rule for drafting a call.
    CallAuthor,
    /// A programme manager of P who is no drafter of C (R-PC-03).
    CallApprover,
    /// A programme manager, call drafter or FSTP coordinator of P.
    CallStaff,
    /// The FSTP coordinator of P.
    Coordinator,
    /// The FSTP coordinator of P, declared and free of conflict: the
    /// knock-out check (`roles-and-sod.md` Conflict declarations).
    CoordinatorDeclared,
    /// The FSTP coordinator of P, and under P-10 "all committee members"
    /// every committee member of P: both declare per proposal before
    /// reading full content (`roles-and-sod.md` Conflict declarations).
    ProposalDeclarant,
    /// The FSTP coordinator of P, in every state of X from SUBMITTED on,
    /// except INELIGIBLE. Reading: the assignment view of one proposal
    /// serves `review.assign` and `review.unassign` (J5). A draft is the
    /// team's alone until it is submitted (I-21, R-AC-01). A knocked-out
    /// proposal receives no further review (R-EV-01), so INELIGIBLE is
    /// closed, pending a reading for the assignments it still carries.
    /// The view holds no content, so I-03, which bars a reviewer, does not
    /// bar it.
    AssignmentBoard,
    /// Any account outside Drafting, Judging and Operations in P: the
    /// draft's creator (SoD-01, SoD-03, SoD-05, SoD-06).
    NewApplicant,
    /// The lead of X (state-machine.md actor "Applicant").
    Lead,
    /// The applicant team of X: lead, team members and guardian.
    Team,
    /// The guardian on X.
    Guardian,
    /// The team, and only while X is in NEGOTIATION. Reading: the landing
    /// shows the negotiation notice and next steps.
    NegotiationTeam,
    /// The assignee of the target assignment, declared or not.
    Assignee,
    /// The declared, conflict-free assignee: every assigned-reviewer act.
    ReviewerAct,
    /// The declared, conflict-free reviewer or IRC assignee of X in the
    /// finding's call: a mark on a finding (I-03, I-10). The engine's
    /// `Mark` rule admits both assignment kinds (lane L-FIND-B).
    FindingMarker,
    /// The declared, conflict-free assignee, in STAGE1 and STAGE2.
    /// Reading: the score sheet is read while scoring.
    ScoreSheet,
    /// The declared, conflict-free assignee, in STAGE2.
    Stage2Thread,
    /// The declared, conflict-free assignee, in STAGE1 and STAGE2, unless
    /// P-10 is "operator staff only". Findings quote content.
    Findings,
    /// Full content (R-AC-01, P-10 NOTE 1, I-03, D6 with P-75, Q39).
    Content,
    /// The title and neutral summary before a declaration (R-CF-02, Q9).
    DeclarationView,
    /// A committee member or chair of P (ranking view, round view; Q16
    /// shows recused rows as "recused" and still opens the view).
    Committee,
    /// A committee member or chair of P who is not recused (R-EV-09 NOTE).
    CommitteeVoter,
    /// The IRC assignee, declared or not.
    IrcAssignee,
    /// The declared, conflict-free IRC assignee.
    IrcAct,
    /// The declared, conflict-free IRC assignee, in IRC_REVIEW (R-IR-03).
    IrcCase,
    /// An auditor of P (roles table: read-only audit access).
    Auditor,
    /// The route position and diary of X (`SPEC/12-journey-ui.md`
    /// sections 7.2 and 10, lane j2). Reading: the team in every state,
    /// and a holder of a role of the section 7.2 matrix in P once X has
    /// left DRAFT (I-21). Call drafters and tenant admins read no diary.
    /// Nor do financial and legal signatories: section 7.2 names neither,
    /// and both bind tenant-wide with no programme (roles-and-sod.md NOTE
    /// 5). Interim, fail closed, design section 15.0 (lane j2).
    /// Which entries show is the visibility function's per request
    /// (I-93), not an authorisation rule, so it is not judged here.
    /// Daniel, 2026-11-06: the lead and the team member read in every
    /// state, a terminal one included, after their bindings end there.
    /// The guardian's binding ends there too, and the decision names no
    /// guardian, so the guardian reads only while X is under way.
    Journey,
    /// The route map of X (ADR-015 amendment of 2026-11-06, section 8.1,
    /// O-58): the lead and the team member in every state, a terminal one
    /// included (Daniel, 2026-11-06). The guardian gets no map.
    RouteMap,
}

impl Rule {
    /// The roles through which the rule can admit a call (P-74, Q42).
    /// `None` is an account acting with no binding yet.
    pub fn acting(self) -> &'static [Option<Role>] {
        const EVERY: [Option<Role>; 17] = [
            None,
            Some(Role::ProgrammeManager),
            Some(Role::CallDrafter),
            Some(Role::FstpCoordinator),
            Some(Role::CommitteeMember),
            Some(Role::CommitteeChair),
            Some(Role::IrcMember),
            Some(Role::Applicant),
            Some(Role::ApplicantTeamMember),
            Some(Role::Guardian),
            Some(Role::TenantAdmin),
            Some(Role::FinanceApprover),
            Some(Role::PaymentReleaser),
            Some(Role::ContractSignatory),
            Some(Role::FinancialSignatory),
            Some(Role::LegalSignatory),
            Some(Role::Auditor),
        ];
        const TEAM: [Option<Role>; 3] = [
            Some(Role::Applicant),
            Some(Role::ApplicantTeamMember),
            Some(Role::Guardian),
        ];
        match self {
            Rule::Anyone | Rule::PublishedCall | Rule::AnyAccount => &EVERY,
            Rule::TenantAdmin | Rule::ApproverAdmin | Rule::SecondAdmin => {
                &[Some(Role::TenantAdmin)]
            }
            Rule::ProgrammeManager | Rule::CallApprover => &[Some(Role::ProgrammeManager)],
            Rule::DraftManager | Rule::Inviter | Rule::CreatorStart => {
                &[Some(Role::ProgrammeManager), Some(Role::TenantAdmin)]
            }
            Rule::CallAuthor => &[Some(Role::ProgrammeManager), Some(Role::CallDrafter)],
            Rule::CallStaff => &[
                Some(Role::ProgrammeManager),
                Some(Role::CallDrafter),
                Some(Role::FstpCoordinator),
            ],
            Rule::Coordinator | Rule::CoordinatorDeclared | Rule::AssignmentBoard => {
                &[Some(Role::FstpCoordinator)]
            }
            Rule::ProposalDeclarant => &[Some(Role::FstpCoordinator), Some(Role::CommitteeMember)],
            Rule::NewApplicant => &[
                None,
                Some(Role::Applicant),
                Some(Role::ApplicantTeamMember),
                Some(Role::Guardian),
            ],
            Rule::Lead => &[Some(Role::Applicant)],
            // The registry names the team for the route map. The guardian is
            // then refused by the rule itself (section 8.1).
            Rule::Team | Rule::NegotiationTeam | Rule::RouteMap => &TEAM,
            Rule::Guardian => &[Some(Role::Guardian)],
            Rule::Assignee
            | Rule::ReviewerAct
            | Rule::ScoreSheet
            | Rule::Stage2Thread
            | Rule::Findings => &[Some(Role::CommitteeMember)],
            Rule::FindingMarker => &[Some(Role::CommitteeMember), Some(Role::IrcMember)],
            Rule::Content => &[
                Some(Role::Applicant),
                Some(Role::ApplicantTeamMember),
                Some(Role::Guardian),
                Some(Role::FstpCoordinator),
                Some(Role::CommitteeMember),
                Some(Role::IrcMember),
            ],
            Rule::DeclarationView => &[
                Some(Role::FstpCoordinator),
                Some(Role::CommitteeMember),
                Some(Role::IrcMember),
            ],
            Rule::Committee | Rule::CommitteeVoter => {
                &[Some(Role::CommitteeMember), Some(Role::CommitteeChair)]
            }
            Rule::IrcAssignee | Rule::IrcAct | Rule::IrcCase => &[Some(Role::IrcMember)],
            Rule::Auditor => &[Some(Role::Auditor)],
            // No signatory: the section 7.2 matrix names neither (NOTE 5).
            Rule::Journey => &[
                Some(Role::Applicant),
                Some(Role::ApplicantTeamMember),
                Some(Role::Guardian),
                Some(Role::FstpCoordinator),
                Some(Role::ProgrammeManager),
                Some(Role::CommitteeMember),
                Some(Role::CommitteeChair),
                Some(Role::IrcMember),
                Some(Role::FinanceApprover),
                Some(Role::PaymentReleaser),
                Some(Role::ContractSignatory),
                Some(Role::Auditor),
            ],
        }
    }
}

/// An MCP tool of the capability table (design section 3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefTool {
    /// The tool name.
    pub name: &'static str,
    /// Whether a token needs a scope for it. Public tools need none.
    pub scoped: bool,
}

/// One operation as the reference knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefOp {
    /// The journey name.
    pub name: &'static str,
    /// What it acts on.
    pub target: Target,
    /// Its rule.
    pub rule: Rule,
    /// Whether it is a read. A read refuses an outsider with
    /// `Visibility`, an act refuses one with `Actor`.
    pub read: bool,
    /// A public page or tool: no account, no session rule.
    pub public: bool,
    /// A public operation the web serves as a page or the feed under `/p`
    /// (M4 design section 3.10, "Routes"). A public operation without one
    /// is a public research tool only (`mcp-server.md`), so the matrix gives
    /// it no web cell. False for every other operation.
    pub page: bool,
    /// High-risk by the table of `authentication.md` or by the strict
    /// reading of Q10.
    pub high_risk: bool,
    /// Binding under P-77. Reading: every command a person issues is
    /// binding except a draft, a plan and a content read, as M2 decided
    /// for R-MC-05. Creator saves and workspace autosaves are drafts.
    pub binding: bool,
    /// Refused while P is a draft programme (change D3).
    pub draft_gate: bool,
    /// The MCP tool, if any.
    pub tool: Option<RefTool>,
}

impl RefOp {
    const fn act(name: &'static str, target: Target, rule: Rule) -> RefOp {
        RefOp {
            name,
            target,
            rule,
            read: false,
            public: false,
            page: false,
            high_risk: false,
            binding: false,
            draft_gate: false,
            tool: None,
        }
    }

    const fn read(name: &'static str, target: Target, rule: Rule) -> RefOp {
        RefOp {
            read: true,
            ..RefOp::act(name, target, rule)
        }
    }

    const fn public(name: &'static str, target: Target, tool: Option<&'static str>) -> RefOp {
        let tool = match tool {
            Some(name) => Some(RefTool {
                name,
                scoped: false,
            }),
            None => None,
        };
        RefOp {
            public: true,
            page: true,
            tool,
            ..RefOp::read(name, target, Rule::Anyone)
        }
    }

    /// A public research tool with no page under `/p` (M4 design section
    /// 3.10, "Routes").
    const fn tool_only(self) -> RefOp {
        RefOp {
            page: false,
            ..self
        }
    }

    const fn hr(self) -> RefOp {
        RefOp {
            high_risk: true,
            ..self
        }
    }

    const fn binding(self) -> RefOp {
        RefOp {
            binding: true,
            ..self
        }
    }

    const fn gated(self) -> RefOp {
        RefOp {
            draft_gate: true,
            ..self
        }
    }

    const fn tool(self, name: &'static str) -> RefOp {
        RefOp {
            tool: Some(RefTool { name, scoped: true }),
            ..self
        }
    }
}

use Rule as R;
use Target as T;

/// Every operation of the M4 journeys J0 to J10, up to NEGOTIATION. The
/// control plane operations of J0 (`cp.*`) run in `fstp-control`, not
/// through the cell's dispatch, so they are not here.
pub const REFERENCE_OPS: &[RefOp] = &[
    // J0 and J10: tenant onboarding, settings and admin approvals.
    RefOp::act("me.begin_verification", T::None, R::AnyAccount),
    RefOp::read("tenant.get_step", T::None, R::TenantAdmin),
    RefOp::act("tenant.save_step", T::None, R::TenantAdmin),
    RefOp::act("tenant.complete", T::None, R::SecondAdmin),
    RefOp::read("tenant.settings", T::None, R::TenantAdmin),
    RefOp::act("tenant.invite_admin", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_login_methods", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_step_up_freshness", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_session_lifetimes", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_mcp", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_payment_mode", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.set_template_licence", T::None, R::TenantAdmin).hr(),
    // R-GA-01 (2026-11-06): the tenant's override of the Guide's data
    // protection texts, high-risk by the strict reading of settings.
    RefOp::act("tenant.set_guide_notice", T::None, R::TenantAdmin).hr(),
    RefOp::read("admin.approvals", T::None, R::TenantAdmin),
    RefOp::act("admin.approve_self_grant", T::None, R::SecondAdmin).hr(),
    RefOp::act("admin.approve_recovery", T::None, R::TenantAdmin).hr(),
    RefOp::act("admin.approve_break_glass", T::None, R::TenantAdmin).hr(),
    // Lane m4reg, the Administrators step: the tenant's admins and whether
    // each verified identity, since onboarding finishes only with two
    // verified admins (J0, SoD-07).
    RefOp::read("tenant.list_admins", T::None, R::TenantAdmin),
    // Lane m4/roles (SA-01, NOTE 5): the tenant-wide signatory roles. Only a
    // tenant admin lists, grants or ends them (Q31), and a grant or an end
    // changes an Operations role, so it is high-risk (I-78). SoD-07 and the
    // re-grant rule judge the grantee, which the shell refuses as a guard
    // of the request, never the caller.
    RefOp::read("tenant.list_signatories", T::None, R::TenantAdmin),
    RefOp::act("tenant.grant_signatory", T::None, R::TenantAdmin).hr(),
    RefOp::act("tenant.end_signatory", T::None, R::TenantAdmin).hr(),
    // SoD-18: any tenant admin reads, requests and approves activation.
    // Whether the approver is the requester, and whether both signatory
    // roles are held (SoD-14, SoD-15), are judged on the request. Neither
    // is high-risk: the table of `authentication.md` names programme
    // activation only (interim, pending Daniel).
    RefOp::read("tenant.get_activation", T::None, R::TenantAdmin),
    RefOp::act("tenant.request_activation", T::None, R::TenantAdmin),
    RefOp::act("tenant.approve_activation", T::None, R::TenantAdmin),
    // M9 lane B1: a tenant admin checks and sets the brand tokens. The
    // set is high-risk by the strict reading (I-78, interim).
    RefOp::act("tenant.branding.check", T::None, R::TenantAdmin),
    RefOp::act("tenant.branding.set", T::None, R::TenantAdmin).hr(),
    // M9 lane T1: interface labels and the Voyage switch (I-72, interim).
    RefOp::act("tenant.terminology.set", T::None, R::TenantAdmin).hr(),
    // M6 lane L6-EGR, ADR-018: the mail relay, high-risk by the strict
    // reading of settings.
    RefOp::act("tenant.set_mail_relay", T::None, R::TenantAdmin).hr(),
    // M6 lane L6-API, M6 design section 6: web only.
    RefOp::read("tenant.get_mail_relay", T::None, R::TenantAdmin),
    RefOp::act("tenant.clear_mail_relay", T::None, R::TenantAdmin).hr(),
    RefOp::read("tenant.deliveries", T::None, R::TenantAdmin),
    // Lane m4reg: the caller's own verification state, beside
    // `me.begin_verification`. Reading: any account reads its own state,
    // as it may begin its own verification.
    RefOp::read("me.get_verification", T::None, R::AnyAccount),
    // J1: the creator and import.
    RefOp::act("creator.open_draft", T::None, R::TenantAdmin).hr(),
    // Lane m4reg, the creator start page: clone sources and templates.
    RefOp::read("creator.list_programmes", T::None, R::CreatorStart),
    RefOp::read("creator.list_templates", T::None, R::CreatorStart),
    RefOp::act("creator.invite", T::Programme, R::Inviter),
    RefOp::read("creator.invitations", T::Programme, R::DraftManager),
    // Reading: whoever may invite may withdraw the invitation.
    RefOp::act("creator.withdraw_invitation", T::Programme, R::Inviter),
    RefOp::act("creator.apply_start", T::Programme, R::ProgrammeManager),
    RefOp::act("creator.save_fields", T::Programme, R::ProgrammeManager)
        .tool("fstp_creator_save_fields"),
    // TH-49: the manager accepts template narrative before it applies.
    RefOp::act(
        "creator.accept_narrative",
        T::Programme,
        R::ProgrammeManager,
    ),
    RefOp::read("creator.get_draft", T::Programme, R::DraftManager).tool("fstp_creator_get_draft"),
    RefOp::read("creator.get_report", T::Programme, R::DraftManager)
        .tool("fstp_creator_get_report"),
    RefOp::act("creator.acknowledge", T::Programme, R::DraftManager),
    RefOp::read("creator.preview", T::Programme, R::DraftManager),
    RefOp::read("creator.impact", T::Programme, R::DraftManager),
    RefOp::act(
        "creator.request_activation",
        T::Programme,
        R::ProgrammeManager,
    ),
    RefOp::act("creator.approve_activation", T::Programme, R::ApproverAdmin).hr(),
    // R-PG-05, Q17 interim: a tenant-private template. Reading: the
    // programme's manager or a tenant admin saves it, as either reads the
    // draft it comes from.
    RefOp::act("creator.save_as_template", T::Programme, R::DraftManager),
    RefOp::act("import.upload", T::Programme, R::ProgrammeManager),
    RefOp::read("import.list", T::Programme, R::DraftManager),
    RefOp::act("import.resolve", T::Programme, R::ProgrammeManager),
    // J1 and J2: people and roles.
    // Lane m4reg, the invitation landing (J2). Reading: the invitation
    // token in the request is the capability. The invitee reads the
    // landing before enrolling a passkey, so the read admits a caller with
    // no account. A token that names no open invitation refuses as an
    // input, outside authorisation. The read has no tool, and it is not a
    // public page: it carries the programme's P-75 and P-77 choices for
    // the confidentiality terms.
    RefOp::read("people.get_invitation", T::None, R::Anyone),
    RefOp::act("people.accept_invitation", T::None, R::AnyAccount),
    RefOp::act("people.begin_verification", T::None, R::AnyAccount),
    RefOp::read("roles.list", T::Programme, R::TenantAdmin),
    RefOp::act("roles.grant", T::Programme, R::TenantAdmin).hr(),
    RefOp::act("roles.end", T::Programme, R::TenantAdmin).hr(),
    RefOp::act("roles.reinstate", T::Programme, R::TenantAdmin).hr(),
    // J3: calls.
    RefOp::act("call.draft", T::Programme, R::CallAuthor)
        .gated()
        .binding()
        .tool("fstp_draft_call"),
    RefOp::act("call.edit", T::Call, R::CallAuthor)
        .gated()
        .binding()
        .tool("fstp_edit_call"),
    RefOp::act("call.approve", T::Call, R::CallApprover)
        .gated()
        .binding(),
    RefOp::act("call.publish", T::Call, R::ProgrammeManager)
        .gated()
        .binding()
        .hr()
        .tool("fstp_prepare_call_publication"),
    RefOp::read("call.board", T::Call, R::CallStaff).tool("fstp_get_call_board"),
    // Lane mcreator: the Studio list of the programme's calls. Reading: the
    // staff who read a call's board read the list of its calls.
    RefOp::read("call.list", T::Programme, R::CallStaff),
    // M6 lane L6-API, M6 design section 6: the programme manager, web only.
    RefOp::read("programme.timeline", T::Programme, R::ProgrammeManager),
    // J4: public pages, open calls and applicants.
    RefOp::public(
        "public.programme",
        T::Programme,
        Some("fstp_public_get_programme"),
    ),
    RefOp::public(
        "public.list_open_calls",
        T::Programme,
        Some("fstp_public_list_open_calls"),
    )
    .tool_only(),
    RefOp::public(
        "public.call",
        T::PublishedCall,
        Some("fstp_public_get_call"),
    ),
    RefOp::public(
        "public.guide",
        T::PublishedCall,
        Some("fstp_public_get_guide"),
    ),
    RefOp::public(
        "public.deadlines",
        T::Programme,
        Some("fstp_public_get_deadlines"),
    )
    .tool_only(),
    RefOp::public(
        "public.eligibility",
        T::Programme,
        Some("fstp_public_get_eligibility"),
    )
    .tool_only(),
    RefOp::public(
        "public.funded",
        T::Programme,
        Some("fstp_public_list_funded"),
    ),
    RefOp::public(
        "public.finished",
        T::Programme,
        Some("fstp_public_list_finished"),
    ),
    RefOp::public("public.feed", T::Programme, None),
    RefOp::read("calls.list_open", T::Programme, R::Anyone).tool("fstp_list_open_calls"),
    RefOp::read("calls.get", T::Call, R::PublishedCall),
    RefOp::read("calls.guide", T::Call, R::PublishedCall).tool("fstp_get_guide"),
    RefOp::act("proposal.create", T::OpenCall, R::NewApplicant).gated(),
    RefOp::read("proposal.list_own", T::None, R::AnyAccount).tool("fstp_list_my_proposals"),
    RefOp::read("proposal.view", T::Proposal, R::Team).tool("fstp_get_my_proposal"),
    RefOp::read("proposal.get_workspace", T::Proposal, R::Team),
    RefOp::act("proposal.save_workspace", T::Proposal, R::Team).tool("fstp_save_workspace"),
    RefOp::act("proposal.record_plan", T::Proposal, R::Lead).tool("fstp_record_plan_version"),
    RefOp::act("proposal.add_member", T::Proposal, R::Lead).binding(),
    RefOp::act("proposal.add_guardian", T::Proposal, R::Lead).binding(),
    RefOp::act("proposal.state_country", T::Proposal, R::Lead),
    RefOp::act("proposal.declare_affiliations", T::Proposal, R::Lead),
    RefOp::act("proposal.state_birth_date", T::Proposal, R::Lead),
    RefOp::act("proposal.submit", T::Proposal, R::Lead)
        .binding()
        .tool("fstp_submit_proposal"),
    RefOp::act("proposal.request_copy", T::Proposal, R::Lead),
    RefOp::read("me.notices", T::None, R::AnyAccount).tool("fstp_list_notices"),
    RefOp::read("stage2.view", T::Proposal, R::Team).tool("fstp_get_stage2_questions"),
    RefOp::act("stage2.answer", T::Proposal, R::Lead)
        .binding()
        .tool("fstp_answer_stage2"),
    RefOp::act("stage2.revise", T::Proposal, R::Lead)
        .binding()
        .tool("fstp_submit_revision"),
    RefOp::act("proposal.withdraw", T::Proposal, R::Lead).binding(),
    // Lane j2, `SPEC/12-journey-ui.md` section 10: web only.
    RefOp::read("proposal.journey", T::Proposal, R::Journey),
    RefOp::read("proposal.diary", T::Proposal, R::Journey),
    // Lane j4, ADR-015 amendment of 2026-11-06: the map is the team's
    // (section 8.1, O-58), and stays the former team's (Daniel,
    // 2026-11-06). Web only.
    RefOp::read("proposal.route_map", T::Proposal, R::RouteMap),
    RefOp::act("guardian.begin_consent", T::Proposal, R::Guardian),
    RefOp::read("negotiation.view", T::Proposal, R::NegotiationTeam),
    RefOp::act("negotiation.acknowledge_notice", T::Proposal, R::Lead),
    // J5: the FSTP coordinator.
    RefOp::read("intake.queue", T::PublishedCall, R::Coordinator),
    RefOp::read("review.declaration_view", T::Proposal, R::DeclarationView),
    RefOp::act("review.declare_proposal", T::Proposal, R::ProposalDeclarant).binding(),
    RefOp::read("review.read_content", T::Proposal, R::Content).tool("fstp_get_proposal_content"),
    RefOp::act("review.knock_out", T::Proposal, R::CoordinatorDeclared).binding(),
    // Lane m4reg: one proposal's assignments, candidates and the P-39 and
    // proximity results as pass or fail, for the assignment screen (J5).
    RefOp::read("review.assignments", T::Proposal, R::AssignmentBoard),
    RefOp::act("review.assign", T::Proposal, R::Coordinator).binding(),
    RefOp::act("review.unassign", T::Assignment, R::Coordinator).binding(),
    RefOp::act("review.admit", T::Proposal, R::Coordinator).binding(),
    RefOp::act("review.close_stage1", T::Proposal, R::Coordinator).binding(),
    RefOp::read(
        "review.notifiable_conflicts",
        T::PublishedCall,
        R::Coordinator,
    ),
    // J6: assigned reviewers.
    RefOp::read("me.assignments", T::None, R::AnyAccount).tool("fstp_list_assignments"),
    RefOp::act("review.declare_assignment", T::Assignment, R::Assignee).binding(),
    RefOp::read("review.score_sheet", T::Assignment, R::ScoreSheet).tool("fstp_get_score_sheet"),
    RefOp::act("review.score", T::Assignment, R::ReviewerAct)
        .binding()
        .tool("fstp_record_score"),
    RefOp::act("review.correct_score", T::Assignment, R::ReviewerAct)
        .binding()
        .tool("fstp_correct_score"),
    RefOp::act("review.ranking_summary", T::Assignment, R::ReviewerAct)
        .binding()
        .tool("fstp_record_ranking_summary"),
    RefOp::read("review.stage2_thread", T::Assignment, R::Stage2Thread),
    RefOp::act("stage2.ask", T::Assignment, R::ReviewerAct).binding(),
    RefOp::act("stage2.no_questions", T::Assignment, R::ReviewerAct).binding(),
    RefOp::act("review.rank", T::Assignment, R::ReviewerAct).binding(),
    RefOp::read("review.findings", T::Assignment, R::Findings).tool("fstp_get_findings"),
    RefOp::act("review.mark_finding", T::Finding, R::FindingMarker).binding(),
    // J7: the committee.
    RefOp::read("committee.ranking", T::PublishedCall, R::Committee).tool("fstp_get_ranking_view"),
    RefOp::read("committee.round", T::Round, R::Committee),
    RefOp::act("committee.open_round", T::PublishedCall, R::CommitteeVoter).binding(),
    RefOp::act("committee.cast", T::Round, R::CommitteeVoter).binding(),
    RefOp::act("committee.delegate", T::Round, R::CommitteeVoter).binding(),
    RefOp::act("committee.record_cutoff", T::Round, R::CommitteeVoter).binding(),
    // J8: IRC and the decline rows.
    RefOp::read("me.irc_cases", T::None, R::AnyAccount),
    RefOp::act("irc.declare", T::IrcAssignment, R::IrcAssignee).binding(),
    RefOp::read("irc.case", T::IrcAssignment, R::IrcCase),
    RefOp::act("irc.review", T::IrcAssignment, R::IrcAct).binding(),
    RefOp::act(
        "decision.decline_after_concern",
        T::Proposal,
        R::ProgrammeManager,
    )
    .binding(),
    RefOp::act(
        "decision.decline_negotiation",
        T::Proposal,
        R::ProgrammeManager,
    )
    .binding(),
    // J9: agents, sessions, pending actions and audit.
    RefOp::act("agents.consent", T::None, R::AnyAccount).hr(),
    RefOp::read("agents.list", T::None, R::AnyAccount),
    RefOp::read("agents.activity", T::None, R::AnyAccount),
    RefOp::act("agents.revoke", T::None, R::AnyAccount),
    RefOp::read("me.sessions", T::None, R::AnyAccount),
    // The interim home page of design section 15.0 (2026-10-31): the
    // caller's own roles. Reading: any account reads its own, web only,
    // with no tool (I-86).
    RefOp::read("me.roles", T::None, R::AnyAccount),
    RefOp::act("me.end_session", T::None, R::AnyAccount),
    RefOp::act("me.add_passkey", T::None, R::AnyAccount).hr(),
    RefOp::read("pending.list", T::None, R::AnyAccount),
    RefOp::act("pending.confirm", T::None, R::AnyAccount),
    RefOp::act("pending.discard", T::None, R::AnyAccount),
    RefOp::read("audit.entries", T::Programme, R::Auditor).tool("fstp_audit_list_entries"),
    RefOp::read("audit.vault_outcomes", T::Programme, R::Auditor),
];

/// Whether the rule admits the principal, and the class if not. The
/// channel, session and step-up rules are applied around it.
fn admit(
    op: &RefOp,
    who: Who,
    state: StateProfile,
    policy: &Policy,
    mcp: bool,
) -> Result<(), AuthClass> {
    use AuthClass::{Actor, Conflict, Visibility};
    let outsider = if op.read { Visibility } else { Actor };
    let open = |ok: bool| if ok { Ok(()) } else { Err(outsider) };
    let x = state.proposal();
    // The acts and reads an assignee performs: I-03 and R-CF-02 refuse an
    // undeclared or conflicted one with `Conflict`.
    let assignee = |declared: Who, undeclared: Who, conflicted: Who| {
        if who == declared {
            Ok(())
        } else if who == undeclared || who == conflicted {
            Err(Conflict)
        } else {
            Err(outsider)
        }
    };
    match op.rule {
        Rule::Anyone => Ok(()),
        Rule::PublishedCall => open(target_exists(Target::PublishedCall, state)),
        Rule::AnyAccount => open(who.account()),
        Rule::TenantAdmin => open(who.tenant_admin()),
        Rule::ApproverAdmin => open(who == Who::TenantAdmin),
        Rule::SecondAdmin => open(who.tenant_admin() && who != Who::SoleTenantAdmin),
        Rule::ProgrammeManager => open(who.manager()),
        Rule::DraftManager | Rule::Inviter => open(who.manager() || who.tenant_admin()),
        Rule::CreatorStart => {
            open(who.tenant_admin() || who.manager() || who == Who::OtherProgrammeManager)
        }
        Rule::CallAuthor => open(who.manager() || who == Who::CallDrafter),
        Rule::CallApprover => open(who == Who::ProgrammeManager),
        Rule::CallStaff => open(who.manager() || who == Who::CallDrafter || who.coordinator()),
        Rule::Coordinator => open(who.coordinator()),
        Rule::ProposalDeclarant => {
            open(who.coordinator() || (who.committee_member() && policy.p10 == P10::AllCommittee))?;
            // A declared conflict is final (Daniel, 2026-11-06): a second
            // declaration is refused under I-03.
            if who.conflicted() {
                Err(Conflict)
            } else {
                Ok(())
            }
        }
        Rule::AssignmentBoard => open(who.coordinator() && x.is_some_and(|s| among(s, &ASSIGNED))),
        Rule::CoordinatorDeclared => assignee(
            Who::Coordinator,
            Who::CoordinatorUndeclared,
            Who::CoordinatorConflicted,
        ),
        Rule::NewApplicant => open(matches!(
            who,
            Who::Unbound | Who::Lead | Who::TeamMember | Who::Guardian | Who::OtherProgrammeManager
        )),
        Rule::Lead => open(who == Who::Lead),
        // Daniel, 2026-11-06: in a terminal state the former lead and team
        // member keep a read-only view. The guardian, whom the decision
        // does not name, reads only while X is under way.
        Rule::Team if op.read => open(former_team_reads(who, x)),
        Rule::Team => open(who.team()),
        Rule::Guardian => open(who == Who::Guardian),
        Rule::NegotiationTeam => open(who.team() && x == Some(StateTag::Negotiation)),
        // A declared conflict is final (Daniel, 2026-11-06): the conflicted
        // assignee's second declaration is refused under I-03.
        Rule::Assignee if who == Who::AssignedReviewerConflicted => Err(Conflict),
        Rule::Assignee => open(matches!(
            who,
            Who::AssignedReviewer | Who::AssignedReviewerUndeclared
        )),
        Rule::FindingMarker => match who {
            Who::AssignedReviewer | Who::IrcAssignee => Ok(()),
            Who::AssignedReviewerUndeclared
            | Who::AssignedReviewerConflicted
            | Who::IrcAssigneeUndeclared
            | Who::IrcAssigneeConflicted => Err(Conflict),
            _ => Err(outsider),
        },
        Rule::ReviewerAct => assignee(
            Who::AssignedReviewer,
            Who::AssignedReviewerUndeclared,
            Who::AssignedReviewerConflicted,
        ),
        Rule::ScoreSheet | Rule::Stage2Thread | Rule::Findings => {
            // I-03: the suspended reviewer's notifiable conflict bars the
            // reads of its own assignment before anything else.
            if who == Who::SuspendedReviewer && who.conflicted_in(x) {
                return Err(Conflict);
            }
            assignee(
                Who::AssignedReviewer,
                Who::AssignedReviewerUndeclared,
                Who::AssignedReviewerConflicted,
            )?;
            let in_state = match op.rule {
                Rule::Stage2Thread => x == Some(StateTag::Stage2),
                Rule::Findings => {
                    matches!(x, Some(StateTag::Stage1 | StateTag::Stage2))
                        && policy.p10 != P10::OperatorStaffOnly
                }
                _ => matches!(x, Some(StateTag::Stage1 | StateTag::Stage2)),
            };
            open(in_state)
        }
        Rule::Content => content(who, x, policy, mcp),
        Rule::DeclarationView => declaration_view(who, x, policy),
        Rule::Committee => open(who.committee()),
        Rule::CommitteeVoter => {
            // A conflict on a ranked proposal of C recuses the member from
            // C's cut-off vote (Conflict declarations). Once the cut-off is
            // recorded no proposal of C is RANKED, so nobody is recused and
            // the recorded round refuses by its state.
            let ranked = x == Some(StateTag::Ranked);
            if ranked
                && matches!(
                    who,
                    Who::RecusedCommitteeMember | Who::AssignedReviewerConflicted
                )
            {
                Err(Conflict)
            } else {
                open(who.committee())
            }
        }
        Rule::IrcAssignee if who == Who::IrcAssigneeConflicted => Err(Conflict),
        Rule::IrcAssignee => open(matches!(who, Who::IrcAssignee | Who::IrcAssigneeUndeclared)),
        Rule::IrcAct => assignee(
            Who::IrcAssignee,
            Who::IrcAssigneeUndeclared,
            Who::IrcAssigneeConflicted,
        ),
        Rule::IrcCase => {
            assignee(
                Who::IrcAssignee,
                Who::IrcAssigneeUndeclared,
                Who::IrcAssigneeConflicted,
            )?;
            open(x == Some(StateTag::IrcReview))
        }
        Rule::Auditor => open(who == Who::Auditor),
        Rule::Journey => {
            let staff = who.manager()
                || who.coordinator()
                || who.committee()
                || matches!(
                    who,
                    Who::IrcMember
                        | Who::IrcAssignee
                        | Who::IrcAssigneeUndeclared
                        | Who::IrcAssigneeConflicted
                        | Who::FinanceApprover
                        | Who::PaymentReleaser
                        | Who::ContractSignatory
                        | Who::Auditor
                );
            // The guardian's binding ends at a terminal state (Daniel,
            // 2026-11-06), the lead's and the member's give a read-only view.
            let team = matches!(who, Who::Lead | Who::TeamMember)
                || (who == Who::Guardian && !x.is_some_and(StateTag::is_terminal));
            open(team || (staff && x.is_some_and(|s| s != StateTag::Draft)))
        }
        Rule::RouteMap => open(matches!(who, Who::Lead | Who::TeamMember)),
    }
}

/// Whether the team reads its own X in state `x`: the lead and the team
/// member in every state, a terminal one included, where their Receiving
/// bindings end but a read-only view stays (Daniel, 2026-11-06). The
/// guardian reads only while X is not terminal, since the decision names
/// no guardian. No command follows from this view.
fn former_team_reads(who: Who, x: Option<StateTag>) -> bool {
    matches!(who, Who::Lead | Who::TeamMember)
        || (who == Who::Guardian && !x.is_some_and(StateTag::is_terminal))
}

/// Full content of X (R-AC-01, P-10 NOTE 1, I-03, R-CF-02, I-21, D6, Q39).
///
/// The team reads its own proposal in every state, through either channel.
/// A conflict refuses anyone else first. Then each state admits:
///
/// - SUBMITTED: the declared coordinator, for the knock-out read;
/// - STAGE1 and STAGE2: the declared assigned reviewer under "assigned
///   reviewers only"; also every declared committee member under "all
///   committee members"; only the declared coordinator under "operator
///   staff only";
/// - IRC_REVIEW: the declared IRC assignee;
/// - NEGOTIATION: the declared assigned reviewer, for the amount;
/// - every other state, DRAFT included: nobody outside the team (I-21,
///   Q39).
///
/// Through MCP, a reader outside the team is refused unless P-75 is on.
fn content(who: Who, x: Option<StateTag>, policy: &Policy, mcp: bool) -> Result<(), AuthClass> {
    use AuthClass::{Conflict, Visibility};
    if former_team_reads(who, x) {
        return Ok(());
    }
    if who.conflicted_in(x) {
        return Err(Conflict);
    }
    let coordinator = || match who {
        Who::Coordinator => Ok(()),
        Who::CoordinatorUndeclared => Err(Conflict),
        _ => Err(Visibility),
    };
    let reviewer = || match who {
        Who::AssignedReviewer => Ok(()),
        Who::AssignedReviewerUndeclared => Err(Conflict),
        _ => Err(Visibility),
    };
    let basis = match x {
        Some(StateTag::Submitted) => coordinator(),
        Some(StateTag::Stage1 | StateTag::Stage2) => match policy.p10 {
            P10::OperatorStaffOnly => coordinator(),
            P10::AssignedOnly => reviewer(),
            P10::AllCommittee => match who {
                Who::CommitteeMember | Who::ReleasedReviewer => Ok(()),
                _ => reviewer(),
            },
        },
        Some(StateTag::IrcReview) => match who {
            Who::IrcAssignee => Ok(()),
            Who::IrcAssigneeUndeclared => Err(Conflict),
            _ => Err(Visibility),
        },
        Some(StateTag::Negotiation) => reviewer(),
        _ => Err(Visibility),
    };
    basis?;
    if mcp && !policy.p75_on {
        return Err(Visibility);
    }
    Ok(())
}

/// The title and neutral summary of X before a declaration (R-CF-02, Q9).
///
/// It opens to each person who must declare before a content read, in
/// the states where that read can follow: the coordinator in SUBMITTED,
/// and in STAGE1 and STAGE2 under "operator staff only"; the assignee in
/// SUBMITTED, STAGE1, STAGE2 and NEGOTIATION; under "all committee
/// members", every committee member in STAGE1 and STAGE2; the IRC
/// assignee in IRC_REVIEW. A conflict refuses it. Reading: the spec states
/// no state list, so this is the strict one.
fn declaration_view(who: Who, x: Option<StateTag>, policy: &Policy) -> Result<(), AuthClass> {
    use AuthClass::{Conflict, Visibility};
    if who.conflicted_in(x) {
        return Err(Conflict);
    }
    let Some(s) = x else {
        return Err(Visibility);
    };
    let staged = matches!(s, StateTag::Stage1 | StateTag::Stage2);
    let ok = match who {
        Who::Coordinator | Who::CoordinatorUndeclared => {
            s == StateTag::Submitted || (staged && policy.p10 == P10::OperatorStaffOnly)
        }
        Who::AssignedReviewer | Who::AssignedReviewerUndeclared => {
            staged || matches!(s, StateTag::Submitted | StateTag::Negotiation)
        }
        Who::CommitteeMember | Who::ReleasedReviewer => staged && policy.p10 == P10::AllCommittee,
        Who::IrcAssignee | Who::IrcAssigneeUndeclared => s == StateTag::IrcReview,
        _ => false,
    };
    if ok { Ok(()) } else { Err(Visibility) }
}

/// Whether P-74 refuses the principal for the rule (Q42 interim): the
/// tenant disabled MCP, or a role the call can act under is outside the
/// roles P-74 allows.
fn p74_refuses(rule: Rule, who: Who, policy: &Policy) -> bool {
    match policy.p74 {
        P74::AllRoles => false,
        P74::Disabled => true,
        P74::ReceivingOnly => who.roles().iter().any(|r| {
            rule.acting().contains(r)
                && !matches!(
                    r,
                    None | Some(Role::Applicant | Role::ApplicantTeamMember | Role::Guardian)
                )
        }),
    }
}

/// The reference outcome of one cell, in the order of design section 3.7:
/// session strength, channel, the dry run's authorisation, then the
/// pending action for MCP or the step-up for the web.
///
/// - Public operations admit anyone. Through MCP they need their tool and
///   an enabled MCP server, and no scope.
/// - Without an account, every other operation refuses with `Actor`,
///   except the open-call reads that admit anyone. A call read refuses
///   anyone with `Visibility` before publication.
/// - A session that is not phishing-resistant refuses a high-risk
///   operation (`authentication.md`) and every call of an account I-77
///   covers. Reading: I-77 forbids such a session outright, so the
///   reference refuses it on every account operation.
/// - Through MCP: no tool gives `NotExposed`, a token without the scope
///   `Scope`, and P-74 `P74`. A call the rule admits becomes `Pending`
///   when the operation is high-risk (I-85), or binding under P-77 "draft
///   only". Otherwise it is `Allow`.
/// - Through the web, a high-risk operation needs a fresh step-up (I-78).
pub fn expected(
    op: &RefOp,
    who: Who,
    state: StateProfile,
    policy: &Policy,
    session: &Session,
) -> Expected {
    let mcp = matches!(session.channel, Channel::Mcp { .. });
    if op.public {
        if mcp {
            if op.tool.is_none() {
                return Expected::Deny(AuthClass::NotExposed);
            }
            if policy.p74 == P74::Disabled {
                return Expected::Deny(AuthClass::P74);
            }
        }
        return Expected::Allow;
    }
    if !who.account() && !matches!(op.rule, Rule::Anyone | Rule::PublishedCall) {
        return Expected::Deny(AuthClass::Actor);
    }
    let weak = session.login.is_some_and(|l| !l.strong());
    if weak && (op.high_risk || who.management()) {
        return Expected::Deny(AuthClass::LoginStrength);
    }
    if let Channel::Mcp { scope } = session.channel {
        let Some(tool) = op.tool else {
            return Expected::Deny(AuthClass::NotExposed);
        };
        if tool.scoped && !scope {
            return Expected::Deny(AuthClass::Scope);
        }
        if p74_refuses(op.rule, who, policy) {
            return Expected::Deny(AuthClass::P74);
        }
    }
    if let Err(class) = admit(op, who, state, policy, mcp) {
        return Expected::Deny(class);
    }
    if op.draft_gate && state == StateProfile::ProgrammeDraft {
        return Expected::Deny(AuthClass::Draft);
    }
    if mcp {
        if op.high_risk || (op.binding && policy.p77_draft_only) {
            return Expected::Pending;
        }
        return Expected::Allow;
    }
    if op.high_risk && session.step_up != StepUp::Fresh {
        return Expected::Deny(AuthClass::StepUp);
    }
    Expected::Allow
}

/// One cell's coordinates, as the reference and the matrix share them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellKey {
    /// The operation name.
    pub op: &'static str,
    /// The principal.
    pub who: Who,
    /// The state.
    pub state: StateProfile,
    /// The policy row.
    pub policy: Policy,
    /// The session.
    pub session: Session,
}

/// The reference outcome table: the operation catalogue and the judging
/// function, with an optional flipped cell for the teeth test.
#[derive(Clone, Debug)]
pub struct AuthzReference {
    ops: BTreeMap<&'static str, RefOp>,
    flipped: Option<CellKey>,
}

impl AuthzReference {
    /// The operation the reference knows by `name`.
    pub fn op(&self, name: &str) -> Option<&RefOp> {
        self.ops.get(name)
    }

    /// Every operation the reference knows, by name.
    pub fn ops(&self) -> impl Iterator<Item = &RefOp> {
        self.ops.values()
    }

    /// The outcome of a cell, or `None` for an operation the reference
    /// does not know. An unknown operation is unjudged, and the matrix
    /// counts it as a failure.
    pub fn expected(&self, cell: &CellKey) -> Option<Expected> {
        let op = self.ops.get(cell.op)?;
        let out = expected(op, cell.who, cell.state, &cell.policy, &cell.session);
        if self.flipped.as_ref() == Some(cell) {
            return Some(match out {
                Expected::Allow | Expected::Pending => Expected::Deny(AuthClass::Actor),
                Expected::Deny(_) => Expected::Allow,
            });
        }
        Some(out)
    }

    /// The same reference with the outcome of one cell flipped: an allowed
    /// cell becomes a denial and a denied one an allowance. Only the teeth
    /// test uses it.
    pub fn with_flip(&self, cell: CellKey) -> AuthzReference {
        AuthzReference {
            ops: self.ops.clone(),
            flipped: Some(cell),
        }
    }
}

/// Builds the `AuthzReference` from [`REFERENCE_OPS`]. A repeated name
/// refuses, so no operation is judged twice.
pub fn authz_reference() -> Result<AuthzReference, NotImplemented> {
    let mut ops = BTreeMap::new();
    for op in REFERENCE_OPS {
        if ops.insert(op.name, *op).is_some() {
            return Err(NotImplemented::new(
                "fstp_api_testkit::reference::authz: a repeated operation name",
            ));
        }
    }
    Ok(AuthzReference { ops, flipped: None })
}
