//! Roles, bindings over time and separation of duties (design section 2.6, I-01, I-02, I-04, I-06).
//!
//! Owned by lane L-SOD (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/roles-and-sod.md` and
//! `SPEC/03-architecture/overview.md` NOTE 1 to 6.
//!
//! - [`RosterState`] holds the bindings that count: held ones (active or
//!   suspended) and voided ones. An ended binding of Drafting, Judging or
//!   Receiving moves to the ended part with its pinned cooling-off bar,
//!   one bar per binding. Voiding an ended Receiving binding drops its bar
//!   (Identity discovery). The bar of an account, programme and group is
//!   the largest bar that is not voided.
//! - Each binding keeps its opening: the call's sequence number for a
//!   Receiving binding, and the latest call sequence published at the
//!   grant otherwise. Two bindings of different separated groups break
//!   I-01 together exactly when each opening is at most the other's bar,
//!   a held binding having no bar. So no ledger position is needed.
//! - Cooling-off is one comparison (Cooling-off section). An end pins the
//!   bar: the latest call sequence published in the programme, plus P-12,
//!   both read before the end record in ledger order. A Receiving binding
//!   in call `c` is refused while `c.seq <= bar`. A Drafting or Judging
//!   binding is refused while the latest published sequence is at most
//!   the bar. P-12 = 0 is allowed.
//! - [`guards`] holds the account-level rules (SoD-01, SoD-02, SoD-03,
//!   SoD-05) and the candidate sets of the identity questions (I-06,
//!   SoD-09, overview NOTE 1).
//! - [`commands`] holds the engine entry points: `GrantRole`, `EndRole`,
//!   `ReinstateBinding` and `VaultChanged`, and this lane's contribution to
//!   other lanes' batches. It writes the Receiving bindings of
//!   `CreateDraft`, `AddTeamMember` and `AddGuardian`, ends them when the
//!   proposal reaches a terminal state, and voids them after a P-13 edit.
//!
//! Readings of this lane, each from the current spec text:
//!
//! - A person is a tenant account, except for I-06 (NOTE 3).
//! - Voided bindings never count as held, past bindings included, and pin
//!   no bar. Suspended bindings are inactive for every action but still
//!   count as held, for I-04 and I-06 too.
//! - SoD-02 and I-02 concern roles held now (NOTE 4).
//! - Identity discovery voids only the discovered account's Receiving
//!   bindings, held and ended ones. The other account's Drafting or
//!   Judging binding stays (strict reading of open point O-53, as the spec
//!   text says). When the vault finds both an exclusion and a shared
//!   identity, the void names I-06, so the R-CF-04 fact is kept.
//! - A shared verified identity behind a Drafting and a Judging binding is
//!   another new violation under enforcement point 3. The reaction
//!   suspends each such held binding. Suspension does not restore I-06,
//!   which is an open question for Daniel.
//! - An end earlier or later than `ctx.now` is refused. A later end could
//!   not pin its bar, because the calls published before it are unknown
//!   when the command is decided. Scheduled ends are an open question for
//!   Daniel. A start before `ctx.now` is refused (no backdating).

pub(crate) mod commands;
pub(crate) mod guards;

use std::collections::BTreeMap;

use crate::id::{AccountId, BindingId, CallId, ProgrammeId, ProposalId};
use crate::refusal::RuleRef;
use crate::time::Timestamp;

pub(crate) use commands::{
    apply, contribute, contribute_queries, decide, governing_policy, queries,
};

/// The four role groups of `SPEC/02-domain/roles-and-sod.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// Programme manager and call drafter.
    Drafting,
    /// FSTP coordinator, committee member and chair, IRC member.
    Judging,
    /// Applicant, applicant team member and guardian.
    Receiving,
    /// Tenant admin, finance approver, payment releaser, contract signatory and auditor.
    Operations,
}

impl Group {
    /// The three groups that I-01 separates, in declaration order.
    pub const SEPARATED: [Group; 3] = [Group::Drafting, Group::Judging, Group::Receiving];

    /// Whether the group is one of the three that I-01 separates.
    pub const fn separated(self) -> bool {
        matches!(self, Group::Drafting | Group::Judging | Group::Receiving)
    }

    /// Whether a binding of the group needs a verified identity (SoD-09).
    pub const fn needs_verification(self) -> bool {
        matches!(self, Group::Drafting | Group::Judging)
    }
}

/// A role a binding can hold, as in the roles table of `SPEC/02-domain/roles-and-sod.md`.
///
/// The assigned reviewer is an assignment over a committee member binding,
/// not a role of its own (design section 2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Programme manager (Drafting).
    ProgrammeManager,
    /// Call drafter (Drafting).
    CallDrafter,
    /// FSTP coordinator (Judging).
    FstpCoordinator,
    /// Committee member (Judging).
    CommitteeMember,
    /// Committee chair (Judging).
    CommitteeChair,
    /// IRC member (Judging).
    IrcMember,
    /// Applicant, the lead of a proposal (Receiving).
    Applicant,
    /// Applicant team member (Receiving).
    ApplicantTeamMember,
    /// Guardian of a minor applicant (Receiving).
    Guardian,
    /// Tenant admin (Operations).
    TenantAdmin,
    /// Finance approver (Operations).
    FinanceApprover,
    /// Payment releaser (Operations).
    PaymentReleaser,
    /// Contract signatory with signing authority (Operations, decided 2026-10-25).
    ContractSignatory,
    /// Auditor (Operations).
    Auditor,
}

impl Role {
    /// Every role, in the order of the roles table.
    pub const ALL: [Role; 14] = [
        Role::ProgrammeManager,
        Role::CallDrafter,
        Role::FstpCoordinator,
        Role::CommitteeMember,
        Role::CommitteeChair,
        Role::IrcMember,
        Role::Applicant,
        Role::ApplicantTeamMember,
        Role::Guardian,
        Role::TenantAdmin,
        Role::FinanceApprover,
        Role::PaymentReleaser,
        Role::ContractSignatory,
        Role::Auditor,
    ];

    /// The group of the role.
    pub const fn group(self) -> Group {
        match self {
            Role::ProgrammeManager | Role::CallDrafter => Group::Drafting,
            Role::FstpCoordinator
            | Role::CommitteeMember
            | Role::CommitteeChair
            | Role::IrcMember => Group::Judging,
            Role::Applicant | Role::ApplicantTeamMember | Role::Guardian => Group::Receiving,
            Role::TenantAdmin
            | Role::FinanceApprover
            | Role::PaymentReleaser
            | Role::ContractSignatory
            | Role::Auditor => Group::Operations,
        }
    }

    /// Whether the role is a Judging role other than IRC member (SoD-02).
    pub const fn other_judging(self) -> bool {
        matches!(
            self,
            Role::FstpCoordinator | Role::CommitteeMember | Role::CommitteeChair
        )
    }

    /// The role's name as the roles table spells it.
    pub const fn spec_name(self) -> &'static str {
        match self {
            Role::ProgrammeManager => "Programme manager",
            Role::CallDrafter => "Call drafter",
            Role::FstpCoordinator => "FSTP coordinator",
            Role::CommitteeMember => "Committee member",
            Role::CommitteeChair => "Committee chair",
            Role::IrcMember => "IRC member",
            Role::Applicant => "Applicant",
            Role::ApplicantTeamMember => "Applicant team member",
            Role::Guardian => "Guardian",
            Role::TenantAdmin => "Tenant admin",
            Role::FinanceApprover => "Finance approver",
            Role::PaymentReleaser => "Payment releaser",
            Role::ContractSignatory => "Contract signatory",
            Role::Auditor => "Auditor",
        }
    }
}

/// What a binding is scoped to. Receiving bindings are scoped to one
/// proposal and its call; every other binding to the programme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingScope {
    /// The whole programme: Drafting, Judging and Operations roles.
    Programme,
    /// One proposal and its call: Receiving roles (`SPEC/02-domain/roles-and-sod.md` Receiving bindings).
    Proposal {
        /// The proposal.
        proposal: ProposalId,
        /// The call the proposal belongs to.
        call: CallId,
    },
}

/// The P-12 value, counted in calls (P-12 NOTE 4). Zero is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoolingOff(pub u8);

/// Whether a binding acts, is suspended or is voided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingStatus {
    /// The binding acts from its start.
    Active,
    /// Suspended under enforcement point 3. Inactive for every action,
    /// still held for every invariant.
    Suspended(RuleRef),
    /// Voided under Identity discovery. Never held, and it pins no bar.
    Voided(RuleRef),
}

/// One binding of the roster: held, or voided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Binding {
    /// The account.
    pub account: AccountId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The role.
    pub role: Role,
    /// The scope.
    pub scope: BindingScope,
    /// The start.
    pub start: Timestamp,
    /// The opening of the cooling-off comparison: the call's sequence
    /// number for a Receiving binding, and the latest call sequence
    /// published in the programme at the grant otherwise.
    pub opened: u32,
    /// Active, suspended or voided.
    pub status: BindingStatus,
}

impl Binding {
    /// The group of the role.
    pub const fn group(&self) -> Group {
        self.role.group()
    }

    /// Whether the binding counts as held: not voided. Ended bindings are
    /// not in the roster at all.
    pub const fn held(&self) -> bool {
        !matches!(self.status, BindingStatus::Voided(_))
    }

    /// Whether the binding is active at `t`: started, held and not
    /// suspended (design section 3.6).
    pub fn active_at(&self, t: Timestamp) -> bool {
        matches!(self.status, BindingStatus::Active) && self.start <= t
    }

    /// The proposal of a Receiving binding.
    pub const fn proposal(&self) -> Option<ProposalId> {
        match self.scope {
            BindingScope::Programme => None,
            BindingScope::Proposal { proposal, .. } => Some(proposal),
        }
    }

    /// The call of a Receiving binding.
    pub const fn call(&self) -> Option<CallId> {
        match self.scope {
            BindingScope::Programme => None,
            BindingScope::Proposal { call, .. } => Some(call),
        }
    }
}

/// An ended binding of Drafting, Judging or Receiving, kept for its bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndedBinding {
    /// The binding as it was at its end, or voided after it.
    pub binding: Binding,
    /// The bar its end pinned (Cooling-off section).
    pub bar: u32,
}

impl EndedBinding {
    /// The bar, unless the binding was voided after its end. A voided
    /// binding pins no bar (Identity discovery).
    pub const fn live_bar(&self) -> Option<u32> {
        match self.binding.status {
            BindingStatus::Voided(_) => None,
            BindingStatus::Active | BindingStatus::Suspended(_) => Some(self.bar),
        }
    }
}

/// Roster part of the projection: bindings and cooling-off bars.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RosterState {
    /// Held and voided bindings. An ended binding leaves.
    bindings: BTreeMap<BindingId, Binding>,
    /// Ended bindings of the three groups that I-01 separates, each with
    /// its bar.
    ended: BTreeMap<BindingId, EndedBinding>,
}

impl RosterState {
    /// The roster before any record.
    pub(crate) const fn genesis() -> RosterState {
        RosterState {
            bindings: BTreeMap::new(),
            ended: BTreeMap::new(),
        }
    }

    /// The binding `id`, when it is held or voided.
    pub fn binding(&self, id: BindingId) -> Option<&Binding> {
        self.bindings.get(&id)
    }

    /// Every held or voided binding, by id.
    pub fn bindings(&self) -> impl Iterator<Item = (BindingId, &Binding)> {
        self.bindings.iter().map(|(id, b)| (*id, b))
    }

    /// Every ended binding of Drafting, Judging or Receiving, by id.
    pub fn ended(&self) -> impl Iterator<Item = (BindingId, &EndedBinding)> {
        self.ended.iter().map(|(id, e)| (*id, e))
    }

    /// The largest cooling-off bar pinned for `account` in `programme` and
    /// `group` by a binding that ended there and was not voided.
    pub fn bar(&self, programme: ProgrammeId, account: AccountId, group: Group) -> Option<u32> {
        self.bars()
            .filter(|(p, a, g, _)| *p == programme && *a == account && *g == group)
            .map(|(_, _, _, bar)| bar)
            .max()
    }

    /// Every bar that is not voided, one per ended binding: programme,
    /// account, group and bar.
    pub fn bars(&self) -> impl Iterator<Item = (ProgrammeId, AccountId, Group, u32)> + '_ {
        self.ended.values().filter_map(|e| {
            e.live_bar().map(|bar| {
                (
                    e.binding.programme,
                    e.binding.account,
                    e.binding.group(),
                    bar,
                )
            })
        })
    }

    /// The binding of `role` that `account` holds in `programme` and that is
    /// active at `now`: started, not ended, not suspended and not voided (design section 3.6).
    /// Other lanes read the roster only through queries like this one.
    pub(crate) fn active_binding(
        &self,
        account: AccountId,
        role: Role,
        programme: ProgrammeId,
        now: Timestamp,
    ) -> Option<BindingId> {
        self.bindings
            .iter()
            .find(|(_, b)| {
                b.account == account
                    && b.role == role
                    && b.programme == programme
                    && b.active_at(now)
            })
            .map(|(id, _)| *id)
    }

    /// The binding of `role` that `account` holds on `proposal` and that is
    /// active at `now` (enforcement point 2).
    pub(crate) fn active_receiving(
        &self,
        account: AccountId,
        role: Role,
        proposal: ProposalId,
        now: Timestamp,
    ) -> Option<BindingId> {
        self.bindings
            .iter()
            .find(|(_, b)| {
                b.account == account
                    && b.role == role
                    && b.proposal() == Some(proposal)
                    && b.active_at(now)
            })
            .map(|(id, _)| *id)
    }

    /// Whether `account` was ever bound to `proposal`, voided and ended
    /// bindings included.
    pub(crate) fn bound_to(&self, account: AccountId, proposal: ProposalId) -> bool {
        self.bindings
            .values()
            .chain(self.ended.values().map(|e| &e.binding))
            .any(|b| b.account == account && b.proposal() == Some(proposal))
    }

    /// The accounts holding a Receiving binding on `proposal` now: the
    /// lead, team members and guardians, voided bindings excluded. Lane
    /// L-REV reads it for the `HasConflict` team.
    #[allow(dead_code, reason = "lanes L-REV and L-MONEY call it")]
    pub(crate) fn receiving_accounts(
        &self,
        proposal: ProposalId,
    ) -> std::collections::BTreeSet<AccountId> {
        self.bindings
            .values()
            .filter(|b| b.held() && b.proposal() == Some(proposal))
            .map(|b| b.account)
            .collect()
    }

    /// The Receiving bindings voided under I-06, held or ended at the void:
    /// binding, account and proposal. Each is an identity discovery. The
    /// scores that a matching Judging account already gave on that proposal
    /// get a notifiable conflict (R-CF-04, Identity discovery), which lane
    /// L-REV records from this fact.
    #[allow(dead_code, reason = "lane L-REV calls it")]
    pub(crate) fn identity_discoveries(
        &self,
    ) -> impl Iterator<Item = (BindingId, AccountId, ProposalId)> + '_ {
        self.bindings
            .iter()
            .chain(self.ended.iter().map(|(id, e)| (id, &e.binding)))
            .filter_map(|(id, b)| match b.status {
                BindingStatus::Voided(RuleRef::I06) => b.proposal().map(|p| (*id, b.account, p)),
                _ => None,
            })
    }
}
