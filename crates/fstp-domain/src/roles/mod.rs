//! Roles, bindings over time and separation of duties (design section 2.6, I-01, I-02, I-04, I-06).
//!
//! Owned by lane L-SOD (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/roles-and-sod.md` and
//! `SPEC/03-architecture/overview.md` NOTE 1 to 6.
//!
//! - [`RosterState`] holds the bindings that are not ended: active,
//!   suspended and voided ones. An ended binding of Drafting, Judging or
//!   Receiving moves to the ended part with its pinned cooling-off bar,
//!   one bar per binding. Voiding an ended Receiving binding, or suspending
//!   an ended Judging binding as a conflict of interest, drops its bar
//!   (Identity discovery). The bar of an account, programme and group is
//!   the largest bar that still counts.
//! - Each binding keeps its opening: the call's sequence number for a
//!   Receiving binding, and the latest call sequence published at the
//!   grant otherwise. Two bindings of different separated groups break
//!   I-01 together exactly when each opening is at most the other's bar,
//!   a held binding having no bar. So I-01 needs no ledger position.
//! - The roster also keeps a fold position for each Judging grant and end.
//!   An open binding and an ended one were held at the same time exactly
//!   when the end folded after the grant. Only the reinstatement of a
//!   conflict-of-interest suspension reads it, for I-02.
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
//!   no bar. Suspended bindings are inactive for every action. A
//!   conflict-of-interest suspension never counts as held either, past
//!   bindings included, and pins no bar. Every other suspended binding
//!   still counts as held, for I-04 and I-06 too (enforcement points NOTE).
//! - The conflict-of-interest marker is a `BindingSuspended` with rule I-06
//!   on a Judging binding. The record shape has no other field for it. Rule
//!   I-06 on a Drafting or Receiving binding is an ordinary suspension, and
//!   this lane never writes one.
//! - SoD-02 and I-02 concern roles held now (NOTE 4).
//! - Identity discovery voids only the discovered account's Receiving
//!   bindings, held and ended ones. The other account's Drafting or
//!   Judging binding stays (strict reading of open point O-53, as the spec
//!   text says). When the vault finds both an exclusion and a shared
//!   identity, the void names I-06, so the R-CF-04 fact is kept.
//! - A shared verified identity behind a Drafting and a Judging binding
//!   arises only from a later identity merge, since SoD-09 refuses it at
//!   binding time. The reaction suspends the Judging binding as a conflict
//!   of interest, in the same step, and the Drafting binding stays
//!   (Identity discovery, decided 2026-10-25). An ended Judging binding
//!   whose bar still breaks I-01 with the Drafting binding is suspended
//!   too, or I-06 would stay broken through that bar.
//! - A conflict-of-interest suspension can still be ended, and its bar
//!   never counts. Its reinstatement is refused while the binding, counted
//!   again, would break I-01 or I-02 for its own account, or I-06 with an
//!   account of its verified identity. Bindings held at the same time break
//!   I-01 forever, so the clash lasts until the vault splits the identities.
//! - Counted again, a reinstated conflict-of-interest suspension counts
//!   over the suspension period too. So its reinstatement is also refused
//!   under I-02 when an IRC binding, or another Judging binding, of its own
//!   account was held beside it, even one that has ended since. Otherwise
//!   the history would show both held at the same time.
//! - A conflict-of-interest suspension and an ordinary suspension of one
//!   binding are kept apart. The marker can land on an ordinarily
//!   suspended binding, and an ordinary suspension can land under the
//!   marker. Reinstating the conflict of interest then falls back to the
//!   ordinary suspension, which stays pending resolution (enforcement
//!   point 3). One `ReinstateBinding` lifts one suspension, the conflict of
//!   interest first.
//! - The roster keeps every identity discovery it folds, in ledger order,
//!   with the vault epoch of its record. A reinstatement or an end never
//!   erases one (R-CF-04).
//! - An end earlier than `ctx.now` is refused, and so is a start (no
//!   backdating). A later end is a scheduled end (Cooling-off NOTE,
//!   decided 2026-10-25), set by `EndRole` or by the `end` of `GrantRole`.
//!   The binding stays held until the instant. The System records its end
//!   through `EndScheduledRole`, which [`crate::due`] lists from the
//!   instant on. That end carries the scheduled instant and pins the bar
//!   when it is recorded. From the instant until that record, the engine
//!   refuses every other command but `VaultChanged` under SoD-05. So no
//!   decision reads the binding as held after its instant, no call is
//!   published and no P-12 is edited in between, and the bar counts the
//!   calls published by the instant and the P-12 value in force at it. A
//!   scheduled end can be brought forward, to `ctx.now` too, which ends
//!   the binding at once. Moving it later is refused, and so is scheduling
//!   the same instant again or an instant at or before the start.

pub(crate) mod commands;
pub(crate) mod guards;

use std::collections::BTreeMap;

use crate::id::{
    AccountId, BindingId, CallId, OrganisationId, ProgrammeId, ProposalId, VaultEpoch,
};
use crate::refusal::RuleRef;
use crate::time::Timestamp;

pub(crate) use commands::{
    apply, contribute, contribute_queries, decide, due, end_overdue, governing_policy, queries,
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
    /// Suspended under enforcement point 3. Inactive for every action.
    /// Rule I-06 on a Judging binding marks a conflict-of-interest
    /// suspension, which never counts as held. Every other suspension is
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
    /// The rule of an ordinary suspension that lies under a
    /// conflict-of-interest suspension, if any. It is `None` whenever the
    /// binding is not under a conflict-of-interest suspension. Reinstating
    /// the conflict of interest restores `Suspended` with this rule.
    pub suspended_beneath: Option<RuleRef>,
    /// The roster fold position of the grant of a Judging binding
    /// (`RosterState::tick`), and 0 for every other group.
    pub granted: u64,
    /// The organisation the grant records, for committee bindings (I-34,
    /// SoD-10).
    pub organisation: Option<OrganisationId>,
    /// The scheduled end instant, if any (Cooling-off NOTE, decided
    /// 2026-10-25). The binding stays held until that instant. The System
    /// records its end, which [`crate::due`] lists from that instant on,
    /// and the engine decides no other command but `VaultChanged` until
    /// the end is recorded.
    pub scheduled_end: Option<Timestamp>,
}

impl Binding {
    /// The group of the role.
    pub const fn group(&self) -> Group {
        self.role.group()
    }

    /// Whether the binding counts as held: neither voided nor under a
    /// conflict-of-interest suspension. Ended bindings are not in the
    /// roster at all. Every other suspended binding still counts.
    pub const fn held(&self) -> bool {
        !self.voided() && !self.conflict_of_interest()
    }

    /// Whether the binding was voided under Identity discovery.
    pub const fn voided(&self) -> bool {
        matches!(self.status, BindingStatus::Voided(_))
    }

    /// Whether the binding is under a conflict-of-interest suspension: a
    /// Judging binding suspended under I-06 (Identity discovery, decided
    /// 2026-10-25). Such a binding never counts, held or past, and pins no bar.
    pub const fn conflict_of_interest(&self) -> bool {
        matches!(self.status, BindingStatus::Suspended(RuleRef::I06))
            && matches!(self.role.group(), Group::Judging)
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
    /// The roster fold position of the end of a Judging binding
    /// (`RosterState::tick`), and 0 for every other group. It is larger
    /// than the grant position of every Judging binding open beside it.
    pub ended: u64,
}

impl EndedBinding {
    /// The bar, unless the binding was voided, or suspended as a conflict
    /// of interest, before or after its end. Neither pins a bar (Identity
    /// discovery).
    pub const fn live_bar(&self) -> Option<u32> {
        if self.binding.held() {
            Some(self.bar)
        } else {
            None
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
    /// Every identity discovery folded so far, in ledger order. Kept for
    /// good: a reinstatement or an end does not erase one.
    discoveries: Vec<IdentityDiscovery>,
    /// The number of Judging grants and ends folded so far.
    clock: u64,
}

impl RosterState {
    /// The roster before any record.
    pub(crate) const fn genesis() -> RosterState {
        RosterState {
            bindings: BTreeMap::new(),
            ended: BTreeMap::new(),
            discoveries: Vec::new(),
            clock: 0,
        }
    }

    /// The next fold position, for the grant or end of a Judging binding.
    /// Positions grow with ledger order, so they order those grants and
    /// ends. Only I-02 reads them, and it concerns Judging roles alone.
    /// Other groups take no position, so the order of their records adds
    /// no state.
    pub(crate) fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    /// Records one identity discovery, in ledger order.
    pub(crate) fn discovered(&mut self, d: IdentityDiscovery) {
        self.discoveries.push(d);
    }

    /// The binding `id`, when it is held or voided.
    pub fn binding(&self, id: BindingId) -> Option<&Binding> {
        self.bindings.get(&id)
    }

    /// The binding `id`, when it is held, voided or ended. An ended
    /// binding keeps its last state beneath the end (R-CF-04).
    pub fn held_or_ended(&self, id: BindingId) -> Option<&Binding> {
        self.bindings
            .get(&id)
            .or_else(|| self.ended.get(&id).map(|e| &e.binding))
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
    /// `group` by a binding that ended there and still counts.
    pub fn bar(&self, programme: ProgrammeId, account: AccountId, group: Group) -> Option<u32> {
        self.bars()
            .filter(|(p, a, g, _)| *p == programme && *a == account && *g == group)
            .map(|(_, _, _, bar)| bar)
            .max()
    }

    /// Every bar that still counts, one per ended binding: programme,
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

    /// Every identity discovery the roster has folded, in ledger order
    /// (Identity discovery). Each is a `BindingVoided` with rule I-06, or a
    /// conflict-of-interest marker, with the vault epoch of its record.
    ///
    /// The list is permanent. A later reinstatement or end of the binding
    /// does not remove its entry, so a reader after the reaction batch still
    /// sees it. A binding suspended, reinstated and suspended again appears
    /// twice, once per epoch. Lane L-REV records the R-CF-04 notifiable
    /// conflicts from these facts, and releases the open assignments of a
    /// conflict-of-interest suspension. Entries at an epoch it already
    /// handled are old ones.
    pub fn identity_discoveries(&self) -> impl Iterator<Item = IdentityDiscovery> + '_ {
        self.discoveries.iter().copied()
    }
}

/// One identity discovery of the roster (`SPEC/02-domain/roles-and-sod.md`, Identity discovery).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentityDiscovery {
    /// A Receiving binding voided under I-06, held or ended at the void.
    /// The scores that a matching Judging account already gave on the
    /// proposal get a notifiable conflict (R-CF-04).
    ReceivingVoided {
        /// The voided binding.
        binding: BindingId,
        /// The discovered account.
        account: AccountId,
        /// The proposal of the binding.
        proposal: ProposalId,
        /// The vault epoch the `BindingVoided` record carries.
        epoch: VaultEpoch,
    },
    /// A Judging binding suspended as a conflict of interest, held or ended
    /// at the suspension (decided 2026-10-25). The account's open
    /// assignments under it are released. The scores it already gave in
    /// the programme get a notifiable conflict (R-CF-04).
    ConflictOfInterest {
        /// The suspended Judging binding.
        binding: BindingId,
        /// The suspended account.
        account: AccountId,
        /// The programme of the binding.
        programme: ProgrammeId,
        /// The Judging role of the binding.
        role: Role,
        /// The vault epoch the `BindingSuspended` record carries.
        epoch: VaultEpoch,
    },
}

impl IdentityDiscovery {
    /// The binding the discovery voided or suspended.
    pub const fn binding(&self) -> BindingId {
        match self {
            IdentityDiscovery::ReceivingVoided { binding, .. }
            | IdentityDiscovery::ConflictOfInterest { binding, .. } => *binding,
        }
    }

    /// The account of that binding.
    pub const fn account(&self) -> AccountId {
        match self {
            IdentityDiscovery::ReceivingVoided { account, .. }
            | IdentityDiscovery::ConflictOfInterest { account, .. } => *account,
        }
    }

    /// The vault epoch of the discovery's record.
    pub const fn epoch(&self) -> VaultEpoch {
        match self {
            IdentityDiscovery::ReceivingVoided { epoch, .. }
            | IdentityDiscovery::ConflictOfInterest { epoch, .. } => *epoch,
        }
    }
}
