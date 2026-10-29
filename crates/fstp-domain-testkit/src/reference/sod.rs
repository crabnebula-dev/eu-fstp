//! Independent reference for roles and separation of duties (design sections 2.6, 3.4, 4.2 and 6.1).
//!
//! Written from `SPEC/02-domain/roles-and-sod.md`, `SPEC/02-domain/invariants.md`
//! (I-01, I-02, I-04, I-06) and `SPEC/03-architecture/overview.md` NOTE 1 to 6.
//! It shares only id, command and record types with production. It never
//! calls a production guard, `Role::group` included.
//!
//! - [`View`] is the reference's own fold of core records. It keeps every
//!   binding with its interval in call-sequence terms: the latest published
//!   call at its start, and at its end the latest published call, the P-12
//!   value and the bar the reference computes itself.
//! - [`check_i01`], [`check_i02`], [`check_i04`] and [`check_i06`] are the
//!   invariant predicates. They read a [`View`] and the vault's ground truth.
//! - [`verdict`] says whether a role command must be accepted or refused.
//!   [`expected_binding`], [`expected_end`] and [`expected_voids`] say what an
//!   accepted command must record.
//!
//! # Readings
//!
//! Each reading below is the strictest one the spec text allows. Where the
//! spec is silent, the reading is marked as a test-author choice, so the
//! implementer can match it or raise it with Daniel.
//!
//! - A person is a tenant account, except for I-06 (NOTE 3).
//! - Cooling-off is one comparison (Cooling-off section). When a binding
//!   of Drafting, Judging or Receiving ends, its bar is the latest call
//!   sequence published in the programme at the end, plus P-12 at the end.
//!   "At the end" means before the end record in ledger order, so a call
//!   published by a later command at the same instant is not covered.
//!   A Receiving binding in call `c` is refused while `c.seq <= bar`. A
//!   Drafting or Judging binding is refused while the latest published
//!   sequence is at most the bar. P-12 = 0 is allowed.
//! - Two bindings of different groups among Drafting, Judging and
//!   Receiving that were held at the same time break I-01 forever, as do a
//!   binding and a later binding inside its bar.
//! - Voided bindings never count as held, past bindings included, and pin
//!   no bar. A conflict-of-interest suspension counts the same way (decided
//!   2026-10-25). Every other suspended binding still counts as held, for
//!   I-04 and I-06 too (enforcement points NOTE).
//! - The conflict-of-interest marker: a `BindingSuspended` with rule I-06
//!   on a Judging binding. The record shape has no other field for it. A
//!   `BindingSuspended` with rule I-06 on a Drafting or Receiving binding
//!   is an ordinary suspension and still counts as held.
//! - SoD-02 and I-02 concern roles held now (NOTE 4). An IRC binding and
//!   another Judging binding (FSTP coordinator, committee member or
//!   committee chair) of one account must never be held at the same time.
//! - SoD-03: an Operations binding and a Receiving binding of one account in
//!   one programme are never held at the same time. A tenant admin at tenant
//!   scope counts as holding an Operations role (`Ctx::binds_tenant_admin`).
//!   No cooling-off applies to Operations.
//! - SoD-07: a tenant admin granting a role to their own account needs
//!   `second_admin` to name the second tenant admin the shell attested in
//!   `Ctx::second_tenant_admin`, and that admin differs from the actor.
//! - SoD-09: a Drafting or Judging grant needs the account verified. The
//!   grant is refused when another verified account of the same identity
//!   holds a binding of another group among Drafting, Judging and Receiving,
//!   or holds an ended one whose bar still bars the new group (NOTE 1).
//! - Receiving bindings arise only from `CreateDraft`, `AddTeamMember` and
//!   `AddGuardian`. `GrantRole` of a Receiving role and `EndRole` of a
//!   Receiving binding are refused. They are scoped to the proposal and its
//!   call. A draft needs a published call, so its sequence number exists.
//! - At a Receiving binding the platform refuses an account in an excluded
//!   class of the call's effective P-13: the union of the call's snapshot and
//!   the live value (P-13 NOTE 7). It also refuses, under I-06, a verified
//!   account whose verified identity is also behind another account holding
//!   a Drafting or Judging binding, or an ended one whose bar covers the call.
//! - Test-author choices where the spec is silent:
//!   - An account holds at most one Receiving binding per proposal. Adding
//!     the lead, or an account already added, is refused.
//!   - A guardian is added only to a minor-flagged proposal. The flag is
//!     derived, never read from the actor's `CreateDraft` field (R-ID-04
//!     Derivation note). Every proposal is minor-flagged until its
//!     IRC_REVIEW to NEGOTIATION gate. It stays flagged unless the vault's
//!     ground truth shows an effective verified over-18 attestation of the
//!     lead at the deadline of the created call when the gate passes
//!     (state-machine NOTE 14, ADR-008 "Which deadline", interim). The
//!     reference reads the vault facts, never production's `VaultOutcome`
//!     records, so it judges both backends alike ([`View::fold_with`]).
//!   - Drafting and Judging grants need accepted confidentiality terms
//!     (Confidentiality on binding). Operations grants never need them.
//!   - A committee member grant needs the reviewer's organisation, since
//!     SoD-10 and I-34 count organisations from it (roles-and-sod.md,
//!     Reviewer assignment, decided 2026-10-25). For other roles the field
//!     is data only.
//!   - A reviewer has one organisation per programme (SoD-10, decided
//!     2026-10-28). A committee member grant that records an organisation
//!     other than the one of a held committee binding of the account in
//!     the programme, whatever its period, is refused (W7 fix round 2).
//!     The reinstatement of a conflict-of-interest suspension is refused the
//!     same way.
//!   - A start before `now` is backdating and refused. A later start is
//!     accepted. An end before `now` is backdating and refused. An end at
//!     `now` ends the binding at once.
//! - Scheduled ends (Cooling-off NOTE, decided 2026-10-25). An end may be
//!   scheduled for a later instant, when the role is granted or afterwards.
//!   The binding stays held until that instant. Its bar is pinned then,
//!   from the calls published by that instant and the P-12 value in force
//!   at it. A scheduled end can be brought forward, never moved earlier
//!   than the current time. The reference reads it as follows.
//!   - `EndRole` with `at` after `now` schedules the end. With a scheduled
//!     end already set, an earlier `at` brings it forward and is accepted.
//!     A later one moves it later and is refused. The same instant is
//!     unjudged. An `EndRole` at `now` ends the binding at once, a
//!     scheduled one too. A scheduled end at or before the start is
//!     refused.
//!   - `GrantRole` may carry an `end` member. It must lie after the start.
//!   - The scheduled end is the record whose JSON type is
//!     `BindingEndScheduled`, with the members `binding` and `at`. The
//!     reference reads it from its JSON form, since the stub interface does
//!     not declare it yet. The `end` member of `GrantRole` is read the same way.
//!   - The binding stays open until its `BindingEnded`. The System records
//!     that end at the instant, through a command that `due` lists then
//!     ([`due_ends`]). The end record carries the scheduled instant, and
//!     the bar of the calls published by then and the P-12 value then.
//!   - Test-author reading of W7 fix round 1: from a scheduled instant
//!     until the System records the end, every account command is
//!     refused under SoD-05. So no command reads the binding as held after
//!     its instant, and the end reads the calls and P-12 of the instant.
//!   - The lead of a proposal acts only while its Applicant binding on that
//!     proposal is held (enforcement point 2).
//! - Identity discovery: the reaction to a vault change voids, in the same
//!   batch, every held Receiving binding that breaks I-04 or I-06 under the
//!   facts the reaction sees. It also voids every ended Receiving binding
//!   that breaks I-06 through its bar, since voided bindings never count,
//!   past ones included. A binding that breaks I-06 is voided under I-06,
//!   so the R-CF-04 fact is kept. A P-13 edit that adds a class voids every
//!   held Receiving binding now in an excluded class. The Drafting or
//!   Judging side stays bound (O-53 strict reading).
//! - Conflict of interest (Identity discovery, last paragraph, decided
//!   2026-10-25): the same reaction suspends every Judging binding that
//!   breaks I-01 with a Drafting binding of another account of the same
//!   verified identity. It writes `BindingSuspended` with rule I-06 on the
//!   Judging binding only. The Drafting binding stays, unsuspended.
//! - Test-author choices for the conflict of interest, where the spec is silent:
//!   - An ended Judging binding whose pair rule with the Drafting binding
//!     still holds is suspended too, held or past. Otherwise I-06 would
//!     stay broken through its bar.
//!   - Voids and suspensions of one reaction are each judged over the
//!     bindings that count before the reaction.
//!   - `EndRole` of a binding under a conflict-of-interest suspension is
//!     accepted. The bar its end pins never counts.
//!   - `ReinstateBinding` of such a binding is refused while the binding,
//!     counted again, would break I-01, I-02 or I-06 with the bindings
//!     that count. Two bindings held at the same time break I-01 forever,
//!     so the clash lasts while the two accounts share a verified identity.
//!     Who may reinstate is unspecified, so the reference judges nothing else.
//!   - A conflict-of-interest suspension and an ordinary suspension of one
//!     binding are kept apart. One reinstatement lifts one of them, the
//!     conflict of interest first, so an ordinary suspension still pending
//!     resolution survives it (enforcement point 3).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{
    AccountId, BindingId, CallId, ClassId, OrganisationId, PolicyVersionId, ProgrammeId,
    ProposalId, VaultEpoch,
};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;

use crate::vault::{GroundTruth, IdentityTag};

// ---------------------------------------------------------------------------
// Groups, from the roles table
// ---------------------------------------------------------------------------

/// The four role groups of the roles table, kept apart from production's `Group`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefGroup {
    /// Programme manager and call drafter.
    Drafting,
    /// FSTP coordinator, committee member, committee chair and IRC member.
    Judging,
    /// Applicant, applicant team member and guardian.
    Receiving,
    /// Tenant admin, finance approver, payment releaser, contract signatory and auditor.
    Operations,
}

impl RefGroup {
    /// Whether the group is one of the three that I-01 separates.
    pub const fn separated(self) -> bool {
        matches!(
            self,
            RefGroup::Drafting | RefGroup::Judging | RefGroup::Receiving
        )
    }

    /// Whether the group needs a verified identity at binding (SoD-09).
    pub const fn needs_verification(self) -> bool {
        matches!(self, RefGroup::Drafting | RefGroup::Judging)
    }
}

/// The group of `role`, as the roles table of `SPEC/02-domain/roles-and-sod.md` lists it.
pub const fn spec_group(role: Role) -> RefGroup {
    match role {
        Role::ProgrammeManager | Role::CallDrafter => RefGroup::Drafting,
        Role::FstpCoordinator | Role::CommitteeMember | Role::CommitteeChair | Role::IrcMember => {
            RefGroup::Judging
        }
        Role::Applicant | Role::ApplicantTeamMember | Role::Guardian => RefGroup::Receiving,
        Role::TenantAdmin
        | Role::FinanceApprover
        | Role::PaymentReleaser
        | Role::ContractSignatory
        | Role::Auditor => RefGroup::Operations,
    }
}

/// Whether `role` is a Judging role other than IRC member (SoD-02).
pub const fn other_judging(role: Role) -> bool {
    matches!(
        role,
        Role::FstpCoordinator | Role::CommitteeMember | Role::CommitteeChair
    )
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// The end of a binding, as the reference computes it, beside what was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefEnd {
    /// The recorded end instant.
    pub at: Timestamp,
    /// The latest call sequence published in the programme before the end record.
    pub latest_at_end: u32,
    /// The P-12 value of the programme head before the end record.
    pub p12_at_end: u8,
    /// The reference bar: `latest_at_end + p12_at_end`.
    pub bar: u32,
    /// The bar the end record carries.
    pub recorded_bar: u32,
    /// The P-12 value the end record carries.
    pub recorded_p12: u8,
}

/// One binding as the reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefBinding {
    /// The binding.
    pub binding: BindingId,
    /// The account.
    pub account: AccountId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The role.
    pub role: Role,
    /// The group, from [`spec_group`].
    pub group: RefGroup,
    /// The proposal of a Receiving binding.
    pub proposal: Option<ProposalId>,
    /// The call of a Receiving binding.
    pub call: Option<CallId>,
    /// The call's sequence number, when the call was published at the binding.
    pub call_seq: Option<u32>,
    /// The recorded start.
    pub start: Timestamp,
    /// The latest call sequence published in the programme before the grant record.
    pub latest_at_start: u32,
    /// Who the record says granted it.
    pub granted_by: AccountId,
    /// Whether the record carries the vault epoch of a SoD-09 answer.
    pub verified_epoch: Option<VaultEpoch>,
    /// The organisation the record carries, for committee bindings (SoD-10).
    pub organisation: Option<OrganisationId>,
    /// The end, once recorded.
    pub end: Option<RefEnd>,
    /// The scheduled end instant, while the binding is open (Cooling-off
    /// NOTE, decided 2026-10-25).
    pub scheduled_end: Option<Timestamp>,
    /// Whether the binding is suspended now, for any reason.
    pub suspended: bool,
    /// Whether the suspension is a conflict-of-interest suspension: a
    /// `BindingSuspended` with rule I-06 on a Judging binding (Identity
    /// discovery, decided 2026-10-25). Such a binding never counts.
    pub conflict_of_interest: bool,
    /// Whether an ordinary suspension is pending, beside or beneath a
    /// conflict-of-interest suspension. Reinstating the conflict of
    /// interest leaves it in place (enforcement point 3).
    pub ordinary_suspension: bool,
    /// The rule of the void, once voided.
    pub voided: Option<RuleRef>,
}

impl RefBinding {
    /// Whether the binding counts for I-01, I-02 and I-06 at all, held or
    /// past: neither voided nor under a conflict-of-interest suspension.
    pub fn counts(&self) -> bool {
        self.voided.is_none() && !self.conflict_of_interest
    }

    /// Whether the binding is still open: not ended and not voided. An open
    /// binding can be ended, even under a conflict-of-interest suspension.
    pub fn open(&self) -> bool {
        self.end.is_none() && self.voided.is_none()
    }

    /// Whether the binding counts as held now: open and counted. Ordinary
    /// suspended bindings still count as held. A conflict-of-interest
    /// suspension never does.
    pub fn held(&self) -> bool {
        self.open() && self.counts()
    }

    /// Whether the binding is active for every action: held and not suspended.
    pub fn active(&self) -> bool {
        self.held() && !self.suspended
    }

    /// The bar of an ended, counted binding of a separated group. A voided
    /// binding and a conflict-of-interest suspension pin no bar.
    pub fn bar(&self) -> Option<u32> {
        if !self.counts() || !self.group.separated() {
            return None;
        }
        self.end.map(|e| e.bar)
    }
}

/// A call as the reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefCall {
    /// Its programme.
    pub programme: ProgrammeId,
    /// Its sequence number, once published.
    pub seq: Option<u32>,
    /// The P-13 value of the version it froze, once published.
    pub snapshot_p13: Option<BTreeSet<ClassId>>,
    /// Its deadline, the instant the lead's age counts at (R-ID-04).
    pub deadline: Timestamp,
}

/// A proposal as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefProposal {
    /// Its call.
    pub call: CallId,
    /// Its lead.
    pub lead: AccountId,
    /// Whether, when its IRC_REVIEW to NEGOTIATION gate passed, the vault
    /// facts showed an effective verified over-18 attestation of the lead
    /// at the deadline of its call (R-ID-04, NOTE 14). `false` before the
    /// gate, so the proposal is minor-flagged.
    pub adult_at_gate: bool,
}

impl RefProposal {
    /// Whether the proposal is minor-flagged (R-ID-04, NOTE 14).
    pub fn minor_flagged(&self) -> bool {
        !self.adult_at_gate
    }
}

/// The live values of one policy version that SoD reads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefVersion {
    /// The programme.
    pub programme: ProgrammeId,
    /// P-12.
    pub p12: u8,
    /// P-13.
    pub p13: BTreeSet<ClassId>,
}

/// The reference's fold of core records.
///
/// It is a value with no history positions, so two histories that reach the
/// same situation give equal views. Overlap and order between bindings are
/// kept as unordered pairs and as "granted after the end of" pairs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct View {
    /// Programmes created.
    pub programmes: BTreeSet<ProgrammeId>,
    /// Policy versions recorded.
    pub versions: BTreeMap<PolicyVersionId, RefVersion>,
    /// The head version of each programme: the last one recorded.
    pub heads: BTreeMap<ProgrammeId, PolicyVersionId>,
    /// Calls drafted.
    pub calls: BTreeMap<CallId, RefCall>,
    /// The latest published call sequence of each programme.
    pub latest: BTreeMap<ProgrammeId, u32>,
    /// Every binding ever recorded.
    pub bindings: BTreeMap<BindingId, RefBinding>,
    /// Pairs of bindings held at the same time, smaller id first.
    pub overlaps: BTreeSet<(BindingId, BindingId)>,
    /// Pairs `(ended, later)`: `later` was granted after `ended` ended.
    pub after_end: BTreeSet<(BindingId, BindingId)>,
    /// Proposals created.
    pub proposals: BTreeMap<ProposalId, RefProposal>,
    /// Conflicts the vault detected, by account and proposal.
    pub detected: BTreeSet<(AccountId, ProposalId)>,
    /// The last vault epoch processed.
    pub epoch: VaultEpoch,
}

impl Default for View {
    fn default() -> View {
        View::new()
    }
}

impl View {
    /// The view of an empty ledger.
    pub fn new() -> View {
        View {
            programmes: BTreeSet::new(),
            versions: BTreeMap::new(),
            heads: BTreeMap::new(),
            calls: BTreeMap::new(),
            latest: BTreeMap::new(),
            bindings: BTreeMap::new(),
            overlaps: BTreeSet::new(),
            after_end: BTreeSet::new(),
            proposals: BTreeMap::new(),
            detected: BTreeSet::new(),
            epoch: VaultEpoch::GENESIS,
        }
    }

    /// The view of `records`, folded in order.
    pub fn of<'a>(records: impl IntoIterator<Item = &'a Record>) -> Result<View, String> {
        let mut v = View::new();
        for r in records {
            v.fold(r)?;
        }
        Ok(v)
    }

    /// The latest published call sequence of `programme`, 0 before any.
    pub fn latest(&self, programme: ProgrammeId) -> u32 {
        self.latest.get(&programme).copied().unwrap_or(0)
    }

    /// The head version of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Option<&RefVersion> {
        self.heads
            .get(&programme)
            .and_then(|v| self.versions.get(v))
    }

    /// The P-12 value of the head of `programme`, 0 for an unknown programme.
    pub fn p12(&self, programme: ProgrammeId) -> u8 {
        self.head(programme).map_or(0, |v| v.p12)
    }

    /// The P-13 classes `call` enforces now: its snapshot and the live head
    /// (P-13 NOTE 7). Before publication, the live head only.
    pub fn effective_p13(&self, call: CallId) -> BTreeSet<ClassId> {
        let Some(c) = self.calls.get(&call) else {
            return BTreeSet::new();
        };
        let mut out = c.snapshot_p13.clone().unwrap_or_default();
        if let Some(h) = self.head(c.programme) {
            out.extend(h.p13.iter().copied());
        }
        out
    }

    /// The bindings of `account` in `programme`.
    pub fn bindings_of(
        &self,
        account: AccountId,
        programme: ProgrammeId,
    ) -> impl Iterator<Item = &RefBinding> {
        self.bindings
            .values()
            .filter(move |b| b.account == account && b.programme == programme)
    }

    /// Whether `x` and `y` were held at the same time.
    pub fn overlapped(&self, x: BindingId, y: BindingId) -> bool {
        self.overlaps.contains(&ordered(x, y))
    }

    /// Whether `later` was granted after `ended` ended.
    pub fn granted_after_end(&self, ended: BindingId, later: BindingId) -> bool {
        self.after_end.contains(&(ended, later))
    }

    /// The Applicant binding of the lead of `proposal`.
    pub fn lead_binding(&self, proposal: ProposalId) -> Option<&RefBinding> {
        let p = self.proposals.get(&proposal)?;
        self.bindings.values().find(|b| {
            b.role == Role::Applicant && b.proposal == Some(proposal) && b.account == p.lead
        })
    }

    /// The largest binding id recorded, 0 before any.
    pub fn max_binding(&self) -> u128 {
        self.bindings.keys().next_back().map_or(0, |b| b.raw())
    }

    /// The largest proposal id recorded, 0 before any.
    pub fn max_proposal(&self) -> u128 {
        self.proposals.keys().next_back().map_or(0, |p| p.raw())
    }

    /// Folds one core record without the vault facts. Records outside
    /// roles, calls, policy and proposals leave the view unchanged. An
    /// error names a record the reference cannot follow, which no engine
    /// may emit. Without the vault facts the IRC_REVIEW to NEGOTIATION
    /// gate leaves the proposal minor-flagged, which fails closed. Only
    /// views whose reader never asks for the flag are built this way.
    pub fn fold(&mut self, record: &Record) -> Result<(), String> {
        self.fold_in(record, None)
    }

    /// Folds one core record with `truth`, the vault facts when the record
    /// was written. At the IRC_REVIEW to NEGOTIATION gate the proposal
    /// stays minor-flagged unless `truth` shows an effective verified
    /// over-18 attestation of its lead at the deadline of its call
    /// (R-ID-04 Derivation note, state-machine NOTE 14).
    pub fn fold_with(&mut self, record: &Record, truth: &GroundTruth) -> Result<(), String> {
        self.fold_in(record, Some(truth))
    }

    fn fold_in(&mut self, record: &Record, truth: Option<&GroundTruth>) -> Result<(), String> {
        match record {
            Record::ProgrammeCreated { programme, .. } => {
                self.programmes.insert(*programme);
            }
            Record::PolicyVersionRecorded { version, .. } => {
                self.versions.insert(
                    version.id,
                    RefVersion {
                        programme: version.programme,
                        p12: version.live.p12.0,
                        p13: version.live.p13.0.clone(),
                    },
                );
                self.heads.insert(version.programme, version.id);
            }
            Record::CallDrafted {
                call,
                programme,
                deadline,
                ..
            } => {
                self.calls.insert(
                    *call,
                    RefCall {
                        programme: *programme,
                        seq: None,
                        snapshot_p13: None,
                        deadline: *deadline,
                    },
                );
            }
            Record::CallEdited { call, deadline, .. } => {
                if let Some(c) = self.calls.get_mut(call) {
                    c.deadline = *deadline;
                }
            }
            Record::CallPublished {
                call, policy, seq, ..
            } => {
                let snapshot = self
                    .versions
                    .get(policy)
                    .map(|v| v.p13.clone())
                    .ok_or_else(|| format!("{call:?} froze unknown version {policy:?}"))?;
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or_else(|| format!("unknown call {call:?} published"))?;
                c.seq = Some(seq.get());
                c.snapshot_p13 = Some(snapshot);
                let programme = c.programme;
                let latest = self.latest.entry(programme).or_insert(0);
                *latest = (*latest).max(seq.get());
            }
            Record::ProposalCreated {
                proposal,
                call,
                lead,
                ..
            } => {
                if self.proposals.contains_key(proposal) {
                    return Err(format!("proposal {proposal:?} created twice"));
                }
                self.proposals.insert(
                    *proposal,
                    RefProposal {
                        call: *call,
                        lead: *lead,
                        adult_at_gate: false,
                    },
                );
            }
            Record::BindingGranted(g) => self.fold_grant(g)?,
            Record::BindingEnded(e) => {
                let programme = self
                    .bindings
                    .get(&e.binding)
                    .map(|b| b.programme)
                    .ok_or_else(|| format!("unknown binding {:?} ended", e.binding))?;
                let latest = self.latest(programme);
                let p12 = self.p12(programme);
                let b = self
                    .bindings
                    .get_mut(&e.binding)
                    .ok_or_else(|| format!("unknown binding {:?} ended", e.binding))?;
                if b.end.is_some() {
                    return Err(format!("binding {:?} ended twice", e.binding));
                }
                b.end = Some(RefEnd {
                    at: e.at,
                    latest_at_end: latest,
                    p12_at_end: p12,
                    bar: latest.saturating_add(u32::from(p12)),
                    recorded_bar: e.barred_through,
                    recorded_p12: e.p12.0,
                });
            }
            Record::BindingSuspended(s) => {
                let b = self
                    .bindings
                    .get_mut(&s.binding)
                    .ok_or_else(|| format!("unknown binding {:?} suspended", s.binding))?;
                if b.voided.is_some() {
                    return Err(format!("voided binding {:?} suspended", s.binding));
                }
                b.suspended = true;
                if s.rule == RuleRef::I06 && b.group == RefGroup::Judging {
                    b.conflict_of_interest = true;
                } else {
                    b.ordinary_suspension = true;
                }
            }
            Record::BindingVoided(v) => {
                let b = self
                    .bindings
                    .get_mut(&v.binding)
                    .ok_or_else(|| format!("unknown binding {:?} voided", v.binding))?;
                if b.voided.is_some() {
                    return Err(format!("binding {:?} voided twice", v.binding));
                }
                b.voided = Some(v.rule);
            }
            Record::BindingReinstated(r) => {
                let b = self
                    .bindings
                    .get_mut(&r.binding)
                    .ok_or_else(|| format!("unknown binding {:?} reinstated", r.binding))?;
                // One reinstatement lifts one suspension, the conflict of
                // interest first. An ordinary suspension beneath it stays.
                if b.conflict_of_interest {
                    b.conflict_of_interest = false;
                } else {
                    b.ordinary_suspension = false;
                }
                b.suspended = b.conflict_of_interest || b.ordinary_suspension;
            }
            Record::VaultEpochProcessed { epoch } => self.epoch = *epoch,
            Record::Transitioned(t)
                if t.from == StateTag::IrcReview && t.to == StateTag::Negotiation =>
            {
                let deadline = self
                    .proposals
                    .get(&t.proposal)
                    .and_then(|p| self.calls.get(&p.call))
                    .map(|c| c.deadline);
                if let Some(p) = self.proposals.get_mut(&t.proposal) {
                    p.adult_at_gate = truth
                        .zip(deadline)
                        .is_some_and(|(truth, d)| truth.is_adult_at(p.lead, d));
                }
            }
            Record::ConflictDetected(c) => {
                self.detected.insert((c.account, c.proposal));
            }
            other => {
                if let Some((binding, at)) = scheduled_end_of(other) {
                    let b = self
                        .bindings
                        .get_mut(&binding)
                        .ok_or_else(|| format!("unknown binding {binding:?} scheduled to end"))?;
                    if !b.open() {
                        return Err(format!(
                            "binding {binding:?} is not open, yet its end is scheduled"
                        ));
                    }
                    b.scheduled_end = Some(at);
                }
            }
        }
        Ok(())
    }

    fn fold_grant(&mut self, g: &fstp_domain::record::BindingGranted) -> Result<(), String> {
        if self.bindings.contains_key(&g.binding) {
            return Err(format!("binding id {:?} granted twice", g.binding));
        }
        let (proposal, call) = match g.scope {
            BindingScope::Programme => (None, None),
            BindingScope::Proposal { proposal, call } => (Some(proposal), Some(call)),
        };
        let call_seq = call.and_then(|c| self.calls.get(&c)).and_then(|c| c.seq);
        for y in self.bindings.values() {
            if y.programme != g.programme || y.voided.is_some() {
                continue;
            }
            if y.end.is_none() {
                self.overlaps.insert(ordered(y.binding, g.binding));
            } else {
                self.after_end.insert((y.binding, g.binding));
            }
        }
        self.bindings.insert(
            g.binding,
            RefBinding {
                binding: g.binding,
                account: g.account,
                programme: g.programme,
                role: g.role,
                group: spec_group(g.role),
                proposal,
                call,
                call_seq,
                start: g.start,
                latest_at_start: self.latest(g.programme),
                granted_by: g.granted_by,
                verified_epoch: g.verified_epoch,
                organisation: g.organisation,
                end: None,
                scheduled_end: None,
                suspended: false,
                conflict_of_interest: false,
                ordinary_suspension: false,
                voided: None,
            },
        );
        Ok(())
    }
}

/// The pair `(x, y)` with the smaller id first.
fn ordered(x: BindingId, y: BindingId) -> (BindingId, BindingId) {
    if x <= y { (x, y) } else { (y, x) }
}

// ---------------------------------------------------------------------------
// The invariant predicates
// ---------------------------------------------------------------------------

/// Why bindings `x` and `y` together break I-01, if they do: they belong
/// to different groups among Drafting, Judging and Receiving, and they were
/// held at the same time, or one was granted inside the other's bar.
/// Voided bindings and conflict-of-interest suspensions never count.
pub fn pair_violation(view: &View, x: &RefBinding, y: &RefBinding) -> Option<String> {
    if x.binding == y.binding
        || x.programme != y.programme
        || x.group == y.group
        || !x.group.separated()
        || !y.group.separated()
        || !x.counts()
        || !y.counts()
    {
        return None;
    }
    if view.overlapped(x.binding, y.binding) {
        return Some(format!(
            "{:?} ({:?}) and {:?} ({:?}) were held at the same time",
            x.binding, x.role, y.binding, y.role
        ));
    }
    for (ended, later) in [(x, y), (y, x)] {
        if !view.granted_after_end(ended.binding, later.binding) {
            continue;
        }
        let Some(bar) = ended.bar() else { continue };
        let barred = match later.group {
            RefGroup::Receiving => later.call_seq.is_none_or(|seq| seq <= bar),
            _ => later.latest_at_start <= bar,
        };
        if barred {
            return Some(format!(
                "{:?} ({:?}) was granted inside the bar {bar} of {:?} ({:?}), call seq {:?}, latest at start {}",
                later.binding,
                later.role,
                ended.binding,
                ended.role,
                later.call_seq,
                later.latest_at_start
            ));
        }
    }
    None
}

/// Checks the I-01 pair rule over every pair of `bindings`.
fn check_pairs<'a>(
    view: &View,
    id: &str,
    who: &str,
    bindings: impl Iterator<Item = &'a RefBinding>,
) -> Result<(), String> {
    let list: Vec<&RefBinding> = bindings.collect();
    for (i, x) in list.iter().enumerate() {
        for y in list.iter().skip(i.saturating_add(1)) {
            if let Some(why) = pair_violation(view, x, y) {
                return Err(format!("{id}: {who} in {:?}: {why}", x.programme));
            }
        }
    }
    Ok(())
}

/// I-01 per account: no account holds roles from more than one of
/// Drafting, Judging and Receiving in a programme, counting past bindings
/// within the cooling-off bar.
pub fn check_i01(view: &View) -> Result<(), String> {
    let accounts: BTreeSet<(AccountId, ProgrammeId)> = view
        .bindings
        .values()
        .map(|b| (b.account, b.programme))
        .collect();
    for (account, programme) in accounts {
        check_pairs(
            view,
            "I-01",
            &format!("account {account:?}"),
            view.bindings_of(account, programme),
        )?;
    }
    Ok(())
}

/// I-06: for each verified identity, the bindings of all its verified
/// accounts together satisfy the I-01 rule. Unverified accounts do not count.
pub fn check_i06(view: &View, truth: &GroundTruth) -> Result<(), String> {
    let mut groups: BTreeMap<(IdentityTag, ProgrammeId), Vec<&RefBinding>> = BTreeMap::new();
    for b in view.bindings.values() {
        if let Some(t) = truth.verified_identity(b.account) {
            groups.entry((t, b.programme)).or_default().push(b);
        }
    }
    for ((t, _), list) in groups {
        check_pairs(
            view,
            "I-06",
            &format!("verified identity {t:?}"),
            list.into_iter(),
        )?;
    }
    Ok(())
}

/// I-02: no account holds an IRC binding and another Judging binding of one
/// programme at the same time. Assignments are lane L-REV's, checked in W4.
/// Voided bindings and conflict-of-interest suspensions never count.
pub fn check_i02(view: &View) -> Result<(), String> {
    for x in view.bindings.values() {
        if x.role != Role::IrcMember || !x.counts() {
            continue;
        }
        for y in view.bindings_of(x.account, x.programme) {
            if other_judging(y.role) && y.counts() && view.overlapped(x.binding, y.binding) {
                return Err(format!(
                    "I-02: account {:?} held IRC member {:?} and {:?} {:?} at the same time",
                    x.account, x.binding, y.role, y.binding
                ));
            }
        }
    }
    Ok(())
}

/// Whether `account` is in a class of `classes` under the vault's
/// effective knowledge. Exclusions are facts about identities, known for
/// every account with an identity, verified or not.
pub fn excluded_under(
    truth: &GroundTruth,
    account: AccountId,
    classes: &BTreeSet<ClassId>,
) -> bool {
    truth
        .identity_of(account)
        .is_some_and(|t| classes.iter().any(|c| truth.is_excluded(t, *c)))
}

/// Whether the held Receiving binding `b` breaks I-04 under `truth`.
pub fn i04_breaks(view: &View, truth: &GroundTruth, b: &RefBinding) -> bool {
    match b.call {
        Some(call) if b.group == RefGroup::Receiving && b.held() => {
            excluded_under(truth, b.account, &view.effective_p13(call))
        }
        _ => false,
    }
}

/// I-04: no account the vault knows to be in an excluded class of the
/// binding's call holds a Receiving binding. Suspended bindings count.
pub fn check_i04(view: &View, truth: &GroundTruth) -> Result<(), String> {
    for b in view.bindings.values() {
        if i04_breaks(view, truth, b) {
            return Err(format!(
                "I-04: account {:?} is in an excluded class of {:?} and holds {:?} {:?}",
                b.account, b.call, b.role, b.binding
            ));
        }
    }
    Ok(())
}

/// SoD-05 on the records: every ended binding of Drafting, Judging or
/// Receiving carries the bar and the P-12 value the reference computes.
pub fn check_bars(view: &View) -> Result<(), String> {
    for b in view.bindings.values() {
        if let Some(e) = b.end
            && b.group.separated()
            && (e.recorded_bar != e.bar || e.recorded_p12 != e.p12_at_end)
        {
            return Err(format!(
                "SoD-05: {:?} ended with bar {} and P-12 {}, the reference pins bar {} (latest {} + P-12 {})",
                b.binding, e.recorded_bar, e.recorded_p12, e.bar, e.latest_at_end, e.p12_at_end
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// One command as the reference judges it: the command and its context.
#[derive(Clone, Copy, Debug)]
pub struct Ask<'a> {
    /// The actor.
    pub actor: Actor,
    /// `Ctx::tenant_admin`.
    pub tenant_admin: bool,
    /// `Ctx::second_tenant_admin`.
    pub second_tenant_admin: Option<AccountId>,
    /// `Ctx::binds_tenant_admin`.
    pub binds_tenant_admin: bool,
    /// `Ctx::now`.
    pub now: Timestamp,
    /// The command.
    pub cmd: &'a Command,
}

/// The reference verdict on a command.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The command must be accepted.
    Accept,
    /// The command must be refused, for the reason named.
    Refuse(String),
    /// The command is outside this reference, so production decides.
    Unjudged,
}

impl Verdict {
    /// Whether the verdict is [`Verdict::Accept`].
    pub fn accepts(&self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

fn refuse(why: &str) -> Verdict {
    Verdict::Refuse(why.to_owned())
}

/// Why a new binding of `account` in group `group` breaks an account-level
/// rule against the account's own bindings in `programme`. For a Receiving
/// target, `call_seq` is its call's sequence number.
fn account_rules(
    view: &View,
    account: AccountId,
    programme: ProgrammeId,
    role: Role,
    call_seq: Option<u32>,
) -> Option<&'static str> {
    let group = spec_group(role);
    let latest = view.latest(programme);
    for x in view.bindings_of(account, programme) {
        if !x.counts() {
            continue;
        }
        if group.separated() && x.group.separated() && x.group != group {
            if x.held() {
                return Some("SoD-01");
            }
            if let Some(bar) = x.bar() {
                let barred = match group {
                    RefGroup::Receiving => call_seq.is_none_or(|s| s <= bar),
                    _ => latest <= bar,
                };
                if barred {
                    return Some("SoD-05");
                }
            }
        }
        let ops_receiving = (group == RefGroup::Operations && x.group == RefGroup::Receiving)
            || (group == RefGroup::Receiving && x.group == RefGroup::Operations);
        if ops_receiving && x.held() {
            return Some("SoD-03");
        }
        let irc_clash = (role == Role::IrcMember && other_judging(x.role))
            || (other_judging(role) && x.role == Role::IrcMember);
        if irc_clash && x.held() {
            return Some("SoD-02");
        }
    }
    None
}

/// Whether another verified account with the verified identity of
/// `account` holds a binding that a new binding of `account` in `group`
/// would break I-01 with (I-06, SoD-09 NOTE 1). For a Receiving target,
/// `call_seq` is its call's sequence number. A conflict-of-interest
/// suspension is not in the candidate set, held or past.
pub fn identity_clash(
    view: &View,
    truth: &GroundTruth,
    account: AccountId,
    programme: ProgrammeId,
    group: RefGroup,
    call_seq: Option<u32>,
) -> bool {
    let Some(t) = truth.verified_identity(account) else {
        return false;
    };
    let latest = view.latest(programme);
    view.bindings.values().any(|y| {
        y.account != account
            && y.programme == programme
            && y.counts()
            && y.group.separated()
            && group.separated()
            && y.group != group
            && truth.verified_identity(y.account) == Some(t)
            && (y.held()
                || y.bar().is_some_and(|bar| match group {
                    RefGroup::Receiving => call_seq.is_none_or(|s| s <= bar),
                    _ => latest <= bar,
                }))
    })
}

/// The checks every new Receiving binding of `account` in `call` runs:
/// account rules, SoD-03 through the tenant admin attestation, SoD-06 and I-06.
fn receiving_rules(
    view: &View,
    truth: &GroundTruth,
    account: AccountId,
    role: Role,
    call: CallId,
    binds_tenant_admin: bool,
) -> Verdict {
    let Some(c) = view.calls.get(&call) else {
        return refuse("unknown call");
    };
    let Some(seq) = c.seq else {
        return refuse("call not published");
    };
    if let Some(rule) = account_rules(view, account, c.programme, role, Some(seq)) {
        return refuse(rule);
    }
    if binds_tenant_admin {
        return refuse("SoD-03");
    }
    if excluded_under(truth, account, &view.effective_p13(call)) {
        return refuse("SoD-06");
    }
    if identity_clash(
        view,
        truth,
        account,
        c.programme,
        RefGroup::Receiving,
        Some(seq),
    ) {
        return refuse("I-06");
    }
    Verdict::Accept
}

/// Whether `account` holds a committee member binding in `programme`,
/// other than `except`, that records an organisation other than
/// `organisation` (SoD-10, decided 2026-10-28: one organisation per
/// programme). Every held binding counts, whatever its period: one with a
/// scheduled end not yet recorded, one that starts later, and an ordinary
/// suspended one, since it can be reinstated. A voided binding or a
/// conflict-of-interest suspension is not held (W7 fix round 2).
pub fn other_organisation(
    view: &View,
    account: AccountId,
    programme: ProgrammeId,
    organisation: OrganisationId,
    except: Option<BindingId>,
) -> bool {
    view.bindings_of(account, programme).any(|b| {
        Some(b.binding) != except
            && b.role == Role::CommitteeMember
            && b.held()
            && b.organisation.is_some_and(|o| o != organisation)
    })
}

/// The rule a reference refusal names, read from the start of its reason,
/// such as `SoD-05` or `I-06`. A reason that names no rule maps to
/// [`RuleRef::Input`].
pub fn rule_of(why: &str) -> RuleRef {
    const RULES: [(&str, RuleRef); 14] = [
        ("SoD-01", RuleRef::Sod01),
        ("SoD-02", RuleRef::Sod02),
        ("SoD-03", RuleRef::Sod03),
        ("SoD-04", RuleRef::Sod04),
        ("SoD-05", RuleRef::Sod05),
        ("SoD-06", RuleRef::Sod06),
        ("SoD-07", RuleRef::Sod07),
        ("SoD-09", RuleRef::Sod09),
        ("SoD-10", RuleRef::Sod10),
        ("SoD-11", RuleRef::Sod11),
        ("I-01", RuleRef::I01),
        ("I-02", RuleRef::I02),
        ("I-04", RuleRef::I04),
        ("I-06", RuleRef::I06),
    ];
    RULES
        .iter()
        .find(|(name, _)| {
            why.strip_prefix(name)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
        .map_or(RuleRef::Input, |(_, rule)| *rule)
}

/// The reference verdict on `ask` under `view` and the vault facts `truth`.
///
/// It judges `GrantRole`, `EndRole`, `CreateDraft`, `AddTeamMember` and
/// `AddGuardian`. Of `ReinstateBinding` it judges only the refusals it
/// knows: an unknown binding, and a conflict-of-interest suspension that is
/// ended or whose clash lasts. Every other command is [`Verdict::Unjudged`].
pub fn verdict(view: &View, truth: &GroundTruth, ask: &Ask<'_>) -> Verdict {
    let Actor::Account(actor) = ask.actor else {
        return match ask.cmd {
            Command::GrantRole { .. }
            | Command::EndRole { .. }
            | Command::CreateDraft { .. }
            | Command::AddTeamMember { .. }
            | Command::AddGuardian { .. } => refuse("actor"),
            _ => Verdict::Unjudged,
        };
    };
    if !due_ends(view, ask.now).is_empty() {
        // Cooling-off NOTE (decided 2026-10-25): the binding stays held
        // until its instant, and its bar is pinned then. Test-author
        // reading of W7 fix round 1: until the System records a due end,
        // every account command is refused, so none reads the binding as
        // held after its instant and the end reads the instant's state.
        return refuse("SoD-05: a scheduled end is due and not yet recorded");
    }
    match ask.cmd {
        Command::GrantRole {
            binding,
            account,
            programme,
            role,
            start,
            second_admin,
            confidentiality,
            organisation,
            end: _,
        } => {
            if !ask.tenant_admin {
                return refuse("actor");
            }
            if !view.programmes.contains(programme) {
                return refuse("unknown programme");
            }
            if view.bindings.contains_key(binding) {
                return refuse("binding id reused");
            }
            let group = spec_group(*role);
            if group == RefGroup::Receiving {
                return refuse("Receiving roles arise from proposals");
            }
            if *role == Role::CommitteeMember && organisation.is_none() {
                return refuse("SoD-10: a committee binding records the reviewer's organisation");
            }
            if *role == Role::CommitteeMember
                && let Some(o) = organisation
                && other_organisation(view, *account, *programme, *o, None)
            {
                return refuse("SoD-10: one organisation per reviewer per programme");
            }
            if *start < ask.now {
                return refuse("backdated start");
            }
            if grant_end(ask.cmd).is_some_and(|e| e <= *start) {
                return refuse("a scheduled end lies after the start");
            }
            if group.needs_verification() && confidentiality.is_none() {
                return refuse("confidentiality terms");
            }
            if *account == actor {
                let approved = match (second_admin, ask.second_tenant_admin) {
                    (Some(s), Some(t)) => *s == t && *s != actor,
                    _ => false,
                };
                if !approved {
                    return refuse("SoD-07");
                }
            }
            if group.needs_verification() && !truth.is_verified(*account) {
                return refuse("SoD-09");
            }
            if let Some(rule) = account_rules(view, *account, *programme, *role, None) {
                return refuse(rule);
            }
            if group.needs_verification()
                && identity_clash(view, truth, *account, *programme, group, None)
            {
                return refuse("I-06");
            }
            Verdict::Accept
        }
        Command::EndRole { binding, at } => {
            if !ask.tenant_admin {
                return refuse("actor");
            }
            let Some(b) = view.bindings.get(binding) else {
                return refuse("unknown binding");
            };
            if b.group == RefGroup::Receiving {
                return refuse("Receiving bindings end with the proposal");
            }
            if !b.open() {
                // A conflict-of-interest suspension is open and can end.
                return refuse("binding not held");
            }
            if *at < ask.now {
                return refuse("backdated end");
            }
            if *at > ask.now && b.scheduled_end.is_none_or(|s| *at < s) && *at <= b.start {
                // Test-author reading: a scheduled end lies after the start,
                // as at the grant.
                return refuse("a scheduled end lies after the start");
            }
            // A later instant schedules the end (Cooling-off NOTE, decided
            // 2026-10-25). A scheduled end can be brought forward, never
            // moved later.
            match b.scheduled_end {
                Some(s) if *at > ask.now && *at > s => {
                    refuse("a scheduled end is never moved later")
                }
                Some(s) if *at > ask.now && *at == s => Verdict::Unjudged,
                _ => Verdict::Accept,
            }
        }
        Command::CreateDraft {
            proposal,
            call,
            binding,
            ..
        } => {
            if view.proposals.contains_key(proposal) {
                return refuse("proposal id reused");
            }
            if view.bindings.contains_key(binding) {
                return refuse("binding id reused");
            }
            receiving_rules(
                view,
                truth,
                actor,
                Role::Applicant,
                *call,
                ask.binds_tenant_admin,
            )
        }
        Command::AddTeamMember {
            proposal,
            account,
            binding,
        }
        | Command::AddGuardian {
            proposal,
            account,
            binding,
        } => {
            let guardian = matches!(ask.cmd, Command::AddGuardian { .. });
            let Some(p) = view.proposals.get(proposal) else {
                return refuse("unknown proposal");
            };
            if p.lead != actor || !view.lead_binding(*proposal).is_some_and(RefBinding::active) {
                return refuse("actor");
            }
            if view.bindings.contains_key(binding) {
                return refuse("binding id reused");
            }
            if guardian && !p.minor_flagged() {
                return refuse("guardian for a proposal that is not minor-flagged");
            }
            let already = view
                .bindings
                .values()
                .any(|b| b.proposal == Some(*proposal) && b.account == *account);
            if already {
                return refuse("account already bound to the proposal");
            }
            let role = if guardian {
                Role::Guardian
            } else {
                Role::ApplicantTeamMember
            };
            receiving_rules(view, truth, *account, role, p.call, ask.binds_tenant_admin)
        }
        Command::ReinstateBinding { binding, .. } => {
            let Some(b) = view.bindings.get(binding) else {
                return refuse("unknown binding");
            };
            if !b.conflict_of_interest {
                return Verdict::Unjudged;
            }
            if b.end.is_some() {
                return refuse("binding ended");
            }
            if b.role == Role::CommitteeMember
                && let Some(o) = b.organisation
                && other_organisation(view, b.account, b.programme, o, Some(b.binding))
            {
                // SoD-10 (decided 2026-10-28): counted again, the binding
                // would give the reviewer two organisations in the programme.
                return refuse("SoD-10: one organisation per reviewer per programme");
            }
            match reinstate_clash(view, truth, b) {
                Some(rule) => refuse(rule),
                None => Verdict::Unjudged,
            }
        }
        _ => Verdict::Unjudged,
    }
}

/// The rule a binding under a conflict-of-interest suspension would break
/// if it were reinstated now, if any (Identity discovery, decided
/// 2026-10-25: reinstatement is refused while the identity clash lasts).
///
/// Counted again, `b` must not break the I-01 pair rule with a counted
/// binding of its own account (I-01) or of another account of its verified
/// identity (I-06). Nor may it break I-02 with a counted binding of its own
/// account that was held beside it, held now or ended since. Counted
/// again, `b` counts over its suspension period too, so the history must
/// not show both held at the same time (`check_i02`).
pub fn reinstate_clash(view: &View, truth: &GroundTruth, b: &RefBinding) -> Option<&'static str> {
    let mut x = b.clone();
    x.suspended = false;
    x.conflict_of_interest = false;
    let identity = truth.verified_identity(x.account);
    for y in view.bindings.values() {
        if y.binding == x.binding || y.programme != x.programme || !y.counts() {
            continue;
        }
        let same_account = y.account == x.account;
        let same_identity = identity.is_some() && truth.verified_identity(y.account) == identity;
        if !same_account && !same_identity {
            continue;
        }
        if pair_violation(view, &x, y).is_some() {
            return Some(if same_account { "I-01" } else { "I-06" });
        }
        let irc_clash = (x.role == Role::IrcMember && other_judging(y.role))
            || (other_judging(x.role) && y.role == Role::IrcMember);
        if same_account && irc_clash && view.overlapped(x.binding, y.binding) {
            return Some("I-02");
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Expected records
// ---------------------------------------------------------------------------

/// The binding an accepted command must record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExpectedBinding {
    /// The binding.
    pub binding: BindingId,
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
    /// The granting account: the tenant admin, or the lead for Receiving roles.
    pub granted_by: AccountId,
}

/// The binding that `ask` must record when accepted, if it creates one.
pub fn expected_binding(view: &View, ask: &Ask<'_>) -> Option<ExpectedBinding> {
    let Actor::Account(actor) = ask.actor else {
        return None;
    };
    match ask.cmd {
        Command::GrantRole {
            binding,
            account,
            programme,
            role,
            start,
            ..
        } => Some(ExpectedBinding {
            binding: *binding,
            account: *account,
            programme: *programme,
            role: *role,
            scope: BindingScope::Programme,
            start: *start,
            granted_by: actor,
        }),
        Command::CreateDraft {
            proposal,
            call,
            binding,
            ..
        } => Some(ExpectedBinding {
            binding: *binding,
            account: actor,
            programme: view.calls.get(call)?.programme,
            role: Role::Applicant,
            scope: BindingScope::Proposal {
                proposal: *proposal,
                call: *call,
            },
            start: ask.now,
            granted_by: actor,
        }),
        Command::AddTeamMember {
            proposal,
            account,
            binding,
        }
        | Command::AddGuardian {
            proposal,
            account,
            binding,
        } => {
            let p = view.proposals.get(proposal)?;
            Some(ExpectedBinding {
                binding: *binding,
                account: *account,
                programme: view.calls.get(&p.call)?.programme,
                role: if matches!(ask.cmd, Command::AddGuardian { .. }) {
                    Role::Guardian
                } else {
                    Role::ApplicantTeamMember
                },
                scope: BindingScope::Proposal {
                    proposal: *proposal,
                    call: p.call,
                },
                start: ask.now,
                granted_by: actor,
            })
        }
        _ => None,
    }
}

/// The bar and P-12 value an `EndRole` of `binding` must pin now:
/// the latest published sequence of its programme plus the head's P-12.
pub fn expected_end(view: &View, binding: BindingId) -> Option<(u32, u8)> {
    let b = view.bindings.get(&binding)?;
    let p12 = view.p12(b.programme);
    Some((view.latest(b.programme).saturating_add(u32::from(p12)), p12))
}

// ---------------------------------------------------------------------------
// Scheduled ends (Cooling-off NOTE, decided 2026-10-25)
// ---------------------------------------------------------------------------

/// The JSON type of the scheduled end record.
pub const SCHEDULED_END_TYPE: &str = "BindingEndScheduled";

/// The decimal string member `name` of the JSON object `v`.
fn decimal_member(v: &fstp_json::Value, name: &str) -> Option<String> {
    match v {
        fstp_json::Value::Object(o) => match o.get(name) {
            Some(fstp_json::Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The binding and instant of a scheduled end record, read from its JSON
/// form: type `BindingEndScheduled`, members `binding` and `at`. `None`
/// for every other record.
pub fn scheduled_end_of(record: &Record) -> Option<(BindingId, Timestamp)> {
    use fstp_json::ToJson;
    let v = record.to_json();
    let fstp_json::Value::Object(o) = &v else {
        return None;
    };
    match o.get("type") {
        Some(fstp_json::Value::String(t)) if t == SCHEDULED_END_TYPE => {}
        _ => return None,
    }
    let binding = decimal_member(&v, "binding")?.parse::<u128>().ok()?;
    let at = decimal_member(&v, "at")?.parse::<i64>().ok()?;
    Some((BindingId::from_raw(binding), Timestamp::from_micros(at)))
}

/// The scheduled end record of `binding` at `at`, built through the record
/// codec from its JSON form, since the stub interface does not declare it
/// yet. The error says that the codec does not know the record.
pub fn scheduled_end_record(binding: BindingId, at: Timestamp) -> Result<Record, String> {
    use fstp_json::FromJson;
    let text = format!(
        "{{\"type\":\"{SCHEDULED_END_TYPE}\",\"binding\":\"{}\",\"at\":\"{}\"}}",
        binding.raw(),
        at.micros()
    );
    let v = fstp_json::parse(text.as_bytes()).map_err(|e| format!("json: {e:?}"))?;
    Record::from_json(&v).map_err(|e| {
        format!("the record codec does not know {SCHEDULED_END_TYPE} yet (Cooling-off NOTE): {e:?}")
    })
}

/// The scheduled end a `GrantRole` carries in its `end` member, if any.
/// The member is read from the JSON form, since the stub interface does
/// not declare it yet. A missing or null member is no scheduled end.
pub fn grant_end(cmd: &Command) -> Option<Timestamp> {
    use fstp_json::ToJson;
    if !matches!(cmd, Command::GrantRole { .. }) {
        return None;
    }
    let micros = decimal_member(&cmd.to_json(), "end")?.parse::<i64>().ok()?;
    Some(Timestamp::from_micros(micros))
}

/// The scheduled end an accepted `ask` must record: an `EndRole` at a
/// later instant than `now`, or a `GrantRole` with an `end` member.
pub fn expected_scheduled(ask: &Ask<'_>) -> Option<(BindingId, Timestamp)> {
    match ask.cmd {
        Command::EndRole { binding, at } if *at > ask.now => Some((*binding, *at)),
        Command::GrantRole { binding, .. } => grant_end(ask.cmd).map(|e| (*binding, e)),
        _ => None,
    }
}

/// The open bindings whose scheduled end is due at `now`, with the
/// scheduled instant. The System records their ends then, through the
/// command `due` lists.
pub fn due_ends(view: &View, now: Timestamp) -> Vec<(BindingId, Timestamp)> {
    view.bindings
        .values()
        .filter(|b| b.open())
        .filter_map(|b| b.scheduled_end.map(|s| (b.binding, s)))
        .filter(|(_, s)| *s <= now)
        .collect()
}

/// Checks an accepted batch that schedules the end of `binding` at `at`:
/// one scheduled end record for it at that instant, and no end yet.
pub fn check_scheduled(
    context: &str,
    binding: BindingId,
    at: Timestamp,
    batch: &[Record],
) -> Result<(), String> {
    let found: Vec<(BindingId, Timestamp)> = batch
        .iter()
        .filter_map(scheduled_end_of)
        .filter(|(b, _)| *b == binding)
        .collect();
    if found != vec![(binding, at)] {
        return Err(format!(
            "Cooling-off NOTE: {context}: the batch schedules {found:?}, the reference expects one {SCHEDULED_END_TYPE} of {binding:?} at {at:?}"
        ));
    }
    if batch
        .iter()
        .any(|r| matches!(r, Record::BindingEnded(e) if e.binding == binding))
    {
        return Err(format!(
            "Cooling-off NOTE: {context}: {binding:?} ends at once, yet it stays held until {at:?}"
        ));
    }
    Ok(())
}

/// Checks the batch of the System's scheduled ends at `now` against
/// [`due_ends`] of `view_before`: exactly those bindings end, each at its
/// scheduled instant, with the bar and P-12 value of [`expected_end`] now.
pub fn check_due_ends(view_before: &View, now: Timestamp, batch: &[Record]) -> Result<(), String> {
    let due = due_ends(view_before, now);
    let ended: BTreeSet<BindingId> = batch
        .iter()
        .filter_map(|r| match r {
            Record::BindingEnded(e) => Some(e.binding),
            _ => None,
        })
        .collect();
    let expected: BTreeSet<BindingId> = due.iter().map(|(b, _)| *b).collect();
    if ended != expected {
        return Err(format!(
            "Cooling-off NOTE: the System ends {ended:?} at {now:?}, the reference expects {expected:?}"
        ));
    }
    for (b, at) in due {
        check_ended("the scheduled end", view_before, b, at, batch)?;
    }
    Ok(())
}

/// Whether the ended Receiving binding `b` breaks I-01 with a binding of
/// another verified account of the same verified identity (I-06). Its bar
/// still counts, so it must be voided too (Identity discovery: voided
/// bindings never count, past bindings within the cooling-off period
/// included).
pub fn past_identity_clash(view: &View, truth: &GroundTruth, b: &RefBinding) -> bool {
    let Some(t) = truth.verified_identity(b.account) else {
        return false;
    };
    view.bindings.values().any(|y| {
        y.account != b.account
            && truth.verified_identity(y.account) == Some(t)
            && pair_violation(view, b, y).is_some()
    })
}

/// The rules under which the Receiving binding `b` must be voided under
/// `truth`: I-04, I-06, both or neither. A held binding breaks I-04 or
/// I-06, and an ended one that is not voided breaks only I-06.
pub fn void_rules(view: &View, truth: &GroundTruth, b: &RefBinding) -> BTreeSet<RuleRef> {
    let mut out = BTreeSet::new();
    if b.group != RefGroup::Receiving || b.voided.is_some() {
        return out;
    }
    if !b.held() {
        if past_identity_clash(view, truth, b) {
            out.insert(RuleRef::I06);
        }
        return out;
    }
    if i04_breaks(view, truth, b) {
        out.insert(RuleRef::I04);
    }
    if identity_clash(
        view,
        truth,
        b.account,
        b.programme,
        RefGroup::Receiving,
        b.call_seq,
    ) {
        out.insert(RuleRef::I06);
    }
    out
}

/// The bindings a reaction must void in the same batch, with the rules
/// each may be voided under (Identity discovery, P-13 NOTE 7). `view` is
/// the view the reaction starts from, with any policy record of the batch
/// already folded, and `truth` holds the facts the reaction sees.
pub fn expected_voids(view: &View, truth: &GroundTruth) -> BTreeMap<BindingId, BTreeSet<RuleRef>> {
    view.bindings
        .values()
        .filter_map(|b| {
            let rules = void_rules(view, truth, b);
            (!rules.is_empty()).then_some((b.binding, rules))
        })
        .collect()
}

/// Checks the voids of a reaction batch against [`expected_voids`]: every
/// expected binding is voided under one of its rules, and no other binding
/// is. A binding that breaks I-06 is voided under I-06, even when it also
/// breaks I-04, so the identity discovery stays a fact for R-CF-04.
pub fn check_voids(
    context: &str,
    expected: &BTreeMap<BindingId, BTreeSet<RuleRef>>,
    batch: &[Record],
) -> Result<(), String> {
    let mut voided: BTreeMap<BindingId, RuleRef> = BTreeMap::new();
    for r in batch {
        if let Record::BindingVoided(v) = r
            && voided.insert(v.binding, v.rule).is_some()
        {
            return Err(format!(
                "{context}: {:?} voided twice in one batch",
                v.binding
            ));
        }
    }
    for (b, rules) in expected {
        match voided.get(b) {
            None => {
                return Err(format!(
                    "{context}: {b:?} breaks {rules:?} and must be voided in the same batch"
                ));
            }
            Some(rule) if !rules.contains(rule) => {
                return Err(format!(
                    "{context}: {b:?} voided under {rule:?}, the reference expects one of {rules:?}"
                ));
            }
            Some(rule) if *rule != RuleRef::I06 && rules.contains(&RuleRef::I06) => {
                return Err(format!(
                    "R-CF-04: {context}: {b:?} shares a verified identity across groups and is voided under {rule:?}, not I-06, so the identity discovery is lost"
                ));
            }
            Some(_) => {}
        }
    }
    for b in voided.keys() {
        if !expected.contains_key(b) {
            return Err(format!(
                "{context}: {b:?} voided, but it breaks neither I-04 nor I-06"
            ));
        }
    }
    Ok(())
}

/// Whether the Judging binding `b` must be suspended as a conflict of
/// interest under `truth` (Identity discovery, last paragraph, decided
/// 2026-10-25). It counts, held or past, and it breaks the I-01 pair rule
/// with a counted Drafting binding of another account of the same
/// verified identity. Only a later identity merge reaches this, since
/// SoD-09 refuses it at binding time.
pub fn conflict_of_interest(view: &View, truth: &GroundTruth, b: &RefBinding) -> bool {
    if b.group != RefGroup::Judging || !b.counts() {
        return false;
    }
    let Some(t) = truth.verified_identity(b.account) else {
        return false;
    };
    view.bindings.values().any(|y| {
        y.account != b.account
            && y.group == RefGroup::Drafting
            && truth.verified_identity(y.account) == Some(t)
            && pair_violation(view, b, y).is_some()
    })
}

/// The Judging bindings a reaction must suspend as a conflict of interest
/// in the same batch. `view` is the view the reaction starts from, and
/// `truth` holds the facts the reaction sees.
pub fn expected_suspensions(view: &View, truth: &GroundTruth) -> BTreeSet<BindingId> {
    view.bindings
        .values()
        .filter(|b| conflict_of_interest(view, truth, b))
        .map(|b| b.binding)
        .collect()
}

/// Checks the suspensions of a batch against [`expected_suspensions`]:
/// every expected Judging binding is suspended once under I-06, the
/// conflict-of-interest marker, and no other binding is suspended. The
/// Drafting binding stays (Identity discovery, decided 2026-10-25).
pub fn check_suspensions(
    context: &str,
    expected: &BTreeSet<BindingId>,
    batch: &[Record],
) -> Result<(), String> {
    let mut suspended: BTreeMap<BindingId, RuleRef> = BTreeMap::new();
    for r in batch {
        if let Record::BindingSuspended(s) = r
            && suspended.insert(s.binding, s.rule).is_some()
        {
            return Err(format!(
                "{context}: {:?} suspended twice in one batch",
                s.binding
            ));
        }
    }
    for b in expected {
        match suspended.get(b) {
            None => {
                return Err(format!(
                    "I-06: {context}: Judging binding {b:?} shares a verified identity with a Drafting binding and must be suspended as a conflict of interest in the same batch"
                ));
            }
            Some(rule) if *rule != RuleRef::I06 => {
                return Err(format!(
                    "I-06: {context}: Judging binding {b:?} suspended under {rule:?}, which still counts as held; the conflict-of-interest suspension is under I06"
                ));
            }
            Some(_) => {}
        }
    }
    for (b, rule) in &suspended {
        if !expected.contains(b) {
            return Err(format!(
                "I-06: {context}: {b:?} suspended under {rule:?}, but it is no Judging binding in a conflict of interest; the Drafting binding stays"
            ));
        }
    }
    Ok(())
}

/// Checks an accepted batch for the binding the reference expects.
pub fn check_granted(
    context: &str,
    expected: &ExpectedBinding,
    batch: &[Record],
) -> Result<(), String> {
    let found: Vec<&fstp_domain::record::BindingGranted> = batch
        .iter()
        .filter_map(|r| match r {
            Record::BindingGranted(g) if g.binding == expected.binding => Some(g),
            _ => None,
        })
        .collect();
    let [g] = found.as_slice() else {
        return Err(format!(
            "{context}: the batch holds {} BindingGranted records for {:?}, expected one",
            found.len(),
            expected.binding
        ));
    };
    let got = ExpectedBinding {
        binding: g.binding,
        account: g.account,
        programme: g.programme,
        role: g.role,
        scope: g.scope,
        start: g.start,
        granted_by: g.granted_by,
    };
    if got != *expected {
        return Err(format!(
            "{context}: recorded {got:?}, the reference expects {expected:?}"
        ));
    }
    if spec_group(g.role).needs_verification() && g.verified_epoch.is_none() {
        return Err(format!(
            "SoD-09: {context}: a {:?} binding records no SoD-09 answer epoch",
            g.role
        ));
    }
    Ok(())
}

/// Checks an accepted `EndRole` batch: one `BindingEnded` for `binding` at
/// `at`, pinning the bar and P-12 value of [`expected_end`].
pub fn check_ended(
    context: &str,
    view_before: &View,
    binding: BindingId,
    at: Timestamp,
    batch: &[Record],
) -> Result<(), String> {
    let (bar, p12) = expected_end(view_before, binding)
        .ok_or_else(|| format!("{context}: the reference knows no binding {binding:?}"))?;
    let found: Vec<&fstp_domain::record::BindingEnded> = batch
        .iter()
        .filter_map(|r| match r {
            Record::BindingEnded(e) if e.binding == binding => Some(e),
            _ => None,
        })
        .collect();
    let [e] = found.as_slice() else {
        return Err(format!(
            "{context}: the batch holds {} BindingEnded records for {binding:?}, expected one",
            found.len()
        ));
    };
    let separated = view_before
        .bindings
        .get(&binding)
        .is_some_and(|b| b.group.separated());
    if e.at != at || (separated && (e.barred_through != bar || e.p12.0 != p12)) {
        return Err(format!(
            "SoD-05: {context}: recorded end at {:?} with bar {} and P-12 {}, the reference pins {at:?}, bar {bar} and P-12 {p12}",
            e.at, e.barred_through, e.p12.0
        ));
    }
    Ok(())
}

/// The bindings recorded in `after` and not in `before`.
pub fn new_bindings<'a>(before: &View, after: &'a View) -> impl Iterator<Item = &'a RefBinding> {
    let known: BTreeSet<BindingId> = before.bindings.keys().copied().collect();
    after
        .bindings
        .values()
        .filter(move |b| !known.contains(&b.binding))
}
