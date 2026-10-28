//! The M-SOD model for fstp-mc, its properties and the shared SoD model steps (design sections 6.2 and 6.3).
//!
//! - [`SodModel`] is M-SOD: accounts a and b share one identity, c has
//!   another, and staff publish up to three calls. Each instance chooses
//!   which subjects act, which roles they may be granted, whether they may
//!   draft and how many bindings each may create. The start state is built
//!   from genesis by production commands ([`SodWorld::from_setup`]).
//! - [`judged`] runs one step on production and compares it with the
//!   reference in both directions, including the records an accepted step
//!   must hold. The M-EXCL and M-RACE models reuse it.
//! - The property builders read only the reference [`View`] and the
//!   ground truth, never production structures.
//!
//! Instances (design 6.3): P-12 = 0, 1 and 2 for I-01; one account in two
//! programmes; I-02 over Judging roles; I-06 with the Sybil pair and an
//! identity merge of c into the Sybil identity; scheduled ends, where an
//! end is scheduled for [`T_SCHEDULED`] and time then moves to it, so the
//! System ends the binding with the bar pinned at that instant
//! (Cooling-off NOTE, decided 2026-10-25). A run of an instance in
//! [`Backend::Reference`] mode checks the model itself: every property
//! passes and every witness is reached on the reference.
//!
//! The merge is the vault operation that the W3b fix round left out. It
//! lets a Drafting and a Judging holder share one verified identity, which
//! the reaction answers with a conflict-of-interest suspension of the
//! Judging binding (Identity discovery, decided 2026-10-25).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, BindingId, CallId, ProgrammeId, ProposalId, VaultEpoch};
use fstp_domain::record::{BindingReinstated, BindingSuspended, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_mc::{Model, Property};

use crate::r#gen::roster::{
    A, B, Backend, C, Facts, ID_AB, P1, P2, SodSetup, SodWorld, Step, T0, call, draft, end, grant,
    publish, reinstate, sod_truth,
};
use crate::reference::sod::{
    RefBinding, RefGroup, Verdict, View, check_bars, check_due_ends, check_ended, check_granted,
    check_i01, check_i02, check_i06, check_scheduled, check_suspensions, check_voids,
    expected_binding, expected_scheduled, expected_suspensions, expected_voids, new_bindings,
    other_judging, verdict,
};
use crate::vault::{GroundTruth, IdentityTag};

// ---------------------------------------------------------------------------
// Shared model state and steps
// ---------------------------------------------------------------------------

/// One state of an SoD model: the world, the creations per account and a
/// divergence between production and the reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SodMcState {
    /// Production, the vault and the reference view.
    pub world: SodWorld,
    /// Bindings each subject created so far.
    pub created: BTreeMap<AccountId, u8>,
    /// Set when production and the reference disagree. The `two-way`
    /// property fails on it, and the state is terminal.
    pub divergence: Option<String>,
    /// Ghost: an accepted `EndRole` brought a scheduled end forward, to an
    /// earlier instant that is still after now (Cooling-off NOTE).
    pub brought_forward: bool,
}

impl SodMcState {
    /// A state over `world` with nothing created.
    pub fn new(world: SodWorld) -> SodMcState {
        SodMcState {
            world,
            created: BTreeMap::new(),
            divergence: None,
            brought_forward: false,
        }
    }

    /// The reference view.
    pub fn view(&self) -> &View {
        &self.world.view
    }

    /// The vault facts.
    pub fn truth(&self) -> &GroundTruth {
        &self.world.truth
    }

    fn diverged(mut self, why: String) -> SodMcState {
        self.divergence = Some(why);
        self
    }
}

/// Runs a role or draft `step` on a copy of `s` and compares the outcome
/// with the reference verdict in both directions. An accepted step must
/// record the binding or end the reference expects, and void or suspend nothing.
///
/// A refused step that the reference also refuses has no successor. A
/// disagreement yields a successor marked with the divergence.
pub fn judged(s: &SodMcState, step: &Step) -> Option<SodMcState> {
    let ask = step.ask(s.world.now);
    let v = verdict(s.view(), s.truth(), &ask);
    let expected = expected_binding(s.view(), &ask);
    let mut next = s.clone();
    let context = format!("{:?} by {:?}", step.cmd, step.actor);
    match next.world.exec(step, Facts::Effective) {
        Err(e) => Some(next.diverged(format!("{context}: {e}"))),
        Ok(Err(r)) => match v {
            Verdict::Accept => Some(next.diverged(format!(
                "{context}: over-denial, the reference accepts, production refuses with {r}"
            ))),
            _ => None,
        },
        Ok(Ok(records)) => {
            if let Verdict::Refuse(why) = &v {
                return Some(next.diverged(format!(
                    "{context}: over-permission, the reference refuses ({why}), production accepts"
                )));
            }
            let mut checks = Vec::new();
            if let Some(e) = expected
                && v.accepts()
            {
                checks.push(check_granted(&context, &e, &records));
            }
            if let Some((binding, at)) = expected_scheduled(&ask)
                && v.accepts()
            {
                checks.push(check_scheduled(&context, binding, at, &records));
            } else if let fstp_domain::command::Command::EndRole { binding, at } = &step.cmd {
                checks.push(check_ended(&context, s.view(), *binding, *at, &records));
            }
            checks.push(check_voids(&context, &BTreeMap::new(), &records));
            checks.push(check_suspensions(&context, &BTreeSet::new(), &records));
            match checks.into_iter().find_map(Result::err) {
                Some(e) => Some(next.diverged(e)),
                None => Some(next),
            }
        }
    }
}

/// Runs a step that production decides alone, such as a staff publication
/// or a policy edit, and checks the voids it records against `voids`,
/// computed by the caller from the state before. The step must be accepted.
pub fn unjudged(
    s: &SodMcState,
    step: &Step,
    voids: impl FnOnce(&SodMcState) -> BTreeMap<BindingId, BTreeSet<RuleRef>>,
) -> Option<SodMcState> {
    let expected = voids(s);
    let mut next = s.clone();
    let context = format!("{:?}", step.cmd.kind());
    // Between a scheduled instant and its System end, every account step is
    // refused under SoD-05 (Cooling-off NOTE, W7 fix round 1 reading).
    let window = !crate::reference::sod::due_ends(s.view(), s.world.now).is_empty();
    match next.world.exec(step, Facts::Effective) {
        Err(e) => Some(next.diverged(format!("{context}: {e}"))),
        Ok(Err(r)) if window && r.rule == RuleRef::Sod05 => None,
        Ok(Ok(_)) if window => Some(next.diverged(format!(
            "{context}: accepted between a scheduled instant and its System end"
        ))),
        Ok(Err(r)) => Some(next.diverged(format!(
            "{context}: production refused a step every engine must accept: {r}"
        ))),
        Ok(Ok(records)) => match check_voids(&context, &expected, &records)
            .and_then(|()| check_suspensions(&context, &BTreeSet::new(), &records))
        {
            Ok(()) => Some(next),
            Err(e) => Some(next.diverged(e)),
        },
    }
}

/// Moves the world of `s` to `at` and runs the System commands `due` lists
/// then. The ends must be exactly the scheduled ends the reference finds
/// due, each with the bar pinned at `at` (Cooling-off NOTE).
pub fn arrive(s: &SodMcState, at: fstp_domain::time::Timestamp) -> Option<SodMcState> {
    let mut next = s.clone();
    let before = s.view().clone();
    match next.world.arrive(at) {
        Err(e) => Some(next.diverged(format!("arrive at {at:?}: {e}"))),
        Ok(Err(r)) => Some(next.diverged(format!(
            "arrive at {at:?}: production refused a System command due then: {r}"
        ))),
        Ok(Ok(records)) => match check_due_ends(&before, at, &records) {
            Ok(()) => Some(next),
            Err(e) => Some(next.diverged(e)),
        },
    }
}

/// Changes the vault with `change`, then runs the reaction in the same
/// step (design 6.1). The reaction must be accepted. It must void exactly
/// the Receiving bindings, and suspend exactly the Judging bindings, that
/// the reference expects under the facts the reaction sees.
pub fn vault_step(s: &SodMcState, change: impl FnOnce(&mut GroundTruth)) -> Option<SodMcState> {
    let mut next = s.clone();
    change(&mut next.world.truth);
    react(next)
}

/// Runs the reaction to a newer vault epoch on `next` under its own facts,
/// and checks the voids. Effective facts unless the truth holds a
/// provisional fact, whose reaction sees it (overview NOTE 4).
pub fn react(next: SodMcState) -> Option<SodMcState> {
    let facts = if next.truth().provisional_accounts().is_empty() {
        Facts::Effective
    } else {
        Facts::WithProvisional
    };
    react_with(next, facts)
}

/// Runs the reaction to a newer vault epoch on `next` under `facts`, and
/// checks the voids and the conflict-of-interest suspensions.
pub fn react_with(mut next: SodMcState, facts: Facts) -> Option<SodMcState> {
    let seen = match facts {
        Facts::Effective => next.truth().clone(),
        Facts::WithProvisional => crate::r#gen::roster::reaction_truth(next.truth()),
    };
    let expected = expected_voids(next.view(), &seen);
    let suspensions = expected_suspensions(next.view(), &seen);
    match next.world.sync(facts) {
        Err(e) => Some(next.diverged(format!("vault reaction: {e}"))),
        Ok(Err(r)) => Some(next.diverged(format!(
            "vault reaction: over-denial, production refused VaultChanged with {r}"
        ))),
        Ok(Ok(records)) => match check_voids("vault reaction", &expected, &records)
            .and_then(|()| check_suspensions("vault reaction", &suspensions, &records))
        {
            Ok(()) => Some(next),
            Err(e) => Some(next.diverged(e)),
        },
    }
}

// ---------------------------------------------------------------------------
// M-SOD
// ---------------------------------------------------------------------------

/// One subject of an M-SOD instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodSubject {
    /// The account.
    pub account: AccountId,
    /// Its position, which numbers its bindings and proposals.
    pub index: u8,
    /// The roles it may be granted, by programme.
    pub grants: Vec<(ProgrammeId, Role)>,
    /// Whether it may create drafts.
    pub drafts: bool,
    /// Whether the vault may verify it during the run.
    pub verify: bool,
    /// The most bindings it may create.
    pub max_creations: u8,
}

/// One M-SOD instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodConfig {
    /// The setup from genesis.
    pub setup: SodSetup,
    /// The calls staff may publish, in order per programme.
    pub calls: Vec<CallId>,
    /// The most calls published during the run.
    pub max_publications: usize,
    /// The subjects.
    pub subjects: Vec<SodSubject>,
    /// The identity merges the vault may make: the account takes the
    /// identity, once, and the platform reacts in the same step.
    pub merges: Vec<(AccountId, IdentityTag)>,
    /// Whether ends may be scheduled for [`T_SCHEDULED`], and time may then
    /// move to it (Cooling-off NOTE, decided 2026-10-25).
    pub schedule: bool,
}

/// An M-SOD action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SodAction {
    /// `GrantRole` of `role` in `programme` to `account`.
    Grant {
        /// The account.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
        /// The role.
        role: Role,
    },
    /// `EndRole` of the binding.
    End(BindingId),
    /// `CreateDraft` by `account` in `call`.
    Draft {
        /// The lead.
        account: AccountId,
        /// The call.
        call: CallId,
    },
    /// The vault verifies the account, and the platform reacts in the same step.
    Verify(AccountId),
    /// The staff programme manager publishes the call.
    Publish(CallId),
    /// The vault merges the account into the identity, and the platform
    /// reacts in the same step (Identity discovery, last paragraph).
    Merge {
        /// The account re-tagged.
        account: AccountId,
        /// The identity it takes.
        identity: IdentityTag,
    },
    /// `ReinstateBinding` of a suspended binding by the tenant admin.
    Reinstate(BindingId),
    /// `EndRole` of the binding at a later instant, [`T_EARLIER`] or
    /// [`T_SCHEDULED`]: a scheduled end (Cooling-off NOTE, decided
    /// 2026-10-25). With an end already scheduled, an earlier instant
    /// brings it forward and a later one is refused.
    ScheduleEnd(BindingId, fstp_domain::time::Timestamp),
    /// Time moves to the instant, and nothing runs. Between a scheduled
    /// instant and the System end, every step is checked against the
    /// reference like any other.
    Advance(fstp_domain::time::Timestamp),
    /// The System runs every command that `due` lists now.
    RunDue,
}

/// The earlier of the two scheduled end instants of M-SOD: half a second
/// after `T0`.
pub const T_EARLIER: fstp_domain::time::Timestamp =
    fstp_domain::time::Timestamp::from_micros(1_500_000);

/// The later of the two scheduled end instants of M-SOD: one second after
/// `T0`.
pub const T_SCHEDULED: fstp_domain::time::Timestamp =
    fstp_domain::time::Timestamp::from_micros(2_000_000);

/// The two scheduled end instants of M-SOD, in order.
pub const SCHEDULE_INSTANTS: [fstp_domain::time::Timestamp; 2] = [T_EARLIER, T_SCHEDULED];

/// The id of the `n`-th creation of the subject at `index`.
pub fn creation_id(index: u8, n: u8) -> u128 {
    1_000u128
        .saturating_add(u128::from(index).saturating_mul(10))
        .saturating_add(u128::from(n))
}

/// The M-SOD model (design 6.3).
pub struct SodModel {
    /// The instance.
    pub config: SodConfig,
    /// The start state.
    pub start: SodMcState,
}

impl SodModel {
    /// The model of `config`, with its start state built from genesis.
    pub fn new(config: SodConfig, backend: Backend) -> Result<SodModel, String> {
        let world = SodWorld::from_setup(backend, sod_truth(), &config.setup)?;
        Ok(SodModel {
            config,
            start: SodMcState::new(world),
        })
    }

    fn subject(&self, account: AccountId) -> Option<&SodSubject> {
        self.config.subjects.iter().find(|s| s.account == account)
    }

    fn next_id(&self, s: &SodMcState, account: AccountId) -> Option<u128> {
        let subject = self.subject(account)?;
        let made = s.created.get(&account).copied().unwrap_or(0);
        (made < subject.max_creations).then(|| creation_id(subject.index, made.saturating_add(1)))
    }

    fn published(&self, s: &SodMcState) -> usize {
        self.config
            .calls
            .iter()
            .filter(|c| s.view().calls.get(c).is_some_and(|r| r.seq.is_some()))
            .count()
    }
}

/// Counts one creation of `account` when the step created a binding.
fn count(mut s: SodMcState, before: usize, account: AccountId) -> SodMcState {
    if s.view().bindings.len() > before {
        let n = s.created.entry(account).or_insert(0);
        *n = n.saturating_add(1);
    }
    s
}

impl Model for SodModel {
    type State = SodMcState;
    type Action = SodAction;

    fn init(&self) -> Vec<SodMcState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &SodMcState, actions: &mut Vec<SodAction>) {
        for subject in &self.config.subjects {
            for (programme, role) in &subject.grants {
                actions.push(SodAction::Grant {
                    account: subject.account,
                    programme: *programme,
                    role: *role,
                });
            }
            if subject.drafts {
                for c in &self.config.calls {
                    if s.view().calls.get(c).is_some_and(|r| r.seq.is_some()) {
                        actions.push(SodAction::Draft {
                            account: subject.account,
                            call: *c,
                        });
                    }
                }
            }
            if subject.verify && !s.truth().is_verified(subject.account) {
                actions.push(SodAction::Verify(subject.account));
            }
        }
        for b in s.view().bindings.values() {
            // An open binding under a conflict-of-interest suspension can end too.
            if b.open() && self.subject(b.account).is_some() && b.group != RefGroup::Receiving {
                actions.push(SodAction::End(b.binding));
            }
            if b.suspended && self.subject(b.account).is_some() {
                actions.push(SodAction::Reinstate(b.binding));
            }
        }
        if self.config.schedule {
            let now = s.world.now;
            let mut any = false;
            for b in s.view().bindings.values() {
                if b.open() && self.subject(b.account).is_some() && b.group != RefGroup::Receiving {
                    any |= b.scheduled_end.is_some();
                    for t in SCHEDULE_INSTANTS {
                        // Scheduling, bringing forward and the refused move
                        // later. The same instant again changes nothing.
                        if t > now && b.scheduled_end != Some(t) {
                            actions.push(SodAction::ScheduleEnd(b.binding, t));
                        }
                    }
                }
            }
            if any {
                for t in SCHEDULE_INSTANTS {
                    if t > now {
                        actions.push(SodAction::Advance(t));
                    }
                }
            }
            if !crate::reference::sod::due_ends(s.view(), now).is_empty() {
                actions.push(SodAction::RunDue);
            }
        }
        for (account, identity) in &self.config.merges {
            if s.truth().identity_of(*account) != Some(*identity) {
                actions.push(SodAction::Merge {
                    account: *account,
                    identity: *identity,
                });
            }
        }
        if self.published(s) < self.config.max_publications {
            let mut seen = BTreeSet::new();
            for c in &self.config.calls {
                let Some(r) = s.view().calls.get(c) else {
                    continue;
                };
                if r.seq.is_none() && seen.insert(r.programme) {
                    actions.push(SodAction::Publish(*c));
                }
            }
        }
    }

    fn step(&self, s: &SodMcState, a: &SodAction) -> Option<SodMcState> {
        if s.divergence.is_some() {
            return None;
        }
        match a {
            SodAction::Grant {
                account,
                programme,
                role,
            } => {
                let id = self.next_id(s, *account)?;
                let step = grant(
                    BindingId::from_raw(id),
                    *account,
                    *programme,
                    *role,
                    s.world.now,
                );
                let n = s.view().bindings.len();
                judged(s, &step).map(|t| count(t, n, *account))
            }
            SodAction::End(binding) => judged(s, &end(*binding, s.world.now)),
            SodAction::ScheduleEnd(binding, at) => {
                let earlier = s
                    .view()
                    .bindings
                    .get(binding)
                    .and_then(|b| b.scheduled_end)
                    .is_some_and(|x| *at < x);
                judged(s, &end(*binding, *at)).map(|mut t| {
                    t.brought_forward |= earlier && t.divergence.is_none();
                    t
                })
            }
            SodAction::Advance(at) => {
                let mut next = s.clone();
                next.world.now = *at;
                Some(next)
            }
            SodAction::RunDue => arrive(s, s.world.now),
            SodAction::Draft { account, call } => {
                let id = self.next_id(s, *account)?;
                let step = draft(
                    *account,
                    ProposalId::from_raw(id),
                    *call,
                    BindingId::from_raw(id),
                    false,
                );
                let n = s.view().bindings.len();
                judged(s, &step).map(|t| count(t, n, *account))
            }
            SodAction::Verify(account) => {
                if s.truth().is_verified(*account) {
                    return None;
                }
                let account = *account;
                vault_step(s, |t| t.verify(account))
            }
            SodAction::Publish(c) => unjudged(s, &publish(*c), |_| BTreeMap::new()),
            SodAction::Merge { account, identity } => {
                if s.truth().identity_of(*account) == Some(*identity) {
                    return None;
                }
                let (account, identity) = (*account, *identity);
                vault_step(s, |t| t.set_identity(account, identity))
            }
            SodAction::Reinstate(binding) => judged(s, &reinstate(*binding)),
        }
    }

    fn is_terminal(&self, s: &SodMcState) -> bool {
        s.divergence.is_some()
    }
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

/// The state counts of the M-SOD instances, measured on the production
/// backend in step W6. Each run stops at twice its count, so growth fails
/// visibly. The reference backend stores the same count or fewer. For the
/// I-01 instances at P-12 = 0, 1 and 2, for I-02 and for I-06, production
/// refines the reference states by its projection only: with the
/// projection removed, the two state sets are equal (step W6 audit).
pub const M_SOD_I01_P12_0_STATES: usize = 1_370;
/// See [`M_SOD_I01_P12_0_STATES`].
pub const M_SOD_I01_P12_1_STATES: usize = 1_225;
/// See [`M_SOD_I01_P12_0_STATES`].
pub const M_SOD_I01_P12_2_STATES: usize = 1_174;
/// See [`M_SOD_I01_P12_0_STATES`].
pub const M_SOD_TWO_PROGRAMMES_STATES: usize = 713;
/// See [`M_SOD_I01_P12_0_STATES`].
pub const M_SOD_I02_STATES: usize = 252;
/// See [`M_SOD_I01_P12_0_STATES`]. The reference backend stores 98_387
/// states.
pub const M_SOD_I06_STATES: usize = 149_961;

/// The state counts of the M-SOD instances on the reference backend, where
/// they differ from production. Each `_reference` twin stops at twice its
/// own count, so growth on the reference fails visibly too (design 6.1).
pub const M_SOD_I01_P12_0_REFERENCE_STATES: usize = 1_300;
/// See [`M_SOD_I01_P12_0_REFERENCE_STATES`].
pub const M_SOD_I01_P12_1_REFERENCE_STATES: usize = 1_155;
/// See [`M_SOD_I01_P12_0_REFERENCE_STATES`].
pub const M_SOD_I01_P12_2_REFERENCE_STATES: usize = 1_104;
/// See [`M_SOD_I01_P12_0_REFERENCE_STATES`].
pub const M_SOD_I02_REFERENCE_STATES: usize = 227;
/// See [`M_SOD_I01_P12_0_REFERENCE_STATES`].
pub const M_SOD_I06_REFERENCE_STATES: usize = 98_387;

/// The calls of the one-programme instances.
pub const SOD_CALLS: [u128; 3] = [1, 2, 3];

/// I-01 at `p12`: c may be a programme manager, a committee member or an
/// IRC member and may draft, with at most two bindings, and staff publish up to three calls.
pub fn i01_config(p12: u8) -> SodConfig {
    SodConfig {
        setup: SodSetup::one(p12, &SOD_CALLS),
        calls: SOD_CALLS.iter().map(|n| call(*n)).collect(),
        max_publications: 3,
        subjects: vec![SodSubject {
            account: C,
            index: 3,
            grants: vec![
                (P1, Role::ProgrammeManager),
                (P1, Role::CommitteeMember),
                (P1, Role::IrcMember),
            ],
            drafts: true,
            verify: false,
            max_creations: 2,
        }],
        merges: Vec::new(),
        schedule: false,
    }
}

/// I-01 across programmes: c may be a programme manager in either programme
/// and may draft, with at most two bindings. Programme 1 has one call and
/// programme 2 two.
pub fn two_programmes_config() -> SodConfig {
    let calls = vec![(P1, call(1)), (P2, call(21)), (P2, call(22))];
    SodConfig {
        setup: SodSetup {
            programmes: vec![P1, P2],
            p12: 1,
            p13: BTreeSet::new(),
            calls: calls.clone(),
            published: Vec::new(),
        },
        calls: calls.into_iter().map(|(_, c)| c).collect(),
        max_publications: 3,
        subjects: vec![SodSubject {
            account: C,
            index: 3,
            grants: vec![(P1, Role::ProgrammeManager), (P2, Role::ProgrammeManager)],
            drafts: true,
            verify: false,
            max_creations: 2,
        }],
        merges: Vec::new(),
        schedule: false,
    }
}

/// I-02: c may hold committee member, committee chair or IRC member, with
/// at most two bindings, and staff publish one call.
pub fn i02_config() -> SodConfig {
    SodConfig {
        setup: SodSetup::one(1, &[1]),
        calls: vec![call(1)],
        max_publications: 1,
        subjects: vec![SodSubject {
            account: C,
            index: 3,
            grants: vec![
                (P1, Role::CommitteeMember),
                (P1, Role::CommitteeChair),
                (P1, Role::IrcMember),
            ],
            drafts: false,
            verify: false,
            max_creations: 2,
        }],
        merges: Vec::new(),
        schedule: false,
    }
}

/// I-06: a may be a committee member or a programme manager; b, the
/// unverified Sybil of a, may be a committee member or draft, and the vault
/// may verify it. c, another identity, may be a committee member or a
/// programme manager, or draft. The vault may merge c into the identity of
/// a and b, once. Each subject creates at most one binding, and staff
/// publish up to two calls.
pub fn i06_config() -> SodConfig {
    SodConfig {
        setup: SodSetup::one(1, &[1, 2]),
        calls: vec![call(1), call(2)],
        max_publications: 2,
        subjects: vec![
            SodSubject {
                account: A,
                index: 1,
                grants: vec![(P1, Role::CommitteeMember), (P1, Role::ProgrammeManager)],
                drafts: false,
                verify: false,
                max_creations: 1,
            },
            SodSubject {
                account: B,
                index: 2,
                grants: vec![(P1, Role::CommitteeMember)],
                drafts: true,
                verify: true,
                max_creations: 1,
            },
            SodSubject {
                account: C,
                index: 3,
                grants: vec![(P1, Role::CommitteeMember), (P1, Role::ProgrammeManager)],
                drafts: true,
                verify: false,
                max_creations: 1,
            },
        ],
        merges: vec![(C, ID_AB)],
        schedule: false,
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// `always("two-way")`: production and the reference agree on every step,
/// in both directions, including the records of accepted steps.
pub fn two_way<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("two-way", |s| match &s.divergence {
        None => Ok(()),
        Some(d) => Err(format!("two-way: {d}")),
    })
}

/// `always("I-01")` over the reference view.
pub fn always_i01<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("I-01", |s| check_i01(s.view()))
}

/// `transition("SoD-01")`: no step creates a binding while the same account
/// holds one of another group among Drafting, Judging and Receiving.
pub fn transition_sod01<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("SoD-01", |before, _, after| {
        for b in new_bindings(before.view(), after.view()) {
            for x in before.view().bindings_of(b.account, b.programme) {
                if x.held() && x.group.separated() && b.group.separated() && x.group != b.group {
                    return Err(format!(
                        "SoD-01: {:?} {:?} granted while {:?} {:?} is held",
                        b.role, b.binding, x.role, x.binding
                    ));
                }
            }
        }
        Ok(())
    })
}

/// Whether the new binding `b` falls inside the bar of `x` in `before`.
fn inside_bar(before: &View, x: &RefBinding, b: &RefBinding) -> Option<u32> {
    if x.group == b.group || !x.group.separated() || !b.group.separated() {
        return None;
    }
    let bar = x.bar()?;
    let barred = match b.group {
        RefGroup::Receiving => b.call_seq.is_none_or(|seq| seq <= bar),
        _ => before.latest(b.programme) <= bar,
    };
    barred.then_some(bar)
}

/// `transition("SoD-05")`: no step creates a binding inside the bar of an
/// ended binding of another group of the same account, and every recorded
/// end pins the reference's bar.
pub fn transition_sod05<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("SoD-05", |before, _, after| {
        for b in new_bindings(before.view(), after.view()) {
            for x in before.view().bindings_of(b.account, b.programme) {
                if let Some(bar) = inside_bar(before.view(), x, b) {
                    return Err(format!(
                        "SoD-05: {:?} {:?} granted inside the bar {bar} of {:?} {:?}",
                        b.role, b.binding, x.role, x.binding
                    ));
                }
            }
        }
        check_bars(after.view())
    })
}

/// `always("I-02")` over the reference view.
pub fn always_i02<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("I-02", |s| check_i02(s.view()))
}

/// `transition("SoD-02")`: no step grants an IRC binding to an account that
/// holds another Judging role, or the reverse.
pub fn transition_sod02<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("SoD-02", |before, _, after| {
        for b in new_bindings(before.view(), after.view()) {
            for x in before.view().bindings_of(b.account, b.programme) {
                let clash = (b.role == Role::IrcMember && other_judging(x.role))
                    || (other_judging(b.role) && x.role == Role::IrcMember);
                if clash && x.held() {
                    return Err(format!(
                        "SoD-02: {:?} {:?} granted while {:?} {:?} is held",
                        b.role, b.binding, x.role, x.binding
                    ));
                }
            }
        }
        Ok(())
    })
}

/// `always("I-06")` over the reference view and the vault's effective facts.
pub fn always_i06<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("I-06", |s| check_i06(s.view(), s.truth()))
}

/// `transition("SoD-09")`: no step creates a Drafting or Judging binding for
/// an account that was not verified before the step.
pub fn transition_sod09<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("SoD-09", |before, _, after| {
        for b in new_bindings(before.view(), after.view()) {
            if b.group.needs_verification() && !before.truth().is_verified(b.account) {
                return Err(format!(
                    "SoD-09: {:?} {:?} granted to unverified {:?}",
                    b.role, b.binding, b.account
                ));
            }
            if b.group.needs_verification() && b.verified_epoch.is_none() {
                return Err(format!(
                    "SoD-09: {:?} {:?} records no SoD-09 answer epoch",
                    b.role, b.binding
                ));
            }
        }
        Ok(())
    })
}

/// The ended `role` bindings and held `later` bindings of one account, with
/// `later` granted after the end.
fn after_end_pairs(
    view: &View,
    role: Role,
    later: Role,
) -> impl Iterator<Item = (&RefBinding, &RefBinding)> {
    view.bindings.values().flat_map(move |x| {
        view.bindings.values().filter_map(move |y| {
            (x.role == role
                && x.end.is_some()
                && y.role == later
                && y.held()
                && y.account == x.account
                && y.programme == x.programme
                && view.granted_after_end(x.binding, y.binding))
            .then_some((x, y))
        })
    })
}

/// Witness: a former programme manager holds Applicant in the first call
/// after the bar: the P-12 calls after the end are barred, the next is open.
pub fn former_pm_applicant_in_first_open_call(s: &SodMcState) -> bool {
    after_end_pairs(s.view(), Role::ProgrammeManager, Role::Applicant).any(|(x, y)| {
        x.bar()
            .is_some_and(|bar| y.call_seq == Some(bar.saturating_add(1)))
    })
}

/// Witness: a former programme manager holds a Judging role, granted when
/// the latest published call was the first after the bar.
pub fn former_pm_judging_after_bar(s: &SodMcState) -> bool {
    after_end_pairs(s.view(), Role::ProgrammeManager, Role::CommitteeMember).any(|(x, y)| {
        x.bar()
            .is_some_and(|bar| y.latest_at_start == bar.saturating_add(1))
    })
}

/// Witness: a call was published while a programme manager binding was
/// held, and its bar covers that call.
pub fn call_published_while_held(s: &SodMcState) -> bool {
    s.view().bindings.values().any(|x| {
        x.role == Role::ProgrammeManager
            && x.end.is_some_and(|e| e.latest_at_end > x.latest_at_start)
    })
}

/// Witness: a committee member became an IRC member after the committee binding ended.
pub fn committee_member_then_irc(s: &SodMcState) -> bool {
    after_end_pairs(s.view(), Role::CommitteeMember, Role::IrcMember)
        .next()
        .is_some()
}

/// Witness: one account holds committee member and committee chair at once.
pub fn member_and_chair(s: &SodMcState) -> bool {
    let v = s.view();
    v.bindings.values().any(|x| {
        x.role == Role::CommitteeMember
            && x.held()
            && v.bindings_of(x.account, x.programme)
                .any(|y| y.role == Role::CommitteeChair && y.held())
    })
}

/// Witness: the Sybil b's Receiving binding was voided under I-06 at its
/// verification, while a's committee binding stays.
pub fn sybil_voided_at_verification(s: &SodMcState) -> bool {
    let v = s.view();
    s.truth().is_verified(B)
        && v.bindings
            .values()
            .any(|b| b.account == B && b.voided == Some(RuleRef::I06))
        && v.bindings
            .values()
            .any(|b| b.account == A && b.role == Role::CommitteeMember && b.held())
}

/// Witness: a distinct identity, c, holds Applicant while a holds a
/// committee binding. GRANTED needs the lifecycle and lands in W4.
pub fn distinct_identity_applies(s: &SodMcState) -> bool {
    let v = s.view();
    s.truth().identity_of(C) != s.truth().identity_of(A)
        && v.bindings
            .values()
            .any(|b| b.account == C && b.role == Role::Applicant && b.held())
        && v.bindings
            .values()
            .any(|b| b.account == A && b.role == Role::CommitteeMember && b.held())
}

/// Witness: after an identity merge, a Judging binding is under a
/// conflict-of-interest suspension, while a Drafting binding of another
/// account of the same verified identity stays unsuspended.
pub fn judging_suspended_drafting_stays(s: &SodMcState) -> bool {
    let v = s.view();
    let t = s.truth();
    v.bindings.values().any(|j| {
        j.group == RefGroup::Judging
            && j.conflict_of_interest
            && t.verified_identity(j.account).is_some_and(|id| {
                v.bindings.values().any(|d| {
                    d.group == RefGroup::Drafting
                        && d.account != j.account
                        && !d.suspended
                        && t.verified_identity(d.account) == Some(id)
                })
            })
    })
}

/// Witness: the Judging binding of a, the account the merge did not
/// re-tag, is under a conflict-of-interest suspension.
pub fn unchanged_account_judging_suspended(s: &SodMcState) -> bool {
    s.view()
        .bindings
        .values()
        .any(|b| b.account == A && b.conflict_of_interest)
}

/// Witness: an ended Judging binding is under a conflict-of-interest
/// suspension, so its bar never counts.
pub fn ended_judging_suspended(s: &SodMcState) -> bool {
    s.view()
        .bindings
        .values()
        .any(|b| b.conflict_of_interest && b.end.is_some() && b.bar().is_none())
}

/// Witness: one account holds a programme manager binding in one programme
/// and Applicant in the other.
pub fn bound_in_both_programmes(s: &SodMcState) -> bool {
    let v = s.view();
    v.bindings.values().any(|x| {
        x.role == Role::ProgrammeManager
            && x.held()
            && v.bindings.values().any(|y| {
                y.account == x.account
                    && y.programme != x.programme
                    && y.role == Role::Applicant
                    && y.held()
            })
    })
}

/// The I-01 properties of M-SOD with its witnesses.
pub fn i01_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i01::<M>(),
        transition_sod01::<M>(),
        transition_sod05::<M>(),
        Property::<M>::reachable(
            "SoD-05 witness: a former programme manager holds Applicant in the first open call",
            former_pm_applicant_in_first_open_call,
        ),
        Property::<M>::reachable(
            "SoD-05 witness: a former programme manager holds a Judging role after the bar",
            former_pm_judging_after_bar,
        ),
        Property::<M>::reachable(
            "SoD-05 witness: a call published while a binding is held",
            call_published_while_held,
        ),
    ]
}

/// The I-01 properties of the two-programme instance with its witness.
pub fn two_programmes_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i01::<M>(),
        transition_sod01::<M>(),
        transition_sod05::<M>(),
        Property::<M>::reachable(
            "I-01 witness: a binding in one programme never counts in the other",
            bound_in_both_programmes,
        ),
    ]
}

/// The I-02 properties with their witnesses.
pub fn i02_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i02::<M>(),
        transition_sod02::<M>(),
        always_i01::<M>(),
        Property::<M>::reachable(
            "SoD-02 witness: a committee member becomes an IRC member after the committee binding ends",
            committee_member_then_irc,
        ),
        Property::<M>::reachable(
            "SoD-02 witness: committee member and chair held together",
            member_and_chair,
        ),
    ]
}

/// The I-06 properties with their witnesses.
pub fn i06_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i06::<M>(),
        transition_sod09::<M>(),
        always_i01::<M>(),
        Property::<M>::reachable(
            "I-06 witness: the Sybil is voided at verification",
            sybil_voided_at_verification,
        ),
        Property::<M>::reachable(
            "I-06 witness: a distinct identity applies while a Judging binding is held",
            distinct_identity_applies,
        ),
        Property::<M>::reachable(
            "I-06 witness: a merge suspends the Judging binding as a conflict of interest and the Drafting binding stays",
            judging_suspended_drafting_stays,
        ),
        Property::<M>::reachable(
            "I-06 witness: the Judging binding of the account the merge did not re-tag is suspended",
            unchanged_account_judging_suspended,
        ),
        Property::<M>::reachable(
            "I-06 witness: an ended Judging binding under a conflict-of-interest suspension pins no bar",
            ended_judging_suspended,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Faults for the teeth tests
// ---------------------------------------------------------------------------

/// The fault of `i01_teeth_binding_inside_window_is_caught`: a broken
/// engine records a draft of c in a published call inside the bar of c's
/// ended programme manager binding.
pub fn fault_receiving_inside_window(s: &SodMcState) -> Option<SodMcState> {
    let v = s.view();
    let (x, target) = v.bindings.values().find_map(|x| {
        if x.account != C || x.role != Role::ProgrammeManager {
            return None;
        }
        let bar = x.bar()?;
        let target = v.calls.iter().find_map(|(id, c)| {
            (c.programme == x.programme && c.seq.is_some_and(|seq| seq <= bar)).then_some(*id)
        })?;
        Some((x, target))
    })?;
    let proposal = ProposalId::from_raw(9_000);
    let binding = BindingId::from_raw(9_000);
    if v.proposals.contains_key(&proposal) {
        return None;
    }
    let records = vec![
        Record::ProposalCreated {
            proposal,
            call: target,
            lead: x.account,
            minor: false,
        },
        injected_grant(
            binding,
            x.account,
            x.programme,
            Role::Applicant,
            Some((proposal, target)),
        ),
    ];
    inject(s, &records)
}

/// The fault of `i02_teeth_irc_with_assignment_is_caught`: a broken engine
/// grants c an IRC binding while c holds a committee binding.
pub fn fault_irc_beside_committee(s: &SodMcState) -> Option<SodMcState> {
    let v = s.view();
    let x = v
        .bindings
        .values()
        .find(|b| b.account == C && b.role == Role::CommitteeMember && b.held())?;
    let binding = BindingId::from_raw(9_001);
    if v.bindings.contains_key(&binding) {
        return None;
    }
    inject(
        s,
        &[injected_grant(
            binding,
            x.account,
            x.programme,
            Role::IrcMember,
            None,
        )],
    )
}

/// The fault of `i06_teeth_sybil_left_bound_is_caught`: the vault verifies
/// b, and a broken reaction records the new epoch without voiding b's
/// Receiving binding while a holds a committee binding.
pub fn fault_sybil_left_bound(s: &SodMcState) -> Option<SodMcState> {
    if s.truth().is_verified(B) {
        return None;
    }
    let v = s.view();
    let held = |account, group| {
        v.bindings
            .values()
            .any(|b| b.account == account && b.group == group && b.held())
    };
    if !(held(A, RefGroup::Judging) && held(B, RefGroup::Receiving)) {
        return None;
    }
    let mut next = s.clone();
    next.world.truth.verify(B);
    let epoch = next.world.truth.epoch();
    let records = vec![Record::VaultEpochProcessed { epoch }];
    match next.world.commit(&records) {
        Ok(()) => Some(next),
        Err(_) => None,
    }
}

/// The fault of `i06_teeth_conflict_suspension_counted_as_held_is_caught`:
/// the vault merges c into the identity of a and b while one of a and c
/// holds a Drafting binding and the other a Judging one. A broken reaction
/// suspends the Judging binding under a rule other than I-06. That is not
/// the conflict-of-interest marker, so the binding still counts as held.
pub fn fault_conflict_suspension_counted_as_held(s: &SodMcState) -> Option<SodMcState> {
    if s.truth().identity_of(C) == Some(ID_AB) {
        return None;
    }
    let v = s.view();
    let open = |account, group| {
        v.bindings
            .values()
            .find(|b| b.account == account && b.group == group && b.open() && !b.suspended)
            .map(|b| b.binding)
    };
    let judging = match (
        open(A, RefGroup::Drafting),
        open(C, RefGroup::Judging),
        open(C, RefGroup::Drafting),
        open(A, RefGroup::Judging),
    ) {
        (Some(_), Some(j), _, _) | (_, _, Some(_), Some(j)) => j,
        _ => return None,
    };
    let mut next = s.clone();
    next.world.truth.set_identity(C, ID_AB);
    let epoch = next.world.truth.epoch();
    let records = vec![
        Record::BindingSuspended(BindingSuspended {
            binding: judging,
            rule: RuleRef::I01,
            epoch,
        }),
        Record::VaultEpochProcessed { epoch },
    ];
    next.world.commit(&records).ok()?;
    Some(next)
}

/// The fault of
/// `i06_teeth_conflict_suspension_reinstated_during_the_clash_is_caught`:
/// a broken engine reinstates a Judging binding under a conflict-of-interest
/// suspension while the identity clash lasts. In M-SOD a merge is never
/// undone, so the clash lasts for the rest of the run.
pub fn fault_conflict_suspension_reinstated(s: &SodMcState) -> Option<SodMcState> {
    let b = s
        .view()
        .bindings
        .values()
        .find(|b| b.conflict_of_interest && b.open())?;
    inject(
        s,
        &[Record::BindingReinstated(BindingReinstated {
            binding: b.binding,
            by: crate::r#gen::roster::ADMIN,
            reason: crate::r#gen::policy::text(9_002),
        })],
    )
}

/// A `BindingGranted` as a broken engine would record it, with a SoD-09
/// epoch so that only the target property can catch it.
pub fn injected_grant(
    binding: BindingId,
    account: AccountId,
    programme: ProgrammeId,
    role: Role,
    proposal: Option<(ProposalId, CallId)>,
) -> Record {
    Record::BindingGranted(fstp_domain::record::BindingGranted {
        binding,
        account,
        programme,
        role,
        scope: match proposal {
            Some((proposal, call)) => fstp_domain::roles::BindingScope::Proposal { proposal, call },
            None => fstp_domain::roles::BindingScope::Programme,
        },
        start: T0,
        granted_by: crate::r#gen::roster::ADMIN,
        second_admin: None,
        confidentiality: None,
        organisation: None,
        verified_epoch: Some(VaultEpoch::GENESIS),
    })
}

/// Folds `records` into a copy of `s` through the public structural
/// `apply` and the reference fold, as a broken engine's batch. `None` when
/// either fold refuses.
pub fn inject(s: &SodMcState, records: &[Record]) -> Option<SodMcState> {
    let mut next = s.clone();
    next.world.commit(records).ok()?;
    Some(next)
}

// ---------------------------------------------------------------------------
// Scheduled ends (Cooling-off NOTE, decided 2026-10-25)
// ---------------------------------------------------------------------------

/// The measured state count of the scheduled end instance on production
/// (W7 fix round 1, design 6.1), with two instants, the bring-forward and
/// a time step apart from the System end. The run's tripwire is twice this.
pub const M_SOD_SCHEDULED_STATES: usize = 12_468;
/// The measured state count of the scheduled end instance on the
/// reference alone (W7 fix round 1). See [`M_SOD_SCHEDULED_STATES`].
pub const M_SOD_SCHEDULED_REFERENCE_STATES: usize = 11_829;

/// The scheduled end instance: P-12 = 1, calls 1 to 3, and c may be a
/// programme manager or a committee member and may draft, with at most
/// two bindings. Staff publish up to two calls. Any open binding of c may
/// have its end scheduled for [`T_EARLIER`] or [`T_SCHEDULED`], brought
/// forward or, refused, moved later. Time moves to either instant on its
/// own, and the System runs the ends due as a separate step. So every step
/// between an instant and its System end is model-checked too.
pub fn scheduled_config() -> SodConfig {
    SodConfig {
        setup: SodSetup::one(1, &SOD_CALLS),
        calls: SOD_CALLS.iter().map(|n| call(*n)).collect(),
        max_publications: 2,
        subjects: vec![SodSubject {
            account: C,
            index: 3,
            grants: vec![(P1, Role::ProgrammeManager), (P1, Role::CommitteeMember)],
            drafts: true,
            verify: false,
            max_creations: 2,
        }],
        merges: Vec::new(),
        schedule: true,
    }
}

/// Witness: a binding with a scheduled end is still held.
pub fn scheduled_and_held(s: &SodMcState) -> bool {
    s.view()
        .bindings
        .values()
        .any(|x| x.scheduled_end.is_some() && x.held())
}

/// Witness: the System ended a binding at its scheduled instant, and a
/// call published after the binding started counts in its bar.
pub fn scheduled_end_counts_a_later_call(s: &SodMcState) -> bool {
    s.view().bindings.values().any(|x| {
        x.end
            .is_some_and(|e| x.scheduled_end == Some(e.at) && e.latest_at_end > x.latest_at_start)
    })
}

/// Witness: a scheduled end was brought forward, and the System ended the
/// binding at the earlier instant [`T_EARLIER`].
pub fn scheduled_end_brought_forward(s: &SodMcState) -> bool {
    s.brought_forward
        && s.view()
            .bindings
            .values()
            .any(|x| x.scheduled_end == Some(T_EARLIER) && x.end.is_some_and(|e| e.at == T_EARLIER))
}

/// Witness: time stands between a scheduled instant and the System end,
/// so every step from here is checked inside that window.
pub fn inside_the_window(s: &SodMcState) -> bool {
    !crate::reference::sod::due_ends(s.view(), s.world.now).is_empty()
}

/// `transition("Cooling-off window")`: from a scheduled instant until the
/// System records the end, no step records anything but those ends, each
/// at its instant with the bar of the reference then (Cooling-off NOTE,
/// decided 2026-10-25; W7 fix round 1 reading). So nothing reads the
/// binding as held after its instant, and the bar counts only the calls
/// published by then.
pub fn transition_window<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::transition_with("Cooling-off window", |before, _, after| {
        let due = crate::reference::sod::due_ends(before.view(), before.world.now);
        if due.is_empty() || after.view() == before.view() {
            return Ok(());
        }
        let mut expected = before.view().clone();
        for (binding, at) in due {
            let (bar, p12) = crate::reference::sod::expected_end(before.view(), binding)
                .ok_or_else(|| format!("unknown binding {binding:?}"))?;
            expected.fold(&Record::BindingEnded(fstp_domain::record::BindingEnded {
                binding,
                at,
                barred_through: bar,
                p12: fstp_domain::roles::CoolingOff(p12),
            }))?;
        }
        if after.view() == &expected {
            Ok(())
        } else {
            Err("Cooling-off NOTE: a step between a scheduled instant and its System end recorded more than those ends".to_owned())
        }
    })
}

/// `always("Cooling-off scheduled end")`: no binding ends after its
/// scheduled instant, so a scheduled end is never moved later.
pub fn always_scheduled_end_kept<'a, M: Model<State = SodMcState>>() -> Property<'a, M> {
    Property::<M>::always_with("Cooling-off scheduled end", |s| {
        for x in s.view().bindings.values() {
            if let (Some(e), Some(at)) = (x.end, x.scheduled_end)
                && e.at > at
            {
                return Err(format!(
                    "Cooling-off NOTE: {:?} ended at {:?}, after its scheduled end {at:?}",
                    x.binding, e.at
                ));
            }
        }
        Ok(())
    })
}

/// The properties of the scheduled end instance with its witnesses.
pub fn scheduled_properties<'a, M: Model<State = SodMcState>>() -> Vec<Property<'a, M>> {
    vec![
        two_way::<M>(),
        always_i01::<M>(),
        transition_sod01::<M>(),
        transition_sod05::<M>(),
        always_scheduled_end_kept::<M>(),
        transition_window::<M>(),
        Property::<M>::reachable(
            "Cooling-off witness: a binding with a scheduled end is held",
            scheduled_and_held,
        ),
        Property::<M>::reachable(
            "Cooling-off witness: a scheduled end pinned at the instant counts a later call",
            scheduled_end_counts_a_later_call,
        ),
        Property::<M>::reachable(
            "Cooling-off witness: a scheduled end brought forward ends the binding at the earlier instant",
            scheduled_end_brought_forward,
        ),
        Property::<M>::reachable(
            "Cooling-off witness: time stands between a scheduled instant and the System end",
            inside_the_window,
        ),
        Property::<M>::reachable(
            "SoD-05 witness: a former programme manager holds Applicant in the first open call",
            former_pm_applicant_in_first_open_call,
        ),
    ]
}

/// The fault of `i01_teeth_grant_inside_the_scheduled_end_window_is_caught`:
/// between a scheduled instant and its System end, a broken engine grants
/// c an auditor binding. Only the window property can catch it, since an
/// Operations binding breaks no SoD rule here.
pub fn fault_grant_inside_the_window(s: &SodMcState) -> Option<SodMcState> {
    if !inside_the_window(s) {
        return None;
    }
    let binding = BindingId::from_raw(9_100);
    if s.view().bindings.contains_key(&binding) {
        return None;
    }
    inject(s, &[injected_grant(binding, C, P1, Role::Auditor, None)])
}
