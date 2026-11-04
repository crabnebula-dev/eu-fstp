//! The M-POLICY model for fstp-mc, the I-12 predicates and the read adapter (design sections 6.2 and 6.3).
//!
//! - [`reads`] is the one place where the policy suites read production
//!   structures. It reads what design 2.4 point 3 says every guard reads:
//!   the frozen policy of a published call, and the programme head.
//! - [`check_i12`] is the I-12 predicate over a reference ghost, the
//!   ledger and the projection. It never reuses guard code.
//! - [`PolicyModel`] is M-POLICY at the policy level: two calls of one
//!   programme, P-02 in {50.00, 75.00}, P-03 in {1, 2} and at most two
//!   edits. Its start state is built from genesis by production commands.
//!
//! The engine-wide twin `i12_frozen_edits_leave_call_outcomes_unchanged`
//! needs the lifecycle and lands in step W6.

use std::collections::BTreeMap;
use std::num::NonZeroU8;

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{CallId, LlmConfigId, PolicyVersionId};
use fstp_domain::policy::{ExclusionClasses, FrozenPolicy, FrozenValues, PolicyVersion};
use fstp_domain::record::Record;
use fstp_domain::state::State;
use fstp_engine::Record as EngineRecord;
use fstp_ledger::Entry;
use fstp_mc::{Model, Property};
use fstp_money::{NonNegAmount, Percent};

use crate::r#gen::policy::{DRAFTER_1, P1, PM_A, PM_B, PolicyWorld, next_version};
use crate::harness::prop::ledger_step;
use crate::reference::policy::{Ghost, Verdict};
use crate::scenario::Scenario;

// ---------------------------------------------------------------------------
// The read adapter
// ---------------------------------------------------------------------------

/// The production read API the policy suites need (design 2.4 point 3, 2.5).
///
/// Each read is one call into the lane L-POL read API:
/// - `fstp_domain::policy::frozen_policy(&State, CallId) -> Option<&FrozenPolicy>`,
///   the frozen read for a call;
/// - `fstp_domain::policy::head(&State, ProgrammeId) -> Option<&PolicyVersion>`;
/// - `fstp_domain::programme::latest_published_seq(&State, ProgrammeId) -> Option<CallSeq>`,
///   the read lane L-SOD pins cooling-off bars with;
/// - `fstp_domain::policy::effective_p05` and `effective_p13`, the limits a
///   call enforces now (NOTE 7), which lanes L-MONEY and L-SOD read;
/// - `fstp_domain::policy::call_allows_mcp_binding`, the frozen P-77 read of
///   the MCP path (R-MC-05);
/// - `fstp_domain::programme::{call, is_open_at, next_published_call, drafters}`.
///
/// Ownership note: the implementer first wired these reads to the
/// production API. The test author reviewed each one and owns the module
/// from fix round 1 on. Each read stays one call with no test logic.
pub mod reads {
    use std::collections::BTreeSet;

    use fstp_domain::id::{AccountId, CallId, CallSeq, LlmConfigId, ProgrammeId};
    use fstp_domain::policy::{ExclusionClasses, PolicyVersion};
    use fstp_domain::state::State;
    use fstp_domain::time::Timestamp;
    use fstp_money::NonNegAmount;

    use super::FrozenView;

    /// The frozen policy of `call`, or `None` while it is unpublished.
    pub fn frozen_policy(state: &State, call: CallId) -> Result<Option<FrozenView>, String> {
        Ok(fstp_domain::policy::frozen_policy(state, call).map(FrozenView::of))
    }

    /// The head policy version of `programme`, or `None` for an unknown programme.
    pub fn head(state: &State, programme: ProgrammeId) -> Result<Option<PolicyVersion>, String> {
        Ok(fstp_domain::policy::head(state, programme).cloned())
    }

    /// The sequence number of the latest call published in `programme`.
    pub fn latest_published_seq(
        state: &State,
        programme: ProgrammeId,
    ) -> Result<Option<CallSeq>, String> {
        Ok(fstp_domain::programme::latest_published_seq(
            state, programme,
        ))
    }

    /// The P-05 cap that `call` enforces now.
    pub fn effective_p05(state: &State, call: CallId) -> Result<NonNegAmount, String> {
        fstp_domain::policy::effective_p05(state, call).map_err(|r| format!("effective_p05: {r}"))
    }

    /// The P-13 classes that `call` enforces now.
    pub fn effective_p13(state: &State, call: CallId) -> Result<ExclusionClasses, String> {
        fstp_domain::policy::effective_p13(state, call).map_err(|r| format!("effective_p13: {r}"))
    }

    /// Whether the frozen P-77 of `call` allows binding actions through MCP.
    pub fn call_allows_mcp_binding(state: &State, call: CallId) -> Result<bool, String> {
        fstp_domain::policy::call_allows_mcp_binding(state, call)
            .map_err(|r| format!("call_allows_mcp_binding: {r}"))
    }

    /// Whether the head P-77 of `programme` allows binding actions through MCP.
    pub fn programme_allows_mcp_binding(
        state: &State,
        programme: ProgrammeId,
    ) -> Result<bool, String> {
        fstp_domain::policy::programme_allows_mcp_binding(state, programme)
            .map_err(|r| format!("programme_allows_mcp_binding: {r}"))
    }

    /// Whether `call` is published and open at `t`.
    pub fn is_open_at(state: &State, call: CallId, t: Timestamp) -> bool {
        fstp_domain::programme::is_open_at(state, call, t)
    }

    /// The next call of the same programme published after `call`.
    pub fn next_published_call(state: &State, call: CallId) -> Option<CallId> {
        fstp_domain::programme::next_published_call(state, call)
    }

    /// The configuration pinned on the call view of `call`.
    pub fn llm_config(state: &State, call: CallId) -> Option<LlmConfigId> {
        fstp_domain::programme::call(state, call).and_then(|c| c.llm_config())
    }

    /// The drafters of `call`.
    pub fn drafters(state: &State, call: CallId) -> Option<BTreeSet<AccountId>> {
        fstp_domain::programme::drafters(state, call)
    }
}

/// What a read of a call's frozen policy shows: the parts I-12 and
/// NOTE 7 constrain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenView {
    /// The call.
    pub call: CallId,
    /// The frozen version.
    pub version: PolicyVersionId,
    /// The frozen values.
    pub values: FrozenValues,
    /// The P-05 snapshot.
    pub p05: NonNegAmount,
    /// The P-13 snapshot.
    pub p13: ExclusionClasses,
}

impl FrozenView {
    /// The view of a production frozen policy.
    pub fn of(f: &FrozenPolicy) -> FrozenView {
        FrozenView {
            call: f.call(),
            version: f.version(),
            values: f.values().clone(),
            p05: f.snapshot().p05,
            p13: f.snapshot().p13.clone(),
        }
    }
}

/// A read of the frozen policy of a call. Teeth tests pass a broken one.
pub type ReadFrozen = fn(&Ghost, &State, CallId) -> Result<Option<FrozenView>, String>;

/// The production read, through [`reads::frozen_policy`].
pub fn production_read(
    _ghost: &Ghost,
    state: &State,
    call: CallId,
) -> Result<Option<FrozenView>, String> {
    reads::frozen_policy(state, call)
}

/// A broken read for the teeth test: it answers with the programme head
/// instead of the publication snapshot, as a guard that read the head would
/// (design 2.4 point 3). It reads the reference head, so it needs no
/// production read.
pub fn head_instead_of_snapshot(
    ghost: &Ghost,
    _state: &State,
    call: CallId,
) -> Result<Option<FrozenView>, String> {
    let Some(c) = ghost.calls.get(&call) else {
        return Ok(None);
    };
    if c.published.is_none() {
        return Ok(None);
    }
    let head = ghost
        .head(c.programme)
        .ok_or("teeth read: no head for the call's programme")?;
    Ok(Some(FrozenView {
        call,
        version: head.id,
        values: head.frozen.clone(),
        p05: head.live.p05,
        p13: head.live.p13.clone(),
    }))
}

// ---------------------------------------------------------------------------
// The I-12 predicates
// ---------------------------------------------------------------------------

/// Checks the ledger side of I-12 against the ghost: each published call
/// has exactly one `CallPublished` record, naming the version and
/// configuration the ghost copied, and that version's only record holds the
/// ghost's frozen values. No call is published that the ghost does not know.
pub fn check_i12_ledger(ghost: &Ghost, entries: &[Entry<EngineRecord>]) -> Result<(), String> {
    let mut published: BTreeMap<CallId, Vec<(PolicyVersionId, LlmConfigId)>> = BTreeMap::new();
    let mut versions: BTreeMap<PolicyVersionId, Vec<&PolicyVersion>> = BTreeMap::new();
    for e in entries {
        match &e.record {
            EngineRecord::Core(Record::CallPublished {
                call,
                policy,
                config,
                ..
            }) => published.entry(*call).or_default().push((*policy, *config)),
            EngineRecord::Core(Record::PolicyVersionRecorded { version, .. }) => {
                versions.entry(version.id).or_default().push(version)
            }
            _ => {}
        }
    }
    for (call, records) in &published {
        let Some(g) = ghost.calls.get(call).and_then(|c| c.published.as_ref()) else {
            return Err(format!(
                "I-12: call {call:?} has a CallPublished record that the reference refuses"
            ));
        };
        if records.as_slice() != [(g.version, g.config)] {
            return Err(format!(
                "I-12: call {call:?} has publication records {records:?}, the reference expects one for {:?}",
                (g.version, g.config)
            ));
        }
    }
    for (call, g) in ghost.published() {
        if !published.contains_key(&call) {
            return Err(format!("I-12: call {call:?} is published without a record"));
        }
        match versions.get(&g.version).map(Vec::as_slice) {
            Some([v]) if v.frozen == g.frozen => {}
            Some([_]) => {
                return Err(format!(
                    "I-12: the record of version {:?} frozen by call {call:?} holds other values than at publication",
                    g.version
                ));
            }
            other => {
                return Err(format!(
                    "I-12: version {:?} frozen by call {call:?} has {} records",
                    g.version,
                    other.map_or(0, <[_]>::len)
                ));
            }
        }
    }
    Ok(())
}

/// Checks the projection side of I-12 through `read`: every call the
/// ghost published reads back exactly what the ghost copied at
/// publication, and every unpublished call reads back no frozen policy.
pub fn check_i12_reads(ghost: &Ghost, state: &State, read: ReadFrozen) -> Result<(), String> {
    for (call, c) in &ghost.calls {
        let got = read(ghost, state, *call)?;
        match (&c.published, got) {
            (None, None) => {}
            (None, Some(v)) => {
                return Err(format!(
                    "I-12: unpublished call {call:?} reads a frozen policy of version {:?}",
                    v.version
                ));
            }
            (Some(_), None) => {
                return Err(format!(
                    "I-12: published call {call:?} reads no frozen policy"
                ));
            }
            (Some(g), Some(v)) => {
                let expected = FrozenView {
                    call: *call,
                    version: g.version,
                    values: g.frozen.clone(),
                    p05: g.p05,
                    p13: g.p13.clone(),
                };
                if v != expected {
                    return Err(format!(
                        "I-12: call {call:?} reads version {:?}, the copy at publication is version {:?}{}",
                        v.version,
                        g.version,
                        if v.values == g.frozen {
                            " (frozen values equal, identity or snapshot differs)"
                        } else {
                            " with other frozen values"
                        }
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Checks that production's head of every programme equals the reference
/// head, so later calls freeze the newest values.
pub fn check_heads(ghost: &Ghost, state: &State) -> Result<(), String> {
    for programme in ghost.programmes.keys() {
        let got = reads::head(state, *programme)?;
        let expected = ghost.head(*programme);
        if got.as_ref() != expected {
            return Err(format!(
                "R-PC-01: the head of {programme:?} is {:?}, the reference head is {:?}",
                got.map(|v| v.id),
                expected.map(|v| v.id)
            ));
        }
    }
    Ok(())
}

/// Checks the limits every known call enforces now against the ghost: the
/// lower of the P-05 snapshot and the live P-05, and the union of the P-13
/// snapshot and the live P-13, or the live values before publication
/// (R-PC-02 NOTE 2, P-05 and P-13 NOTE 7).
pub fn check_effective_limits(ghost: &Ghost, state: &State) -> Result<(), String> {
    for call in ghost.calls.keys() {
        let p05 = ghost
            .effective_p05(*call)?
            .ok_or("a known call has no P-05")?;
        let got = reads::effective_p05(state, *call)?;
        if got != p05 {
            return Err(format!(
                "R-PC-02 NOTE 7: {call:?} enforces P-05 {got:?}, the reference expects {p05:?}"
            ));
        }
        let p13 = ghost
            .effective_p13(*call)?
            .ok_or("a known call has no P-13")?;
        let got = reads::effective_p13(state, *call)?;
        if got != p13 {
            return Err(format!(
                "R-PC-02 NOTE 7: {call:?} enforces P-13 {got:?}, the reference expects {p13:?}"
            ));
        }
    }
    Ok(())
}

/// The full I-12 check of the machine invariant: ledger, frozen reads and heads.
pub fn check_i12(
    ghost: &Ghost,
    entries: &[Entry<EngineRecord>],
    state: &State,
) -> Result<(), String> {
    check_i12_ledger(ghost, entries)?;
    check_i12_reads(ghost, state, production_read)?;
    check_effective_limits(ghost, state)?;
    check_heads(ghost, state)
}

// ---------------------------------------------------------------------------
// M-POLICY
// ---------------------------------------------------------------------------

/// The two calls of M-POLICY.
pub const M_CALLS: [CallId; 2] = [CallId::from_raw(1), CallId::from_raw(2)];

/// The P-02 values of M-POLICY, in basis points.
pub const M_P02: [u16; 2] = [5_000, 7_500];

/// The P-03 values of M-POLICY.
pub const M_P03: [u8; 2] = [1, 2];

/// The most edits a run of M-POLICY makes.
pub const M_EDITS: u8 = 2;

/// The state count of M-POLICY, computed by hand: every action is accepted
/// once its guard holds and each history keeps its own ledger. Edit
/// histories of up to two edits over four values, interleaved with either
/// order of up to two publications, give 5 + 44 + 304 = 353 states. Step W6
/// measured the same count on production.
pub const M_POLICY_STATES: usize = 353;

/// One M-POLICY state: the production side, the reference side and the
/// number of edits made.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyMcState {
    /// Production: the scenario and its reference ghost.
    pub world: crate::r#gen::policy::Setup,
    /// Edits made so far.
    pub edits: u8,
    /// The calls in publication order.
    pub order: Vec<CallId>,
    /// Set when production and the reference disagree on whether a step
    /// is accepted. The `two-way` property fails on it.
    pub divergence: Option<String>,
}

/// An M-POLICY action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    /// `EditPolicy` by programme manager B, setting P-02 and P-03.
    Edit {
        /// P-02 in basis points.
        p02: u16,
        /// P-03.
        p03: u8,
    },
    /// `PublishCall` of the call by programme manager A.
    Publish(CallId),
}

/// The M-POLICY start state from genesis: programme 1 at P-02 75.00 and
/// P-03 2, both calls drafted by the call drafter and approved by
/// programme manager A. Every step must succeed.
pub fn m_policy_start() -> Result<PolicyMcState, String> {
    let mut w = PolicyWorld::new(false)?;
    for call in M_CALLS {
        w.draft(DRAFTER_1, call.raw(), P1)?
            .map_err(|e| format!("M-POLICY start: DraftCall {call:?}: {e:?}"))?;
        w.approve(PM_A, call.raw())
            .map_err(|e| format!("M-POLICY start: approval of {call:?}: {e:?}"))?;
    }
    Ok(PolicyMcState {
        world: w.setup,
        edits: 0,
        order: Vec::new(),
        divergence: None,
    })
}

/// M-POLICY at the policy level (design 6.3).
pub struct PolicyModel {
    /// The start state, from [`m_policy_start`].
    pub start: PolicyMcState,
}

impl PolicyModel {
    /// Runs `cmd` by `actor` on a copy of `s`. The ghost follows the
    /// reference, and production decides whether the step is enabled.
    ///
    /// A step on which the two sides disagree yields a successor marked
    /// with the divergence, so over-denial and over-acceptance both fail
    /// the `two-way` property. It does not depend on a witness going away.
    fn run(
        &self,
        s: &PolicyMcState,
        actor: fstp_domain::id::AccountId,
        cmd: Command,
    ) -> Option<PolicyMcState> {
        let mut next = s.clone();
        let verdict = match next.world.ghost.verdict(Actor::Account(actor), false, &cmd) {
            Ok(v) => v,
            Err(e) => {
                next.divergence = Some(format!("the reference cannot judge {cmd:?}: {e}"));
                return Some(next);
            }
        };
        let ctx = next.world.ctx(actor, false);
        let result = next.world.scenario.run_core(&cmd, ctx);
        match (verdict, result) {
            (Verdict::Accept, Err(e)) => {
                next.divergence = Some(format!(
                    "{:?} by {actor:?}: the reference accepts, production refuses with {e:?}",
                    cmd.kind()
                ));
                Some(next)
            }
            (_, Err(_)) => None,
            (Verdict::Refuse, Ok(_)) => {
                // The ghost stays behind, so the I-12 properties report it too.
                next.divergence = Some(format!(
                    "{:?} by {actor:?}: the reference refuses, production accepts",
                    cmd.kind()
                ));
                Some(next)
            }
            (_, Ok(_)) => {
                if let Err(e) = next.world.ghost.apply(Actor::Account(actor), &cmd) {
                    next.divergence = Some(format!("the reference cannot follow {cmd:?}: {e}"));
                }
                Some(next)
            }
        }
    }
}

impl Model for PolicyModel {
    type State = PolicyMcState;
    type Action = PolicyAction;

    fn init(&self) -> Vec<PolicyMcState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &PolicyMcState, actions: &mut Vec<PolicyAction>) {
        if s.edits < M_EDITS {
            for p02 in M_P02 {
                for p03 in M_P03 {
                    actions.push(PolicyAction::Edit { p02, p03 });
                }
            }
        }
        for call in M_CALLS {
            actions.push(PolicyAction::Publish(call));
        }
    }

    fn step(&self, s: &PolicyMcState, a: &PolicyAction) -> Option<PolicyMcState> {
        match a {
            PolicyAction::Edit { p02, p03 } => {
                if s.edits >= M_EDITS {
                    return None;
                }
                let head = s.world.ghost.head(P1)?.clone();
                let id = PolicyVersionId::from_raw(100u128.saturating_add(u128::from(s.edits)));
                let mut v = next_version(&head, id);
                v.frozen.p02 = Percent::from_bp(*p02)?;
                v.frozen.p03 = NonZeroU8::new(*p03)?;
                let cmd = Command::EditPolicy {
                    base: head.id,
                    version: Box::new(v),
                };
                let mut next = self.run(s, PM_B, cmd)?;
                next.edits = next.edits.saturating_add(1);
                Some(next)
            }
            PolicyAction::Publish(call) => {
                let primary = s.world.ghost.head(P1)?.frozen.p21.primary.clone();
                let cmd = Command::PublishCall {
                    call: *call,
                    config: LlmConfigId::from_raw(call.raw()),
                    config_model: primary,
                };
                let mut next = self.run(s, PM_A, cmd)?;
                next.order.push(*call);
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &PolicyMcState) -> bool {
        s.divergence.is_some() || (s.order.len() == M_CALLS.len() && s.edits == M_EDITS)
    }
}

/// The ledger of a model state, or an empty one when it cannot be read.
fn ledger(s: &PolicyMcState) -> Result<Vec<Entry<EngineRecord>>, String> {
    s.world
        .scenario
        .entries()
        .map_err(|e| format!("entries: {e:?}"))
}

/// The scenario of a model state.
fn scenario(s: &PolicyMcState) -> &Scenario {
    &s.world.scenario
}

/// Whether two published calls froze different values, with an edit between them.
fn edit_between_publications(s: &PolicyMcState) -> bool {
    let published: Vec<_> = s
        .order
        .iter()
        .filter_map(|c| s.world.ghost.calls.get(c))
        .collect();
    match published.as_slice() {
        [first, second] => match (&first.published, &second.published) {
            (Some(a), Some(b)) => a.version != b.version && a.frozen != b.frozen,
            _ => false,
        },
        _ => false,
    }
}

/// Whether both calls froze the same version.
fn both_on_one_version(s: &PolicyMcState) -> bool {
    let versions: Vec<_> = s
        .order
        .iter()
        .filter_map(|c| {
            s.world
                .ghost
                .calls
                .get(c)
                .and_then(|g| g.published.as_ref())
        })
        .map(|p| p.version)
        .collect();
    matches!(versions.as_slice(), [a, b] if a == b)
}

/// The M-POLICY properties with frozen reads through `read`:
///
/// - `two-way`: no step on which production and the reference disagree
///   about acceptance, in either direction.
/// - `I-12`: in every state, each published call reads back the copy the
///   ghost took at publication, and the ledger agrees.
/// - `I-12 edit`: no transition changes the frozen policy of a call that
///   was published before it.
/// - `R-PC-02`: a publication freezes the head of the state before it, so a
///   call published after an edit carries the new values.
/// - `I-23`: every transition extends the ledger and replays to the state.
/// - two `reachable` witnesses: an edit between publications, and both
///   calls on one version.
pub fn m_policy_properties<'a, M>(read: ReadFrozen) -> Vec<Property<'a, M>>
where
    M: Model<State = PolicyMcState, Action = PolicyAction>,
{
    vec![
        Property::<M>::always_with("two-way", |s| match &s.divergence {
            None => Ok(()),
            Some(d) => Err(format!("two-way: {d}")),
        }),
        Property::<M>::always_with("I-12", move |s| {
            check_i12_ledger(&s.world.ghost, &ledger(s)?)?;
            check_i12_reads(&s.world.ghost, &scenario(s).state().core, read)
        }),
        Property::<M>::transition_with("I-12 edit", move |before, _a, after| {
            for (call, _) in before.world.ghost.published() {
                let was = read(&before.world.ghost, &scenario(before).state().core, call)?;
                let now = read(&after.world.ghost, &scenario(after).state().core, call)?;
                if was != now {
                    return Err(format!(
                        "I-12 edit: the frozen policy of {call:?} changed from {:?} to {:?}",
                        was.map(|v| v.version),
                        now.map(|v| v.version)
                    ));
                }
            }
            Ok(())
        }),
        Property::<M>::transition_with("R-PC-02", move |before, a, after| {
            let PolicyAction::Publish(call) = a else {
                return Ok(());
            };
            let head = before
                .world
                .ghost
                .head(P1)
                .ok_or("R-PC-02: no head before the publication")?;
            let got = read(&after.world.ghost, &scenario(after).state().core, *call)?
                .ok_or("R-PC-02: the published call reads no frozen policy")?;
            if got.version != head.id || got.values != head.frozen {
                return Err(format!(
                    "R-PC-02: {call:?} froze version {:?}, the head before publication was {:?}",
                    got.version, head.id
                ));
            }
            if got.p05 != head.live.p05 || got.p13 != head.live.p13 {
                return Err(format!(
                    "R-PC-02: {call:?} snapshot of P-05 and P-13 differs from the head's live values"
                ));
            }
            Ok(())
        }),
        Property::<M>::transition_with("I-23", |before, _a, after| {
            ledger_step(&ledger(before)?, &ledger(after)?, scenario(after).state())
        }),
        Property::<M>::reachable(
            "I-12 witness: an edit between publications",
            edit_between_publications,
        ),
        Property::<M>::reachable(
            "I-12 witness: both calls on one version",
            both_on_one_version,
        ),
    ]
}
