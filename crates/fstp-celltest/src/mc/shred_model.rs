//! M-SHRED (design section 14.2, I-81). Lane W1d owns this file.
//!
//! The model drives an erasure planner through a symbolic environment: a
//! keystore of [`Row`]s, custody roots, keystore snapshots and an
//! attacker. The planner is a [`ShredBackend`]: the [`Reference`]
//! planner, [`Production`] (`fstp_keys::erasure`) or a [`Mutant`] with one
//! seeded [`Defect`].
//!
//! The universe: two groups of two data keys (`g0 = {k0, k1}`,
//! `g1 = {k2, k3}`), and three erasure requests at any step. It has two
//! request orders, one start state each: `k0, k2, k1` ([`REQUESTS`]) and
//! `k0, k2, k3` ([`REQUESTS_SAME_GROUP`]). A request on an idle chain
//! starts its run at once, so `k0` always runs alone. The first order then
//! lets a batch span two groups, and the second lets a batch erase two
//! siblings of one group, as `Text` groups of up to 256 keys do.
//!
//! Beside the data key groups is one keyed digest group `g2` with no data
//! keys (design section 3.5, G24). Its subjects are `k0` and `k2`, as a
//! `Lookup` key digests two login emails. This adds a group to the
//! universe of design section 14.2, so that I-81 covers the digest keys.
//!
//! Keystore snapshots happen at any step. Each trace has at most one
//! crash and at most one custody fault, in any order. A crash is a crash
//! at any step or a crash right after a custody call. A custody fault is
//! a custody call that fails or one whose reply is lost. That covers a
//! crash during recovery from a custody fault, and a custody fault after
//! a crash. The bound is a deliberate narrowing of design section 14.2,
//! which allows a fault after any operation: more than one fault of each
//! kind per trace is not explored.
//!
//! The attacker sees every row ever written: committed, aborted in the
//! WAL, or in a snapshot. That covers every backup taken at any step,
//! every WAL segment, replica and dead tuple, so the model needs no
//! separate backup action. The attacker also holds every live custody
//! root. The properties:
//!
//! - `I-81`: no erased key opens from what the attacker holds. No digest
//!   key that computed a digest of an erased key opens either (G24).
//! - `no-data-loss`: every live key opens from the live store, and from
//!   the newest verified snapshot, under the live custody roots. The
//!   current digest key opens from the live store.
//! - `completion-after-receipt`: an erasure is recorded complete only
//!   once every older root epoch has a destroy receipt.
//! - `requests-complete`: the planner is never idle while a recorded
//!   request is incomplete. ADR-004 part 2 has requests that arrive mid
//!   rotation join the next one, and a crash lose nothing.
//! - `backend-answers`: the planner answered every call.
//! - `planner-steps-run`: every step the planner gives can run in the
//!   environment. A step that cannot run would end its branch quietly,
//!   and the other properties would then hold on it for no reason.
//!
//! Witnesses: an erasure completes; every request completes; a crash in
//! the middle of a run resumes to a completion; a custody fault that
//! fired recovers to a completion.
//!
//! Environment semantics this model fixes, which production must meet:
//!
//! - Steps 2 and 3 are durable only with the commit of step 4. A crash
//!   before it restores the planner state of the last durable step.
//! - `DestroyRoot(e)` destroys every custody root of epoch `e`, including
//!   one that a crashed or retried `NewEpoch(e)` created. The shell finds
//!   those through the `KeyOp` record written before each custody call
//!   (ADR-004 "Reconciliation"). A root left alive there would wrap old
//!   group generations that a later erasure needs dead.
//! - A destroy of a root already destroyed returns its receipt again.
//! - A new digest key recomputes the index from the live sealed values of
//!   its subjects. A subject whose erasure is requested is refused for
//!   open from step 1, so the new key never digests it.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use fstp_keys::erasure::{self as prod, ChainState, KeyFoldError, Step};
use fstp_keys::{DekId, Epoch, GroupId};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::reference::keys::{
    Defect, GroupIx, KeyIx, Layout, PlanError, RefPlan, RefStep, RootId, Row, SecretId, closure,
};

// ---------------------------------------------------------------------------
// Backends.

/// The planner calls M-SHRED makes. Each backend keeps its own state type.
pub trait ShredBackend {
    /// The planner state of one chain.
    type Plan: Clone + Eq + Hash + std::fmt::Debug;

    /// The state of a fresh chain at epoch 1 with the groups of `layout`.
    fn genesis(&self, layout: &Layout) -> Result<Self::Plan, String>;
    /// Step 1: records an erasure request for `dek`.
    fn request(&self, plan: &Self::Plan, dek: KeyIx) -> Result<Self::Plan, String>;
    /// The next step, or `None` when nothing is to do.
    fn next(&self, plan: &Self::Plan) -> Result<Option<RefStep>, String>;
    /// Folds a completed step into the state.
    fn apply(&self, plan: &Self::Plan, done: &RefStep) -> Result<Self::Plan, String>;
    /// The state to resume from after a process restart, given the state
    /// stored at the last durable step.
    fn restart(&self, stored: &Self::Plan) -> Result<Self::Plan, String>;
}

/// The reference backend: [`RefPlan`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

fn plan_err(e: PlanError) -> String {
    e.0
}

impl ShredBackend for Reference {
    type Plan = RefPlan;

    fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
        Ok(RefPlan::genesis(layout, None))
    }

    fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
        plan.request(dek).map_err(plan_err)
    }

    fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
        Ok(plan.next())
    }

    fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
        plan.apply(done).map_err(plan_err)
    }

    fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
        Ok(stored.restart())
    }
}

/// The reference planner with one seeded defect.
#[derive(Clone, Copy, Debug)]
pub struct Mutant(pub Defect);

impl ShredBackend for Mutant {
    type Plan = RefPlan;

    fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
        Ok(RefPlan::genesis(layout, Some(self.0)))
    }

    fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
        plan.request(dek).map_err(plan_err)
    }

    fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
        Ok(plan.next())
    }

    fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
        plan.apply(done).map_err(plan_err)
    }

    fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
        Ok(stored.restart())
    }
}

/// The production backend: `fstp_keys::erasure`.
///
/// Every call goes to production. `genesis` builds the chain through the
/// three admissions of lane W2f: `ChainState::add_group` and
/// `ChainState::admit` for each data key group, then
/// `ChainState::add_digest_group` for each keyed digest group with its
/// subjects (design section 3.5, G24). `request` calls
/// `ChainState::request` (step 1). No reference logic stands in for
/// production.
#[derive(Clone, Copy, Debug)]
pub struct Production {
    _probe: (),
}

/// The group id of group `g` of the universe.
pub fn group_id(g: GroupIx) -> GroupId {
    GroupId([0x10_u8.saturating_add(g); 16])
}

/// The data key id of key `k` of the universe.
pub fn dek_id(k: KeyIx) -> DekId {
    DekId([0x20_u8.saturating_add(k); 16])
}

fn group_ix(g: &GroupId) -> Option<GroupIx> {
    let first = *g.0.first()?;
    let ix = first.checked_sub(0x10)?;
    (*g == group_id(ix) && ix < 16).then_some(ix)
}

fn key_ix(k: &DekId) -> Option<KeyIx> {
    let first = *k.0.first()?;
    let ix = first.checked_sub(0x20)?;
    (*k == dek_id(ix) && ix < 16).then_some(ix)
}

/// The production step of a reference step.
pub fn to_prod(s: &RefStep) -> Step {
    match s {
        RefStep::NewGroups(gs) => Step::NewGroups {
            groups: gs.iter().map(|g| group_id(*g)).collect(),
        },
        RefStep::Reseal { group, keep } => Step::Reseal {
            group: group_id(*group),
            keep: keep.iter().map(|k| dek_id(*k)).collect(),
        },
        RefStep::NewEpoch(e) => Step::NewEpoch(Epoch(*e)),
        RefStep::RewrapGroups(e) => Step::RewrapGroups(Epoch(*e)),
        RefStep::Commit(e) => Step::Commit(Epoch(*e)),
        RefStep::Snapshot(e) => Step::Snapshot(Epoch(*e)),
        RefStep::VerifySnapshot(e) => Step::VerifySnapshot(Epoch(*e)),
        RefStep::DestroyRoot(e) => Step::DestroyRoot(Epoch(*e)),
        RefStep::Complete { epoch, erased } => Step::Complete {
            epoch: Epoch(*epoch),
            erased: erased.iter().map(|k| dek_id(*k)).collect(),
        },
    }
}

/// The reference step of a production step, or why it names an id
/// outside the universe.
pub fn from_prod(s: &Step) -> Result<RefStep, String> {
    let g = |id: &GroupId| group_ix(id).ok_or_else(|| format!("unknown group {id:?} in {s:?}"));
    let k = |id: &DekId| key_ix(id).ok_or_else(|| format!("unknown data key {id:?} in {s:?}"));
    Ok(match s {
        Step::NewGroups { groups } => {
            RefStep::NewGroups(groups.iter().map(g).collect::<Result<_, _>>()?)
        }
        Step::Reseal { group, keep } => RefStep::Reseal {
            group: g(group)?,
            keep: keep.iter().map(k).collect::<Result<_, _>>()?,
        },
        Step::NewEpoch(e) => RefStep::NewEpoch(e.0),
        Step::RewrapGroups(e) => RefStep::RewrapGroups(e.0),
        Step::Commit(e) => RefStep::Commit(e.0),
        Step::Snapshot(e) => RefStep::Snapshot(e.0),
        Step::VerifySnapshot(e) => RefStep::VerifySnapshot(e.0),
        Step::DestroyRoot(e) => RefStep::DestroyRoot(e.0),
        Step::Complete { epoch, erased } => RefStep::Complete {
            epoch: epoch.0,
            erased: erased.iter().map(k).collect::<Result<_, _>>()?,
        },
    })
}

fn fold_err(e: KeyFoldError) -> String {
    match e {
        KeyFoldError::NotImplemented(op) => NotImplemented::new(op).to_string(),
        refused => format!("fstp_keys::erasure refused: {refused}"),
    }
}

/// A production chain state as a model state. `ChainState` derives `Eq`
/// but not `Hash`, so the hash is taken over its `Debug` form, which is
/// deterministic: every map in it is a `BTreeMap`. Equal states have
/// equal `Debug` forms, so the hash agrees with `Eq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProdPlan(pub ChainState);

impl Hash for ProdPlan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self.0).hash(state);
    }
}

impl Production {
    /// The production backend, once `fstp_keys::erasure::next` answers on
    /// a fresh chain.
    ///
    /// # Errors
    ///
    /// Returns the refusal of `next`.
    pub fn new() -> Result<Production, NotImplemented> {
        match prod::next(&ChainState::genesis(Epoch(1))) {
            Err(KeyFoldError::NotImplemented(op)) => Err(NotImplemented::new(op)),
            // Any other answer, a refusal included, is production
            // answering.
            Ok(_) | Err(_) => Ok(Production { _probe: () }),
        }
    }
}

impl ShredBackend for Production {
    type Plan = ProdPlan;

    fn genesis(&self, layout: &Layout) -> Result<ProdPlan, String> {
        let mut s = ChainState::genesis(Epoch(1));
        for (g, keys) in (0..layout.group_count()).zip(layout.groups.iter()) {
            if layout.is_digest(g) {
                continue;
            }
            s.add_group(group_id(g)).map_err(fold_err)?;
            for k in keys {
                s.admit(group_id(g), dek_id(*k)).map_err(fold_err)?;
            }
        }
        for g in (0..layout.group_count()).filter(|g| layout.is_digest(*g)) {
            let subjects: Vec<DekId> = layout.subjects_of(g).iter().map(|k| dek_id(*k)).collect();
            s.add_digest_group(group_id(g), &subjects)
                .map_err(fold_err)?;
        }
        Ok(ProdPlan(s))
    }

    /// Step 1 through `ChainState::request`. The model has no ledger, so
    /// every request carries ledger sequence 0.
    fn request(&self, plan: &ProdPlan, dek: KeyIx) -> Result<ProdPlan, String> {
        let mut s = plan.0.clone();
        s.request(dek_id(dek), 0).map_err(fold_err)?;
        Ok(ProdPlan(s))
    }

    fn next(&self, plan: &ProdPlan) -> Result<Option<RefStep>, String> {
        match prod::next(&plan.0).map_err(fold_err)? {
            None => Ok(None),
            Some(step) => from_prod(&step).map(Some),
        }
    }

    fn apply(&self, plan: &ProdPlan, done: &RefStep) -> Result<ProdPlan, String> {
        let mut s = plan.0.clone();
        prod::apply(&mut s, &to_prod(done)).map_err(fold_err)?;
        Ok(ProdPlan(s))
    }

    /// `ChainState::restart` of the stored state. The model stores it only
    /// at the durable points of [`RefStep::is_durable`] and at requests,
    /// so a production state stored there resumes as it is. Lane W2f's
    /// restart also resets a run stored before its commit to its first
    /// step, which a shell that stores more often needs.
    fn restart(&self, stored: &ProdPlan) -> Result<ProdPlan, String> {
        Ok(ProdPlan(stored.0.restart()))
    }
}

/// Production's full plan for `batch` from `plan`, through
/// `fstp_keys::erasure::plan_erasure`, in reference steps.
///
/// # Errors
///
/// Returns the production refusal, or an id outside the universe.
pub fn production_plan(plan: &ProdPlan, batch: &BTreeSet<KeyIx>) -> Result<Vec<RefStep>, String> {
    let batch: BTreeSet<DekId> = batch.iter().map(|k| dek_id(*k)).collect();
    prod::plan_erasure(&plan.0, &batch)
        .map_err(fold_err)?
        .steps
        .iter()
        .map(from_prod)
        .collect()
}

// ---------------------------------------------------------------------------
// The environment.

/// One custody root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootRec {
    /// The epoch its label names.
    pub epoch: u64,
    /// Whether custody still holds it.
    pub alive: bool,
}

/// A keystore snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Snap {
    /// The epoch it was taken under.
    pub epoch: u64,
    /// The keystore rows it holds.
    pub rows: BTreeSet<Row>,
    /// Whether it passed verification.
    pub verified: bool,
}

/// A custody fault armed for the next custody call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The call fails and has no effect.
    Fails,
    /// The call takes effect, and its reply is lost.
    ReplyLost,
}

/// A recorded completion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Completion {
    /// The new epoch the completion names.
    pub epoch: u64,
    /// The keys it names.
    pub erased: Vec<KeyIx>,
}

/// The symbolic world around the planner.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Env {
    /// Custody roots, by [`RootId`].
    pub roots: Vec<RootRec>,
    /// The group of each group secret instance, by [`SecretId`].
    pub secret_group: Vec<GroupIx>,
    /// The digest subjects each group secret instance computed digests
    /// of, by [`SecretId`] (G24). Empty for an instance of a data key
    /// group. A new instance of a digest group digests the live sealed
    /// value of each subject whose erasure is not requested: a requested
    /// key is refused for open from step 1, so its value is not read.
    pub digest_knows: Vec<BTreeSet<KeyIx>>,
    /// The committed current secret instance of each group.
    pub current: Vec<SecretId>,
    /// The committed root epoch.
    pub epoch: u64,
    /// The new root of the running attempt, while its `S(e+1)` is in
    /// process memory.
    pub new_root: Option<RootId>,
    /// The new group secrets of the running attempt, in process memory.
    pub new_secrets: BTreeMap<GroupIx, SecretId>,
    /// Committed rows: the live keystore.
    pub live: BTreeSet<Row>,
    /// Rows written by the running attempt and not committed.
    pub pending: BTreeSet<Row>,
    /// Every row ever written, committed or aborted. The WAL, its archive
    /// and every backup hold a subset of it.
    pub written: BTreeSet<Row>,
    /// Keystore snapshots, oldest first.
    pub snapshots: Vec<Snap>,
    /// Keys whose erasure request is recorded.
    pub requested: BTreeSet<KeyIx>,
    /// Keys recorded as erased (step 7).
    pub erased: BTreeSet<KeyIx>,
    /// Completions in order.
    pub completions: Vec<Completion>,
    /// Epochs with a destroy receipt.
    pub receipts: BTreeSet<u64>,
    /// The armed custody fault.
    pub armed: Option<Fault>,
    /// Whether the run's one custody fault is armed or used.
    pub fault_used: bool,
    /// Whether the run's one crash is used: a crash, or a crash right
    /// after a custody call.
    pub crash_used: bool,
    /// Whether an armed custody fault fired: a custody call took it.
    pub fault_fired: bool,
    /// Whether the run's one daily snapshot is used.
    pub daily_used: bool,
    /// Completions recorded after a crash in the middle of a run.
    pub resumed_after_crash: bool,
    /// A crash happened while a run was in flight.
    pub crashed_mid_run: bool,
    /// Completions recorded after a custody fault.
    pub recovered_after_fault: bool,
    /// Whether `DestroyRoot` destroys only the committed root of its
    /// epoch, and leaves alive a root that a crashed or retried
    /// `NewEpoch` created. Off in M-SHRED. On only to show why the shell
    /// must destroy those roots too.
    pub orphans_survive: bool,
}

impl Env {
    /// The world after provisioning: root 0 at epoch 1, one secret
    /// instance per group, every key sealed to its group, and a verified
    /// snapshot.
    pub fn genesis(layout: &Layout) -> Env {
        let mut live = BTreeSet::new();
        live.insert(Row::WrappedSeal { root: 0 });
        let mut secret_group = Vec::new();
        let mut digest_knows = Vec::new();
        let mut current = Vec::new();
        for (g, keys) in layout.groups.iter().enumerate() {
            let s = SecretId::try_from(g).unwrap_or(SecretId::MAX);
            let gi = GroupIx::try_from(g).unwrap_or(GroupIx::MAX);
            secret_group.push(gi);
            digest_knows.push(layout.subjects_of(gi).iter().copied().collect());
            current.push(s);
            live.insert(Row::GroupSecret {
                secret: s,
                under: 0,
            });
            for k in keys {
                live.insert(Row::DataKey { dek: *k, secret: s });
            }
        }
        Env {
            roots: vec![RootRec {
                epoch: 1,
                alive: true,
            }],
            secret_group,
            digest_knows,
            current,
            epoch: 1,
            new_root: None,
            new_secrets: BTreeMap::new(),
            written: live.clone(),
            snapshots: vec![Snap {
                epoch: 1,
                rows: live.clone(),
                verified: true,
            }],
            live,
            pending: BTreeSet::new(),
            requested: BTreeSet::new(),
            erased: BTreeSet::new(),
            completions: Vec::new(),
            receipts: BTreeSet::new(),
            armed: None,
            fault_used: false,
            crash_used: false,
            fault_fired: false,
            daily_used: false,
            resumed_after_crash: false,
            crashed_mid_run: false,
            recovered_after_fault: false,
            orphans_survive: false,
        }
    }

    /// The live custody roots.
    pub fn live_roots(&self) -> BTreeSet<RootId> {
        self.roots
            .iter()
            .enumerate()
            .filter(|(_, r)| r.alive)
            .filter_map(|(i, _)| RootId::try_from(i).ok())
            .collect()
    }

    /// The live roots of epoch `e`.
    fn roots_of(&self, e: u64) -> BTreeSet<RootId> {
        self.roots
            .iter()
            .enumerate()
            .filter(|(_, r)| r.alive && r.epoch == e)
            .filter_map(|(i, _)| RootId::try_from(i).ok())
            .collect()
    }

    /// The keys that must stay readable: every key of the layout whose
    /// erasure is not requested.
    pub fn live_keys(&self, layout: &Layout) -> Vec<KeyIx> {
        layout
            .keys()
            .into_iter()
            .filter(|k| !self.requested.contains(k))
            .collect()
    }

    /// The newest verified snapshot.
    pub fn newest_verified(&self) -> Option<&Snap> {
        self.snapshots.iter().rev().find(|s| s.verified)
    }

    fn write(&mut self, row: Row) {
        self.pending.insert(row);
        self.written.insert(row);
    }

    fn new_secret(&mut self, layout: &Layout, g: GroupIx) -> Option<SecretId> {
        let s = SecretId::try_from(self.secret_group.len()).ok()?;
        self.secret_group.push(g);
        let knows = layout
            .subjects_of(g)
            .iter()
            .copied()
            .filter(|k| !self.requested.contains(k))
            .collect();
        self.digest_knows.push(knows);
        Some(s)
    }

    /// The digest group secret instances that computed a digest of `k`.
    pub fn digest_keys_of(&self, k: KeyIx) -> BTreeSet<SecretId> {
        self.digest_knows
            .iter()
            .enumerate()
            .filter(|(_, knows)| knows.contains(&k))
            .filter_map(|(s, _)| SecretId::try_from(s).ok())
            .collect()
    }

    fn new_root_rec(&mut self, epoch: u64) -> Option<RootId> {
        let r = RootId::try_from(self.roots.len()).ok()?;
        self.roots.push(RootRec { epoch, alive: true });
        Some(r)
    }

    /// Process memory is lost: the running attempt's new secrets, its new
    /// `S(e+1)` and its uncommitted rows. The rows stay in `written`.
    fn lose_memory(&mut self) {
        self.new_root = None;
        self.new_secrets.clear();
        self.pending.clear();
    }
}

/// What executing a step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    /// The step took effect.
    Done,
    /// The step could not run here: it has no effect and is not applied.
    Refused,
    /// A custody fault: the call failed, or its reply was lost.
    Faulted,
}

/// Executes `step` against the environment.
fn execute(env: &mut Env, layout: &Layout, step: &RefStep) -> Effect {
    if step.calls_custody()
        && let Some(f) = env.armed.take()
    {
        env.fault_fired = true;
        if f == Fault::Fails {
            return Effect::Faulted;
        }
        let _ = execute_inner(env, layout, step);
        return Effect::Faulted;
    }
    execute_inner(env, layout, step)
}

fn execute_inner(env: &mut Env, layout: &Layout, step: &RefStep) -> Effect {
    match step {
        RefStep::NewGroups(gs) => {
            for g in gs {
                if usize::from(*g) >= layout.groups.len() {
                    return Effect::Refused;
                }
                let Some(s) = env.new_secret(layout, *g) else {
                    return Effect::Refused;
                };
                env.new_secrets.insert(*g, s);
            }
            Effect::Done
        }
        RefStep::Reseal { group, keep } => {
            let Some(s) = env.new_secrets.get(group).copied() else {
                return Effect::Refused;
            };
            if keep.len() > 256 {
                return Effect::Refused;
            }
            for k in keep {
                env.write(Row::DataKey { dek: *k, secret: s });
            }
            Effect::Done
        }
        RefStep::NewEpoch(e) => {
            if *e <= env.epoch {
                return Effect::Refused;
            }
            let Some(r) = env.new_root_rec(*e) else {
                return Effect::Refused;
            };
            env.new_root = Some(r);
            env.write(Row::WrappedSeal { root: r });
            Effect::Done
        }
        RefStep::RewrapGroups(e) => {
            let Some(r) = env.new_root.filter(|r| {
                env.roots
                    .get(usize::from(*r))
                    .is_some_and(|x| x.epoch == *e && x.alive)
            }) else {
                return Effect::Refused;
            };
            for (g, cur) in env.current.clone().into_iter().enumerate() {
                let g = GroupIx::try_from(g).unwrap_or(GroupIx::MAX);
                let s = env.new_secrets.get(&g).copied().unwrap_or(cur);
                env.write(Row::GroupSecret {
                    secret: s,
                    under: r,
                });
            }
            Effect::Done
        }
        RefStep::Commit(e) => {
            let Some(r) = env.new_root else {
                return Effect::Refused;
            };
            if env.roots.get(usize::from(r)).map(|x| x.epoch) != Some(*e) {
                return Effect::Refused;
            }
            let pending = std::mem::take(&mut env.pending);
            env.live.extend(pending);
            for (g, s) in std::mem::take(&mut env.new_secrets) {
                if let Some(slot) = env.current.get_mut(usize::from(g)) {
                    *slot = s;
                }
            }
            env.epoch = *e;
            env.new_root = None;
            Effect::Done
        }
        RefStep::Snapshot(e) => {
            if *e != env.epoch {
                return Effect::Refused;
            }
            env.snapshots.push(Snap {
                epoch: *e,
                rows: env.live.clone(),
                verified: false,
            });
            Effect::Done
        }
        RefStep::VerifySnapshot(e) => {
            let roots = env.roots_of(*e);
            let keys = env.live_keys(layout);
            let Some(snap) = env.snapshots.iter_mut().rev().find(|s| s.epoch == *e) else {
                return Effect::Refused;
            };
            let opened = closure(snap.rows.iter(), &roots);
            if roots.is_empty() || !keys.iter().all(|k| opened.deks.contains(k)) {
                return Effect::Refused;
            }
            snap.verified = true;
            Effect::Done
        }
        RefStep::DestroyRoot(e) => {
            let committed: BTreeSet<RootId> = env
                .live
                .iter()
                .filter_map(|row| match row {
                    Row::WrappedSeal { root } => Some(*root),
                    _ => None,
                })
                .collect();
            let orphans_survive = env.orphans_survive;
            let mut any = false;
            for (i, r) in env.roots.iter_mut().enumerate() {
                let id = RootId::try_from(i).unwrap_or(RootId::MAX);
                if r.epoch == *e && (!orphans_survive || committed.contains(&id)) {
                    r.alive = false;
                    any = true;
                }
            }
            if !any {
                return Effect::Refused;
            }
            env.receipts.insert(*e);
            Effect::Done
        }
        RefStep::Complete { epoch, erased } => {
            env.erased.extend(erased.iter().copied());
            env.completions.push(Completion {
                epoch: *epoch,
                erased: erased.clone(),
            });
            if env.crashed_mid_run {
                env.resumed_after_crash = true;
            }
            if env.fault_fired && !env.crashed_mid_run {
                env.recovered_after_fault = true;
            }
            Effect::Done
        }
    }
}

// ---------------------------------------------------------------------------
// The model.

/// The keys the universe requests, in order, in its first request order.
/// A request on an idle chain starts its run at once, so `k0` runs alone,
/// and `k2` and `k1` can meet in one batch across two groups.
pub const REQUESTS: [KeyIx; 3] = [0, 2, 1];

/// The second request order: `k2` and `k3` can meet in one batch of the
/// same group `g1`, as siblings of a `Text` group do in production.
pub const REQUESTS_SAME_GROUP: [KeyIx; 3] = [0, 2, 3];

/// The state of M-SHRED.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShredState<P> {
    /// The request order this trace follows, as an index into the model's
    /// orders.
    pub order: usize,
    /// The planner state now. `None` only in the halted start state of a
    /// backend that gave no genesis.
    pub plan: Option<P>,
    /// The planner state at the last durable step.
    pub durable: Option<P>,
    /// The world.
    pub env: Env,
    /// The first backend refusal or malformed step.
    pub halt: Option<String>,
    /// The first planner step the environment could not run.
    pub refused: Option<String>,
}

/// An action of M-SHRED.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShredAction {
    /// The next erasure request of [`REQUESTS`] arrives.
    Request,
    /// The planner's next step runs.
    Step,
    /// The planner's next step runs, and the process crashes right after
    /// its custody call, before the planner folds it.
    StepThenCrash,
    /// The process crashes.
    Crash,
    /// The next custody call fails with no effect.
    CustodyFails,
    /// The next custody call takes effect and its reply is lost.
    CustodyReplyLost,
    /// The daily keystore snapshot runs.
    DailySnapshot,
}

/// Every action, in exploration order.
pub const ACTIONS: [ShredAction; 7] = [
    ShredAction::Request,
    ShredAction::Step,
    ShredAction::StepThenCrash,
    ShredAction::Crash,
    ShredAction::CustodyFails,
    ShredAction::CustodyReplyLost,
    ShredAction::DailySnapshot,
];

/// M-SHRED over a backend and a layout.
#[derive(Clone, Debug)]
pub struct ShredModel<B> {
    backend: B,
    layout: Layout,
    orders: Vec<Vec<KeyIx>>,
    orphans_survive: bool,
}

impl<B: ShredBackend> ShredModel<B> {
    /// M-SHRED over `backend` in the universe of design section 14.2, over
    /// both request orders [`REQUESTS`] and [`REQUESTS_SAME_GROUP`]. Each
    /// order is one start state, so one run covers a batch across groups
    /// and a batch of siblings in one group.
    pub fn new(backend: B) -> ShredModel<B> {
        ShredModel::with_orders(
            backend,
            Layout::m_shred(),
            vec![REQUESTS.to_vec(), REQUESTS_SAME_GROUP.to_vec()],
        )
    }

    /// The model over `backend`, `layout` and one request order.
    pub fn with(backend: B, layout: Layout, requests: Vec<KeyIx>) -> ShredModel<B> {
        ShredModel::with_orders(backend, layout, vec![requests])
    }

    /// The model over `backend`, `layout` and several request orders, one
    /// start state each. The first order is the start state of [`walk`].
    pub fn with_orders(backend: B, layout: Layout, orders: Vec<Vec<KeyIx>>) -> ShredModel<B> {
        ShredModel {
            backend,
            layout,
            orders,
            orphans_survive: false,
        }
    }

    /// The request order of state `s`.
    pub fn requests_of(&self, s: &ShredState<B::Plan>) -> &[KeyIx] {
        self.orders.get(s.order).map_or(&[][..], Vec::as_slice)
    }

    /// The same model in an environment where `DestroyRoot` leaves the
    /// orphan roots of a crashed or retried `NewEpoch` alive. It shows
    /// the environment requirement of the module documentation.
    #[must_use]
    pub fn with_orphans_surviving(mut self) -> ShredModel<B> {
        self.orphans_survive = true;
        self
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The layout.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Whether the planner of `s` answers that it has nothing to do. A
    /// halted or refused state, or a refusal of `next`, is not idle: the
    /// properties `backend-answers` and `planner-steps-run` report those.
    pub fn idle(&self, s: &ShredState<B::Plan>) -> bool {
        s.halt.is_none()
            && s.refused.is_none()
            && s.plan
                .as_ref()
                .is_some_and(|p| matches!(self.backend.next(p), Ok(None)))
    }

    /// The initial state, or the halted state when the backend refuses.
    pub fn initial(&self) -> Option<ShredState<B::Plan>> {
        self.init().into_iter().next()
    }

    fn halted(s: &ShredState<B::Plan>, why: String) -> ShredState<B::Plan> {
        let mut t = s.clone();
        t.halt = Some(why);
        t
    }

    fn crash(&self, t: &mut ShredState<B::Plan>) {
        if t.env.requested != t.env.erased {
            t.env.crashed_mid_run = true;
        }
        t.env.lose_memory();
        t.env.crash_used = true;
        match t.durable.as_ref().map(|d| self.backend.restart(d)) {
            Some(Ok(p)) => t.plan = Some(p),
            Some(Err(e)) => t.halt = Some(e),
            None => t.plan = None,
        }
    }

    fn run_step(&self, s: &ShredState<B::Plan>, crash_after: bool) -> Option<ShredState<B::Plan>> {
        let plan = s.plan.as_ref()?;
        let step = match self.backend.next(plan) {
            Err(e) => return Some(Self::halted(s, e)),
            Ok(None) => return None,
            Ok(Some(step)) => step,
        };
        if crash_after && (s.env.crash_used || !step.calls_custody()) {
            return None;
        }
        let mut t = s.clone();
        match execute(&mut t.env, &self.layout, &step) {
            Effect::Refused => {
                let mut u = s.clone();
                u.refused = Some(format!("the environment cannot run {step:?}"));
                Some(u)
            }
            Effect::Faulted => Some(t),
            Effect::Done if crash_after => {
                self.crash(&mut t);
                Some(t)
            }
            Effect::Done => match self.backend.apply(plan, &step) {
                Err(e) => Some(Self::halted(s, e)),
                Ok(next) => {
                    if step.is_durable() {
                        t.durable = Some(next.clone());
                    }
                    t.plan = Some(next);
                    Some(t)
                }
            },
        }
    }
}

impl<B: ShredBackend> Model for ShredModel<B> {
    type State = ShredState<B::Plan>;
    type Action = ShredAction;

    fn init(&self) -> Vec<Self::State> {
        let mut env = Env::genesis(&self.layout);
        env.orphans_survive = self.orphans_survive;
        let (plan, halt) = match self.backend.genesis(&self.layout) {
            Ok(plan) => (Some(plan), None),
            Err(e) => (None, Some(e)),
        };
        (0..self.orders.len())
            .map(|order| ShredState {
                order,
                durable: plan.clone(),
                plan: plan.clone(),
                env: env.clone(),
                halt: halt.clone(),
                refused: None,
            })
            .collect()
    }

    fn actions(&self, s: &Self::State, out: &mut Vec<ShredAction>) {
        if s.halt.is_none() && s.refused.is_none() {
            out.extend(ACTIONS);
        }
    }

    fn step(&self, s: &Self::State, a: &ShredAction) -> Option<Self::State> {
        if s.halt.is_some() || s.refused.is_some() {
            return None;
        }
        match a {
            ShredAction::Request => {
                let k = *self.requests_of(s).get(s.env.requested.len())?;
                let mut t = s.clone();
                t.env.requested.insert(k);
                let plan = self.backend.request(s.plan.as_ref()?, k);
                let durable = self.backend.request(s.durable.as_ref()?, k);
                match (plan, durable) {
                    (Ok(p), Ok(d)) => {
                        t.plan = Some(p);
                        t.durable = Some(d);
                        Some(t)
                    }
                    (Err(e), _) | (_, Err(e)) => Some(Self::halted(s, e)),
                }
            }
            ShredAction::Step => self.run_step(s, false),
            ShredAction::StepThenCrash => self.run_step(s, true),
            // A fault while no run is in flight changes nothing the
            // properties read, so the model offers faults only during runs.
            ShredAction::Crash => {
                if s.env.crash_used || s.env.requested == s.env.erased {
                    return None;
                }
                let mut t = s.clone();
                self.crash(&mut t);
                Some(t)
            }
            ShredAction::CustodyFails | ShredAction::CustodyReplyLost => {
                if s.env.fault_used || s.env.requested == s.env.erased {
                    return None;
                }
                let mut t = s.clone();
                t.env.fault_used = true;
                t.env.armed = Some(if *a == ShredAction::CustodyFails {
                    Fault::Fails
                } else {
                    Fault::ReplyLost
                });
                Some(t)
            }
            ShredAction::DailySnapshot => {
                if s.env.daily_used {
                    return None;
                }
                let mut t = s.clone();
                t.env.daily_used = true;
                let roots = t.env.roots_of(t.env.epoch);
                let opened = closure(t.env.live.iter(), &roots);
                let verified = t
                    .env
                    .live_keys(&self.layout)
                    .iter()
                    .all(|k| opened.deks.contains(k));
                t.env.snapshots.push(Snap {
                    epoch: t.env.epoch,
                    rows: t.env.live.clone(),
                    verified,
                });
                Some(t)
            }
        }
    }

    fn is_terminal(&self, s: &Self::State) -> bool {
        s.halt.is_some()
            || s.refused.is_some()
            || (s.env.requested.len() == self.requests_of(s).len()
                && s.env.erased == s.env.requested
                && s.env.crash_used
                && s.env.fault_used
                && s.env.daily_used)
    }
}

// ---------------------------------------------------------------------------
// Predicates. Each returns why the state breaks it.

/// I-81: an erased key that the attacker opens from every row ever
/// written and every live custody root.
///
/// It also covers the keyed digests of design section 3.5 (G24): no
/// digest key that computed a digest of an erased key opens. Such a key
/// would let a guessed email or attribute tuple be confirmed against the
/// erased subject's index row in a backup.
pub fn i81_breach(env: &Env) -> Option<String> {
    let open = closure(env.written.iter(), &env.live_roots());
    if let Some(k) = env.erased.iter().find(|k| open.deks.contains(k)) {
        return Some(format!(
            "I-81: erased key k{k} still opens from the stored rows under live roots {:?}",
            env.live_roots()
        ));
    }
    env.erased.iter().find_map(|k| {
        env.digest_keys_of(*k)
            .into_iter()
            .find(|s| open.secrets.contains(s))
            .map(|s| {
                format!(
                    "I-81 (G24): digest key instance s{s}, which digested erased key k{k}, still opens under live roots {:?}",
                    env.live_roots()
                )
            })
    })
}

/// Progress: the planner has nothing to do while a recorded request is
/// not complete. ADR-004 part 2: requests that arrive while a rotation
/// runs "join the next rotation, which starts as soon as the running one
/// ends", and "A crash at any step loses nothing".
pub fn request_stranded(env: &Env, idle: bool) -> Option<String> {
    if !idle || env.requested == env.erased {
        return None;
    }
    let stranded: Vec<KeyIx> = env.requested.difference(&env.erased).copied().collect();
    Some(format!(
        "requests-complete: the planner is idle while the erasure of {stranded:?} is requested and not complete"
    ))
}

/// No data loss: a live key that does not open from the live store, or
/// from the newest verified snapshot, under the live custody roots.
pub fn data_loss(env: &Env, layout: &Layout) -> Option<String> {
    let roots = env.live_roots();
    let live = closure(env.live.iter(), &roots);
    if let Some(k) = env
        .live_keys(layout)
        .into_iter()
        .find(|k| !live.deks.contains(k))
    {
        return Some(format!(
            "no-data-loss: live key k{k} does not open from the live store"
        ));
    }
    if let Some(g) = (0..layout.group_count())
        .filter(|g| layout.is_digest(*g))
        .find(|g| {
            env.current
                .get(usize::from(*g))
                .is_none_or(|s| !live.secrets.contains(s))
        })
    {
        return Some(format!(
            "no-data-loss: the current digest key of g{g} does not open from the live store"
        ));
    }
    let Some(snap) = env.newest_verified() else {
        return Some("no-data-loss: no verified snapshot".to_owned());
    };
    let restored = closure(snap.rows.iter(), &roots);
    env.live_keys(layout)
        .into_iter()
        .find(|k| !restored.deks.contains(k))
        .map(|k| {
            format!(
                "no-data-loss: live key k{k} does not open from the newest verified snapshot (epoch {})",
                snap.epoch
            )
        })
}

/// Completion after the receipt: a completion in `t` that `s` did not
/// have, while a root older than its epoch is alive or the previous
/// epoch has no receipt.
pub fn completion_breach(s: &Env, t: &Env) -> Option<String> {
    if t.completions.len() <= s.completions.len() {
        return None;
    }
    let c = t.completions.last()?;
    let older_alive = t.roots.iter().any(|r| r.alive && r.epoch < c.epoch);
    let previous = c.epoch.saturating_sub(1);
    if older_alive || !t.receipts.contains(&previous) {
        Some(format!(
            "completion-after-receipt: {c:?} recorded with receipts {:?} and an older root alive: {older_alive}",
            t.receipts
        ))
    } else {
        None
    }
}

/// The property ids of M-SHRED.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// Every step the planner gives can run in the environment.
    pub const STEPS_RUN: &str = "planner-steps-run";
    /// I-81 over every row ever written and every live custody root.
    pub const I81: &str = "I-81";
    /// No live key is lost, from the live store or the newest verified
    /// snapshot.
    pub const NO_DATA_LOSS: &str = "no-data-loss";
    /// A completion is recorded only after the old epoch's receipt.
    pub const COMPLETION_AFTER_RECEIPT: &str = "completion-after-receipt";
    /// The planner is never idle while a recorded request is incomplete.
    pub const REQUESTS_COMPLETE: &str = "requests-complete";
    /// Witness: an erasure completes.
    pub const W_COMPLETES: &str = "witness-erasure-completes";
    /// Witness: every request of the universe completes.
    pub const W_ALL: &str = "witness-every-request-completes";
    /// Witness: a crash in the middle of a run resumes to a completion.
    pub const W_CRASH_RESUMES: &str = "witness-crash-resumes";
    /// Witness: a custody fault recovers to a completion.
    pub const W_FAULT_RECOVERS: &str = "witness-custody-fault-recovers";
}

/// Every property of M-SHRED.
pub fn properties<'a, B: ShredBackend>(m: &'a ShredModel<B>) -> Vec<Property<'a, ShredModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &ShredState<B::Plan>| {
            match &s.halt {
                None => Ok(()),
                Some(why) => Err(format!("the backend did not answer: {why}")),
            }
        }),
        Property::always_with(ids::STEPS_RUN, |s: &ShredState<B::Plan>| {
            s.refused.as_ref().map_or(Ok(()), |why| Err(why.clone()))
        }),
        Property::always_with(ids::I81, |s: &ShredState<B::Plan>| {
            i81_breach(&s.env).map_or(Ok(()), Err)
        }),
        Property::always_with(ids::NO_DATA_LOSS, move |s: &ShredState<B::Plan>| {
            data_loss(&s.env, m.layout()).map_or(Ok(()), Err)
        }),
        Property::transition_with(
            ids::COMPLETION_AFTER_RECEIPT,
            |s: &ShredState<B::Plan>, _a: &ShredAction, t: &ShredState<B::Plan>| {
                completion_breach(&s.env, &t.env).map_or(Ok(()), Err)
            },
        ),
        Property::always_with(ids::REQUESTS_COMPLETE, move |s: &ShredState<B::Plan>| {
            request_stranded(&s.env, m.idle(s)).map_or(Ok(()), Err)
        }),
        Property::reachable(ids::W_COMPLETES, |s: &ShredState<B::Plan>| {
            !s.env.erased.is_empty()
        }),
        Property::reachable(ids::W_ALL, move |s: &ShredState<B::Plan>| {
            s.env.erased.len() == m.requests_of(s).len()
        }),
        Property::reachable(ids::W_CRASH_RESUMES, |s: &ShredState<B::Plan>| {
            s.env.resumed_after_crash
        }),
        Property::reachable(ids::W_FAULT_RECOVERS, |s: &ShredState<B::Plan>| {
            s.env.recovered_after_fault
        }),
    ]
}

// ---------------------------------------------------------------------------
// Scripted walks, for the deterministic I-81 tests.

/// Why exploration stops at `s`: a backend refusal or a step the
/// environment cannot run.
fn stopped<P>(s: &ShredState<P>) -> Option<String> {
    match (&s.halt, &s.refused) {
        (Some(why), _) => Some(format!("the backend did not answer: {why}")),
        (None, Some(why)) => Some(format!("{}: {why}", ids::STEPS_RUN)),
        (None, None) => None,
    }
}

/// The states of one walk: the start state and the state after each
/// action. A disabled action ends the walk with an error.
///
/// # Errors
///
/// Returns why the walk stopped: no start state, or a disabled action.
pub fn walk<B: ShredBackend>(
    m: &ShredModel<B>,
    script: &[ShredAction],
) -> Result<Vec<ShredState<B::Plan>>, String> {
    let mut s = m.initial().ok_or("the model gave no start state")?;
    if let Some(why) = stopped(&s) {
        return Err(why);
    }
    let mut out = vec![s.clone()];
    for (i, a) in script.iter().enumerate() {
        s = m
            .step(&s, a)
            .ok_or_else(|| format!("action {i} ({a:?}) is disabled"))?;
        if let Some(why) = stopped(&s) {
            return Err(why);
        }
        out.push(s.clone());
    }
    Ok(out)
}

/// Runs steps from `s` until the planner has nothing to do, at most
/// `limit` steps.
///
/// # Errors
///
/// Returns why the run stopped: a halt, a refused step or the limit.
pub fn drain<B: ShredBackend>(
    m: &ShredModel<B>,
    s: &ShredState<B::Plan>,
    limit: usize,
) -> Result<Vec<ShredState<B::Plan>>, String> {
    let mut out = Vec::new();
    let mut cur = s.clone();
    for _ in 0..limit {
        if let Some(why) = stopped(&cur) {
            return Err(why);
        }
        let Some(plan) = cur.plan.as_ref() else {
            return Err("no planner state".to_owned());
        };
        match m.backend().next(plan) {
            Err(e) => return Err(format!("the backend did not answer: {e}")),
            Ok(None) => return Ok(out),
            Ok(Some(step)) => {
                cur = m
                    .step(&cur, &ShredAction::Step)
                    .ok_or_else(|| format!("{step:?} could not run"))?;
                if let Some(why) = stopped(&cur) {
                    return Err(why);
                }
                out.push(cur.clone());
            }
        }
    }
    Err(format!("no end after {limit} steps"))
}

/// The breaches of the three safety predicates along `states`, in order.
pub fn breaches<P>(states: &[ShredState<P>], layout: &Layout) -> Vec<String> {
    let mut out = Vec::new();
    for s in states {
        out.extend(i81_breach(&s.env));
        out.extend(data_loss(&s.env, layout));
    }
    for pair in states.windows(2) {
        if let [s, t] = pair {
            out.extend(completion_breach(&s.env, &t.env));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! Teeth of the `planner-steps-run` property. The other teeth of
    //! M-SHRED live in `tests/i81_shred.rs`.

    #![allow(clippy::panic, reason = "test code reports a missed defect")]

    use super::*;
    use fstp_domain_testkit::harness::teeth::expect_violation;
    use fstp_mc::{Config, check};

    /// The reference planner, but it skips step 3's custody call: it gives
    /// `RewrapGroups(e)` where `NewEpoch(e)` is due. No root of epoch `e`
    /// exists then, so the environment cannot run the step.
    struct SkipsNewEpoch;

    impl ShredBackend for SkipsNewEpoch {
        type Plan = RefPlan;

        fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
            Reference.genesis(layout)
        }

        fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
            Reference.request(plan, dek)
        }

        fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
            Ok(match Reference.next(plan)? {
                Some(RefStep::NewEpoch(e)) => Some(RefStep::RewrapGroups(e)),
                other => other,
            })
        }

        fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
            Reference.apply(plan, done)
        }

        fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
            Reference.restart(stored)
        }
    }

    /// I-81 teeth for M-SHRED's `planner-steps-run`: a planner step the
    /// environment cannot run is reported, not pruned in silence.
    #[test]
    fn i81_teeth_unrunnable_step_is_caught() {
        let model = ShredModel::new(SkipsNewEpoch);
        let props = properties(&model);
        let outcome = check(
            &model,
            &props,
            &Config::default().with_stop_when_decided(false),
        );
        if let Err(e) = expect_violation(&outcome, ids::STEPS_RUN) {
            panic!("{e}\n{outcome}");
        }
    }
}
