//! The [`Model`] trait: a transition system the checker can explore.

use core::fmt::Debug;
use core::hash::Hash;

/// A finite transition system for the checker to explore.
///
/// A model is a set of initial states, a set of candidate actions per state,
/// and a step function. The step function returns `None` when the action's
/// guard is false in that state, so the action is disabled there.
///
/// # Requirements
///
/// Every method must be a pure, deterministic function of its arguments and
/// of `self`. The checker relies on this in three ways:
///
/// - Exploration order, and therefore every reported trace, follows the order
///   of [`Model::init`] and of the actions pushed by [`Model::actions`].
/// - Trace replay ([`crate::Trace::replay`]) re-runs [`Model::step`] and must
///   get the same states back.
/// - Breadth-first order makes the first counterexample a shortest one only
///   when the same state always has the same successors.
///
/// Methods may panic only for bugs in the model itself. The checker does not
/// catch panics from model code.
///
/// # Domain models
///
/// The proposal state machine, contracts, payment requests and separation of
/// duties over time are modelled on this trait from M2 onwards
/// (`07-test-plan/test-plan.md`). Policy parameters live in `self`. A role or
/// guard check that denies an action makes [`Model::step`] return `None`.
pub trait Model {
    /// A state of the system. Two states that compare equal are the same
    /// state. The checker stores full states, never lossy fingerprints.
    type State: Clone + Eq + Hash + Debug;

    /// An action that may move the system from one state to another.
    type Action: Clone + Debug;

    /// Returns the initial states. Duplicates are ignored. Order matters for
    /// determinism: the checker explores initial states in this order.
    fn init(&self) -> Vec<Self::State>;

    /// Pushes the candidate actions for `state` onto `actions`.
    ///
    /// The buffer is empty on entry. Push actions whose guard may be false
    /// as well: [`Model::step`] decides whether each one is enabled.
    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>);

    /// Applies `action` to `state`.
    ///
    /// Returns the successor state, or `None` when the action's guard is
    /// false in `state`. An action whose step returns `Some` is enabled.
    fn step(&self, state: &Self::State, action: &Self::Action) -> Option<Self::State>;

    /// Returns true when `state` is a legitimate final state.
    ///
    /// A state with no enabled action is a deadlock unless it is terminal.
    /// The default declares no state terminal. Terminal states are still
    /// expanded if they have enabled actions.
    fn is_terminal(&self, state: &Self::State) -> bool {
        let _ = state;
        false
    }

    /// Maps `state` to the representative of its symmetry class.
    ///
    /// The default is the identity, which disables symmetry reduction. The
    /// checker stores and expands only the representatives, so a model with
    /// interchangeable identities (for example two reviewers with the same
    /// roles) explores one state per class instead of one per permutation.
    ///
    /// # Soundness requirement
    ///
    /// Let `G` be a group of bijections on states and actions, and write
    /// `s ~ t` when `t = g(s)` for some `g` in `G`. Symmetry reduction gives
    /// the same verdicts as a full search only when all of these hold:
    ///
    /// 1. `canonicalize(s) ~ s` for every state `s`.
    /// 2. The initial states are closed under `G`.
    /// 3. Every `g` in `G` commutes with the transition relation: `a` is
    ///    enabled in `s` exactly when `g(a)` is enabled in `g(s)`, and then
    ///    `step(g(s), g(a)) == Some(g(step(s, a)))`.
    /// 4. [`Model::is_terminal`] and every property give the same answer on
    ///    `s` and `g(s)`, and every transition property gives the same answer
    ///    on `(s, a, t)` and `(g(s), g(a), g(t))`.
    ///
    /// Mapping equivalent states to one representative is not needed for
    /// soundness. It only decides how much the state space shrinks.
    ///
    /// With a non-identity canonicalization, a reported trace is valid up to
    /// symmetry. Each state in it is the canonical form of the result of
    /// applying the action to the previous state. The last state of a
    /// transition counterexample is the successor exactly as
    /// [`Model::step`] returned it, which is what the predicate saw.
    /// Shortest trace lengths are preserved.
    fn canonicalize(&self, state: &Self::State) -> Self::State {
        state.clone()
    }
}
