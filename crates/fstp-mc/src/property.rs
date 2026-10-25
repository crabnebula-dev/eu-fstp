//! Properties checked during exploration, and the bookkeeping of verdicts.

use core::fmt;

use crate::model::Model;
use crate::outcome::{PropertyResult, Verdict, Violation};
use crate::trace::{Step, Trace};

/// The kind of a [`Property`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PropertyKind {
    /// A state predicate that must hold in every reachable state.
    Always,
    /// A predicate over `(before, action, after)` that must hold for every
    /// enabled transition out of a reachable state.
    Transition,
    /// A state predicate that must hold in at least one reachable state.
    /// This detects vacuous models, for example a model where no proposal
    /// can ever reach GRANTED.
    Reachable,
    /// Every reachable state that is not terminal has an enabled action.
    DeadlockFree,
}

impl PropertyKind {
    /// Returns the lowercase name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            PropertyKind::Always => "always",
            PropertyKind::Transition => "transition",
            PropertyKind::Reachable => "reachable",
            PropertyKind::DeadlockFree => "deadlock freedom",
        }
    }
}

impl fmt::Display for PropertyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

type StatePred<'a, S> = Box<dyn Fn(&S) -> Result<(), String> + 'a>;
type TransitionPred<'a, S, A> = Box<dyn Fn(&S, &A, &S) -> Result<(), String> + 'a>;
type ReachPred<'a, S> = Box<dyn Fn(&S) -> bool + 'a>;

enum Pred<'a, S, A> {
    Always(StatePred<'a, S>),
    Transition(TransitionPred<'a, S, A>),
    Reachable(ReachPred<'a, S>),
    DeadlockFree,
}

/// A named property of a [`Model`].
///
/// The identifier names the specification item the property checks, such as
/// `I-05` or `SoD-04`, so a failure report points at the rule that broke.
/// Several properties may share one identifier when a rule needs more than
/// one check.
///
/// Predicates must be deterministic. With symmetry reduction they must also
/// be invariant under the model's symmetries ([`Model::canonicalize`]).
///
/// The model type usually needs naming, because closures need to know their
/// argument types: `Property::<MyModel>::always("I-05", |s| ...)`.
pub struct Property<'a, M: Model> {
    id: String,
    pred: Pred<'a, M::State, M::Action>,
}

impl<'a, M: Model> Property<'a, M> {
    /// A state predicate that must hold in every reachable state.
    pub fn always(id: impl Into<String>, pred: impl Fn(&M::State) -> bool + 'a) -> Self {
        Property::always_with(
            id,
            move |s| {
                if pred(s) { Ok(()) } else { Err(String::new()) }
            },
        )
    }

    /// Like [`Property::always`], with a predicate that explains a failure.
    /// The message appears in the violation report.
    pub fn always_with(
        id: impl Into<String>,
        pred: impl Fn(&M::State) -> Result<(), String> + 'a,
    ) -> Self {
        Property {
            id: id.into(),
            pred: Pred::Always(Box::new(pred)),
        }
    }

    /// A predicate over `(before, action, after)` that must hold for every
    /// enabled transition out of a reachable state.
    pub fn transition(
        id: impl Into<String>,
        pred: impl Fn(&M::State, &M::Action, &M::State) -> bool + 'a,
    ) -> Self {
        Property::transition_with(id, move |s, a, t| {
            if pred(s, a, t) {
                Ok(())
            } else {
                Err(String::new())
            }
        })
    }

    /// Like [`Property::transition`], with a predicate that explains a failure.
    pub fn transition_with(
        id: impl Into<String>,
        pred: impl Fn(&M::State, &M::Action, &M::State) -> Result<(), String> + 'a,
    ) -> Self {
        Property {
            id: id.into(),
            pred: Pred::Transition(Box::new(pred)),
        }
    }

    /// A state predicate that at least one reachable state must satisfy.
    ///
    /// The verdict is [`Verdict::Reached`] with a shortest witness trace,
    /// [`Verdict::Unreachable`] after an exhaustive run without a witness,
    /// or [`Verdict::Unknown`] after a bounded run without a witness.
    pub fn reachable(id: impl Into<String>, pred: impl Fn(&M::State) -> bool + 'a) -> Self {
        Property {
            id: id.into(),
            pred: Pred::Reachable(Box::new(pred)),
        }
    }

    /// Every reachable state either is terminal ([`Model::is_terminal`]) or
    /// has at least one enabled action.
    pub fn deadlock_free(id: impl Into<String>) -> Self {
        Property {
            id: id.into(),
            pred: Pred::DeadlockFree,
        }
    }

    /// Returns the identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the kind.
    pub fn kind(&self) -> PropertyKind {
        match self.pred {
            Pred::Always(_) => PropertyKind::Always,
            Pred::Transition(_) => PropertyKind::Transition,
            Pred::Reachable(_) => PropertyKind::Reachable,
            Pred::DeadlockFree => PropertyKind::DeadlockFree,
        }
    }
}

impl<M: Model> fmt::Debug for Property<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Property")
            .field("id", &self.id)
            .field("kind", &self.kind())
            .finish()
    }
}

fn detail(message: String) -> Option<String> {
    if message.is_empty() {
        None
    } else {
        Some(message)
    }
}

/// Records the first verdict of each property during a run.
///
/// Exploration calls the `check_*` methods in breadth-first order, so the
/// first violation recorded for a property has a shortest trace.
pub(crate) struct Tracker<'p, 'a, M: Model> {
    props: &'p [Property<'a, M>],
    decided: Vec<Option<Verdict<M::State, M::Action>>>,
    open: usize,
    always: Vec<usize>,
    transition: Vec<usize>,
    reachable: Vec<usize>,
    deadlock: Vec<usize>,
}

impl<'p, 'a, M: Model> Tracker<'p, 'a, M> {
    pub(crate) fn new(props: &'p [Property<'a, M>]) -> Self {
        let mut t = Tracker {
            props,
            decided: props.iter().map(|_| None).collect(),
            open: props.len(),
            always: Vec::new(),
            transition: Vec::new(),
            reachable: Vec::new(),
            deadlock: Vec::new(),
        };
        for (i, p) in props.iter().enumerate() {
            match p.kind() {
                PropertyKind::Always => t.always.push(i),
                PropertyKind::Transition => t.transition.push(i),
                PropertyKind::Reachable => t.reachable.push(i),
                PropertyKind::DeadlockFree => t.deadlock.push(i),
            }
        }
        t
    }

    /// True when there is at least one property and every one is decided.
    pub(crate) fn all_decided(&self) -> bool {
        !self.props.is_empty() && self.open == 0
    }

    fn is_open(&self, i: usize) -> bool {
        matches!(self.decided.get(i), Some(None))
    }

    fn decide(&mut self, i: usize, verdict: Verdict<M::State, M::Action>) {
        if let Some(slot @ None) = self.decided.get_mut(i) {
            *slot = Some(verdict);
            self.open = self.open.saturating_sub(1);
        }
    }

    /// Checks the always and reachable properties on a newly reached state.
    /// `trace` builds the path to that state and runs only when needed.
    pub(crate) fn check_state(
        &mut self,
        state: &M::State,
        trace: impl Fn() -> Trace<M::State, M::Action>,
    ) {
        for k in 0..self.always.len() {
            let Some(&i) = self.always.get(k) else {
                continue;
            };
            if !self.is_open(i) {
                continue;
            }
            let result = match self.props.get(i).map(|p| &p.pred) {
                Some(Pred::Always(pred)) => pred(state),
                _ => Ok(()),
            };
            if let Err(message) = result {
                let v = Violation {
                    trace: trace(),
                    detail: detail(message),
                };
                self.decide(i, Verdict::Violated(v));
            }
        }
        for k in 0..self.reachable.len() {
            let Some(&i) = self.reachable.get(k) else {
                continue;
            };
            if !self.is_open(i) {
                continue;
            }
            let hit = match self.props.get(i).map(|p| &p.pred) {
                Some(Pred::Reachable(pred)) => pred(state),
                _ => false,
            };
            if hit {
                self.decide(i, Verdict::Reached(trace()));
            }
        }
    }

    /// Checks the transition properties on one enabled transition.
    /// `prefix` builds the path to `before` and runs only when needed.
    pub(crate) fn check_transition(
        &mut self,
        before: &M::State,
        action: &M::Action,
        after: &M::State,
        prefix: impl Fn() -> Trace<M::State, M::Action>,
    ) {
        for k in 0..self.transition.len() {
            let Some(&i) = self.transition.get(k) else {
                continue;
            };
            if !self.is_open(i) {
                continue;
            }
            let result = match self.props.get(i).map(|p| &p.pred) {
                Some(Pred::Transition(pred)) => pred(before, action, after),
                _ => Ok(()),
            };
            if let Err(message) = result {
                let mut trace = prefix();
                trace.steps.push(Step {
                    action: action.clone(),
                    state: after.clone(),
                });
                let v = Violation {
                    trace,
                    detail: detail(message),
                };
                self.decide(i, Verdict::Violated(v));
            }
        }
    }

    /// Records a deadlock: a non-terminal state with no enabled action.
    pub(crate) fn check_deadlock(&mut self, trace: impl Fn() -> Trace<M::State, M::Action>) {
        for k in 0..self.deadlock.len() {
            let Some(&i) = self.deadlock.get(k) else {
                continue;
            };
            if !self.is_open(i) {
                continue;
            }
            let v = Violation {
                trace: trace(),
                detail: Some("no enabled action in a non-terminal state".to_owned()),
            };
            self.decide(i, Verdict::Violated(v));
        }
    }

    /// True when some deadlock property is still open, so deadlock checks
    /// are worth their cost.
    pub(crate) fn wants_deadlock(&self) -> bool {
        self.deadlock.iter().any(|&i| self.is_open(i))
    }

    /// True when some transition property is still open.
    pub(crate) fn wants_transitions(&self) -> bool {
        self.transition.iter().any(|&i| self.is_open(i))
    }

    /// Produces one result per property, in input order. Undecided
    /// properties become verified (or unreachable) only when `exhaustive`.
    pub(crate) fn finish(self, exhaustive: bool) -> Vec<PropertyResult<M::State, M::Action>> {
        self.props
            .iter()
            .zip(self.decided)
            .map(|(p, decided)| {
                let kind = p.kind();
                let verdict = match decided {
                    Some(v) => v,
                    None if !exhaustive => Verdict::Unknown,
                    None if kind == PropertyKind::Reachable => Verdict::Unreachable,
                    None => Verdict::Verified,
                };
                PropertyResult {
                    id: p.id.clone(),
                    kind,
                    verdict,
                }
            })
            .collect()
    }
}
