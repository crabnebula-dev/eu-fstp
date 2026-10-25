//! Execution traces: an initial state followed by action and state steps.

use core::fmt::{self, Debug, Display};
use core::hash::Hash;
use std::collections::HashMap;

use crate::model::Model;

/// One step of a [`Trace`]: the action taken and the state it led to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step<S, A> {
    /// The action applied to the previous state.
    pub action: A,
    /// The state after the action.
    pub state: S,
}

/// A path through a model: an initial state, then action and state steps.
///
/// Traces from the exhaustive checker are shortest paths to their last
/// state, or to the last transition for a transition property. The
/// [`Display`] form prints one line per state and per action. The alternate
/// form (`{:#}`) pretty-prints states and actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace<S, A> {
    /// The initial state.
    pub init: S,
    /// The steps taken from the initial state, in order.
    pub steps: Vec<Step<S, A>>,
}

impl<S, A> Trace<S, A> {
    /// Creates a trace with no steps.
    pub fn new(init: S) -> Trace<S, A> {
        Trace {
            init,
            steps: Vec::new(),
        }
    }

    /// Returns the number of steps (actions) in the trace.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns true when the trace has no steps, so it is a single initial state.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Returns the last state: the state the trace ends in.
    pub fn last_state(&self) -> &S {
        match self.steps.last() {
            Some(step) => &step.state,
            None => &self.init,
        }
    }

    /// Returns every state in order, starting with the initial state.
    pub fn states(&self) -> impl Iterator<Item = &S> {
        core::iter::once(&self.init).chain(self.steps.iter().map(|s| &s.state))
    }

    /// Returns every action in order.
    pub fn actions(&self) -> impl Iterator<Item = &A> {
        self.steps.iter().map(|s| &s.action)
    }
}

impl<S: Clone + Eq + Hash, A: Clone> Trace<S, A> {
    /// Returns a trace with every cycle removed.
    ///
    /// The result starts and ends in the same states as `self`. Each of its
    /// steps is a step of `self`, so it is a valid path whenever `self` is.
    /// No state appears in it twice.
    pub fn without_cycles(&self) -> Trace<S, A> {
        // Position in `steps` of each state on the current path. The initial
        // state sits at position 0, step i at position i + 1.
        let mut seen: HashMap<&S, usize> = HashMap::new();
        seen.insert(&self.init, 0);
        let mut kept: Vec<&Step<S, A>> = Vec::new();
        for step in &self.steps {
            if let Some(&pos) = seen.get(&step.state) {
                // Cut the cycle: drop every step after the earlier visit at
                // position `pos`, which itself stays on the path.
                // Every recorded position is at most `kept.len()`; `min`
                // keeps `drain` total even so.
                for dropped in kept.drain(pos.min(kept.len())..) {
                    seen.remove(&dropped.state);
                }
            } else {
                kept.push(step);
                seen.insert(&step.state, kept.len());
            }
        }
        Trace {
            init: self.init.clone(),
            steps: kept.into_iter().cloned().collect(),
        }
    }
}

impl<S, A> Trace<S, A>
where
    S: Clone + Eq + Hash + Debug,
    A: Clone + Debug,
{
    /// Checks that the trace is a real execution of `model`.
    ///
    /// The initial state must be one of [`Model::init`], before or after
    /// [`Model::canonicalize`]. Every action must be enabled in the previous
    /// state, and the recorded state must equal the successor, before or
    /// after canonicalization. Returns a description of the first mismatch.
    pub fn replay<M>(&self, model: &M) -> Result<(), String>
    where
        M: Model<State = S, Action = A>,
    {
        let inits = model.init();
        let init_ok = inits
            .iter()
            .any(|s| *s == self.init || model.canonicalize(s) == self.init);
        if !init_ok {
            return Err(format!(
                "initial state {:?} is not an initial state of the model",
                self.init
            ));
        }
        let mut prev = &self.init;
        for (i, step) in self.steps.iter().enumerate() {
            let n = i.saturating_add(1);
            let Some(next) = model.step(prev, &step.action) else {
                return Err(format!(
                    "step {n}: action {:?} is not enabled in {prev:?}",
                    step.action
                ));
            };
            if next != step.state && model.canonicalize(&next) != step.state {
                return Err(format!(
                    "step {n}: action {:?} leads to {next:?}, but the trace records {:?}",
                    step.action, step.state
                ));
            }
            prev = &step.state;
        }
        Ok(())
    }
}

impl<S: Debug, A: Debug> Display for Trace<S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pretty = f.alternate();
        if pretty {
            writeln!(f, "initial state: {:#?}", self.init)?;
        } else {
            writeln!(f, "initial state: {:?}", self.init)?;
        }
        for (i, step) in self.steps.iter().enumerate() {
            let n = i.saturating_add(1);
            if pretty {
                writeln!(f, "step {n}: {:#?}", step.action)?;
                writeln!(f, "  state: {:#?}", step.state)?;
            } else {
                writeln!(f, "step {n}: {:?}", step.action)?;
                writeln!(f, "  state: {:?}", step.state)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(init: u8, path: &[u8]) -> Trace<u8, char> {
        Trace {
            init,
            steps: path
                .iter()
                .map(|&s| Step {
                    action: char::from(b'a'.wrapping_add(s)),
                    state: s,
                })
                .collect(),
        }
    }

    fn states(t: &Trace<u8, char>) -> Vec<u8> {
        t.states().copied().collect()
    }

    #[test]
    fn without_cycles_removes_loops() {
        assert_eq!(states(&trace(0, &[1, 2, 1, 3]).without_cycles()), [0, 1, 3]);
        assert_eq!(states(&trace(0, &[1, 0, 2]).without_cycles()), [0, 2]);
        assert_eq!(states(&trace(0, &[1, 2, 0]).without_cycles()), [0]);
        assert_eq!(
            states(&trace(0, &[1, 2, 3, 2, 4, 1, 5]).without_cycles()),
            [0, 1, 5]
        );
        assert_eq!(states(&trace(0, &[1, 2, 3]).without_cycles()), [0, 1, 2, 3]);
        assert_eq!(states(&trace(7, &[]).without_cycles()), [7]);
    }

    #[test]
    fn without_cycles_keeps_original_actions() {
        let t = trace(0, &[1, 2, 1, 3]).without_cycles();
        let actions: Vec<char> = t.actions().copied().collect();
        assert_eq!(actions, ['b', 'd']);
    }

    #[test]
    fn display_lists_states_and_actions() {
        let t = trace(0, &[1, 2]);
        let text = t.to_string();
        assert_eq!(
            text,
            "initial state: 0\nstep 1: 'b'\n  state: 1\nstep 2: 'c'\n  state: 2\n"
        );
        assert_eq!(t.len(), 2);
        assert_eq!(*t.last_state(), 2);
        assert!(!t.is_empty());
        assert!(Trace::<u8, char>::new(3).is_empty());
    }
}
