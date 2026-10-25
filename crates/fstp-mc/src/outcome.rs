//! Results of a run: statistics, the exhaustive flag and one verdict per property.

use core::fmt::{self, Debug, Display};

use crate::property::PropertyKind;
use crate::trace::Trace;

/// A violated property with its counterexample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation<S, A> {
    /// The counterexample. For the exhaustive checker it is a shortest one.
    pub trace: Trace<S, A>,
    /// The message returned by the predicate, if any.
    pub detail: Option<String>,
}

/// The verdict on one property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict<S, A> {
    /// The property holds in every reachable state or transition. Only an
    /// exhaustive run gives this verdict.
    Verified,
    /// The property fails. The trace leads to the violating state, to the
    /// violating transition, or to the deadlocked state.
    Violated(Violation<S, A>),
    /// A reachable property is satisfied. The trace leads to a witness state.
    Reached(Trace<S, A>),
    /// A reachable property is satisfied by no reachable state. Only an
    /// exhaustive run gives this verdict. It usually means the model, or the
    /// property, is wrong.
    Unreachable,
    /// The run was not exhaustive and found neither a violation nor a
    /// witness. Nothing is claimed about the property.
    Unknown,
}

impl<S, A> Verdict<S, A> {
    /// True for [`Verdict::Verified`] and [`Verdict::Reached`].
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Verified | Verdict::Reached(_))
    }

    /// True for [`Verdict::Violated`] and [`Verdict::Unreachable`].
    pub fn is_failure(&self) -> bool {
        matches!(self, Verdict::Violated(_) | Verdict::Unreachable)
    }

    /// True for [`Verdict::Unknown`].
    pub fn is_unknown(&self) -> bool {
        matches!(self, Verdict::Unknown)
    }

    /// Returns the violation, if the property was violated.
    pub fn violation(&self) -> Option<&Violation<S, A>> {
        match self {
            Verdict::Violated(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the witness trace, if a reachable property was reached.
    pub fn witness(&self) -> Option<&Trace<S, A>> {
        match self {
            Verdict::Reached(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the counterexample or witness trace, whichever exists.
    pub fn trace(&self) -> Option<&Trace<S, A>> {
        match self {
            Verdict::Violated(v) => Some(&v.trace),
            Verdict::Reached(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the uppercase label used in reports.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::Violated(_) => "VIOLATED",
            Verdict::Reached(_) => "REACHED",
            Verdict::Unreachable => "UNREACHABLE",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

/// The verdict on one property, with the property's identifier and kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyResult<S, A> {
    /// The property's identifier, such as `I-05`.
    pub id: String,
    /// The property's kind.
    pub kind: PropertyKind,
    /// The verdict.
    pub verdict: Verdict<S, A>,
}

/// Counters for a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Exhaustive mode: distinct states stored. Simulation: state visits,
    /// counting repeats.
    pub states: usize,
    /// Enabled transitions evaluated. A transition to an already stored
    /// state counts too.
    pub transitions: usize,
    /// Exhaustive mode: the depth of the deepest stored state, which is the
    /// length of the longest shortest path. Simulation: the longest walk.
    pub max_depth: usize,
}

/// How a run explored the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Breadth-first exploration of every reachable state within the bounds.
    Exhaustive {
        /// The configured depth bound.
        max_depth: usize,
        /// The configured state bound.
        max_states: usize,
    },
    /// Seeded random walks. Never exhaustive.
    Simulation {
        /// The seed of the walk generator.
        seed: u64,
        /// The number of walks performed.
        walks: usize,
        /// The configured maximum number of steps per walk.
        max_steps: usize,
    },
}

/// The result of a run.
///
/// [`Display`] prints a report with the statistics, then one line per
/// property and the trace of every violation and witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome<S, A> {
    /// How the model was explored.
    pub mode: Mode,
    /// Counters.
    pub stats: Stats,
    /// True only when every reachable state was stored and every enabled
    /// transition out of it was evaluated. A random simulation is never
    /// exhaustive.
    pub exhaustive: bool,
    /// True when a successor that is not stored was dropped because its depth
    /// along the current path exceeds the depth bound. Such a successor may
    /// also have been dropped earlier by the state bound.
    pub depth_bound_hit: bool,
    /// True when a new state was dropped because the state bound was reached.
    pub state_bound_hit: bool,
    /// True when exploration stopped because every property was decided.
    pub stopped_early: bool,
    /// One result per property, in the order the properties were given.
    pub results: Vec<PropertyResult<S, A>>,
}

impl<S, A> Outcome<S, A> {
    /// Returns the first result whose identifier is `id`.
    pub fn result(&self, id: &str) -> Option<&PropertyResult<S, A>> {
        self.results.iter().find(|r| r.id == id)
    }

    /// Returns the verdict of the first property whose identifier is `id`.
    pub fn verdict(&self, id: &str) -> Option<&Verdict<S, A>> {
        self.result(id).map(|r| &r.verdict)
    }

    /// True when some property was violated or found unreachable.
    pub fn has_failures(&self) -> bool {
        self.results.iter().any(|r| r.verdict.is_failure())
    }

    /// True when every property passed: verified, or reached for reachable
    /// properties. A property with an unknown verdict did not pass.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.verdict.is_pass())
    }

    /// Returns the results that failed.
    pub fn failures(&self) -> impl Iterator<Item = &PropertyResult<S, A>> {
        self.results.iter().filter(|r| r.verdict.is_failure())
    }
}

impl<S: Debug, A: Debug> Outcome<S, A> {
    /// Returns `Ok` when [`Outcome::all_passed`], else the full report.
    ///
    /// Use it where full verification is the goal, which needs an exhaustive
    /// run.
    pub fn require_all_passed(&self) -> Result<(), String> {
        if self.all_passed() {
            Ok(())
        } else {
            Err(self.to_string())
        }
    }

    /// Returns `Ok` unless [`Outcome::has_failures`], else the full report.
    ///
    /// Unknown verdicts pass. Use it for bounded runs and simulations, which
    /// can find bugs but cannot verify.
    pub fn require_no_failures(&self) -> Result<(), String> {
        if self.has_failures() {
            Err(self.to_string())
        } else {
            Ok(())
        }
    }
}

impl<S: Debug, A: Debug> Display for Outcome<S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = &self.stats;
        match self.mode {
            Mode::Exhaustive {
                max_depth,
                max_states,
            } => {
                writeln!(
                    f,
                    "fstp-mc breadth-first check: {} states, {} transitions, max depth {}",
                    st.states, st.transitions, st.max_depth
                )?;
                if self.exhaustive {
                    writeln!(f, "exhaustive: yes, every reachable state was explored")?;
                } else {
                    let mut why = Vec::new();
                    if self.depth_bound_hit {
                        why.push(format!("depth bound {max_depth} hit"));
                    }
                    if self.state_bound_hit {
                        why.push(format!("state bound {max_states} hit"));
                    }
                    if self.stopped_early {
                        why.push("stopped once every property was decided".to_owned());
                    }
                    writeln!(
                        f,
                        "exhaustive: NO ({}); nothing is verified",
                        why.join(", ")
                    )?;
                }
            }
            Mode::Simulation {
                seed,
                walks,
                max_steps,
            } => {
                writeln!(
                    f,
                    "fstp-mc random simulation (NOT exhaustive): seed {seed}, {walks} walks of at most {max_steps} steps"
                )?;
                writeln!(
                    f,
                    "{} state visits, {} transitions, longest walk {}; nothing is verified",
                    st.states, st.transitions, st.max_depth
                )?;
            }
        }
        for r in &self.results {
            write!(f, "[{}] {} ({})", r.verdict.label(), r.id, r.kind)?;
            match &r.verdict {
                Verdict::Violated(v) => {
                    writeln!(f, ": counterexample of {} steps", v.trace.len())?;
                    if let Some(d) = &v.detail {
                        writeln!(f, "detail: {d}")?;
                    }
                    if f.alternate() {
                        write!(f, "{:#}", v.trace)?;
                    } else {
                        write!(f, "{}", v.trace)?;
                    }
                }
                Verdict::Reached(t) => {
                    writeln!(f, ": witness of {} steps", t.len())?;
                    if f.alternate() {
                        write!(f, "{t:#}")?;
                    } else {
                        write!(f, "{t}")?;
                    }
                }
                Verdict::Verified | Verdict::Unreachable | Verdict::Unknown => writeln!(f)?,
            }
        }
        Ok(())
    }
}
