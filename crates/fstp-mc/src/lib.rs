//! In-house bounded explicit-state model checker.
//!
//! This is the model-checking layer of `SPEC/07-test-plan/test-plan.md`. From M2
//! onwards it checks the proposal state machine, contracts, payment requests
//! and separation of duties over time. `SPEC/02-domain/invariants.md` gives every
//! invariant that involves state transitions a model-checking property.
//!
//! # How it works
//!
//! A [`Model`] has initial states, candidate actions and a step function
//! whose `None` result means the action's guard is false. [`check`] explores
//! every reachable state breadth-first and evaluates [`Property`] values:
//!
//! | Kind | Holds when |
//! | --- | --- |
//! | [`Property::always`] | the predicate holds in every reachable state |
//! | [`Property::transition`] | the predicate holds for every enabled transition `(before, action, after)` |
//! | [`Property::reachable`] | some reachable state satisfies the predicate; this catches vacuous models |
//! | [`Property::deadlock_free`] | every reachable non-terminal state has an enabled action |
//!
//! Each property carries an identifier, such as `I-05` or `SoD-04`, which
//! names it in every report.
//!
//! # Guarantees
//!
//! - **Sound visited set.** The checker stores full states and compares them
//!   for equality. It never uses lossy fingerprints, so a hash collision can
//!   never hide a state.
//! - **Shortest counterexamples.** Breadth-first order makes the first
//!   violation of each property a shortest trace. Parent links rebuild it.
//! - **Honest bounds.** [`Config::max_depth`] and [`Config::max_states`]
//!   bound a run. A run that drops a state at a bound reports
//!   `exhaustive: false`. Only an exhaustive run reports
//!   [`Verdict::Verified`] or [`Verdict::Unreachable`]. Anything else that
//!   was not decided is [`Verdict::Unknown`].
//! - **Determinism.** Results depend only on the model, the properties and
//!   the configuration. Exploration order follows [`Model::init`] and
//!   [`Model::actions`], and never hash-map iteration order.
//!
//! [`Model::canonicalize`] enables symmetry reduction; read its soundness
//! requirement before overriding it. [`simulate`] runs seeded random walks
//! for state spaces too large to exhaust, and its outcome is always labelled
//! non-exhaustive. [`explore`] returns the stored state space itself.
//!
//! # Example
//!
//! The Die Hard water jugs: with a 3-gallon and a 5-gallon jug, measure
//! exactly 4 gallons.
//!
//! ```
//! use fstp_mc::{check, Config, Model, Property, Verdict};
//!
//! struct Jugs;
//!
//! #[derive(Clone, Debug)]
//! enum Pour { FillSmall, FillBig, EmptySmall, EmptyBig, SmallToBig, BigToSmall }
//!
//! impl Model for Jugs {
//!     /// (small, big) in gallons.
//!     type State = (u8, u8);
//!     type Action = Pour;
//!
//!     fn init(&self) -> Vec<(u8, u8)> {
//!         vec![(0, 0)]
//!     }
//!
//!     fn actions(&self, _: &(u8, u8), actions: &mut Vec<Pour>) {
//!         use Pour::*;
//!         actions.extend([FillSmall, FillBig, EmptySmall, EmptyBig, SmallToBig, BigToSmall]);
//!     }
//!
//!     fn step(&self, &(small, big): &(u8, u8), pour: &Pour) -> Option<(u8, u8)> {
//!         let next = match pour {
//!             Pour::FillSmall => (3, big),
//!             Pour::FillBig => (small, 5),
//!             Pour::EmptySmall => (0, big),
//!             Pour::EmptyBig => (small, 0),
//!             Pour::SmallToBig => {
//!                 let moved = small.min(5 - big);
//!                 (small - moved, big + moved)
//!             }
//!             Pour::BigToSmall => {
//!                 let moved = big.min(3 - small);
//!                 (small + moved, big - moved)
//!             }
//!         };
//!         // A pour that changes nothing is disabled.
//!         (next != (small, big)).then_some(next)
//!     }
//! }
//!
//! // Domain models use specification identifiers such as I-05 here.
//! let properties = [
//!     Property::<Jugs>::always("never-four-gallons", |&(_, big)| big != 4),
//!     Property::<Jugs>::reachable("four-gallons-reachable", |&(_, big)| big == 4),
//!     Property::<Jugs>::deadlock_free("no-deadlock"),
//! ];
//! let config = Config::default().with_stop_when_decided(false);
//! let outcome = check(&Jugs, &properties, &config);
//!
//! assert!(outcome.exhaustive);
//! assert_eq!(outcome.stats.states, 16);
//! let violation = outcome.verdict("never-four-gallons").and_then(Verdict::violation);
//! let trace = &violation.expect("4 gallons are reachable").trace;
//! assert_eq!(trace.len(), 6);
//! assert_eq!(*trace.last_state(), (3, 4));
//! assert!(matches!(outcome.verdict("no-deadlock"), Some(Verdict::Verified)));
//! println!("{outcome}");
//! ```

mod explore;
pub mod graph;
mod model;
mod outcome;
mod property;
mod rng;
mod sim;
mod table;
mod trace;

pub use explore::{Config, DEFAULT_MAX_STATES, StateSpace, check, explore};
pub use model::Model;
pub use outcome::{Mode, Outcome, PropertyResult, Stats, Verdict, Violation};
pub use property::{Property, PropertyKind};
pub use sim::{SimConfig, simulate};
pub use trace::{Step, Trace};
