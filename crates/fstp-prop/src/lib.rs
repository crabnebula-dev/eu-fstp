//! In-house property-based testing harness with integrated shrinking.
//!
//! This is the property-based layer of `SPEC/07-test-plan/test-plan.md`. Every
//! invariant in `SPEC/02-domain/invariants.md` gets a property built on it.
//!
//! # How it works
//!
//! A property is a closure that takes a [`Gen`] and returns `Ok(())` or an
//! error message. Every value a generator returns is built from bounded `u64`
//! choices. Random generation records the choices of each case. When a case
//! fails, the shrinker edits the recorded sequence and runs the property again.
//! It keeps any edit that still fails and is smaller in shortlex order. Every
//! generator therefore shrinks, including generators composed by hand, with no
//! per-type shrinking code. A replay that runs past the end of its sequence
//! draws 0, and every generator maps 0 to its simplest value.
//!
//! Generators are edge-biased. Integers favour both bounds, zero, small values
//! and power-of-two boundaries. Collections favour the minimum length, short
//! lengths and the maximum length, and still reach every length that fits in
//! [`Config::max_choices`]. Strings favour characters that often break
//! parsers and encoders.
//!
//! # Determinism and environment variables
//!
//! The seed is a stable hash of the property name ([`seed_for_name`]), so a run
//! gives the same result every time. [`check`] and [`check_with`] read these
//! variables on top of their configuration:
//!
//! | Variable | Effect |
//! | --- | --- |
//! | `FSTP_PROP_CASES` | Number of valid cases (default 256) |
//! | `FSTP_PROP_SEED` | Seed, decimal or `0x` hex |
//! | `FSTP_PROP_REPLAY` | Replay one choice sequence, in the format of [`format_replay`] |
//! | `FSTP_PROP_REPLAY_FILE` | Replay the choice sequence stored in this file |
//!
//! A set variable must be well formed, or the check panics with the reason.
//! An empty `FSTP_PROP_REPLAY` replays the empty sequence, which is the case
//! where every generator returns its simplest value. Set at most one of the
//! two replay variables.
//!
//! A failure report names the property, the seed, the cases that passed, the
//! shrink steps, the notes and message of the minimal case, and a command that
//! replays it. The command filters `cargo test` to the exact test that failed,
//! and to its package and integration test target when they are known. Keep
//! one check per test function: the replay variable applies to every check in
//! the filtered tests. A check that runs outside a libtest test thread prints
//! a `<TEST>` placeholder and the location of the check instead of a test
//! path. A minimal sequence longer than [`MAX_REPLAY_ENV_LEN`] is written to a
//! file under the target directory, and the command uses
//! `FSTP_PROP_REPLAY_FILE`. [`run`] ignores the environment and returns an
//! [`Outcome`] instead of panicking.
//!
//! [`Config::cases`] must be at least 1. A run with zero cases would pass
//! without testing anything, so [`run`] reports [`FailureKind::InvalidConfig`]
//! and the check functions panic with that report.
//!
//! Each case may draw at most [`Config::max_choices`] choices. A case that
//! draws more is discarded, as is a case rejected by [`Gen::assume`]. A run
//! that discards more than [`MAX_DISCARD_RATIO`] cases per requested case
//! fails, so a property never passes by discarding everything.
//!
//! Panics inside a property are caught and reported as failures. The harness
//! needs the default `panic = "unwind"` strategy, which `cargo test` uses.
//!
//! # Example
//!
//! ```
//! use fstp_prop::{check, prop_assert, prop_assert_eq};
//!
//! check("reverse_twice_is_identity", |g| {
//!     let v = g.vec(0..=16, |g| g.u32());
//!     let mut w = v.clone();
//!     w.reverse();
//!     w.reverse();
//!     prop_assert_eq!(w, v);
//!     Ok(())
//! });
//!
//! check("sorted_output_is_ordered", |g| {
//!     let mut v = g.bytes(0..=32);
//!     v.sort_unstable();
//!     g.note("sorted", &v);
//!     prop_assert!(v.windows(2).all(|w| w[0] <= w[1]), "not sorted: {:?}", v);
//!     Ok(())
//! });
//! ```
//!
//! A failing property shrinks to its minimal counterexample:
//!
//! ```
//! use fstp_prop::{run, prop_assert, Config, Outcome};
//!
//! let outcome = run("below_1000", Config::default(), |g| {
//!     let x = g.u64();
//!     prop_assert!(x < 1000);
//!     Ok(())
//! });
//! let failure = outcome.failure().expect("the property is false");
//! assert_eq!(failure.choices, vec![1000]);
//! ```
//!
//! # Stateful testing
//!
//! ```
//! use fstp_prop::{check_machine, Gen, StateMachine};
//!
//! /// A counter that must never exceed its limit.
//! struct Counter { limit: u32 }
//!
//! #[derive(Debug)]
//! enum Cmd { Add(u32), Reset }
//!
//! impl StateMachine for Counter {
//!     type Model = u32;
//!     type Sut = u32;
//!     type Command = Cmd;
//!     type Output = u32;
//!
//!     fn init_model(&self) -> u32 { 0 }
//!     fn init_sut(&self) -> u32 { 0 }
//!     fn command(&self, g: &mut Gen, model: &u32) -> Cmd {
//!         match g.u8_in(0..=1) {
//!             0 => Cmd::Add(g.u32_in(0..=self.limit - model)),
//!             _ => Cmd::Reset,
//!         }
//!     }
//!     fn precondition(&self, model: &u32, cmd: &Cmd) -> bool {
//!         match cmd { Cmd::Add(n) => model + n <= self.limit, Cmd::Reset => true }
//!     }
//!     fn run(&self, sut: &mut u32, cmd: &Cmd) -> u32 {
//!         match cmd { Cmd::Add(n) => *sut += n, Cmd::Reset => *sut = 0 }
//!         *sut
//!     }
//!     fn next_state(&self, model: &mut u32, cmd: &Cmd) {
//!         match cmd { Cmd::Add(n) => *model += n, Cmd::Reset => *model = 0 }
//!     }
//!     fn postcondition(&self, model: &u32, cmd: &Cmd, out: &u32) -> Result<(), String> {
//!         let expected = match cmd { Cmd::Add(n) => model + n, Cmd::Reset => 0 };
//!         if *out == expected { Ok(()) } else { Err(format!("expected {expected}, got {out}")) }
//!     }
//!     fn invariant(&self, model: &u32, sut: &u32) -> Result<(), String> {
//!         if sut == model && *sut <= self.limit { Ok(()) } else { Err("counter drifted".into()) }
//!     }
//! }
//!
//! check_machine("counter_respects_limit", &Counter { limit: 100 });
//! ```

mod chars;
mod exec;
mod generator;
mod replay;
mod rng;
mod runner;
mod shrink;
mod state;

pub use generator::Gen;
pub use replay::{ReplayLimits, ReplayParseError, format_replay, parse_replay, parse_replay_with};
pub use runner::{
    Config, ConfigError, DEFAULT_CASES, DEFAULT_MAX_CHOICES, DEFAULT_MAX_SHRINK_STEPS, ENV_CASES,
    ENV_REPLAY, ENV_REPLAY_FILE, ENV_SEED, Failure, FailureKind, MAX_DISCARD_RATIO,
    MAX_REPLAY_ENV_LEN, Outcome, check, check_with, run, seed_for_name,
};
pub use state::{
    DEFAULT_MAX_COMMANDS, StateMachine, check_machine, check_machine_with, commands_for,
    run_machine,
};

/// Fails the property with a message when a condition is false.
///
/// Use it inside a property or any function that returns `Result<_, String>`.
/// An optional format string and arguments add context to the message.
///
/// ```
/// use fstp_prop::prop_assert;
/// fn even(n: u32) -> Result<(), String> {
///     prop_assert!(n % 2 == 0, "{} is odd", n);
///     Ok(())
/// }
/// assert!(even(4).is_ok());
/// assert!(even(3).unwrap_err().contains("3 is odd"));
/// ```
#[macro_export]
macro_rules! prop_assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err(::std::format!(
                "assertion failed: {} at {}:{}",
                ::core::stringify!($cond),
                ::core::file!(),
                ::core::line!()
            ));
        }
    };
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return ::core::result::Result::Err(::std::format!(
                "{} (assertion failed: {} at {}:{})",
                ::std::format!($($fmt)+),
                ::core::stringify!($cond),
                ::core::file!(),
                ::core::line!()
            ));
        }
    };
}

/// Fails the property when two values are not equal, showing both with `Debug`.
///
/// ```
/// use fstp_prop::prop_assert_eq;
/// fn same(a: u8, b: u8) -> Result<(), String> {
///     prop_assert_eq!(a, b);
///     Ok(())
/// }
/// assert!(same(1, 1).is_ok());
/// assert!(same(1, 2).unwrap_err().contains("left: 1"));
/// ```
#[macro_export]
macro_rules! prop_assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        let left = &$left;
        let right = &$right;
        if !(left == right) {
            return ::core::result::Result::Err(::std::format!(
                "assertion `left == right` failed at {}:{}\n  left: {:?}\n right: {:?}",
                ::core::file!(),
                ::core::line!(),
                left,
                right
            ));
        }
    }};
    ($left:expr, $right:expr, $($fmt:tt)+) => {{
        let left = &$left;
        let right = &$right;
        if !(left == right) {
            return ::core::result::Result::Err(::std::format!(
                "{}\nassertion `left == right` failed at {}:{}\n  left: {:?}\n right: {:?}",
                ::std::format!($($fmt)+),
                ::core::file!(),
                ::core::line!(),
                left,
                right
            ));
        }
    }};
}

/// Fails the property when two values are equal, showing both with `Debug`.
///
/// ```
/// use fstp_prop::prop_assert_ne;
/// fn differ(a: u8, b: u8) -> Result<(), String> {
///     prop_assert_ne!(a, b);
///     Ok(())
/// }
/// assert!(differ(1, 2).is_ok());
/// assert!(differ(3, 3).is_err());
/// ```
#[macro_export]
macro_rules! prop_assert_ne {
    ($left:expr, $right:expr $(,)?) => {{
        let left = &$left;
        let right = &$right;
        if left == right {
            return ::core::result::Result::Err(::std::format!(
                "assertion `left != right` failed at {}:{}\n  left: {:?}\n right: {:?}",
                ::core::file!(),
                ::core::line!(),
                left,
                right
            ));
        }
    }};
    ($left:expr, $right:expr, $($fmt:tt)+) => {{
        let left = &$left;
        let right = &$right;
        if left == right {
            return ::core::result::Result::Err(::std::format!(
                "{}\nassertion `left != right` failed at {}:{}\n  left: {:?}\n right: {:?}",
                ::std::format!($($fmt)+),
                ::core::file!(),
                ::core::line!(),
                left,
                right
            ));
        }
    }};
}
