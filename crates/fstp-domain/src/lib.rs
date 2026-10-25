//! Pure domain core of the FSTP platform, without findings.
//!
//! The crate holds the domain model: ids and time, the policy engine,
//! programmes and calls, roles and separation of duties, and assignments and
//! conflicts. It also holds proposals and plans, scoring, decisions, grants,
//! the payments seam, visibility and the identity vault query types. The
//! pure `queries`, `decide`, `apply` and `due` functions live here too, with
//! their codecs (`docs/handoff/m2-design.md`).
//!
//! The crate does no I/O and never reads a clock. It has no dependency path
//! to `fstp-findings` or `fstp-engine` (I-10), which `tools/deps-check`
//! enforces.
//!
//! Status: interface from milestone M2 step W1c. The interface modules hold
//! ids, time, refusals, commands, records, vault queries, the projection,
//! the transition and actor tables and the parameter catalogue. The engine
//! is a fixed dispatcher. It runs the checks every command shares, then calls
//! one stub per lane module, which refuses with `Refusal::not_implemented()`.
//! Lane modules hold the vocabulary the interface names and those stubs.
//! Each lane fills only the modules it owns (design section 10).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

// Interface modules, owned by lane W1c.
pub mod command;
pub mod engine;
pub mod id;
pub mod oracle;
pub mod record;
pub mod refusal;
pub mod rules;
pub mod state;
pub mod time;

// L-POL.
pub mod policy;
pub mod programme;

// L-SOD.
pub mod roles;

// L-SCORE.
pub mod scoring;

// L-CODEC.
pub mod codec;

// L-REV.
pub mod assignment;
pub mod visibility;

// L-LIFE.
pub mod decision;
pub mod proposal;

// L-MONEY.
pub mod amendment;
pub mod grant;
pub mod payment;

pub use command::{Actor, Command, CommandKind, Ctx, SystemCause, Via};
pub use engine::{FoldError, apply, decide, due, queries, replay, stage1_ready};
pub use oracle::{Answer, Answers, OracleDown, Query, QueryKind};
pub use record::{Record, RulesVersion};
pub use refusal::{Refusal, RefusalReason, RuleRef};
pub use rules::{ACTOR_RULES, CATALOGUE, Row, StateTag, TRANSITIONS};
pub use state::State;
