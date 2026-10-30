//! The creator path of the M4 demo, from `OpenDraft` to
//! `ApproveActivation` (lane m4creator, step m4cg; M4 design sections
//! 3.1, 3.2 and 8.4; R-PG-01 to R-PG-03 and R-PG-05; I-50, I-51, I-66 and
//! I-67).
//!
//! # Where these tests run
//!
//! The lane scope asks for the path through `fstp-engine` with
//! `CreatorDecider` and a test `CreatorEnvironment`. This crate cannot take
//! `fstp-engine` as a dev-dependency: layering rules A3 and A4 count dev
//! edges, and `fstp-engine` reaches `fstp-import` and is itself on the A4
//! list. So [`harness::Cell`] replays the engine's creator entry here,
//! step for step as `fstp_engine::compose::decide_creator_command` does
//! it:
//!
//! 1. The environment gives the shell's `CreatorInputs`. The cell then
//!    writes the vault answers the engine owns: `IsVerified` and
//!    `SameIdentityAsAny` for the commands that read the report.
//! 2. `fstp_creator::decide_creator` decides the command.
//! 3. Each composed core command is decided by `fstp_domain::decide` on
//!    the core state after the earlier ones, with the same context.
//! 4. An `ActivationApproved` record composes the core
//!    `ActivateProgramme`, which the core guard decides again (I-67).
//! 5. The entry folds as one ledger entry: creator records through
//!    `CreatorState::apply`, core records through `fstp_domain::apply` and
//!    `CreatorState::observe_core`.
//! 6. After a `SaveFields` entry, the shell holds the saved values with
//!    `CreatorState::hold_saved`, since the ledger body keeps only their
//!    digests (ADR-007). The engine driver holds import values the same
//!    way. Until it holds creator values too, the checks that read an
//!    artefact value fail closed in an engine cell.
//!
//! The tests of the commands after `OpenDraft` open their draft with the
//! entry a correct `OpenDraft` appends, which
//! `r_pg_02_d1_open_draft_composes_create_programme_with_the_profile_default`
//! pins, so each test stands or falls at its own command.
//!
//! # The Guide
//!
//! `fstp_guide::parse_template` and `fstp_guide::render` refuse with
//! `NotImplemented` until lane m4guide lands. While they refuse, the
//! Guide checks must fail closed with a reason that names `fstp_guide`.
//! Once they work, the same tests expect a clean report and an active
//! programme. [`harness::guide_works`] tells the two cases apart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod commands;
mod harness;
mod i50_i51;
mod i66;
mod i67;
mod starts;
