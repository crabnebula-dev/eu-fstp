//! Journey definitions and the drift check against the domain core (ADR-015, I-95).
//!
//! The journey layer is a read model (I-92). Its graph comes from one JSON
//! definition per profile, shipped in this crate under `definitions/`. This
//! crate reads a definition and checks it against the domain core:
//!
//! - [`definition`] parses a definition of the `SPEC/12-journey-ui.md`
//!   section 5.3 shape, only through the in-house `fstp-json` codec. It
//!   refuses unknown members, missing members, wrong types, repeated ids
//!   and edges that name no node. The parsed value carries the SHA-256 of
//!   the file bytes, as `fstp-migrate` records for each migration.
//! - [`drift`] compares a parsed definition with the domain core's
//!   `StateTag::ALL` and `TRANSITIONS` (R-JV-02). It reports every node,
//!   edge or "any non-terminal state before GRANTED" rule that differs on
//!   either side. It also reports a side track of section 9 that the
//!   definition leaves out.
//! - [`overlay`] computes the programme overlay of section 5.5 from a
//!   frozen policy version (R-JV-07).
//! - [`projector`] folds the ledger into journey rows (I-92, I-97).
//! - [`visibility`] decides per request whether a diary entry reaches a
//!   viewer (I-93, O-54, O-57, O-58, O-60).
//! - [`diary`] builds diary items at read time from rows and the ledger
//!   (I-97, I-27).
//! - [`vocab`] parses the plain and Voyage vocabulary packs and looks
//!   labels up for one tenant (O-55, I-72, I-96).
//! - [`summary`] holds the catalogue keys of diary sentences, and
//!   [`zones`] the shipped deadline zone table (ADR-015).
//!
//! The crate holds no authority, does no I/O and never reads a clock. The
//! definition and vocabulary pack parsers have fuzz targets in `fuzz/`
//! (ADR-003).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod definition;
pub mod diary;
pub mod drift;
pub mod overlay;
pub mod projector;
pub mod summary;
pub mod visibility;
pub mod vocab;
pub mod zones;

use definition::{Definition, DefinitionError};
use drift::Drift;

/// The bytes of `definitions/proposal.v1.json`, the proposal journey
/// definition the platform ships.
pub const PROPOSAL_V1: &[u8] = include_bytes!("../definitions/proposal.v1.json");

/// Why the shipped proposal definition cannot be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The parser refused the definition.
    Definition(DefinitionError),
    /// The definition parsed but differs from the domain core (I-95).
    Drift(Vec<Drift>),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::Definition(e) => write!(f, "{e}"),
            LoadError::Drift(found) => {
                write!(f, "journey definition drifted from the state machine:")?;
                for d in found {
                    write!(f, " {d};")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Parses [`PROPOSAL_V1`] and checks it against the domain core, as the
/// platform does at startup. A definition that drifts is never loaded.
pub fn load_proposal_v1() -> Result<Definition, LoadError> {
    let def = definition::parse(PROPOSAL_V1).map_err(LoadError::Definition)?;
    drift::check(&def).map_err(LoadError::Drift)?;
    Ok(def)
}
