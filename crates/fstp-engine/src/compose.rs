//! The engine compositions of activation and publication (I-51, I-52,
//! I-66, I-67, M4 design section 3.4, change D2e).
//!
//! The engine composes the core `ActivateProgramme` only from an approved
//! creator decision, and `PublishCall` only with a recomputed clean report
//! and its `GuidePublished` record in the same entry.
//!
//! Lane W2e (L-ENGINE) owns this file. The M4 W0 lane added it with its
//! `mod` line. The designed signatures name `fstp-creator` and
//! `fstp-guide` types. Those edges are not yet in this crate's
//! `Cargo.toml`, so the stubs name engine and domain types only.
//!
//! Status: W0 stub. It refuses with [`ComposeError::NotImplemented`].

use fstp_domain::id::{CallId, ProgrammeId};

use crate::{Command, EngineState};

/// Why a composition failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

/// Composes the activation of a draft programme from its approved creator
/// decision.
pub fn activation(state: &EngineState, programme: ProgrammeId) -> Result<Command, ComposeError> {
    let _ = (state, programme);
    Err(ComposeError::NotImplemented(
        "fstp_engine::compose::activation",
    ))
}

/// Composes the publication of a call with its Guide record.
pub fn publication(state: &EngineState, call: CallId) -> Result<Command, ComposeError> {
    let _ = (state, call);
    Err(ComposeError::NotImplemented(
        "fstp_engine::compose::publication",
    ))
}
