//! The engine compositions of activation and publication (I-51, I-52,
//! I-66, I-67, M4 design section 3.4, change D2e).
//!
//! The engine composes the core `ActivateProgramme` only from an approved
//! creator decision, and `PublishCall` only with a recomputed clean report
//! and its `GuidePublished` record in the same entry.
//!
//! Both compositions fail closed. Each checks what it can read in the
//! engine state, in this order:
//!
//! - [`activation`]: the programme exists, then an approved creator
//!   decision for it exists.
//! - [`publication`]: the call exists, then it is not yet published,
//!   then a clean validation report of its programme exists.
//!
//! Interim, pending the creator part of the engine state (design section
//! 4.2). The `EngineState::creator` part, the `Creator` envelope variants
//! and the `GuidePublished` record come from `fstp-creator` and
//! `fstp-guide`. This crate has no `Cargo.toml` edge to either yet. So the
//! state holds no creator decision and no validation report, and both
//! compositions refuse every programme and call that exists. They never
//! build a command they cannot justify. The accepting paths land with
//! those edges.

use fstp_domain::id::{CallId, ProgrammeId};
use fstp_domain::programme::CallStatus;

use crate::{Command, EngineState};

/// Why a composition failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComposeError {
    /// Kept for the lanes that code against the W0 stub. Neither
    /// composition of this crate returns it.
    NotImplemented(&'static str),
    /// No programme with this id exists in the core state.
    UnknownProgramme,
    /// The programme has no approved creator decision: no
    /// `ActivationApproved` built from an `ActivationClearance` (I-66,
    /// I-67).
    NoApprovedDecision,
    /// No call with this id exists in the core state.
    UnknownCall,
    /// The call is already published, so a second Guide would follow
    /// (I-52, design section 3.10).
    AlreadyPublished,
    /// The recomputed validation report of the call's programme is not
    /// clean, or no report can be computed (I-51, I-52).
    NoCleanReport,
}

impl core::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ComposeError::NotImplemented(op) => write!(f, "{op} is not implemented"),
            ComposeError::UnknownProgramme => f.write_str("unknown programme"),
            ComposeError::NoApprovedDecision => {
                f.write_str("the programme has no approved creator decision")
            }
            ComposeError::UnknownCall => f.write_str("unknown call"),
            ComposeError::AlreadyPublished => f.write_str("the call is already published"),
            ComposeError::NoCleanReport => {
                f.write_str("the programme has no clean validation report")
            }
        }
    }
}

impl std::error::Error for ComposeError {}

/// Composes the activation of a draft programme from its approved creator
/// decision (I-66, I-67).
///
/// It refuses an unknown programme with
/// [`ComposeError::UnknownProgramme`]. It refuses every other programme
/// with [`ComposeError::NoApprovedDecision`], since the engine state holds
/// no creator decision yet (module documentation).
pub fn activation(state: &EngineState, programme: ProgrammeId) -> Result<Command, ComposeError> {
    if state.core.policy().programme(programme).is_none() {
        return Err(ComposeError::UnknownProgramme);
    }
    Err(ComposeError::NoApprovedDecision)
}

/// Composes the publication of a call with its Guide record (I-51, I-52,
/// R-GA-01).
///
/// It refuses an unknown call with [`ComposeError::UnknownCall`] and a
/// published one with [`ComposeError::AlreadyPublished`]. It refuses every
/// other call with [`ComposeError::NoCleanReport`], since the engine state
/// holds no creator records to recompute the report from yet (module
/// documentation). Whether the call's publication is approved stays the
/// core `PublishCall` guard's question (R-PC-03).
pub fn publication(state: &EngineState, call: CallId) -> Result<Command, ComposeError> {
    let view = fstp_domain::programme::call(&state.core, call).ok_or(ComposeError::UnknownCall)?;
    if view.status() == CallStatus::Published {
        return Err(ComposeError::AlreadyPublished);
    }
    Err(ComposeError::NoCleanReport)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-66, D2e: the empty state has no programme to activate.
    #[test]
    fn i66_genesis_activation_names_the_unknown_programme() {
        assert_eq!(
            activation(&EngineState::genesis(), ProgrammeId::from_raw(1)),
            Err(ComposeError::UnknownProgramme)
        );
    }

    /// I-52, D2e: the empty state has no call to publish.
    #[test]
    fn i52_genesis_publication_names_the_unknown_call() {
        assert_eq!(
            publication(&EngineState::genesis(), CallId::from_raw(1)),
            Err(ComposeError::UnknownCall)
        );
    }
}
