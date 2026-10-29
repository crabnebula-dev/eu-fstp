//! The import bridge (I-65, M4 design section 3.3). It is the only place
//! where the import store and the creator meet.
//!
//! `resolve_import` checks the programme manager binding, the proposal,
//! the `shown` digest and the field. It then emits the import record and
//! the creator's `SaveFields` with import provenance in one entry.
//!
//! Lane W2b (L-IMPORT) owns this file. The M4 W0 lane added it with its
//! `mod` line. The designed signature names `fstp-import` and
//! `fstp-creator` types. Those edges are not yet in this crate's
//! `Cargo.toml`, so the stub names engine and domain types only.
//!
//! Status: W0 stub. It refuses with [`BridgeError::NotImplemented`].

use fstp_domain::id::ProgrammeId;

use crate::{Command, EngineState};

/// Why a bridge command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

/// Resolves one import proposal of a draft programme.
pub fn resolve_import(
    state: &EngineState,
    programme: ProgrammeId,
) -> Result<Vec<Command>, BridgeError> {
    let _ = (state, programme);
    Err(BridgeError::NotImplemented(
        "fstp_engine::bridge::resolve_import",
    ))
}
