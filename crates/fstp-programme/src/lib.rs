//! The programme as data (M4 design section 3.1).
//!
//! A [`ProgrammeSpec`] is one programme as the creator captures it. People
//! are never part of it (I-73). `compile` turns a spec into an M2 policy
//! version and the programme artefacts, deterministically. `decompile` is
//! its inverse on accepted specs. The crate also holds the `FIELDS` table,
//! the shipped templates, the SuperSAFE fixture and the R-PG-04 `impact`
//! function.
//!
//! Status: W0 stub. Lane W1a (L-SPEC) owns this crate and writes the
//! designed types. Every operation refuses with
//! [`ProgrammeError::NotImplemented`], so no test passes on a stub.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

/// Why a programme operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgrammeError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for ProgrammeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgrammeError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for ProgrammeError {}

/// One programme as the creator captures it.
///
/// W0 placeholder with no fields. Lane W1a writes the ten creator steps of
/// design section 3.1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammeSpec {
    _w0: (),
}

/// The output of [`compile`]: the policy version, the artefacts and the
/// unset fields.
///
/// W0 placeholder with no fields. Lane W1a writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    _w0: (),
}

/// One decoded field value.
///
/// W0 placeholder with no fields. Lane W1a writes the per-field values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldValue {
    _w0: (),
}

/// Decodes a spec from its canonical JSON text. Unknown members are
/// rejected, and amounts decode only as ADR-006 strings. Fuzzed
/// (`spec_decode`).
pub fn decode_spec(bytes: &[u8]) -> Result<ProgrammeSpec, ProgrammeError> {
    let _ = bytes;
    Err(ProgrammeError::NotImplemented(
        "fstp_programme::decode_spec",
    ))
}

/// Compiles a spec into an M2 policy version and the programme artefacts.
/// Pure and deterministic. Fuzzed (`spec_compile`).
pub fn compile(spec: &ProgrammeSpec) -> Result<Compiled, ProgrammeError> {
    let _ = spec;
    Err(ProgrammeError::NotImplemented("fstp_programme::compile"))
}

/// Decodes one field value with its field's strict decoder. Fuzzed
/// (`field_value_decode`).
pub fn decode_field_value(bytes: &[u8]) -> Result<FieldValue, ProgrammeError> {
    let _ = bytes;
    Err(ProgrammeError::NotImplemented(
        "fstp_programme::decode_field_value",
    ))
}
