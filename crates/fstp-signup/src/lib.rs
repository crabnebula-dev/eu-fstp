//! Control plane onboarding (TH-46, M4 design section 3.5).
//!
//! The crate holds the server-rendered sign-up and agreement forms, their
//! strict form decoder, the control plane records for sign-up, agreement
//! acceptance and the operator review of the tenant's identity, and the
//! client side of the `Provisioner` port. It names no tenant record, so
//! the control plane still cannot decode tenant data (I-19, I-20).
//!
//! Status: W0 stub. Lane W2f (L-CP) owns this crate. Every operation
//! refuses with [`SignupError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignupError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for SignupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignupError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for SignupError {}

/// A decoded sign-up or agreement form.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignupForm {
    _w0: (),
}

/// Decodes a submitted sign-up or agreement form. Duplicate fields, unknown fields, bad percent-encoding and over-long values are refused. Fuzzed (`signup_form_decode`).
pub fn decode_signup_form(bytes: &[u8]) -> Result<SignupForm, SignupError> {
    let _ = bytes;
    Err(SignupError::NotImplemented(
        "fstp_signup::decode_signup_form",
    ))
}

/// A control plane onboarding record.
///
/// W0 placeholder with no fields. The owning lane writes the designed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpRecord {
    _w0: (),
}

/// Decodes a stored control plane record. Fuzzed (`cp_record_decode`).
pub fn decode_cp_record(bytes: &[u8]) -> Result<CpRecord, SignupError> {
    let _ = bytes;
    Err(SignupError::NotImplemented("fstp_signup::decode_cp_record"))
}
