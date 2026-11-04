//! Control plane onboarding (TH-46, R-TN-01, Q22; M4 design section 3.5).
//!
//! The crate holds the server-rendered sign-up and agreement forms, their
//! strict form decoder, the control plane records for the agreement
//! offer, sign-up, agreement acceptance, the operator review of the
//! tenant's identity and provisioning, the fold of those records, and the
//! provisioning gate in front of the `Provisioner` port. It names no
//! tenant record, so the control plane still cannot decode tenant data
//! (I-19, I-20). It is sans-IO and pure (layering rule A10).
//!
//! - [`render_signup_form`] and [`render_agreement_form`] write the two
//!   forms through `fstp-html` (I-68). They carry exactly the fields the
//!   decoder demands.
//! - [`decode_signup_form`] reads an `application/x-www-form-urlencoded`
//!   body. Duplicate, unknown and missing fields, bad percent-encoding,
//!   non-UTF-8 values, over-long values, control characters, format
//!   characters and Unicode line separators are refused (TH-26, H-05,
//!   TH-46). Fuzzed (`signup_form_decode`).
//! - [`CpRecord`] values encode to RFC 8785 canonical JSON and decode
//!   strictly (ADR-007). Fuzzed (`cp_record_decode`).
//! - [`decide`] turns a [`CpCommand`] into records, and
//!   [`SignupState::apply`] folds them under the same rules, so a forged
//!   ledger never folds into a state that `decide` could not reach.
//! - [`provision_permit`] is the TH-46 gate. It issues a
//!   [`ProvisionPermit`] only for a tenant that signed up, accepted every
//!   agreement at the versions the ledger offers, holds approvals of its
//!   identity by [`APPROVALS_NEEDED`] distinct operator staff with no
//!   rejection, and is not provisioned yet.
//!
//! Interim, pending Daniel: the design names "operator staff" and records
//! one reviewer. This crate needs two distinct staff approvals and treats
//! any rejection as final. It mirrors the decided two-staff rule for the
//! first tenant admin verification (`roles-and-sod.md`).
//!
//! TODO(legal): Daniel supplies the SaaS terms, the data processing
//! agreement and the sub-processor list. Until then the agreement form
//! renders a placeholder for each text, and the records name versions
//! only.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod error;
mod form;
mod record;
mod render;
mod state;
mod text;
mod types;

pub use error::{FormError, RecordError, Refusal, SignupError};
pub use form::{MAX_FORM_BYTES, decode_signup_form, encode_signup_form};
pub use record::{
    CP_RECORD_SCHEMA, CpRecord, decode_cp_record, decode_cp_record_at, encode_cp_record,
};
pub use render::{
    SIGNUP_ACTION, SIGNUP_LOCALE, SIGNUP_MESSAGES, agreement_form_page, render_agreement_form,
    render_signup_form, signup_catalogues, signup_form_page,
};
pub use state::{
    APPROVALS_NEEDED, CpCommand, ProvisionPermit, Provisioner, SignupState, decide,
    provision_permit,
};
pub use text::MAX_FIELD_BYTES;
pub use types::{
    Agreement, AgreementFields, AgreementVersions, ReviewOutcome, SignupFields, SignupForm,
    StaffId, TenantId,
};
