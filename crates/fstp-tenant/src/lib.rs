//! Tenant onboarding in the cell (M4 design section 3.5, lane W2d).
//!
//! The crate is pure. It holds:
//!
//! - the onboarding steps, each of which validates before the next opens
//!   (R-TN-01), with checks that need a prober failing closed where none
//!   exists (Q5);
//! - the tenant admin set, its invitations bound to their invitee, and
//!   the single-use, expiring SoD-07 self-grant approvals, as ledger
//!   records (Q31 A, interim pending Daniel);
//! - the tenant-wide Financial and Legal signatory bindings (NOTE 5), and
//!   the activation of the organisation by a request and a second tenant
//!   admin's approval (SoD-14 to SoD-18);
//! - the tenant-level settings P-20, P-69 to P-72 and P-74, one high-risk
//!   operation per parameter. P-73 and P-78 are not settable in M4;
//! - the tenant defaults that prefill the programme fields P-18, P-21 and
//!   P-45. They are never parameters themselves;
//! - the inference configuration record that `call.publish` reads.
//!
//! The shell runs a command in three steps. It asks [`queries`] what the
//! command needs from the vault, the control plane, the domain and the
//! prober. It calls [`decide`] with the answers, and folds the returned
//! records with [`TenantState::apply_all`]. [`TenantState::replay`] folds a stored
//! ledger, and the fold checks every rule a record alone can show.
//!
//! Every value in this crate is integer or text. No float appears.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod codec;
mod command;
mod decide;
mod refusal;
pub mod rules;
mod state;
mod types;

pub use codec::{
    CURRENT_SCHEMA, MAX_P69_WIRE_BYTES, MAX_TEXT_BYTES, PUBLISHED_SCHEMAS, decode_command,
    decode_record, decode_record_at, encode_command, encode_record,
};
pub use command::{TenantCommand, TenantCtx, TenantKind, TenantRecord};
pub use decide::{ProbeOutcome, TenantAnswers, TenantQuery, decide, queries};
pub use refusal::{DecodeError, FoldError, TenantError, TenantRefusal};
pub use rules::ProbeKind;
pub use state::{
    AdminInvitation, GuideNotice, InferenceConfig, PLATFORM_DATA_PROTECTION_SUMMARY,
    PLATFORM_PRIVACY_STATEMENT_URL, SelfGrantApproval, TenantDefaults, TenantSettings, TenantState,
};
pub use types::{
    Activation, ActivationRequestId, AgreementVersions, ApprovalId, BankInterface, BrandingPackage,
    CellKind, DomainName, GrantRef, GuideNoticeOverride, InferenceDefault, InvitationId,
    LoginMethod, MailRelay, McpSettings, Milestone, ModelRef, OnboardingStep, PaymentMode,
    ProviderRef, RpMode, SettingValue, SignatoryRole, StepFailure, StepOutcome, StepStatus,
    StepValues, TenantParam, TenantRevision, Terminology, Token, TokenDigest, VerifyMethod,
};
