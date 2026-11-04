//! Errors and refusals. None of them carries input content (R-NF-02).

use std::fmt;

/// Why an operation of this crate failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignupError {
    /// A submitted form, or the form part of a command, was refused.
    Form(FormError),
    /// A record was refused by its codec or by the fold's value rules.
    Record(RecordError),
    /// A command, a record of the fold or the provisioning gate was
    /// refused by an onboarding rule.
    Refused(Refusal),
}

impl fmt::Display for SignupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignupError::Form(e) => write!(f, "form refused: {e}"),
            SignupError::Record(e) => write!(f, "record refused: {e}"),
            SignupError::Refused(r) => write!(f, "refused: {r}"),
        }
    }
}

impl std::error::Error for SignupError {}

impl From<FormError> for SignupError {
    fn from(e: FormError) -> SignupError {
        SignupError::Form(e)
    }
}

impl From<RecordError> for SignupError {
    fn from(e: RecordError) -> SignupError {
        SignupError::Record(e)
    }
}

impl From<Refusal> for SignupError {
    fn from(r: Refusal) -> SignupError {
        SignupError::Refused(r)
    }
}

/// Why a submitted form was refused. A named field is a field name of
/// the form, never input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FormError {
    /// The body is longer than [`crate::MAX_FORM_BYTES`].
    TooLong,
    /// An empty pair, a pair without `=`, a pair with an empty name, or a
    /// second `=` in one pair.
    Malformed,
    /// A `%` that does not start two hex digits, or a raw byte that a
    /// form body must percent-encode.
    BadPercentEncoding,
    /// The decoded bytes of a name or value are not UTF-8.
    NotUtf8,
    /// The `form` value names no form.
    UnknownForm,
    /// A name outside the selected form.
    UnknownField,
    /// A field that appears twice.
    DuplicateField,
    /// The named field is missing.
    MissingField(&'static str),
    /// The named value is longer than [`crate::MAX_FIELD_BYTES`] after
    /// decoding.
    ValueTooLong(&'static str),
    /// The named value is not valid for its field.
    BadValue(&'static str),
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormError::TooLong => f.write_str("the body is too long"),
            FormError::Malformed => f.write_str("a pair is malformed"),
            FormError::BadPercentEncoding => f.write_str("bad percent-encoding"),
            FormError::NotUtf8 => f.write_str("a decoded value is not UTF-8"),
            FormError::UnknownForm => f.write_str("unknown form"),
            FormError::UnknownField => f.write_str("unknown field"),
            FormError::DuplicateField => f.write_str("duplicate field"),
            FormError::MissingField(n) => write!(f, "missing field {n}"),
            FormError::ValueTooLong(n) => write!(f, "value of {n} is too long"),
            FormError::BadValue(n) => write!(f, "value of {n} is not valid"),
        }
    }
}

/// Why a record was refused by its codec or by the fold's value rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordError {
    /// The bytes are not a JSON text within the codec's limits.
    NotJson,
    /// The bytes are JSON but not their RFC 8785 canonical text.
    NotCanonical,
    /// The schema version is not published.
    UnknownSchema,
    /// The value does not match the record schema: a wrong type, an
    /// unknown kind, or a missing or unknown member.
    Schema,
    /// The named member holds a value outside its domain.
    BadValue(&'static str),
    /// The record holds a value that has no canonical text.
    Encode,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::NotJson => f.write_str("not a JSON text within limits"),
            RecordError::NotCanonical => f.write_str("not canonical (RFC 8785)"),
            RecordError::UnknownSchema => f.write_str("unpublished schema version"),
            RecordError::Schema => f.write_str("does not match the record schema"),
            RecordError::BadValue(m) => write!(f, "member {m} is not valid"),
            RecordError::Encode => f.write_str("no canonical text"),
        }
    }
}

/// Why a command, a record of the fold or the provisioning gate was
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// No sign-up record names the tenant.
    UnknownTenant,
    /// The tenant already signed up.
    TenantExists,
    /// No agreement versions are offered yet.
    NoOffer,
    /// An offer holds a zero version, moves a version back, or changes
    /// nothing.
    BadOffer,
    /// An accepted version differs from the current offer.
    VersionNotOffered,
    /// Every agreement is already accepted at the offered version, or the
    /// record repeats an accepted (tenant, agreement, version).
    AlreadyAccepted,
    /// The staff member already approved this tenant.
    SameReviewer,
    /// A staff member rejected this tenant. The rejection is final.
    ReviewRejected,
    /// An offered version is not accepted.
    AgreementsNotAccepted,
    /// Fewer distinct staff approved than the gate needs
    /// ([`crate::APPROVALS_NEEDED`]).
    ReviewPending,
    /// The tenant's cell is already provisioned. The gate permits once,
    /// and no review follows it.
    AlreadyProvisioned,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::UnknownTenant => "the tenant did not sign up",
            Refusal::TenantExists => "the tenant already signed up",
            Refusal::NoOffer => "no agreement versions are offered",
            Refusal::BadOffer => "the offer is not a forward change of the current one",
            Refusal::VersionNotOffered => "an accepted version is not the offered one",
            Refusal::AlreadyAccepted => "the agreements are already accepted",
            Refusal::SameReviewer => "the staff member already approved",
            Refusal::ReviewRejected => "the tenant's review was rejected",
            Refusal::AgreementsNotAccepted => "the offered agreements are not accepted",
            Refusal::ReviewPending => "more distinct staff approvals are needed",
            Refusal::AlreadyProvisioned => "the tenant is already provisioned",
        })
    }
}
