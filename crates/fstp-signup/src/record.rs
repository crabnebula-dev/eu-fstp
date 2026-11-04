//! The control plane onboarding records and their canonical codec
//! (ADR-007; M4 design sections 3.5, 4.3 and 9).
//!
//! - A record is one flat JSON object with a `kind` member. The stored
//!   text is its RFC 8785 canonical text, and the decoder refuses any
//!   other spelling, so each record has exactly one.
//! - A missing or unknown member is refused.
//! - Tenant and staff ids are 32 lower-case hex digits, as the forms and
//!   `cp.tenants.tenant_id` carry them. Versions and times are canonical
//!   decimal strings. JSON numbers are refused everywhere.
//! - Text members obey the form's value rules, so a record holds only
//!   values the sign-up and agreement forms accept.
//! - Errors carry a fixed message only (R-NF-02). No decode path panics
//!   (TH-26, H-05; fuzz target `cp_record_decode`).

use fstp_json::{Object, ParseLimits, Value, parse_with, to_canonical};
use fstp_ledger::SCHEMA_V1;

use crate::error::{RecordError, SignupError};
use crate::text::{MAX_FIELD_BYTES, check_text, id_hex, parse_id_hex, parse_version};
use crate::types::{Agreement, AgreementVersions, ReviewOutcome, StaffId, TenantId};

/// The schema version [`encode_cp_record`] writes and the only one
/// [`decode_cp_record_at`] accepts.
pub const CP_RECORD_SCHEMA: u16 = SCHEMA_V1;

/// The longest record text in bytes. Three text members of
/// [`MAX_FIELD_BYTES`] bytes stay far below it even when every character
/// is escaped.
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// A control plane onboarding record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CpRecord {
    /// Operator staff offered one version of each agreement (R-TN-01).
    /// Acceptances recorded after it name these versions. Interim, pending
    /// Daniel.
    AgreementsOffered {
        /// One version of each agreement.
        versions: AgreementVersions,
        /// The staff member.
        by: StaffId,
        /// Unix seconds.
        at: i64,
    },
    /// A tenant signed up (R-TN-01, Q22).
    SignedUp {
        /// The tenant.
        tenant: TenantId,
        /// The legal entity.
        legal_name: String,
        /// The billing address.
        billing_address: String,
        /// The contracting signatory.
        contracting_signatory: String,
        /// Unix seconds.
        at: i64,
    },
    /// A tenant accepted one agreement at one exact version (R-TN-01).
    AgreementAccepted {
        /// The tenant.
        tenant: TenantId,
        /// The agreement.
        agreement: Agreement,
        /// The exact version accepted.
        version: u32,
        /// The person who accepted.
        by: String,
        /// Unix seconds.
        at: i64,
    },
    /// A staff member reviewed the tenant's identity (TH-46).
    TenantReviewed {
        /// The tenant.
        tenant: TenantId,
        /// The outcome.
        outcome: ReviewOutcome,
        /// The staff member.
        by: StaffId,
        /// Unix seconds.
        at: i64,
    },
    /// The tenant's SaaS cell was provisioned after it passed the gate
    /// (TH-46). The gate never permits the tenant again.
    TenantProvisioned {
        /// The tenant.
        tenant: TenantId,
        /// The offer the tenant had accepted in full.
        versions: AgreementVersions,
        /// Unix seconds.
        at: i64,
    },
}

/// Checks that every version of `v` is at least 1.
fn check_versions(v: AgreementVersions) -> Result<(), RecordError> {
    for (agreement, version) in v.pairs() {
        if version == 0 {
            return Err(RecordError::BadValue(agreement.name()));
        }
    }
    Ok(())
}

impl CpRecord {
    /// The tenant the record names. An offer names none.
    pub const fn tenant(&self) -> Option<TenantId> {
        match self {
            CpRecord::AgreementsOffered { .. } => None,
            CpRecord::SignedUp { tenant, .. }
            | CpRecord::AgreementAccepted { tenant, .. }
            | CpRecord::TenantReviewed { tenant, .. }
            | CpRecord::TenantProvisioned { tenant, .. } => Some(*tenant),
        }
    }

    /// Checks the value rules of every member. The codec and the fold
    /// both run it, so neither holds a value the forms refuse.
    pub(crate) fn check_values(&self) -> Result<(), RecordError> {
        let text = |member: &'static str, s: &str, line_breaks: bool| {
            check_text(s, line_breaks).map_err(|_| RecordError::BadValue(member))
        };
        match self {
            CpRecord::SignedUp {
                legal_name,
                billing_address,
                contracting_signatory,
                ..
            } => {
                text("legal_name", legal_name, false)?;
                text("billing_address", billing_address, true)?;
                text("contracting_signatory", contracting_signatory, false)
            }
            CpRecord::AgreementAccepted { version, by, .. } => {
                if *version == 0 {
                    return Err(RecordError::BadValue("version"));
                }
                text("by", by, false)
            }
            CpRecord::TenantReviewed { .. } => Ok(()),
            CpRecord::AgreementsOffered { versions, .. }
            | CpRecord::TenantProvisioned { versions, .. } => check_versions(*versions),
        }
    }
}

/// Encodes a control plane record as RFC 8785 canonical JSON, the stored
/// body under [`CP_RECORD_SCHEMA`]. A record whose values break the form
/// rules is refused, so every encoding decodes.
pub fn encode_cp_record(record: &CpRecord) -> Result<Vec<u8>, SignupError> {
    record.check_values()?;
    let v = record_value(record);
    to_canonical(&v)
        .map(String::into_bytes)
        .map_err(|_| SignupError::Record(RecordError::Encode))
}

/// Decodes a stored control plane record of the current schema. Fuzzed
/// (`cp_record_decode`).
pub fn decode_cp_record(bytes: &[u8]) -> Result<CpRecord, SignupError> {
    decode_cp_record_at(CP_RECORD_SCHEMA, bytes)
}

/// Decodes a control plane record stored under schema version `schema`.
/// A version other than [`CP_RECORD_SCHEMA`] is refused. Stored bytes
/// are never rewritten.
pub fn decode_cp_record_at(schema: u16, bytes: &[u8]) -> Result<CpRecord, SignupError> {
    if schema != CP_RECORD_SCHEMA {
        return Err(SignupError::Record(RecordError::UnknownSchema));
    }
    let v = parse_canonical(bytes)?;
    let record = take_record(&v)?;
    record.check_values()?;
    Ok(record)
}

// ---------------------------------------------------------------- writing

fn s(x: &str) -> Value {
    Value::String(x.to_owned())
}

fn object(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// The three version members of `v`, keyed by agreement name.
fn version_members(v: AgreementVersions) -> [(&'static str, Value); 3] {
    v.pairs().map(|(a, n)| (a.name(), s(&n.to_string())))
}

fn record_value(record: &CpRecord) -> Value {
    match record {
        CpRecord::AgreementsOffered { versions, by, at } => {
            let mut members = vec![("kind", s(KIND_AGREEMENTS_OFFERED))];
            members.extend(version_members(*versions));
            members.push(("by", s(&id_hex(by.raw()))));
            members.push(("at", s(&at.to_string())));
            object(members)
        }
        CpRecord::TenantProvisioned {
            tenant,
            versions,
            at,
        } => {
            let mut members = vec![
                ("kind", s(KIND_TENANT_PROVISIONED)),
                ("tenant", s(&id_hex(tenant.raw()))),
            ];
            members.extend(version_members(*versions));
            members.push(("at", s(&at.to_string())));
            object(members)
        }
        CpRecord::SignedUp {
            tenant,
            legal_name,
            billing_address,
            contracting_signatory,
            at,
        } => object(vec![
            ("kind", s(KIND_SIGNED_UP)),
            ("tenant", s(&id_hex(tenant.raw()))),
            ("legal_name", s(legal_name)),
            ("billing_address", s(billing_address)),
            ("contracting_signatory", s(contracting_signatory)),
            ("at", s(&at.to_string())),
        ]),
        CpRecord::AgreementAccepted {
            tenant,
            agreement,
            version,
            by,
            at,
        } => object(vec![
            ("kind", s(KIND_AGREEMENT_ACCEPTED)),
            ("tenant", s(&id_hex(tenant.raw()))),
            ("agreement", s(agreement.name())),
            ("version", s(&version.to_string())),
            ("by", s(by)),
            ("at", s(&at.to_string())),
        ]),
        CpRecord::TenantReviewed {
            tenant,
            outcome,
            by,
            at,
        } => object(vec![
            ("kind", s(KIND_TENANT_REVIEWED)),
            ("tenant", s(&id_hex(tenant.raw()))),
            ("outcome", s(outcome.name())),
            ("by", s(&id_hex(by.raw()))),
            ("at", s(&at.to_string())),
        ]),
    }
}

// ---------------------------------------------------------------- reading

const KIND_SIGNED_UP: &str = "signed_up";
const KIND_AGREEMENT_ACCEPTED: &str = "agreement_accepted";
const KIND_TENANT_REVIEWED: &str = "tenant_reviewed";
const KIND_AGREEMENTS_OFFERED: &str = "agreements_offered";
const KIND_TENANT_PROVISIONED: &str = "tenant_provisioned";

type R<T> = Result<T, RecordError>;

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_RECORD_BYTES)
        .with_max_depth(4)
        .with_max_string_bytes(MAX_FIELD_BYTES.saturating_mul(8))
        .with_max_container_len(16)
        .with_max_nodes(32)
        .with_max_memory_bytes(1 << 18)
}

/// Parses `bytes` and checks that they are the canonical text of the
/// value they hold.
fn parse_canonical(bytes: &[u8]) -> R<Value> {
    let v = parse_with(bytes, &limits()).map_err(|_| RecordError::NotJson)?;
    let text = to_canonical(&v).map_err(|_| RecordError::NotCanonical)?;
    if text.as_bytes() == bytes {
        Ok(v)
    } else {
        Err(RecordError::NotCanonical)
    }
}

/// The members of an object whose member names are exactly `members`.
struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    fn of(o: &'a Object, members: &[&str]) -> R<Fields<'a>> {
        if o.len() == members.len() && members.iter().all(|m| o.contains_key(m)) {
            Ok(Fields(o))
        } else {
            Err(RecordError::Schema)
        }
    }

    fn str(&self, k: &'static str) -> R<&'a str> {
        self.0
            .get(k)
            .ok_or(RecordError::Schema)?
            .as_str()
            .ok_or(RecordError::Schema)
    }

    fn text(&self, k: &'static str) -> R<String> {
        self.str(k).map(str::to_owned)
    }

    fn id(&self, k: &'static str) -> R<u128> {
        parse_id_hex(self.str(k)?).ok_or(RecordError::BadValue(k))
    }

    fn at(&self) -> R<i64> {
        parse_i64(self.str("at")?).ok_or(RecordError::BadValue("at"))
    }

    fn version(&self, a: Agreement) -> R<u32> {
        let k = a.name();
        parse_version(self.str(k)?).ok_or(RecordError::BadValue(k))
    }

    fn versions(&self) -> R<AgreementVersions> {
        Ok(AgreementVersions {
            saas_terms: self.version(Agreement::SaasTerms)?,
            dpa: self.version(Agreement::Dpa)?,
            sub_processors: self.version(Agreement::SubProcessors)?,
        })
    }
}

/// A canonical signed decimal: digits with no leading zero, an optional
/// `-`, and no `-0`.
fn parse_i64(s: &str) -> Option<i64> {
    let body = s.strip_prefix('-').unwrap_or(s);
    let digits = !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit());
    let no_leading_zero = body == "0" || !body.starts_with('0');
    let no_negative_zero = s != "-0";
    if digits && no_leading_zero && no_negative_zero {
        s.parse::<i64>().ok()
    } else {
        None
    }
}

fn take_record(v: &Value) -> R<CpRecord> {
    let o = v.as_object().ok_or(RecordError::Schema)?;
    let kind = o
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(RecordError::Schema)?;
    match kind {
        KIND_SIGNED_UP => {
            let f = Fields::of(
                o,
                &[
                    "kind",
                    "tenant",
                    "legal_name",
                    "billing_address",
                    "contracting_signatory",
                    "at",
                ],
            )?;
            Ok(CpRecord::SignedUp {
                tenant: TenantId::from_raw(f.id("tenant")?),
                legal_name: f.text("legal_name")?,
                billing_address: f.text("billing_address")?,
                contracting_signatory: f.text("contracting_signatory")?,
                at: f.at()?,
            })
        }
        KIND_AGREEMENT_ACCEPTED => {
            let f = Fields::of(o, &["kind", "tenant", "agreement", "version", "by", "at"])?;
            Ok(CpRecord::AgreementAccepted {
                tenant: TenantId::from_raw(f.id("tenant")?),
                agreement: Agreement::from_name(f.str("agreement")?)
                    .ok_or(RecordError::BadValue("agreement"))?,
                version: parse_version(f.str("version")?)
                    .ok_or(RecordError::BadValue("version"))?,
                by: f.text("by")?,
                at: f.at()?,
            })
        }
        KIND_TENANT_REVIEWED => {
            let f = Fields::of(o, &["kind", "tenant", "outcome", "by", "at"])?;
            Ok(CpRecord::TenantReviewed {
                tenant: TenantId::from_raw(f.id("tenant")?),
                outcome: ReviewOutcome::from_name(f.str("outcome")?)
                    .ok_or(RecordError::BadValue("outcome"))?,
                by: StaffId::from_raw(f.id("by")?),
                at: f.at()?,
            })
        }
        KIND_AGREEMENTS_OFFERED => {
            let f = Fields::of(
                o,
                &["kind", "saas_terms", "dpa", "sub_processors", "by", "at"],
            )?;
            Ok(CpRecord::AgreementsOffered {
                versions: f.versions()?,
                by: StaffId::from_raw(f.id("by")?),
                at: f.at()?,
            })
        }
        KIND_TENANT_PROVISIONED => {
            let f = Fields::of(
                o,
                &[
                    "kind",
                    "tenant",
                    "saas_terms",
                    "dpa",
                    "sub_processors",
                    "at",
                ],
            )?;
            Ok(CpRecord::TenantProvisioned {
                tenant: TenantId::from_raw(f.id("tenant")?),
                versions: f.versions()?,
                at: f.at()?,
            })
        }
        _ => Err(RecordError::Schema),
    }
}
