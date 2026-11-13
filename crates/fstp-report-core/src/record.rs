//! The `Report` ledger envelope (M5 design section 4.3): its records, their
//! stored JSON form, the fold and the approval decision (R-RP-03, Q3).
//!
//! - `ReportGenerated` names the output, its scope, the snapshot digest,
//!   the template version, the funder profile it was generated under (id,
//!   version and file digest, M9 design section 2.1), the document digest
//!   and the generator.
//! - `ReportApproved` names the approver. A Financial signatory who did
//!   not generate the document approves it (Q3, answered 2026-11-06).
//!   [`approve`] decides it, and the fold refuses a self-approval too, so
//!   no ledger that replays holds one.
//!
//! The JSON form follows the core codec: a `type` tag, ids as canonical
//! decimal strings, digests as lowercase hex, and every member required.
//! Unknown members are refused. Fuzzed (`report_record_decode`).

use std::collections::BTreeMap;

use fstp_domain::id::{AccountId, CallId, ContentDigest, ProgrammeId};
use fstp_domain::roles::{Role, RosterState};
use fstp_domain::time::Timestamp;
use fstp_json::{FromJson, FromJsonError, FromJsonErrorKind, Object, ToJson, Value};

use crate::kind::{ReportKind, Scope};
use crate::pin::{ProfilePin, is_profile_id};

/// The envelope name of report records in the stored engine form.
pub const ENVELOPE: &str = "report";

/// A funder document, as the ledger names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportId(u128);

impl ReportId {
    /// The id with raw value `r`, as drawn by the shell.
    pub const fn from_raw(r: u128) -> ReportId {
        ReportId(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// A record of the `Report` envelope.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReportRecord {
    /// A funder document was generated as a draft (R-RP-01).
    Generated {
        /// The document.
        report: ReportId,
        /// The output of the funder profile.
        kind: ReportKind,
        /// The call or programme it covers.
        scope: Scope,
        /// The digest of the data snapshot.
        snapshot: ContentDigest,
        /// The template version.
        template: String,
        /// The funder profile it was generated under (P-53).
        profile: ProfilePin,
        /// The SHA-256 of the document bytes.
        document: ContentDigest,
        /// The generator.
        by: AccountId,
    },
    /// A funder document was approved for release (R-RP-03).
    Approved {
        /// The document.
        report: ReportId,
        /// The approver: a Financial signatory, not the generator.
        approver: AccountId,
    },
}

/// One generated document in the store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoredReport {
    /// The output.
    pub kind: ReportKind,
    /// The scope.
    pub scope: Scope,
    /// The snapshot digest.
    pub snapshot: ContentDigest,
    /// The template version.
    pub template: String,
    /// The funder profile.
    pub profile: ProfilePin,
    /// The document digest.
    pub document: ContentDigest,
    /// The generator.
    pub generator: AccountId,
    /// The approver, once approved.
    pub approver: Option<AccountId>,
}

/// Why the fold refused a report record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFoldError {
    /// A second `ReportGenerated` of one id.
    DuplicateReport,
    /// An approval of an unknown report.
    UnknownReport,
    /// A second approval.
    AlreadyApproved,
    /// The generator approved its own document (Q3, SoD).
    SelfApproval,
}

/// Every funder document of the ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReportStore {
    reports: BTreeMap<ReportId, StoredReport>,
}

impl ReportStore {
    /// The document `report`.
    pub fn report(&self, report: ReportId) -> Option<&StoredReport> {
        self.reports.get(&report)
    }

    /// Every document, by id.
    pub fn reports(&self) -> impl Iterator<Item = (ReportId, &StoredReport)> {
        self.reports.iter().map(|(k, v)| (*k, v))
    }

    /// Folds `record`. A refused record changes nothing.
    pub fn apply(&mut self, record: &ReportRecord) -> Result<(), ReportFoldError> {
        match record {
            ReportRecord::Generated {
                report,
                kind,
                scope,
                snapshot,
                template,
                profile,
                document,
                by,
            } => {
                if self.reports.contains_key(report) {
                    return Err(ReportFoldError::DuplicateReport);
                }
                self.reports.insert(
                    *report,
                    StoredReport {
                        kind: *kind,
                        scope: *scope,
                        snapshot: *snapshot,
                        template: template.clone(),
                        profile: profile.clone(),
                        document: *document,
                        generator: *by,
                        approver: None,
                    },
                );
                Ok(())
            }
            ReportRecord::Approved { report, approver } => {
                let r = self
                    .reports
                    .get_mut(report)
                    .ok_or(ReportFoldError::UnknownReport)?;
                if r.approver.is_some() {
                    return Err(ReportFoldError::AlreadyApproved);
                }
                if r.generator == *approver {
                    return Err(ReportFoldError::SelfApproval);
                }
                r.approver = Some(*approver);
                Ok(())
            }
        }
    }
}

/// Why an approval was refused (R-RP-03, Q3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// No such document.
    UnknownReport,
    /// The document is approved already.
    AlreadyApproved,
    /// The approver generated the document (Q3, separation of duties).
    Generator,
    /// The approver holds no Financial signatory role (Q3).
    NotFinancialSignatory,
}

/// Decides the approval of `report` by `approver`. `financial_signatory`
/// is whether the approver holds the Financial signatory role now, as
/// [`is_financial_signatory`] answers it.
pub fn approve(
    store: &ReportStore,
    report: ReportId,
    approver: AccountId,
    financial_signatory: bool,
) -> Result<ReportRecord, ApprovalRefusal> {
    let r = store.report(report).ok_or(ApprovalRefusal::UnknownReport)?;
    if r.approver.is_some() {
        return Err(ApprovalRefusal::AlreadyApproved);
    }
    if r.generator == approver {
        return Err(ApprovalRefusal::Generator);
    }
    if !financial_signatory {
        return Err(ApprovalRefusal::NotFinancialSignatory);
    }
    Ok(ReportRecord::Approved { report, approver })
}

/// Whether `account` holds an active Financial signatory binding at `at`.
pub fn is_financial_signatory(roster: &RosterState, account: AccountId, at: Timestamp) -> bool {
    roster
        .bindings()
        .any(|(_, b)| b.account == account && b.role == Role::FinancialSignatory && b.active_at(at))
}

// ---------------------------------------------------------------------------
// The stored JSON form
// ---------------------------------------------------------------------------

const GENERATED: &str = "ReportGenerated";
const APPROVED: &str = "ReportApproved";
const GENERATED_MEMBERS: [&str; 9] = [
    "type", "report", "kind", "scope", "snapshot", "template", "profile", "document", "by",
];
const PROFILE_MEMBERS: [&str; 3] = ["id", "version", "digest"];
const APPROVED_MEMBERS: [&str; 3] = ["type", "report", "approver"];
/// The longest template version accepted.
const MAX_TEMPLATE: usize = 128;

fn id(n: u128) -> Value {
    Value::String(n.to_string())
}

fn hex(d: ContentDigest) -> Value {
    let mut s = String::with_capacity(64);
    for b in d.bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    Value::String(s)
}

impl ToJson for ReportRecord {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            ReportRecord::Generated {
                report,
                kind,
                scope,
                snapshot,
                template,
                profile,
                document,
                by,
            } => {
                o.insert("type", Value::String(GENERATED.into()));
                o.insert("report", id(report.raw()));
                o.insert("kind", Value::String(kind.name().into()));
                let mut s = Object::new();
                match scope {
                    Scope::Call(c) => s.insert("call", id(c.raw())),
                    Scope::Programme(p) => s.insert("programme", id(p.raw())),
                };
                o.insert("scope", Value::Object(s));
                o.insert("snapshot", hex(*snapshot));
                o.insert("template", Value::String(template.clone()));
                let mut p = Object::new();
                p.insert("id", Value::String(profile.id.clone()));
                p.insert("version", Value::String(profile.version.to_string()));
                p.insert("digest", hex(profile.digest));
                o.insert("profile", Value::Object(p));
                o.insert("document", hex(*document));
                o.insert("by", id(by.raw()));
            }
            ReportRecord::Approved { report, approver } => {
                o.insert("type", Value::String(APPROVED.into()));
                o.insert("report", id(report.raw()));
                o.insert("approver", id(approver.raw()));
            }
        }
        Value::Object(o)
    }
}

fn invalid() -> FromJsonError {
    FromJsonError::invalid("not a report record value")
}

fn exact<'v>(v: &'v Value, members: &[&str]) -> Result<&'v Object, FromJsonError> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::wrong_type("an object", v))?;
    if o.len() != members.len() || !members.iter().all(|m| o.contains_key(m)) {
        return Err(FromJsonError::new(FromJsonErrorKind::UnknownField));
    }
    Ok(o)
}

fn take_id(o: &Object, k: &str) -> Result<u128, FromJsonError> {
    let s = o.get(k).and_then(Value::as_str).ok_or_else(invalid)?;
    let n: u128 = s.parse().map_err(|_| invalid())?;
    if n.to_string() != s {
        return Err(invalid());
    }
    Ok(n)
}

fn take_digest(o: &Object, k: &str) -> Result<ContentDigest, FromJsonError> {
    let s = o.get(k).and_then(Value::as_str).ok_or_else(invalid)?;
    if s.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        let mut b = 0_u8;
        for c in pair {
            let d = match c {
                b'0'..=b'9' => c.wrapping_sub(b'0'),
                b'a'..=b'f' => c.wrapping_sub(b'a').wrapping_add(10),
                _ => return Err(invalid()),
            };
            b = b.wrapping_mul(16).wrapping_add(d);
        }
        *slot = b;
    }
    Ok(ContentDigest::from_bytes(out))
}

/// The `profile` member: `{id, version, digest}`, the version a canonical
/// decimal string from 1 to 65535.
fn take_profile(o: &Object) -> Result<ProfilePin, FromJsonError> {
    let p = exact(o.get("profile").ok_or_else(invalid)?, &PROFILE_MEMBERS)?;
    let id = p
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_profile_id(id))
        .ok_or_else(invalid)?
        .to_owned();
    let v = p
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let version: u16 = v.parse().map_err(|_| invalid())?;
    if version == 0 || version.to_string() != v {
        return Err(invalid());
    }
    Ok(ProfilePin {
        id,
        version,
        digest: take_digest(p, "digest")?,
    })
}

impl FromJson for ReportRecord {
    fn from_json(value: &Value) -> Result<ReportRecord, FromJsonError> {
        let tag = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        match tag {
            GENERATED => {
                let o = exact(value, &GENERATED_MEMBERS)?;
                let kind = o
                    .get("kind")
                    .and_then(Value::as_str)
                    .and_then(ReportKind::from_name)
                    .ok_or_else(invalid)?;
                let scope_v = o.get("scope").ok_or_else(invalid)?;
                let scope = if scope_v.get("call").is_some() {
                    Scope::Call(CallId::from_raw(take_id(
                        exact(scope_v, &["call"])?,
                        "call",
                    )?))
                } else {
                    let s = exact(scope_v, &["programme"])?;
                    Scope::Programme(ProgrammeId::from_raw(take_id(s, "programme")?))
                };
                let template = o
                    .get("template")
                    .and_then(Value::as_str)
                    .filter(|t| !t.is_empty() && t.len() <= MAX_TEMPLATE)
                    .ok_or_else(invalid)?
                    .to_owned();
                Ok(ReportRecord::Generated {
                    report: ReportId::from_raw(take_id(o, "report")?),
                    kind,
                    scope,
                    snapshot: take_digest(o, "snapshot")?,
                    template,
                    profile: take_profile(o)?,
                    document: take_digest(o, "document")?,
                    by: AccountId::from_raw(take_id(o, "by")?),
                })
            }
            APPROVED => {
                let o = exact(value, &APPROVED_MEMBERS)?;
                Ok(ReportRecord::Approved {
                    report: ReportId::from_raw(take_id(o, "report")?),
                    approver: AccountId::from_raw(take_id(o, "approver")?),
                })
            }
            _ => Err(invalid()),
        }
    }
}
