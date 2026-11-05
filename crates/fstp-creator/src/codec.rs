//! JSON codecs of creator commands and records (M4 design section 9,
//! fuzz targets `creator_command_decode`, `creator_record_decode` and
//! `validate_total`).
//!
//! The rules follow the M2 domain codec:
//!
//! - Every object is decoded against its schema. An unknown or missing
//!   member is refused. An optional value is present as `null`.
//! - Ids, sequence numbers, counts and timestamps are canonical decimal
//!   strings. A leading zero, a sign on an unsigned value, `-0` or any
//!   other character is refused.
//! - Digests are lowercase hexadecimal strings of 64 characters.
//! - Sets are lists in strictly ascending order.
//! - A variant is an object with a `kind` member naming it.
//! - A field is its `FieldId::key`, such as `"money.p05_recipient_cap"`.
//!   A field value is a string holding its canonical RFC 8785 text from
//!   `fstp_programme::encode_field_value`. It decodes with the field's
//!   strict decoder and must re-encode byte for byte.
//! - Decode errors carry a kind and member names only, never input
//!   content (R-NF-02). No decode path panics.
//!
//! Decoding is structural. It runs no guard. `CleanReport` and
//! `ActivationClearance` have no codec, and `ActivationApproved` decodes
//! only inside a record.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{
    AccountId, ContentDigest, DecisionId, OrganisationId, PolicyVersionId, ProgrammeId, TextId,
    TextRef,
};
use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{Array, FromJson, FromJsonError, Object, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::Currency;
use fstp_programme::{FieldId, FieldValue, decode_field_value_in, encode_field_value};

use crate::check::{CallPackageElement, CheckId, CheckSubject, WarningKey};
use crate::ids::{ImportDocumentId, ImportProposalId, InvitationId, TemplateId};
use crate::inputs::{CreatorInputs, PortPresence, PreviewOutcome, SodPreview, VaultChecks};
use crate::model::{
    CreatorCommand, CreatorRecord, DraftRevision, FieldEdit, ImportResolution, Invitee, Provenance,
    ReportDigest, StartingPoint, ValueDigest,
};
use crate::probe::{ProbeKind, ProbeOutcome, ProbeSet};
use crate::state::CreatorState;
use crate::theme::{MandatoryElement, TextRole, Theme, ThemeMode};
use crate::validate::{ValidationReport, draft_facts, validate_at};
use crate::witness::ActivationApproved;

type R<T> = Result<T, FromJsonError>;

/// Why a creator decode failed.
#[derive(Clone, Debug)]
pub enum CreatorError {
    /// The bytes are not JSON within the parse limits.
    NotJson,
    /// The JSON does not match the schema.
    Decode(FromJsonError),
    /// The value has no canonical RFC 8785 text.
    NotCanonical,
}

impl std::fmt::Display for CreatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreatorError::NotJson => f.write_str("the input is not JSON"),
            CreatorError::Decode(e) => write!(f, "{e}"),
            CreatorError::NotCanonical => f.write_str("the value has no canonical text"),
        }
    }
}

impl std::error::Error for CreatorError {}

fn parse(bytes: &[u8]) -> Result<Value, CreatorError> {
    fstp_json::parse(bytes).map_err(|_| CreatorError::NotJson)
}

/// Decodes a creator command from its JSON text. Fuzzed
/// (`creator_command_decode`).
pub fn decode_command(bytes: &[u8]) -> Result<CreatorCommand, CreatorError> {
    CreatorCommand::from_json(&parse(bytes)?).map_err(CreatorError::Decode)
}

/// Decodes a creator record from its stored JSON text. Fuzzed
/// (`creator_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<CreatorRecord, CreatorError> {
    CreatorRecord::from_json(&parse(bytes)?).map_err(CreatorError::Decode)
}

/// The canonical RFC 8785 text of a creator command.
pub fn encode_command(cmd: &CreatorCommand) -> Result<String, CreatorError> {
    cmd.to_json()
        .to_canonical()
        .map_err(|_| CreatorError::NotCanonical)
}

/// The canonical RFC 8785 text of a creator record, as the ledger stores
/// it.
pub fn encode_record(record: &CreatorRecord) -> Result<String, CreatorError> {
    record
        .to_json()
        .to_canonical()
        .map_err(|_| CreatorError::NotCanonical)
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

fn s(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn dec(n: u128) -> Value {
    Value::String(n.to_string())
}

fn take_str(v: &Value) -> R<&str> {
    v.as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a string", v))
}

fn take_dec(v: &Value) -> R<u128> {
    let t = take_str(v)?;
    let b = t.as_bytes();
    let canonical = match b {
        [] => false,
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(FromJsonError::invalid("not a canonical decimal string"));
    }
    t.parse::<u128>()
        .map_err(|_| FromJsonError::invalid("decimal string out of range"))
}

fn take_u32(v: &Value) -> R<u32> {
    u32::try_from(take_dec(v)?).map_err(|_| FromJsonError::invalid("decimal string out of range"))
}

fn take_u64(v: &Value) -> R<u64> {
    u64::try_from(take_dec(v)?).map_err(|_| FromJsonError::invalid("decimal string out of range"))
}

fn put_i64(n: i64) -> Value {
    Value::String(n.to_string())
}

fn take_i64(v: &Value) -> R<i64> {
    let t = take_str(v)?;
    match t.strip_prefix('-') {
        Some(rest) => {
            let m = take_dec(&s(rest))?;
            if m == 0 {
                return Err(FromJsonError::invalid("not a canonical decimal string"));
            }
            let m = i128::try_from(m)
                .map_err(|_| FromJsonError::invalid("decimal string out of range"))?;
            i64::try_from(m.saturating_neg())
                .map_err(|_| FromJsonError::invalid("decimal string out of range"))
        }
        None => i64::try_from(take_dec(v)?)
            .map_err(|_| FromJsonError::invalid("decimal string out of range")),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex32(b: [u8; 32]) -> Value {
    let mut out = String::with_capacity(64);
    for x in b {
        out.push(char::from(
            HEX.get(usize::from(x >> 4)).copied().unwrap_or(b'0'),
        ));
        out.push(char::from(
            HEX.get(usize::from(x & 0x0f)).copied().unwrap_or(b'0'),
        ));
    }
    Value::String(out)
}

fn take_hex32(v: &Value) -> R<[u8; 32]> {
    let t = take_str(v)?.as_bytes();
    if t.len() != 64 {
        return Err(FromJsonError::invalid("not a 32-byte lowercase hex digest"));
    }
    let nibble = |c: u8| -> R<u8> {
        match c {
            b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
            b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
            _ => Err(FromJsonError::invalid("not a 32-byte lowercase hex digest")),
        }
    };
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(t.chunks_exact(2)) {
        let (Some(hi), Some(lo)) = (pair.first(), pair.get(1)) else {
            return Err(FromJsonError::invalid("not a 32-byte lowercase hex digest"));
        };
        *slot = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Ok(out)
}

fn obj(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

fn tagged(kind: &'static str, mut members: Vec<(&'static str, Value)>) -> Value {
    members.insert(0, ("kind", s(kind)));
    obj(members)
}

/// The object `v` with exactly the members `names`.
fn exact<'a>(v: &'a Value, names: &[&'static str]) -> R<&'a Object> {
    let o = expect_object(v)?;
    reject_unknown(o, names)?;
    for n in names {
        if !o.contains_key(n) {
            return Err(
                FromJsonError::new(fstp_json::typed::FromJsonErrorKind::MissingField).at_field(n),
            );
        }
    }
    Ok(o)
}

fn member<'a>(o: &'a Object, name: &'static str) -> R<&'a Value> {
    o.get(name).ok_or_else(|| {
        FromJsonError::new(fstp_json::typed::FromJsonErrorKind::MissingField).at_field(name)
    })
}

fn at<'a, T>(o: &'a Object, name: &'static str, f: impl FnOnce(&'a Value) -> R<T>) -> R<T> {
    f(member(o, name)?).map_err(|e| e.at_field(name))
}

/// The `kind` of a tagged object.
fn kind_of(v: &Value) -> R<&str> {
    let o = expect_object(v)?;
    at(o, "kind", take_str)
}

fn list(v: &Value) -> R<&Array> {
    v.as_array()
        .ok_or_else(|| FromJsonError::wrong_type("an array", v))
}

fn take_list<T>(v: &Value, f: impl Fn(&Value) -> R<T>) -> R<Vec<T>> {
    list(v)?
        .iter()
        .enumerate()
        .map(|(i, x)| f(x).map_err(|e| e.at_index(i)))
        .collect()
}

fn take_set<T: Ord>(v: &Value, f: impl Fn(&Value) -> R<T>) -> R<BTreeSet<T>> {
    let items = take_list(v, f)?;
    if items.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
        return Err(FromJsonError::invalid(
            "set not in strictly ascending order",
        ));
    }
    Ok(items.into_iter().collect())
}

fn put_option<T>(x: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    x.map_or(Value::Null, f)
}

fn take_option<T>(v: &Value, f: impl FnOnce(&Value) -> R<T>) -> R<Option<T>> {
    if v.is_null() {
        Ok(None)
    } else {
        f(v).map(Some)
    }
}

fn named<T: Copy>(v: &Value, all: &[T], name: impl Fn(T) -> &'static str) -> R<T> {
    let t = take_str(v)?;
    all.iter()
        .copied()
        .find(|x| name(*x) == t)
        .ok_or_else(|| FromJsonError::invalid("unknown name"))
}

// ---------------------------------------------------------------------------
// Domain and creator values
// ---------------------------------------------------------------------------

fn programme(v: &Value) -> R<ProgrammeId> {
    take_dec(v).map(ProgrammeId::from_raw)
}

fn account(v: &Value) -> R<AccountId> {
    take_dec(v).map(AccountId::from_raw)
}

fn digest(v: &Value) -> R<ContentDigest> {
    take_hex32(v).map(ContentDigest::from_bytes)
}

fn put_profile(p: &FunderProfileRef) -> Value {
    s(p.0.as_str())
}

/// A profile reference: a string holding canonical RFC 8785 text.
fn profile(v: &Value) -> R<FunderProfileRef> {
    let text = take_str(v)?;
    let inner = fstp_json::parse(text.as_bytes())
        .map_err(|_| FromJsonError::invalid("opaque value is not JSON"))?;
    let o = OpaqueValue::from_value(&inner)
        .map_err(|_| FromJsonError::invalid("opaque value is not canonical"))?;
    if o.as_str() != text {
        return Err(FromJsonError::invalid("opaque value is not canonical"));
    }
    Ok(FunderProfileRef(o))
}

fn put_revision(r: DraftRevision) -> Value {
    obj(vec![
        ("seq", dec(u128::from(r.seq()))),
        ("entry", dec(u128::from(r.entry().raw()))),
    ])
}

fn revision(v: &Value) -> R<DraftRevision> {
    let o = exact(v, &["seq", "entry"])?;
    Ok(DraftRevision::new(
        at(o, "seq", take_u32)?,
        Seq::from_raw(at(o, "entry", take_u64)?),
    ))
}

const ROLE_NAMES: [(Role, &str); 16] = [
    (Role::ProgrammeManager, "ProgrammeManager"),
    (Role::CallDrafter, "CallDrafter"),
    (Role::FstpCoordinator, "FstpCoordinator"),
    (Role::CommitteeMember, "CommitteeMember"),
    (Role::CommitteeChair, "CommitteeChair"),
    (Role::IrcMember, "IrcMember"),
    (Role::Applicant, "Applicant"),
    (Role::ApplicantTeamMember, "ApplicantTeamMember"),
    (Role::Guardian, "Guardian"),
    (Role::TenantAdmin, "TenantAdmin"),
    (Role::FinanceApprover, "FinanceApprover"),
    (Role::PaymentReleaser, "PaymentReleaser"),
    (Role::ContractSignatory, "ContractSignatory"),
    (Role::FinancialSignatory, "FinancialSignatory"),
    (Role::LegalSignatory, "LegalSignatory"),
    (Role::Auditor, "Auditor"),
];

fn role_name(r: Role) -> &'static str {
    ROLE_NAMES
        .iter()
        .find(|(x, _)| *x == r)
        .map_or("", |(_, n)| *n)
}

fn role(v: &Value) -> R<Role> {
    let roles: Vec<Role> = ROLE_NAMES.iter().map(|(r, _)| *r).collect();
    named(v, &roles, role_name)
}

/// A field id: its [`FieldId::key`], `"<step>.<member>"`, such as
/// `"money.p05_recipient_cap"`.
fn put_field(f: FieldId) -> Value {
    Value::String(f.key())
}

/// A field id from its key. Only the exact key of a field is accepted, so
/// the decoded id encodes back to the same string.
fn field(v: &Value) -> R<FieldId> {
    let text = take_str(v)?;
    match FieldId::from_key(text) {
        Some(f) if f.key() == text => Ok(f),
        _ => Err(FromJsonError::invalid("unknown field")),
    }
}

/// The currency field values are decoded in.
///
/// ADR-006 fixes EUR, and `Currency::from_code` knows no other code, so
/// every programme is in EUR. A second currency would need a currency
/// member in the edit, and this constant would go.
const VALUE_CURRENCY: Currency = Currency::Eur;

/// A field value: a string holding its canonical RFC 8785 text, as
/// [`encode_field_value`] writes it. The shell's [`ValueDigest`] is a
/// digest of exactly these bytes.
fn put_value(value: &FieldValue) -> Value {
    Value::String(encode_field_value(value))
}

/// A field value of `f`, decoded by the field's strict decoder.
///
/// The text must re-encode byte for byte. So a value has one spelling on
/// the wire and in the ledger, and its digest names one text.
fn value_of(f: FieldId, v: &Value) -> R<FieldValue> {
    let text = take_str(v)?;
    let value = decode_field_value_in(f, VALUE_CURRENCY, text.as_bytes())
        .map_err(|_| FromJsonError::invalid("field value does not decode"))?;
    if encode_field_value(&value) != text {
        return Err(FromJsonError::invalid("field value is not canonical"));
    }
    Ok(value)
}

fn put_value_digest(d: ValueDigest) -> Value {
    hex32(d.digest().bytes())
}

fn value_digest(v: &Value) -> R<ValueDigest> {
    digest(v).map(ValueDigest::new)
}

fn put_text_ref(t: TextRef) -> Value {
    obj(vec![
        ("id", dec(t.id().raw())),
        ("digest", hex32(t.digest().bytes())),
    ])
}

fn text_ref(v: &Value) -> R<TextRef> {
    let o = exact(v, &["id", "digest"])?;
    Ok(TextRef::new(
        TextId::from_raw(at(o, "id", take_dec)?),
        at(o, "digest", digest)?,
    ))
}

fn put_start(st: &StartingPoint) -> Value {
    match st {
        StartingPoint::Blank { profile } => {
            tagged("Blank", vec![("profile", put_profile(profile))])
        }
        StartingPoint::Clone { source } => tagged("Clone", vec![("source", dec(source.raw()))]),
        StartingPoint::Template { template, version } => tagged(
            "Template",
            vec![
                ("template", dec(template.raw())),
                ("version", dec(u128::from(*version))),
            ],
        ),
        StartingPoint::Import { document } => {
            tagged("Import", vec![("document", dec(document.raw()))])
        }
    }
}

fn start(v: &Value) -> R<StartingPoint> {
    match kind_of(v)? {
        "Blank" => {
            let o = exact(v, &["kind", "profile"])?;
            Ok(StartingPoint::Blank {
                profile: at(o, "profile", profile)?,
            })
        }
        "Clone" => {
            let o = exact(v, &["kind", "source"])?;
            Ok(StartingPoint::Clone {
                source: at(o, "source", programme)?,
            })
        }
        "Template" => {
            let o = exact(v, &["kind", "template", "version"])?;
            Ok(StartingPoint::Template {
                template: TemplateId::from_raw(at(o, "template", take_dec)?),
                version: at(o, "version", take_u32)?,
            })
        }
        "Import" => {
            let o = exact(v, &["kind", "document"])?;
            Ok(StartingPoint::Import {
                document: ImportDocumentId::from_raw(at(o, "document", take_dec)?),
            })
        }
        _ => Err(FromJsonError::invalid("unknown kind")),
    }
}

fn resolution_name(r: ImportResolution) -> &'static str {
    match r {
        ImportResolution::Confirmed => "Confirmed",
        ImportResolution::Edited => "Edited",
    }
}

fn put_provenance(p: &Provenance) -> Value {
    match p {
        Provenance::Manual => tagged("Manual", vec![]),
        Provenance::Default { profile } => {
            tagged("Default", vec![("profile", put_profile(profile))])
        }
        Provenance::Template { template, version } => tagged(
            "Template",
            vec![
                ("template", dec(template.raw())),
                ("version", dec(u128::from(*version))),
            ],
        ),
        Provenance::Clone { source, version } => tagged(
            "Clone",
            vec![
                ("source", dec(source.raw())),
                ("version", dec(version.raw())),
            ],
        ),
        Provenance::Import {
            proposal,
            resolution,
        } => tagged(
            "Import",
            vec![
                ("proposal", dec(proposal.raw())),
                ("resolution", s(resolution_name(*resolution))),
            ],
        ),
    }
}

fn provenance(v: &Value) -> R<Provenance> {
    match kind_of(v)? {
        "Manual" => {
            exact(v, &["kind"])?;
            Ok(Provenance::Manual)
        }
        "Default" => {
            let o = exact(v, &["kind", "profile"])?;
            Ok(Provenance::Default {
                profile: at(o, "profile", profile)?,
            })
        }
        "Template" => {
            let o = exact(v, &["kind", "template", "version"])?;
            Ok(Provenance::Template {
                template: TemplateId::from_raw(at(o, "template", take_dec)?),
                version: at(o, "version", take_u32)?,
            })
        }
        "Clone" => {
            let o = exact(v, &["kind", "source", "version"])?;
            Ok(Provenance::Clone {
                source: at(o, "source", programme)?,
                version: PolicyVersionId::from_raw(at(o, "version", take_dec)?),
            })
        }
        "Import" => {
            let o = exact(v, &["kind", "proposal", "resolution"])?;
            Ok(Provenance::Import {
                proposal: ImportProposalId::from_raw(at(o, "proposal", take_dec)?),
                resolution: at(o, "resolution", |x| {
                    named(
                        x,
                        &[ImportResolution::Confirmed, ImportResolution::Edited],
                        resolution_name,
                    )
                })?,
            })
        }
        _ => Err(FromJsonError::invalid("unknown kind")),
    }
}

fn put_invitee(i: Invitee) -> Value {
    match i {
        Invitee::Account(a) => tagged("Account", vec![("account", dec(a.raw()))]),
        Invitee::Pending { contact } => tagged("Pending", vec![("contact", put_text_ref(contact))]),
    }
}

fn invitee(v: &Value) -> R<Invitee> {
    match kind_of(v)? {
        "Account" => {
            let o = exact(v, &["kind", "account"])?;
            Ok(Invitee::Account(at(o, "account", account)?))
        }
        "Pending" => {
            let o = exact(v, &["kind", "contact"])?;
            Ok(Invitee::Pending {
                contact: at(o, "contact", text_ref)?,
            })
        }
        _ => Err(FromJsonError::invalid("unknown kind")),
    }
}

fn mode_name(m: ThemeMode) -> &'static str {
    match m {
        ThemeMode::Light => "Light",
        ThemeMode::Dark => "Dark",
    }
}

const TEXT_ROLES: [TextRole; 5] = [
    TextRole::Body,
    TextRole::Muted,
    TextRole::Link,
    TextRole::Error,
    TextRole::OnAccent,
];

fn text_role_name(r: TextRole) -> &'static str {
    match r {
        TextRole::Body => "Body",
        TextRole::Muted => "Muted",
        TextRole::Link => "Link",
        TextRole::Error => "Error",
        TextRole::OnAccent => "OnAccent",
    }
}

fn element_name(e: MandatoryElement) -> &'static str {
    match e {
        MandatoryElement::FunderVisibility => "FunderVisibility",
        MandatoryElement::AiDisclosure => "AiDisclosure",
        MandatoryElement::PrivacyNotice => "PrivacyNotice",
        MandatoryElement::AccessibilityStatement => "AccessibilityStatement",
        MandatoryElement::DataActInformation => "DataActInformation",
        MandatoryElement::PlatformAttribution => "PlatformAttribution",
    }
}

fn put_subject(sub: &CheckSubject) -> Value {
    match sub {
        CheckSubject::Draft => tagged("Draft", vec![]),
        CheckSubject::Field(f) => tagged("Field", vec![("field", put_field(*f))]),
        CheckSubject::Invitation(i) => tagged("Invitation", vec![("invitation", dec(i.raw()))]),
        CheckSubject::Probe(p) => tagged("Probe", vec![("probe", s(p.name()))]),
        CheckSubject::Colour { mode, role } => tagged(
            "Colour",
            vec![
                ("mode", s(mode_name(*mode))),
                ("role", s(text_role_name(*role))),
            ],
        ),
        CheckSubject::Element(e) => tagged("Element", vec![("element", s(element_name(*e)))]),
        CheckSubject::CallPackage(e) => tagged("CallPackage", vec![("element", s(e.name()))]),
        CheckSubject::GuideSection(h) => tagged("GuideSection", vec![("heading", s(h))]),
        CheckSubject::Placeholder(p) => tagged("Placeholder", vec![("name", s(p))]),
        CheckSubject::FlowDown(o) => tagged("FlowDown", vec![("obligation", s(o))]),
    }
}

fn subject(v: &Value) -> R<CheckSubject> {
    let string = |o: &Object, name: &'static str| at(o, name, |x| take_str(x).map(str::to_owned));
    match kind_of(v)? {
        "Draft" => {
            exact(v, &["kind"])?;
            Ok(CheckSubject::Draft)
        }
        "Field" => {
            let o = exact(v, &["kind", "field"])?;
            Ok(CheckSubject::Field(at(o, "field", field)?))
        }
        "Invitation" => {
            let o = exact(v, &["kind", "invitation"])?;
            Ok(CheckSubject::Invitation(InvitationId::from_raw(at(
                o,
                "invitation",
                take_dec,
            )?)))
        }
        "Probe" => {
            let o = exact(v, &["kind", "probe"])?;
            Ok(CheckSubject::Probe(at(o, "probe", probe_kind)?))
        }
        "Colour" => {
            let o = exact(v, &["kind", "mode", "role"])?;
            Ok(CheckSubject::Colour {
                mode: at(o, "mode", |x| {
                    named(x, &[ThemeMode::Light, ThemeMode::Dark], mode_name)
                })?,
                role: at(o, "role", |x| named(x, &TEXT_ROLES, text_role_name))?,
            })
        }
        "Element" => {
            let o = exact(v, &["kind", "element"])?;
            Ok(CheckSubject::Element(at(o, "element", |x| {
                named(x, &MandatoryElement::ALL, element_name)
            })?))
        }
        "CallPackage" => {
            let o = exact(v, &["kind", "element"])?;
            Ok(CheckSubject::CallPackage(at(o, "element", |x| {
                named(x, &CallPackageElement::ALL, CallPackageElement::name)
            })?))
        }
        "GuideSection" => {
            let o = exact(v, &["kind", "heading"])?;
            Ok(CheckSubject::GuideSection(string(o, "heading")?))
        }
        "Placeholder" => {
            let o = exact(v, &["kind", "name"])?;
            Ok(CheckSubject::Placeholder(string(o, "name")?))
        }
        "FlowDown" => {
            let o = exact(v, &["kind", "obligation"])?;
            Ok(CheckSubject::FlowDown(string(o, "obligation")?))
        }
        _ => Err(FromJsonError::invalid("unknown kind")),
    }
}

fn check_id(v: &Value) -> R<CheckId> {
    named(v, &CheckId::ALL, CheckId::name)
}

fn probe_kind(v: &Value) -> R<ProbeKind> {
    named(v, &ProbeKind::ALL, ProbeKind::name)
}

fn probe_outcome(v: &Value) -> R<ProbeOutcome> {
    named(v, &ProbeOutcome::ALL, ProbeOutcome::name)
}

fn put_key(k: &WarningKey) -> Value {
    obj(vec![
        ("check", s(k.check.name())),
        ("subject", put_subject(&k.subject)),
    ])
}

fn key(v: &Value) -> R<WarningKey> {
    let o = exact(v, &["check", "subject"])?;
    Ok(WarningKey {
        check: at(o, "check", check_id)?,
        subject: at(o, "subject", subject)?,
    })
}

fn put_digest(d: &ReportDigest) -> Value {
    obj(vec![
        ("programme", dec(d.programme().raw())),
        ("revision", put_revision(d.revision())),
        ("rows", Value::Array(d.rows().iter().map(put_key).collect())),
    ])
}

fn report_digest(v: &Value) -> R<ReportDigest> {
    let o = exact(v, &["programme", "revision", "rows"])?;
    Ok(ReportDigest::new(
        at(o, "programme", programme)?,
        at(o, "revision", revision)?,
        at(o, "rows", |x| take_list(x, key))?,
    ))
}

fn put_accounts(set: &BTreeSet<AccountId>) -> Value {
    Value::Array(set.iter().map(|a| dec(a.raw())).collect())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// A field edit: `{field, value, digest, provenance}`.
///
/// `value` is written under `field`, and the decoder reads it with the
/// decoder of `field`. So an edit whose value belongs to another field
/// never survives a round trip: it is refused, or it decodes as a value of
/// `field`. Every decoded edit holds a value of its own field.
fn put_edit(e: &FieldEdit) -> Value {
    obj(vec![
        ("field", put_field(e.field)),
        ("value", put_value(&e.value)),
        ("digest", put_value_digest(e.digest)),
        ("provenance", put_provenance(&e.provenance)),
    ])
}

fn edit(v: &Value) -> R<FieldEdit> {
    let o = exact(v, &["field", "value", "digest", "provenance"])?;
    let f = at(o, "field", field)?;
    Ok(FieldEdit {
        field: f,
        value: at(o, "value", |x| value_of(f, x))?,
        digest: at(o, "digest", value_digest)?,
        provenance: at(o, "provenance", provenance)?,
    })
}

impl ToJson for CreatorCommand {
    fn to_json(&self) -> Value {
        let p = |id: ProgrammeId| ("programme", dec(id.raw()));
        match self {
            CreatorCommand::OpenDraft {
                programme,
                version,
                profile,
            } => tagged(
                "OpenDraft",
                vec![
                    p(*programme),
                    ("version", dec(version.raw())),
                    ("profile", put_profile(profile)),
                ],
            ),
            CreatorCommand::ApplyStart {
                programme,
                base,
                start,
            } => tagged(
                "ApplyStart",
                vec![
                    p(*programme),
                    ("base", put_revision(*base)),
                    ("start", put_start(start)),
                ],
            ),
            CreatorCommand::SaveFields {
                programme,
                base,
                fields,
            } => tagged(
                "SaveFields",
                vec![
                    p(*programme),
                    ("base", put_revision(*base)),
                    (
                        "fields",
                        Value::Array(fields.iter().map(put_edit).collect()),
                    ),
                ],
            ),
            CreatorCommand::AcceptNarrative {
                programme,
                base,
                field,
            } => tagged(
                "AcceptNarrative",
                vec![
                    p(*programme),
                    ("base", put_revision(*base)),
                    ("field", put_field(*field)),
                ],
            ),
            CreatorCommand::Invite {
                programme,
                invitation,
                role,
                invitee,
                organisation,
            } => tagged(
                "Invite",
                vec![
                    p(*programme),
                    ("invitation", dec(invitation.raw())),
                    ("role", s(role_name(*role))),
                    ("invitee", put_invitee(*invitee)),
                    ("organisation", put_option(*organisation, |o| dec(o.raw()))),
                ],
            ),
            CreatorCommand::WithdrawInvitation {
                programme,
                invitation,
            } => tagged(
                "WithdrawInvitation",
                vec![p(*programme), ("invitation", dec(invitation.raw()))],
            ),
            CreatorCommand::AcknowledgeWarning {
                programme,
                revision,
                warning,
            } => tagged(
                "AcknowledgeWarning",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("warning", put_key(warning)),
                ],
            ),
            CreatorCommand::RequestActivation {
                programme,
                revision,
            } => tagged(
                "RequestActivation",
                vec![p(*programme), ("revision", put_revision(*revision))],
            ),
            CreatorCommand::ApproveActivation {
                programme,
                revision,
                decision,
            } => tagged(
                "ApproveActivation",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("decision", dec(decision.raw())),
                ],
            ),
            CreatorCommand::SaveAsTenantTemplate {
                programme,
                template,
            } => tagged(
                "SaveAsTenantTemplate",
                vec![p(*programme), ("template", dec(template.raw()))],
            ),
        }
    }
}

impl FromJson for CreatorCommand {
    fn from_json(v: &Value) -> R<CreatorCommand> {
        let kind = kind_of(v)?;
        let o = |names: &[&'static str]| exact(v, names);
        match kind {
            "OpenDraft" => {
                let o = o(&["kind", "programme", "version", "profile"])?;
                Ok(CreatorCommand::OpenDraft {
                    programme: at(o, "programme", programme)?,
                    version: PolicyVersionId::from_raw(at(o, "version", take_dec)?),
                    profile: at(o, "profile", profile)?,
                })
            }
            "ApplyStart" => {
                let o = o(&["kind", "programme", "base", "start"])?;
                Ok(CreatorCommand::ApplyStart {
                    programme: at(o, "programme", programme)?,
                    base: at(o, "base", revision)?,
                    start: at(o, "start", start)?,
                })
            }
            "SaveFields" => {
                let o = o(&["kind", "programme", "base", "fields"])?;
                Ok(CreatorCommand::SaveFields {
                    programme: at(o, "programme", programme)?,
                    base: at(o, "base", revision)?,
                    fields: at(o, "fields", |x| take_list(x, edit))?,
                })
            }
            "AcceptNarrative" => {
                let o = o(&["kind", "programme", "base", "field"])?;
                Ok(CreatorCommand::AcceptNarrative {
                    programme: at(o, "programme", programme)?,
                    base: at(o, "base", revision)?,
                    field: at(o, "field", field)?,
                })
            }
            "Invite" => {
                let o = o(&[
                    "kind",
                    "programme",
                    "invitation",
                    "role",
                    "invitee",
                    "organisation",
                ])?;
                Ok(CreatorCommand::Invite {
                    programme: at(o, "programme", programme)?,
                    invitation: InvitationId::from_raw(at(o, "invitation", take_dec)?),
                    role: at(o, "role", role)?,
                    invitee: at(o, "invitee", invitee)?,
                    organisation: at(o, "organisation", |x| {
                        take_option(x, |y| take_dec(y).map(OrganisationId::from_raw))
                    })?,
                })
            }
            "WithdrawInvitation" => {
                let o = o(&["kind", "programme", "invitation"])?;
                Ok(CreatorCommand::WithdrawInvitation {
                    programme: at(o, "programme", programme)?,
                    invitation: InvitationId::from_raw(at(o, "invitation", take_dec)?),
                })
            }
            "AcknowledgeWarning" => {
                let o = o(&["kind", "programme", "revision", "warning"])?;
                Ok(CreatorCommand::AcknowledgeWarning {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    warning: at(o, "warning", key)?,
                })
            }
            "RequestActivation" => {
                let o = o(&["kind", "programme", "revision"])?;
                Ok(CreatorCommand::RequestActivation {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                })
            }
            "ApproveActivation" => {
                let o = o(&["kind", "programme", "revision", "decision"])?;
                Ok(CreatorCommand::ApproveActivation {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    decision: DecisionId::from_raw(at(o, "decision", take_dec)?),
                })
            }
            "SaveAsTenantTemplate" => {
                let o = o(&["kind", "programme", "template"])?;
                Ok(CreatorCommand::SaveAsTenantTemplate {
                    programme: at(o, "programme", programme)?,
                    template: TemplateId::from_raw(at(o, "template", take_dec)?),
                })
            }
            _ => Err(FromJsonError::invalid("unknown kind")),
        }
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One saved field of a record: `{field, digest, provenance}`. The ledger
/// body holds the value's digest, never the value.
fn put_saved(f: &(FieldId, ValueDigest, Provenance)) -> Value {
    obj(vec![
        ("field", put_field(f.0)),
        ("digest", put_value_digest(f.1)),
        ("provenance", put_provenance(&f.2)),
    ])
}

fn saved(v: &Value) -> R<(FieldId, ValueDigest, Provenance)> {
    let o = exact(v, &["field", "digest", "provenance"])?;
    Ok((
        at(o, "field", field)?,
        at(o, "digest", value_digest)?,
        at(o, "provenance", provenance)?,
    ))
}

impl ToJson for CreatorRecord {
    fn to_json(&self) -> Value {
        let p = |id: ProgrammeId| ("programme", dec(id.raw()));
        let by = |a: AccountId| ("by", dec(a.raw()));
        match self {
            CreatorRecord::DraftOpened {
                programme,
                profile,
                by: b,
            } => tagged(
                "DraftOpened",
                vec![p(*programme), ("profile", put_profile(profile)), by(*b)],
            ),
            CreatorRecord::StartApplied {
                programme,
                revision,
                start,
                by: b,
            } => tagged(
                "StartApplied",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("start", put_start(start)),
                    by(*b),
                ],
            ),
            CreatorRecord::FieldsSaved {
                programme,
                revision,
                fields,
                by: b,
            } => tagged(
                "FieldsSaved",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    (
                        "fields",
                        Value::Array(fields.iter().map(put_saved).collect()),
                    ),
                    by(*b),
                ],
            ),
            CreatorRecord::NarrativeAccepted {
                programme,
                revision,
                field,
                by: b,
            } => tagged(
                "NarrativeAccepted",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("field", put_field(*field)),
                    by(*b),
                ],
            ),
            CreatorRecord::InvitationRecorded {
                programme,
                invitation,
                role,
                invitee,
                organisation,
                by: b,
            } => tagged(
                "InvitationRecorded",
                vec![
                    p(*programme),
                    ("invitation", dec(invitation.raw())),
                    ("role", s(role_name(*role))),
                    ("invitee", put_invitee(*invitee)),
                    ("organisation", put_option(*organisation, |o| dec(o.raw()))),
                    by(*b),
                ],
            ),
            CreatorRecord::InvitationWithdrawn {
                programme,
                invitation,
                by: b,
            } => tagged(
                "InvitationWithdrawn",
                vec![p(*programme), ("invitation", dec(invitation.raw())), by(*b)],
            ),
            CreatorRecord::ProbeRecorded {
                programme,
                probe,
                outcome,
                at: t,
            } => tagged(
                "ProbeRecorded",
                vec![
                    p(*programme),
                    ("probe", s(probe.name())),
                    ("outcome", s(outcome.name())),
                    ("at", put_i64(t.micros())),
                ],
            ),
            CreatorRecord::WarningAcknowledged {
                programme,
                revision,
                warning,
                by: b,
            } => tagged(
                "WarningAcknowledged",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("warning", put_key(warning)),
                    by(*b),
                ],
            ),
            CreatorRecord::ActivationRequested {
                programme,
                revision,
                report,
                by: b,
            } => tagged(
                "ActivationRequested",
                vec![
                    p(*programme),
                    ("revision", put_revision(*revision)),
                    ("report", put_digest(report)),
                    by(*b),
                ],
            ),
            CreatorRecord::ActivationApproved(a) => tagged(
                "ActivationApproved",
                vec![
                    p(a.programme()),
                    ("revision", put_revision(a.revision())),
                    ("report", put_digest(a.report())),
                    ("decision", dec(a.decision().raw())),
                    ("approver", dec(a.approver().raw())),
                    ("builders", put_accounts(a.builders())),
                ],
            ),
            CreatorRecord::TemplateSaved {
                template,
                programme,
                spec,
                by: b,
            } => tagged(
                "TemplateSaved",
                vec![
                    ("template", dec(template.raw())),
                    p(*programme),
                    ("spec", hex32(spec.bytes())),
                    by(*b),
                ],
            ),
        }
    }
}

impl FromJson for CreatorRecord {
    fn from_json(v: &Value) -> R<CreatorRecord> {
        let kind = kind_of(v)?;
        let o = |names: &[&'static str]| exact(v, names);
        match kind {
            "DraftOpened" => {
                let o = o(&["kind", "programme", "profile", "by"])?;
                Ok(CreatorRecord::DraftOpened {
                    programme: at(o, "programme", programme)?,
                    profile: at(o, "profile", profile)?,
                    by: at(o, "by", account)?,
                })
            }
            "StartApplied" => {
                let o = o(&["kind", "programme", "revision", "start", "by"])?;
                Ok(CreatorRecord::StartApplied {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    start: at(o, "start", start)?,
                    by: at(o, "by", account)?,
                })
            }
            "FieldsSaved" => {
                let o = o(&["kind", "programme", "revision", "fields", "by"])?;
                Ok(CreatorRecord::FieldsSaved {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    fields: at(o, "fields", |x| take_list(x, saved))?,
                    by: at(o, "by", account)?,
                })
            }
            "NarrativeAccepted" => {
                let o = o(&["kind", "programme", "revision", "field", "by"])?;
                Ok(CreatorRecord::NarrativeAccepted {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    field: at(o, "field", field)?,
                    by: at(o, "by", account)?,
                })
            }
            "InvitationRecorded" => {
                let o = o(&[
                    "kind",
                    "programme",
                    "invitation",
                    "role",
                    "invitee",
                    "organisation",
                    "by",
                ])?;
                Ok(CreatorRecord::InvitationRecorded {
                    programme: at(o, "programme", programme)?,
                    invitation: InvitationId::from_raw(at(o, "invitation", take_dec)?),
                    role: at(o, "role", role)?,
                    invitee: at(o, "invitee", invitee)?,
                    organisation: at(o, "organisation", |x| {
                        take_option(x, |y| take_dec(y).map(OrganisationId::from_raw))
                    })?,
                    by: at(o, "by", account)?,
                })
            }
            "InvitationWithdrawn" => {
                let o = o(&["kind", "programme", "invitation", "by"])?;
                Ok(CreatorRecord::InvitationWithdrawn {
                    programme: at(o, "programme", programme)?,
                    invitation: InvitationId::from_raw(at(o, "invitation", take_dec)?),
                    by: at(o, "by", account)?,
                })
            }
            "ProbeRecorded" => {
                let o = o(&["kind", "programme", "probe", "outcome", "at"])?;
                Ok(CreatorRecord::ProbeRecorded {
                    programme: at(o, "programme", programme)?,
                    probe: at(o, "probe", probe_kind)?,
                    outcome: at(o, "outcome", probe_outcome)?,
                    at: Timestamp::from_micros(at(o, "at", take_i64)?),
                })
            }
            "WarningAcknowledged" => {
                let o = o(&["kind", "programme", "revision", "warning", "by"])?;
                Ok(CreatorRecord::WarningAcknowledged {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    warning: at(o, "warning", key)?,
                    by: at(o, "by", account)?,
                })
            }
            "ActivationRequested" => {
                let o = o(&["kind", "programme", "revision", "report", "by"])?;
                Ok(CreatorRecord::ActivationRequested {
                    programme: at(o, "programme", programme)?,
                    revision: at(o, "revision", revision)?,
                    report: at(o, "report", report_digest)?,
                    by: at(o, "by", account)?,
                })
            }
            "ActivationApproved" => {
                let o = o(&[
                    "kind",
                    "programme",
                    "revision",
                    "report",
                    "decision",
                    "approver",
                    "builders",
                ])?;
                Ok(CreatorRecord::ActivationApproved(
                    ActivationApproved::decoded(
                        at(o, "programme", programme)?,
                        at(o, "revision", revision)?,
                        at(o, "report", report_digest)?,
                        DecisionId::from_raw(at(o, "decision", take_dec)?),
                        at(o, "approver", account)?,
                        at(o, "builders", |x| take_set(x, account))?,
                    ),
                ))
            }
            "TemplateSaved" => {
                let o = o(&["kind", "template", "programme", "spec", "by"])?;
                Ok(CreatorRecord::TemplateSaved {
                    template: TemplateId::from_raw(at(o, "template", take_dec)?),
                    programme: at(o, "programme", programme)?,
                    spec: at(o, "spec", digest)?,
                    by: at(o, "by", account)?,
                })
            }
            _ => Err(FromJsonError::invalid("unknown kind")),
        }
    }
}

// ---------------------------------------------------------------------------
// The `validate_total` fuzz input
// ---------------------------------------------------------------------------

/// One draft history and the engine inputs, for the `validate_total` fuzz
/// target: creator records with their ledger sequence numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftInput {
    /// The records, each with its entry's sequence number.
    pub records: Vec<(Seq, CreatorRecord)>,
    /// The engine inputs. The theme is the default theme and no funder
    /// profile is passed.
    pub inputs: CreatorInputs,
}

/// Decodes a [`DraftInput`] from JSON of the shape
/// `{"records": [{"seq", "record"}], "inputs": {...}}`. Fuzzed
/// (`validate_total`).
pub fn decode_draft(bytes: &[u8]) -> Result<DraftInput, CreatorError> {
    draft_input(&parse(bytes)?).map_err(CreatorError::Decode)
}

fn draft_input(v: &Value) -> R<DraftInput> {
    let o = exact(v, &["records", "inputs"])?;
    let records = at(o, "records", |x| {
        take_list(x, |e| {
            let e = exact(e, &["seq", "record"])?;
            Ok((
                Seq::from_raw(at(e, "seq", take_u64)?),
                at(e, "record", CreatorRecord::from_json)?,
            ))
        })
    })?;
    let i = at(o, "inputs", |x| {
        exact(
            x,
            &[
                "unresolved_imports",
                "probes",
                "admitted",
                "refused",
                "verified",
                "unverified",
                "same_identity",
                "tenant_admins",
                "exclusion_classes_known",
                "proximity_lists_declared",
                "precheck",
                "score_tools",
            ],
        )
    })?;
    let mut probes = ProbeSet::absent();
    let probe_obj = at(i, "probes", expect_object)?;
    for (name, value) in probe_obj.iter() {
        let p =
            ProbeKind::from_name(name).ok_or_else(|| FromJsonError::invalid("unknown probe"))?;
        probes.set(p, probe_outcome(value).map_err(|e| e.at_field("probes"))?);
    }
    let ids = |name: &'static str| {
        at(i, name, |x| {
            take_set(x, |y| take_dec(y).map(InvitationId::from_raw))
        })
    };
    let accounts = |name: &'static str| at(i, name, |x| take_set(x, account));
    let mut outcomes = BTreeMap::new();
    for id in ids("admitted")? {
        outcomes.insert(id, PreviewOutcome::Admitted);
    }
    for id in ids("refused")? {
        outcomes.insert(id, PreviewOutcome::Refused(RuleRef::Sod01));
    }
    let mut is_verified = BTreeMap::new();
    for a in accounts("verified")? {
        is_verified.insert(a, true);
    }
    for a in accounts("unverified")? {
        is_verified.insert(a, false);
    }
    let same_identity = accounts("same_identity")?
        .into_iter()
        .map(|a| (a, true))
        .collect();
    let flag = |name: &'static str| {
        at(i, name, |x| {
            x.as_bool()
                .ok_or_else(|| FromJsonError::wrong_type("a boolean", x))
        })
    };
    let maybe = |name: &'static str| {
        at(i, name, |x| {
            take_option(x, |y| {
                y.as_bool()
                    .ok_or_else(|| FromJsonError::wrong_type("a boolean", y))
            })
        })
    };
    Ok(DraftInput {
        records,
        inputs: CreatorInputs {
            unresolved_imports: at(i, "unresolved_imports", take_u32)?,
            probes,
            sod: SodPreview { outcomes },
            vault: VaultChecks {
                is_verified,
                same_identity,
                exclusion_classes_known: maybe("exclusion_classes_known")?,
                proximity_lists_declared: maybe("proximity_lists_declared")?,
            },
            tenant_admins: accounts("tenant_admins")?,
            ports: PortPresence {
                precheck: flag("precheck")?,
                score_tools: flag("score_tools")?,
            },
            theme: Theme::m4_default(),
            profile: None,
        },
    })
}

/// Folds the records of `input` from genesis, skipping any the fold
/// refuses, and validates every draft over the genesis core state. Total:
/// it never panics on any input.
pub fn validate_draft(input: &DraftInput) -> Vec<ValidationReport> {
    let core = State::genesis();
    let mut creator = CreatorState::genesis();
    for (seq, record) in &input.records {
        let _ = creator.apply(*seq, record);
    }
    let mut programmes: Vec<ProgrammeId> = creator.drafts().map(|(p, _)| p).collect();
    programmes.push(ProgrammeId::from_raw(0));
    programmes
        .into_iter()
        .map(|p| {
            let facts = draft_facts(&core, &creator, p, None);
            validate_at(&core, &creator, p, &facts, &input.inputs)
        })
        .collect()
}
