//! The canonical codec of tenant commands and records (ADR-007, design
//! sections 4.2 and 9).
//!
//! - The stored and sent text is the RFC 8785 text of the encoding. The
//!   decoders refuse any other spelling, so each value has exactly one.
//! - Every object is decoded against its schema. A missing or unknown
//!   member is refused. An absent optional value is `null`.
//! - Ids, revisions, versions and microsecond values are canonical
//!   decimal strings. JSON numbers are refused everywhere.
//! - Sets are lists in strictly ascending order: accounts by id, names by
//!   their spelling.
//! - Free text never appears in a record. The data protection contact is
//!   a text reference. Names are [`Token`]s and domains are
//!   [`DomainName`]s. Only a command's P-69 value is an arbitrary short
//!   string, and only a valid one reaches a record.
//! - The brand tokens of `BrandingSet` hold the tenant name, a short text
//!   checked by `fstp_brand` (no markup, no control character), and
//!   `#rrggbb` colours (I-68).
//! - Decoding is structural and never runs a tenant rule. Errors carry a
//!   fixed message only (R-NF-02). No decode path panics (TH-26, H-05).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fstp_domain::id::{AccountId, ContentDigest, LlmConfigId, ProgrammeId, TextId, TextRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ParseLimits, Value, parse_with, to_canonical};
use fstp_ledger::SCHEMA_V1;

use crate::command::{TenantCommand, TenantRecord};
use crate::refusal::{DecodeError, TenantError};
use crate::types::{
    ActivationRequestId, ApprovalId, BankInterface, BrandingPackage, DomainName, GrantRef,
    GuideNoticeOverride, InferenceDefault, InvitationId, LoginMethod, McpSettings, Milestone,
    ModelRef, OnboardingStep, PaymentMode, RpMode, SettingValue, SignatoryRole, StepFailure,
    StepOutcome, StepValues, TenantParam, TenantRevision, Token, TokenDigest, VerifyMethod,
};

/// The record schema versions this build decodes. Version 1 is the only
/// published one.
pub const PUBLISHED_SCHEMAS: [u16; 1] = [SCHEMA_V1];

/// The schema version [`encode_record`] writes.
pub const CURRENT_SCHEMA: u16 = SCHEMA_V1;

/// The longest command or record text in bytes.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// The longest P-69 string a command may carry, in bytes.
pub const MAX_P69_WIRE_BYTES: usize = 256;

type R<T> = Result<T, DecodeError>;

const fn err(m: &'static str) -> DecodeError {
    DecodeError(m)
}

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_TEXT_BYTES)
        .with_max_depth(8)
        .with_max_string_bytes(1024)
        .with_max_container_len(256)
        .with_max_nodes(4096)
        .with_max_memory_bytes(1 << 20)
}

/// Parses `bytes` and checks that they are the canonical text of the
/// value they hold.
fn parse_canonical(bytes: &[u8]) -> R<Value> {
    let v = parse_with(bytes, &limits()).map_err(|e| err(e.kind().message()))?;
    let text = to_canonical(&v).map_err(|_| err("value has no canonical text"))?;
    if text.as_bytes() != bytes {
        return Err(err("text is not canonical (RFC 8785)"));
    }
    Ok(v)
}

fn canonical_bytes(v: &Value) -> Result<Vec<u8>, TenantError> {
    to_canonical(v)
        .map(String::into_bytes)
        .map_err(|_| TenantError::Encode)
}

/// Encodes a command to its canonical text.
pub fn encode_command(cmd: &TenantCommand) -> Result<Vec<u8>, TenantError> {
    canonical_bytes(&command_value(cmd))
}

/// Decodes a tenant command from its canonical text. Fuzzed
/// (`tenant_command_decode`).
pub fn decode_command(bytes: &[u8]) -> Result<TenantCommand, TenantError> {
    let v = parse_canonical(bytes)?;
    Ok(take_command(&v)?)
}

/// Encodes a record to its canonical text, the stored body under
/// [`CURRENT_SCHEMA`].
pub fn encode_record(rec: &TenantRecord) -> Result<Vec<u8>, TenantError> {
    canonical_bytes(&record_value(rec))
}

/// Decodes a stored tenant record of schema version 1. Fuzzed
/// (`tenant_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<TenantRecord, TenantError> {
    decode_record_at(CURRENT_SCHEMA, bytes)
}

/// Decodes a tenant record stored under schema version `schema`. A
/// version outside [`PUBLISHED_SCHEMAS`] is refused. Stored bytes are
/// never rewritten.
pub fn decode_record_at(schema: u16, bytes: &[u8]) -> Result<TenantRecord, TenantError> {
    if !PUBLISHED_SCHEMAS.contains(&schema) {
        return Err(TenantError::Decode(err(
            "unpublished record schema version",
        )));
    }
    let v = parse_canonical(bytes)?;
    Ok(take_record(&v)?)
}

// ---------------------------------------------------------------- writing

fn s(x: &str) -> Value {
    Value::String(x.to_owned())
}

fn dec(x: impl std::fmt::Display) -> Value {
    Value::String(x.to_string())
}

fn object(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

fn tagged(kind: &'static str, mut members: Vec<(&'static str, Value)>) -> Value {
    members.push(("kind", s(kind)));
    object(members)
}

fn accounts(set: &BTreeSet<AccountId>) -> Value {
    Value::Array(set.iter().map(|a| dec(a.raw())).collect::<Array>())
}

/// A set of named values, as a list ascending by spelling.
fn names<T: Copy>(set: impl IntoIterator<Item = T>, name: fn(T) -> &'static str) -> Value {
    let mut v: Vec<&'static str> = set.into_iter().map(name).collect();
    v.sort_unstable();
    Value::Array(v.into_iter().map(s).collect::<Array>())
}

fn tokens(list: &[Token]) -> Value {
    Value::Array(list.iter().map(|t| s(t.as_str())).collect::<Array>())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn text_ref(t: &TextRef) -> Value {
    object(vec![
        ("digest", s(&hex(&t.digest().bytes()))),
        ("id", dec(t.id().raw())),
    ])
}

fn guide_notice(n: &Option<GuideNoticeOverride>) -> Value {
    n.as_ref().map_or(Value::Null, |n| {
        object(vec![
            ("privacy_statement_url", s(&n.privacy_statement_url)),
            ("summary", text_ref(&n.summary)),
        ])
    })
}

fn token_digest(d: TokenDigest) -> Value {
    s(&hex(&d.bytes()))
}

fn grant(g: &GrantRef) -> Value {
    object(vec![
        ("grantee", dec(g.grantee.raw())),
        ("programme", dec(g.programme.raw())),
        ("role", s(g.role.spec_name())),
    ])
}

fn values(v: &StepValues) -> Value {
    match v {
        StepValues::Organisation {
            data_protection_contact,
            signatories,
        } => object(vec![
            ("data_protection_contact", text_ref(data_protection_contact)),
            ("signatories", accounts(signatories)),
        ]),
        StepValues::Agreements {
            saas_terms,
            dpa,
            sub_processors,
        } => object(vec![
            ("dpa", dec(dpa)),
            ("saas_terms", dec(saas_terms)),
            ("sub_processors", dec(sub_processors)),
        ]),
        StepValues::Branding { package } => object(vec![("package", s(package.name()))]),
        StepValues::DomainsAndEmail { sending_domain } => {
            object(vec![("sending_domain", s(sending_domain.as_str()))])
        }
        StepValues::Identity { p18, p45 } => object(vec![
            ("p18", names(p18.iter().copied(), VerifyMethod::name)),
            ("p45", s(p45.name())),
        ]),
        StepValues::Inference(d) => object(vec![
            ("fallbacks", tokens(&d.fallbacks)),
            ("primary", s(d.primary.as_str())),
            ("provider", s(d.provider.as_str())),
        ]),
        StepValues::Payments { bank_interface } => {
            object(vec![("bank_interface", s(bank_interface.name()))])
        }
        StepValues::Channels {
            matrix_homeserver,
            whatsapp,
        } => object(vec![
            (
                "matrix_homeserver",
                matrix_homeserver
                    .as_ref()
                    .map_or(Value::Null, |d| s(d.as_str())),
            ),
            ("whatsapp", Value::Bool(*whatsapp)),
        ]),
        StepValues::Administrators { admins } => object(vec![("admins", accounts(admins))]),
    }
}

fn setting(v: &SettingValue) -> Value {
    match v {
        SettingValue::P20(m) => s(m.name()),
        SettingValue::P69(id) => s(id),
        SettingValue::P70(m) => names(m.iter().copied(), LoginMethod::name),
        SettingValue::P71 { us } => dec(us),
        SettingValue::P72 {
            idle_us,
            absolute_us,
        } => object(vec![
            ("absolute_us", dec(absolute_us)),
            ("idle_us", dec(idle_us)),
        ]),
        SettingValue::P74(m) => object(vec![
            ("enabled", Value::Bool(m.enabled)),
            ("public_tools", Value::Bool(m.public_tools)),
            (
                "roles",
                m.roles
                    .as_ref()
                    .map_or(Value::Null, |r| names(r.iter().copied(), Role::spec_name)),
            ),
        ]),
    }
}

fn param_name(p: TenantParam) -> &'static str {
    p.param_id().spec_id()
}

fn outcome_name(o: StepOutcome) -> &'static str {
    match o {
        StepOutcome::Validated => "validated",
        StepOutcome::Failed(StepFailure::InvalidValues) => "invalid_values",
        StepOutcome::Failed(StepFailure::ProbeFailed) => "probe_failed",
        StepOutcome::Failed(StepFailure::ProberAbsent) => "prober_absent",
        StepOutcome::Failed(StepFailure::TooFewAdmins) => "too_few_admins",
        StepOutcome::Failed(StepFailure::NoFinancialSignatory) => "no_financial_signatory",
        StepOutcome::Failed(StepFailure::NoLegalSignatory) => "no_legal_signatory",
        StepOutcome::Failed(StepFailure::AgreementsNotRecorded) => "agreements_not_recorded",
        StepOutcome::Failed(StepFailure::PaymentModeUnset) => "payment_mode_unset",
        StepOutcome::Failed(StepFailure::Unavailable(m)) => match m {
            Milestone::M5 => "unavailable_m5",
            Milestone::M6 => "unavailable_m6",
            Milestone::M8 => "unavailable_m8",
            Milestone::M9 => "unavailable_m9",
        },
    }
}

const OUTCOMES: [StepOutcome; 13] = [
    StepOutcome::Validated,
    StepOutcome::Failed(StepFailure::InvalidValues),
    StepOutcome::Failed(StepFailure::ProbeFailed),
    StepOutcome::Failed(StepFailure::ProberAbsent),
    StepOutcome::Failed(StepFailure::TooFewAdmins),
    StepOutcome::Failed(StepFailure::NoFinancialSignatory),
    StepOutcome::Failed(StepFailure::NoLegalSignatory),
    StepOutcome::Failed(StepFailure::AgreementsNotRecorded),
    StepOutcome::Failed(StepFailure::PaymentModeUnset),
    StepOutcome::Failed(StepFailure::Unavailable(Milestone::M5)),
    StepOutcome::Failed(StepFailure::Unavailable(Milestone::M6)),
    StepOutcome::Failed(StepFailure::Unavailable(Milestone::M8)),
    StepOutcome::Failed(StepFailure::Unavailable(Milestone::M9)),
];

fn command_value(cmd: &TenantCommand) -> Value {
    match cmd {
        TenantCommand::SaveStep { values: v, base } => tagged(
            "SaveStep",
            vec![
                ("base", dec(base.raw())),
                ("step", s(v.step().name())),
                ("values", values(v)),
            ],
        ),
        TenantCommand::InviteAdmin {
            invitation,
            invitee,
            token_digest: d,
        } => tagged(
            "InviteAdmin",
            vec![
                ("invitation", dec(invitation.raw())),
                ("invitee", dec(invitee.raw())),
                ("token_digest", token_digest(*d)),
            ],
        ),
        TenantCommand::AcceptAdminInvitation {
            invitation,
            token_digest: d,
        } => tagged(
            "AcceptAdminInvitation",
            vec![
                ("invitation", dec(invitation.raw())),
                ("token_digest", token_digest(*d)),
            ],
        ),
        TenantCommand::ApproveSelfGrant { approval, grant: g } => tagged(
            "ApproveSelfGrant",
            vec![("approval", dec(approval.raw())), ("grant", grant(g))],
        ),
        TenantCommand::UseSelfGrantApproval { approval, grant: g } => tagged(
            "UseSelfGrantApproval",
            vec![("approval", dec(approval.raw())), ("grant", grant(g))],
        ),
        TenantCommand::SetSetting { value } => tagged(
            "SetSetting",
            vec![
                ("param", s(param_name(value.param()))),
                ("value", setting(value)),
            ],
        ),
        TenantCommand::SetGuideNotice { notice } => {
            tagged("SetGuideNotice", vec![("notice", guide_notice(notice))])
        }
        TenantCommand::RecordInferenceConfig {
            config,
            primary,
            fallbacks,
        } => tagged(
            "RecordInferenceConfig",
            vec![
                ("config", dec(config.raw())),
                ("fallbacks", tokens(fallbacks)),
                ("primary", s(primary.as_str())),
            ],
        ),
        TenantCommand::Complete => tagged("Complete", Vec::new()),
        TenantCommand::GrantSignatory { role, account } => tagged(
            "GrantSignatory",
            vec![("account", dec(account.raw())), ("role", s(role.name()))],
        ),
        TenantCommand::EndSignatory { role, account } => tagged(
            "EndSignatory",
            vec![("account", dec(account.raw())), ("role", s(role.name()))],
        ),
        TenantCommand::RequestActivation { request } => {
            tagged("RequestActivation", vec![("request", dec(request.raw()))])
        }
        TenantCommand::ApproveActivation { request } => {
            tagged("ApproveActivation", vec![("request", dec(request.raw()))])
        }
        TenantCommand::SetBranding { tokens, digest } => tagged(
            "SetBranding",
            vec![
                ("digest", s(&hex(&digest.bytes()))),
                ("tokens", fstp_brand::to_value(tokens)),
            ],
        ),
    }
}

fn record_value(rec: &TenantRecord) -> Value {
    match rec {
        TenantRecord::StepSaved {
            values: v,
            by,
            outcome,
        } => tagged(
            "StepSaved",
            vec![
                ("by", dec(by.raw())),
                ("outcome", s(outcome_name(*outcome))),
                ("step", s(v.step().name())),
                ("values", values(v)),
            ],
        ),
        TenantRecord::StepValidated { step, by } => tagged(
            "StepValidated",
            vec![("by", dec(by.raw())), ("step", s(step.name()))],
        ),
        TenantRecord::AdminInvited {
            invitation,
            invitee,
            token_digest: d,
            by,
        } => tagged(
            "AdminInvited",
            vec![
                ("by", dec(by.raw())),
                ("invitation", dec(invitation.raw())),
                ("invitee", dec(invitee.raw())),
                ("token_digest", token_digest(*d)),
            ],
        ),
        TenantRecord::AdminAdded {
            account,
            invitation,
        } => tagged(
            "AdminAdded",
            vec![
                ("account", dec(account.raw())),
                ("invitation", dec(invitation.raw())),
            ],
        ),
        TenantRecord::SelfGrantApproved {
            approval,
            grant: g,
            by,
            at,
        } => tagged(
            "SelfGrantApproved",
            vec![
                ("approval", dec(approval.raw())),
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
                ("grant", grant(g)),
            ],
        ),
        TenantRecord::SelfGrantApprovalUsed { approval, by, at } => tagged(
            "SelfGrantApprovalUsed",
            vec![
                ("approval", dec(approval.raw())),
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
            ],
        ),
        TenantRecord::SettingChanged { value, by } => tagged(
            "SettingChanged",
            vec![
                ("by", dec(by.raw())),
                ("param", s(param_name(value.param()))),
                ("value", setting(value)),
            ],
        ),
        TenantRecord::GuideNoticeSet { notice, by } => tagged(
            "GuideNoticeSet",
            vec![("by", dec(by.raw())), ("notice", guide_notice(notice))],
        ),
        TenantRecord::InferenceConfigRecorded {
            config,
            primary,
            fallbacks,
            by,
        } => tagged(
            "InferenceConfigRecorded",
            vec![
                ("by", dec(by.raw())),
                ("config", dec(config.raw())),
                ("fallbacks", tokens(fallbacks)),
                ("primary", s(primary.as_str())),
            ],
        ),
        TenantRecord::OnboardingCompleted { by } => {
            tagged("OnboardingCompleted", vec![("by", dec(by.raw()))])
        }
        TenantRecord::SignatoryGranted {
            role,
            account,
            by,
            at,
        } => tagged(
            "SignatoryGranted",
            vec![
                ("account", dec(account.raw())),
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
                ("role", s(role.name())),
            ],
        ),
        TenantRecord::SignatoryEnded {
            role,
            account,
            by,
            at,
        } => tagged(
            "SignatoryEnded",
            vec![
                ("account", dec(account.raw())),
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
                ("role", s(role.name())),
            ],
        ),
        TenantRecord::ActivationRequested { request, by, at } => tagged(
            "ActivationRequested",
            vec![
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
                ("request", dec(request.raw())),
            ],
        ),
        TenantRecord::ActivationApproved { request, by, at } => tagged(
            "ActivationApproved",
            vec![
                ("at", dec(at.micros())),
                ("by", dec(by.raw())),
                ("request", dec(request.raw())),
            ],
        ),
        TenantRecord::BrandingSet { tokens, digest, by } => tagged(
            "BrandingSet",
            vec![
                ("by", dec(by.raw())),
                ("digest", s(&hex(&digest.bytes()))),
                ("tokens", fstp_brand::to_value(tokens)),
            ],
        ),
    }
}

// ---------------------------------------------------------------- reading

/// The members of an object that must hold exactly `members`.
struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    fn of(v: &'a Value, members: &[&str]) -> R<Fields<'a>> {
        let o = v.as_object().ok_or(err("expected an object"))?;
        if o.len() != members.len() || !members.iter().all(|m| o.contains_key(m)) {
            return Err(err("object members do not match the schema"));
        }
        Ok(Fields(o))
    }

    fn get(&self, k: &str) -> R<&'a Value> {
        self.0.get(k).ok_or(err("missing member"))
    }
}

fn tag_of(v: &Value) -> R<&str> {
    v.as_object()
        .ok_or(err("expected an object"))?
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(err("missing kind"))
}

fn str_of(v: &Value) -> R<&str> {
    v.as_str().ok_or(err("expected a string"))
}

fn bool_of(v: &Value) -> R<bool> {
    v.as_bool().ok_or(err("expected a boolean"))
}

fn array_of(v: &Value) -> R<&Array> {
    v.as_array().ok_or(err("expected an array"))
}

/// The digits of a canonical unsigned decimal: no sign, no leading zero.
fn digits(s: &str) -> R<&str> {
    let canonical =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if canonical {
        Ok(s)
    } else {
        Err(err("not a canonical decimal string"))
    }
}

fn take_u128(v: &Value) -> R<u128> {
    digits(str_of(v)?)?
        .parse::<u128>()
        .map_err(|_| err("decimal out of range"))
}

fn take_u64(v: &Value) -> R<u64> {
    digits(str_of(v)?)?
        .parse::<u64>()
        .map_err(|_| err("decimal out of range"))
}

fn take_u32(v: &Value) -> R<u32> {
    digits(str_of(v)?)?
        .parse::<u32>()
        .map_err(|_| err("decimal out of range"))
}

fn take_i64(v: &Value) -> R<i64> {
    let s = str_of(v)?;
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    if neg && body == "0" {
        return Err(err("not a canonical decimal string"));
    }
    digits(body)?;
    s.parse::<i64>().map_err(|_| err("decimal out of range"))
}

/// Brand tokens, by the strict rules of `fstp_brand::from_value` (I-68).
fn take_brand(v: &Value) -> R<fstp_brand::BrandTokens> {
    fstp_brand::from_value(v).map_err(|e| err(e.0))
}

fn take_account(v: &Value) -> R<AccountId> {
    take_u128(v).map(AccountId::from_raw)
}

fn take_accounts(v: &Value) -> R<BTreeSet<AccountId>> {
    let mut out = BTreeSet::new();
    let mut last: Option<u128> = None;
    for item in array_of(v)? {
        let n = take_u128(item)?;
        if last.is_some_and(|l| l >= n) {
            return Err(err("set is not strictly ascending"));
        }
        last = Some(n);
        out.insert(AccountId::from_raw(n));
    }
    Ok(out)
}

fn named<T: Copy>(s: &str, all: &[T], name: fn(T) -> &'static str) -> R<T> {
    all.iter()
        .copied()
        .find(|t| name(*t) == s)
        .ok_or(err("unknown name"))
}

fn take_named<T: Copy>(v: &Value, all: &[T], name: fn(T) -> &'static str) -> R<T> {
    named(str_of(v)?, all, name)
}

fn take_name_set<T: Copy + Ord>(
    v: &Value,
    all: &[T],
    name: fn(T) -> &'static str,
) -> R<BTreeSet<T>> {
    let mut out = BTreeSet::new();
    let mut last: Option<&str> = None;
    for item in array_of(v)? {
        let s = str_of(item)?;
        if last.is_some_and(|l| l >= s) {
            return Err(err("set is not strictly ascending"));
        }
        last = Some(s);
        out.insert(named(s, all, name)?);
    }
    Ok(out)
}

fn take_token(v: &Value) -> R<Token> {
    Token::new(str_of(v)?).ok_or(err("not a token"))
}

fn take_tokens(v: &Value) -> R<Vec<ModelRef>> {
    array_of(v)?.iter().map(take_token).collect()
}

fn take_domain(v: &Value) -> R<DomainName> {
    DomainName::new(str_of(v)?).ok_or(err("not a domain name"))
}

fn nibble(c: u8) -> R<u8> {
    let d = char::from(c)
        .to_digit(16)
        .filter(|_| !c.is_ascii_uppercase())
        .ok_or(err("not lowercase hexadecimal"))?;
    u8::try_from(d).map_err(|_| err("not lowercase hexadecimal"))
}

fn take_digest(v: &Value) -> R<[u8; 32]> {
    let s = str_of(v)?.as_bytes();
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return Err(err("digest is not 64 hexadecimal digits"));
    }
    for (slot, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        let [h, l] = pair else {
            return Err(err("digest is not 64 hexadecimal digits"));
        };
        let hi = nibble(*h)?;
        let lo = nibble(*l)?;
        *slot = hi
            .checked_mul(16)
            .and_then(|x| x.checked_add(lo))
            .ok_or(err("not lowercase hexadecimal"))?;
    }
    Ok(out)
}

fn take_token_digest(v: &Value) -> R<TokenDigest> {
    take_digest(v).map(TokenDigest::from_bytes)
}

fn take_instant(v: &Value) -> R<Timestamp> {
    take_i64(v).map(Timestamp::from_micros)
}

fn take_invitation(v: &Value) -> R<InvitationId> {
    take_u128(v).map(InvitationId::from_raw)
}

fn take_approval(v: &Value) -> R<ApprovalId> {
    take_u128(v).map(ApprovalId::from_raw)
}

fn take_request(v: &Value) -> R<ActivationRequestId> {
    take_u128(v).map(ActivationRequestId::from_raw)
}

fn take_signatory_role(v: &Value) -> R<SignatoryRole> {
    take_named(v, &SignatoryRole::ALL, SignatoryRole::name)
}

fn take_text_ref(v: &Value) -> R<TextRef> {
    let f = Fields::of(v, &["digest", "id"])?;
    let digest = ContentDigest::from_bytes(take_digest(f.get("digest")?)?);
    let id = TextId::from_raw(take_u128(f.get("id")?)?);
    Ok(TextRef::new(id, digest))
}

/// The Guide notice override, or `None` for `null`. The address must be
/// an https address (`crate::rules::https_address`), as a domain name
/// must be a host name.
fn take_guide_notice(v: &Value) -> R<Option<GuideNoticeOverride>> {
    if v.is_null() {
        return Ok(None);
    }
    let f = Fields::of(v, &["privacy_statement_url", "summary"])?;
    let url = str_of(f.get("privacy_statement_url")?)?;
    if !crate::rules::https_address(url) {
        return Err(err("not an https address"));
    }
    Ok(Some(GuideNoticeOverride {
        summary: take_text_ref(f.get("summary")?)?,
        privacy_statement_url: url.to_owned(),
    }))
}

fn take_grant(v: &Value) -> R<GrantRef> {
    let f = Fields::of(v, &["grantee", "programme", "role"])?;
    Ok(GrantRef {
        grantee: take_account(f.get("grantee")?)?,
        programme: ProgrammeId::from_raw(take_u128(f.get("programme")?)?),
        role: take_named(f.get("role")?, &Role::ALL, Role::spec_name)?,
    })
}

fn take_values(step: OnboardingStep, v: &Value) -> R<StepValues> {
    Ok(match step {
        OnboardingStep::Organisation => {
            let f = Fields::of(v, &["data_protection_contact", "signatories"])?;
            StepValues::Organisation {
                data_protection_contact: take_text_ref(f.get("data_protection_contact")?)?,
                signatories: take_accounts(f.get("signatories")?)?,
            }
        }
        OnboardingStep::Agreements => {
            let f = Fields::of(v, &["dpa", "saas_terms", "sub_processors"])?;
            StepValues::Agreements {
                saas_terms: take_u32(f.get("saas_terms")?)?,
                dpa: take_u32(f.get("dpa")?)?,
                sub_processors: take_u32(f.get("sub_processors")?)?,
            }
        }
        OnboardingStep::Branding => {
            let f = Fields::of(v, &["package"])?;
            StepValues::Branding {
                package: take_named(
                    f.get("package")?,
                    &BrandingPackage::ALL,
                    BrandingPackage::name,
                )?,
            }
        }
        OnboardingStep::DomainsAndEmail => {
            let f = Fields::of(v, &["sending_domain"])?;
            StepValues::DomainsAndEmail {
                sending_domain: take_domain(f.get("sending_domain")?)?,
            }
        }
        OnboardingStep::Identity => {
            let f = Fields::of(v, &["p18", "p45"])?;
            StepValues::Identity {
                p18: take_name_set(f.get("p18")?, &VerifyMethod::ALL, VerifyMethod::name)?,
                p45: take_named(f.get("p45")?, &RpMode::ALL, RpMode::name)?,
            }
        }
        OnboardingStep::Inference => {
            let f = Fields::of(v, &["fallbacks", "primary", "provider"])?;
            StepValues::Inference(InferenceDefault {
                provider: take_token(f.get("provider")?)?,
                primary: take_token(f.get("primary")?)?,
                fallbacks: take_tokens(f.get("fallbacks")?)?,
            })
        }
        OnboardingStep::Payments => {
            let f = Fields::of(v, &["bank_interface"])?;
            StepValues::Payments {
                bank_interface: take_named(
                    f.get("bank_interface")?,
                    &BankInterface::ALL,
                    BankInterface::name,
                )?,
            }
        }
        OnboardingStep::Channels => {
            let f = Fields::of(v, &["matrix_homeserver", "whatsapp"])?;
            let hs = f.get("matrix_homeserver")?;
            StepValues::Channels {
                matrix_homeserver: if hs.is_null() {
                    None
                } else {
                    Some(take_domain(hs)?)
                },
                whatsapp: bool_of(f.get("whatsapp")?)?,
            }
        }
        OnboardingStep::Administrators => {
            let f = Fields::of(v, &["admins"])?;
            StepValues::Administrators {
                admins: take_accounts(f.get("admins")?)?,
            }
        }
    })
}

fn take_step(v: &Value) -> R<OnboardingStep> {
    OnboardingStep::from_name(str_of(v)?).ok_or(err("unknown step"))
}

fn take_param(v: &Value) -> R<TenantParam> {
    let s = str_of(v)?;
    TenantParam::ALL
        .into_iter()
        .find(|p| param_name(*p) == s)
        .ok_or(err("not a settable parameter"))
}

fn take_setting(param: TenantParam, v: &Value) -> R<SettingValue> {
    Ok(match param {
        TenantParam::P20 => SettingValue::P20(take_named(v, &PaymentMode::ALL, PaymentMode::name)?),
        TenantParam::P69 => {
            let s = str_of(v)?;
            if s.len() > MAX_P69_WIRE_BYTES {
                return Err(err("P-69 value too long"));
            }
            SettingValue::P69(s.to_owned())
        }
        TenantParam::P70 => {
            SettingValue::P70(take_name_set(v, &LoginMethod::ALL, LoginMethod::name)?)
        }
        TenantParam::P71 => SettingValue::P71 { us: take_i64(v)? },
        TenantParam::P72 => {
            let f = Fields::of(v, &["absolute_us", "idle_us"])?;
            SettingValue::P72 {
                idle_us: take_i64(f.get("idle_us")?)?,
                absolute_us: take_i64(f.get("absolute_us")?)?,
            }
        }
        TenantParam::P74 => {
            let f = Fields::of(v, &["enabled", "public_tools", "roles"])?;
            let roles = f.get("roles")?;
            SettingValue::P74(McpSettings {
                enabled: bool_of(f.get("enabled")?)?,
                public_tools: bool_of(f.get("public_tools")?)?,
                roles: if roles.is_null() {
                    None
                } else {
                    Some(take_name_set(roles, &Role::ALL, Role::spec_name)?)
                },
            })
        }
    })
}

fn take_outcome(v: &Value) -> R<StepOutcome> {
    named(str_of(v)?, &OUTCOMES, outcome_name)
}

fn take_command(v: &Value) -> R<TenantCommand> {
    Ok(match tag_of(v)? {
        "SaveStep" => {
            let f = Fields::of(v, &["base", "kind", "step", "values"])?;
            let step = take_step(f.get("step")?)?;
            TenantCommand::SaveStep {
                values: take_values(step, f.get("values")?)?,
                base: TenantRevision::from_raw(take_u64(f.get("base")?)?),
            }
        }
        "InviteAdmin" => {
            let f = Fields::of(v, &["invitation", "invitee", "kind", "token_digest"])?;
            TenantCommand::InviteAdmin {
                invitation: take_invitation(f.get("invitation")?)?,
                invitee: take_account(f.get("invitee")?)?,
                token_digest: take_token_digest(f.get("token_digest")?)?,
            }
        }
        "AcceptAdminInvitation" => {
            let f = Fields::of(v, &["invitation", "kind", "token_digest"])?;
            TenantCommand::AcceptAdminInvitation {
                invitation: take_invitation(f.get("invitation")?)?,
                token_digest: take_token_digest(f.get("token_digest")?)?,
            }
        }
        "ApproveSelfGrant" => {
            let f = Fields::of(v, &["approval", "grant", "kind"])?;
            TenantCommand::ApproveSelfGrant {
                approval: take_approval(f.get("approval")?)?,
                grant: take_grant(f.get("grant")?)?,
            }
        }
        "UseSelfGrantApproval" => {
            let f = Fields::of(v, &["approval", "grant", "kind"])?;
            TenantCommand::UseSelfGrantApproval {
                approval: take_approval(f.get("approval")?)?,
                grant: take_grant(f.get("grant")?)?,
            }
        }
        "SetSetting" => {
            let f = Fields::of(v, &["kind", "param", "value"])?;
            let param = take_param(f.get("param")?)?;
            TenantCommand::SetSetting {
                value: take_setting(param, f.get("value")?)?,
            }
        }
        "SetGuideNotice" => {
            let f = Fields::of(v, &["kind", "notice"])?;
            TenantCommand::SetGuideNotice {
                notice: take_guide_notice(f.get("notice")?)?,
            }
        }
        "RecordInferenceConfig" => {
            let f = Fields::of(v, &["config", "fallbacks", "kind", "primary"])?;
            TenantCommand::RecordInferenceConfig {
                config: LlmConfigId::from_raw(take_u128(f.get("config")?)?),
                primary: take_token(f.get("primary")?)?,
                fallbacks: take_tokens(f.get("fallbacks")?)?,
            }
        }
        "Complete" => {
            Fields::of(v, &["kind"])?;
            TenantCommand::Complete
        }
        "GrantSignatory" => {
            let f = Fields::of(v, &["account", "kind", "role"])?;
            TenantCommand::GrantSignatory {
                role: take_signatory_role(f.get("role")?)?,
                account: take_account(f.get("account")?)?,
            }
        }
        "EndSignatory" => {
            let f = Fields::of(v, &["account", "kind", "role"])?;
            TenantCommand::EndSignatory {
                role: take_signatory_role(f.get("role")?)?,
                account: take_account(f.get("account")?)?,
            }
        }
        "RequestActivation" => {
            let f = Fields::of(v, &["kind", "request"])?;
            TenantCommand::RequestActivation {
                request: take_request(f.get("request")?)?,
            }
        }
        "ApproveActivation" => {
            let f = Fields::of(v, &["kind", "request"])?;
            TenantCommand::ApproveActivation {
                request: take_request(f.get("request")?)?,
            }
        }
        "SetBranding" => {
            let f = Fields::of(v, &["digest", "kind", "tokens"])?;
            TenantCommand::SetBranding {
                tokens: take_brand(f.get("tokens")?)?,
                digest: ContentDigest::from_bytes(take_digest(f.get("digest")?)?),
            }
        }
        _ => return Err(err("unknown command kind")),
    })
}

fn take_record(v: &Value) -> R<TenantRecord> {
    Ok(match tag_of(v)? {
        "StepSaved" => {
            let f = Fields::of(v, &["by", "kind", "outcome", "step", "values"])?;
            let step = take_step(f.get("step")?)?;
            TenantRecord::StepSaved {
                values: take_values(step, f.get("values")?)?,
                by: take_account(f.get("by")?)?,
                outcome: take_outcome(f.get("outcome")?)?,
            }
        }
        "StepValidated" => {
            let f = Fields::of(v, &["by", "kind", "step"])?;
            TenantRecord::StepValidated {
                step: take_step(f.get("step")?)?,
                by: take_account(f.get("by")?)?,
            }
        }
        "AdminInvited" => {
            let f = Fields::of(v, &["by", "invitation", "invitee", "kind", "token_digest"])?;
            TenantRecord::AdminInvited {
                invitation: take_invitation(f.get("invitation")?)?,
                invitee: take_account(f.get("invitee")?)?,
                token_digest: take_token_digest(f.get("token_digest")?)?,
                by: take_account(f.get("by")?)?,
            }
        }
        "AdminAdded" => {
            let f = Fields::of(v, &["account", "invitation", "kind"])?;
            TenantRecord::AdminAdded {
                account: take_account(f.get("account")?)?,
                invitation: take_invitation(f.get("invitation")?)?,
            }
        }
        "SelfGrantApproved" => {
            let f = Fields::of(v, &["approval", "at", "by", "grant", "kind"])?;
            TenantRecord::SelfGrantApproved {
                approval: take_approval(f.get("approval")?)?,
                grant: take_grant(f.get("grant")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "SelfGrantApprovalUsed" => {
            let f = Fields::of(v, &["approval", "at", "by", "kind"])?;
            TenantRecord::SelfGrantApprovalUsed {
                approval: take_approval(f.get("approval")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "SettingChanged" => {
            let f = Fields::of(v, &["by", "kind", "param", "value"])?;
            let param = take_param(f.get("param")?)?;
            TenantRecord::SettingChanged {
                value: take_setting(param, f.get("value")?)?,
                by: take_account(f.get("by")?)?,
            }
        }
        "GuideNoticeSet" => {
            let f = Fields::of(v, &["by", "kind", "notice"])?;
            TenantRecord::GuideNoticeSet {
                notice: take_guide_notice(f.get("notice")?)?,
                by: take_account(f.get("by")?)?,
            }
        }
        "InferenceConfigRecorded" => {
            let f = Fields::of(v, &["by", "config", "fallbacks", "kind", "primary"])?;
            TenantRecord::InferenceConfigRecorded {
                config: LlmConfigId::from_raw(take_u128(f.get("config")?)?),
                primary: take_token(f.get("primary")?)?,
                fallbacks: take_tokens(f.get("fallbacks")?)?,
                by: take_account(f.get("by")?)?,
            }
        }
        "OnboardingCompleted" => {
            let f = Fields::of(v, &["by", "kind"])?;
            TenantRecord::OnboardingCompleted {
                by: take_account(f.get("by")?)?,
            }
        }
        "SignatoryGranted" => {
            let f = Fields::of(v, &["account", "at", "by", "kind", "role"])?;
            TenantRecord::SignatoryGranted {
                role: take_signatory_role(f.get("role")?)?,
                account: take_account(f.get("account")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "SignatoryEnded" => {
            let f = Fields::of(v, &["account", "at", "by", "kind", "role"])?;
            TenantRecord::SignatoryEnded {
                role: take_signatory_role(f.get("role")?)?,
                account: take_account(f.get("account")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "ActivationRequested" => {
            let f = Fields::of(v, &["at", "by", "kind", "request"])?;
            TenantRecord::ActivationRequested {
                request: take_request(f.get("request")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "ActivationApproved" => {
            let f = Fields::of(v, &["at", "by", "kind", "request"])?;
            TenantRecord::ActivationApproved {
                request: take_request(f.get("request")?)?,
                by: take_account(f.get("by")?)?,
                at: take_instant(f.get("at")?)?,
            }
        }
        "BrandingSet" => {
            let f = Fields::of(v, &["by", "digest", "kind", "tokens"])?;
            TenantRecord::BrandingSet {
                tokens: take_brand(f.get("tokens")?)?,
                digest: ContentDigest::from_bytes(take_digest(f.get("digest")?)?),
                by: take_account(f.get("by")?)?,
            }
        }
        _ => return Err(err("unknown record kind")),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code asserts on known-good values"
    )]

    use super::{decode_command, decode_record, decode_record_at, encode_command, encode_record};
    use crate::refusal::TenantError;

    macro_rules! seeds {
        ($dir:literal: $($name:literal),* $(,)?) => {
            [$(($name, &include_bytes!(concat!("../fuzz/seeds/", $dir, "/", $name))[..])),*]
        };
    }

    /// ADR-007, TH-26: every command seed of the fuzz project decodes, and
    /// encoding it again gives the same bytes.
    #[test]
    fn adr007_command_seeds_round_trip() {
        let seeds = seeds!("tenant_command_decode": "save_identity", "save_organisation",
            "save_payments", "invite_admin", "accept_admin_invitation", "approve_self_grant",
            "use_self_grant_approval", "set_p74", "set_p72", "record_inference", "complete",
            "grant_signatory", "end_signatory", "request_activation", "approve_activation", "set_branding");
        for (name, bytes) in seeds {
            let c = decode_command(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(encode_command(&c).as_deref(), Ok(bytes), "{name}");
        }
    }

    /// ADR-007, TH-26: every record seed of the fuzz project decodes, and
    /// encoding it again gives the same bytes.
    #[test]
    fn adr007_record_seeds_round_trip() {
        let seeds = seeds!("tenant_record_decode": "step_saved_channels",
            "step_saved_payments", "step_saved_agreements", "step_validated", "admin_invited",
            "admin_added", "self_grant_approved", "self_grant_approval_used", "setting_p70",
            "inference_recorded", "completed", "signatory_granted", "signatory_ended",
            "activation_requested", "activation_approved", "branding_set");
        for (name, bytes) in seeds {
            let r = decode_record(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(encode_record(&r).as_deref(), Ok(bytes), "{name}");
        }
    }

    /// ADR-007: each value has one spelling. Leading zeros, `-0`, a JSON
    /// number, uppercase hexadecimal, an unordered set, a duplicate set
    /// member, an extra member and whitespace are all refused.
    #[test]
    fn adr007_other_spellings_are_refused() {
        let d = "5a".repeat(32);
        let invite = |invitation: &str, tail: &str| {
            format!(
                r#"{{"invitation":{invitation},"invitee":"2","kind":"InviteAdmin","token_digest":"{d}"{tail}}}"#
            )
        };
        assert!(decode_command(invite(r#""7""#, "").as_bytes()).is_ok());
        let bad = [
            invite(r#""07""#, ""),
            invite("7", ""),
            invite(r#""-7""#, ""),
            invite(r#""7""#, r#","x":null"#),
            format!(r#"{{"invitation": "7","invitee":"2","kind":"InviteAdmin","token_digest":"{d}"}}"#),
            format!(r#"{{"invitee":"2","invitation":"7","kind":"InviteAdmin","token_digest":"{d}"}}"#),
            r#"{"invitation":"7","invitee":"2","kind":"InviteAdmin"}"#.to_string(),
            format!(
                r#"{{"invitation":"7","invitee":"2","kind":"InviteAdmin","token_digest":"{}"}}"#,
                d.to_uppercase()
            ),
            format!(r#"{{"invitation":"7","kind":"AcceptAdminInvitation","token_digest":"{}"}}"#, &d[..62]),
            r#"{"kind":"SetSetting","param":"P-71","value":"-0"}"#.to_string(),
            r#"{"kind":"SetSetting","param":"P-71","value":"+5"}"#.to_string(),
            r#"{"kind":"SetSetting","param":"P-70","value":["passkey","magic_link"]}"#.to_string(),
            r#"{"kind":"SetSetting","param":"P-70","value":["passkey","passkey"]}"#.to_string(),
            r#"{"kind":"SetSetting","param":"P-73","value":"x"}"#.to_string(),
            format!(
                r#"{{"base":"0","kind":"SaveStep","step":"organisation","values":{{"data_protection_contact":{{"digest":"{}","id":"1"}},"signatories":["2","1"]}}}}"#,
                d
            ),
            format!(
                r#"{{"base":"0","kind":"SaveStep","step":"organisation","values":{{"data_protection_contact":{{"digest":"{}","id":"1"}},"signatories":[]}}}}"#,
                d.to_uppercase()
            ),
            r#"{"base":"0","kind":"SaveStep","step":"channels","values":{"matrix_homeserver":"Matrix.example.org","whatsapp":false}}"#.to_string(),
            r#"{"config":"1","fallbacks":["a b"],"kind":"RecordInferenceConfig","primary":"m"}"#.to_string(),
        ];
        for text in bad {
            let r = decode_command(text.as_bytes());
            assert!(matches!(r, Err(TenantError::Decode(_))), "{text}: {r:?}");
        }
    }

    /// ADR-007: a record schema version that was never published is
    /// refused.
    #[test]
    fn adr007_unpublished_record_schema_is_refused() {
        let text = br#"{"by":"2","kind":"OnboardingCompleted"}"#;
        assert!(decode_record_at(1, text).is_ok());
        assert!(matches!(
            decode_record_at(2, text),
            Err(TenantError::Decode(_))
        ));
        assert!(matches!(
            decode_record_at(0, text),
            Err(TenantError::Decode(_))
        ));
    }

    /// R-NF-02: a refusal shows a fixed message, never the input.
    #[test]
    fn r_nf_02_decode_errors_hold_no_input() {
        let text = br#"{"kind":"SECRET-VALUE-42"}"#;
        let shown = format!(
            "{:?} {}",
            decode_command(text),
            decode_record(text)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );
        assert!(!shown.contains("SECRET"), "{shown}");
    }
}
