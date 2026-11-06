//! The tenant operations: their strict request decoders and their read
//! models (M4 design sections 2.2 J0, 3.5 and 3.7, lane m4tenant).
//!
//! # Requests
//!
//! The bodies are those the onboarding pages send (`web/src/onboarding`):
//!
//! - `tenant.get_step` names a step in its path. A name no onboarding step
//!   has is refused, so no read model is built for it.
//! - `tenant.save_step` takes `{base, values}`. `base` is the tenant
//!   revision as a canonical decimal string. `values` is the step's values
//!   in the `fstp-tenant` codec form, except that the data protection
//!   contact is the free text itself. Dispatch stores the text and puts
//!   its reference in the values (design 3.7 step 1).
//! - Each `tenant.set_*` takes `{value}`, the setting in the codec form of
//!   its parameter.
//! - `tenant.set_guide_notice` takes `{privacy_statement_url, summary}`,
//!   the tenant's override of the Guide's data protection texts
//!   (R-GA-01). Dispatch stores the summary as a public text only once
//!   the command is admitted, as it stores the data protection contact.
//! - `tenant.invite_admin` takes `{email}`.
//! - `tenant.complete` and `admin.approve_self_grant` take no member.
//! - `tenant.grant_signatory` takes `{account, role}`. A body that names
//!   a programme is refused, since a signatory binding is tenant-wide
//!   (NOTE 5). `tenant.end_signatory` names the role and the account in
//!   its path and takes no member.
//! - `tenant.request_activation` takes no member. Dispatch draws the
//!   request id. `tenant.approve_activation` takes `{request}`, the id the
//!   activation read shows (SoD-18).
//!
//! Each body is checked by building the `fstp-tenant` codec text of its
//! command and decoding it with `fstp_tenant::decode_command`. So the
//! codec's rules hold here too: no JSON number anywhere (ADR-006), sets
//! strictly ascending, known names only, and no unknown or missing member.
//! Errors name no request content (R-NF-02).
//!
//! # Read models
//!
//! [`TenantView`] is the reply of the tenant reads and of a step save.
//! Saved values and settings are shown in the codec form, taken from the
//! codec's own encoding, so the page reads what it sends.

use fstp_access::{OpKind, OpSpec, TenantKind};
use fstp_domain::id::{AccountId, TextRef};
use fstp_json::{Object, Value};
use fstp_tenant::{
    Activation, ActivationRequestId, AgreementVersions, OnboardingStep, SettingValue,
    SignatoryRole, StepOutcome, StepStatus, StepValues, TenantCommand, TenantParam, TenantRecord,
    TenantRevision,
};

use crate::ApiError;
use crate::forms::REQUEST_RULE;

/// The longest data protection contact, in bytes (interim, pending
/// Daniel).
pub(crate) const CONTACT_LIMIT: usize = 2_000;

/// The longest email address, in bytes (RFC 5321 path limit).
pub(crate) const EMAIL_LIMIT: usize = 254;

fn bad() -> ApiError {
    ApiError::bad_request(REQUEST_RULE)
}

/// The step named by the path parameter of `request`.
fn step_param(request: &Object) -> Result<OnboardingStep, ApiError> {
    request
        .get("step")
        .and_then(Value::as_str)
        .and_then(OnboardingStep::from_name)
        .ok_or_else(bad)
}

/// The body members of `request`: every member but the route's
/// parameters.
fn body_members<'a>(spec: &OpSpec, request: &'a Object) -> Vec<&'a str> {
    let params = crate::forms::route_param_names(spec);
    request.keys().filter(|k| !params.contains(k)).collect()
}

/// Whether the body of `request` holds exactly `want`.
fn exactly(spec: &OpSpec, request: &Object, want: &[&str]) -> bool {
    let members = body_members(spec, request);
    members.len() == want.len() && want.iter().all(|w| members.contains(w))
}

/// The tenant parameter a `tenant.set_*` operation of `kind` changes.
const fn param_of(kind: TenantKind) -> Option<TenantParam> {
    use fstp_access::TenantParam as P;
    match kind {
        TenantKind::SetSetting(p) => Some(match p {
            P::P20 => TenantParam::P20,
            P::P69 => TenantParam::P69,
            P::P70 => TenantParam::P70,
            P::P71 => TenantParam::P71,
            P::P72 => TenantParam::P72,
            P::P74 => TenantParam::P74,
        }),
        _ => None,
    }
}

/// The strict decoder of a tenant operation's request, or `None` for an
/// operation that is not one. Fuzzed through `api_request_decode`.
pub(crate) fn check(spec: &OpSpec, request: &Object) -> Option<Result<(), ApiError>> {
    let ok = |b: bool| if b { Ok(()) } else { Err(bad()) };
    match (spec.name, spec.kind) {
        ("tenant.get_step", _) => {
            Some(step_param(request).and_then(|_| ok(exactly(spec, request, &[]))))
        }
        (_, OpKind::Tenant(kind)) => Some(match kind {
            TenantKind::SaveStep => {
                if exactly(spec, request, &["base", "values"]) {
                    save_request(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::Complete | TenantKind::ApproveSelfGrant | TenantKind::RequestActivation => {
                ok(exactly(spec, request, &[]))
            }
            TenantKind::GrantSignatory => {
                if exactly(spec, request, &["account", "role"]) {
                    signatory_request(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::EndSignatory => {
                if exactly(spec, request, &[]) {
                    signatory_request(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::ApproveActivation => {
                if exactly(spec, request, &["request"]) {
                    activation_request(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::InviteAdmin => {
                if exactly(spec, request, &["email"]) {
                    invite_email(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::SetSetting(_) => {
                if exactly(spec, request, &["value"]) {
                    setting_request(request, kind).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            TenantKind::SetGuideNotice => {
                if exactly(spec, request, &["privacy_statement_url", "summary"]) {
                    notice_request(request).map(|_| ())
                } else {
                    Err(bad())
                }
            }
            // No operation of the registry has this kind: the inference
            // record has no route (design 3.5).
            TenantKind::RecordInferenceConfig => Err(bad()),
        }),
        _ => None,
    }
}

/// A decoded `tenant.save_step` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaveRequest {
    /// The revision the values were edited against.
    pub(crate) base: TenantRevision,
    /// The values. The data protection contact, if any, holds a
    /// placeholder reference with id 0 and the text's digest until
    /// dispatch stores the text.
    pub(crate) values: StepValues,
    /// The data protection contact as the tenant typed it.
    pub(crate) contact: Option<String>,
}

/// Whether `s` is a data protection contact the cell keeps: some text,
/// within [`CONTACT_LIMIT`], and no control character but a line break or
/// a tab.
fn contact_ok(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= CONTACT_LIMIT
        && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t')
}

/// The codec form of a text reference.
fn text_ref_json(r: &TextRef) -> Value {
    let mut o = Object::new();
    let _ = o.insert("digest", Value::String(hex(&r.digest().bytes())));
    let _ = o.insert("id", Value::String(r.id().raw().to_string()));
    Value::Object(o)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes `{codec}` with the tenant codec, through its canonical text.
fn decode_command(v: Value) -> Result<TenantCommand, ApiError> {
    let text = fstp_json::to_canonical(&v).map_err(|_| bad())?;
    fstp_tenant::decode_command(text.as_bytes()).map_err(|_| bad())
}

/// Decodes a `tenant.save_step` request.
pub(crate) fn save_request(request: &Object) -> Result<SaveRequest, ApiError> {
    let step = step_param(request)?;
    let base = request.get("base").cloned().ok_or_else(bad)?;
    let mut values = match request.get("values") {
        Some(Value::Object(o)) => o.clone(),
        _ => return Err(bad()),
    };
    let mut contact = None;
    if step == OnboardingStep::Organisation {
        let text = match values.get("data_protection_contact") {
            Some(Value::String(s)) if contact_ok(s) => s.clone(),
            _ => return Err(bad()),
        };
        let placeholder = crate::forms::text_ref(0, &text);
        let _ = values.insert("data_protection_contact", text_ref_json(&placeholder));
        contact = Some(text);
    }
    let mut cmd = Object::new();
    let _ = cmd.insert("base", base);
    let _ = cmd.insert("kind", Value::from("SaveStep"));
    let _ = cmd.insert("step", Value::from(step.name()));
    let _ = cmd.insert("values", Value::Object(values));
    match decode_command(Value::Object(cmd))? {
        TenantCommand::SaveStep { values, base } if values.step() == step => Ok(SaveRequest {
            base,
            values,
            contact,
        }),
        _ => Err(bad()),
    }
}

/// Decodes the value of a `tenant.set_*` request of `kind`.
pub(crate) fn setting_request(
    request: &Object,
    kind: TenantKind,
) -> Result<SettingValue, ApiError> {
    let param = param_of(kind).ok_or_else(bad)?;
    let value = request.get("value").cloned().ok_or_else(bad)?;
    let mut cmd = Object::new();
    let _ = cmd.insert("kind", Value::from("SetSetting"));
    let _ = cmd.insert("param", Value::from(param.param_id().spec_id()));
    let _ = cmd.insert("value", value);
    match decode_command(Value::Object(cmd))? {
        TenantCommand::SetSetting { value } if value.param() == param => Ok(value),
        _ => Err(bad()),
    }
}

/// The role and account of a `tenant.grant_signatory` body, or of the
/// path of a `tenant.end_signatory`, decoded with the tenant codec. The
/// role is a wire name such as `financial_signatory` (NOTE 5).
pub(crate) fn signatory_request(request: &Object) -> Result<(SignatoryRole, AccountId), ApiError> {
    let role = request.get("role").cloned().ok_or_else(bad)?;
    let account = request.get("account").cloned().ok_or_else(bad)?;
    let mut cmd = Object::new();
    let _ = cmd.insert("account", account);
    let _ = cmd.insert("kind", Value::from("GrantSignatory"));
    let _ = cmd.insert("role", role);
    match decode_command(Value::Object(cmd))? {
        TenantCommand::GrantSignatory { role, account } => Ok((role, account)),
        _ => Err(bad()),
    }
}

/// The request id of a `tenant.approve_activation` body, decoded with the
/// tenant codec (SoD-18).
pub(crate) fn activation_request(request: &Object) -> Result<ActivationRequestId, ApiError> {
    let id = request.get("request").cloned().ok_or_else(bad)?;
    let mut cmd = Object::new();
    let _ = cmd.insert("kind", Value::from("ApproveActivation"));
    let _ = cmd.insert("request", id);
    match decode_command(Value::Object(cmd))? {
        TenantCommand::ApproveActivation { request } => Ok(request),
        _ => Err(bad()),
    }
}

/// The email of a `tenant.invite_admin` request: text with one `@`
/// between a local part and a domain, no space and no control character,
/// within [`EMAIL_LIMIT`].
pub(crate) fn invite_email(request: &Object) -> Result<String, ApiError> {
    let Some(Value::String(s)) = request.get("email") else {
        return Err(bad());
    };
    let shape = match s.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && !domain.contains('@'),
        None => false,
    };
    let clean = s.chars().all(|c| !c.is_control() && !c.is_whitespace());
    if shape && clean && s.len() <= EMAIL_LIMIT {
        Ok(s.clone())
    } else {
        Err(bad())
    }
}

/// The longest privacy statement address a request may carry, in bytes.
/// The tenant core checks the address itself (`fstp_tenant::decide`).
pub(crate) const ADDRESS_LIMIT: usize = 2_048;

/// A decoded `tenant.set_guide_notice` request (R-GA-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NoticeRequest {
    /// The data protection summary as the tenant typed it.
    pub(crate) summary: String,
    /// The privacy statement address. Only its length is checked here,
    /// so a non-`https:` address reaches the tenant core, which refuses
    /// it naming R-GA-01.
    pub(crate) privacy_statement_url: String,
}

impl NoticeRequest {
    /// The command, with the summary referenced by `summary`.
    pub(crate) fn command(&self, summary: TextRef) -> TenantCommand {
        TenantCommand::SetGuideNotice {
            notice: Some(fstp_tenant::GuideNoticeOverride {
                summary,
                privacy_statement_url: self.privacy_statement_url.clone(),
            }),
        }
    }
}

/// Decodes a `tenant.set_guide_notice` request: `{privacy_statement_url,
/// summary}`, both strings. The summary follows the rule of a data
/// protection contact ([`CONTACT_LIMIT`]).
pub(crate) fn notice_request(request: &Object) -> Result<NoticeRequest, ApiError> {
    let (Some(Value::String(summary)), Some(Value::String(url))) =
        (request.get("summary"), request.get("privacy_statement_url"))
    else {
        return Err(bad());
    };
    if !contact_ok(summary) || url.is_empty() || url.len() > ADDRESS_LIMIT {
        return Err(bad());
    }
    Ok(NoticeRequest {
        summary: summary.clone(),
        privacy_statement_url: url.clone(),
    })
}

// ---------------------------------------------------------------------------
// Read models
// ---------------------------------------------------------------------------

/// The reply of a tenant read or a step save.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantView {
    /// `tenant.get_step` and the reply of `tenant.save_step`.
    Step(StepView),
    /// `tenant.settings`.
    Settings(SettingsView),
    /// `tenant.list_admins`.
    Admins(crate::model::TenantAdmins),
    /// `tenant.list_signatories` (NOTE 5).
    Signatories(SignatoryList),
    /// `tenant.get_activation` (SoD-18).
    Activation(ActivationView),
}

/// One signatory binding as the onboarding pages read it: the account,
/// the role and the account's pseudonymous handle. A binding is
/// tenant-wide, so it names no programme (NOTE 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatoryRow {
    /// The account.
    pub account: AccountId,
    /// The role.
    pub role: SignatoryRole,
    /// The display handle from `Accounts::display_handle`.
    pub handle: crate::port::DisplayHandle,
}

/// `tenant.list_signatories`: the signatory bindings held now, by role
/// then account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatoryList {
    rows: Vec<SignatoryRow>,
}

impl SignatoryList {
    /// The list of `rows`, by role then account, each binding once.
    pub(crate) fn new(rows: impl IntoIterator<Item = SignatoryRow>) -> SignatoryList {
        let mut rows: Vec<SignatoryRow> = rows.into_iter().collect();
        rows.sort_by_key(|r| (r.role, r.account));
        rows.dedup_by_key(|r| (r.role, r.account));
        SignatoryList { rows }
    }

    /// The rows.
    pub fn rows(&self) -> &[SignatoryRow] {
        &self.rows
    }
}

/// `tenant.get_activation`: the activation of the organisation (SoD-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationView(pub(crate) Activation);

/// The JSON of an activation: its state, its request and the requesting
/// and approving admins, each `null` where the state has none.
fn activation_json(a: Activation, o: &mut Object) {
    let id = |x: u128| Value::String(x.to_string());
    let (state, request, requested_by, approved_by) = match a {
        Activation::NotRequested => ("not_requested", None, None, None),
        Activation::Requested { request, by } => {
            ("requested", Some(request.raw()), Some(by.raw()), None)
        }
        Activation::Active {
            request,
            requested_by,
            approved_by,
        } => (
            "active",
            Some(request.raw()),
            Some(requested_by.raw()),
            Some(approved_by.raw()),
        ),
    };
    let _ = o.insert("state", Value::from(state));
    let _ = o.insert("request", request.map_or(Value::Null, id));
    let _ = o.insert("requested_by", requested_by.map_or(Value::Null, id));
    let _ = o.insert("approved_by", approved_by.map_or(Value::Null, id));
}

/// One onboarding step as the onboarding pages read it
/// (`web/src/onboarding/model.ts`, `readStep`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepView {
    step: OnboardingStep,
    status: StepStatus,
    revision: TenantRevision,
    /// The latest saved values in the codec form, the data protection
    /// contact shown as its text.
    values: Option<Value>,
    outcome: Option<StepOutcome>,
    /// For the Agreements step of a SaaS cell: the versions the control
    /// plane recorded as accepted.
    accepted: Option<AgreementVersions>,
}

impl StepView {
    /// The view of `step`.
    pub(crate) fn new(
        step: OnboardingStep,
        status: StepStatus,
        revision: TenantRevision,
        values: Option<Value>,
        outcome: Option<StepOutcome>,
        accepted: Option<AgreementVersions>,
    ) -> StepView {
        StepView {
            step,
            status,
            revision,
            values,
            outcome,
            accepted,
        }
    }
}

/// The tenant settings, each in the codec form of its parameter. P-20 is
/// `null` while no tenant admin has chosen it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsView {
    members: Vec<(&'static str, Value)>,
}

/// The codec spelling of a step status.
const fn status_name(s: StepStatus) -> &'static str {
    match s {
        StepStatus::Locked => "locked",
        StepStatus::Open => "open",
        StepStatus::Saved => "saved",
        StepStatus::Validated => "validated",
        StepStatus::Skipped => "skipped",
        StepStatus::Unavailable { .. } => "unavailable",
    }
}

/// The member `name` of the codec encoding of `record`.
fn codec_member(record: &TenantRecord, name: &str) -> Option<Value> {
    let bytes = fstp_tenant::encode_record(record).ok()?;
    match fstp_json::parse(&bytes).ok()? {
        Value::Object(mut o) => o.remove(name),
        _ => None,
    }
}

/// The codec form of saved `values`, from the codec's own encoding. A
/// data protection contact shows as `contact`, its text.
pub(crate) fn values_json(values: &StepValues, contact: Option<&str>) -> Option<Value> {
    let record = TenantRecord::StepSaved {
        values: values.clone(),
        by: AccountId::from_raw(0),
        outcome: StepOutcome::Validated,
    };
    let mut v = codec_member(&record, "values")?;
    if let (Some(text), Value::Object(o)) = (contact, &mut v) {
        let _ = o.insert("data_protection_contact", Value::from(text));
    }
    Some(v)
}

/// The codec spelling of a save outcome, such as `"validated"` or
/// `"too_few_admins"`.
pub(crate) fn outcome_name(outcome: StepOutcome) -> Option<String> {
    let record = TenantRecord::StepSaved {
        values: StepValues::Branding {
            package: fstp_tenant::BrandingPackage::Default,
        },
        by: AccountId::from_raw(0),
        outcome,
    };
    codec_member(&record, "outcome").and_then(|v| v.as_str().map(str::to_owned))
}

/// The codec form of one setting value.
fn setting_json(value: &SettingValue) -> Option<Value> {
    let record = TenantRecord::SettingChanged {
        value: value.clone(),
        by: AccountId::from_raw(0),
    };
    codec_member(&record, "value")
}

impl SettingsView {
    /// The view of `s`. `None` when a value has no codec form, which a
    /// folded setting always has.
    pub(crate) fn of(s: &fstp_tenant::TenantSettings) -> Option<SettingsView> {
        let p20 = match s.p20 {
            Some(m) => setting_json(&SettingValue::P20(m))?,
            None => Value::Null,
        };
        Some(SettingsView {
            members: vec![
                ("p20", p20),
                ("p69", setting_json(&SettingValue::P69(s.p69.clone()))?),
                ("p70", setting_json(&SettingValue::P70(s.p70.clone()))?),
                ("p71", setting_json(&SettingValue::P71 { us: s.p71_us })?),
                (
                    "p72",
                    setting_json(&SettingValue::P72 {
                        idle_us: s.p72_idle_us,
                        absolute_us: s.p72_absolute_us,
                    })?,
                ),
                ("p74", setting_json(&SettingValue::P74(s.p74.clone()))?),
            ],
        })
    }
}

fn agreements_json(a: AgreementVersions) -> Value {
    let mut o = Object::new();
    let _ = o.insert("dpa", Value::String(a.dpa.to_string()));
    let _ = o.insert("saas_terms", Value::String(a.saas_terms.to_string()));
    let _ = o.insert(
        "sub_processors",
        Value::String(a.sub_processors.to_string()),
    );
    Value::Object(o)
}

impl fstp_json::ToJson for TenantView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            TenantView::Step(v) => {
                let _ = o.insert("step", Value::from(v.step.name()));
                let _ = o.insert("status", Value::from(status_name(v.status)));
                let _ = o.insert("revision", Value::String(v.revision.raw().to_string()));
                let _ = o.insert("values", v.values.clone().unwrap_or(Value::Null));
                let outcome = v
                    .outcome
                    .and_then(outcome_name)
                    .map_or(Value::Null, Value::String);
                let _ = o.insert("outcome", outcome);
                let _ = o.insert("accepted", v.accepted.map_or(Value::Null, agreements_json));
            }
            TenantView::Settings(s) => {
                for (k, v) in &s.members {
                    let _ = o.insert(*k, v.clone());
                }
            }
            TenantView::Admins(list) => return fstp_json::ToJson::to_json(list),
            TenantView::Signatories(list) => {
                let rows: Vec<Value> = list
                    .rows
                    .iter()
                    .map(|r| {
                        let mut row = Object::new();
                        let _ = row.insert("account", Value::String(r.account.raw().to_string()));
                        let _ = row.insert("role", Value::from(r.role.name()));
                        let _ = row.insert("handle", Value::from(r.handle.0.as_str()));
                        Value::Object(row)
                    })
                    .collect();
                let _ = o.insert("signatories", Value::from(rows));
            }
            TenantView::Activation(ActivationView(a)) => activation_json(*a, &mut o),
        }
        Value::Object(o)
    }
}

/// One view of each kind, with every optional member set somewhere: a
/// step view of each step and status with saved values and an outcome,
/// the Agreements step with the recorded versions, and the settings at
/// their defaults and changed. The reply shape test of `model.rs` checks
/// each against its operation's shape (TH-26).
#[cfg(test)]
pub(crate) fn samples() -> Vec<TenantView> {
    use std::collections::BTreeSet;

    use fstp_domain::id::{ContentDigest, TextId};
    use fstp_domain::roles::Role;
    use fstp_tenant::{
        BankInterface, BrandingPackage, DomainName, InferenceDefault, LoginMethod, McpSettings,
        Milestone, PaymentMode, RpMode, StepFailure, Token, VerifyMethod,
    };

    let a = |n: u128| AccountId::from_raw(n);
    let token = |s: &str| Token::new(s).unwrap_or_else(|| panic!("token {s}"));
    let domain = |s: &str| DomainName::new(s).unwrap_or_else(|| panic!("domain {s}"));
    let all = [
        StepValues::Organisation {
            data_protection_contact: TextRef::new(
                TextId::from_raw(1),
                ContentDigest::from_bytes([1; 32]),
            ),
            signatories: [a(1), a(2)].into_iter().collect(),
        },
        StepValues::Agreements {
            saas_terms: 1,
            dpa: 2,
            sub_processors: 3,
        },
        StepValues::Branding {
            package: BrandingPackage::WhiteLabel,
        },
        StepValues::DomainsAndEmail {
            sending_domain: domain("mail.e2e.invalid"),
        },
        StepValues::Identity {
            p18: VerifyMethod::ALL.into_iter().collect(),
            p45: RpMode::CrabNebulaIntermediary,
        },
        StepValues::Inference(InferenceDefault {
            provider: token("placeholder"),
            primary: token("placeholder-model"),
            fallbacks: vec![token("placeholder-fallback")],
        }),
        StepValues::Payments {
            bank_interface: BankInterface::Connect,
        },
        StepValues::Channels {
            matrix_homeserver: Some(domain("matrix.e2e.invalid")),
            whatsapp: true,
        },
        StepValues::Administrators {
            admins: [a(1), a(2)].into_iter().collect(),
        },
    ];
    let statuses = [
        StepStatus::Locked,
        StepStatus::Open,
        StepStatus::Saved,
        StepStatus::Validated,
        StepStatus::Skipped,
        StepStatus::Unavailable {
            milestone: Milestone::M6,
        },
    ];
    let outcomes = [
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
    let mut out = Vec::new();
    let paired = all
        .iter()
        .zip(statuses.iter().cycle())
        .zip(outcomes.iter().cycle());
    for ((values, status), outcome) in paired {
        let step = values.step();
        let contact = (step == OnboardingStep::Organisation).then_some("Synthetic contact.");
        let accepted = (step == OnboardingStep::Agreements).then_some(AgreementVersions {
            saas_terms: 1,
            dpa: 1,
            sub_processors: 1,
        });
        out.push(TenantView::Step(StepView::new(
            step,
            *status,
            TenantRevision::from_raw(7),
            values_json(values, contact),
            Some(*outcome),
            accepted,
        )));
    }
    for status in statuses {
        out.push(TenantView::Step(StepView::new(
            OnboardingStep::Branding,
            status,
            TenantRevision::GENESIS,
            None,
            None,
            None,
        )));
    }
    for outcome in outcomes {
        out.push(TenantView::Step(StepView::new(
            OnboardingStep::Branding,
            StepStatus::Saved,
            TenantRevision::from_raw(1),
            values_json(
                &StepValues::Branding {
                    package: BrandingPackage::Default,
                },
                None,
            ),
            Some(outcome),
            None,
        )));
    }
    let defaults = fstp_tenant::TenantSettings::spec_defaults();
    let mut changed = defaults.clone();
    changed.p20 = Some(PaymentMode::Execution);
    changed.p70 = LoginMethod::ALL.into_iter().collect();
    changed.p74 = McpSettings {
        enabled: false,
        roles: Some(
            [Role::Applicant, Role::ProgrammeManager]
                .into_iter()
                .collect(),
        ),
        public_tools: false,
    };
    let mut none = defaults.clone();
    none.p74.roles = Some(BTreeSet::new());
    for s in [defaults, changed, none] {
        if let Some(v) = SettingsView::of(&s) {
            out.push(TenantView::Settings(v));
        }
    }
    let row = |n: u128, role| SignatoryRow {
        account: a(n),
        role,
        handle: crate::port::DisplayHandle(format!("signatory-{n}")),
    };
    out.push(TenantView::Signatories(SignatoryList::new([])));
    out.push(TenantView::Signatories(SignatoryList::new([
        row(2, SignatoryRole::Legal),
        row(2, SignatoryRole::Financial),
        row(3, SignatoryRole::Financial),
    ])));
    let request = fstp_tenant::ActivationRequestId::from_raw(9);
    for activation in [
        Activation::NotRequested,
        Activation::Requested { request, by: a(1) },
        Activation::Active {
            request,
            requested_by: a(1),
            approved_by: a(2),
        },
    ] {
        out.push(TenantView::Activation(ActivationView(activation)));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// R-TN-01: every save outcome has its codec spelling, and an outcome
    /// read back names the outcome the codec wrote.
    #[test]
    fn r_tn_01_outcome_names_are_the_codec_spellings() {
        assert_eq!(
            outcome_name(StepOutcome::Validated).as_deref(),
            Some("validated")
        );
        assert_eq!(
            outcome_name(StepOutcome::Failed(fstp_tenant::StepFailure::TooFewAdmins)).as_deref(),
            Some("too_few_admins")
        );
    }

    /// R-LG-03: the settings view shows the spec defaults in the codec
    /// form, with P-20 unset.
    #[test]
    fn r_lg_03_settings_view_shows_the_defaults_in_codec_form() {
        let view = SettingsView::of(&fstp_tenant::TenantSettings::spec_defaults()).unwrap();
        let v = fstp_json::ToJson::to_json(&TenantView::Settings(view));
        let text = fstp_json::to_canonical(&v).unwrap();
        assert_eq!(
            text,
            r#"{"p20":null,"p69":"CC-BY-4.0","p70":["passkey"],"p71":"300000000","p72":{"absolute_us":"43200000000","idle_us":"1800000000"},"p74":{"enabled":true,"public_tools":true,"roles":null}}"#
        );
    }
}
