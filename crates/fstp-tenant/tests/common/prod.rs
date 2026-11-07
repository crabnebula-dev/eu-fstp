//! The one adapter over the `fstp-tenant` production API.
//!
//! Each seam maps the test vocabulary of [`super::vocab`] onto the types
//! of design section 3.5 and returns the same vocabulary.
//!
//! - [`Sut`] holds the tenant state, the appended records and the `Env`.
//!   [`Sut::genesis`] builds the state of a SaaS cell with
//!   `env.first_admin` as the only tenant admin, as the first-admin
//!   enrolment from the control plane leaves it.
//! - [`Sut::run`] maps the `Op` to a `TenantCommand` and a `TenantCtx`
//!   (actor, `via` and the fixed instant [`RUN_AT`]). It asks `queries`
//!   what the command needs. It answers each vault query from
//!   `env.verified`, each probe from `env.probes`, the control plane's
//!   agreements from `env.agreements_recorded`, and each Receiving
//!   question from `env.receiving`. It runs `decide`, folds the records on
//!   acceptance, and returns the verdict with the records mapped to
//!   `RecordView`.
//! - An invitation token is derived from the invitation id, and the
//!   adapter passes its digest ([`token_digest`]) on both sides.
//! - [`Sut::observe`] reads the projection. [`Sut::replayed`] folds the
//!   appended records into a fresh genesis and reads that projection.
//! - [`Sut::record_texts`] gives the canonical text of each appended
//!   record, for the `decode_record` round trip.
//!
//! A `StepInput::Plain { valid }` becomes concrete values of the step's
//! kind that pass or fail the step's own checks. A plain input for the
//! Identity or Inference step, which the generators never build, maps to
//! values of that step with the same validity.

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, ContentDigest, LlmConfigId, TextId, TextRef};
use fstp_domain::rules::ParamId;
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    AgreementVersions, ApprovalId, BankInterface, BrandingPackage, CellKind, DomainName, GrantRef,
    InferenceDefault, InvitationId, LoginMethod, McpSettings, OnboardingStep, PaymentMode,
    ProbeOutcome, RpMode, SettingValue, SignatoryRole, StepValues, TenantAnswers, TenantCommand,
    TenantCtx, TenantError, TenantParam, TenantQuery, TenantRecord, TenantState, Token,
    TokenDigest, VerifyMethod,
};

use super::vocab::{
    self, Approval, Defaults, Env, Grant, Inference, Observed, Op, Probes, RecordView, Setting,
    Settings, Signatory, Step, StepInput, Verdict,
};

/// The one instant of every adapter run: 2026-01-01T00:00:00Z. No SoD-07
/// approval lapses within a run.
pub const RUN_AT: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);

/// The agreement versions a valid Agreements save names, which the
/// control plane confirms when `Env::agreements_recorded` holds.
pub const AGREEMENTS: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

/// The digest of the token of invitation `invitation`, as the shell would
/// compute it. The adapter derives the token from the id, so the invitee
/// always presents the right one.
pub fn token_digest(invitation: u128) -> TokenDigest {
    let half = invitation.to_le_bytes();
    let mut b = [0u8; 32];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = half[i % 16] ^ 0xa5;
    }
    TokenDigest::from_bytes(b)
}

/// What one operation gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether it was accepted.
    pub verdict: Verdict,
    /// The records it appended, in order. Empty when refused.
    pub records: Vec<RecordView>,
}

/// The system under test: the production tenant state and its records.
#[derive(Debug)]
pub struct Sut {
    env: Env,
    state: TenantState,
    records: Vec<TenantRecord>,
}

impl Sut {
    /// The genesis of `env`, in a SaaS cell.
    pub fn genesis(env: &Env) -> Result<Sut, TenantError> {
        Ok(Sut {
            env: env.clone(),
            state: TenantState::genesis(env.first_admin, CellKind::Saas),
            records: Vec::new(),
        })
    }

    /// Runs one operation.
    pub fn run(&mut self, op: &Op) -> Result<Outcome, TenantError> {
        let cmd = command(op, &self.state, self.env.first_admin)?;
        let ctx = TenantCtx {
            actor: op.actor(),
            via: op.via(),
            at: RUN_AT,
        };
        let mut answers = TenantAnswers::new();
        for q in fstp_tenant::queries(&self.state, &cmd) {
            match q {
                TenantQuery::AdminVerified(a) => {
                    answers.verified(a, self.env.verified.contains(&a))
                }
                TenantQuery::Probe(k) => {
                    let o = match self.env.probes {
                        Probes::Absent => ProbeOutcome::Absent,
                        Probes::Fake { pass: true } => ProbeOutcome::Passed,
                        Probes::Fake { pass: false } => ProbeOutcome::Failed,
                    };
                    answers.probe(k, o);
                }
                TenantQuery::Agreements => {
                    if self.env.agreements_recorded {
                        answers.agreements(AGREEMENTS);
                    }
                }
                TenantQuery::HoldsReceiving(a) => {
                    answers.holds_receiving(a, self.env.receiving.contains(&a));
                }
            }
        }
        match fstp_tenant::decide(&self.state, &ctx, &cmd, &answers) {
            Ok(records) => {
                self.state.apply_all(&records)?;
                let views = records.iter().map(record_view).collect();
                self.records.extend(records);
                Ok(Outcome {
                    verdict: Verdict::Accepted,
                    records: views,
                })
            }
            Err(_) => Ok(Outcome {
                verdict: Verdict::Refused,
                records: Vec::new(),
            }),
        }
    }

    /// The projection of the current state.
    pub fn observe(&self) -> Result<Observed, TenantError> {
        Ok(observed(&self.state))
    }

    /// The projection of a state folded from the appended records alone.
    pub fn replayed(&self) -> Result<Observed, TenantError> {
        let s = TenantState::replay(self.env.first_admin, CellKind::Saas, &self.records)?;
        Ok(observed(&s))
    }

    /// The configuration and model `call.publish` takes (design 3.5).
    pub fn publication_config(&self) -> Result<Option<(LlmConfigId, String)>, TenantError> {
        Ok(self
            .state
            .publication_config()
            .map(|(c, m)| (c, m.as_str().to_string())))
    }

    /// The canonical RFC 8785 text of every appended record, in order.
    pub fn record_texts(&self) -> Result<Vec<Vec<u8>>, TenantError> {
        self.records
            .iter()
            .map(fstp_tenant::encode_record)
            .collect()
    }
}

/// The parameters `TenantParam` covers, as domain parameter ids.
pub fn settable_params() -> Result<BTreeSet<ParamId>, TenantError> {
    Ok(TenantParam::ALL
        .into_iter()
        .map(TenantParam::param_id)
        .collect())
}

/// Whether the production command of `op` is high-risk.
pub fn high_risk(op: &Op) -> Result<bool, TenantError> {
    let genesis = TenantState::genesis(vocab::acct(1), CellKind::Saas);
    Ok(command(op, &genesis, vocab::acct(1))?.high_risk())
}

/// Encodes the production command of `op` to its canonical text.
pub fn encode_command(op: &Op) -> Result<Vec<u8>, TenantError> {
    let genesis = TenantState::genesis(vocab::acct(1), CellKind::Saas);
    fstp_tenant::encode_command(&command(op, &genesis, vocab::acct(1))?)
}

/// Decodes `bytes` with the production decoder and encodes the result
/// again. `Ok(None)` means the decoder refused the bytes.
pub fn command_reencoded(bytes: &[u8]) -> Result<Option<Vec<u8>>, TenantError> {
    match fstp_tenant::decode_command(bytes) {
        Ok(c) => fstp_tenant::encode_command(&c).map(Some),
        Err(TenantError::NotImplemented(op)) => Err(TenantError::NotImplemented(op)),
        Err(_) => Ok(None),
    }
}

/// Decodes a stored record and encodes it again. `Ok(None)` means the
/// decoder refused the bytes.
pub fn record_reencoded(bytes: &[u8]) -> Result<Option<Vec<u8>>, TenantError> {
    match fstp_tenant::decode_record(bytes) {
        Ok(r) => fstp_tenant::encode_record(&r).map(Some),
        Err(TenantError::NotImplemented(op)) => Err(TenantError::NotImplemented(op)),
        Err(_) => Ok(None),
    }
}

// ------------------------------------------------------------- mapping

fn token(s: &str) -> Result<Token, TenantError> {
    Token::new(s).ok_or(TenantError::Encode)
}

fn tokens(list: &[String]) -> Result<Vec<Token>, TenantError> {
    list.iter().map(|s| token(s)).collect()
}

fn domain(s: &str) -> Result<DomainName, TenantError> {
    DomainName::new(s).ok_or(TenantError::Encode)
}

fn step_of(s: Step) -> OnboardingStep {
    match s {
        Step::Organisation => OnboardingStep::Organisation,
        Step::Agreements => OnboardingStep::Agreements,
        Step::Branding => OnboardingStep::Branding,
        Step::DomainsAndEmail => OnboardingStep::DomainsAndEmail,
        Step::Identity => OnboardingStep::Identity,
        Step::Inference => OnboardingStep::Inference,
        Step::Payments => OnboardingStep::Payments,
        Step::Channels => OnboardingStep::Channels,
        Step::Administrators => OnboardingStep::Administrators,
    }
}

fn step_view(s: OnboardingStep) -> Step {
    match s {
        OnboardingStep::Organisation => Step::Organisation,
        OnboardingStep::Agreements => Step::Agreements,
        OnboardingStep::Branding => Step::Branding,
        OnboardingStep::DomainsAndEmail => Step::DomainsAndEmail,
        OnboardingStep::Identity => Step::Identity,
        OnboardingStep::Inference => Step::Inference,
        OnboardingStep::Payments => Step::Payments,
        OnboardingStep::Channels => Step::Channels,
        OnboardingStep::Administrators => Step::Administrators,
    }
}

fn verify_of(m: vocab::VerifyMethod) -> VerifyMethod {
    match m {
        vocab::VerifyMethod::EudiWallet => VerifyMethod::EudiWallet,
        vocab::VerifyMethod::DocumentUpload => VerifyMethod::DocumentUpload,
    }
}

fn verify_view(m: VerifyMethod) -> vocab::VerifyMethod {
    match m {
        VerifyMethod::EudiWallet => vocab::VerifyMethod::EudiWallet,
        VerifyMethod::DocumentUpload => vocab::VerifyMethod::DocumentUpload,
    }
}

fn rp_of(m: vocab::RpMode) -> RpMode {
    match m {
        vocab::RpMode::TenantRegistration => RpMode::TenantRegistration,
        vocab::RpMode::CrabNebulaIntermediary => RpMode::CrabNebulaIntermediary,
    }
}

fn rp_view(m: RpMode) -> vocab::RpMode {
    match m {
        RpMode::TenantRegistration => vocab::RpMode::TenantRegistration,
        RpMode::CrabNebulaIntermediary => vocab::RpMode::CrabNebulaIntermediary,
    }
}

fn login_of(m: vocab::LoginMethod) -> LoginMethod {
    match m {
        vocab::LoginMethod::Passkey => LoginMethod::Passkey,
        vocab::LoginMethod::EudiWallet => LoginMethod::EudiWallet,
        vocab::LoginMethod::Opaque => LoginMethod::Opaque,
        vocab::LoginMethod::MagicLink => LoginMethod::MagicLink,
    }
}

fn login_view(m: LoginMethod) -> vocab::LoginMethod {
    match m {
        LoginMethod::Passkey => vocab::LoginMethod::Passkey,
        LoginMethod::EudiWallet => vocab::LoginMethod::EudiWallet,
        LoginMethod::Opaque => vocab::LoginMethod::Opaque,
        LoginMethod::MagicLink => vocab::LoginMethod::MagicLink,
    }
}

fn payment_of(m: vocab::PaymentMode) -> PaymentMode {
    match m {
        vocab::PaymentMode::RecordOnly => PaymentMode::RecordOnly,
        vocab::PaymentMode::Execution => PaymentMode::Execution,
    }
}

fn payment_view(m: PaymentMode) -> vocab::PaymentMode {
    match m {
        PaymentMode::RecordOnly => vocab::PaymentMode::RecordOnly,
        PaymentMode::Execution => vocab::PaymentMode::Execution,
    }
}

fn inference_default_of(d: &vocab::InferenceDefault) -> Result<InferenceDefault, TenantError> {
    Ok(InferenceDefault {
        provider: token(&d.provider)?,
        primary: token(&d.primary)?,
        fallbacks: tokens(&d.fallbacks)?,
    })
}

fn inference_default_view(d: &InferenceDefault) -> vocab::InferenceDefault {
    vocab::InferenceDefault {
        provider: d.provider.as_str().to_string(),
        primary: d.primary.as_str().to_string(),
        fallbacks: d.fallbacks.iter().map(|f| f.as_str().to_string()).collect(),
    }
}

/// Concrete values of `step` that pass (`valid`) or fail its own checks.
fn plain_values(
    step: Step,
    valid: bool,
    state: &TenantState,
    first_admin: AccountId,
) -> Result<StepValues, TenantError> {
    Ok(match step {
        Step::Organisation => StepValues::Organisation {
            data_protection_contact: TextRef::new(
                TextId::from_raw(1),
                ContentDigest::from_bytes([0x5a; 32]),
            ),
            signatories: if valid {
                [first_admin].into_iter().collect()
            } else {
                BTreeSet::new()
            },
        },
        Step::Agreements => StepValues::Agreements {
            saas_terms: 1,
            dpa: u32::from(valid),
            sub_processors: 1,
        },
        Step::Branding => StepValues::Branding {
            package: if valid {
                BrandingPackage::Default
            } else {
                BrandingPackage::WhiteLabel
            },
        },
        Step::DomainsAndEmail => StepValues::DomainsAndEmail {
            sending_domain: domain(if valid {
                "mail.example.org"
            } else {
                "localhost"
            })?,
        },
        Step::Identity => StepValues::Identity {
            p18: if valid {
                [VerifyMethod::EudiWallet].into_iter().collect()
            } else {
                BTreeSet::new()
            },
            p45: RpMode::TenantRegistration,
        },
        Step::Inference => StepValues::Inference(InferenceDefault {
            provider: token("synthetic-provider")?,
            primary: token(if valid { "model-a" } else { "" })?,
            fallbacks: Vec::new(),
        }),
        Step::Payments => StepValues::Payments {
            bank_interface: if valid {
                BankInterface::NotConnected
            } else {
                BankInterface::Connect
            },
        },
        Step::Channels => StepValues::Channels {
            matrix_homeserver: Some(domain(if valid {
                "matrix.example.org"
            } else {
                "localhost"
            })?),
            whatsapp: false,
        },
        Step::Administrators => StepValues::Administrators {
            admins: if valid {
                state.admins().clone()
            } else {
                BTreeSet::new()
            },
        },
    })
}

fn step_values(
    step: Step,
    input: &StepInput,
    state: &TenantState,
    first_admin: AccountId,
) -> Result<StepValues, TenantError> {
    match (step, input) {
        (Step::Identity, StepInput::Identity { p18, p45 }) => Ok(StepValues::Identity {
            p18: p18.iter().copied().map(verify_of).collect(),
            p45: rp_of(*p45),
        }),
        (Step::Inference, StepInput::Inference(d)) => {
            Ok(StepValues::Inference(inference_default_of(d)?))
        }
        (_, StepInput::Plain { valid }) => plain_values(step, *valid, state, first_admin),
        (_, _) => plain_values(step, false, state, first_admin),
    }
}

fn mcp_of(m: &vocab::McpSetting) -> McpSettings {
    McpSettings {
        enabled: m.enabled,
        roles: m.roles.clone(),
        public_tools: m.public_tools,
    }
}

fn mcp_view(m: &McpSettings) -> vocab::McpSetting {
    vocab::McpSetting {
        enabled: m.enabled,
        roles: m.roles.clone(),
        public_tools: m.public_tools,
    }
}

fn setting_of(s: &Setting) -> SettingValue {
    match s {
        Setting::P20(m) => SettingValue::P20(payment_of(*m)),
        Setting::P69(id) => SettingValue::P69(id.clone()),
        Setting::P70(m) => SettingValue::P70(m.iter().copied().map(login_of).collect()),
        Setting::P71 { us } => SettingValue::P71 { us: *us },
        Setting::P72 {
            idle_us,
            absolute_us,
        } => SettingValue::P72 {
            idle_us: *idle_us,
            absolute_us: *absolute_us,
        },
        Setting::P74(m) => SettingValue::P74(mcp_of(m)),
    }
}

fn signatory_of(r: Signatory) -> SignatoryRole {
    match r {
        Signatory::Financial => SignatoryRole::Financial,
        Signatory::Legal => SignatoryRole::Legal,
    }
}

fn signatory_view(r: SignatoryRole) -> Signatory {
    match r {
        SignatoryRole::Financial => Signatory::Financial,
        SignatoryRole::Legal => Signatory::Legal,
    }
}

fn grant_of(g: &Grant) -> GrantRef {
    GrantRef {
        grantee: g.grantee,
        programme: g.programme,
        role: g.role,
    }
}

fn command(
    op: &Op,
    state: &TenantState,
    first_admin: AccountId,
) -> Result<TenantCommand, TenantError> {
    Ok(match op {
        Op::SaveStep { step, input, .. } => TenantCommand::SaveStep {
            values: step_values(*step, input, state, first_admin)?,
            base: state.revision(),
        },
        Op::InviteAdmin {
            invitation,
            invitee,
            ..
        } => TenantCommand::InviteAdmin {
            invitation: InvitationId::from_raw(*invitation),
            invitee: *invitee,
            token_digest: token_digest(*invitation),
        },
        Op::AcceptAdminInvitation { invitation, .. } => TenantCommand::AcceptAdminInvitation {
            invitation: InvitationId::from_raw(*invitation),
            token_digest: token_digest(*invitation),
        },
        Op::ApproveSelfGrant {
            approval, grant, ..
        } => TenantCommand::ApproveSelfGrant {
            approval: ApprovalId::from_raw(*approval),
            grant: grant_of(grant),
        },
        Op::UseSelfGrantApproval {
            approval, grant, ..
        } => TenantCommand::UseSelfGrantApproval {
            approval: ApprovalId::from_raw(*approval),
            grant: grant_of(grant),
        },
        Op::SetSetting { setting, .. } => TenantCommand::SetSetting {
            value: setting_of(setting),
        },
        Op::RecordInference {
            config,
            primary,
            fallbacks,
            ..
        } => TenantCommand::RecordInferenceConfig {
            config: *config,
            primary: token(primary)?,
            fallbacks: tokens(fallbacks)?,
        },
        Op::Complete { .. } => TenantCommand::Complete,
        Op::GrantSignatory { account, role, .. } => TenantCommand::GrantSignatory {
            role: signatory_of(*role),
            account: *account,
        },
        Op::EndSignatory { account, role, .. } => TenantCommand::EndSignatory {
            role: signatory_of(*role),
            account: *account,
        },
    })
}

fn record_view(r: &TenantRecord) -> RecordView {
    match r {
        TenantRecord::StepSaved { values, .. } => RecordView::StepSaved(step_view(values.step())),
        TenantRecord::StepValidated { step, .. } => RecordView::StepValidated(step_view(*step)),
        TenantRecord::AdminInvited { invitation, by, .. } => RecordView::AdminInvited {
            invitation: invitation.raw(),
            by: *by,
        },
        TenantRecord::AdminAdded { account, .. } => RecordView::AdminAdded { account: *account },
        TenantRecord::SelfGrantApproved { approval, by, .. } => RecordView::SelfGrantApproved {
            approval: approval.raw(),
            by: *by,
        },
        TenantRecord::SelfGrantApprovalUsed { approval, by, .. } => {
            RecordView::SelfGrantApprovalUsed {
                approval: approval.raw(),
                by: *by,
            }
        }
        TenantRecord::SettingChanged { value, by } => RecordView::SettingChanged {
            param: value.param().param_id(),
            by: *by,
        },
        TenantRecord::GuideNoticeSet { by, .. } => RecordView::GuideNoticeSet { by: *by },
        TenantRecord::InferenceConfigRecorded { config, by, .. } => {
            RecordView::InferenceConfigRecorded {
                config: *config,
                by: *by,
            }
        }
        TenantRecord::OnboardingCompleted { by } => RecordView::OnboardingCompleted { by: *by },
        TenantRecord::SignatoryGranted {
            role, account, by, ..
        } => RecordView::SignatoryGranted {
            role: signatory_view(*role),
            account: *account,
            by: *by,
        },
        TenantRecord::SignatoryEnded {
            role, account, by, ..
        } => RecordView::SignatoryEnded {
            role: signatory_view(*role),
            account: *account,
            by: *by,
        },
        TenantRecord::ActivationRequested { by, .. } => RecordView::ActivationRequested { by: *by },
        TenantRecord::ActivationApproved { by, .. } => RecordView::ActivationApproved { by: *by },
        TenantRecord::BrandingSet { by, .. } => RecordView::BrandingSet { by: *by },
        TenantRecord::TerminologySet { by, .. } => RecordView::TerminologySet { by: *by },
        TenantRecord::MailRelaySet { by, .. } => RecordView::MailRelaySet { by: *by },
    }
}

fn observed(s: &TenantState) -> Observed {
    let t = s.settings();
    let d = s.defaults();
    Observed {
        validated: s.validated().iter().copied().map(step_view).collect(),
        admins: s.admins().clone(),
        approvals: s
            .approvals()
            .iter()
            .map(|(id, a)| {
                (
                    id.raw(),
                    Approval {
                        approver: a.approver,
                        grant: Grant {
                            grantee: a.grant.grantee,
                            programme: a.grant.programme,
                            role: a.grant.role,
                        },
                        used: a.used,
                    },
                )
            })
            .collect(),
        settings: Settings {
            p20: t.p20.map(payment_view),
            p69: t.p69.clone(),
            p70: t.p70.iter().copied().map(login_view).collect(),
            p71_us: t.p71_us,
            p72_idle_us: t.p72_idle_us,
            p72_absolute_us: t.p72_absolute_us,
            p74: mcp_view(&t.p74),
        },
        defaults: Defaults {
            p18: d.p18.map(|m| m.into_iter().map(verify_view).collect()),
            p45: d.p45.map(rp_view),
            p21: d.p21.as_ref().map(inference_default_view),
        },
        inference: s.inference().map(|i| Inference {
            config: i.config,
            primary: i.primary.as_str().to_string(),
            fallbacks: i.fallbacks.iter().map(|f| f.as_str().to_string()).collect(),
        }),
        completed: s.completed(),
        signatories: s
            .signatories()
            .iter()
            .map(|(r, a)| (signatory_view(*r), *a))
            .collect(),
    }
}
