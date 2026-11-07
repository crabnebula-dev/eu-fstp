//! The tenant state, its fold and its projection (design section 3.5).
//!
//! The state is a fold of tenant records over a genesis that names the
//! first tenant admin and the kind of cell. The admin set and the SoD-07
//! approvals live here, so they have the ledger's replay and append-only
//! guarantees (Q31 A, interim pending Daniel).
//!
//! The tenant-wide signatory bindings (NOTE 5) and the activation of the
//! organisation live here too. Activation is a request by one tenant
//! admin and an approval by another (SoD-18), each while both signatory
//! roles have a holder (SoD-14, SoD-15). Once the organisation is active,
//! the last holder of either role stays (SoD-17).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, LlmConfigId};
use fstp_domain::time::Timestamp;

use crate::command::TenantRecord;
use crate::refusal::{FoldError, TenantRefusal};
use crate::rules::{
    P69_DEFAULT, P71_DEFAULT_US, P72_ABSOLUTE_DEFAULT_US, P72_IDLE_DEFAULT_US, https_address,
    mail_relay_valid, models_valid, p74_default, prober_milestone, setting_valid, values_check,
};
use crate::types::{
    Activation, ActivationRequestId, ApprovalId, CellKind, GrantRef, GuideNoticeOverride,
    InferenceDefault, InvitationId, LoginMethod, MailRelay, McpSettings, ModelRef, OnboardingStep,
    PaymentMode, RpMode, SettingValue, SignatoryRole, StepFailure, StepOutcome, StepStatus,
    StepValues, TenantRevision, TokenDigest, VerifyMethod,
};

/// The tenant settings, as the projection shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantSettings {
    /// P-20, or `None` while no tenant admin has chosen one. The spec
    /// gives no default.
    pub p20: Option<PaymentMode>,
    /// P-69, an SPDX identifier.
    pub p69: String,
    /// P-70, the enabled login methods. Always holds passkeys.
    pub p70: BTreeSet<LoginMethod>,
    /// P-71 in microseconds.
    pub p71_us: i64,
    /// P-72 idle lifetime in microseconds.
    pub p72_idle_us: i64,
    /// P-72 absolute lifetime in microseconds.
    pub p72_absolute_us: i64,
    /// P-74.
    pub p74: McpSettings,
    /// The tenant's override of the Guide's data protection texts, or
    /// `None` for the platform default ([`TenantSettings::guide_notice`]).
    pub guide_notice: Option<GuideNoticeOverride>,
}

impl TenantSettings {
    /// The Default column of `policy-parameters.md`.
    pub fn spec_defaults() -> TenantSettings {
        TenantSettings {
            p20: None,
            p69: P69_DEFAULT.to_owned(),
            p70: [LoginMethod::Passkey].into_iter().collect(),
            p71_us: P71_DEFAULT_US,
            p72_idle_us: P72_IDLE_DEFAULT_US,
            p72_absolute_us: P72_ABSOLUTE_DEFAULT_US,
            p74: p74_default(),
            guide_notice: None,
        }
    }

    /// The Guide's data protection texts: the tenant's override, or the
    /// platform default (R-GA-01; section 15.0 of the M4 design,
    /// 2026-11-06).
    pub fn guide_notice(&self) -> GuideNotice<'_> {
        match &self.guide_notice {
            Some(o) => GuideNotice::Tenant(o),
            None => GuideNotice::Platform,
        }
    }

    fn set(&mut self, value: &SettingValue) {
        match value {
            SettingValue::P20(m) => self.p20 = Some(*m),
            SettingValue::P69(id) => self.p69.clone_from(id),
            SettingValue::P70(m) => self.p70.clone_from(m),
            SettingValue::P71 { us } => self.p71_us = *us,
            SettingValue::P72 {
                idle_us,
                absolute_us,
            } => {
                self.p72_idle_us = *idle_us;
                self.p72_absolute_us = *absolute_us;
            }
            SettingValue::P74(m) => self.p74 = m.clone(),
        }
    }
}

/// The platform default of the Guide's data protection summary,
/// `{{gdpr.notice_summary}}` (R-GA-01; Daniel's answer of 2026-11-06).
/// Daniel supplies the approved wording. Until then it says so, and no
/// legal text is made up here.
pub const PLATFORM_DATA_PROTECTION_SUMMARY: &str =
    "TODO(legal): the platform data protection summary awaits approved wording from Daniel.";

/// The platform default of the Guide's privacy statement address,
/// `{{funder.privacy_statement_url}}`. TODO(legal): Daniel supplies the
/// address. Until then it is a reserved name that resolves nowhere
/// (RFC 2606).
pub const PLATFORM_PRIVACY_STATEMENT_URL: &str = "https://privacy-statement.invalid/todo-legal";

/// Where the Guide's data protection texts come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuideNotice<'a> {
    /// The platform default: [`PLATFORM_DATA_PROTECTION_SUMMARY`] and
    /// [`PLATFORM_PRIVACY_STATEMENT_URL`].
    Platform,
    /// The tenant's override.
    Tenant(&'a GuideNoticeOverride),
}

/// The tenant defaults that prefill new drafts. They are never parameters
/// (design sections 3.1 and 3.5, Q36 A interim). A default shows only
/// while the latest save of its step validated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantDefaults {
    /// The P-18 default.
    pub p18: Option<BTreeSet<VerifyMethod>>,
    /// The P-45 default.
    pub p45: Option<RpMode>,
    /// The P-21 default.
    pub p21: Option<InferenceDefault>,
}

/// An issued admin invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminInvitation {
    /// The account the invitation is for.
    pub invitee: AccountId,
    /// The digest of the invitation token.
    pub token_digest: TokenDigest,
    /// Whether the invitee took it.
    pub taken: bool,
}

/// A recorded SoD-07 approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfGrantApproval {
    /// The approving tenant admin.
    pub approver: AccountId,
    /// The approved self-grant.
    pub grant: GrantRef,
    /// The instant of the approval.
    pub approved_at: Timestamp,
    /// The last instant at which the self-grant may use it: P-71 after
    /// the approval, as M3 builds it (interim, pending Daniel).
    pub expires_at: Timestamp,
    /// Whether the self-grant used it. An approval admits one grant
    /// (TH-05).
    pub used: bool,
}

/// The latest inference configuration record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceConfig {
    /// The pinned LLM configuration.
    pub config: LlmConfigId,
    /// The primary model.
    pub primary: ModelRef,
    /// The ordered fallbacks.
    pub fallbacks: Vec<ModelRef>,
}

/// The tenant state of one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantState {
    cell: CellKind,
    revision: TenantRevision,
    admins: BTreeSet<AccountId>,
    invitations: BTreeMap<InvitationId, AdminInvitation>,
    approvals: BTreeMap<ApprovalId, SelfGrantApproval>,
    /// The latest save of each step, with its current outcome.
    saved: BTreeMap<OnboardingStep, (StepValues, StepOutcome)>,
    validated: BTreeSet<OnboardingStep>,
    settings: TenantSettings,
    configs: BTreeSet<LlmConfigId>,
    inference: Option<InferenceConfig>,
    completed: bool,
    /// The signatory bindings held now, by role and account (NOTE 5).
    signatories: BTreeSet<(SignatoryRole, AccountId)>,
    /// The activation of the organisation (SoD-18).
    activation: Activation,
    branding: Option<(fstp_brand::BrandTokens, fstp_domain::id::ContentDigest)>,
    terminology: Option<crate::types::Terminology>,
    /// The mail submission relay (ADR-018, proposed).
    mail_relay: Option<MailRelay>,
}

/// The instant `t`, or [`TenantRefusal::InvalidInstant`] when it lies
/// outside the ledger's range of 0 to `fstp_ledger::MAX_AT`.
fn instant(t: Timestamp) -> Result<Timestamp, TenantRefusal> {
    if (0..=fstp_ledger::MAX_AT).contains(&t.micros()) {
        Ok(t)
    } else {
        Err(TenantRefusal::InvalidInstant)
    }
}

impl TenantState {
    /// The genesis of a cell of kind `cell`. `first_admin`, enrolled
    /// through the one-time link of the control plane (or the enrolment
    /// token of a self-hosted cell), is the only tenant admin. The
    /// settings are the spec defaults, and no step is saved.
    pub fn genesis(first_admin: AccountId, cell: CellKind) -> TenantState {
        TenantState {
            cell,
            revision: TenantRevision::GENESIS,
            admins: [first_admin].into_iter().collect(),
            invitations: BTreeMap::new(),
            approvals: BTreeMap::new(),
            saved: BTreeMap::new(),
            validated: BTreeSet::new(),
            settings: TenantSettings::spec_defaults(),
            configs: BTreeSet::new(),
            inference: None,
            completed: false,
            signatories: BTreeSet::new(),
            activation: Activation::NotRequested,
            branding: None,
            terminology: None,
            mail_relay: None,
        }
    }

    /// Folds `records` into the genesis of `first_admin` in a cell of kind
    /// `cell`.
    pub fn replay<'a>(
        first_admin: AccountId,
        cell: CellKind,
        records: impl IntoIterator<Item = &'a TenantRecord>,
    ) -> Result<TenantState, FoldError> {
        let mut s = TenantState::genesis(first_admin, cell);
        for r in records {
            s.apply(r)?;
        }
        Ok(s)
    }

    /// Folds the records of one accepted command. On an error the state
    /// is unchanged.
    pub fn apply_all(&mut self, records: &[TenantRecord]) -> Result<(), FoldError> {
        let mut next = self.clone();
        for r in records {
            next.apply(r)?;
        }
        *self = next;
        Ok(())
    }

    /// Folds one record. The fold checks again every rule that the record
    /// alone can show, so a ledger that breaks one refuses to fold. On an
    /// error the state may be partly changed; [`Self::apply_all`] keeps it
    /// whole.
    ///
    /// Answers from outside (the prober, the control plane, the vault)
    /// exist only when `decide` runs, so the fold cannot check them again.
    pub fn apply(&mut self, record: &TenantRecord) -> Result<(), FoldError> {
        let refuse = |r: TenantRefusal| Err(FoldError(r));
        match record {
            TenantRecord::StepSaved {
                values,
                by,
                outcome,
            } => {
                self.need_admin(*by)?;
                let step = values.step();
                self.check_saveable(step).map_err(FoldError)?;
                if *outcome == StepOutcome::Validated
                    && (values_check(values, self).is_err()
                        || (step == OnboardingStep::Administrators
                            && (self.admins.len() < 2 || self.missing_signatory().is_some())))
                {
                    return refuse(TenantRefusal::Inconsistent);
                }
                self.validated.remove(&step);
                self.saved.insert(step, (values.clone(), *outcome));
            }
            TenantRecord::StepValidated { step, by } => {
                self.need_admin(*by)?;
                let saved_ok = self
                    .saved
                    .get(step)
                    .is_some_and(|(_, o)| *o == StepOutcome::Validated);
                if !saved_ok || self.validated.contains(step) {
                    return refuse(TenantRefusal::Inconsistent);
                }
                self.validated.insert(*step);
            }
            TenantRecord::AdminInvited {
                invitation,
                invitee,
                token_digest,
                by,
            } => {
                self.need_admin(*by)?;
                self.check_invite(*invitation, *invitee)
                    .map_err(FoldError)?;
                self.invitations.insert(
                    *invitation,
                    AdminInvitation {
                        invitee: *invitee,
                        token_digest: *token_digest,
                        taken: false,
                    },
                );
            }
            TenantRecord::AdminAdded {
                account,
                invitation,
            } => {
                let digest = self
                    .invitations
                    .get(invitation)
                    .map(|i| i.token_digest)
                    .ok_or(FoldError(TenantRefusal::InvitationNotOpen))?;
                self.check_accept(*invitation, *account, digest)
                    .map_err(FoldError)?;
                if let Some(i) = self.invitations.get_mut(invitation) {
                    i.taken = true;
                }
                self.admins.insert(*account);
            }
            TenantRecord::SelfGrantApproved {
                approval,
                grant,
                by,
                at,
            } => {
                self.need_admin(*by)?;
                self.check_approval(*approval, grant, *by)
                    .map_err(FoldError)?;
                let expires_at = self.approval_expiry(*at).map_err(FoldError)?;
                self.approvals.insert(
                    *approval,
                    SelfGrantApproval {
                        approver: *by,
                        grant: *grant,
                        approved_at: *at,
                        expires_at,
                        used: false,
                    },
                );
            }
            TenantRecord::SelfGrantApprovalUsed { approval, by, at } => {
                self.need_admin(*by)?;
                let grant = self
                    .approvals
                    .get(approval)
                    .map(|a| a.grant)
                    .ok_or(FoldError(TenantRefusal::ApprovalNotOpen))?;
                self.check_use(*approval, &grant, *by, *at)
                    .map_err(FoldError)?;
                if let Some(a) = self.approvals.get_mut(approval) {
                    a.used = true;
                }
            }
            TenantRecord::GuideNoticeSet { notice, by } => {
                self.need_admin(*by)?;
                if notice
                    .as_ref()
                    .is_some_and(|n| !https_address(&n.privacy_statement_url))
                {
                    return refuse(TenantRefusal::Inconsistent);
                }
                self.settings.guide_notice.clone_from(notice);
            }
            TenantRecord::SettingChanged { value, by } => {
                self.need_admin(*by)?;
                if !setting_valid(value) {
                    return refuse(TenantRefusal::InvalidSetting(value.param()));
                }
                self.settings.set(value);
                if matches!(value, SettingValue::P20(_)) {
                    self.recheck_payments();
                }
            }
            TenantRecord::InferenceConfigRecorded {
                config,
                primary,
                fallbacks,
                by,
            } => {
                self.need_admin(*by)?;
                self.check_inference_record(*config, primary, fallbacks)
                    .map_err(FoldError)?;
                self.configs.insert(*config);
                self.inference = Some(InferenceConfig {
                    config: *config,
                    primary: primary.clone(),
                    fallbacks: fallbacks.clone(),
                });
            }
            TenantRecord::OnboardingCompleted { by } => {
                self.need_admin(*by)?;
                self.check_completion().map_err(FoldError)?;
                self.completed = true;
            }
            TenantRecord::SignatoryGranted {
                role,
                account,
                by,
                at,
            } => {
                self.need_admin(*by)?;
                instant(*at).map_err(FoldError)?;
                self.check_grant_signatory(*by, *role, *account)
                    .map_err(FoldError)?;
                self.signatories.insert((*role, *account));
            }
            TenantRecord::SignatoryEnded {
                role,
                account,
                by,
                at,
            } => {
                self.need_admin(*by)?;
                instant(*at).map_err(FoldError)?;
                self.check_end_signatory(*role, *account)
                    .map_err(FoldError)?;
                self.signatories.remove(&(*role, *account));
            }
            TenantRecord::ActivationRequested { request, by, at } => {
                self.need_admin(*by)?;
                instant(*at).map_err(FoldError)?;
                self.check_request().map_err(FoldError)?;
                self.activation = Activation::Requested {
                    request: *request,
                    by: *by,
                };
            }
            TenantRecord::ActivationApproved { request, by, at } => {
                self.need_admin(*by)?;
                instant(*at).map_err(FoldError)?;
                let requested_by = self.check_approve(*request, *by).map_err(FoldError)?;
                self.activation = Activation::Active {
                    request: *request,
                    requested_by,
                    approved_by: *by,
                };
            }
            TenantRecord::BrandingSet { tokens, digest, by } => {
                self.need_admin(*by)?;
                crate::decide::check_branding(tokens).map_err(FoldError)?;
                self.branding = Some((tokens.clone(), *digest));
            }
            TenantRecord::TerminologySet { terminology, by } => {
                self.need_admin(*by)?;
                crate::decide::check_terminology(terminology).map_err(FoldError)?;
                self.terminology = Some(terminology.clone());
            }
            TenantRecord::MailRelaySet { relay, by } => {
                self.need_admin(*by)?;
                if relay.as_ref().is_some_and(|r| !mail_relay_valid(r)) {
                    return refuse(TenantRefusal::Inconsistent);
                }
                self.mail_relay.clone_from(relay);
            }
        }
        self.revision = self.revision.next();
        Ok(())
    }

    fn need_admin(&self, a: AccountId) -> Result<(), FoldError> {
        if self.is_admin(a) {
            Ok(())
        } else {
            Err(FoldError(TenantRefusal::NotTenantAdmin))
        }
    }

    /// A change of P-20 checks the validated Payments step again with the
    /// new mode. If the saved values no longer pass, the step is no longer
    /// validated and shows why (R-TN-01: "bank interface where execution
    /// mode is used").
    fn recheck_payments(&mut self) {
        let step = OnboardingStep::Payments;
        if !self.validated.contains(&step) {
            return;
        }
        let failure = match self.saved.get(&step) {
            Some((values, _)) => values_check(values, self).err(),
            None => Some(StepFailure::InvalidValues),
        };
        if let Some(f) = failure {
            self.validated.remove(&step);
            if let Some(entry) = self.saved.get_mut(&step) {
                entry.1 = StepOutcome::Failed(f);
            }
        }
    }

    /// Whether `step` may be saved now: the tenant goes through it in this
    /// kind of cell, and every earlier step is done (R-TN-01).
    pub(crate) fn check_saveable(&self, step: OnboardingStep) -> Result<(), TenantRefusal> {
        if !step.required_in(self.cell) {
            Err(TenantRefusal::StepSkipped)
        } else if !self.is_open(step) {
            Err(TenantRefusal::StepLocked)
        } else {
            Ok(())
        }
    }

    /// The rule of a new invitation: the id is unused and the invitee is
    /// not a tenant admin.
    pub(crate) fn check_invite(
        &self,
        invitation: InvitationId,
        invitee: AccountId,
    ) -> Result<(), TenantRefusal> {
        if self.invitations.contains_key(&invitation) {
            Err(TenantRefusal::InvitationTaken)
        } else if self.is_admin(invitee) {
            Err(TenantRefusal::AlreadyAdmin)
        } else {
            Ok(())
        }
    }

    /// The rule of taking `invitation` as `account` with the token digest
    /// `digest`: the invitation is open, `account` is its invitee, the
    /// digest is the recorded one, and `account` is not an admin yet.
    pub(crate) fn check_accept(
        &self,
        invitation: InvitationId,
        account: AccountId,
        digest: TokenDigest,
    ) -> Result<(), TenantRefusal> {
        let Some(i) = self.invitations.get(&invitation).filter(|i| !i.taken) else {
            return Err(TenantRefusal::InvitationNotOpen);
        };
        if i.invitee != account || i.token_digest != digest {
            Err(TenantRefusal::InvitationMismatch)
        } else if self.is_admin(account) {
            Err(TenantRefusal::AlreadyAdmin)
        } else {
            Ok(())
        }
    }

    /// The SoD-07 rule of one approval by `approver`: the id is unused,
    /// the grantee is a tenant admin, and the approver is a different
    /// account (NOTE 3: per account).
    pub(crate) fn check_approval(
        &self,
        approval: ApprovalId,
        grant: &GrantRef,
        approver: AccountId,
    ) -> Result<(), TenantRefusal> {
        if self.approvals.contains_key(&approval) {
            Err(TenantRefusal::ApprovalTaken)
        } else if !self.is_admin(grant.grantee) {
            Err(TenantRefusal::GranteeNotAdmin)
        } else if grant.grantee == approver {
            Err(TenantRefusal::SelfApproval)
        } else {
            Ok(())
        }
    }

    /// The last instant an approval given at `at` admits its self-grant:
    /// `at` plus P-71 (interim, pending Daniel, as M3's
    /// `fstp_cell_core` builds it).
    pub(crate) fn approval_expiry(&self, at: Timestamp) -> Result<Timestamp, TenantRefusal> {
        let at = instant(at)?;
        let end = at
            .micros()
            .checked_add(self.settings.p71_us)
            .ok_or(TenantRefusal::InvalidInstant)?;
        instant(Timestamp::from_micros(end))
    }

    /// The rule of using `approval` for `grant` as `by` at `at`: the
    /// approval exists and is unused, it names exactly this grant, `by` is
    /// the grantee, and the approval has not lapsed (TH-05).
    pub(crate) fn check_use(
        &self,
        approval: ApprovalId,
        grant: &GrantRef,
        by: AccountId,
        at: Timestamp,
    ) -> Result<(), TenantRefusal> {
        let at = instant(at)?;
        let Some(a) = self.approvals.get(&approval) else {
            return Err(TenantRefusal::ApprovalNotOpen);
        };
        if a.used || a.grant != *grant || grant.grantee != by {
            Err(TenantRefusal::ApprovalNotOpen)
        } else if at > a.expires_at {
            Err(TenantRefusal::ApprovalExpired)
        } else {
            Ok(())
        }
    }

    /// The rule of an inference record (design 3.5, interim pending
    /// Daniel): the id is new, the models meet the P-21 rule, and they
    /// equal the P-21 default of the validated Inference step. So the
    /// model `call.publish` takes is the one new drafts are prefilled
    /// with.
    pub(crate) fn check_inference_record(
        &self,
        config: LlmConfigId,
        primary: &ModelRef,
        fallbacks: &[ModelRef],
    ) -> Result<(), TenantRefusal> {
        if !models_valid(primary, fallbacks) {
            return Err(TenantRefusal::InvalidModels);
        }
        if self.configs.contains(&config) {
            return Err(TenantRefusal::ConfigTaken);
        }
        match self.defaults().p21 {
            Some(d) if d.primary == *primary && d.fallbacks == fallbacks => Ok(()),
            _ => Err(TenantRefusal::NotDefaultModels),
        }
    }

    /// The completion rules the state alone can show: not yet completed,
    /// every step the cell requires validated and at least two tenant
    /// admins (SoD-07).
    pub(crate) fn check_completion(&self) -> Result<(), TenantRefusal> {
        if self.completed {
            Err(TenantRefusal::AlreadyCompleted)
        } else if !self.all_steps_done() {
            Err(TenantRefusal::StepsNotValidated)
        } else if self.admins.len() < 2 {
            Err(TenantRefusal::TooFewAdmins)
        } else {
            Ok(())
        }
    }

    /// The rule of a grant of `role` to `account` by the admin `by`: no
    /// grant to one's own account (SoD-07, NOTE 5), and no second binding
    /// of a role the account holds (M4 design section 15.0). NOTE 5: no
    /// verified identity is needed, since SoD-09 covers Drafting and
    /// Judging only.
    pub(crate) fn check_grant_signatory(
        &self,
        by: AccountId,
        role: SignatoryRole,
        account: AccountId,
    ) -> Result<(), TenantRefusal> {
        if account == by {
            Err(TenantRefusal::SignatorySelfGrant)
        } else if self.signatories.contains(&(role, account)) {
            Err(TenantRefusal::SignatoryHeld)
        } else {
            Ok(())
        }
    }

    /// The rule of ending `account`'s binding of `role`: the binding is
    /// held, and while the organisation is active it is not the role's
    /// last holder (SoD-17).
    pub(crate) fn check_end_signatory(
        &self,
        role: SignatoryRole,
        account: AccountId,
    ) -> Result<(), TenantRefusal> {
        if !self.signatories.contains(&(role, account)) {
            Err(TenantRefusal::SignatoryNotHeld)
        } else if self.is_active() && self.holders(role).count() <= 1 {
            Err(TenantRefusal::LastSignatory)
        } else {
            Ok(())
        }
    }

    /// The refusal of a missing holder of `role` (SoD-14, SoD-15).
    const fn no_holder(role: SignatoryRole) -> TenantRefusal {
        match role {
            SignatoryRole::Financial => TenantRefusal::NoFinancialSignatory,
            SignatoryRole::Legal => TenantRefusal::NoLegalSignatory,
        }
    }

    /// The rules of an activation request: the organisation is not active
    /// and no request is open (SoD-18), each signatory role has a holder
    /// (SoD-14, SoD-15), every required step is validated (R-TN-01), and
    /// at least two tenant admins exist (SoD-07). The signatory rules come
    /// first, so a refusal names the missing role even where the
    /// Administrators step is not validated for that reason.
    pub(crate) fn check_request(&self) -> Result<(), TenantRefusal> {
        match self.activation {
            Activation::Active { .. } => return Err(TenantRefusal::AlreadyActive),
            Activation::Requested { .. } => return Err(TenantRefusal::ActivationPending),
            Activation::NotRequested => {}
        }
        if let Some(role) = self.missing_signatory() {
            return Err(TenantState::no_holder(role));
        }
        if !self.all_steps_done() {
            Err(TenantRefusal::StepsNotValidated)
        } else if self.admins.len() < 2 {
            Err(TenantRefusal::TooFewAdmins)
        } else {
            Ok(())
        }
    }

    /// The rules of an approval of `request` by the admin `by`: it names
    /// the open request, `by` did not request it (SoD-18), and each
    /// signatory role has a holder at this instant (SoD-14, SoD-15). The
    /// steps are checked again, since a P-20 change can leave Payments not
    /// validated after the request. Returns the requester.
    pub(crate) fn check_approve(
        &self,
        request: ActivationRequestId,
        by: AccountId,
    ) -> Result<AccountId, TenantRefusal> {
        let (open, requester) = match self.activation {
            Activation::Requested { request, by } => (request, by),
            Activation::Active { .. } => return Err(TenantRefusal::AlreadyActive),
            Activation::NotRequested => return Err(TenantRefusal::ActivationNotOpen),
        };
        if open != request {
            return Err(TenantRefusal::ActivationNotOpen);
        }
        if requester == by {
            return Err(TenantRefusal::SelfActivationApproval);
        }
        if let Some(role) = self.missing_signatory() {
            return Err(TenantState::no_holder(role));
        }
        if !self.all_steps_done() {
            Err(TenantRefusal::StepsNotValidated)
        } else if self.admins.len() < 2 {
            Err(TenantRefusal::TooFewAdmins)
        } else {
            Ok(requester)
        }
    }

    /// The accounts that hold `role` now, in account order.
    pub fn holders(&self, role: SignatoryRole) -> impl Iterator<Item = AccountId> + '_ {
        self.signatories
            .iter()
            .filter(move |(r, _)| *r == role)
            .map(|(_, a)| *a)
    }

    /// The signatory bindings held now, by role then account (NOTE 5).
    pub fn signatories(&self) -> &BTreeSet<(SignatoryRole, AccountId)> {
        &self.signatories
    }

    /// Whether `account` holds `role` now.
    pub fn holds_signatory(&self, role: SignatoryRole, account: AccountId) -> bool {
        self.signatories.contains(&(role, account))
    }

    /// The first signatory role with no holder, Financial first (SoD-14,
    /// SoD-15), if any.
    pub fn missing_signatory(&self) -> Option<SignatoryRole> {
        SignatoryRole::ALL
            .into_iter()
            .find(|r| self.holders(*r).next().is_none())
    }

    /// The activation of the organisation (SoD-18).
    pub fn activation(&self) -> Activation {
        self.activation
    }

    /// The latest brand tokens and their digest, or `None` while the
    /// tenant shows the platform brand (M9 design section 2.1).
    pub fn branding(&self) -> Option<(&fstp_brand::BrandTokens, fstp_domain::id::ContentDigest)> {
        self.branding.as_ref().map(|(t, d)| (t, *d))
    }

    /// The latest terminology and Voyage switch, or `None` while the tenant
    /// shows the plain pack without overrides (M9 lane T1).
    pub fn terminology(&self) -> Option<&crate::types::Terminology> {
        self.terminology.as_ref()
    }

    /// Whether a second tenant admin approved the activation, so the
    /// organisation is active (SoD-17, SoD-18).
    pub fn is_active(&self) -> bool {
        matches!(self.activation, Activation::Active { .. })
    }

    fn done(&self, step: OnboardingStep) -> bool {
        !step.required_in(self.cell) || self.validated.contains(&step)
    }

    fn all_steps_done(&self) -> bool {
        OnboardingStep::ALL.iter().all(|s| self.done(*s))
    }

    /// The kind of cell, as the genesis named it.
    pub fn cell(&self) -> CellKind {
        self.cell
    }

    /// The number of records folded so far.
    pub fn revision(&self) -> TenantRevision {
        self.revision
    }

    /// The tenant admin set (Q31).
    pub fn admins(&self) -> &BTreeSet<AccountId> {
        &self.admins
    }

    /// Whether `a` is a tenant admin now.
    pub fn is_admin(&self, a: AccountId) -> bool {
        self.admins.contains(&a)
    }

    /// Whether `invitation` was issued.
    pub fn invitation_issued(&self, invitation: InvitationId) -> bool {
        self.invitations.contains_key(&invitation)
    }

    /// Whether `invitation` was issued and not yet taken.
    pub fn invitation_open(&self, invitation: InvitationId) -> bool {
        self.invitations.get(&invitation).is_some_and(|i| !i.taken)
    }

    /// The issued invitation `invitation`, if any.
    pub fn invitation(&self, invitation: InvitationId) -> Option<&AdminInvitation> {
        self.invitations.get(&invitation)
    }

    /// The recorded SoD-07 approvals.
    pub fn approvals(&self) -> &BTreeMap<ApprovalId, SelfGrantApproval> {
        &self.approvals
    }

    /// Whether every step before `step` is done, so `step` takes saves
    /// (R-TN-01). A step the cell skips counts as done.
    pub fn is_open(&self, step: OnboardingStep) -> bool {
        step.before().all(|s| self.done(s))
    }

    /// The validated steps. A skipped step is never in the set.
    pub fn validated(&self) -> &BTreeSet<OnboardingStep> {
        &self.validated
    }

    /// The latest saved values of `step`.
    pub fn saved_values(&self, step: OnboardingStep) -> Option<&StepValues> {
        self.saved.get(&step).map(|(v, _)| v)
    }

    /// The current outcome of the latest save of `step`, as the step view
    /// names it. A change of P-20 may turn a validated Payments save into
    /// a failed one (lane m4tenant: the read model shows it).
    pub fn saved_outcome(&self, step: OnboardingStep) -> Option<StepOutcome> {
        self.saved.get(&step).map(|(_, o)| *o)
    }

    /// The status of `step` for the onboarding view.
    pub fn status(&self, step: OnboardingStep) -> StepStatus {
        if !step.required_in(self.cell) {
            return StepStatus::Skipped;
        }
        if !self.is_open(step) {
            return StepStatus::Locked;
        }
        if self.validated.contains(&step) {
            return StepStatus::Validated;
        }
        match self.saved.get(&step).map(|(_, o)| *o) {
            None => StepStatus::Open,
            Some(StepOutcome::Failed(StepFailure::ProberAbsent)) => StepStatus::Unavailable {
                milestone: prober_milestone(step),
            },
            Some(StepOutcome::Failed(StepFailure::Unavailable(milestone))) => {
                StepStatus::Unavailable { milestone }
            }
            Some(_) => StepStatus::Saved,
        }
    }

    /// The tenant settings.
    pub fn settings(&self) -> &TenantSettings {
        &self.settings
    }

    /// The tenant defaults: the values of the Identity and Inference
    /// steps while each is validated.
    pub fn defaults(&self) -> TenantDefaults {
        let mut d = TenantDefaults::default();
        for step in [OnboardingStep::Identity, OnboardingStep::Inference] {
            if !self.validated.contains(&step) {
                continue;
            }
            match self.saved_values(step) {
                Some(StepValues::Identity { p18, p45 }) => {
                    d.p18 = Some(p18.clone());
                    d.p45 = Some(*p45);
                }
                Some(StepValues::Inference(i)) => d.p21 = Some(i.clone()),
                _ => {}
            }
        }
        d
    }

    /// Whether an inference record under `config` exists. A configuration
    /// id is recorded once.
    pub fn inference_config_taken(&self, config: LlmConfigId) -> bool {
        self.configs.contains(&config)
    }

    /// The mail submission relay, or `None` while none is set (ADR-018).
    pub fn mail_relay(&self) -> Option<&MailRelay> {
        self.mail_relay.as_ref()
    }

    /// The latest inference configuration record.
    pub fn inference(&self) -> Option<&InferenceConfig> {
        self.inference.as_ref()
    }

    /// The configuration and model `call.publish` takes: those of the
    /// latest inference record, never from the client. `None` before any
    /// record, so publication fails closed.
    pub fn publication_config(&self) -> Option<(LlmConfigId, &ModelRef)> {
        self.inference.as_ref().map(|i| (i.config, &i.primary))
    }

    /// Whether an `OnboardingCompleted` record exists. This is history:
    /// a later save or a P-20 change may leave a step not validated, and
    /// this stays true. [`Self::onboarded`] gives the current answer.
    pub fn completed(&self) -> bool {
        self.completed
    }

    /// Whether onboarding was completed and still holds now: every step
    /// the cell requires is validated and at least two tenant admins
    /// exist (SoD-07). The vault's verification of each admin is checked
    /// at completion only, since the state does not hold it.
    pub fn onboarded(&self) -> bool {
        self.completed && self.all_steps_done() && self.admins.len() >= 2
    }
}
