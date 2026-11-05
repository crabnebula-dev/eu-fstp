//! The reference of lane W2d, written from the spec text and design
//! section 3.5, never from the production code.
//!
//! Sources and readings, rule by rule:
//!
//! - **Actor.** Every tenant command is a tenant admin command. The admin
//!   set is the ledger's own (Q31 A, interim pending Daniel). The one
//!   exception is the invitee who takes an admin invitation.
//! - **I-85 and I-78.** Inviting an admin, approving a self-grant and
//!   changing a setting are high-risk (design 3.5, 3.6). Taking an admin
//!   invitation and using a self-grant approval each complete a grant.
//!   Each of these that arrives through MCP is refused, as the domain
//!   refuses its own high-risk kinds (interim pending Daniel: defence in
//!   depth).
//! - **Invitations.** An invitation names its invitee, and only the
//!   invitee takes it. Its token stays out of the ledger: a reader of the
//!   ledger cannot take it (`authentication.md`, granting tenant admin is
//!   high-risk).
//! - **SoD-03.** A tenant admin counts as holding Operations in every
//!   programme, so an account with a Receiving binding cannot take an
//!   admin invitation.
//! - **R-TN-01.** "Each step validates before the next opens. The tenant
//!   can save and return at any point." A step is open when every earlier
//!   step is validated. A save of an open step is accepted. It validates
//!   the step when the values pass, and otherwise leaves it saved but not
//!   validated. A save of a step that is not open is refused.
//! - **Q22.** The Agreements step validates only when the control plane
//!   recorded the acceptance of the saved versions.
//! - **P-20.** The Payments step captures the payment mode and a bank
//!   interface where execution mode is used. It validates only in
//!   record-only mode without a bank interface, since bank interfaces
//!   arrive with M5. A change of P-20 to execution mode leaves the step
//!   not validated.
//! - **Q5.** The sending domain and channel checks need a prober. Without
//!   one they fail closed. A recording fake answers each probe.
//! - **SoD-07.** The Administrators step validates with at least two tenant
//!   admins, and (SoD-14, SoD-15, `programme-creator.md` onboarding table)
//!   with at least one holder of each signatory role. Completing onboarding needs every step validated, at least
//!   two admins, and every admin verified (design J0, Q2 B interim).
//! - **Signatory roles** (NOTE 5, SA-01). A tenant admin grants Financial or
//!   Legal signatory to an account. The grant is high-risk (I-78: an
//!   Operations role). A grant to the granting admin's own account is
//!   refused (SoD-07: no second admin approves it in this model). A second
//!   grant of a held role is refused (design 15.0). SoD-03 bars an account
//!   with a Receiving binding, as for tenant admin. No verified identity is
//!   needed (SoD-09). One account may hold both (SoD-16). An end of a held
//!   binding completes. No activation runs here, so SoD-17 never binds.
//! - **SoD-07 approvals.** The approver is a tenant admin, the grantee is a
//!   tenant admin, and they are different accounts (NOTE 3: per account).
//!   The self-grant uses its approval once (TH-05). Every run has one
//!   fixed instant, so no approval lapses here.
//! - **Ids.** An invitation, approval or configuration id is used once, as
//!   the domain refuses a taken id.
//! - **P-70.** Passkeys are always enabled.
//! - **P-71.** Positive and no longer than the default: "may only shorten".
//!   This is the reading of `fstp_auth::stepup::validate_p71`.
//! - **P-72.** Positive and no longer than each default. This is the
//!   strict reading M3 built in `fstp_cell_core::tenant` (Q37).
//! - **P-69.** An SPDX identifier.
//! - **P-21 and NOTE 10.** A primary model and an ordered list of distinct
//!   fallbacks, none equal to the primary and none empty (interim strict
//!   reading: a duplicate replacement would never change the model).
//! - **Inference record.** It records the models of the validated
//!   Inference step (design 3.5: "The Inference step also records an
//!   `InferenceConfigRecorded` entry"), so it needs that step's P-21
//!   default and the same models.
//! - **Tenant defaults.** Only the values of a save that validated its
//!   step prefill drafts. While the latest save of the step failed, the
//!   default is absent.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::Via;
use fstp_domain::id::{AccountId, LlmConfigId};
use fstp_domain::rules::ParamId;

use super::vocab::{
    Approval, Defaults, Env, Inference, InferenceDefault, LoginMethod, Observed, Op,
    P71_DEFAULT_US, P72_ABSOLUTE_DEFAULT_US, P72_IDLE_DEFAULT_US, PaymentMode, Probes, RecordView,
    Setting, Settings, Signatory, Step, StepInput, VALID_SPDX, Verdict, spec_default_settings,
};

/// One issued invitation in the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefInvitation {
    /// The account it is for.
    pub invitee: AccountId,
    /// Whether it was taken.
    pub taken: bool,
}

/// The reference state.
#[derive(Clone, Debug)]
pub struct Reference {
    env: Env,
    validated: BTreeSet<Step>,
    admins: BTreeSet<AccountId>,
    invitations: BTreeMap<u128, RefInvitation>,
    approvals: BTreeMap<u128, Approval>,
    settings: Settings,
    defaults: Defaults,
    inference: Option<Inference>,
    configs: BTreeSet<LlmConfigId>,
    completed: bool,
    signatories: BTreeSet<(Signatory, AccountId)>,
}

impl Reference {
    /// The genesis of `env`: the first admin only, spec default settings.
    pub fn new(env: &Env) -> Reference {
        Reference {
            env: env.clone(),
            validated: BTreeSet::new(),
            admins: [env.first_admin].into_iter().collect(),
            invitations: BTreeMap::new(),
            approvals: BTreeMap::new(),
            settings: spec_default_settings(),
            defaults: Defaults::default(),
            inference: None,
            configs: BTreeSet::new(),
            completed: false,
            signatories: BTreeSet::new(),
        }
    }

    /// Whether `a` is a tenant admin now.
    pub fn is_admin(&self, a: AccountId) -> bool {
        self.admins.contains(&a)
    }

    /// The tenant admins now.
    pub fn admins(&self) -> &BTreeSet<AccountId> {
        &self.admins
    }

    /// Whether the step is open: every earlier step is validated.
    pub fn is_open(&self, step: Step) -> bool {
        step.before().iter().all(|s| self.validated.contains(s))
    }

    /// Whether the step is validated.
    pub fn is_validated(&self, step: Step) -> bool {
        self.validated.contains(&step)
    }

    /// The first step that is not validated, if any.
    pub fn next_step(&self) -> Option<Step> {
        Step::ALL.into_iter().find(|s| !self.validated.contains(s))
    }

    /// The open invitations (issued and not taken), with their invitee.
    pub fn open_invitations(&self) -> Vec<(u128, AccountId)> {
        self.invitations
            .iter()
            .filter(|(_, i)| !i.taken)
            .map(|(id, i)| (*id, i.invitee))
            .collect()
    }

    /// The unused approvals, with their grant.
    pub fn open_approvals(&self) -> Vec<(u128, Approval)> {
        self.approvals
            .iter()
            .filter(|(_, a)| !a.used)
            .map(|(id, a)| (*id, *a))
            .collect()
    }

    /// The current P-21 default, if the Inference step is validated.
    pub fn p21_default(&self) -> Option<&InferenceDefault> {
        self.defaults.p21.as_ref()
    }

    /// The current P-20 setting.
    pub fn p20(&self) -> Option<PaymentMode> {
        self.settings.p20
    }

    /// The verdict of `op` in this state.
    pub fn verdict(&self, op: &Op) -> Verdict {
        if self.admits(op) {
            Verdict::Accepted
        } else {
            Verdict::Refused
        }
    }

    fn admits(&self, op: &Op) -> bool {
        if is_web_only(op) && op.via() == Via::Mcp {
            return false;
        }
        if !matches!(op, Op::AcceptAdminInvitation { .. }) && !self.is_admin(op.actor()) {
            return false;
        }
        match op {
            Op::SaveStep { step, input, .. } => self.is_open(*step) && input_fits(*step, input),
            Op::InviteAdmin {
                invitation,
                invitee,
                ..
            } => !self.invitations.contains_key(invitation) && !self.is_admin(*invitee),
            Op::AcceptAdminInvitation {
                account,
                invitation,
                ..
            } => {
                self.invitations
                    .get(invitation)
                    .is_some_and(|i| !i.taken && i.invitee == *account)
                    && !self.is_admin(*account)
                    && !self.env.receiving.contains(account)
            }
            Op::ApproveSelfGrant {
                actor,
                approval,
                grant,
                ..
            } => {
                !self.approvals.contains_key(approval)
                    && self.is_admin(grant.grantee)
                    && *actor != grant.grantee
            }
            Op::UseSelfGrantApproval {
                actor,
                approval,
                grant,
                ..
            } => self
                .approvals
                .get(approval)
                .is_some_and(|a| !a.used && a.grant == *grant && grant.grantee == *actor),
            Op::SetSetting { setting, .. } => setting_valid(setting),
            Op::RecordInference {
                config,
                primary,
                fallbacks,
                ..
            } => {
                !self.configs.contains(config)
                    && models_valid(primary, fallbacks)
                    && self
                        .defaults
                        .p21
                        .as_ref()
                        .is_some_and(|d| d.primary == *primary && d.fallbacks == *fallbacks)
            }
            Op::GrantSignatory {
                actor,
                account,
                role,
                ..
            } => {
                account != actor
                    && !self.signatories.contains(&(*role, *account))
                    && !self.env.receiving.contains(account)
            }
            Op::EndSignatory { account, role, .. } => self.signatories.contains(&(*role, *account)),
            Op::Complete { .. } => {
                !self.completed
                    && Step::ALL.iter().all(|s| self.validated.contains(s))
                    && self.admins.len() >= 2
                    && self.admins.iter().all(|a| self.env.verified.contains(a))
            }
        }
    }

    /// Whether the values of a save validate the step in this state.
    pub fn step_validates(&self, step: Step, input: &StepInput) -> bool {
        let own = match input {
            StepInput::Plain { valid } => *valid,
            StepInput::Identity { p18, .. } => !p18.is_empty(),
            StepInput::Inference(d) => {
                !d.provider.is_empty() && models_valid(&d.primary, &d.fallbacks)
            }
        };
        let probes = !step.needs_prober() || self.env.probes == Probes::Fake { pass: true };
        let admins = step != Step::Administrators
            || (self.admins.len() >= 2
                && Signatory::ALL
                    .iter()
                    .all(|r| self.signatories.iter().any(|(h, _)| h == r)));
        let agreements = step != Step::Agreements || self.env.agreements_recorded;
        let payments = step != Step::Payments || self.settings.p20 == Some(PaymentMode::RecordOnly);
        own && probes && admins && agreements && payments
    }

    /// Advances the reference by `op`, when it is accepted.
    pub fn apply(&mut self, op: &Op) {
        if self.verdict(op) != Verdict::Accepted {
            return;
        }
        match op {
            Op::SaveStep { step, input, .. } => {
                let ok = self.step_validates(*step, input);
                if ok {
                    self.validated.insert(*step);
                } else {
                    self.validated.remove(step);
                }
                match input {
                    StepInput::Identity { p18, p45 } => {
                        self.defaults.p18 = ok.then(|| p18.clone());
                        self.defaults.p45 = ok.then_some(*p45);
                    }
                    StepInput::Inference(d) => {
                        self.defaults.p21 = ok.then(|| d.clone());
                    }
                    StepInput::Plain { .. } => {}
                }
            }
            Op::InviteAdmin {
                invitation,
                invitee,
                ..
            } => {
                self.invitations.insert(
                    *invitation,
                    RefInvitation {
                        invitee: *invitee,
                        taken: false,
                    },
                );
            }
            Op::AcceptAdminInvitation {
                account,
                invitation,
                ..
            } => {
                if let Some(i) = self.invitations.get_mut(invitation) {
                    i.taken = true;
                }
                self.admins.insert(*account);
            }
            Op::ApproveSelfGrant {
                actor,
                approval,
                grant,
                ..
            } => {
                self.approvals.insert(
                    *approval,
                    Approval {
                        approver: *actor,
                        grant: *grant,
                        used: false,
                    },
                );
            }
            Op::UseSelfGrantApproval { approval, .. } => {
                if let Some(a) = self.approvals.get_mut(approval) {
                    a.used = true;
                }
            }
            Op::SetSetting { setting, .. } => self.set(setting),
            Op::RecordInference {
                config,
                primary,
                fallbacks,
                ..
            } => {
                self.configs.insert(*config);
                self.inference = Some(Inference {
                    config: *config,
                    primary: primary.clone(),
                    fallbacks: fallbacks.clone(),
                });
            }
            Op::Complete { .. } => self.completed = true,
            Op::GrantSignatory { account, role, .. } => {
                self.signatories.insert((*role, *account));
            }
            Op::EndSignatory { account, role, .. } => {
                self.signatories.remove(&(*role, *account));
            }
        }
    }

    fn set(&mut self, setting: &Setting) {
        let s = &mut self.settings;
        match setting {
            Setting::P20(m) => {
                s.p20 = Some(*m);
                if *m == PaymentMode::Execution {
                    self.validated.remove(&Step::Payments);
                }
            }
            Setting::P69(id) => s.p69 = id.clone(),
            Setting::P70(m) => s.p70 = m.clone(),
            Setting::P71 { us } => s.p71_us = *us,
            Setting::P72 {
                idle_us,
                absolute_us,
            } => {
                s.p72_idle_us = *idle_us;
                s.p72_absolute_us = *absolute_us;
            }
            Setting::P74(m) => s.p74 = m.clone(),
        }
    }

    /// What the projection must show.
    pub fn observed(&self) -> Observed {
        Observed {
            validated: self.validated.clone(),
            admins: self.admins.clone(),
            approvals: self.approvals.clone(),
            settings: self.settings.clone(),
            defaults: self.defaults.clone(),
            inference: self.inference.clone(),
            completed: self.completed,
            signatories: self.signatories.clone(),
        }
    }

    /// The configuration and model that `call.publish` takes: those of the
    /// latest inference record, never from the client (design 3.5).
    pub fn publication_config(&self) -> Option<(LlmConfigId, String)> {
        self.inference
            .as_ref()
            .map(|i| (i.config, i.primary.clone()))
    }
}

/// Whether the op is high-risk (design sections 3.5 and 3.6, and
/// `authentication.md` for the signatory grants and ends).
pub fn is_high_risk(op: &Op) -> bool {
    matches!(
        op,
        Op::InviteAdmin { .. }
            | Op::ApproveSelfGrant { .. }
            | Op::SetSetting { .. }
            | Op::GrantSignatory { .. }
            | Op::EndSignatory { .. }
    )
}

/// Whether the op may arrive through the web only (I-85): every
/// high-risk op, and the two that complete a grant.
pub fn is_web_only(op: &Op) -> bool {
    is_high_risk(op)
        || matches!(
            op,
            Op::AcceptAdminInvitation { .. } | Op::UseSelfGrantApproval { .. }
        )
}

/// Whether the input is of the step's kind. Generators only build fitting
/// inputs, so a misfit never reaches the system under test.
pub fn input_fits(step: Step, input: &StepInput) -> bool {
    match input {
        StepInput::Identity { .. } => step == Step::Identity,
        StepInput::Inference(_) => step == Step::Inference,
        StepInput::Plain { .. } => step != Step::Identity && step != Step::Inference,
    }
}

/// The P-21 model list rule of the reference.
pub fn models_valid(primary: &str, fallbacks: &[String]) -> bool {
    if primary.is_empty() || fallbacks.iter().any(|f| f.is_empty() || f == primary) {
        return false;
    }
    let distinct: BTreeSet<&String> = fallbacks.iter().collect();
    distinct.len() == fallbacks.len()
}

/// The per-parameter value rules of the reference.
pub fn setting_valid(setting: &Setting) -> bool {
    match setting {
        Setting::P20(_) | Setting::P74(_) => true,
        Setting::P69(id) => VALID_SPDX.contains(&id.as_str()),
        Setting::P70(m) => m.contains(&LoginMethod::Passkey),
        Setting::P71 { us } => *us > 0 && *us <= P71_DEFAULT_US,
        Setting::P72 {
            idle_us,
            absolute_us,
        } => {
            *idle_us > 0
                && *idle_us <= P72_IDLE_DEFAULT_US
                && *absolute_us > 0
                && *absolute_us <= P72_ABSOLUTE_DEFAULT_US
        }
    }
}

/// The record that an accepted op must append, beside any others. A
/// setting change appends exactly this one record.
pub fn required_record(op: &Op) -> RecordView {
    match op {
        Op::SaveStep { step, .. } => RecordView::StepSaved(*step),
        Op::InviteAdmin {
            actor, invitation, ..
        } => RecordView::AdminInvited {
            invitation: *invitation,
            by: *actor,
        },
        Op::AcceptAdminInvitation { account, .. } => RecordView::AdminAdded { account: *account },
        Op::ApproveSelfGrant {
            actor, approval, ..
        } => RecordView::SelfGrantApproved {
            approval: *approval,
            by: *actor,
        },
        Op::UseSelfGrantApproval {
            actor, approval, ..
        } => RecordView::SelfGrantApprovalUsed {
            approval: *approval,
            by: *actor,
        },
        Op::SetSetting { actor, setting, .. } => RecordView::SettingChanged {
            param: setting.param(),
            by: *actor,
        },
        Op::RecordInference { actor, config, .. } => RecordView::InferenceConfigRecorded {
            config: *config,
            by: *actor,
        },
        Op::Complete { actor } => RecordView::OnboardingCompleted { by: *actor },
        Op::GrantSignatory {
            actor,
            account,
            role,
            ..
        } => RecordView::SignatoryGranted {
            role: *role,
            account: *account,
            by: *actor,
        },
        Op::EndSignatory {
            actor,
            account,
            role,
            ..
        } => RecordView::SignatoryEnded {
            role: *role,
            account: *account,
            by: *actor,
        },
    }
}

/// The parameters the cell may set in M4 (design 3.5): P-20, P-69 to
/// P-72 and P-74. P-73 changes through the control plane, and P-78 arrives
/// with M5.
pub const SETTABLE: [ParamId; 6] = [
    ParamId::P20,
    ParamId::P69,
    ParamId::P70,
    ParamId::P71,
    ParamId::P72,
    ParamId::P74,
];

/// The programme-level parameters onboarding captures as tenant defaults
/// only (design 3.1, Q36 A interim).
pub const DEFAULTS_ONLY: [ParamId; 3] = [ParamId::P18, ParamId::P21, ParamId::P45];

/// An inference default that passes the P-21 rule.
pub fn sample_inference_default() -> InferenceDefault {
    InferenceDefault {
        provider: "synthetic-provider".to_string(),
        primary: "model-a".to_string(),
        fallbacks: vec!["model-b".to_string()],
    }
}
