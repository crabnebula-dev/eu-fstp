//! The test vocabulary of lane W2d.
//!
//! It names what the spec and design section 3.5 name, in plain test
//! types. The adapter in [`super::prod`] maps each value to the production
//! types once they exist.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::Via;
use fstp_domain::id::{AccountId, LlmConfigId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain::rules::ParamId;

/// An onboarding step, in the order of the onboarding table of
/// `SPEC/02-domain/programme-creator.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// Legal entity, address, signatories, data protection contact.
    Organisation,
    /// SaaS terms, data processing agreement, sub-processor list.
    Agreements,
    /// White-label package (default package only in M4).
    Branding,
    /// Custom domains and the sending domain with its checks.
    DomainsAndEmail,
    /// P-45 and P-18, as tenant defaults.
    Identity,
    /// P-21, as a tenant default.
    Inference,
    /// P-20 and the bank interface.
    Payments,
    /// Matrix homeserver and WhatsApp Business account.
    Channels,
    /// At least two tenant admins (SoD-07).
    Administrators,
}

impl Step {
    /// Every step, in the spec's order.
    pub const ALL: [Step; 9] = [
        Step::Organisation,
        Step::Agreements,
        Step::Branding,
        Step::DomainsAndEmail,
        Step::Identity,
        Step::Inference,
        Step::Payments,
        Step::Channels,
        Step::Administrators,
    ];

    /// The position of the step in [`Step::ALL`].
    pub fn index(self) -> usize {
        Step::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    /// The steps that come before this one.
    pub fn before(self) -> &'static [Step] {
        &Step::ALL[..self.index()]
    }

    /// Whether the step's check runs through a prober that M4 production
    /// cells lack: the sending domain check (M6) and the channel checks
    /// (M6, M8). Design section 3.5 "Later machinery" and Q5.
    pub fn needs_prober(self) -> bool {
        matches!(self, Step::DomainsAndEmail | Step::Channels)
    }
}

/// A P-18 identity verification method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyMethod {
    /// The EUDI Wallet.
    EudiWallet,
    /// Document upload with a manual check.
    DocumentUpload,
}

/// A P-45 EUDI Wallet relying party mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpMode {
    /// The tenant registers as relying party.
    TenantRegistration,
    /// CrabNebula acts as intermediary.
    CrabNebulaIntermediary,
}

/// The P-21 default that the Inference step records.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InferenceDefault {
    /// The inference provider.
    pub provider: String,
    /// The primary pinned model.
    pub primary: String,
    /// The ordered fallback list (P-21 NOTE 10).
    pub fallbacks: Vec<String>,
}

/// What one step save carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepInput {
    /// A step whose values this lane does not interpret. `valid` says
    /// whether the values pass the step's own checks. The adapter builds
    /// concrete values of each kind.
    Plain {
        /// Whether the values pass the step's own checks.
        valid: bool,
    },
    /// The Identity step.
    Identity {
        /// The P-18 default.
        p18: BTreeSet<VerifyMethod>,
        /// The P-45 default.
        p45: RpMode,
    },
    /// The Inference step.
    Inference(InferenceDefault),
}

/// The probes the shell offers to step validation (Q5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probes {
    /// No prober, as in an M4 production cell. Checks that need one fail
    /// closed.
    Absent,
    /// A recording fake that answers `pass` to every probe.
    Fake {
        /// The answer of every probe.
        pass: bool,
    },
}

/// A P-70 login method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoginMethod {
    /// Passkeys, always enabled.
    Passkey,
    /// The EUDI Wallet.
    EudiWallet,
    /// OPAQUE passwords.
    Opaque,
    /// Magic links.
    MagicLink,
}

impl LoginMethod {
    /// Every method.
    pub const ALL: [LoginMethod; 4] = [
        LoginMethod::Passkey,
        LoginMethod::EudiWallet,
        LoginMethod::Opaque,
        LoginMethod::MagicLink,
    ];
}

/// A P-20 payment mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaymentMode {
    /// Record-only.
    RecordOnly,
    /// Execution.
    Execution,
}

/// The P-74 value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct McpSetting {
    /// Whether the MCP server is enabled.
    pub enabled: bool,
    /// The roles allowed, or `None` for every role.
    pub roles: Option<BTreeSet<Role>>,
    /// Whether the public research tools are served.
    pub public_tools: bool,
}

/// One tenant setting change, one variant per settable parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// P-20.
    P20(PaymentMode),
    /// P-69, an SPDX identifier.
    P69(String),
    /// P-70, the enabled login methods.
    P70(BTreeSet<LoginMethod>),
    /// P-71 in microseconds.
    P71 {
        /// The freshness in microseconds.
        us: i64,
    },
    /// P-72 in microseconds.
    P72 {
        /// The idle lifetime.
        idle_us: i64,
        /// The absolute lifetime.
        absolute_us: i64,
    },
    /// P-74.
    P74(McpSetting),
}

impl Setting {
    /// The parameter the setting changes.
    pub fn param(&self) -> ParamId {
        match self {
            Setting::P20(_) => ParamId::P20,
            Setting::P69(_) => ParamId::P69,
            Setting::P70(_) => ParamId::P70,
            Setting::P71 { .. } => ParamId::P71,
            Setting::P72 { .. } => ParamId::P72,
            Setting::P74(_) => ParamId::P74,
        }
    }
}

/// The grant a SoD-07 approval names: a tenant admin grants `role` in
/// `programme` to their own account `grantee`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Grant {
    /// The account the grant binds, which is the granting admin.
    pub grantee: AccountId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The role.
    pub role: Role,
}

/// One operation on the tenant, as a test states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `TenantCommand::SaveStep`.
    SaveStep {
        /// The issuing account.
        actor: AccountId,
        /// The step.
        step: Step,
        /// The values.
        input: StepInput,
    },
    /// `TenantCommand::InviteAdmin` (high-risk). The invitation names its
    /// invitee, and the adapter records the digest of a token derived
    /// from the invitation id.
    InviteAdmin {
        /// The issuing account.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The invitation id, drawn by the shell.
        invitation: u128,
        /// The account the invitation is for.
        invitee: AccountId,
    },
    /// The invitee enrols and takes the invitation, presenting its token.
    /// Design section 3.5 has the `AdminAdded` record but no command that
    /// yields it (gap). It completes a tenant admin grant, so it is web
    /// only (I-85).
    AcceptAdminInvitation {
        /// The account that takes it.
        account: AccountId,
        /// The channel.
        via: Via,
        /// The invitation id.
        invitation: u128,
    },
    /// `TenantCommand::ApproveSelfGrant` (SoD-07, high-risk).
    ApproveSelfGrant {
        /// The approving account.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The approval id, drawn by the shell.
        approval: u128,
        /// The self-grant it approves.
        grant: Grant,
    },
    /// `TenantCommand::UseSelfGrantApproval`: the self-grant consumes its
    /// approval, once (TH-05). Web only (I-85).
    UseSelfGrantApproval {
        /// The granting admin, who is the grantee.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The approval id.
        approval: u128,
        /// The self-grant.
        grant: Grant,
    },
    /// `TenantCommand::SetSetting` (high-risk, one op per parameter).
    SetSetting {
        /// The issuing account.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The new value.
        setting: Setting,
    },
    /// `TenantCommand::RecordInferenceConfig`.
    RecordInference {
        /// The issuing account.
        actor: AccountId,
        /// The pinned LLM configuration.
        config: LlmConfigId,
        /// The primary model.
        primary: String,
        /// The ordered fallbacks.
        fallbacks: Vec<String>,
    },
    /// `tenant.complete`. Design section 2.2 J0 names the op, and section
    /// 3.5 has neither its command nor its record (gap).
    Complete {
        /// The issuing account.
        actor: AccountId,
    },
    /// A tenant admin grants a tenant-wide signatory role (NOTE 5 of
    /// `roles-and-sod.md`). High-risk: it grants an Operations role.
    GrantSignatory {
        /// The issuing account.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The account the role binds.
        account: AccountId,
        /// The role.
        role: Signatory,
    },
    /// A tenant admin ends a signatory binding. High-risk: it changes an
    /// Operations role.
    EndSignatory {
        /// The issuing account.
        actor: AccountId,
        /// The channel.
        via: Via,
        /// The account whose binding ends.
        account: AccountId,
        /// The role.
        role: Signatory,
    },
}

/// A tenant-wide signatory role of the roles table (SA-01, NOTE 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signatory {
    /// Financial signatory (SoD-14).
    Financial,
    /// Legal signatory (SoD-15).
    Legal,
}

impl Signatory {
    /// Both roles.
    pub const ALL: [Signatory; 2] = [Signatory::Financial, Signatory::Legal];
}

impl Op {
    /// The account that issues the operation.
    pub fn actor(&self) -> AccountId {
        match self {
            Op::SaveStep { actor, .. }
            | Op::InviteAdmin { actor, .. }
            | Op::ApproveSelfGrant { actor, .. }
            | Op::UseSelfGrantApproval { actor, .. }
            | Op::SetSetting { actor, .. }
            | Op::RecordInference { actor, .. }
            | Op::GrantSignatory { actor, .. }
            | Op::EndSignatory { actor, .. }
            | Op::Complete { actor } => *actor,
            Op::AcceptAdminInvitation { account, .. } => *account,
        }
    }

    /// The channel. Operations without a channel field arrive on the web.
    pub fn via(&self) -> Via {
        match self {
            Op::InviteAdmin { via, .. }
            | Op::AcceptAdminInvitation { via, .. }
            | Op::ApproveSelfGrant { via, .. }
            | Op::UseSelfGrantApproval { via, .. }
            | Op::SetSetting { via, .. }
            | Op::GrantSignatory { via, .. }
            | Op::EndSignatory { via, .. } => *via,
            _ => Via::Web,
        }
    }
}

/// Whether the system accepted an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Accepted, with its records appended.
    Accepted,
    /// Refused, with nothing appended.
    Refused,
}

/// The fixed context of one run. Every run is in a SaaS cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Env {
    /// The first tenant admin, enrolled from the control plane link
    /// (design section 3.5 "Administrators").
    pub first_admin: AccountId,
    /// The accounts whose identity the vault reports as verified
    /// (verification purpose `AdminIdentity`, design 6.1 item 13).
    pub verified: BTreeSet<AccountId>,
    /// The probes step validation can use.
    pub probes: Probes,
    /// Whether the control plane recorded the tenant's acceptance of the
    /// agreement versions that a valid Agreements save names (Q22).
    /// Without it the Agreements step fails closed.
    pub agreements_recorded: bool,
    /// The accounts that hold a Receiving binding. None of them may become
    /// a tenant admin (SoD-03).
    pub receiving: BTreeSet<AccountId>,
}

/// The tenant settings, as the projection shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// P-20, or `None` while the tenant has not chosen one.
    pub p20: Option<PaymentMode>,
    /// P-69.
    pub p69: String,
    /// P-70.
    pub p70: BTreeSet<LoginMethod>,
    /// P-71 in microseconds.
    pub p71_us: i64,
    /// P-72 idle lifetime in microseconds.
    pub p72_idle_us: i64,
    /// P-72 absolute lifetime in microseconds.
    pub p72_absolute_us: i64,
    /// P-74.
    pub p74: McpSetting,
}

/// The tenant defaults that prefill new drafts. They are never parameters
/// (design sections 3.1 and 3.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Defaults {
    /// The P-18 default.
    pub p18: Option<BTreeSet<VerifyMethod>>,
    /// The P-45 default.
    pub p45: Option<RpMode>,
    /// The P-21 default.
    pub p21: Option<InferenceDefault>,
}

/// The latest inference configuration record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inference {
    /// The pinned LLM configuration.
    pub config: LlmConfigId,
    /// The primary model.
    pub primary: String,
    /// The ordered fallbacks.
    pub fallbacks: Vec<String>,
}

/// A recorded SoD-07 approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approval {
    /// The approving tenant admin.
    pub approver: AccountId,
    /// The approved self-grant.
    pub grant: Grant,
    /// Whether the self-grant used it (TH-05: one approval, one grant).
    pub used: bool,
}

/// What the tenant projection shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// The steps whose status is validated.
    pub validated: BTreeSet<Step>,
    /// The tenant admin set (Q31).
    pub admins: BTreeSet<AccountId>,
    /// The SoD-07 approvals by approval id.
    pub approvals: BTreeMap<u128, Approval>,
    /// The tenant settings.
    pub settings: Settings,
    /// The tenant defaults.
    pub defaults: Defaults,
    /// The latest inference configuration record.
    pub inference: Option<Inference>,
    /// Whether onboarding was completed.
    pub completed: bool,
    /// The signatory bindings held, by role and account (NOTE 5).
    pub signatories: BTreeSet<(Signatory, AccountId)>,
}

/// One appended record, in the test vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordView {
    /// `StepSaved`.
    StepSaved(Step),
    /// `StepValidated`.
    StepValidated(Step),
    /// `AdminInvited`.
    AdminInvited {
        /// The invitation.
        invitation: u128,
        /// The inviting admin.
        by: AccountId,
    },
    /// `AdminAdded`.
    AdminAdded {
        /// The new admin.
        account: AccountId,
    },
    /// `SelfGrantApproved`.
    SelfGrantApproved {
        /// The approval id.
        approval: u128,
        /// The approving admin.
        by: AccountId,
    },
    /// `SelfGrantApprovalUsed`.
    SelfGrantApprovalUsed {
        /// The approval id.
        approval: u128,
        /// The granting admin.
        by: AccountId,
    },
    /// `SettingChanged { param, value, by }`.
    SettingChanged {
        /// The parameter.
        param: ParamId,
        /// The admin who changed it.
        by: AccountId,
    },
    /// `GuideNoticeSet`. The machine issues no such command.
    GuideNoticeSet {
        /// The admin who set it.
        by: AccountId,
    },
    /// `InferenceConfigRecorded`.
    InferenceConfigRecorded {
        /// The configuration.
        config: LlmConfigId,
        /// The recording admin.
        by: AccountId,
    },
    /// The completion record that design section 3.5 lacks (gap).
    OnboardingCompleted {
        /// The completing admin.
        by: AccountId,
    },
    /// A signatory grant.
    SignatoryGranted {
        /// The role.
        role: Signatory,
        /// The account it binds.
        account: AccountId,
        /// The granting admin.
        by: AccountId,
    },
    /// The end of a signatory binding.
    SignatoryEnded {
        /// The role.
        role: Signatory,
        /// The account whose binding ended.
        account: AccountId,
        /// The ending admin.
        by: AccountId,
    },
    /// An activation request (SoD-18).
    ActivationRequested {
        /// The requesting admin.
        by: AccountId,
    },
    /// An activation approval (SoD-18).
    ActivationApproved {
        /// The approving admin.
        by: AccountId,
    },
    /// A branding set (M9 lane B1).
    BrandingSet {
        /// The setting admin.
        by: AccountId,
    },
    /// A terminology set (M9 lane T1).
    TerminologySet {
        /// The setting admin.
        by: AccountId,
    },
}

/// The defaults of `SPEC/02-domain/policy-parameters.md` for the settable
/// parameters. P-71 and P-72 are marked "(proposed)" there. M3 builds the
/// same values (`fstp_cell_core::tenant`, Q37). P-20 has no default, so it
/// is unset until a tenant admin chooses it.
pub fn spec_default_settings() -> Settings {
    Settings {
        p20: None,
        p69: "CC-BY-4.0".to_string(),
        p70: [LoginMethod::Passkey].into_iter().collect(),
        p71_us: P71_DEFAULT_US,
        p72_idle_us: P72_IDLE_DEFAULT_US,
        p72_absolute_us: P72_ABSOLUTE_DEFAULT_US,
        p74: McpSetting {
            enabled: true,
            roles: None,
            public_tools: true,
        },
    }
}

/// P-71 default: 5 minutes.
pub const P71_DEFAULT_US: i64 = 5 * 60 * 1_000_000;
/// P-72 default idle lifetime: 30 minutes.
pub const P72_IDLE_DEFAULT_US: i64 = 30 * 60 * 1_000_000;
/// P-72 default absolute lifetime: 12 hours.
pub const P72_ABSOLUTE_DEFAULT_US: i64 = 12 * 60 * 60 * 1_000_000;

/// SPDX identifiers the generators offer as valid P-69 values.
pub const VALID_SPDX: [&str; 5] = ["CC-BY-4.0", "CC0-1.0", "CC-BY-SA-4.0", "MIT", "Apache-2.0"];
/// Strings the generators offer as invalid P-69 values.
pub const INVALID_SPDX: [&str; 4] = ["", "CC BY 4.0", "<b>MIT</b>", "MIT\n"];

/// The account with raw id `n`.
pub const fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}
