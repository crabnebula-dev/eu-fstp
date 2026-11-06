//! The values that tenant commands and records carry (design section 3.5).
//!
//! Every value type here is structural. A constructor checks only the
//! spelling that keeps free text out of ledger bodies (ADR-007). The rules
//! a value must meet to change the tenant live in [`crate::rules`], and
//! `decide` and the fold apply them.

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, ProgrammeId, TextRef};
use fstp_domain::roles::Role;
use fstp_domain::rules::ParamId;

macro_rules! tenant_id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

tenant_id!(
    /// An admin invitation, drawn by the shell. It is an identifier, not a
    /// secret: ledger bodies, exports and audit views show it. Taking the
    /// invitation needs the named invitee as actor and the digest of the
    /// invitation token ([`TokenDigest`]).
    InvitationId,
    /// A SoD-07 self-grant approval.
    ApprovalId,
    /// A request to activate the organisation, drawn by the shell. The
    /// approval names it, so an approval answers one request only (SoD-18).
    ActivationRequestId,
);

/// The SHA-256 digest of an invitation token, as M3 stores it
/// (`fstp_auth::ceremony::Invitation::token_digest`).
///
/// The shell draws the token with `fstp_crypto`, sends it to the invitee
/// out of band and computes this digest. The token itself never reaches
/// this crate or a ledger body. A reader of the ledger learns the digest
/// only, which does not let it present the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// The digest with bytes `b`, as computed by the shell.
    pub const fn from_bytes(b: [u8; 32]) -> TokenDigest {
        TokenDigest(b)
    }

    /// The bytes.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The kind of cell the tenant runs in. The genesis names it, because
/// some onboarding rules differ between SaaS and self-hosted cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CellKind {
    /// A SaaS cell provisioned by the CrabNebula control plane.
    Saas,
    /// A self-hosted cell. No control plane exists, so the Agreements step
    /// is skipped and P-45 allows tenant registration only
    /// (`programme-creator.md`, `policy-parameters.md`).
    SelfHosted,
}

/// The agreement versions the control plane recorded as accepted for the
/// tenant (Q22). The shell answers [`crate::TenantQuery::Agreements`] with
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgreementVersions {
    /// The SaaS terms.
    pub saas_terms: u32,
    /// The data processing agreement.
    pub dpa: u32,
    /// The sub-processor list.
    pub sub_processors: u32,
}

/// The revision of the tenant state: the number of records folded into
/// it. A step save names the revision it was made against, so a save over
/// a newer state is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantRevision(u64);

impl TenantRevision {
    /// The revision of a fresh genesis.
    pub const GENESIS: TenantRevision = TenantRevision(0);

    /// The revision with raw value `r`.
    pub const fn from_raw(r: u64) -> TenantRevision {
        TenantRevision(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The revision after one more record, saturating at `u64::MAX`.
    pub(crate) const fn next(self) -> TenantRevision {
        TenantRevision(self.0.saturating_add(1))
    }
}

/// An onboarding step, in the order of the onboarding table of
/// `SPEC/02-domain/programme-creator.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OnboardingStep {
    /// Data protection contact and contract signatories. The legal entity
    /// stays in the control plane (Q22).
    Organisation,
    /// The agreement versions the control plane recorded as accepted.
    Agreements,
    /// The white-label package. Only the default package exists in M4.
    Branding,
    /// The sending domain, checked through the prober (M6).
    DomainsAndEmail,
    /// The P-18 and P-45 tenant defaults.
    Identity,
    /// The P-21 tenant default.
    Inference,
    /// The bank interface (M5). P-20 itself is a tenant setting.
    Payments,
    /// The Matrix homeserver and the WhatsApp Business account (M6, M8).
    Channels,
    /// At least two tenant admins (SoD-07), and at least one Financial
    /// signatory and one Legal signatory (SoD-14, SoD-15).
    Administrators,
}

impl OnboardingStep {
    /// Every step, in order.
    pub const ALL: [OnboardingStep; 9] = [
        OnboardingStep::Organisation,
        OnboardingStep::Agreements,
        OnboardingStep::Branding,
        OnboardingStep::DomainsAndEmail,
        OnboardingStep::Identity,
        OnboardingStep::Inference,
        OnboardingStep::Payments,
        OnboardingStep::Channels,
        OnboardingStep::Administrators,
    ];

    /// Whether a tenant in a cell of kind `cell` goes through the step.
    /// Self-hosted cells skip the Agreements step (`programme-creator.md`:
    /// "skipped for self-hosted"). Interim, pending Daniel: a skipped
    /// step refuses saves and counts as done for the order and for
    /// completion.
    pub const fn required_in(self, cell: CellKind) -> bool {
        !matches!(
            (self, cell),
            (OnboardingStep::Agreements, CellKind::SelfHosted)
        )
    }

    /// The steps before this one.
    pub fn before(self) -> impl Iterator<Item = OnboardingStep> {
        OnboardingStep::ALL
            .into_iter()
            .take_while(move |s| *s != self)
    }

    /// The spelling in routes and in the codec, such as
    /// `"domains_and_email"`.
    pub const fn name(self) -> &'static str {
        match self {
            OnboardingStep::Organisation => "organisation",
            OnboardingStep::Agreements => "agreements",
            OnboardingStep::Branding => "branding",
            OnboardingStep::DomainsAndEmail => "domains_and_email",
            OnboardingStep::Identity => "identity",
            OnboardingStep::Inference => "inference",
            OnboardingStep::Payments => "payments",
            OnboardingStep::Channels => "channels",
            OnboardingStep::Administrators => "administrators",
        }
    }

    /// The step spelled `s`.
    pub fn from_name(s: &str) -> Option<OnboardingStep> {
        OnboardingStep::ALL.into_iter().find(|t| t.name() == s)
    }
}

/// A later milestone that a step's machinery waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Milestone {
    /// Grant agreements and payments.
    M5,
    /// Notifications and the prober.
    M6,
    /// Matrix and WhatsApp.
    M8,
    /// White-label packages.
    M9,
}

impl Milestone {
    /// Every milestone named here.
    pub const ALL: [Milestone; 4] = [Milestone::M5, Milestone::M6, Milestone::M8, Milestone::M9];

    /// The name, such as `"M6"`.
    pub const fn name(self) -> &'static str {
        match self {
            Milestone::M5 => "M5",
            Milestone::M6 => "M6",
            Milestone::M8 => "M8",
            Milestone::M9 => "M9",
        }
    }
}

/// What the status view shows for a step (design section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepStatus {
    /// An earlier step is not validated, so the step refuses saves.
    Locked,
    /// Open and never saved.
    Open,
    /// Saved, and the latest save did not validate.
    Saved,
    /// The latest save validated.
    Validated,
    /// The tenant does not go through the step in this kind of cell
    /// ([`OnboardingStep::required_in`]).
    Skipped,
    /// The latest save could not validate, because the machinery of a
    /// later milestone is missing (Q5: fail closed).
    Unavailable {
        /// The milestone that brings it.
        milestone: Milestone,
    },
}

/// Why a step save did not validate the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepFailure {
    /// The values fail the step's own checks.
    InvalidValues,
    /// The prober ran and the check failed.
    ProbeFailed,
    /// No prober exists in this cell, so the check fails closed (Q5).
    ProberAbsent,
    /// Fewer than two tenant admins exist (SoD-07).
    TooFewAdmins,
    /// No account holds Financial signatory (SoD-14).
    NoFinancialSignatory,
    /// No account holds Legal signatory (SoD-15).
    NoLegalSignatory,
    /// The control plane did not confirm that the tenant accepted the
    /// saved agreement versions, or gave no answer (Q22, Q5: fail closed).
    AgreementsNotRecorded,
    /// No tenant admin has chosen the P-20 payment mode yet. The spec
    /// gives P-20 no default, and the Payments step captures it.
    PaymentModeUnset,
    /// The chosen option arrives with a later milestone.
    Unavailable(Milestone),
}

/// The outcome of a step save, as its `StepSaved` record keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepOutcome {
    /// The save validated the step.
    Validated,
    /// The save left the step not validated.
    Failed(StepFailure),
}

/// A short machine name: a model, a provider or similar.
///
/// It holds at most [`Token::MAX_LEN`] bytes of ASCII letters, digits and
/// `. _ : / @ + -`. So no free text reaches a ledger body through it
/// (ADR-007). It may be empty. The rules that need a name refuse an empty
/// one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(String);

impl Token {
    /// The longest token in bytes.
    pub const MAX_LEN: usize = 128;

    /// The token `s`, or `None` when `s` is too long or holds a byte
    /// outside the token alphabet.
    pub fn new(s: &str) -> Option<Token> {
        let ok = s.len() <= Token::MAX_LEN
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
            });
        ok.then(|| Token(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the token is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A pinned model, by its provider's model name.
pub type ModelRef = Token;

/// An inference provider, by name.
pub type ProviderRef = Token;

/// A domain name as the tenant typed it, in lowercase.
///
/// It holds at most [`DomainName::MAX_LEN`] bytes of `a-z`, `0-9`, `.`
/// and `-`. Whether it is a fully qualified host name is a step check
/// ([`crate::rules::is_host_name`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// The longest domain name in bytes.
    pub const MAX_LEN: usize = 253;

    /// The domain name `s`, or `None` when `s` is too long or holds a
    /// byte outside the alphabet.
    pub fn new(s: &str) -> Option<DomainName> {
        let ok = s.len() <= DomainName::MAX_LEN
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        ok.then(|| DomainName(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
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

impl VerifyMethod {
    /// Every method.
    pub const ALL: [VerifyMethod; 2] = [VerifyMethod::EudiWallet, VerifyMethod::DocumentUpload];

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            VerifyMethod::EudiWallet => "eudi_wallet",
            VerifyMethod::DocumentUpload => "document_upload",
        }
    }
}

/// A P-45 EUDI Wallet relying party mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpMode {
    /// The tenant registers as relying party.
    TenantRegistration,
    /// CrabNebula acts as intermediary.
    CrabNebulaIntermediary,
}

impl RpMode {
    /// Every mode.
    pub const ALL: [RpMode; 2] = [RpMode::TenantRegistration, RpMode::CrabNebulaIntermediary];

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            RpMode::TenantRegistration => "tenant_registration",
            RpMode::CrabNebulaIntermediary => "crabnebula_intermediary",
        }
    }
}

/// The white-label package of the Branding step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrandingPackage {
    /// The default platform theme.
    Default,
    /// A white-label package, which arrives with M9.
    WhiteLabel,
}

impl BrandingPackage {
    /// Every package.
    pub const ALL: [BrandingPackage; 2] = [BrandingPackage::Default, BrandingPackage::WhiteLabel];

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            BrandingPackage::Default => "default",
            BrandingPackage::WhiteLabel => "white_label",
        }
    }
}

/// The bank interface of the Payments step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BankInterface {
    /// No bank interface. Payments are recorded only.
    NotConnected,
    /// Connect a bank interface, which arrives with M5.
    Connect,
}

impl BankInterface {
    /// Every choice.
    pub const ALL: [BankInterface; 2] = [BankInterface::NotConnected, BankInterface::Connect];

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            BankInterface::NotConnected => "not_connected",
            BankInterface::Connect => "connect",
        }
    }
}

/// The P-21 default that the Inference step records.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InferenceDefault {
    /// The inference provider.
    pub provider: ProviderRef,
    /// The primary pinned model.
    pub primary: ModelRef,
    /// The ordered fallback list (P-21 NOTE 10).
    pub fallbacks: Vec<ModelRef>,
}

/// The values of one step save. The variant names the step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepValues {
    /// The Organisation step.
    Organisation {
        /// The data protection contact, as a text reference: the text
        /// itself lives outside ledger bodies (ADR-007).
        data_protection_contact: TextRef,
        /// The accounts that sign contracts for the tenant.
        signatories: BTreeSet<AccountId>,
    },
    /// The Agreements step: the versions the control plane recorded as
    /// accepted. Version 0 means not accepted. The step validates only
    /// when the control plane confirms the same versions (Q22).
    Agreements {
        /// The SaaS terms.
        saas_terms: u32,
        /// The data processing agreement.
        dpa: u32,
        /// The sub-processor list.
        sub_processors: u32,
    },
    /// The Branding step.
    Branding {
        /// The package.
        package: BrandingPackage,
    },
    /// The Domains and email step.
    DomainsAndEmail {
        /// The sending domain.
        sending_domain: DomainName,
    },
    /// The Identity step: the P-18 and P-45 tenant defaults.
    Identity {
        /// The P-18 default.
        p18: BTreeSet<VerifyMethod>,
        /// The P-45 default.
        p45: RpMode,
    },
    /// The Inference step: the P-21 tenant default.
    Inference(InferenceDefault),
    /// The Payments step. P-20 itself is a high-risk tenant setting. The
    /// step validates only once P-20 is chosen, and in execution mode only
    /// with a bank interface (M5).
    Payments {
        /// The bank interface.
        bank_interface: BankInterface,
    },
    /// The Channels step.
    Channels {
        /// The Matrix homeserver, if Matrix is used.
        matrix_homeserver: Option<DomainName>,
        /// Whether a WhatsApp Business account is used.
        whatsapp: bool,
    },
    /// The Administrators step: the admin set the saving admin reviewed.
    Administrators {
        /// The admins as the saving admin saw them.
        admins: BTreeSet<AccountId>,
    },
}

impl StepValues {
    /// The step these values belong to.
    pub fn step(&self) -> OnboardingStep {
        match self {
            StepValues::Organisation { .. } => OnboardingStep::Organisation,
            StepValues::Agreements { .. } => OnboardingStep::Agreements,
            StepValues::Branding { .. } => OnboardingStep::Branding,
            StepValues::DomainsAndEmail { .. } => OnboardingStep::DomainsAndEmail,
            StepValues::Identity { .. } => OnboardingStep::Identity,
            StepValues::Inference(_) => OnboardingStep::Inference,
            StepValues::Payments { .. } => OnboardingStep::Payments,
            StepValues::Channels { .. } => OnboardingStep::Channels,
            StepValues::Administrators { .. } => OnboardingStep::Administrators,
        }
    }
}

/// A tenant parameter the cell may set in M4. P-73 changes through the
/// control plane (ADR-005), and P-78 arrives with M5, so neither has a
/// variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantParam {
    /// P-20, the payment mode.
    P20,
    /// P-69, the default licence of published templates.
    P69,
    /// P-70, the enabled login methods.
    P70,
    /// P-71, the step-up freshness.
    P71,
    /// P-72, the session lifetimes.
    P72,
    /// P-74, the MCP server settings.
    P74,
}

impl TenantParam {
    /// Every settable parameter.
    pub const ALL: [TenantParam; 6] = [
        TenantParam::P20,
        TenantParam::P69,
        TenantParam::P70,
        TenantParam::P71,
        TenantParam::P72,
        TenantParam::P74,
    ];

    /// The domain parameter id.
    pub const fn param_id(self) -> ParamId {
        match self {
            TenantParam::P20 => ParamId::P20,
            TenantParam::P69 => ParamId::P69,
            TenantParam::P70 => ParamId::P70,
            TenantParam::P71 => ParamId::P71,
            TenantParam::P72 => ParamId::P72,
            TenantParam::P74 => ParamId::P74,
        }
    }

    /// The settable parameter with domain id `p`, if any.
    pub fn of(p: ParamId) -> Option<TenantParam> {
        TenantParam::ALL.into_iter().find(|t| t.param_id() == p)
    }
}

/// A P-20 payment mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaymentMode {
    /// Record-only.
    RecordOnly,
    /// Execution.
    Execution,
}

impl PaymentMode {
    /// Every mode.
    pub const ALL: [PaymentMode; 2] = [PaymentMode::RecordOnly, PaymentMode::Execution];

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            PaymentMode::RecordOnly => "record_only",
            PaymentMode::Execution => "execution",
        }
    }
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

    /// The codec spelling.
    pub const fn name(self) -> &'static str {
        match self {
            LoginMethod::Passkey => "passkey",
            LoginMethod::EudiWallet => "eudi_wallet",
            LoginMethod::Opaque => "opaque",
            LoginMethod::MagicLink => "magic_link",
        }
    }
}

/// The P-74 value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct McpSettings {
    /// Whether the MCP server is enabled.
    pub enabled: bool,
    /// The roles allowed, or `None` for every role.
    pub roles: Option<BTreeSet<Role>>,
    /// Whether the public research tools are served.
    pub public_tools: bool,
}

/// The value of one setting change. The variant names the parameter.
///
/// The value is as the client sent it. [`crate::rules::setting_valid`]
/// decides whether it may become the tenant's setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingValue {
    /// P-20.
    P20(PaymentMode),
    /// P-69, which must be an SPDX identifier.
    P69(String),
    /// P-70, the enabled login methods.
    P70(BTreeSet<LoginMethod>),
    /// P-71 in microseconds.
    P71 {
        /// The freshness.
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
    P74(McpSettings),
}

impl SettingValue {
    /// The parameter the value is for.
    pub fn param(&self) -> TenantParam {
        match self {
            SettingValue::P20(_) => TenantParam::P20,
            SettingValue::P69(_) => TenantParam::P69,
            SettingValue::P70(_) => TenantParam::P70,
            SettingValue::P71 { .. } => TenantParam::P71,
            SettingValue::P72 { .. } => TenantParam::P72,
            SettingValue::P74(_) => TenantParam::P74,
        }
    }
}

/// The grant a SoD-07 approval names: a tenant admin grants `role` in
/// `programme` to their own account `grantee`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantRef {
    /// The account the grant binds, which is the granting admin.
    pub grantee: AccountId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The role.
    pub role: Role,
}

/// A tenant-wide signatory role (NOTE 5 of `roles-and-sod.md`, decided by
/// Daniel 2026-11-01). A binding of either names no programme. The tenant
/// state holds these bindings, as it holds the tenant admin set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatoryRole {
    /// Financial signatory (SoD-14).
    Financial,
    /// Legal signatory (SoD-15).
    Legal,
}

impl SignatoryRole {
    /// Both roles, Financial first.
    pub const ALL: [SignatoryRole; 2] = [SignatoryRole::Financial, SignatoryRole::Legal];

    /// The domain role.
    pub const fn role(self) -> Role {
        match self {
            SignatoryRole::Financial => Role::FinancialSignatory,
            SignatoryRole::Legal => Role::LegalSignatory,
        }
    }

    /// The signatory role of `role`, if it is one.
    pub const fn of_role(role: Role) -> Option<SignatoryRole> {
        match role {
            Role::FinancialSignatory => Some(SignatoryRole::Financial),
            Role::LegalSignatory => Some(SignatoryRole::Legal),
            _ => None,
        }
    }

    /// The spelling in routes and in the codec: the wire name of the
    /// domain role, such as `"financial_signatory"`.
    pub const fn name(self) -> &'static str {
        match self {
            SignatoryRole::Financial => "financial_signatory",
            SignatoryRole::Legal => "legal_signatory",
        }
    }

    /// The role spelled `s`.
    pub fn from_name(s: &str) -> Option<SignatoryRole> {
        SignatoryRole::ALL.into_iter().find(|r| r.name() == s)
    }

    /// The step failure of a missing holder of the role.
    pub const fn missing(self) -> StepFailure {
        match self {
            SignatoryRole::Financial => StepFailure::NoFinancialSignatory,
            SignatoryRole::Legal => StepFailure::NoLegalSignatory,
        }
    }
}

/// The activation of the organisation (SoD-14, SoD-15 and SoD-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Activation {
    /// No tenant admin has requested activation yet.
    NotRequested,
    /// A tenant admin requested activation, and no second admin has
    /// approved it yet.
    Requested {
        /// The request.
        request: ActivationRequestId,
        /// The requesting admin.
        by: AccountId,
    },
    /// A second tenant admin approved the request, so the organisation is
    /// active.
    Active {
        /// The approved request.
        request: ActivationRequestId,
        /// The requesting admin.
        requested_by: AccountId,
        /// The approving admin, never the requester (SoD-18).
        approved_by: AccountId,
    },
}

/// A tenant's override of the Guide's data protection texts (R-GA-01,
/// `{{gdpr.notice_summary}}` and `{{funder.privacy_statement_url}}`;
/// Daniel's answer of 2026-11-06 in section 15.0 of the M4 design).
///
/// It is approved text that a tenant admin sets, never text from the
/// applicant side. The summary is a text reference, since free text lives
/// outside ledger bodies (ADR-007). The address is an `https:` address
/// that [`crate::rules::https_address`] accepts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuideNoticeOverride {
    /// The data protection summary.
    pub summary: TextRef,
    /// The privacy statement address.
    pub privacy_statement_url: String,
}
