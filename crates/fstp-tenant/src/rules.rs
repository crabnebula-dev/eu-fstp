//! The value rules of the tenant (design section 3.5,
//! `SPEC/02-domain/policy-parameters.md`).
//!
//! `decide` applies them before it appends a record, and the fold applies
//! them again, so a ledger that breaks one never folds.

use std::collections::BTreeSet;

use crate::state::TenantState;
use crate::types::{
    AgreementVersions, BankInterface, BrandingPackage, CellKind, DomainName, LoginMethod,
    MailRelay, McpSettings, Milestone, ModelRef, OnboardingStep, PaymentMode, RpMode, SettingValue,
    StepFailure, StepValues,
};

/// P-71 default: 5 minutes, "(proposed)" in `policy-parameters.md`, as M3
/// builds it (Q37).
pub const P71_DEFAULT_US: i64 = 5 * 60 * 1_000_000;
/// P-72 default idle lifetime: 30 minutes (proposed).
pub const P72_IDLE_DEFAULT_US: i64 = 30 * 60 * 1_000_000;
/// P-72 default absolute lifetime: 12 hours (proposed).
pub const P72_ABSOLUTE_DEFAULT_US: i64 = 12 * 60 * 60 * 1_000_000;
/// P-69 default: CC BY 4.0, as its SPDX identifier.
pub const P69_DEFAULT: &str = "CC-BY-4.0";
/// The longest P-69 value in bytes.
pub const P69_MAX_LEN: usize = 64;
/// The longest fallback list of P-21.
pub const MAX_FALLBACKS: usize = 16;
/// The most accounts a step value may list.
pub const MAX_ACCOUNTS: usize = 64;

/// Whether `value` may become the tenant's setting.
///
/// - P-20 and P-74: every value.
/// - P-69: an SPDX short identifier ([`spdx_id_valid`]).
/// - P-70: "Passkeys always", so the set holds passkeys.
/// - P-71: positive and no longer than the default ("may only shorten",
///   as `fstp_auth::stepup` reads it).
/// - P-72: each lifetime positive and no longer than its default. This is
///   the strict reading M3 built in `fstp_cell_core::tenant` (Q37).
///   Interim, pending Daniel.
pub fn setting_valid(value: &SettingValue) -> bool {
    match value {
        SettingValue::P20(_) | SettingValue::P74(_) => true,
        SettingValue::P69(id) => spdx_id_valid(id),
        SettingValue::P70(methods) => methods.contains(&LoginMethod::Passkey),
        SettingValue::P71 { us } => shortens(*us, P71_DEFAULT_US),
        SettingValue::P72 {
            idle_us,
            absolute_us,
        } => {
            shortens(*idle_us, P72_IDLE_DEFAULT_US)
                && shortens(*absolute_us, P72_ABSOLUTE_DEFAULT_US)
        }
    }
}

fn shortens(v: i64, default: i64) -> bool {
    v > 0 && v <= default
}

/// Whether `s` is an SPDX short licence identifier: 1 to
/// [`P69_MAX_LEN`] bytes of ASCII letters, digits, `.` and `-`, starting
/// and ending with a letter or digit, with an optional trailing `+`.
///
/// Interim, pending Daniel: the check is syntactic. It does not consult
/// the SPDX licence list, so a well-formed unknown identifier passes.
pub fn spdx_id_valid(s: &str) -> bool {
    if s.len() > P69_MAX_LEN {
        return false;
    }
    let body = s.strip_suffix('+').unwrap_or(s);
    let bytes = body.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-')
}

/// The P-21 model rule (NOTE 10): a non-empty primary model and an
/// ordered list of at most [`MAX_FALLBACKS`] distinct, non-empty
/// fallbacks, none equal to the primary.
///
/// Interim strict reading, pending Daniel: a fallback equal to the
/// primary or to an earlier fallback would never change the model, so it
/// is refused.
pub fn models_valid(primary: &ModelRef, fallbacks: &[ModelRef]) -> bool {
    if primary.is_empty() || fallbacks.len() > MAX_FALLBACKS {
        return false;
    }
    let mut seen: BTreeSet<&ModelRef> = BTreeSet::new();
    seen.insert(primary);
    fallbacks.iter().all(|f| !f.is_empty() && seen.insert(f))
}

/// Whether `d` is a fully qualified host name: at least two labels of 1
/// to 63 bytes, none starting or ending with `-`, and a last label that
/// is not all digits.
pub fn is_host_name(d: &DomainName) -> bool {
    let s = d.as_str();
    if s.is_empty() {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok =
        |l: &&str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-');
    labels.len() >= 2
        && labels.iter().all(label_ok)
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `relay` may be the tenant's mail relay (ADR-018, I-38): a
/// fully qualified host name that is not a CrabNebula host, and a
/// non-empty secret name. The cell's egress checks the host again.
pub fn mail_relay_valid(relay: &MailRelay) -> bool {
    let h = relay.host.as_str();
    is_host_name(&relay.host)
        && h != "crabnebula.dev"
        && !h.ends_with(".crabnebula.dev")
        && !relay.credential.is_empty()
}

/// The check that runs through the prober for a step's values (Q5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeKind {
    /// SPF, DKIM and DMARC of the sending domain (M6).
    SendingDomain(DomainName),
    /// Reachability of the configured channels (M6, M8).
    Channels,
}

/// The prober check that a save of `values` needs, if any.
pub fn probe_for(values: &StepValues) -> Option<ProbeKind> {
    match values {
        StepValues::DomainsAndEmail { sending_domain } => {
            Some(ProbeKind::SendingDomain(sending_domain.clone()))
        }
        StepValues::Channels { .. } => Some(ProbeKind::Channels),
        _ => None,
    }
}

/// The step's own checks of `values` in `state`: its admin set, its
/// settings and its kind of cell. `decide` and the fold both run them.
///
/// - Organisation: at least one and at most [`MAX_ACCOUNTS`] signatories.
/// - Agreements: every agreement accepted (version 1 or later). The
///   control plane must also confirm the versions, which only `decide`
///   can ask ([`agreements_confirmed`]).
/// - Branding: the default package. White-label packages arrive with M9.
/// - Domains and email: a fully qualified sending host name.
/// - Identity: at least one P-18 method. A self-hosted cell uses tenant
///   registration only for P-45 (`policy-parameters.md`).
/// - Inference: a provider and the P-21 model rule.
/// - Payments: [`payments_check`].
/// - Channels: a Matrix homeserver, if given, is a host name.
/// - Administrators: the reviewed set equals the ledger's admin set
///   (interim, pending Daniel).
pub fn values_check(values: &StepValues, state: &TenantState) -> Result<(), StepFailure> {
    let ok = match values {
        StepValues::Organisation { signatories, .. } => {
            !signatories.is_empty() && signatories.len() <= MAX_ACCOUNTS
        }
        StepValues::Agreements {
            saas_terms,
            dpa,
            sub_processors,
        } => *saas_terms >= 1 && *dpa >= 1 && *sub_processors >= 1,
        StepValues::Branding { package } => match package {
            BrandingPackage::Default => true,
            BrandingPackage::WhiteLabel => {
                return Err(StepFailure::Unavailable(Milestone::M9));
            }
        },
        StepValues::DomainsAndEmail { sending_domain } => is_host_name(sending_domain),
        StepValues::Identity { p18, p45 } => !p18.is_empty() && p45_allowed(*p45, state.cell()),
        StepValues::Inference(d) => {
            !d.provider.is_empty() && models_valid(&d.primary, &d.fallbacks)
        }
        StepValues::Payments { bank_interface } => {
            return payments_check(*bank_interface, state.settings().p20);
        }
        StepValues::Channels {
            matrix_homeserver, ..
        } => matrix_homeserver.as_ref().is_none_or(is_host_name),
        StepValues::Administrators { admins: reviewed } => reviewed == state.admins(),
    };
    if ok {
        Ok(())
    } else {
        Err(StepFailure::InvalidValues)
    }
}

/// Whether the P-45 mode `mode` is allowed in a cell of kind `cell`. A
/// self-hosted cell uses tenant registration only (`policy-parameters.md`
/// P-45), since no CrabNebula intermediary serves it.
pub fn p45_allowed(mode: RpMode, cell: CellKind) -> bool {
    match cell {
        CellKind::Saas => true,
        CellKind::SelfHosted => mode == RpMode::TenantRegistration,
    }
}

/// The Payments step check (`programme-creator.md`: "Payment mode (P-20),
/// bank interface where execution mode is used"). Interim, pending
/// Daniel:
///
/// - P-20 unset fails with [`StepFailure::PaymentModeUnset`]. The spec
///   gives P-20 no default, so onboarding never completes without it.
/// - Execution mode needs a bank interface, which arrives with M5.
/// - A bank interface in any mode arrives with M5.
/// - Record-only mode with no bank interface validates.
pub fn payments_check(
    bank_interface: BankInterface,
    p20: Option<PaymentMode>,
) -> Result<(), StepFailure> {
    match (p20, bank_interface) {
        (None, _) => Err(StepFailure::PaymentModeUnset),
        (Some(PaymentMode::Execution), _)
        | (Some(PaymentMode::RecordOnly), BankInterface::Connect) => {
            Err(StepFailure::Unavailable(Milestone::M5))
        }
        (Some(PaymentMode::RecordOnly), BankInterface::NotConnected) => Ok(()),
    }
}

/// Whether the control plane's answer `recorded` confirms the saved
/// agreement versions (Q22). No answer fails closed (Q5).
pub fn agreements_confirmed(
    saas_terms: u32,
    dpa: u32,
    sub_processors: u32,
    recorded: Option<AgreementVersions>,
) -> bool {
    recorded
        == Some(AgreementVersions {
            saas_terms,
            dpa,
            sub_processors,
        })
}

/// The milestone that brings the prober a step needs.
pub fn prober_milestone(step: OnboardingStep) -> Milestone {
    match step {
        OnboardingStep::Channels => Milestone::M8,
        _ => Milestone::M6,
    }
}

/// The P-74 default: enabled for every role, with the public research
/// tools.
pub fn p74_default() -> McpSettings {
    McpSettings {
        enabled: true,
        roles: None,
        public_tools: true,
    }
}

/// The longest privacy statement address a tenant may set, in bytes.
pub const MAX_ADDRESS_BYTES: usize = 2048;

/// Whether `s` may stand as the Guide's privacy statement address: an
/// `https://` address of at most [`MAX_ADDRESS_BYTES`] bytes, with a non-empty
/// host, made of visible ASCII with no quote, angle bracket, backslash or
/// backtick (R-GA-01). Interim, pending Daniel: the check is syntactic.
pub fn https_address(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let host_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    s.len() <= MAX_ADDRESS_BYTES
        && host_len > 0
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'<' | b'>' | b'\\' | b'`'))
}
