//! The configuration of a cell and its decoder (design sections 1.2,
//! 10.3 and 14.4).
//!
//! No field may hold a payment account type or a debtor account (I-16,
//! `i16_config_types_hold_no_debtor_account`). The configuration names
//! exactly one cell (I-19, `i19_cell_process_serves_one_cell`).
//!
//! # Format
//!
//! One JSON object, parsed by `fstp_json`, with these members and no
//! other:
//!
//! - `cell`: 32 lowercase hex digits.
//! - `mode`: `"saas"` or `"self_hosted"`.
//! - `eudi_relying_party`: `"tenant_registration"` or `"intermediary"`,
//!   optional, `"tenant_registration"` by default. These are the W1g
//!   proposal names of `fstp-celltest` `i38_egress`. A self-hosted build
//!   refuses `"intermediary"` (P-45, `eudi-wallet.md`, I-38).
//! - `licence`: 32 lowercase hex digits. Optional for a self-hosted cell
//!   and refused for a SaaS cell, which never reaches CrabNebula (B12).
//!   A self-hosted cell starts before its holder registers, and takes
//!   the licence from the first token it imports (design section 10.2,
//!   Q41). When both name a licence, they must name the same one.
//! - `version`: `"major.minor.patch"`, the running product version.
//!
//! The member grammar is the lane W3a reading. Design section 9.5 fixes no
//! configuration grammar yet.

use fstp_cp_proto::CellId;
use fstp_release::egress::ProductVersion;
use fstp_release::licence::LicenceId;

/// How a cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A SaaS cell, which reaches the control plane and never CrabNebula.
    Saas,
    /// A self-hosted cell, which has no control plane and reaches
    /// CrabNebula only through `fstp_release::egress` (B12).
    SelfHosted,
}

/// How the cell acts as an EUDI relying party (P-45).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelyingParty {
    /// The tenant registers as its own relying party.
    TenantRegistration,
    /// The platform acts as an intermediary. A self-hosted build refuses
    /// it, since it would send identity data to a CrabNebula service.
    Intermediary,
}

/// The configuration of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellConfig {
    /// The one cell this process serves.
    pub cell: CellId,
    /// The deployment mode.
    pub mode: Mode,
    /// The EUDI relying party mode.
    pub relying_party: RelyingParty,
    /// The licence of a self-hosted cell.
    pub licence: Option<LicenceId>,
    /// The running product version.
    pub version: ProductVersion,
}

/// Why a configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// No configuration was given.
    Missing,
    /// The bytes are not one JSON object.
    NotAnObject,
    /// A member is not known. Unknown members are refused, so a typo
    /// never falls back to a default.
    UnknownMember,
    /// A required member is absent.
    MissingMember(&'static str),
    /// A member's value does not have its grammar.
    Invalid(&'static str),
    /// A self-hosted build refuses P-45 intermediary mode (I-38).
    IntermediaryWhenSelfHosted,
    /// A SaaS cell holds no licence: it never reaches CrabNebula (B12).
    LicenceWhenSaas,
}

const MEMBERS: [&str; 5] = ["cell", "mode", "eudi_relying_party", "licence", "version"];

/// The largest configuration accepted, in bytes.
pub const MAX_CONFIG_LEN: usize = 4096;

fn hex16(text: &str, member: &'static str) -> Result<[u8; 16], ConfigError> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return Err(ConfigError::Invalid(member));
    }
    let mut out = [0u8; 16];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = nibble(pair.first().copied()).ok_or(ConfigError::Invalid(member))?;
        let lo = nibble(pair.get(1).copied()).ok_or(ConfigError::Invalid(member))?;
        let slot = out.get_mut(i).ok_or(ConfigError::Invalid(member))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(b: Option<u8>) -> Option<u8> {
    match b? {
        c @ b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        c @ b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes and checks a configuration.
///
/// # Errors
///
/// [`ConfigError`] for any input that is not a valid configuration. A
/// self-hosted configuration with intermediary mode is refused with
/// [`ConfigError::IntermediaryWhenSelfHosted`].
pub fn decode(bytes: &[u8]) -> Result<CellConfig, ConfigError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(ConfigError::Invalid("length"));
    }
    let value = fstp_json::parse(bytes).map_err(|_| ConfigError::NotAnObject)?;
    let obj = value.as_object().ok_or(ConfigError::NotAnObject)?;
    for (name, _) in obj.iter() {
        if !MEMBERS.contains(&name) {
            return Err(ConfigError::UnknownMember);
        }
    }
    let text = |name: &'static str| -> Result<Option<&str>, ConfigError> {
        match obj.get(name) {
            None => Ok(None),
            Some(v) => v.as_str().map(Some).ok_or(ConfigError::Invalid(name)),
        }
    };
    let cell = text("cell")?.ok_or(ConfigError::MissingMember("cell"))?;
    let cell = CellId(hex16(cell, "cell")?);
    let mode = match text("mode")?.ok_or(ConfigError::MissingMember("mode"))? {
        "saas" => Mode::Saas,
        "self_hosted" => Mode::SelfHosted,
        _ => return Err(ConfigError::Invalid("mode")),
    };
    let relying_party = match text("eudi_relying_party")? {
        None | Some("tenant_registration") => RelyingParty::TenantRegistration,
        Some("intermediary") => RelyingParty::Intermediary,
        Some(_) => return Err(ConfigError::Invalid("eudi_relying_party")),
    };
    let licence = text("licence")?
        .map(|t| hex16(t, "licence").map(LicenceId))
        .transpose()?;
    let version = text("version")?.ok_or(ConfigError::MissingMember("version"))?;
    let version =
        ProductVersion::parse(version.as_bytes()).ok_or(ConfigError::Invalid("version"))?;
    match (mode, relying_party, licence) {
        (Mode::SelfHosted, RelyingParty::Intermediary, _) => {
            Err(ConfigError::IntermediaryWhenSelfHosted)
        }
        (Mode::Saas, _, Some(_)) => Err(ConfigError::LicenceWhenSaas),
        _ => Ok(CellConfig {
            cell,
            mode,
            relying_party,
            licence,
            version,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CELL: &str = "000102030405060708090a0b0c0d0e0f";

    fn cfg(extra: &str) -> Vec<u8> {
        format!("{{\"cell\":\"{CELL}\",\"version\":\"0.3.0\",{extra}}}").into_bytes()
    }

    /// I-38: a self-hosted configuration with intermediary mode is refused
    /// at decode, and the same one without it decodes.
    #[test]
    fn i38_config_refuses_intermediary_mode_when_self_hosted() {
        let lic = "\"licence\":\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"";
        let bad = cfg(&format!(
            "\"mode\":\"self_hosted\",{lic},\"eudi_relying_party\":\"intermediary\""
        ));
        assert_eq!(decode(&bad), Err(ConfigError::IntermediaryWhenSelfHosted));
        let good = cfg(&format!("\"mode\":\"self_hosted\",{lic}"));
        assert_eq!(decode(&good).map(|c| c.mode), Ok(Mode::SelfHosted));
    }

    /// I-39, design section 10.2 (Q41): a self-hosted cell starts before
    /// its holder registers, so its configuration decodes without a
    /// licence. The licence comes from the first token it imports.
    #[test]
    fn i39_config_accepts_a_self_hosted_cell_before_its_first_token() {
        let c = decode(&cfg("\"mode\":\"self_hosted\""));
        assert_eq!(c.map(|c| (c.mode, c.licence)), Ok((Mode::SelfHosted, None)));
    }

    /// B12: a SaaS cell holds no licence, and an unknown member or a bad
    /// cell id is refused.
    #[test]
    fn i38_config_refuses_a_licence_on_saas_and_unknown_members() {
        let lic = "\"licence\":\"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\"";
        assert_eq!(
            decode(&cfg(&format!("\"mode\":\"saas\",{lic}"))),
            Err(ConfigError::LicenceWhenSaas)
        );
        assert_eq!(
            decode(&cfg("\"mode\":\"saas\",\"x\":1")),
            Err(ConfigError::UnknownMember)
        );
        assert_eq!(
            decode(b"{\"cell\":\"00\",\"mode\":\"saas\",\"version\":\"0.3.0\"}"),
            Err(ConfigError::Invalid("cell"))
        );
        assert_eq!(
            decode(&cfg("\"mode\":\"saas\"")).map(|c| c.cell.0[15]),
            Ok(15)
        );
    }
}
