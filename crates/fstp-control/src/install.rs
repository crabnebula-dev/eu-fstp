//! The self-hosted install and certificate renewal (design section 9.5,
//! ADR-011 "Self-hosted install").
//!
//! The install configuration is one JSON object with exactly two members:
//!
//! ```json
//! {"host": "cell.example.org", "eudi_relying_party": "tenant_registration"}
//! ```
//!
//! - `host` is the cell host, a lowercase LDH name. The install routes it
//!   and `id.<host>` through the local edge (step 7), so `id.<host>` must
//!   be a host name too.
//! - `eudi_relying_party` is the P-45 mode. A self-hosted build takes
//!   `tenant_registration` only. The `intermediary` mode would send
//!   identity data to a CrabNebula service, which I-38 forbids, so it is
//!   refused at decode.
//!
//! No member holds a credential. Every credential is generated at install
//! (R-NF-05). Unknown members, duplicate members and any other JSON form
//! are refused.

use fstp_json::{ParseLimits, Value};

use crate::ControlError;

/// The P-45 EUDI relying party mode of a self-hosted cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EudiRelyingParty {
    /// The tenant registers as its own relying party.
    TenantRegistration,
}

/// A decoded install configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallConfig {
    /// The cell host, a lowercase LDH name whose `id.` name is one too.
    pub host: String,
    /// The EUDI relying party mode.
    pub eudi_relying_party: EudiRelyingParty,
}

/// The longest configuration, in bytes.
pub const MAX_CONFIG_LEN: usize = 4096;

/// The longest cell host, so that `id.<host>` stays within 253 bytes.
pub const MAX_HOST_LEN: usize = 250;

/// Whether `name` is a lowercase LDH host name of at most [`MAX_HOST_LEN`]
/// bytes: labels of 1 to 63 letters, digits and hyphens, no hyphen at a
/// label's edge, and a last label that is not all digits.
pub fn is_cell_host(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_HOST_LEN {
        return false;
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    name.split('.').all(label_ok)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

/// Decodes an install configuration. Fuzzed (`install_config_decode`).
///
/// # Errors
///
/// [`ControlError::Config`] naming the rule broken.
pub fn decode_install_config(bytes: &[u8]) -> Result<InstallConfig, ControlError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(ControlError::Config("too long"));
    }
    let limits = ParseLimits::default()
        .with_max_input_bytes(MAX_CONFIG_LEN)
        .with_max_depth(2)
        .with_max_container_len(8)
        .with_max_string_bytes(MAX_CONFIG_LEN);
    let value = fstp_json::parse_with(bytes, &limits).map_err(|_| ControlError::Config("json"))?;
    let Value::Object(obj) = value else {
        return Err(ControlError::Config("not an object"));
    };
    if obj.keys().any(|k| k != "host" && k != "eudi_relying_party") {
        return Err(ControlError::Config("unknown member"));
    }
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or(ControlError::Config("host"))?;
    if !is_cell_host(host) {
        return Err(ControlError::Config("host"));
    }
    let eudi_relying_party = match obj.get("eudi_relying_party").and_then(Value::as_str) {
        Some("tenant_registration") => EudiRelyingParty::TenantRegistration,
        Some("intermediary") => {
            return Err(ControlError::Config(
                "intermediary mode is refused on a self-hosted cell (I-38)",
            ));
        }
        _ => return Err(ControlError::Config("eudi_relying_party")),
    };
    Ok(InstallConfig {
        host: host.to_owned(),
        eudi_relying_party,
    })
}

/// Runs an install or a renewal.
///
/// Not built yet. The install composes `fstp-keyd`, both cluster CAs, the
/// local witness and the local edge. ADR-011 leaves the issuer of the
/// local edge's tunnel certificate and the local witness's server
/// certificate open, and Daniel decides it before the install is built.
/// The parts the install shares with SaaS are built here: the
/// configuration, `Placement`, the role plan, the `pg_hba` generator and
/// the provisioning jobs.
///
/// # Errors
///
/// Always [`ControlError::NotImplemented`].
pub fn run() -> Result<(), ControlError> {
    Err(ControlError::NotImplemented("fstp_control::install::run"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-NF-01, I-38: the one accepted form decodes, and the intermediary
    /// mode, unknown members and credentials are refused.
    #[test]
    fn r_nf_01_install_config_takes_one_form() {
        let ok = decode_install_config(
            br#"{"host":"cell.example.org","eudi_relying_party":"tenant_registration"}"#,
        );
        assert_eq!(
            ok,
            Ok(InstallConfig {
                host: "cell.example.org".to_owned(),
                eudi_relying_party: EudiRelyingParty::TenantRegistration,
            })
        );
        for bad in [
            &br#"{"host":"cell.example.org","eudi_relying_party":"intermediary"}"#[..],
            br#"{"host":"cell.example.org"}"#,
            br#"{"host":"cell.example.org","eudi_relying_party":"tenant_registration","password":"x"}"#,
            br#"{"host":"Cell.example.org","eudi_relying_party":"tenant_registration"}"#,
            br#"{"host":"10.0.0.1","eudi_relying_party":"tenant_registration"}"#,
            br#"["cell.example.org"]"#,
        ] {
            assert!(decode_install_config(bad).is_err(), "{bad:?}");
        }
    }
}
