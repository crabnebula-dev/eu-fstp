//! The self-hosted install and certificate renewal (design section 9.5).

use crate::ControlError;

/// A decoded install configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallConfig {
    /// The cell host.
    pub host: String,
}

/// Decodes an install configuration. Fuzzed (`install_config_decode`).
pub fn decode_install_config(bytes: &[u8]) -> Result<InstallConfig, ControlError> {
    let _ = bytes;
    Err(ControlError::NotImplemented(
        "fstp_control::install::decode_install_config",
    ))
}

/// Runs an install or a renewal.
pub fn run() -> Result<(), ControlError> {
    Err(ControlError::NotImplemented("fstp_control::install::run"))
}
