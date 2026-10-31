//! The canary vault and the canary crawl (I-86, design section 8.4). Lane W3c owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// A vault whose identity facts are canary strings.
///
/// W0 placeholder with no fields. Lane W3c writes it.
#[derive(Debug)]
pub struct CanaryVault {
    _w0: (),
}

/// Builds the `CanaryVault`.
pub fn canary_vault() -> Result<CanaryVault, NotImplemented> {
    Err(NotImplemented::new(
        "fstp_api_testkit::canary::canary_vault",
    ))
}
