//! The synthetic legal-wording profile source (design section 3.10, rule A9b). It reads `profiles/synthetic-wording/` of this crate and reaches only `fstp-e2e-cell`. Lane W2c owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The testkit implementation of `fstp_guide::ProfileSource`.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Debug)]
pub struct SyntheticProfiles {
    _w0: (),
}

/// Builds the `SyntheticProfiles`.
pub fn synthetic_profiles() -> Result<SyntheticProfiles, NotImplemented> {
    Err(NotImplemented::new(
        "fstp_api_testkit::profiles::synthetic_profiles",
    ))
}
