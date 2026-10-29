//! The scenario bridge to `fstp-domain-testkit` (design section 8.1). Lane W3b owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// A domain scenario driven through the API core.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Debug)]
pub struct Scenario {
    _w0: (),
}

/// Builds the `Scenario`.
pub fn scenario() -> Result<Scenario, NotImplemented> {
    Err(NotImplemented::new("fstp_api_testkit::scenario::scenario"))
}
