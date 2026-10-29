//! Fakes of the M3 ports of `fstp_api_core::port` (design section 6.1). A contract test runs each fake and each M3 implementation through the same suite. Lane W3b owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// Every fake port of one cell.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Debug)]
pub struct FakePorts {
    _w0: (),
}

/// Builds the `FakePorts`.
pub fn fake_ports() -> Result<FakePorts, NotImplemented> {
    Err(NotImplemented::new("fstp_api_testkit::fake::fake_ports"))
}
