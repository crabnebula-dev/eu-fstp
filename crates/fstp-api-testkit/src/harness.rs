//! The three-channel harness over `fstp_rt::duplex`: direct dispatch, HTTP and MCP (design section 8.3). Lane W3b owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// One cell reachable through all three channels.
///
/// W0 placeholder with no fields. Lane W3b writes it.
#[derive(Debug)]
pub struct Harness {
    _w0: (),
}

/// Builds the `Harness`.
pub fn harness() -> Result<Harness, NotImplemented> {
    Err(NotImplemented::new("fstp_api_testkit::harness::harness"))
}
