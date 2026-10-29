//! The independent creator reference for I-66 and I-67 (design section 8.4). Lane W2a owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference validation and clearance.
///
/// W0 placeholder with no fields. Lane W2a writes it.
#[derive(Debug)]
pub struct CreatorReference {
    _w0: (),
}

/// Builds the `CreatorReference`.
pub fn creator_reference() -> Result<CreatorReference, NotImplemented> {
    Err(NotImplemented::new(
        "fstp_api_testkit::reference::creator::creator_reference",
    ))
}
