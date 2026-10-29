//! The independent reference filter from `public-transparency.md`, for M-PUBLIC (design section 8.5). Lane W2c owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference public filter.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Debug)]
pub struct PublicReference {
    _w0: (),
}

/// Builds the `PublicReference`.
pub fn public_reference() -> Result<PublicReference, NotImplemented> {
    Err(NotImplemented::new(
        "fstp_api_testkit::reference::public::public_reference",
    ))
}
