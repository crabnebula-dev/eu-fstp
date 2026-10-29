//! The independent authorisation reference, read from the spec (design section 8.3). It never reads `ACTOR_RULES`. Lane W3a owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The reference outcome table.
///
/// W0 placeholder with no fields. Lane W3a writes it.
#[derive(Debug)]
pub struct AuthzReference {
    _w0: (),
}

/// Builds the `AuthzReference`.
pub fn authz_reference() -> Result<AuthzReference, NotImplemented> {
    Err(NotImplemented::new(
        "fstp_api_testkit::reference::authz::authz_reference",
    ))
}
