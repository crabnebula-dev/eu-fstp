//! The authorisation matrix generator (design section 8.3). Lane W3a owns this file.
//!
//! Status: W0 stub. It refuses with [`NotImplemented`].

use crate::NotImplemented;

/// The generated matrix of operations, principals and states.
///
/// W0 placeholder with no fields. Lane W3a writes it.
#[derive(Debug)]
pub struct Matrix {
    _w0: (),
}

/// Builds the `Matrix`.
pub fn matrix() -> Result<Matrix, NotImplemented> {
    Err(NotImplemented::new("fstp_api_testkit::matrix::matrix"))
}
