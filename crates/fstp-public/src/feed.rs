//! The public feed (P-52). It takes only a `&PublicView` (rule A6).

use crate::PublicError;
use crate::view::PublicView;

/// The feed of `view` as JSON text.
pub fn feed(view: &PublicView) -> Result<Vec<u8>, PublicError> {
    let _ = view;
    Err(PublicError::NotImplemented("fstp_public::feed::feed"))
}
