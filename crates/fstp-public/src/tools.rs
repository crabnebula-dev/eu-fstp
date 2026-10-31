//! The public tool encoder. It takes only a `&PublicView` (rule A6).

use crate::PublicError;
use crate::query::PublicQuery;
use crate::view::PublicView;

/// The answer to one public tool query, as JSON text.
pub fn select(view: &PublicView, query: &PublicQuery) -> Result<Vec<u8>, PublicError> {
    let _ = (view, query);
    Err(PublicError::NotImplemented("fstp_public::tools::select"))
}
