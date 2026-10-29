//! The public page renderer. It takes only a `&PublicView` (rule A6).

use crate::PublicError;
use crate::view::PublicView;

/// A rendered public page.
///
/// W0 placeholder with no fields. Lane W2c writes it over `fstp-html`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtmlDocument {
    _w0: (),
}

/// Renders one public page of `view`.
pub fn render_html(view: &PublicView) -> Result<HtmlDocument, PublicError> {
    let _ = view;
    Err(PublicError::NotImplemented(
        "fstp_public::html::render_html",
    ))
}
