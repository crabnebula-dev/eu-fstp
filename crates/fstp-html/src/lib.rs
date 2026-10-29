//! Server-rendered HTML (M4 design section 1.1).
//!
//! The crate holds:
//!
//! - an escaping HTML writer with no raw-insertion API ([`Document`],
//!   [`Element`], [`Node`], [`SafeUrl`], [`HtmlDocument`]; I-68, TW-2);
//! - the message catalogues for server-rendered text ([`Catalogues`];
//!   R-NF-04);
//! - the [`Label`] and [`ApprovedText`] kinds (I-72 seam, R-WL-05);
//! - a test sink that records every dynamic text node
//!   ([`Document::render_traced`]; I-87 seam);
//! - the well-formedness checker that tests and fuzz targets use
//!   ([`check_wellformed`]);
//! - the `Accept-Language` parser and locale negotiation
//!   ([`parse_accept_language`], [`negotiate_locale`]).
//!
//! Every rule the design leaves open is an interim reading, pending
//! Daniel. Each is stated in the module that builds it.
//!
//! ```
//! use fstp_html::{
//!     CatalogueSource, Catalogues, Document, Element, EntrySource, Label, MessageKind, Node,
//!     SafeUrl, check_wellformed,
//! };
//!
//! let entries = [EntrySource { id: "nav.home", kind: MessageKind::Label, message: "Home" }];
//! let cats = Catalogues::new(&CatalogueSource { locale: "en", entries: &entries }, &[])?;
//! let page = Document::new("en")
//!     .title(Node::label(&Label::new("nav.home"), &[]))
//!     .body(
//!         Element::new("p")
//!             .text("<script>alert(1)</script>")
//!             .child(Element::new("a").attr_url("href", SafeUrl::new("/p/x/")?).text("x")),
//!     );
//! let doc = page.render(&cats)?;
//! check_wellformed(doc.as_bytes())?;
//! assert!(doc.as_str().contains("&lt;script&gt;"));
//! # Ok::<(), fstp_html::HtmlError>(())
//! ```

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod catalogue;
mod check;
mod error;
mod lang;
mod message;
mod subset;
mod url;
mod writer;

pub use catalogue::{
    ApprovedText, CatalogueSource, Catalogues, EntrySource, Label, LabelOverride, MAX_ID_BYTES,
    MessageKind,
};
pub use check::check_wellformed;
pub use error::HtmlError;
pub use lang::{
    AcceptLanguage, LanguageRange, MAX_ACCEPT_LANGUAGE_BYTES, MAX_LANGUAGE_RANGES,
    negotiate_locale, parse_accept_language,
};
pub use message::{MAX_MESSAGE_BYTES, MAX_PLACEHOLDER_BYTES, MessageFormat, parse_message_format};
pub use url::SafeUrl;
pub use writer::{Document, Element, HtmlDocument, MAX_DEPTH, Node, TraceEvent, TracePlace};
