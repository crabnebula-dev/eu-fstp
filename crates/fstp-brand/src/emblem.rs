//! The fixed platform slot for the EU emblem and the funding
//! acknowledgement (ADR-030 section 2).
//!
//! The emblem is a platform asset, never tenant data. Daniel supplies the
//! file. Until then the slot holds nothing, and every page, email and PDF
//! renders nothing in its place.
//!
//! TODO(legal): the emblem usage rules (size, clear space, colour
//! versions and placement) and the funding acknowledgement wording that
//! goes beside it (L-08). Nothing here states either.

/// The EU emblem as a PNG for PDFs and pages, once Daniel supplies it.
/// To fill the slot, set it to `Some(include_bytes!("<file>.png"))`. The
/// file must pass [`crate::image::inspect`], and a PDF shows it only when
/// [`crate::image::pdf_image`] accepts it (opaque, not interlaced).
pub const EU_EMBLEM_PNG: Option<&[u8]> = None;

/// The approved funding acknowledgement beside the emblem, once Daniel
/// supplies it. TODO(legal) (L-08): `None` until then, so documents show
/// no acknowledgement text and pages show the pending placeholder.
pub const FUNDING_ACKNOWLEDGEMENT: Option<&str> = None;
