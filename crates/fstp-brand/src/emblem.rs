//! The fixed platform slot for the EU emblem and the funding
//! acknowledgement (ADR-030 section 2, ADR-034).
//!
//! The emblem is a platform asset, never tenant data. Since 2026-11-22
//! the slot holds the "Funded by the European Union" logo Daniel
//! supplied ([`crate::funding`]).
//!
//! TODO(legal): the emblem usage rules (size, clear space, colour
//! versions and placement) and the funding acknowledgement wording that
//! goes beside it (L-08). Nothing here states either.

/// The EU emblem as a PNG for PDFs, emails and pages: the "Funded by the
/// European Union" logo (ADR-034 section 1). It passes
/// [`crate::image::inspect`], and [`crate::image::pdf_image`] accepts it.
pub const EU_EMBLEM_PNG: Option<&[u8]> = Some(crate::funding::FUNDED_BY_EU_PNG);

/// The approved funding acknowledgement beside the emblem, once Daniel
/// supplies it. TODO(legal) (L-08): `None` until then, so documents show
/// no acknowledgement text and pages show the pending placeholder.
pub const FUNDING_ACKNOWLEDGEMENT: Option<&str> = None;
