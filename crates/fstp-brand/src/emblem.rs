//! The fixed platform slot for the EU emblem and the funding
//! acknowledgement (ADR-030 section 2, ADR-034).
//!
//! The emblem is a platform asset, never tenant data. Since 2026-11-22
//! the slot holds the "Funded by the European Union" logo Daniel
//! supplied ([`crate::funding`]).
//!
//! The funding acknowledgement is per programme since 2026-11-22
//! (ADR-036): [`crate::funding::FundingCard::acknowledgement`]. The
//! emblem's usage rules are in [`crate::funding::EMBLEM_MIN_HEIGHT`] and
//! [`crate::funding::EMBLEM_CLEAR_SPACE`].

/// The EU emblem as a PNG for PDFs, emails and pages: the "Funded by the
/// European Union" logo (ADR-034 section 1). It passes
/// [`crate::image::inspect`], and [`crate::image::pdf_image`] accepts it.
pub const EU_EMBLEM_PNG: Option<&[u8]> = Some(crate::funding::FUNDED_BY_EU_PNG);
