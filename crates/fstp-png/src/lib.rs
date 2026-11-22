//! In-house PNG and DEFLATE codec for tenant logos (ADR-031).
//!
//! The crate is pure: no I/O, no `unsafe`, no float, and no panic on any
//! input. It holds:
//!
//! - [`inflate`] and [`zlib_decompress`]: a strict RFC 1951 decoder and
//!   its RFC 1950 wrapper, with an output cap the caller names;
//! - [`deflate`] and [`zlib_compress`]: a deterministic encoder (LZ77,
//!   then the smallest of stored, fixed and dynamic blocks);
//! - [`decode`]: every colour type and bit depth of PNG 1.2, `PLTE`,
//!   `tRNS`, Adam7 and all five filters, with a CRC-32 check on every
//!   chunk, to 8-bit RGBA under [`Limits`];
//! - [`encode`] and [`reencode`]: one canonical shape, so only the pixels
//!   of a logo survive (I-68);
//! - [`flatten`], [`pdf_rgb`] and [`pdf_alpha`] for PDFs, and
//!   [`contrast`] with [`ratio_x100`], an integer estimate of a logo's
//!   contrast on a header colour through the bounds of
//!   [`fstp_creator::meets_aa`] (I-70).
//!
//! WebP is not decoded here (ADR-031 section "WebP").

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod check;
mod contrast;
mod deflate;
mod encode;
mod image;
mod inflate;
mod png;

pub use check::{adler32, crc32};
pub use contrast::{Contrast, contrast, ratio_x100};
pub use deflate::{Blocks, deflate, deflate_with, zlib_compress, zlib_compress_with};
pub use encode::{PdfStream, encode, flatten, pdf_alpha, pdf_rgb, reencode};
pub use image::Image;
pub use inflate::{InflateError, inflate, zlib_decompress};
pub use png::{Limits, MAX_RAW_BYTES, PngError, decode};
