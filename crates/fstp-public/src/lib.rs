//! Public pages, the feed and the public tools (I-87, M4 design section
//! 3.10).
//!
//! [`public_view`] is the only constructor of a [`PublicView`] and the only
//! filter (I-41, I-42, I-43, P-54). It takes the core `State` only, so this
//! crate has no path to findings (layering rule A4). The page renderer in
//! `html`, the public tools in `tools` and the feed in `feed` take only a
//! `&PublicView`, and name no state type (rule A6).
//!
//! Status: W0 stub. Lane W2c (L-GUIDE-PUBLIC) owns this crate. Every
//! operation refuses with [`PublicError::NotImplemented`].

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod feed;
pub mod html;
pub mod query;
pub mod tools;
pub mod view;

pub use view::{PublicView, public_view};

/// Why a public operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicError {
    /// The W0 stub of the named operation refuses.
    NotImplemented(&'static str),
}

impl std::fmt::Display for PublicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
        }
    }
}

impl std::error::Error for PublicError {}
