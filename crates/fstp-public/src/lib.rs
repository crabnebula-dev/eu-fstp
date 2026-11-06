//! Public pages, the feed and the public tools (I-87, M4 design section
//! 3.10).
//!
//! [`public_view`] is the only constructor of a [`PublicView`] and the only
//! filter (I-41, I-42, I-43, P-54). It takes the core `State` only, so this
//! crate has no path to findings (layering rule A4). The page renderer in
//! `html`, the public tools in `tools` and the feed in `feed` take only a
//! `&PublicView`, and name no state type (rule A6). The Guide of a
//! published call comes from `guide`.
//!
//! The creator's previews of a draft come from `preview`.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod feed;
pub mod guide;
pub mod html;
pub mod preview;
pub mod query;
mod route;
pub mod slug;
pub mod tools;
pub mod view;

pub use guide::{GuideSource, published_guide};
pub use html::{Chrome, PublicPage, render_html, render_traced};
pub use preview::{draft_guide_preview, draft_public_preview};
pub use query::{PublicPart, PublicQuery, parse_public_query};
pub use slug::{public_slugs, resolve_slug};
pub use view::{
    GrantChoice, GrantChoices, GrantStatus, Level, ProgrammeIdentity, PublicAggregate, PublicCall,
    PublicGrant, PublicGuide, PublicProgramme, PublicTexts, PublicView, public_view,
    public_view_with,
};

/// Why a public operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicError {
    /// The stub of the named operation refuses.
    NotImplemented(&'static str),
    /// The programme, call or page is not public.
    NotFound,
    /// The feed is off (P-52).
    FeedOff,
    /// A query string breaks the named rule of the grammar.
    Query(&'static str),
    /// The Guide template lacks the named required section (I-52).
    GuideSectionMissing(&'static str),
    /// The Guide did not bind or render (I-51).
    Guide(fstp_guide::GuideError),
    /// The HTML writer refused a page. This signals a defect here.
    Html(&'static str),
}

impl std::fmt::Display for PublicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            PublicError::NotFound => f.write_str("not public"),
            PublicError::FeedOff => f.write_str("the public feed is off (P-52)"),
            PublicError::Query(rule) => write!(f, "malformed public query: {rule}"),
            PublicError::GuideSectionMissing(s) => {
                write!(f, "the Guide lacks the required section {s:?} (I-52)")
            }
            PublicError::Guide(e) => write!(f, "the Guide: {e}"),
            PublicError::Html(rule) => write!(f, "the HTML writer refused the page: {rule}"),
        }
    }
}

impl std::error::Error for PublicError {}
