//! The public feed (P-52). It takes only a `&PublicView` (rule A6).
//!
//! The feed is `{programme, open_calls, funded, finished}`, each member as
//! [`crate::tools::select`] gives it for that part, so it applies the
//! filter of the pages (`public-transparency.md`, I-87). It is refused
//! with [`PublicError::FeedOff`] when P-52 is off.

use fstp_json::Value;

use crate::PublicError;
use crate::tools::{grants, object, open_calls, programme};
use crate::view::PublicView;

/// The feed of `view`.
pub fn feed(view: &PublicView) -> Result<Value, PublicError> {
    if !view.programme.feed {
        return Err(PublicError::FeedOff);
    }
    Ok(object(vec![
        ("programme", programme(view)),
        ("open_calls", open_calls(view, None)),
        ("funded", grants(&view.funded)),
        ("finished", grants(&view.finished)),
    ]))
}
