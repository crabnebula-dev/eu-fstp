//! I-87 teeth on M-PUBLIC (M4 design sections 8.4 and 8.5).
//!
//! Each fault is planted in the test kit's model, never in production.
//! The model builds the faulty surface around the production view:
//!
//! - `Fault::FeedSkipsFilter`: the feed is built from every grant the
//!   core state holds, read around `public_view_with`. The property
//!   "I-87 M-PUBLIC feed equals pages", the state-level form of
//!   `i87_feed_equals_pages`, must report it.
//! - `Fault::ToolReadsState`: the funded and finished tools read the
//!   core state directly, around `public_view_with`. The property
//!   "I-87 M-PUBLIC tools equal pages" must report it.
//!
//! The filter property itself must stay unviolated, so the catch comes
//! from the surface check and not from a changed view. The leak is the
//! minor's grant (I-42) or a hidden choice (I-43) that the faulty source
//! shows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::public_model::{
    Backend, FEED_EQUALS_PAGES, Fault, PublicModel, TOOLS_EQUAL_PAGES, TRIPWIRE,
    m_public_properties,
};
use fstp_domain_testkit::harness::mc::tripwire;
use fstp_domain_testkit::harness::teeth::expect_violation;
use fstp_mc::check;

fn caught(fault: Fault, id: &str) {
    let model = PublicModel::with_fault(Backend::Production, fault)
        .unwrap_or_else(|e| panic!("M-PUBLIC: {e}"));
    let properties = m_public_properties(&model);
    let outcome = check(
        &model,
        &properties,
        &tripwire(TRIPWIRE.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
    if let Err(e) = expect_violation(&outcome, "I-87 M-PUBLIC filter") {
        assert!(
            e.contains("undetected"),
            "the fault must leave the view itself unchanged: {e}"
        );
    } else {
        panic!("the fault changed the production view, not only the surface\n{outcome}");
    }
}

/// I-87 teeth: a feed that skips the public filter is caught by the
/// feed-equals-pages property of M-PUBLIC.
#[test]
fn i87_teeth_filter_skipped_for_feed_is_caught() {
    caught(Fault::FeedSkipsFilter, FEED_EQUALS_PAGES);
}

/// I-87 teeth: a public tool that reads the core state around
/// `public_view` is caught by the tools-equal-pages property of M-PUBLIC.
#[test]
fn i87_teeth_tool_reads_state_directly_is_caught() {
    caught(Fault::ToolReadsState, TOOLS_EQUAL_PAGES);
}
