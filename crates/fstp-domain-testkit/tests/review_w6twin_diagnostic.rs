//! Review reproducer for lane w6-twin: the deadlock diagnostic reports an IRC_REVIEW stall that production resolves (design 6.4).
//!
//! After a concern raised while no later call exists, publishing call 2
//! enables the System's `DeclineAfterConcern`, which production offers in
//! `due` and which takes IRC_REVIEW to DEFERRED (NOTE 7). M-CONFORMANCE
//! sends that command only as the programme manager, which production
//! refuses once a later call exists. So the model never runs the System
//! branch two-way, and the diagnostic lists a stall that is not real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_domain_testkit::mc::conformance::{
    ConformanceModel, M_CONFORMANCE_NO_WITHDRAW_STATES, stalls,
};

/// Design 6.4, R-IR-02, NOTE 7: without withdrawal, no IRC_REVIEW state
/// stalls, because the System defers a concern once a later call exists.
#[test]
fn review_w6twin_r_ir_02_no_irc_review_stall_once_a_later_call_exists() {
    let model = ConformanceModel::new(false).unwrap_or_else(|e| panic!("{e}"));
    let (_, found) =
        stalls(&model, M_CONFORMANCE_NO_WITHDRAW_STATES).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !found.contains_key(&StateTag::IrcReview),
        "the diagnostic lists IRC_REVIEW stalls the System's DeclineAfterConcern resolves: {:?}",
        found.get(&StateTag::IrcReview)
    );
}
