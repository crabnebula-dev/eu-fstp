//! Review fix round 1: the drift check holds the side tracks to the section 9 set.
//!
//! `SPEC/12-journey-ui.md` section 9 names five side tracks, and section
//! 5.3 spells them in the proposal definition. A definition that drops one
//! still parses, so the drift check must report it and the loader must
//! refuse to start.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_domain::rules::{StateTag, TRANSITIONS};
use fstp_journey::definition::SideTrack;
use fstp_journey::drift::{Drift, check, drift};
use fstp_json::Value;

/// I-95, ADR-015 (section 9): each side track removed from a copy of the
/// shipped definition is reported by name, and the check fails.
#[test]
fn review_i95_drift_names_each_missing_side_track() {
    for track in SideTrack::ALL {
        let mut v = support::shipped_value();
        support::list(&mut v, "side_tracks").retain(|t| t.as_str() != Some(track.as_str()));
        let def = support::reparse(&v).unwrap_or_else(|e| panic!("I-95: {e}"));
        let found = drift(&def, &StateTag::ALL, TRANSITIONS);
        assert!(
            found.contains(&Drift::SideTrackMissing(track.as_str().to_owned())),
            "I-95: side track {} dropped, drift is {found:?}",
            track.as_str()
        );
        assert!(
            check(&def).is_err(),
            "I-95: check passed without {}",
            track.as_str()
        );
    }
}

/// I-95, ADR-015 (section 9): an empty side track list parses but never
/// passes the check, so it can never be loaded.
#[test]
fn review_i95_empty_side_tracks_never_pass_the_check() {
    let mut v = support::shipped_value();
    support::top(&mut v).insert("side_tracks".to_owned(), Value::from(Vec::<Value>::new()));
    let def = support::reparse(&v).unwrap_or_else(|e| panic!("I-95: {e}"));
    let found = check(&def).expect_err("I-95: an empty side track list passed");
    assert_eq!(found.len(), SideTrack::ALL.len(), "I-95: {found:?}");
}
