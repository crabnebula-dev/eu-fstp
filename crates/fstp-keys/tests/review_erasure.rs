//! Review reproducers for lane W2f: the erasure planner (design section
//! 3.5, ADR-004 part 2 "Erasure construction", I-81).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use fstp_keys::erasure::{ChainState, Phase};
use fstp_keys::{DekId, Epoch, GroupId};

/// I-81, design section 3.5: a rotation re-seals only the groups its
/// batch touches, and re-wraps every group secret under the new epoch.
/// A data key admitted to an untouched group is sealed to a generation
/// that survives the rotation, so admitting it mid-run loses nothing.
/// The planner refuses it with `RunInFlight` for the whole run, steps 2
/// to 7, snapshot upload and verification included. Every text write of
/// the chain then stalls during every erasure.
#[test]
fn review_admit_to_unaffected_group_during_a_rotation() {
    let (g0, g1) = (GroupId([1; 16]), GroupId([2; 16]));
    let mut s = ChainState::genesis(Epoch(1));
    s.add_group(g0).unwrap();
    s.add_group(g1).unwrap();
    s.admit(g0, DekId([10; 16])).unwrap();
    s.admit(g0, DekId([11; 16])).unwrap();
    s.admit(g1, DekId([20; 16])).unwrap();
    s.request(DekId([10; 16]), 1).unwrap();
    assert_ne!(s.phase(), Phase::Idle, "the request started no rotation");
    assert_eq!(
        s.admit(g1, DekId([21; 16])),
        Ok(()),
        "a new data key in a group the running batch does not touch was refused"
    );
}
