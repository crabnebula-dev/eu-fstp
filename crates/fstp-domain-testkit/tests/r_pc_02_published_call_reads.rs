//! R-PC-02 with the call states of `SPEC/02-domain/state-machine.md`: the
//! reads of a published call that later lanes build on.
//!
//! - Publication pins the LLM configuration on the call view (I-11, R-LA-05).
//! - A published call is open from its opening time until its deadline.
//!   The opening instant is open, and the deadline instant is closed,
//!   because a submission must come before the deadline (SUBMITTED). This
//!   boundary is a reading reported to Daniel.
//! - The next published call of a programme is the "future call exists"
//!   fact of NOTE 7. Calls of another programme never count.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{CallId, LlmConfigId};
use fstp_domain::record::Record;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::{
    DEADLINE, DRAFTER_1, DRAFTER_2, OPENS, P1, P2, PM_A, PM_B, PM_C, PM_D, PolicyWorld,
};
use fstp_domain_testkit::mc::policy_model::reads;

fn at(micros: i64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn open(w: &PolicyWorld, call: u128, t: Timestamp) -> bool {
    reads::is_open_at(w.state(), CallId::from_raw(call), t)
}

/// R-PC-02 and I-11: the call view of a published call carries the
/// configuration its `CallPublished` record pinned. An unpublished call
/// carries none.
#[test]
fn r_pc_02_publication_pins_the_llm_config_on_the_call_view() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    for call in [1, 2] {
        assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
        assert!(w.approve(PM_B, call).is_ok());
    }
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let pinned: Vec<LlmConfigId> = w
        .records()
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            Record::CallPublished { config, .. } => Some(config),
            _ => None,
        })
        .collect();
    assert_eq!(pinned.len(), 1);
    assert_eq!(
        reads::llm_config(w.state(), CallId::from_raw(1)),
        pinned.first().copied()
    );
    assert_eq!(reads::llm_config(w.state(), CallId::from_raw(2)), None);
}

/// R-PC-02 with the call states: a published call is open at its opening
/// time and until just before its deadline. It is closed before the
/// opening and from the deadline on. An unpublished call is never open.
#[test]
fn r_pc_02_a_published_call_is_open_from_opening_until_its_deadline() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    for call in [1, 2] {
        assert!(w.draft(DRAFTER_1, call, P1).unwrap().is_ok());
        assert!(w.approve(PM_B, call).is_ok());
    }
    assert!(!open(&w, 1, OPENS));
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let opens = OPENS.micros();
    let deadline = DEADLINE.micros();
    assert!(!open(&w, 1, at(opens.saturating_sub(1))));
    assert!(open(&w, 1, OPENS));
    assert!(open(&w, 1, at(deadline.saturating_sub(1))));
    assert!(!open(&w, 1, DEADLINE));
    assert!(!open(&w, 1, at(deadline.saturating_add(1))));
    assert!(!open(&w, 2, OPENS));
}

/// R-PC-02 with state-machine NOTE 7: the next published call of a call is
/// the first call of the same programme published after it. A call of
/// another programme, or an unpublished call, never counts.
#[test]
fn r_pc_02_next_published_call_stays_in_the_programme() {
    let mut w = PolicyWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.draft(DRAFTER_2, 2, P2).unwrap().is_ok());
    assert!(w.draft(DRAFTER_1, 3, P1).unwrap().is_ok());
    assert!(w.draft(DRAFTER_1, 4, P1).unwrap().is_ok());
    for (call, approver) in [(1, PM_B), (2, PM_D), (3, PM_B), (4, PM_B)] {
        assert!(w.approve(approver, call).is_ok());
    }
    let next =
        |w: &PolicyWorld, call: u128| reads::next_published_call(w.state(), CallId::from_raw(call));
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    assert_eq!(next(&w, 1), None);
    assert!(w.publish(PM_C, 2).unwrap().is_ok());
    assert_eq!(next(&w, 1), None);
    assert!(w.publish(PM_A, 3).unwrap().is_ok());
    assert_eq!(next(&w, 1), Some(CallId::from_raw(3)));
    assert_eq!(next(&w, 2), None);
    assert_eq!(next(&w, 3), None);
    assert_eq!(next(&w, 4), None);
}
