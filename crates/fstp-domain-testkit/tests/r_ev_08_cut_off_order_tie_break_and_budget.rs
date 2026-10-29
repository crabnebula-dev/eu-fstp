//! R-EV-08: the cut-off is a rank position over the call's RANKED proposals, with a recorded P-17 tie-break and the remaining budget (NOTE 6).
//!
//! Each story runs production commands from genesis with PR1 by L1 and PR2
//! by L2 in call 1. Committee members R1, R2 and R3 vote, with R1
//! recording. Every attempt is also compared with the lifecycle reference
//! in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::decision::Vote;
use fstp_domain::id::ProposalId;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{L1, L2, PR1, PR2, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, call};
use fstp_domain_testkit::mc::life_model::{
    Story, ballots, cut_off, cut_off_decision, life_judges, story_setup,
};
use fstp_money::{Amount, Currency};

/// PR1 and PR2 ranked with the stage 1 vectors given, then "no questions".
fn story(backend: Backend, pr1: [u8; 2], pr2: Option<[u8; 2]>) -> Story {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L1, PR1, &[R1, R2], &[pr1.to_vec(), pr1.to_vec()])
        .unwrap_or_else(|e| panic!("PR1 to RANKED: {e}"));
    if let Some(v) = pr2 {
        s.ranked(L2, PR2, &[R1, R2], &[v.to_vec(), v.to_vec()])
            .unwrap_or_else(|e| panic!("PR2 to RANKED: {e}"));
    }
    s
}

fn cut(n: u128, order: Vec<ProposalId>, nominated: u32, tie_break: bool) -> Vec<Step> {
    cut_off(
        R1,
        cut_off_decision(n),
        call(1),
        order,
        nominated,
        tie_break,
        ballots(&[R1, R2, R3], Vote::For),
    )
}

fn r_ev_08_tie_needs_a_recorded_tie_break_on(b: Backend) {
    let mut s = story(b, [2, 1], Some([2, 1]));
    let refused = s
        .attempt(&cut(1, vec![PR1, PR2], 1, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        refused.is_none(),
        "R-EV-08 AC: a tie at the cut-off without a P-17 tie-break must be rejected"
    );
    s.run(&cut(1, vec![PR1, PR2], 1, true))
        .unwrap_or_else(|e| panic!("R-EV-08: the cut-off with a tie-break: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    assert_eq!(s.state(PR2), Some(StateTag::NotSelected));
}

fn r_ev_08_order_lists_the_ranked_proposals_by_effective_score_on(b: Backend) {
    let mut s = story(b, [2, 2], Some([2, 1]));
    for (order, why) in [
        (vec![PR2, PR1], "PR2 scores lower and may not come first"),
        (vec![PR1], "PR2 is RANKED and must be in the order"),
        (vec![PR1, PR2, PR1], "a proposal is listed twice"),
    ] {
        let got = s
            .attempt(&cut(1, order, 1, false))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(got.is_none(), "NOTE 6: {why}, the cut-off must be rejected");
    }
    s.run(&cut(1, vec![PR1, PR2], 2, false))
        .unwrap_or_else(|e| panic!("NOTE 6: the cut-off over the full order: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    assert_eq!(s.state(PR2), Some(StateTag::IrcReview));
}

fn remaining(records: &[Record]) -> Option<Amount> {
    records.iter().find_map(|r| match r {
        Record::CutOffRecorded(c) => Some(c.remaining_budget),
        _ => None,
    })
}

/// The remaining budget the committee ranking view shows for call 1 now.
/// On the references alone production keeps no projection, so the
/// lifecycle reference's remaining budget stands in for the view.
fn shown(s: &Story) -> Option<Amount> {
    if s.world.backend() == Backend::Reference {
        return s.world.life.remaining_budget(call(1));
    }
    fstp_domain::visibility::ranking_view(&s.world.rev.sod.state, call(1))
        .unwrap_or_else(|r| panic!("the ranking view of call 1: {r}"))
        .first()
        .map(|row| row.remaining_budget)
}

fn r_ev_08_each_round_shows_the_remaining_budget_on(b: Backend) {
    let mut s = story(b, [2, 2], None);
    let seen = shown(&s);
    let first = s
        .run(&cut(1, vec![PR1], 1, false))
        .unwrap_or_else(|e| panic!("round 1: {e}"));
    let budget = Amount::from_minor(100_000_000, Currency::Eur).unwrap();
    assert_eq!(
        remaining(&first),
        Some(budget),
        "R-EV-08: no proposal of the call is nominated before round 1"
    );
    assert_eq!(
        remaining(&first),
        seen,
        "R-EV-08: round 1 records the remaining budget the ranking view showed"
    );
    s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("PR2 to RANKED: {e}"));
    let seen = shown(&s);
    let second = s
        .run(&cut(2, vec![PR2], 0, false))
        .unwrap_or_else(|e| panic!("round 2: {e}"));
    let left = Amount::from_minor(99_900_000, Currency::Eur).unwrap();
    assert_eq!(
        remaining(&second),
        Some(left),
        "R-EV-08, Q14: round 2 shows the budget minus PR1's 1000.00 in IRC_REVIEW"
    );
    assert_eq!(
        remaining(&second),
        seen,
        "R-EV-08: round 2 records the remaining budget the ranking view showed"
    );
    assert_eq!(s.state(PR2), Some(StateTag::NotSelected));
}

/// R-EV-08 AC, NOTE 6, P-17: a tie across the cut-off position needs a recorded tie-break.
#[test]
fn r_ev_08_tie_needs_a_recorded_tie_break() {
    r_ev_08_tie_needs_a_recorded_tie_break_on(Backend::Production);
}

/// R-EV-08, NOTE 6: the order lists exactly the call's RANKED proposals, by effective score.
#[test]
fn r_ev_08_order_lists_the_ranked_proposals_by_effective_score() {
    r_ev_08_order_lists_the_ranked_proposals_by_effective_score_on(Backend::Production);
}

/// R-EV-08, NOTE 6, Q14: each round covers the proposals RANKED then, and
/// records the remaining call budget that the ranking view showed.
#[test]
fn r_ev_08_each_round_shows_the_remaining_budget() {
    r_ev_08_each_round_shows_the_remaining_budget_on(Backend::Production);
}

/// R-EV-08: the stories above pass on the references alone.
#[test]
fn r_ev_08_stories_pass_on_the_reference() {
    r_ev_08_tie_needs_a_recorded_tie_break_on(Backend::Reference);
    r_ev_08_order_lists_the_ranked_proposals_by_effective_score_on(Backend::Reference);
    r_ev_08_each_round_shows_the_remaining_budget_on(Backend::Reference);
}
