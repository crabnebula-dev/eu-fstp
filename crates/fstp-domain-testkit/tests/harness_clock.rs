//! Self-tests of the reduced clock (`docs/handoff/m2-design.md` section 6.1).
//!
//! `Tick` moves `now` to the next scenario instant only: each opening,
//! deadline, window end and next-call opening, and one microsecond before
//! each. Guards only compare times, so these instants cover every distinct
//! guard outcome. The clock must yield each such instant once, in order.
//!
//! API this file is written against: `ReducedClock::new(instants)`,
//! `ReducedClock::instants()` and `ReducedClock::next_after(now)`.
//!
//! Readings taken where the design is silent: the minimum instant has no
//! predecessor, so it contributes only itself. The clock also holds the
//! instant one microsecond after the last point, so a guard on the last
//! point sees its later outcome.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::ops::Bound;

use fstp_domain::time::Timestamp;
use fstp_domain_testkit::clock::ReducedClock;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// Scenario instants, biased towards collisions: adjacent instants, repeats
/// and the bounds of the time line.
fn instants(g: &mut Gen) -> Vec<Timestamp> {
    g.vec(0..=12, |g| {
        let micros = match g.u8_in(0..=2) {
            0 => g.i64_in(0..=24),
            1 => g.i64(),
            _ => *g.pick(&[i64::MIN, i64::MIN + 1, i64::MAX, -1, 0, 1]),
        };
        Timestamp::from_micros(micros)
    })
}

/// The reference: every instant and the instant one microsecond before it,
/// and the instant one microsecond after the last, sorted, without duplicates.
fn expected(points: &[Timestamp]) -> BTreeSet<Timestamp> {
    let mut out = BTreeSet::new();
    for t in points {
        out.insert(*t);
        if let Some(p) = t.checked_pred() {
            out.insert(p);
        }
    }
    if let Some(last) = points.iter().max()
        && let Some(after) = last.micros().checked_add(1)
    {
        out.insert(Timestamp::from_micros(after));
    }
    out
}

/// Design 6.1: the clock holds each scenario instant, the instant one
/// microsecond before it and the instant one microsecond after the last,
/// in increasing order and without duplicates.
#[test]
fn harness_reduced_clock_yields_each_instant_and_the_one_before_in_order() {
    check(
        "harness_reduced_clock_yields_each_instant_and_the_one_before_in_order",
        |g| {
            let points = instants(g);
            g.note("points", &points);
            let clock = ReducedClock::new(points.iter().copied());
            let want: Vec<Timestamp> = expected(&points).into_iter().collect();
            prop_assert_eq!(clock.instants(), &want[..]);
            Ok(())
        },
    );
}

/// Design 6.1: a tick from any instant moves to the least clock instant
/// strictly after it, and there is none after the last.
#[test]
fn harness_reduced_clock_next_after_is_the_least_later_instant() {
    check(
        "harness_reduced_clock_next_after_is_the_least_later_instant",
        |g| {
            let points = instants(g);
            let now = Timestamp::from_micros(match g.u8_in(0..=1) {
                0 => g.i64_in(-2..=26),
                _ => g.i64(),
            });
            g.note("points", &points);
            g.note("now", &now);
            let clock = ReducedClock::new(points.iter().copied());
            let want = expected(&points)
                .range((Bound::Excluded(now), Bound::Unbounded))
                .next()
                .copied();
            prop_assert_eq!(clock.next_after(now), want);
            Ok(())
        },
    );
}

/// Design 6.1: ticking from the first instant visits every instant once, in
/// order, and stops after the last.
#[test]
fn harness_reduced_clock_ticks_visit_every_instant_once() {
    check(
        "harness_reduced_clock_ticks_visit_every_instant_once",
        |g| {
            let points = instants(g);
            g.note("points", &points);
            let clock = ReducedClock::new(points.iter().copied());
            let all = clock.instants().to_vec();
            let Some(first) = all.first().copied() else {
                prop_assert!(points.is_empty(), "no instants from {points:?}");
                return Ok(());
            };
            let mut visited = vec![first];
            let mut now = first;
            while let Some(next) = clock.next_after(now) {
                prop_assert!(next > now, "tick went from {now:?} to {next:?}");
                prop_assert!(visited.len() <= all.len(), "ticks do not stop");
                visited.push(next);
                now = next;
            }
            prop_assert_eq!(visited, all);
            Ok(())
        },
    );
}

/// Design 6.1, by example: an opening at 10, a deadline at 11 and a window
/// end at 30 give 9, 10, 11, 29, 30 and 31. The 10 before the deadline and
/// the opening at 10 are one instant. The maximum instant has no successor.
#[test]
fn harness_reduced_clock_example() {
    let t = Timestamp::from_micros;
    let clock = ReducedClock::new([t(30), t(10), t(11), t(10)]);
    assert_eq!(
        clock.instants(),
        &[t(9), t(10), t(11), t(29), t(30), t(31)][..]
    );
    assert_eq!(clock.next_after(t(i64::MIN)), Some(t(9)));
    assert_eq!(clock.next_after(t(11)), Some(t(29)));
    assert_eq!(clock.next_after(t(30)), Some(t(31)));
    assert_eq!(clock.next_after(t(31)), None);
    let edge = ReducedClock::new([t(i64::MIN)]);
    assert_eq!(edge.instants(), &[t(i64::MIN), t(i64::MIN + 1)][..]);
    let top = ReducedClock::new([t(i64::MAX)]);
    assert_eq!(top.instants(), &[t(i64::MAX - 1), t(i64::MAX)][..]);
    let mut grown = ReducedClock::new([t(10)]);
    grown.insert(t(20));
    assert_eq!(grown.instants(), &[t(9), t(10), t(19), t(20), t(21)][..]);
}
