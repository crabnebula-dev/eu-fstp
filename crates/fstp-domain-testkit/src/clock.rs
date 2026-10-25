//! Reduced clock over scenario instants (design section 6.1).
//!
//! A model's `Tick` moves `now` to the next scenario instant only. The
//! instants are each opening, deadline, window end and next-call opening,
//! and the instant one microsecond before each. Guards only compare times,
//! so these instants cover every distinct guard outcome.
//!
//! Readings taken where the design is silent:
//! - The earliest possible instant has no predecessor, so it contributes
//!   only itself.
//! - The clock also holds the instant one microsecond after the last
//!   point, when there is one. Without it, a guard such as `now > t` on the
//!   last deadline would never see its later outcome. Every point before
//!   the last already has a later instant.

use std::collections::BTreeSet;

use fstp_domain::time::Timestamp;

/// The instants a model may move `now` to, sorted and without duplicates.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReducedClock {
    points: BTreeSet<Timestamp>,
    instants: Vec<Timestamp>,
}

/// The instant one microsecond after `t`, or `None` at the maximum.
fn succ(t: Timestamp) -> Option<Timestamp> {
    t.micros().checked_add(1).map(Timestamp::from_micros)
}

impl ReducedClock {
    /// The clock over `points`: each point and the instant one microsecond
    /// before it, and the instant one microsecond after the last point.
    pub fn new(points: impl IntoIterator<Item = Timestamp>) -> ReducedClock {
        let mut clock = ReducedClock {
            points: points.into_iter().collect(),
            instants: Vec::new(),
        };
        clock.rebuild();
        clock
    }

    /// Adds `point`, the instant one microsecond before it, and moves the
    /// instant after the last point when `point` is the new last one.
    pub fn insert(&mut self, point: Timestamp) {
        if self.points.insert(point) {
            self.rebuild();
        }
    }

    /// Every instant, in increasing order.
    pub fn instants(&self) -> &[Timestamp] {
        &self.instants
    }

    /// The first instant, if any.
    pub fn first(&self) -> Option<Timestamp> {
        self.instants.first().copied()
    }

    /// The least instant strictly after `now`, or `None` after the last.
    pub fn next_after(&self, now: Timestamp) -> Option<Timestamp> {
        let i = self.instants.partition_point(|t| *t <= now);
        self.instants.get(i).copied()
    }

    /// Recomputes the instants from the points.
    fn rebuild(&mut self) {
        let mut set = BTreeSet::new();
        for t in &self.points {
            set.insert(*t);
            if let Some(p) = t.checked_pred() {
                set.insert(p);
            }
        }
        if let Some(after) = self.points.last().copied().and_then(succ) {
            set.insert(after);
        }
        self.instants = set.into_iter().collect();
    }
}
