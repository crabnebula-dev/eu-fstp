//! Exact non-negative rationals for the I-08 comparison.

use core::cmp::Ordering;
use core::num::NonZeroU64;

use crate::percent::Percent;

/// Exact non-negative rational in lowest terms, so derived `Eq` and `Hash`
/// match value equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ratio {
    num: u64,
    den: NonZeroU64,
}

impl Ratio {
    /// The ratio `num / den` in lowest terms.
    ///
    /// Stub: keeps `num` and `den` unreduced until lane W1a.
    pub fn new(num: u64, den: NonZeroU64) -> Ratio {
        Ratio { num, den }
    }

    /// Whether the ratio is strictly above `p`: `num * 10_000 > bp * den`,
    /// computed in `u128`. This is the I-08 strict comparison.
    ///
    /// Stub: returns `false` until lane W1a, so nothing passes.
    pub fn exceeds(self, p: Percent) -> bool {
        let _ = (self, p);
        false
    }
}

impl Ord for Ratio {
    /// Compares `a/b` with `c/d` as `a*d` with `c*b` in `u128`.
    ///
    /// Stub: compares `(num, den)` field by field until lane W1a. That order
    /// is total and agrees with the derived `Eq`, but is not numeric.
    fn cmp(&self, other: &Ratio) -> Ordering {
        (self.num, self.den).cmp(&(other.num, other.den))
    }
}

impl PartialOrd for Ratio {
    fn partial_cmp(&self, other: &Ratio) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
