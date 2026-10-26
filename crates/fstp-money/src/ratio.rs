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

/// The greatest common divisor of `a` and `b`, by Euclid's algorithm.
///
/// It is at least 1 when `b` is not zero.
fn gcd(mut a: u64, b: NonZeroU64) -> NonZeroU64 {
    let mut b = b.get();
    while let Some(r) = a.checked_rem(b) {
        a = b;
        b = r;
    }
    // The loop ends when `b` is zero, and `a` then holds the last non-zero
    // divisor, which is at least 1.
    NonZeroU64::new(a).unwrap_or(NonZeroU64::MIN)
}

impl Ratio {
    /// The ratio `num / den` in lowest terms. Zero is held as `0/1`.
    pub fn new(num: u64, den: NonZeroU64) -> Ratio {
        let g = gcd(num, den);
        let reduced = num
            .checked_div(g.get())
            .zip(den.get().checked_div(g.get()).and_then(NonZeroU64::new));
        match reduced {
            Some((num, den)) => Ratio { num, den },
            // Not reached: `g` divides both and is at least 1.
            None => Ratio { num, den },
        }
    }

    /// The numerator in lowest terms.
    pub fn num(self) -> u64 {
        self.num
    }

    /// The denominator in lowest terms.
    pub fn den(self) -> NonZeroU64 {
        self.den
    }

    /// Whether the ratio is strictly above `p`: `num * 10_000 > bp * den`,
    /// computed in `u128`. This is the I-08 strict comparison. A ratio equal
    /// to `p` never exceeds it.
    pub fn exceeds(self, p: Percent) -> bool {
        // Both products are below 2^80, so `u128` holds them exactly.
        let lhs = u128::from(self.num).saturating_mul(u128::from(Percent::MAX_BP));
        let rhs = u128::from(p.bp()).saturating_mul(u128::from(self.den.get()));
        lhs > rhs
    }
}

impl Ord for Ratio {
    /// Compares `a/b` with `c/d` as `a*d` with `c*b` in `u128`.
    fn cmp(&self, other: &Ratio) -> Ordering {
        // Each product of two `u64` values fits `u128` exactly.
        let lhs = u128::from(self.num).saturating_mul(u128::from(other.den.get()));
        let rhs = u128::from(other.num).saturating_mul(u128::from(self.den.get()));
        lhs.cmp(&rhs)
    }
}

impl PartialOrd for Ratio {
    fn partial_cmp(&self, other: &Ratio) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
