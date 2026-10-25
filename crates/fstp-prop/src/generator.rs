//! The [`Gen`] handle and its built-in generators.
//!
//! Every generator draws bounded `u64` choices through [`Gen::draw`]. During
//! random generation the choices come from an edge-biased PRNG. During
//! shrinking and replay they come from a recorded sequence. A replay that runs
//! past the end of its sequence draws 0, which every generator maps to its
//! simplest value.

use core::fmt::Debug;
use core::ops::RangeInclusive;
use std::panic::resume_unwind;

use crate::chars;
use crate::rng::Rng;

/// Upper bound on recorded spans per case, which bounds memory.
const MAX_SPANS: usize = 1 << 16;

/// Bit widths whose boundaries are classic overflow points.
const BOUNDARY_BITS: [u32; 7] = [7, 8, 15, 16, 31, 32, 63];

/// Why a case ended without a pass or a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Invalid {
    /// [`Gen::assume`] or [`Gen::reject`] discarded the case.
    Assume,
    /// The case drew more than `max_choices` choices.
    Overrun,
}

/// Unwinding payload that ends a case early. The runner catches it.
#[derive(Debug)]
pub(crate) enum Stop {
    /// The case is discarded.
    Invalid(Invalid),
    /// The case fails with this message.
    Fail(String),
}

/// Everything a finished case recorded.
#[derive(Debug, Default)]
pub(crate) struct Recording {
    /// The choices drawn, with trailing zeros trimmed.
    pub(crate) choices: Vec<u64>,
    /// Half-open choice ranges that form structural units, such as one element of a vector.
    pub(crate) spans: Vec<(usize, usize)>,
    /// Notes, when the case collected them.
    pub(crate) notes: Vec<String>,
}

/// Source of generated values for one test case.
///
/// A property receives a `&mut Gen` and calls its methods to build inputs.
/// Composed generators are plain functions or closures that take a `&mut Gen`.
/// They shrink with no extra code, because shrinking works on the choices
/// underneath every value.
///
/// Methods that cannot produce a value end the current case as a failure with
/// a descriptive message. Examples are an empty range or [`Gen::pick`] on an
/// empty slice. They do this by unwinding, and the runner catches it.
pub struct Gen {
    prefix: Vec<u64>,
    rng: Option<Rng>,
    choices: Vec<u64>,
    max_choices: usize,
    spans: Vec<(usize, usize)>,
    notes: Option<Vec<String>>,
    invalid: Option<Invalid>,
    forced_failure: Option<String>,
}

impl Gen {
    /// Creates a generator that draws fresh edge-biased random choices.
    pub(crate) fn random(rng: Rng, max_choices: usize) -> Gen {
        Gen {
            prefix: Vec::new(),
            rng: Some(rng),
            choices: Vec::new(),
            max_choices,
            spans: Vec::new(),
            notes: None,
            invalid: None,
            forced_failure: None,
        }
    }

    /// Creates a generator that replays `prefix` and then draws zeros.
    pub(crate) fn replay(prefix: Vec<u64>, max_choices: usize) -> Gen {
        Gen {
            prefix,
            rng: None,
            choices: Vec::new(),
            max_choices,
            spans: Vec::new(),
            notes: None,
            invalid: None,
            forced_failure: None,
        }
    }

    /// Turns on note collection. Only the final run of a minimal case needs it.
    pub(crate) fn collecting_notes(mut self) -> Gen {
        self.notes = Some(Vec::new());
        self
    }

    /// Why the case was discarded, if it was.
    pub(crate) fn invalid(&self) -> Option<Invalid> {
        self.invalid
    }

    /// Number of choices drawn so far.
    pub(crate) fn position(&self) -> usize {
        self.choices.len()
    }

    /// Consumes the generator and returns what it recorded.
    pub(crate) fn into_recording(self) -> Recording {
        let mut choices = self.choices;
        let end = choices
            .iter()
            .rposition(|&c| c != 0)
            .map_or(0, |i| i.saturating_add(1));
        choices.truncate(end);
        let spans = self
            .spans
            .into_iter()
            .filter(|&(s, _)| s < end)
            .map(|(s, e)| (s, e.min(end)))
            .collect();
        Recording {
            choices,
            spans,
            notes: self.notes.unwrap_or_default(),
        }
    }

    /// Draws one choice in `0..=max`.
    ///
    /// Replay reads the prefix and clamps values above `max`. Past the prefix,
    /// random mode calls `random` and replay mode returns 0.
    pub(crate) fn draw(&mut self, max: u64, random: impl FnOnce(&mut Rng) -> u64) -> u64 {
        if self.choices.len() >= self.max_choices {
            self.discard(Invalid::Overrun);
        }
        let value = match self.prefix.get(self.choices.len()) {
            Some(&v) => v.min(max),
            None => match self.rng.as_mut() {
                Some(rng) => random(rng).min(max),
                None => 0,
            },
        };
        self.choices.push(value);
        value
    }

    /// Ends the case as discarded.
    fn discard(&mut self, why: Invalid) -> ! {
        self.invalid = Some(why);
        resume_unwind(Box::new(Stop::Invalid(why)))
    }

    /// The failure forced by a generator, if any. Recorded on the generator as
    /// well as in the unwinding payload, so a property that catches the unwind
    /// itself still fails.
    pub(crate) fn forced_failure(&self) -> Option<&str> {
        self.forced_failure.as_deref()
    }

    /// Ends the case as a failure with `message`.
    pub(crate) fn fail_case(&mut self, message: String) -> ! {
        if self.forced_failure.is_none() {
            self.forced_failure = Some(message.clone());
        }
        resume_unwind(Box::new(Stop::Fail(message)))
    }

    /// Records a structural span that started at choice index `start`.
    pub(crate) fn end_span(&mut self, start: usize) {
        let end = self.choices.len();
        if end > start && self.spans.len() < MAX_SPANS {
            self.spans.push((start, end));
        }
    }

    /// Runs `f` and marks the choices it draws as one structural unit.
    ///
    /// The shrinker tries to delete or zero whole spans, which helps it remove
    /// compound values that a fixed-size chunk would split. [`Gen::vec`] already
    /// marks each element, so most generators never need to call this.
    pub fn span<T>(&mut self, f: impl FnOnce(&mut Gen) -> T) -> T {
        let start = self.position();
        let out = f(self);
        self.end_span(start);
        out
    }

    /// Discards the current case when `condition` is false.
    ///
    /// Use it for preconditions. A discarded case counts neither as a pass nor
    /// as a failure. A run that discards too many cases fails, so a property
    /// can never pass by discarding everything.
    pub fn assume(&mut self, condition: bool) {
        if !condition {
            self.discard(Invalid::Assume);
        }
    }

    /// Discards the current case unconditionally. See [`Gen::assume`].
    pub fn reject(&mut self) -> ! {
        self.discard(Invalid::Assume)
    }

    /// Records `label = value` for the failure report.
    ///
    /// Notes are formatted only during the final run of the minimal failing
    /// case, so they cost almost nothing while searching.
    pub fn note(&mut self, label: &str, value: &dyn Debug) {
        if let Some(notes) = self.notes.as_mut() {
            notes.push(format!("{label} = {value:?}"));
        }
    }

    /// Records the string built by `f` for the failure report.
    ///
    /// `f` runs only during the final run of the minimal failing case.
    pub fn note_with(&mut self, f: impl FnOnce() -> String) {
        if let Some(notes) = self.notes.as_mut() {
            notes.push(f());
        }
    }

    /// Generates a boolean, each value with probability one half. Shrinks
    /// towards `false`.
    pub fn bool(&mut self) -> bool {
        self.draw(1, |rng| u64::from(rng.coin())) == 1
    }

    /// Generates an integer in `lo..=hi`, ordered by distance from the value
    /// closest to zero.
    fn int_in(&mut self, lo: i128, hi: i128) -> i128 {
        if lo > hi {
            self.fail_case(format!("empty integer range {lo}..={hi}"));
        }
        let Ok(n) = u64::try_from(hi.saturating_sub(lo)) else {
            self.fail_case(format!("integer range {lo}..={hi} is wider than 64 bits"));
        };
        let c = self.draw(n, |rng| int_choice(rng, lo, hi, n));
        zigzag(lo, hi, c)
    }

    /// Generates a choice index in `0..=max` that shrinks towards 0, with no
    /// edge bias. Used for weighted picks.
    fn uniform(&mut self, max: u64) -> u64 {
        self.draw(max, |rng| rng.upto(max))
    }

    /// Generates a vector whose length lies in `len`, building each element with `f`.
    ///
    /// Lengths are biased towards the minimum, small values and the maximum,
    /// but every length that fits in [`crate::Config::max_choices`] can occur.
    /// Shrinks towards shorter vectors and simpler elements. An empty length
    /// range ends the case as a failure.
    pub fn vec<T>(
        &mut self,
        len: RangeInclusive<usize>,
        mut f: impl FnMut(&mut Gen) -> T,
    ) -> Vec<T> {
        let (min, max) = len.into_inner();
        if min > max {
            self.fail_case(format!("empty length range {min}..={max}"));
        }
        let mut many = Many::new(min, max);
        let mut out = Vec::new();
        loop {
            let start = self.position();
            if !many.more(self) {
                break;
            }
            let item = f(self);
            self.end_span(start);
            out.push(item);
        }
        out
    }

    /// Generates a byte vector whose length lies in `len`.
    pub fn bytes(&mut self, len: RangeInclusive<usize>) -> Vec<u8> {
        self.vec(len, Gen::u8)
    }

    /// Picks a reference to one element of `items`. Shrinks towards the first element.
    ///
    /// # Panics
    ///
    /// An empty slice ends the current case as a failure. The harness unwinds
    /// and reports the failure like any other.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let Some(max) = items.len().checked_sub(1) else {
            self.fail_case("Gen::pick called with an empty slice".to_owned());
        };
        let i = self.usize_in(0..=max);
        match items.get(i) {
            Some(item) => item,
            None => self.fail_case(format!("Gen::pick index {i} out of range")),
        }
    }

    /// Shuffles `items` in place with a Fisher-Yates shuffle. Shrinks towards
    /// the original order.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        let len = items.len();
        for i in 0..len.saturating_sub(1) {
            let offset = self.usize_in(0..=len.saturating_sub(1).saturating_sub(i));
            let j = i.saturating_add(offset);
            if j < len {
                items.swap(i, j);
            }
        }
    }

    /// Picks an index into `weights` with probability proportional to its weight.
    ///
    /// Indices with weight 0 are never returned. Shrinks towards the first
    /// index with a non-zero weight. Weights that are all zero, or an empty
    /// slice, end the current case as a failure.
    pub fn weighted(&mut self, weights: &[u32]) -> usize {
        let total = weights
            .iter()
            .try_fold(0u64, |acc, &w| acc.checked_add(u64::from(w)));
        let Some(max) = total.and_then(|t| t.checked_sub(1)) else {
            self.fail_case("Gen::weighted needs at least one non-zero weight".to_owned());
        };
        let c = self.uniform(max);
        let mut acc = 0u64;
        for (i, &w) in weights.iter().enumerate() {
            acc = acc.saturating_add(u64::from(w));
            if c < acc {
                return i;
            }
        }
        self.fail_case("Gen::weighted choice out of range".to_owned())
    }

    /// Generates `Some` value built by `f`, or `None`. Shrinks towards `None`.
    pub fn option<T>(&mut self, f: impl FnOnce(&mut Gen) -> T) -> Option<T> {
        if self.draw(1, |rng| rng.below(4).min(1)) == 1 {
            Some(f(self))
        } else {
            None
        }
    }

    /// Generates one ASCII character, biased towards letters, digits and
    /// characters that often break parsers. Shrinks towards `'a'`.
    pub fn ascii_char(&mut self) -> char {
        let c = self.draw(chars::ASCII_MAX_CHOICE, chars::random_ascii_choice);
        chars::ascii_from_choice(c)
    }

    /// Generates any Unicode scalar value, biased towards ASCII and towards
    /// encoding edge cases. Shrinks towards `'a'`.
    pub fn char(&mut self) -> char {
        let c = self.draw(chars::SCALAR_MAX_CHOICE, chars::random_scalar_choice);
        chars::scalar_from_choice(c)
    }

    /// Generates an ASCII string whose length in characters lies in `len`.
    pub fn ascii_string(&mut self, len: RangeInclusive<usize>) -> String {
        self.vec(len, Gen::ascii_char).into_iter().collect()
    }

    /// Generates a string of any Unicode scalar values whose length in
    /// characters (not bytes) lies in `len`. Biased towards edge cases.
    pub fn string(&mut self, len: RangeInclusive<usize>) -> String {
        self.vec(len, Gen::char).into_iter().collect()
    }
}

macro_rules! int_methods {
    ($($t:ident, $ranged:ident;)*) => {
        impl Gen {
            $(
                #[doc = concat!(
                    "Generates any `", stringify!($t), "`, biased towards zero, small values, ",
                    "the type bounds and power-of-two boundaries. Shrinks towards zero."
                )]
                pub fn $t(&mut self) -> $t {
                    self.$ranged(<$t>::MIN..=<$t>::MAX)
                }

                #[doc = concat!(
                    "Generates a `", stringify!($t), "` in `range`, biased towards both bounds, ",
                    "zero and small values. Shrinks towards the value in the range closest to zero.\n\n",
                    "An empty range ends the current case as a failure."
                )]
                pub fn $ranged(&mut self, range: RangeInclusive<$t>) -> $t {
                    let (lo, hi) = range.into_inner();
                    let v = self.int_in(lo as i128, hi as i128);
                    <$t>::try_from(v).unwrap_or(lo)
                }
            )*
        }
    };
}

int_methods! {
    u8, u8_in;
    u16, u16_in;
    u32, u32_in;
    u64, u64_in;
    usize, usize_in;
    i8, i8_in;
    i16, i16_in;
    i32, i32_in;
    i64, i64_in;
}

/// Counts elements of a collection and draws a continue flag before each
/// optional element. Used by [`Gen::vec`] and by stateful command sequences.
///
/// In random mode a target length is chosen once, edge-biased, and the flags
/// follow it. The target never asks for more elements than the remaining
/// choice budget allows, since each one draws a flag. In replay mode the
/// flags come from the sequence, and a 0 flag (also drawn past the end) stops
/// the collection.
pub(crate) struct Many {
    min: usize,
    max: usize,
    count: usize,
    target: Option<usize>,
}

impl Many {
    /// Creates a counter for a collection whose length lies in `min..=max`.
    pub(crate) fn new(min: usize, max: usize) -> Many {
        Many {
            min,
            max,
            count: 0,
            target: None,
        }
    }

    /// Returns whether the collection gets another element.
    pub(crate) fn more(&mut self, g: &mut Gen) -> bool {
        if self.count >= self.max {
            return false;
        }
        let go = if self.count < self.min {
            true
        } else {
            let (count, min, max) = (self.count, self.min, self.max);
            let budget = g.max_choices.saturating_sub(g.position());
            let target = &mut self.target;
            let flag = g.draw(1, |rng| {
                let t = *target.get_or_insert_with(|| target_len(rng, min, max, budget));
                u64::from(count < t)
            });
            flag == 1
        };
        if go {
            self.count = self.count.saturating_add(1);
        }
        go
    }
}

/// Picks an edge-biased target length in `min..=max`.
///
/// `budget` is the number of choices the case may still draw. Every element
/// beyond `min` draws at least one flag, so the extra length is capped at the
/// budget. Within that cap, three draws in sixteen pick the minimum and one
/// picks one more. One picks the maximum when it fits the budget, and a small
/// extra length otherwise. Eight pick small extra lengths. Two pick a
/// log-uniform extra length up to the cap's bit length, and one picks a
/// uniform one, so every length up to the cap can occur.
fn target_len(rng: &mut Rng, min: usize, max: usize, budget: usize) -> usize {
    let span = max.saturating_sub(min);
    let cap = span.min(budget);
    let cap64 = u64::try_from(cap).unwrap_or(u64::MAX);
    let extra = match rng.below(16) {
        0..=2 => 0,
        3 => 1,
        4 if span <= budget => cap64,
        4..=9 => rng.upto(cap64.min(8)),
        10..=12 => rng.upto(cap64.min(32)),
        13 | 14 => {
            let width = u64::from(u64::BITS.saturating_sub(cap64.leading_zeros()));
            let bits = u32::try_from(rng.upto(width)).unwrap_or(0);
            let limit = 1u64
                .checked_shl(bits)
                .map_or(u64::MAX, |v| v.saturating_sub(1));
            rng.upto(cap64.min(limit))
        }
        _ => rng.upto(cap64),
    };
    min.saturating_add(usize::try_from(extra.min(cap64)).unwrap_or(cap))
}

/// Returns the value in `lo..=hi` closest to zero. Requires `lo <= hi`.
fn origin(lo: i128, hi: i128) -> i128 {
    if lo > 0 {
        lo
    } else if hi < 0 {
        hi
    } else {
        0
    }
}

/// Maps a choice in `0..=hi-lo` to a value in `lo..=hi`.
///
/// Choice 0 is the origin (the value closest to zero). Odd choices step up and
/// even choices step down, alternating until one side of the range runs out.
/// The remaining choices continue on the longer side. This is a bijection, and
/// a smaller choice is never further from the origin.
pub(crate) fn zigzag(lo: i128, hi: i128, c: u64) -> i128 {
    let o = origin(lo, hi);
    let up = hi.saturating_sub(o);
    let down = o.saturating_sub(lo);
    let m = up.min(down);
    let c = i128::from(c);
    let v = if c <= m.saturating_mul(2) {
        let half = c.saturating_add(1).checked_div(2).unwrap_or(0);
        if c == 0 {
            o
        } else if c.checked_rem(2) == Some(1) {
            o.saturating_add(half)
        } else {
            o.saturating_sub(half)
        }
    } else {
        let k = c.saturating_sub(m.saturating_mul(2));
        if up > down {
            o.saturating_add(m).saturating_add(k)
        } else {
            o.saturating_sub(m).saturating_sub(k)
        }
    };
    v.max(lo).min(hi)
}

/// Inverse of [`zigzag`]: returns the choice that maps to `v`, clamping `v` into range.
pub(crate) fn unzigzag(lo: i128, hi: i128, v: i128) -> u64 {
    let v = v.max(lo).min(hi);
    let o = origin(lo, hi);
    let up = hi.saturating_sub(o);
    let down = o.saturating_sub(lo);
    let m = up.min(down);
    let c = if v >= o {
        let d = v.saturating_sub(o);
        if d == 0 {
            0
        } else if d <= m {
            d.saturating_mul(2).saturating_sub(1)
        } else {
            m.saturating_mul(2).saturating_add(d.saturating_sub(m))
        }
    } else {
        let d = o.saturating_sub(v);
        if d <= m {
            d.saturating_mul(2)
        } else {
            m.saturating_mul(2).saturating_add(d.saturating_sub(m))
        }
    };
    u64::try_from(c).unwrap_or(u64::MAX)
}

/// Picks an edge-biased integer choice for the range `lo..=hi` with `n = hi - lo`.
///
/// One draw in sixteen each picks the lower bound, the upper bound, the
/// origin, a neighbour of the origin, and a neighbour of a bound. Two in
/// sixteen pick a power-of-two boundary inside the range. The rest pick small
/// values, values of random bit width, and uniform values.
fn int_choice(rng: &mut Rng, lo: i128, hi: i128, n: u64) -> u64 {
    let at = |v: i128| unzigzag(lo, hi, v);
    match rng.below(16) {
        0 => at(lo),
        1 => at(hi),
        2 => 0,
        3 => rng.upto(n.min(2)),
        4 => {
            if rng.coin() {
                at(lo.saturating_add(1))
            } else {
                at(hi.saturating_sub(1))
            }
        }
        5 | 6 => match pick_boundary(rng, lo, hi) {
            Some(v) => at(v),
            None => rng.upto(n),
        },
        7 | 8 => rng.upto(n.min(32)),
        9..=11 => {
            let bits = u32::try_from(rng.below(65)).unwrap_or(64);
            let mask = u64::MAX
                .checked_shr(64u32.saturating_sub(bits))
                .unwrap_or(0);
            let raw = rng.next_u64() & mask;
            match n.checked_add(1) {
                Some(m) => raw.checked_rem(m).unwrap_or(0),
                None => raw,
            }
        }
        _ => rng.upto(n),
    }
}

/// Picks a power-of-two boundary (`2^k - 1`, `2^k`, `-2^k`, `-2^k - 1` for
/// the widths in [`BOUNDARY_BITS`]) that lies strictly inside `lo..=hi`.
fn pick_boundary(rng: &mut Rng, lo: i128, hi: i128) -> Option<i128> {
    let mut found = [0i128; BOUNDARY_BITS.len() * 4];
    let mut count = 0usize;
    for bits in BOUNDARY_BITS {
        let p = 1i128.checked_shl(bits).unwrap_or(0);
        for v in [
            p.saturating_sub(1),
            p,
            p.saturating_neg(),
            p.saturating_neg().saturating_sub(1),
        ] {
            if lo < v
                && v < hi
                && let Some(slot) = found.get_mut(count)
            {
                *slot = v;
                count = count.saturating_add(1);
            }
        }
    }
    found.get(rng.index(count)).copied().filter(|_| count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zigzag_is_a_bijection_on_small_ranges() {
        for lo in -6i128..=6 {
            for hi in lo..=7 {
                let n = u64::try_from(hi - lo).unwrap();
                let mut seen = Vec::new();
                let mut last_distance = 0i128;
                for c in 0..=n {
                    let v = zigzag(lo, hi, c);
                    assert!((lo..=hi).contains(&v));
                    assert!(!seen.contains(&v), "{lo}..={hi} repeats {v}");
                    seen.push(v);
                    assert_eq!(unzigzag(lo, hi, v), c);
                    let d = (v - origin(lo, hi)).abs();
                    assert!(d >= last_distance, "distance decreased at {c}");
                    last_distance = d;
                }
            }
        }
    }

    #[test]
    fn zigzag_round_trips_on_full_ranges() {
        let ranges = [
            (0i128, i128::from(u64::MAX)),
            (i128::from(i64::MIN), i128::from(i64::MAX)),
            (i128::from(i8::MIN), i128::from(i8::MAX)),
            (-10, 1_000_000),
            (-1_000_000, 10),
            (5, 9),
            (-9, -5),
        ];
        let mut rng = Rng::new(11);
        for (lo, hi) in ranges {
            let n = u64::try_from(hi - lo).unwrap();
            for c in [0, 1, 2, 3, n / 2, n.saturating_sub(1), n] {
                let v = zigzag(lo, hi, c);
                assert!((lo..=hi).contains(&v));
                assert_eq!(unzigzag(lo, hi, v), c);
            }
            for _ in 0..1000 {
                let c = rng.upto(n);
                assert_eq!(unzigzag(lo, hi, zigzag(lo, hi, c)), c);
            }
            assert_eq!(zigzag(lo, hi, 0), origin(lo, hi));
        }
        assert_eq!(
            zigzag(i128::from(i64::MIN), i128::from(i64::MAX), u64::MAX),
            i128::from(i64::MIN)
        );
        assert_eq!(zigzag(i128::from(i64::MIN), i128::from(i64::MAX), 1), 1);
        assert_eq!(zigzag(i128::from(i64::MIN), i128::from(i64::MAX), 2), -1);
    }

    #[test]
    fn int_choice_stays_in_range() {
        let mut rng = Rng::new(5);
        for (lo, hi) in [
            (0i128, 0i128),
            (0, 1),
            (-3, 3),
            (0, i128::from(u64::MAX)),
            (100, 200),
        ] {
            let n = u64::try_from(hi - lo).unwrap();
            for _ in 0..5000 {
                assert!(int_choice(&mut rng, lo, hi, n) <= n);
            }
        }
    }

    #[test]
    fn target_len_stays_in_range() {
        let mut rng = Rng::new(6);
        for (min, max) in [
            (0, 0),
            (0, 1),
            (3, 3),
            (2, 10),
            (0, usize::MAX),
            (5, 100_000),
        ] {
            for budget in [0, 1, 7, 65_536, usize::MAX] {
                for _ in 0..2000 {
                    let t = target_len(&mut rng, min, max, budget);
                    assert!((min..=max).contains(&t), "{t} not in {min}..={max}");
                    assert!(t - min <= budget, "{t} exceeds budget {budget} over {min}");
                }
            }
        }
    }

    /// Every part of a wide length range occurs, including the middle and
    /// the exact maximum when it fits the budget (review finding
    /// prop-wide-length-hole).
    #[test]
    fn target_len_covers_wide_ranges() {
        let mut rng = Rng::new(8);
        let mut buckets = [0u32; 8];
        let mut max_hits = 0u32;
        for _ in 0..20_000 {
            let t = target_len(&mut rng, 0, 4096, 65_536);
            buckets[(t * 8 / 4097).min(7)] += 1;
            max_hits += u32::from(t == 4096);
        }
        assert!(buckets.iter().all(|&b| b > 0), "{buckets:?}");
        assert!(max_hits > 0);
        // A span wider than the budget reaches the budget but never beyond it.
        let mut longest = 0;
        for _ in 0..20_000 {
            longest = longest.max(target_len(&mut rng, 10, 1_000_000, 50_000));
        }
        assert!(longest > 10 + 40_000, "{longest}");
        assert!(longest <= 10 + 50_000, "{longest}");
    }

    #[test]
    fn replay_past_end_draws_zero_and_clamps() {
        let mut g = Gen::replay(vec![5, 300], 100);
        assert_eq!(g.draw(10, |_| 99), 5);
        assert_eq!(g.draw(255, |_| 99), 255);
        assert_eq!(g.draw(7, |_| 99), 0);
        let rec = g.into_recording();
        assert_eq!(rec.choices, vec![5, 255]);
    }
}
