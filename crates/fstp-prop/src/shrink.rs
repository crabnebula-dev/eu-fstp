//! Shrinking of failing choice sequences.
//!
//! The shrinker edits the choice sequence of a failing case and runs the
//! property again on each candidate. It keeps a candidate when the property
//! still fails and the recorded sequence is smaller in shortlex order: shorter
//! first, then lexicographically smaller. Shortlex order is well-founded, so
//! shrinking always terminates. It also stops after `max_steps` property runs.
//!
//! Cheap passes, repeated until nothing changes:
//! - delete recorded spans (structural units such as vector elements), or zero them;
//! - delete chunks of 8, 4, 2 and 1 choices, growing a deletion that succeeds;
//! - zero chunks of 8, 4 and 2 choices;
//! - minimise each choice by binary search (this also covers zeroing one choice).
//!
//! Then the pair pass adjusts pairs of nearby choices: it lowers both
//! together, or moves value from the earlier choice to the later one. If it
//! changes anything, the whole cycle repeats.
//!
//! Signed integers map to choices that alternate sides of zero (see
//! `generator::zigzag`). Minimisation and pair moves therefore also search in
//! steps of two, which stay on one side of zero.

use std::collections::HashSet;

use crate::exec::{Status, execute};
use crate::generator::Gen;

/// Chunk sizes for the deletion pass.
const DELETE_SIZES: [usize; 4] = [8, 4, 2, 1];
/// Chunk sizes for the zeroing pass. Single choices are zeroed by minimisation.
const ZERO_SIZES: [usize; 3] = [8, 4, 2];
/// Maximum distance between the two choices of a pair.
const PAIR_WINDOW: usize = 8;

/// Returns whether `a` is strictly smaller than `b` in shortlex order.
pub(crate) fn shortlex_lt(a: &[u64], b: &[u64]) -> bool {
    a.len() < b.len() || (a.len() == b.len() && a < b)
}

/// Returns `seq` without trailing zeros. A replay draws 0 past the end, so
/// trailing zeros carry no information.
fn trim_zeros(seq: &[u64]) -> &[u64] {
    let end = seq
        .iter()
        .rposition(|&c| c != 0)
        .map_or(0, |i| i.saturating_add(1));
    seq.get(..end).unwrap_or(seq)
}

/// A stable 64-bit hash of a sequence (FNV-1a over little-endian words).
fn hash_seq(seq: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in seq {
        for b in c.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h ^ u64::try_from(seq.len()).unwrap_or(u64::MAX)
}

/// Returns `seq` with `len` choices removed at `start`, or `None` when out of range.
fn without(seq: &[u64], start: usize, len: usize) -> Option<Vec<u64>> {
    let (head, rest) = seq.split_at_checked(start)?;
    let tail = rest.get(len..)?;
    let mut out = Vec::with_capacity(head.len().saturating_add(tail.len()));
    out.extend_from_slice(head);
    out.extend_from_slice(tail);
    Some(out)
}

/// Returns `seq` with `len` choices set to zero at `start`, or `None` when
/// out of range or already zero.
fn zeroed(seq: &[u64], start: usize, len: usize) -> Option<Vec<u64>> {
    let end = start.checked_add(len)?;
    let chunk = seq.get(start..end)?;
    if chunk.iter().all(|&c| c == 0) {
        return None;
    }
    let mut out = seq.to_vec();
    out.get_mut(start..end)?.fill(0);
    Some(out)
}

/// Returns `seq` with the choices at `i` and `j` replaced.
fn with_pair(seq: &[u64], i: usize, a: u64, j: usize, b: u64) -> Vec<u64> {
    let mut out = seq.to_vec();
    if let Some(x) = out.get_mut(i) {
        *x = a;
    }
    if let Some(x) = out.get_mut(j) {
        *x = b;
    }
    out
}

/// Shrinks one failing case.
pub(crate) struct Shrinker<'a, F> {
    prop: &'a F,
    max_choices: usize,
    max_steps: u32,
    /// The smallest failing sequence found so far.
    pub(crate) best: Vec<u64>,
    /// Spans recorded by the run of `best`.
    spans: Vec<(usize, usize)>,
    /// Failure message of the run of `best`.
    pub(crate) message: String,
    /// Property runs spent so far.
    pub(crate) steps: u32,
    /// Candidates that replaced `best`.
    pub(crate) accepted: u32,
    /// Hashes of candidates that did not improve, to avoid running them again.
    seen: HashSet<u64>,
}

impl<'a, F> Shrinker<'a, F>
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    /// Creates a shrinker for a failing case with the given recorded choices and spans.
    pub(crate) fn new(
        prop: &'a F,
        max_choices: usize,
        max_steps: u32,
        best: Vec<u64>,
        spans: Vec<(usize, usize)>,
        message: String,
    ) -> Self {
        Shrinker {
            prop,
            max_choices,
            max_steps,
            best,
            spans,
            message,
            steps: 0,
            accepted: 0,
            seen: HashSet::new(),
        }
    }

    /// Runs all passes until a fixpoint or until the step budget is spent.
    pub(crate) fn shrink(&mut self) {
        loop {
            // The cheap passes run to their own fixpoint first. The pair pass
            // costs a few runs per pair, so it runs only once they stall.
            loop {
                let before = self.best.clone();
                self.pass_spans();
                self.pass_delete();
                self.pass_zero();
                self.pass_minimize();
                if self.exhausted() || self.best == before {
                    break;
                }
            }
            let before = self.best.clone();
            self.pass_pairs();
            if self.exhausted() || self.best == before {
                break;
            }
        }
    }

    fn exhausted(&self) -> bool {
        self.steps >= self.max_steps
    }

    /// Runs the property on `candidate` and keeps it if it fails with a
    /// shortlex-smaller recording. Returns whether `best` changed.
    fn consider(&mut self, candidate: &[u64]) -> bool {
        let candidate = trim_zeros(candidate);
        if !shortlex_lt(candidate, &self.best) {
            return false;
        }
        let key = hash_seq(candidate);
        if self.seen.contains(&key) || self.exhausted() {
            return false;
        }
        self.steps = self.steps.saturating_add(1);
        let mut g = Gen::replay(candidate.to_vec(), self.max_choices);
        if let Status::Fail(message) = execute(self.prop, &mut g) {
            let rec = g.into_recording();
            if shortlex_lt(&rec.choices, &self.best) {
                self.best = rec.choices;
                self.spans = rec.spans;
                self.message = message;
                self.accepted = self.accepted.saturating_add(1);
                return true;
            }
        }
        self.seen.insert(key);
        false
    }

    /// Deletes or zeroes each recorded span, last span first.
    fn pass_spans(&mut self) {
        let mut j = self.spans.len();
        while let Some(next) = j.checked_sub(1) {
            j = next;
            if self.exhausted() {
                return;
            }
            let Some(&(start, end)) = self.spans.get(j) else {
                continue;
            };
            let len = end.saturating_sub(start);
            if len == 0 {
                continue;
            }
            if let Some(c) = without(&self.best, start, len)
                && self.consider(&c)
            {
                continue;
            }
            if let Some(c) = zeroed(&self.best, start, len) {
                self.consider(&c);
            }
        }
    }

    /// Deletes chunks of each size, from the back to the front.
    fn pass_delete(&mut self) {
        for size in DELETE_SIZES {
            let mut i = self.best.len().saturating_sub(size);
            loop {
                if self.exhausted() {
                    return;
                }
                if i.saturating_add(size) <= self.best.len() {
                    self.delete_at(i, size);
                }
                match i.checked_sub(1) {
                    Some(prev) => i = prev,
                    None => break,
                }
            }
        }
    }

    /// Deletes `size` choices at `i`. On success, keeps doubling the deletion.
    /// On failure, also tries the deletion with the previous choice lowered by
    /// one, which repairs a length or count that precedes the chunk.
    fn delete_at(&mut self, i: usize, size: usize) {
        let Some(candidate) = without(&self.best, i, size) else {
            return;
        };
        if self.consider(&candidate) {
            let mut extra = size;
            loop {
                let remaining = self.best.len().saturating_sub(i);
                if remaining == 0 || self.exhausted() {
                    return;
                }
                let take = extra.min(remaining);
                let Some(c) = without(&self.best, i, take) else {
                    return;
                };
                if !self.consider(&c) || take == remaining {
                    return;
                }
                extra = extra.saturating_mul(2);
            }
        }
        if let Some(prev) = i.checked_sub(1) {
            let mut c = candidate;
            if let Some(v) = c.get_mut(prev)
                && *v > 0
            {
                *v = v.saturating_sub(1);
                self.consider(&c);
            }
        }
    }

    /// Zeroes chunks of each size, from the front to the back.
    fn pass_zero(&mut self) {
        for size in ZERO_SIZES {
            let mut i = 0;
            while i < self.best.len() {
                if self.exhausted() {
                    return;
                }
                let len = size.min(self.best.len().saturating_sub(i));
                if let Some(c) = zeroed(&self.best, i, len) {
                    self.consider(&c);
                }
                i = i.saturating_add(1);
            }
        }
    }

    /// Minimises each choice by binary search, from the front to the back.
    fn pass_minimize(&mut self) {
        let mut i = 0;
        while i < self.best.len() {
            if self.exhausted() {
                return;
            }
            self.minimize_at(i);
            i = i.saturating_add(1);
        }
    }

    /// Finds the smallest value for choice `i` that still fails, assuming
    /// monotonicity. Stops early if the structure of `best` shifts.
    fn minimize_at(&mut self, i: usize) {
        let Some(&current) = self.best.get(i) else {
            return;
        };
        if current == 0 || self.try_value(i, 0) {
            return;
        }
        let Some(hi) = self.bisect(i, current, 1) else {
            return;
        };
        // Signed integers alternate sides of zero with the parity of their
        // choice, so the failing choices need not be monotone. Search the
        // values of the same parity as well. One run settles the common case.
        if hi >= 2 {
            self.bisect(i, hi, 2);
        }
    }

    /// Sets choice `i` to `v` in a copy of `best` and considers it.
    fn try_value(&mut self, i: usize, v: u64) -> bool {
        let mut c = self.best.clone();
        match c.get_mut(i) {
            Some(x) => *x = v,
            None => return false,
        }
        self.consider(&c)
    }

    /// Binary search for the smallest failing value of choice `i` among
    /// `hi - k * step` for k >= 0, where `hi` is known to fail. For step 2 the
    /// value `hi - step` is tried first, so a search with nothing to gain costs
    /// one run. Returns the final failing value, or `None` if `best` stopped
    /// lining up with the search.
    fn bisect(&mut self, i: usize, hi: u64, step: u64) -> Option<u64> {
        // Search over k: the value is `base + k * step`, with k = 0 the smallest.
        let base = hi.checked_rem(step).unwrap_or(0);
        let mut k_hi = hi.checked_div(step).unwrap_or(0);
        // The smallest candidate is known not to fail when it is 0 (tried
        // already); otherwise k = 0 still needs a run.
        let mut k_lo: Option<u64> = if base == 0 { Some(0) } else { None };
        if step > 1 {
            let Some(below) = k_hi.checked_sub(1) else {
                return Some(hi);
            };
            if below == 0 && base == 0 {
                return Some(hi);
            }
            let v = base.saturating_add(below.saturating_mul(step));
            if !self.try_value(i, v) {
                return Some(hi);
            }
            if self.best.get(i) != Some(&v) {
                return None;
            }
            k_hi = below;
        }
        if k_lo.is_none() {
            if self.try_value(i, base) {
                return (self.best.get(i) == Some(&base)).then_some(base);
            }
            k_lo = Some(0);
        }
        let mut lo = k_lo.unwrap_or(0);
        while lo.saturating_add(1) < k_hi {
            if self.exhausted() {
                break;
            }
            let mid = lo.saturating_add(k_hi.saturating_sub(lo) / 2);
            let v = base.saturating_add(mid.saturating_mul(step));
            if self.try_value(i, v) {
                if self.best.get(i) != Some(&v) {
                    return None;
                }
                k_hi = mid;
            } else {
                lo = mid;
            }
        }
        Some(base.saturating_add(k_hi.saturating_mul(step)))
    }

    /// Adjusts every pair of choices at most [`PAIR_WINDOW`] apart.
    fn pass_pairs(&mut self) {
        let mut i = 0;
        while i < self.best.len() {
            for d in 1..=PAIR_WINDOW {
                if self.exhausted() {
                    return;
                }
                let j = i.saturating_add(d);
                if j >= self.best.len() {
                    break;
                }
                self.lower_pair(i, j);
                self.move_between(i, j);
            }
            i = i.saturating_add(1);
        }
    }

    /// Lowers choices `i` and `j` together by the largest amount that still fails.
    fn lower_pair(&mut self, i: usize, j: usize) {
        let (Some(&a), Some(&b)) = (self.best.get(i), self.best.get(j)) else {
            return;
        };
        let limit = a.min(b);
        if limit == 0 {
            return;
        }
        let base = self.best.clone();
        self.adjust_pair(limit, |d| {
            with_pair(&base, i, a.saturating_sub(d), j, b.saturating_sub(d))
        });
    }

    /// Moves the largest amount that still fails from choice `i` to choice `j`.
    /// The earlier choice decreases, so each accepted move is shortlex smaller.
    fn move_between(&mut self, i: usize, j: usize) {
        let (Some(&a), Some(&b)) = (self.best.get(i), self.best.get(j)) else {
            return;
        };
        if a == 0 {
            return;
        }
        let base = self.best.clone();
        self.adjust_pair(a, |d| {
            with_pair(&base, i, a.saturating_sub(d), j, b.saturating_add(d))
        });
    }

    /// Searches for a large change `d` in `1..=limit` for which `make(d)`
    /// still fails. When steps of 1 achieve nothing, it retries with even
    /// steps, which keep the side of zero of signed integers.
    fn adjust_pair(&mut self, limit: u64, make: impl Fn(u64) -> Vec<u64>) {
        if self.find_max_k(limit, &make) || limit < 2 {
            return;
        }
        self.find_max_k(limit / 2, |k| make(k.saturating_mul(2)));
    }

    /// Finds a large `k` in `1..=limit` for which `make(k)` still fails.
    /// Tries 1 first, then `limit`, then binary search between them. Returns
    /// whether any candidate was accepted.
    fn find_max_k(&mut self, limit: u64, make: impl Fn(u64) -> Vec<u64>) -> bool {
        if limit == 0 || !self.consider(&make(1)) {
            return false;
        }
        if limit == 1 || self.consider(&make(limit)) {
            return true;
        }
        let (mut lo, mut hi) = (1u64, limit);
        while lo.saturating_add(1) < hi {
            if self.exhausted() {
                break;
            }
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            if self.consider(&make(mid)) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortlex_order() {
        assert!(shortlex_lt(&[], &[0]));
        assert!(shortlex_lt(&[9], &[0, 0]));
        assert!(shortlex_lt(&[1, 2], &[1, 3]));
        assert!(!shortlex_lt(&[1, 3], &[1, 3]));
        assert!(!shortlex_lt(&[2], &[1]));
    }

    #[test]
    fn helpers() {
        assert_eq!(trim_zeros(&[1, 0, 2, 0, 0]), &[1, 0, 2]);
        assert_eq!(trim_zeros(&[0, 0]), &[] as &[u64]);
        assert_eq!(without(&[1, 2, 3, 4], 1, 2), Some(vec![1, 4]));
        assert_eq!(without(&[1, 2, 3, 4], 3, 2), None);
        assert_eq!(zeroed(&[1, 2, 3], 1, 2), Some(vec![1, 0, 0]));
        assert_eq!(zeroed(&[1, 0, 0], 1, 2), None);
        assert_eq!(with_pair(&[5, 6, 7], 0, 1, 2, 9), vec![1, 6, 9]);
        assert_ne!(hash_seq(&[1, 0]), hash_seq(&[1]));
    }
}
