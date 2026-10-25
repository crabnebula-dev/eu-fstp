//! Deterministic, non-cryptographic pseudo-random numbers for test generation.
//!
//! The generator is xoshiro256** seeded through SplitMix64. It is used only
//! to pick test inputs. It is not suitable for anything security related.

/// Advances a SplitMix64 state and returns the next output.
pub(crate) fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ z.wrapping_shr(31)
}

/// A xoshiro256** generator.
#[derive(Clone, Debug)]
pub(crate) struct Rng {
    s: [u64; 4],
}

impl Rng {
    /// Creates a generator whose state is expanded from `seed` with SplitMix64.
    pub(crate) fn new(seed: u64) -> Rng {
        let mut st = seed;
        let s = [
            splitmix64(&mut st),
            splitmix64(&mut st),
            splitmix64(&mut st),
            splitmix64(&mut st),
        ];
        Rng { s }
    }

    /// Creates a generator from a raw state, for reference-vector tests.
    #[cfg(test)]
    pub(crate) fn from_state(s: [u64; 4]) -> Rng {
        Rng { s }
    }

    /// Returns the next 64 random bits.
    pub(crate) fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1.wrapping_shl(17);
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        let s2 = s2 ^ t;
        let s3 = s3.rotate_left(45);
        self.s = [s0, s1, s2, s3];
        result
    }

    /// Returns a uniform value in `0..n`, or 0 when `n` is 0.
    ///
    /// Uses Lemire's multiply-and-reject method, so there is no modulo bias.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let threshold = n.wrapping_neg().checked_rem(n).unwrap_or(0);
        loop {
            let m = u128::from(self.next_u64()).wrapping_mul(u128::from(n));
            let low = m as u64;
            if low >= threshold {
                return m.wrapping_shr(64) as u64;
            }
        }
    }

    /// Returns a uniform value in `0..=max`.
    pub(crate) fn upto(&mut self, max: u64) -> u64 {
        match max.checked_add(1) {
            Some(n) => self.below(n),
            None => self.next_u64(),
        }
    }

    /// Returns a uniform boolean.
    pub(crate) fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Returns a uniform index into a collection of `len` items, or 0 when empty.
    pub(crate) fn index(&mut self, len: usize) -> usize {
        let n = u64::try_from(len).unwrap_or(u64::MAX);
        usize::try_from(self.below(n)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published xoshiro256** reference output for the state {1, 2, 3, 4}.
    #[test]
    fn xoshiro_reference_vector() {
        let mut r = Rng::from_state([1, 2, 3, 4]);
        let got: Vec<u64> = (0..4).map(|_| r.next_u64()).collect();
        assert_eq!(
            got,
            vec![11520, 0, 1_509_978_240, 1_215_971_899_390_074_240]
        );
    }

    /// `Rng::new` expands the seed with SplitMix64. The expected states and
    /// outputs were computed by an independent implementation. Changing them
    /// changes every default run, so they must never change (review finding
    /// prop-selftest-generator-gap).
    #[test]
    fn new_matches_golden_values() {
        let mut r = Rng::new(0);
        let mut by_state = Rng::from_state([
            0xe220_a839_7b1d_cdaf,
            0x6e78_9e6a_a1b9_65f4,
            0x06c4_5d18_8009_454f,
            0xf88b_b8a8_724c_81ec,
        ]);
        let want = [
            0x99ec_5f36_cb75_f2b4,
            0xbf6e_1f78_4956_452a,
            0x1a5f_849d_4933_e6e0,
        ];
        for w in want {
            assert_eq!(r.next_u64(), w);
            assert_eq!(by_state.next_u64(), w);
        }
        let mut r = Rng::new(42);
        let got: Vec<u64> = (0..3).map(|_| r.next_u64()).collect();
        assert_eq!(
            got,
            vec![
                0x1578_0b2e_0c2e_c716,
                0x6104_d986_6d11_3a7e,
                0xae17_5332_39e4_99a1
            ]
        );
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
    }

    #[test]
    fn below_and_upto_stay_in_range() {
        let mut r = Rng::new(7);
        for n in [1u64, 2, 3, 7, 100, 1 << 40, u64::MAX] {
            for _ in 0..1000 {
                assert!(r.below(n) < n);
                assert!(r.upto(n) <= n);
            }
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.upto(0), 0);
        assert_eq!(r.index(0), 0);
    }

    #[test]
    fn below_covers_small_ranges() {
        let mut r = Rng::new(9);
        let mut seen = [false; 5];
        for _ in 0..200 {
            seen[usize::try_from(r.below(5)).unwrap()] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }
}
