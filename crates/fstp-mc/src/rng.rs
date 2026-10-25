//! Deterministic, non-cryptographic pseudo-random numbers for random walks.
//!
//! SplitMix64 picks the next action of a simulated walk. It is not suitable
//! for anything security related.

/// A SplitMix64 generator.
#[derive(Clone, Debug)]
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a uniform index in `0..len`, or 0 when `len` is 0.
    ///
    /// Lemire's multiply-and-reject method, so there is no modulo bias.
    pub(crate) fn index(&mut self, len: usize) -> usize {
        let Ok(n) = u64::try_from(len) else {
            return 0;
        };
        if n == 0 {
            return 0;
        }
        let threshold = n.wrapping_neg().checked_rem(n).unwrap_or(0);
        loop {
            let m = u128::from(self.next_u64()).wrapping_mul(u128::from(n));
            if (m as u64) >= threshold {
                return usize::try_from(m >> 64).unwrap_or(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64 reference output for seed 1234567 (from the public
    /// reference implementation by Sebastiano Vigna).
    #[test]
    fn splitmix_reference_vector() {
        let mut r = SplitMix64::new(1_234_567);
        let got: Vec<u64> = (0..3).map(|_| r.next_u64()).collect();
        assert_eq!(
            got,
            vec![
                6_457_827_717_110_365_317,
                3_203_168_211_198_807_973,
                9_817_491_932_198_370_423
            ]
        );
    }

    #[test]
    fn index_stays_in_range_and_covers() {
        let mut r = SplitMix64::new(9);
        let mut seen = [false; 7];
        for _ in 0..1000 {
            let i = r.index(7);
            assert!(i < 7);
            seen[i] = true;
        }
        assert!(seen.iter().all(|&s| s));
        assert_eq!(r.index(0), 0);
        assert_eq!(r.index(1), 0);
    }
}
