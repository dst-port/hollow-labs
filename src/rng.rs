//! Deterministic PRNG on splitmix64 / xorshift128+.
//!
//! No external dependencies — all scenario and quiz randomization flows through
//! a single seed so that groups and instructors can reproduce a run with the
//! `--seed N` flag.

/// Fast deterministic generator. One seed -> one stream of numbers.
#[derive(Clone, Debug)]
pub struct Rng {
    s0: u64,
    s1: u64,
}

impl Rng {
    /// Builds a generator from a seed. Any u64 is valid, including 0.
    pub fn new(seed: u64) -> Self {
        // Spread the seed through splitmix64 to get two non-zero words.
        let mut z = seed;
        let s0 = splitmix64(&mut z);
        let s1 = splitmix64(&mut z);
        Self {
            s0: s0 | 1,
            s1: s1 | 1,
        }
    }

    /// Next 64-bit number (xorshift128+).
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s0;
        let y = self.s1;
        self.s0 = y;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        self.s1 = x;
        x.wrapping_add(y)
    }

    /// Number in `[0, n)`. Returns 0 when `n == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Drop the tail to avoid modulo bias.
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// Number in the inclusive range `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        lo + self.below(hi - lo + 1)
    }

    /// `true` with probability `p` (0.0..=1.0).
    pub fn chance(&mut self, p: f64) -> bool {
        (self.next_u64() as f64 / u64::MAX as f64) < p
    }

    /// Random element of a slice. `None` if the slice is empty.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let i = self.below(items.len() as u64) as usize;
        Some(&items[i])
    }

    /// In-place shuffle of a slice (Fisher–Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        let len = items.len();
        if len < 2 {
            return;
        }
        for i in (1..len).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }

    /// Fork an independent stream — for generating several artifacts in
    /// parallel without overlapping sequences.
    pub fn fork(&mut self) -> Rng {
        Rng::new(self.next_u64())
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_respects_bound() {
        let mut r = Rng::new(7);
        for _ in 0..10_000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn range_is_inclusive() {
        let mut r = Rng::new(9);
        let mut saw_lo = false;
        let mut saw_hi = false;
        for _ in 0..10_000 {
            let v = r.range(5, 8);
            assert!((5..=8).contains(&v));
            saw_lo |= v == 5;
            saw_hi |= v == 8;
        }
        assert!(saw_lo && saw_hi);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut r = Rng::new(123);
        let mut v: Vec<u32> = (0..50).collect();
        r.shuffle(&mut v);
        v.sort();
        assert_eq!(v, (0..50).collect::<Vec<_>>());
    }
}
