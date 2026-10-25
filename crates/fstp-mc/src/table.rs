//! An open-addressing index from full states to their position in a vector.
//!
//! The visited set keeps every state exactly once, inside the node vector.
//! This table maps a state to its node by hash, then confirms the match by
//! comparing full states. A hash collision therefore costs time and never
//! merges two distinct states. Hash values never influence exploration order.

use core::hash::{BuildHasher, Hash};
use std::hash::{BuildHasherDefault, DefaultHasher};

/// Hashes a state with a fixed-key hasher. The value only picks a slot.
pub(crate) fn hash_state<S: Hash>(state: &S) -> u64 {
    BuildHasherDefault::<DefaultHasher>::default().hash_one(state)
}

const MIN_SLOTS: usize = 16;

/// Result of a lookup.
pub(crate) enum Probe {
    /// The state is stored at this node index.
    Found(usize),
    /// The state is absent; this empty slot is where it belongs.
    Vacant(usize),
}

/// Linear-probing table of node indices. A slot holds `index + 1`, or 0
/// when empty. The load factor stays at or below one half, so every probe
/// sequence reaches an empty slot.
pub(crate) struct IndexTable {
    slots: Vec<usize>,
    len: usize,
}

impl IndexTable {
    pub(crate) fn new() -> IndexTable {
        IndexTable {
            slots: vec![0; MIN_SLOTS],
            len: 0,
        }
    }

    fn mask(&self) -> usize {
        // The slot count is a power of two of at least MIN_SLOTS.
        self.slots.len().wrapping_sub(1)
    }

    fn start(&self, hash: u64) -> usize {
        // Truncation on 32-bit targets is fine: any bits pick a slot.
        (hash as usize) & self.mask()
    }

    /// Looks up a state with hash `hash`. `is_match(i)` must return true
    /// when node `i` holds the state.
    pub(crate) fn probe(&self, hash: u64, mut is_match: impl FnMut(usize) -> bool) -> Probe {
        let mask = self.mask();
        let mut i = self.start(hash);
        for _ in 0..self.slots.len() {
            match self.slots.get(i) {
                Some(&0) | None => return Probe::Vacant(i),
                Some(&v) => {
                    let node = v.wrapping_sub(1);
                    if is_match(node) {
                        return Probe::Found(node);
                    }
                }
            }
            i = i.wrapping_add(1) & mask;
        }
        // Unreachable while the load factor is at most one half.
        Probe::Vacant(self.slots.len())
    }

    /// True when one more insertion would push the load factor above one half.
    pub(crate) fn needs_growth(&self) -> bool {
        self.len.saturating_add(1).saturating_mul(2) > self.slots.len()
    }

    /// Stores node index `node` in the empty slot `slot` from a
    /// [`Probe::Vacant`] result. Returns false if the slot is not empty.
    pub(crate) fn insert_at(&mut self, slot: usize, node: usize) -> bool {
        match self.slots.get_mut(slot) {
            Some(s @ 0) => {
                *s = node.saturating_add(1);
                self.len = self.len.saturating_add(1);
                true
            }
            _ => false,
        }
    }

    /// Doubles the slot count and re-inserts every node from its stored hash.
    pub(crate) fn grow(&mut self, hashes: impl Iterator<Item = u64>) {
        let new_len = self.slots.len().saturating_mul(2);
        self.slots = vec![0; new_len];
        self.len = 0;
        let mask = self.mask();
        for (node, hash) in hashes.enumerate() {
            let mut i = self.start(hash);
            for _ in 0..new_len {
                if let Some(s @ 0) = self.slots.get_mut(i) {
                    *s = node.saturating_add(1);
                    self.len = self.len.saturating_add(1);
                    break;
                }
                i = i.wrapping_add(1) & mask;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inserts `keys` with the given hash function and checks every lookup.
    fn roundtrip(keys: &[u64], hash: impl Fn(u64) -> u64) {
        let mut table = IndexTable::new();
        let mut stored: Vec<(u64, u64)> = Vec::new();
        for &k in keys {
            let h = hash(k);
            let probe = table.probe(h, |i| stored.get(i).is_some_and(|&(sk, _)| sk == k));
            match probe {
                Probe::Found(_) => continue,
                Probe::Vacant(_) => {}
            }
            if table.needs_growth() {
                table.grow(stored.iter().map(|&(_, h)| h));
            }
            let Probe::Vacant(slot) =
                table.probe(h, |i| stored.get(i).is_some_and(|&(sk, _)| sk == k))
            else {
                panic!("key {k} appeared during growth");
            };
            assert!(table.insert_at(slot, stored.len()));
            stored.push((k, h));
        }
        for (idx, &(k, h)) in stored.iter().enumerate() {
            match table.probe(h, |i| stored.get(i).is_some_and(|&(sk, _)| sk == k)) {
                Probe::Found(i) => assert_eq!(i, idx),
                Probe::Vacant(_) => panic!("key {k} lost"),
            }
        }
        assert!(table.len.saturating_mul(2) <= table.slots.len());
    }

    #[test]
    fn stores_and_finds_with_good_hash() {
        let keys: Vec<u64> = (0..5000).map(|k| k % 3000).collect();
        roundtrip(&keys, |k| hash_state(&k));
    }

    #[test]
    fn full_collisions_keep_keys_distinct() {
        // Every key has the same hash: lookups must compare full keys.
        let keys: Vec<u64> = (0..300).collect();
        roundtrip(&keys, |_| 42);
    }

    #[test]
    fn hash_is_stable_within_a_build() {
        assert_eq!(hash_state(&(1u8, "x")), hash_state(&(1u8, "x")));
    }
}
