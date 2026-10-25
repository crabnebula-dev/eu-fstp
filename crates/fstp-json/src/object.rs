//! JSON objects: unique member names, insertion order, fast lookup.
//!
//! Members live in a vector in insertion order, so a parsed object writes back
//! in its original order. Small objects look keys up with a linear scan.
//! Objects with more than [`LINEAR_MAX`] members also keep a hash index keyed
//! by a randomly seeded SipHash of each name, so lookup and insertion take
//! expected constant time and adversarial names cannot force collisions.

use core::fmt;
use std::collections::HashMap;
use std::collections::hash_map::{Entry, RandomState};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};

use crate::value::{Value, drop_deep, exact_capacity};

/// Objects up to this size use a linear scan and no index.
pub(crate) const LINEAR_MAX: usize = 8;

/// A JSON object.
///
/// Member names are unique. [`Object::insert`] replaces the value of an
/// existing name in place and keeps its position. Equality ignores member
/// order. Use [`Value::identical`] to compare order too.
#[derive(Clone, Default)]
pub struct Object {
    members: Vec<(String, Value)>,
    index: Option<Box<KeyIndex>>,
}

/// A list of members that repeats a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateKey {
    index: usize,
}

impl DuplicateKey {
    /// Position of the first member whose name appeared earlier.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl fmt::Display for DuplicateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate member name at member {}", self.index)
    }
}

impl std::error::Error for DuplicateKey {}

impl Object {
    /// An empty object.
    pub fn new() -> Object {
        Object::default()
    }

    /// An empty object with room for `capacity` members.
    pub fn with_capacity(capacity: usize) -> Object {
        Object {
            members: Vec::with_capacity(capacity),
            index: None,
        }
    }

    /// Builds an object from members in order. Fails on a repeated name.
    pub fn from_members(members: Vec<(String, Value)>) -> Result<Object, DuplicateKey> {
        let mut object = Object::with_capacity(members.len());
        for (i, (key, value)) in members.into_iter().enumerate() {
            if object.contains_key(&key) {
                return Err(DuplicateKey { index: i });
            }
            object.push_new(key, value);
        }
        Ok(object)
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns true when there are no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The position of the member called `key`.
    pub fn position(&self, key: &str) -> Option<usize> {
        match &self.index {
            Some(index) => index.find(&self.members, key),
            None => self.members.iter().position(|(k, _)| k == key),
        }
    }

    /// Returns true when a member is called `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// The value of the member called `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let i = self.position(key)?;
        self.members.get(i).map(|(_, v)| v)
    }

    /// The value of the member called `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        let i = self.position(key)?;
        self.members.get_mut(i).map(|(_, v)| v)
    }

    /// The member at `position` in insertion order.
    pub fn member_at(&self, position: usize) -> Option<(&str, &Value)> {
        self.members.get(position).map(|(k, v)| (k.as_str(), v))
    }

    /// Sets a member. Returns the previous value when the name existed.
    ///
    /// An existing member keeps its position. A new member goes at the end.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        match self.position(&key) {
            Some(i) => self
                .members
                .get_mut(i)
                .map(|(_, v)| core::mem::replace(v, value)),
            None => {
                self.push_new(key, value);
                None
            }
        }
    }

    /// Removes a member and returns its value. Later members move up one place.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let i = self.position(key)?;
        if i >= self.members.len() {
            return None;
        }
        let (_, value) = self.members.remove(i);
        self.index = if self.members.len() > LINEAR_MAX {
            Some(Box::new(KeyIndex::build(&self.members)))
        } else {
            None
        };
        Some(value)
    }

    /// Iterates over members in insertion order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.members.iter(),
        }
    }

    /// Iterates over members in insertion order, with mutable values.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (&str, &mut Value)> {
        self.members.iter_mut().map(|(k, v)| (k.as_str(), v))
    }

    /// Iterates over member names in insertion order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> {
        self.members.iter().map(|(k, _)| k.as_str())
    }

    /// Iterates over member values in insertion order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &Value> {
        self.members.iter().map(|(_, v)| v)
    }

    /// Takes the members out in insertion order.
    pub fn into_members(mut self) -> Vec<(String, Value)> {
        self.index = None;
        core::mem::take(&mut self.members)
    }

    /// Appends a member whose name the caller has checked is new.
    pub(crate) fn push_new(&mut self, key: String, value: Value) {
        let position = self.members.len();
        match &mut self.index {
            Some(index) => index.add(&key, position),
            None if position >= LINEAR_MAX => {
                let mut index = KeyIndex::build(&self.members);
                index.add(&key, position);
                self.index = Some(Box::new(index));
            }
            None => {}
        }
        self.members.push((key, value));
    }

    /// Releases spare member capacity. The hash index keeps its size.
    pub(crate) fn shrink_to_fit(&mut self) {
        self.members = exact_capacity(core::mem::take(&mut self.members));
    }

    /// An object with the same names and index as `self` and the given
    /// members, which must be clones of `self`'s members in the same order.
    pub(crate) fn with_cloned_members(&self, members: Vec<(String, Value)>) -> Object {
        Object {
            members,
            index: self.index.clone(),
        }
    }

    /// Moves every value into `pending` and empties the object.
    pub(crate) fn drain_values_into(&mut self, pending: &mut Vec<Value>) {
        self.index = None;
        pending.extend(self.members.drain(..).map(|(_, v)| v));
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        if self.members.iter().any(|(_, v)| v.has_children()) {
            let mut pending = Vec::with_capacity(self.members.len());
            self.drain_values_into(&mut pending);
            drop_deep(pending);
        }
    }
}

impl PartialEq for Object {
    fn eq(&self, other: &Object) -> bool {
        // Compare through the iterative value equality.
        self.len() == other.len()
            && self
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|w| v == w))
    }
}

impl Eq for Object {}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl FromIterator<(String, Value)> for Object {
    /// Collects members with [`Object::insert`] semantics: a repeated name
    /// keeps its first position and takes the last value.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Object {
        let mut object = Object::new();
        object.extend(iter);
        object
    }
}

impl Extend<(String, Value)> for Object {
    fn extend<I: IntoIterator<Item = (String, Value)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl IntoIterator for Object {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_members().into_iter()
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Iterator over the members of an [`Object`] in insertion order.
#[derive(Clone)]
pub struct Iter<'a> {
    inner: core::slice::Iter<'a, (String, Value)>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k.as_str(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(k, v)| (k.as_str(), v))
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// Hash index from member name to position.
#[derive(Clone)]
struct KeyIndex {
    state: RandomState,
    slots: HashMap<u64, Slot, BuildHasherDefault<Prehashed>>,
}

/// Positions of the names that share one 64-bit hash.
#[derive(Clone)]
enum Slot {
    One(usize),
    Many(Vec<usize>),
}

impl KeyIndex {
    fn build(members: &[(String, Value)]) -> KeyIndex {
        let mut index = KeyIndex {
            state: RandomState::new(),
            slots: HashMap::with_capacity_and_hasher(members.len(), BuildHasherDefault::default()),
        };
        for (i, (k, _)) in members.iter().enumerate() {
            index.add(k, i);
        }
        index
    }

    fn add(&mut self, key: &str, position: usize) {
        let h = self.state.hash_one(key);
        match self.slots.entry(h) {
            Entry::Vacant(e) => {
                e.insert(Slot::One(position));
            }
            Entry::Occupied(mut e) => {
                let slot = e.get_mut();
                match slot {
                    Slot::One(first) => *slot = Slot::Many(vec![*first, position]),
                    Slot::Many(list) => list.push(position),
                }
            }
        }
    }

    fn find(&self, members: &[(String, Value)], key: &str) -> Option<usize> {
        let matches = |i: usize| members.get(i).is_some_and(|(k, _)| k == key);
        match self.slots.get(&self.state.hash_one(key))? {
            Slot::One(i) => matches(*i).then_some(*i),
            Slot::Many(list) => list.iter().copied().find(|&i| matches(i)),
        }
    }
}

/// Hasher for keys that are already SipHash outputs: passes them through.
#[derive(Default)]
struct Prehashed(u64);

impl Hasher for Prehashed {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Value {
        Value::String(x.to_owned())
    }

    #[test]
    fn insert_get_remove_across_the_index_threshold() {
        let mut o = Object::new();
        for i in 0..100 {
            assert_eq!(o.insert(format!("k{i}"), Value::from(i)), None);
        }
        assert_eq!(o.len(), 100);
        for i in 0..100 {
            assert_eq!(o.get(&format!("k{i}")), Some(&Value::from(i)));
            assert_eq!(o.position(&format!("k{i}")), Some(i));
        }
        assert_eq!(o.insert("k5", s("five")), Some(Value::from(5)));
        assert_eq!(o.position("k5"), Some(5));
        assert_eq!(o.remove("k0"), Some(Value::from(0)));
        assert_eq!(o.position("k1"), Some(0));
        assert_eq!(o.get("k0"), None);
        for i in 1..95 {
            assert!(o.remove(&format!("k{i}")).is_some());
        }
        assert_eq!(o.len(), 5);
        assert_eq!(
            o.keys().collect::<Vec<_>>(),
            ["k95", "k96", "k97", "k98", "k99"]
        );
        assert_eq!(o.get("k99"), Some(&Value::from(99)));
    }

    #[test]
    fn equality_ignores_order() {
        let a: Object = [("x".to_owned(), s("1")), ("y".to_owned(), s("2"))]
            .into_iter()
            .collect();
        let b: Object = [("y".to_owned(), s("2")), ("x".to_owned(), s("1"))]
            .into_iter()
            .collect();
        assert_eq!(a, b);
        assert!(!Value::Object(a.clone()).identical(&Value::Object(b)));
        assert!(Value::Object(a.clone()).identical(&Value::Object(a)));
    }

    #[test]
    fn from_members_rejects_duplicates() {
        let members = vec![
            ("a".to_owned(), Value::Null),
            ("b".to_owned(), Value::Null),
            ("a".to_owned(), Value::Null),
        ];
        assert_eq!(
            Object::from_members(members).map(|o| o.len()),
            Err(DuplicateKey { index: 2 })
        );
    }

    #[test]
    fn prehashed_hasher_passes_u64_through() {
        let mut h = Prehashed::default();
        h.write_u64(42);
        assert_eq!(h.finish(), 42);
        h.write(&[1, 2]);
        assert_ne!(h.finish(), 42);
    }
}
