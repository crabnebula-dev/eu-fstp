//! The JSON value tree.
//!
//! No operation in this module recurses on the depth of a value. Drop, clone,
//! equality and formatting walk the tree with an explicit stack, so a value of
//! any depth never overflows the call stack.

use core::fmt;
use core::ops::{Deref, DerefMut};

use crate::number::Number;
use crate::object::Object;

/// A JSON value.
///
/// Equality is semantic for objects: member order does not matter, because
/// I-JSON member names are unique. Use [`Value::identical`] to compare member
/// order as well. Numbers compare by exact lexeme (see [`Number`]).
///
/// `Display` and `Debug` both write compact JSON text.
#[derive(Default)]
pub enum Value {
    /// `null`.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number with its exact lexeme.
    Number(Number),
    /// A string of Unicode scalar values.
    String(String),
    /// An ordered list of values.
    Array(Array),
    /// Members with unique names, in insertion order.
    Object(Object),
}

impl Value {
    /// The JSON type name: `null`, `boolean`, `number`, `string`, `array` or `object`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// Returns true for `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number, if this is one.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    /// The number as an `i64`, if this is an integer number in range.
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }

    /// The number as a `u64`, if this is an integer number in range.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(Number::as_u64)
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&Array> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The array, mutably, if this is one.
    pub fn as_array_mut(&mut self) -> Option<&mut Array> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The object, mutably, if this is one.
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Looks up a member by name. `None` when this is not an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }

    /// Looks up an array element. `None` when this is not an array.
    pub fn get_index(&self, index: usize) -> Option<&Value> {
        self.as_array().and_then(|a| a.get(index))
    }

    /// Compares two values exactly: same member order, same number lexemes.
    pub fn identical(&self, other: &Value) -> bool {
        eq_deep(self, other, true)
    }

    /// Writes compact JSON. See [`crate::to_compact`].
    pub fn to_compact(&self) -> String {
        crate::ser::to_compact(self)
    }

    /// Writes indented JSON. See [`crate::to_pretty`].
    pub fn to_pretty(&self) -> String {
        crate::ser::to_pretty(self)
    }

    /// Writes RFC 8785 canonical JSON. See [`crate::to_canonical`].
    pub fn to_canonical(&self) -> Result<String, crate::ser::CanonicalError> {
        crate::ser::to_canonical(self)
    }

    /// Returns true for a non-empty array or object.
    pub(crate) fn has_children(&self) -> bool {
        match self {
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            _ => false,
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        eq_deep(self, other, false)
    }
}

impl Eq for Value {}

impl Clone for Value {
    fn clone(&self) -> Value {
        match self {
            Value::Null => Value::Null,
            Value::Bool(b) => Value::Bool(*b),
            Value::Number(n) => Value::Number(n.clone()),
            Value::String(s) => Value::String(s.clone()),
            Value::Array(_) | Value::Object(_) => clone_deep(self),
        }
    }
}

/// Parses with [`crate::parse_str`] and the default limits.
impl core::str::FromStr for Value {
    type Err = crate::parse::ParseError;

    fn from_str(s: &str) -> Result<Value, Self::Err> {
        crate::parse::parse_str(s)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::ser::to_compact(self))
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::ser::to_compact(self))
    }
}

/// Compares two trees with an explicit stack.
fn eq_deep(a: &Value, b: &Value, ordered: bool) -> bool {
    let mut stack: Vec<(&Value, &Value)> = vec![(a, b)];
    while let Some(pair) = stack.pop() {
        match pair {
            (Value::Null, Value::Null) => {}
            (Value::Bool(x), Value::Bool(y)) if x == y => {}
            (Value::Number(x), Value::Number(y)) if x == y => {}
            (Value::String(x), Value::String(y)) if x == y => {}
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
                stack.extend(x.iter().zip(y.iter()));
            }
            (Value::Object(x), Value::Object(y)) if x.len() == y.len() => {
                if ordered {
                    for ((kx, vx), (ky, vy)) in x.iter().zip(y.iter()) {
                        if kx != ky {
                            return false;
                        }
                        stack.push((vx, vy));
                    }
                } else {
                    for (k, vx) in x.iter() {
                        match y.get(k) {
                            Some(vy) => stack.push((vx, vy)),
                            None => return false,
                        }
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

/// A container being cloned: the source and the children cloned so far.
enum CloneFrame<'a> {
    Array(&'a Array, Vec<Value>),
    Object(&'a Object, Vec<(String, Value)>),
}

impl<'a> CloneFrame<'a> {
    fn open(v: &'a Value) -> Option<CloneFrame<'a>> {
        match v {
            Value::Array(a) => Some(CloneFrame::Array(a, Vec::with_capacity(a.len()))),
            Value::Object(o) => Some(CloneFrame::Object(o, Vec::with_capacity(o.len()))),
            _ => None,
        }
    }

    /// The next source child, or `None` when every child is cloned.
    fn next_child(&self) -> Option<&'a Value> {
        match self {
            CloneFrame::Array(src, out) => src.get(out.len()),
            CloneFrame::Object(src, out) => src.member_at(out.len()).map(|(_, v)| v),
        }
    }

    /// Appends a cloned child, pairing it with its member name for objects.
    fn push(&mut self, child: Value) {
        match self {
            CloneFrame::Array(_, out) => out.push(child),
            CloneFrame::Object(src, out) => {
                let key = src
                    .member_at(out.len())
                    .map(|(k, _)| k.to_owned())
                    .unwrap_or_default();
                out.push((key, child));
            }
        }
    }

    fn finish(self) -> Value {
        match self {
            CloneFrame::Array(_, out) => Value::Array(Array::from(out)),
            CloneFrame::Object(src, out) => Value::Object(src.with_cloned_members(out)),
        }
    }
}

/// Clones a container with an explicit stack.
fn clone_deep(root: &Value) -> Value {
    let Some(first) = CloneFrame::open(root) else {
        return root.clone();
    };
    let mut stack = vec![first];
    loop {
        let next = match stack.last() {
            Some(top) => top.next_child(),
            None => return Value::Null,
        };
        match next {
            Some(child) => match CloneFrame::open(child) {
                Some(frame) => stack.push(frame),
                None => {
                    if let Some(top) = stack.last_mut() {
                        top.push(child.clone());
                    }
                }
            },
            None => {
                let Some(done) = stack.pop() else {
                    return Value::Null;
                };
                let value = done.finish();
                match stack.last_mut() {
                    Some(parent) => parent.push(value),
                    None => return value,
                }
            }
        }
    }
}

/// Moves the items into an allocation of exactly their length.
///
/// The parser uses this when a container closes, so the finished value
/// holds no growth capacity. A fresh allocation, unlike `shrink_to_fit`,
/// leaves no split-off fragment in the allocator.
pub(crate) fn exact_capacity<T>(items: Vec<T>) -> Vec<T> {
    if items.capacity() == items.len() {
        return items;
    }
    let mut exact = Vec::with_capacity(items.len());
    exact.extend(items);
    exact
}

/// Drops values with an explicit stack so deep trees never recurse.
pub(crate) fn drop_deep(mut pending: Vec<Value>) {
    while let Some(mut v) = pending.pop() {
        match &mut v {
            Value::Array(a) => pending.append(&mut a.items),
            Value::Object(o) => o.drain_values_into(&mut pending),
            _ => {}
        }
        // `v` drops here with no children left.
    }
}

/// A JSON array.
///
/// It dereferences to `Vec<Value>`, so the usual vector methods apply.
#[derive(Default, PartialEq, Eq)]
pub struct Array {
    items: Vec<Value>,
}

impl Array {
    /// An empty array.
    pub fn new() -> Array {
        Array { items: Vec::new() }
    }

    /// An empty array with room for `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Array {
        Array {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Takes the elements out as a vector.
    pub fn into_vec(mut self) -> Vec<Value> {
        core::mem::take(&mut self.items)
    }
}

impl Drop for Array {
    fn drop(&mut self) {
        if self.items.iter().any(Value::has_children) {
            drop_deep(core::mem::take(&mut self.items));
        }
    }
}

impl Clone for Array {
    fn clone(&self) -> Array {
        // Each element clones with its own explicit stack.
        Array {
            items: self.items.iter().map(Value::clone).collect(),
        }
    }
}

impl Deref for Array {
    type Target = Vec<Value>;

    fn deref(&self) -> &Vec<Value> {
        &self.items
    }
}

impl DerefMut for Array {
    fn deref_mut(&mut self) -> &mut Vec<Value> {
        &mut self.items
    }
}

impl From<Vec<Value>> for Array {
    fn from(items: Vec<Value>) -> Array {
        Array { items }
    }
}

impl FromIterator<Value> for Array {
    fn from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Array {
        Array {
            items: iter.into_iter().collect(),
        }
    }
}

impl IntoIterator for Array {
    type Item = Value;
    type IntoIter = std::vec::IntoIter<Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<'a> IntoIterator for &'a Array {
    type Item = &'a Value;
    type IntoIter = core::slice::Iter<'a, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl fmt::Debug for Array {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.items.iter()).finish()
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_owned())
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Value {
        Value::Number(n)
    }
}

impl From<Array> for Value {
    fn from(a: Array) -> Value {
        Value::Array(a)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Value {
        Value::Array(Array::from(items))
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Value {
        Value::Object(o)
    }
}

macro_rules! value_from_int {
    ($($t:ty),*) => {
        $(
            impl From<$t> for Value {
                fn from(n: $t) -> Value {
                    Value::Number(Number::from(n))
                }
            }
        )*
    };
}

value_from_int!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);
