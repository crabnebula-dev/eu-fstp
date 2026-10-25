//! Shared helpers for the fstp-ledger suites (I-23, ADR-007).
//!
//! The helpers are written from the spec text and the design, not from the
//! production code.
//!
//! - [`Rec`] is the test record. Its canonical bytes are its RFC 8785 text.
//! - [`Parts`] is a plain description of an entry. [`forge`] turns it into an
//!   [`Entry`] through the public decoder, which is the only way outside the
//!   crate to build an entry with a chosen sequence number.
//! - [`parts`] is the single place that reads entry fields. If the entry
//!   fields become private, only this function changes.
//! - [`extends`] is the reference for "the later read extends the earlier
//!   read without changing, dropping or reordering any entry".
//!
//! The entry JSON shape follows the W0 fuzz seed
//! `fuzz/seeds/entry_decode/entry`: `seq` is a decimal string, `at` and
//! `schema` are JSON integers, `command` is 32 lowercase hex digits and
//! `record` is the record value.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_json::{FromJson, FromJsonError, Number, Object, ToJson, Value, to_canonical};
use fstp_ledger::{Canonical, Entry};
use fstp_prop::Gen;

/// Largest magnitude of an integer that an IEEE 754 double holds exactly.
/// RFC 8785 writes every number through a double, so only `at` values within
/// this bound have a canonical form as a JSON number.
pub(crate) const MAX_SAFE: i64 = (1_i64 << 53) - 1;

/// A test record: any JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rec(pub(crate) Value);

impl ToJson for Rec {
    fn to_json(&self) -> Value {
        self.0.clone()
    }
}

impl FromJson for Rec {
    fn from_json(value: &Value) -> Result<Rec, FromJsonError> {
        Ok(Rec(value.clone()))
    }
}

impl Canonical for Rec {
    /// RFC 8785 text. The generators never build a number without a
    /// canonical form, so the fallback marks a generator bug only.
    fn canonical(&self) -> Vec<u8> {
        match to_canonical(&self.0) {
            Ok(text) => text.into_bytes(),
            Err(_) => {
                let mut out = b"\x00no canonical form:".to_vec();
                out.extend_from_slice(self.0.to_compact().as_bytes());
                out
            }
        }
    }
}

/// A plain description of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parts {
    pub(crate) seq: u64,
    pub(crate) at: i64,
    pub(crate) command: [u8; 16],
    pub(crate) schema: u16,
    pub(crate) record: Rec,
}

impl Parts {
    /// True when both describe the same stored entry: same envelope and the
    /// same canonical record bytes.
    pub(crate) fn same_stored(&self, other: &Parts) -> bool {
        self.seq == other.seq
            && self.at == other.at
            && self.command == other.command
            && self.schema == other.schema
            && self.record.canonical() == other.record.canonical()
    }
}

/// Lowercase hex of a command id.
pub(crate) fn hex(command: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in command {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A JSON integer.
pub(crate) fn int(n: impl ToString) -> Value {
    Value::Number(Number::from_lexeme(&n.to_string()).expect("an integer lexeme"))
}

/// The JSON form of an entry, in the shape of the W0 fuzz seed.
pub(crate) fn entry_json(p: &Parts) -> Value {
    let mut o = Object::new();
    o.insert("seq", Value::String(p.seq.to_string()));
    o.insert("at", int(p.at));
    o.insert("command", Value::String(hex(&p.command)));
    o.insert("schema", int(p.schema));
    o.insert("record", p.record.0.clone());
    Value::Object(o)
}

/// Builds an entry through the public decoder.
pub(crate) fn forge(p: &Parts) -> Result<Entry<Rec>, String> {
    Entry::<Rec>::from_json(&entry_json(p))
        .map_err(|e| format!("the entry decoder refused a well-formed entry {p:?}: {e}"))
}

/// Builds every entry of a ledger through the public decoder.
pub(crate) fn forge_all(ps: &[Parts]) -> Result<Vec<Entry<Rec>>, String> {
    ps.iter().map(forge).collect()
}

/// Reads the fields of an entry. This is the only field access in the suites.
pub(crate) fn parts(e: &Entry<Rec>) -> Parts {
    Parts {
        seq: e.seq.raw(),
        at: e.at,
        command: e.command,
        schema: e.schema,
        record: e.record.clone(),
    }
}

/// Reference for I-23: `new` extends `old` when it is at least as long,
/// numbers its entries 1, 2, 3 and so on, and holds every entry of `old`
/// unchanged at the same position.
pub(crate) fn extends(old: &[Parts], new: &[Parts]) -> bool {
    new.len() >= old.len()
        && new.iter().enumerate().all(|(i, p)| p.seq == i as u64 + 1)
        && old.iter().zip(new).all(|(a, b)| a.same_stored(b))
}

/// A short generated JSON value with a canonical form.
pub(crate) fn gen_value(g: &mut Gen, depth: u8) -> Value {
    let kinds: &[u32] = if depth == 0 {
        &[1, 1, 3, 3, 0, 0]
    } else {
        &[1, 1, 3, 3, 1, 2]
    };
    match g.weighted(kinds) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => int(g.i64_in(-1_000_000..=1_000_000)),
        3 => Value::String(g.string(0..=6)),
        4 => Value::Array(g.vec(0..=3, |g| gen_value(g, depth - 1)).into()),
        _ => {
            let mut o = Object::new();
            for _ in 0..g.usize_in(0..=3) {
                let key = g.string(0..=3);
                let v = gen_value(g, depth - 1);
                o.insert(key, v);
            }
            Value::Object(o)
        }
    }
}

/// A generated record. Shrinks towards `null`.
pub(crate) fn gen_record(g: &mut Gen) -> Rec {
    Rec(gen_value(g, 2))
}

/// A generated record whose canonical bytes differ from `old`'s.
pub(crate) fn gen_other_record(g: &mut Gen, old: &Rec) -> Rec {
    let candidate = gen_record(g);
    if candidate.canonical() != old.canonical() {
        return candidate;
    }
    // Wrap the old value, which always changes the canonical bytes.
    Rec(Value::Array(vec![old.0.clone()].into()))
}

/// Generates an honest ledger of `min_batches` to `max_batches` batches.
/// A batch holds one to three records under its own command id and time.
/// Times never decrease, and entries are numbered from 1.
pub(crate) fn gen_ledger(g: &mut Gen, min_batches: usize, max_batches: usize) -> Vec<Parts> {
    let batches = g.usize_in(min_batches..=max_batches);
    let mut at = g.i64_in(0..=1_800_000_000_000_000);
    let mut out: Vec<Parts> = Vec::new();
    for b in 0..batches {
        at += g.i64_in(0..=1_000_000);
        let mut command = [0u8; 16];
        for byte in command.iter_mut() {
            *byte = g.u8();
        }
        // The batch index in the first byte keeps command ids unique.
        command[0] = u8::try_from(b).expect("fewer than 256 batches");
        let schema = g.u16_in(1..=3);
        for _ in 0..g.usize_in(1..=3) {
            let seq = out.len() as u64 + 1;
            out.push(Parts {
                seq,
                at,
                command,
                schema,
                record: gen_record(g),
            });
        }
    }
    out
}
