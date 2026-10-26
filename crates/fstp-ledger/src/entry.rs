//! Sequence numbers, entries and the entry codec (I-23, ADR-007).

use std::fmt;
use std::fmt::Write as _;

use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{
    CanonicalError, FromJson, FromJsonError, FromJsonErrorKind, Object, ToJson, Value, to_canonical,
};

/// Position of an entry in a ledger, from 1. The head of an empty ledger is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub(crate) u64);

impl Seq {
    /// The head of an empty ledger.
    pub const ZERO: Seq = Seq(0);

    /// The sequence number `r`.
    pub const fn from_raw(r: u64) -> Seq {
        Seq(r)
    }

    /// The raw number.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Largest magnitude of `at`: 2^53 - 1 microseconds, about 285 years from
/// the epoch. RFC 8785 writes numbers through an IEEE 754 double, so only
/// integers within this bound have an exact canonical form.
pub const MAX_AT: i64 = 9_007_199_254_740_991;

/// The first schema version. Schema versions start at 1.
pub const SCHEMA_V1: u16 = 1;

/// One ledger entry.
///
/// Outside this crate an entry cannot be written as a struct literal. A
/// store numbers every entry it appends, and the decoder rebuilds entries
/// from their stored form. [`Entry::map_record`] and
/// [`Entry::try_map_record`] change the record type and keep the envelope.
/// [`Entry::canonical_text_of`] gives the stored bytes of an entry that
/// another store is about to append.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entry<R> {
    /// Position in the ledger.
    pub seq: Seq,
    /// UTC microseconds since the Unix epoch, from the command context.
    pub at: i64,
    /// Idempotency key of the command that produced the entry.
    pub command: [u8; 16],
    /// Schema version of the record encoding.
    pub schema: u16,
    /// The record.
    pub record: R,
}

/// The member names of the stored form.
const MEMBERS: [&str; 5] = ["seq", "at", "command", "schema", "record"];

impl<R> Entry<R> {
    /// Builds an entry. Only stores in this crate call it.
    pub(crate) fn new(seq: Seq, at: i64, command: [u8; 16], schema: u16, record: R) -> Entry<R> {
        Entry {
            seq,
            at,
            command,
            schema,
            record,
        }
    }

    /// The same entry with its record converted by `f`. The sequence
    /// number, time, command id and schema version are kept.
    pub fn map_record<S>(self, f: impl FnOnce(R) -> S) -> Entry<S> {
        Entry::new(self.seq, self.at, self.command, self.schema, f(self.record))
    }

    /// The same entry with its record converted by `f`, which also gets the
    /// schema version. This is the hook for upcasting in memory: decode an
    /// `Entry<Value>`, then decode the record by its version (ADR-007).
    ///
    /// ```
    /// use fstp_json::{FromJson, Value, parse};
    /// use fstp_ledger::Entry;
    ///
    /// let text = br#"{"at":0,"command":"00000000000000000000000000000000","record":"7","schema":2,"seq":"1"}"#;
    /// let raw = Entry::<Value>::from_json(&parse(text).ok().ok_or("parse")?).map_err(|_| "decode")?;
    /// let up = raw.try_map_record(|schema, v| match (schema, v.as_str()) {
    ///     (2, Some(s)) => s.parse::<u32>().map_err(|_| "bad v2 record"),
    ///     _ => Err("unknown schema"),
    /// })?;
    /// assert_eq!((up.seq.raw(), up.schema, up.record), (1, 2, 7));
    /// # Ok::<(), &str>(())
    /// ```
    pub fn try_map_record<S, E>(
        self,
        f: impl FnOnce(u16, R) -> Result<S, E>,
    ) -> Result<Entry<S>, E> {
        let record = f(self.schema, self.record)?;
        Ok(Entry::new(
            self.seq,
            self.at,
            self.command,
            self.schema,
            record,
        ))
    }
}

impl<R: ToJson> Entry<R> {
    /// The RFC 8785 text of the entry. These are the stored bytes.
    ///
    /// The fields of an entry are public, so a caller may have changed them.
    /// The envelope is checked first, as for [`Entry::canonical_text_of`],
    /// so every text this returns decodes again.
    ///
    /// # Errors
    ///
    /// - [`EntryTextError::SeqZero`] when `seq` is 0;
    /// - [`EntryTextError::TimeOutOfRange`] when `at` is beyond [`MAX_AT`]
    ///   in magnitude;
    /// - [`EntryTextError::SchemaZero`] when `schema` is 0;
    /// - [`EntryTextError::Record`] when the record holds a number without
    ///   an exact canonical form.
    pub fn canonical_text(&self) -> Result<String, EntryTextError> {
        Entry::canonical_text_of(self.seq, self.at, &self.command, self.schema, &self.record)
    }

    /// The RFC 8785 text of the entry with these parts, without building
    /// it. A store outside this crate calls it on append, so its stored
    /// bytes come from the same codec as [`Entry::canonical_text`]. It
    /// checks the envelope with the rules the decoder and [`MemStore`]
    /// apply, so every text it returns decodes again.
    ///
    /// [`MemStore`]: crate::MemStore
    ///
    /// # Errors
    ///
    /// - [`EntryTextError::SeqZero`] when `seq` is 0;
    /// - [`EntryTextError::TimeOutOfRange`] when `at` is beyond [`MAX_AT`]
    ///   in magnitude;
    /// - [`EntryTextError::SchemaZero`] when `schema` is 0;
    /// - [`EntryTextError::Record`] when the record holds a number without
    ///   an exact canonical form.
    pub fn canonical_text_of(
        seq: Seq,
        at: i64,
        command: &[u8; 16],
        schema: u16,
        record: &R,
    ) -> Result<String, EntryTextError> {
        check_envelope(seq, at, schema)?;
        to_canonical(&envelope(seq, at, command, schema, record.to_json()))
            .map_err(EntryTextError::Record)
    }
}

/// Why an entry has no stored form.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryTextError {
    /// The sequence number is 0. Entries are numbered from 1.
    SeqZero,
    /// The time is beyond [`MAX_AT`] in magnitude, so it has no exact
    /// RFC 8785 form.
    TimeOutOfRange,
    /// The schema version is 0. Schema versions start at [`SCHEMA_V1`].
    SchemaZero,
    /// The record holds a number without an exact canonical form.
    Record(CanonicalError),
}

impl fmt::Display for EntryTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryTextError::SeqZero => f.write_str("sequence number 0"),
            EntryTextError::TimeOutOfRange => f.write_str("time out of range"),
            EntryTextError::SchemaZero => f.write_str("schema version 0"),
            EntryTextError::Record(e) => write!(f, "record has no canonical form: {e}"),
        }
    }
}

impl std::error::Error for EntryTextError {}

/// Whether `at` is within [`MAX_AT`] in magnitude. The decoder, the
/// encoder and [`crate::MemStore`] share this rule.
pub(crate) fn time_in_range(at: i64) -> bool {
    (-MAX_AT..=MAX_AT).contains(&at)
}

/// The envelope rules of the stored form: `seq` from 1, `at` within
/// [`MAX_AT`] in magnitude and `schema` from 1. The decoder and the encoder
/// share this check.
fn check_envelope(seq: Seq, at: i64, schema: u16) -> Result<(), EntryTextError> {
    if seq == Seq::ZERO {
        return Err(EntryTextError::SeqZero);
    }
    if !time_in_range(at) {
        return Err(EntryTextError::TimeOutOfRange);
    }
    if schema < SCHEMA_V1 {
        return Err(EntryTextError::SchemaZero);
    }
    Ok(())
}

impl<R: ToJson> ToJson for Entry<R> {
    /// The JSON form of the entry. `seq` is a decimal string and `command`
    /// is 32 lowercase hex digits. It does not check the envelope. Stored
    /// bytes come from [`Entry::canonical_text`], which does.
    fn to_json(&self) -> Value {
        envelope(
            self.seq,
            self.at,
            &self.command,
            self.schema,
            self.record.to_json(),
        )
    }
}

/// The JSON form of an entry with these parts.
fn envelope(seq: Seq, at: i64, command: &[u8; 16], schema: u16, record: Value) -> Value {
    let mut o = Object::with_capacity(MEMBERS.len());
    o.insert("seq", Value::String(seq.0.to_string()));
    o.insert("at", Value::from(at));
    o.insert("command", Value::String(hex(command)));
    o.insert("schema", Value::from(schema));
    o.insert("record", record);
    Value::Object(o)
}

impl<R: FromJson> FromJson for Entry<R> {
    /// Decodes an entry. Unknown or missing members are refused, and so is
    /// every envelope spelling other than the one [`ToJson`] writes.
    fn from_json(value: &Value) -> Result<Entry<R>, FromJsonError> {
        let o = expect_object(value)?;
        reject_unknown(o, &MEMBERS)?;
        let seq = decode_seq(member(o, "seq")?).map_err(|e| e.at_field("seq"))?;
        let at = decode_int(member(o, "at")?, -MAX_AT, MAX_AT, "a ledger time")
            .map_err(|e| e.at_field("at"))?;
        let command = decode_command(member(o, "command")?).map_err(|e| e.at_field("command"))?;
        let schema = decode_int(
            member(o, "schema")?,
            i64::from(SCHEMA_V1),
            i64::from(u16::MAX),
            "u16",
        )
        .and_then(|n| u16::try_from(n).map_err(|_| out_of_range("u16")))
        .map_err(|e| e.at_field("schema"))?;
        // The member decoders above already enforce these bounds. The shared
        // check keeps the decoder and the encoder on one set of rules.
        check_envelope(seq, at, schema).map_err(|e| match e {
            EntryTextError::SeqZero => out_of_range("a sequence number").at_field("seq"),
            EntryTextError::TimeOutOfRange => out_of_range("a ledger time").at_field("at"),
            _ => out_of_range("u16").at_field("schema"),
        })?;
        let record = R::from_json(member(o, "record")?).map_err(|e| e.at_field("record"))?;
        Ok(Entry::new(seq, at, command, schema, record))
    }
}

/// A required member, or a missing-member error at its path.
fn member<'a>(o: &'a Object, key: &'static str) -> Result<&'a Value, FromJsonError> {
    o.get(key)
        .ok_or_else(|| FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key))
}

fn out_of_range(target: &'static str) -> FromJsonError {
    FromJsonError::new(FromJsonErrorKind::OutOfRange { target })
}

/// A decimal string from 1 to `u64::MAX`, without sign, leading zeros,
/// fraction or white space.
fn decode_seq(v: &Value) -> Result<Seq, FromJsonError> {
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a decimal string", v))?;
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b'1'..=b'9') => {}
        Some(b'0') if bytes.len() == 1 => return Err(out_of_range("a sequence number")),
        _ => return Err(FromJsonError::invalid("not a canonical decimal string")),
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        let d = char::from(b)
            .to_digit(10)
            .ok_or_else(|| FromJsonError::invalid("not a canonical decimal string"))?;
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_add(u64::from(d)))
            .ok_or_else(|| out_of_range("u64"))?;
    }
    Ok(Seq(acc))
}

/// A JSON integer within `min..=max`, spelled as Rust prints it. This
/// refuses fractions, exponents and `-0`.
fn decode_int(v: &Value, min: i64, max: i64, target: &'static str) -> Result<i64, FromJsonError> {
    let n = v
        .as_number()
        .ok_or_else(|| FromJsonError::wrong_type("an integer", v))?;
    if !n.is_integer() {
        return Err(FromJsonError::new(FromJsonErrorKind::NotAnInteger));
    }
    let i = n.as_i64().ok_or_else(|| out_of_range(target))?;
    if !(min..=max).contains(&i) {
        return Err(out_of_range(target));
    }
    if n.as_str() != i.to_string() {
        return Err(FromJsonError::invalid("not a canonical integer"));
    }
    Ok(i)
}

/// 32 lowercase hex digits.
fn decode_command(v: &Value) -> Result<[u8; 16], FromJsonError> {
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type("32 lowercase hex digits", v))?;
    let bytes = s.as_bytes();
    let lower_hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
    if bytes.len() != 32 || !bytes.iter().all(lower_hex) {
        return Err(FromJsonError::invalid("not 32 lowercase hex digits"));
    }
    let mut out = [0u8; 16];
    for (dst, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *dst = std::str::from_utf8(pair)
            .ok()
            .and_then(|p| u8::from_str_radix(p, 16).ok())
            .ok_or_else(|| FromJsonError::invalid("not 32 lowercase hex digits"))?;
    }
    Ok(out)
}

/// Lowercase hex of a command id.
fn hex(command: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in command {
        // Writing to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use fstp_json::parse;

    /// I-23: the hex codec of command ids round-trips every byte value.
    #[test]
    fn i23_command_hex_round_trips_every_byte() {
        for b in 0..=u8::MAX {
            let c = [b; 16];
            let v = Value::String(hex(&c));
            assert_eq!(decode_command(&v), Ok(c));
        }
    }

    /// I-23: `-0` is a second spelling of 0 and is refused.
    #[test]
    fn i23_negative_zero_time_is_refused() {
        let v = parse(br#"{"seq":"1","at":-0,"command":"00000000000000000000000000000000","schema":1,"record":null}"#)
            .unwrap();
        assert!(Entry::<Value>::from_json(&v).is_err());
    }

    /// I-23: schema 0 is not a published version and is refused.
    #[test]
    fn i23_schema_zero_is_refused() {
        let v = parse(br#"{"seq":"1","at":0,"command":"00000000000000000000000000000000","schema":0,"record":null}"#)
            .unwrap();
        assert!(Entry::<Value>::from_json(&v).is_err());
    }

    /// ADR-007: `map_record` and `try_map_record` keep the whole envelope,
    /// and `try_map_record` hands the schema version to the converter.
    #[test]
    fn adr007_map_record_keeps_the_envelope() {
        let e = Entry::new(Seq(42), -5, [0xab; 16], 3, 9u8);
        let m = e.clone().map_record(u32::from);
        assert_eq!(
            (m.seq, m.at, m.command, m.schema, m.record),
            (Seq(42), -5, [0xab; 16], 3, 9u32)
        );
        let t = e.clone().try_map_record(|s, r| Ok::<_, ()>((s, r)));
        assert_eq!(
            t.map(|t| (t.seq, t.at, t.command, t.schema, t.record)),
            Ok((Seq(42), -5, [0xab; 16], 3, (3, 9u8)))
        );
        assert_eq!(
            e.try_map_record(|_, _| Err::<u8, _>("refused")),
            Err("refused")
        );
    }

    /// ADR-007: `canonical_text_of` gives the same bytes as
    /// `canonical_text` on the entry with those parts.
    #[test]
    fn adr007_canonical_text_of_matches_canonical_text() {
        for (seq, at, command, schema) in [
            (1, 0, [0u8; 16], 1),
            (u64::MAX, MAX_AT, [0xff; 16], u16::MAX),
            (7, -MAX_AT, [0x0f; 16], 2),
        ] {
            let record = Value::String("r".to_owned());
            let e = Entry::new(Seq(seq), at, command, schema, record.clone());
            let of = Entry::canonical_text_of(Seq(seq), at, &command, schema, &record);
            assert_eq!(of, e.canonical_text());
            let text = of.unwrap();
            let back = Entry::<Value>::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
            assert_eq!(back, e);
        }
    }

    /// I-23: the bounds of `at` decode, and one past them is refused.
    #[test]
    fn i23_time_bounds() {
        for (at, ok) in [
            ("9007199254740991", true),
            ("-9007199254740991", true),
            ("9007199254740992", false),
            ("-9007199254740992", false),
        ] {
            let text = format!(
                r#"{{"seq":"1","at":{at},"command":"00000000000000000000000000000000","schema":1,"record":null}}"#
            );
            let v = parse(text.as_bytes()).unwrap();
            assert_eq!(Entry::<Value>::from_json(&v).is_ok(), ok, "{at}");
        }
    }

    /// I-23 and ADR-007: the encoder refuses every envelope the decoder
    /// refuses, so no stored text is left that can never be decoded. A time
    /// near `i64::MAX` is a range error, not a number error, and only the
    /// record can give a number error.
    #[test]
    fn i23_encoder_refuses_envelopes_the_decoder_refuses() {
        let c = [0u8; 16];
        let r = Value::Null;
        let of = |seq, at, schema| Entry::canonical_text_of(Seq(seq), at, &c, schema, &r);
        assert_eq!(of(0, 0, 1), Err(EntryTextError::SeqZero));
        assert_eq!(of(1, 0, 0), Err(EntryTextError::SchemaZero));
        for at in [MAX_AT + 1, -MAX_AT - 1, i64::MAX, i64::MIN] {
            assert_eq!(of(1, at, 1), Err(EntryTextError::TimeOutOfRange), "{at}");
        }
        let lossy = Entry::canonical_text_of(Seq(1), 0, &c, 1, &Value::from(i64::MAX));
        assert!(matches!(lossy, Err(EntryTextError::Record(_))), "{lossy:?}");

        // An entry whose public fields were changed is checked the same way.
        let mut e = Entry::new(Seq(1), 0, c, 1, Value::Null);
        e.seq = Seq::ZERO;
        assert_eq!(e.canonical_text(), Err(EntryTextError::SeqZero));
        e.seq = Seq(1);
        e.schema = 0;
        assert_eq!(e.canonical_text(), Err(EntryTextError::SchemaZero));
        e.schema = 1;
        e.at = MAX_AT + 1;
        assert_eq!(e.canonical_text(), Err(EntryTextError::TimeOutOfRange));
    }
}
