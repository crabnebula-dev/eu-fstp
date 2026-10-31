//! Value kinds of programme fields and their strict JSON codecs.
//!
//! Every field value decodes through [`Codec::decode`]. Each decoder is
//! strict in the same ways:
//!
//! - objects reject unknown members and need every member;
//! - amounts and percentages decode only from ADR-006 strings, so a JSON
//!   number is refused;
//! - integers need an integer lexeme and a value in range;
//! - lists hold at most [`MAX_LIST`] elements, and a list read as a set
//!   must be strictly ascending, so a set has exactly one spelling.
//!
//! [`Codec::encode`] writes a value that `decode` reads back to the same
//! value. Every encoding is the JSON the policy keeps for an opaque
//! parameter, so the spec and the policy agree byte for byte.

use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::id::{ContentDigest, TextId, TextRef};
use fstp_domain::policy::{EffectiveScoreRule, McpBindingActions, ReadAccess, ReviewerAnonymity};
use fstp_domain::roles::CoolingOff;
use fstp_domain::time::Days;
use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{FromJson, FromJsonError, FromJsonErrorKind, Number, Object, Value};
use fstp_money::{
    Amount, AmountRange, Currency, NonNegAmount, Percent, nonneg_amount_from_json,
    percent_from_json,
};

/// The most elements one list in a field value may hold.
pub const MAX_LIST: usize = 1024;

/// The longest inline narrative text, in UTF-8 bytes.
pub const NARRATIVE_MAX_BYTES: usize = 65_536;

/// A strict JSON codec for one kind of field value.
pub(crate) trait Codec: Sized {
    /// Decodes `v`, reading amounts in currency `c`.
    fn decode(v: &Value, c: Currency) -> Result<Self, FromJsonError>;
    /// The JSON value that [`Codec::decode`] reads back to `self`.
    fn encode(&self) -> Value;
    /// The value a gap compiles to. It is never a choice anyone made: a gap
    /// is always a validation failure (`FieldUnset`).
    fn placeholder(c: Currency) -> Option<Self>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The object `v` with exactly the members `members`.
pub(crate) fn object<'a>(v: &'a Value, members: &[&str]) -> Result<&'a Object, FromJsonError> {
    let o = expect_object(v)?;
    reject_unknown(o, members)?;
    Ok(o)
}

/// Decodes the required member `key` of `o`.
pub(crate) fn member<T: Codec>(
    o: &Object,
    key: &'static str,
    c: Currency,
) -> Result<T, FromJsonError> {
    match o.get(key) {
        Some(v) => T::decode(v, c).map_err(|e| e.at_field(key)),
        None => Err(FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key)),
    }
}

/// An object value from its members. Names are distinct by construction.
pub(crate) fn obj(members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// The elements of the array `v`, each decoded, at most [`MAX_LIST`].
pub(crate) fn list<T: Codec>(v: &Value, c: Currency) -> Result<Vec<T>, FromJsonError> {
    let a = v
        .as_array()
        .ok_or_else(|| FromJsonError::wrong_type("an array", v))?;
    if a.len() > MAX_LIST {
        return Err(FromJsonError::invalid("the list is too long"));
    }
    a.iter()
        .enumerate()
        .map(|(i, x)| T::decode(x, c).map_err(|e| e.at_index(i)))
        .collect()
}

/// An array value of the encodings of `items`.
pub(crate) fn array<T: Codec>(items: &[T]) -> Value {
    Value::from(items.iter().map(Codec::encode).collect::<Vec<Value>>())
}

/// Whether no two keys are equal.
pub(crate) fn distinct<K: Ord>(keys: impl Iterator<Item = K>) -> bool {
    let mut seen = BTreeSet::new();
    keys.into_iter().all(|k| seen.insert(k))
}

/// Whether the keys are strictly ascending.
pub(crate) fn ascending<K: Ord>(keys: impl Iterator<Item = K>) -> bool {
    let mut last: Option<K> = None;
    for k in keys {
        if let Some(prev) = &last
            && *prev >= k
        {
            return false;
        }
        last = Some(k);
    }
    true
}

/// An integer of type `T` from `v`, refusing fractions and exponents.
fn integer<T: FromJson>(v: &Value) -> Result<T, FromJsonError> {
    T::from_json(v)
}

/// The string inside `v`.
pub(crate) fn string(v: &Value) -> Result<&str, FromJsonError> {
    v.as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a string", v))
}

/// A `u128` id written as a decimal string without leading zeros.
pub(crate) fn decode_id(v: &Value) -> Result<u128, FromJsonError> {
    let s = string(v)?;
    let ok = !s.is_empty()
        && s.len() <= 39
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !ok {
        return Err(FromJsonError::invalid("an id is a decimal string"));
    }
    s.parse::<u128>()
        .map_err(|_| FromJsonError::invalid("the id is out of range"))
}

/// The decimal string of a `u128` id.
pub(crate) fn encode_id(raw: u128) -> Value {
    Value::String(raw.to_string())
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

impl Codec for bool {
    fn decode(v: &Value, _: Currency) -> Result<bool, FromJsonError> {
        v.as_bool()
            .ok_or_else(|| FromJsonError::wrong_type("a boolean", v))
    }
    fn encode(&self) -> Value {
        Value::Bool(*self)
    }
    fn placeholder(_: Currency) -> Option<bool> {
        Some(false)
    }
}

impl Codec for NonZeroU8 {
    fn decode(v: &Value, _: Currency) -> Result<NonZeroU8, FromJsonError> {
        NonZeroU8::new(integer::<u8>(v)?).ok_or_else(|| FromJsonError::invalid("zero is refused"))
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.get()))
    }
    fn placeholder(_: Currency) -> Option<NonZeroU8> {
        Some(NonZeroU8::MIN)
    }
}

impl Codec for NonZeroU16 {
    fn decode(v: &Value, _: Currency) -> Result<NonZeroU16, FromJsonError> {
        NonZeroU16::new(integer::<u16>(v)?).ok_or_else(|| FromJsonError::invalid("zero is refused"))
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.get()))
    }
    fn placeholder(_: Currency) -> Option<NonZeroU16> {
        Some(NonZeroU16::MIN)
    }
}

/// The P-03 minimum of assigned reviewers: 1 to
/// [`fstp_domain::policy::P03_MAX`], the bound that keeps the exact score
/// arithmetic safe (M2 design section 2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReviewerMinimum(NonZeroU8);

impl ReviewerMinimum {
    /// The minimum `n`, or `None` outside 1 to `P03_MAX`.
    pub fn new(n: u8) -> Option<ReviewerMinimum> {
        NonZeroU8::new(n)
            .filter(|n| n.get() <= fstp_domain::policy::P03_MAX)
            .map(ReviewerMinimum)
    }

    /// The minimum.
    pub fn get(self) -> NonZeroU8 {
        self.0
    }
}

impl Codec for ReviewerMinimum {
    fn decode(v: &Value, _: Currency) -> Result<ReviewerMinimum, FromJsonError> {
        ReviewerMinimum::new(integer::<u8>(v)?)
            .ok_or_else(|| FromJsonError::invalid("P-03 is 1 to 64"))
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.0.get()))
    }
    fn placeholder(_: Currency) -> Option<ReviewerMinimum> {
        Some(ReviewerMinimum(NonZeroU8::MIN))
    }
}

impl Codec for CoolingOff {
    fn decode(v: &Value, _: Currency) -> Result<CoolingOff, FromJsonError> {
        integer::<u8>(v).map(CoolingOff)
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.0))
    }
    fn placeholder(_: Currency) -> Option<CoolingOff> {
        Some(CoolingOff(0))
    }
}

impl Codec for Days {
    /// `{"days": n}`.
    fn decode(v: &Value, c: Currency) -> Result<Days, FromJsonError> {
        let o = object(v, &["days"])?;
        member::<U16>(o, "days", c).map(|n| Days::new(n.0))
    }
    fn encode(&self) -> Value {
        obj(vec![("days", Value::Number(Number::from(self.get())))])
    }
    fn placeholder(_: Currency) -> Option<Days> {
        Some(Days::new(0))
    }
}

/// A plain `u16`, as a member of a larger value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct U16(pub(crate) u16);

impl Codec for U16 {
    fn decode(v: &Value, _: Currency) -> Result<U16, FromJsonError> {
        integer::<u16>(v).map(U16)
    }
    fn encode(&self) -> Value {
        Value::Number(Number::from(self.0))
    }
    fn placeholder(_: Currency) -> Option<U16> {
        Some(U16(0))
    }
}

/// A whole number of working days, written `{"working_days": n}`. The
/// working-day calendar is P-40.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkingDays(pub u16);

impl Codec for WorkingDays {
    fn decode(v: &Value, c: Currency) -> Result<WorkingDays, FromJsonError> {
        let o = object(v, &["working_days"])?;
        member::<U16>(o, "working_days", c).map(|n| WorkingDays(n.0))
    }
    fn encode(&self) -> Value {
        obj(vec![("working_days", Value::Number(Number::from(self.0)))])
    }
    fn placeholder(_: Currency) -> Option<WorkingDays> {
        Some(WorkingDays(0))
    }
}

impl Codec for Percent {
    /// An ADR-006 percentage string such as `"75.00"`. Numbers are refused.
    fn decode(v: &Value, _: Currency) -> Result<Percent, FromJsonError> {
        percent_from_json(v)
    }
    fn encode(&self) -> Value {
        Value::String(self.to_string())
    }
    /// 100.00, which no score passes.
    fn placeholder(_: Currency) -> Option<Percent> {
        Percent::from_bp(Percent::MAX_BP)
    }
}

impl Codec for NonNegAmount {
    /// An ADR-006 amount string in currency `c`. Numbers are refused.
    fn decode(v: &Value, c: Currency) -> Result<NonNegAmount, FromJsonError> {
        nonneg_amount_from_json(v, c)
    }
    fn encode(&self) -> Value {
        Value::String(self.amount().to_string())
    }
    fn placeholder(c: Currency) -> Option<NonNegAmount> {
        NonNegAmount::new(Amount::zero(c)).ok()
    }
}

impl Codec for AmountRange {
    /// `{"max": amount, "min": amount}` with the minimum at most the maximum.
    fn decode(v: &Value, c: Currency) -> Result<AmountRange, FromJsonError> {
        let o = object(v, &["max", "min"])?;
        let min = member::<NonNegAmount>(o, "min", c)?;
        let max = member::<NonNegAmount>(o, "max", c)?;
        AmountRange::new(min, max)
            .map_err(|_| FromJsonError::invalid("the minimum is above the maximum"))
    }
    fn encode(&self) -> Value {
        obj(vec![
            ("max", self.max().encode()),
            ("min", self.min().encode()),
        ])
    }
    fn placeholder(c: Currency) -> Option<AmountRange> {
        let zero = NonNegAmount::placeholder(c)?;
        AmountRange::new(zero, zero).ok()
    }
}

// ---------------------------------------------------------------------------
// Text kinds
// ---------------------------------------------------------------------------

/// Whether `s` is 1 to `max` bytes, every byte passing `ok`, the first
/// byte passing `first`.
fn shaped(s: &str, max: usize, first: impl Fn(u8) -> bool, ok: impl Fn(u8) -> bool) -> bool {
    match s.as_bytes().split_first() {
        Some((b, rest)) => s.len() <= max && first(*b) && rest.iter().all(|b| ok(*b)),
        None => false,
    }
}

/// A closed-vocabulary word: 1 to 64 bytes of lowercase ASCII letters,
/// digits, `_` and `-`, starting with a letter. Tokens hold the options of
/// parameters whose option lists the spec leaves open. They carry no free
/// text, so they may sit in ledger bodies (ADR-007).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(String);

impl Token {
    /// The longest token, in bytes.
    pub const MAX_BYTES: usize = 64;

    /// The token `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<Token> {
        shaped(
            s,
            Token::MAX_BYTES,
            |b| b.is_ascii_lowercase(),
            |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-',
        )
        .then(|| Token(s.to_owned()))
    }

    /// A token from a literal the crate itself spells. Only crate code calls
    /// it, and a unit test checks each such literal with [`Token::new`].
    pub(crate) fn trusted(s: &'static str) -> Token {
        Token(s.to_owned())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for Token {
    fn decode(v: &Value, _: Currency) -> Result<Token, FromJsonError> {
        Token::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not a token"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    fn placeholder(_: Currency) -> Option<Token> {
        Some(Token::trusted("unset"))
    }
}

/// A public URL segment: 1 to 63 bytes of lowercase ASCII letters, digits
/// and `-`, neither starting nor ending with `-`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slug(String);

impl Slug {
    /// The slug `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<Slug> {
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let ok = shaped(s, 63, edge, |b| edge(b) || b == b'-') && !s.ends_with('-');
        ok.then(|| Slug(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for Slug {
    fn decode(v: &Value, _: Currency) -> Result<Slug, FromJsonError> {
        Slug::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not a slug"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    fn placeholder(_: Currency) -> Option<Slug> {
        Some(Slug("unset".to_owned()))
    }
}

/// A programme language as an ISO 639 code: two or three lowercase ASCII
/// letters, such as `"en"` (P-25).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LanguageCode(String);

impl LanguageCode {
    /// The code `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<LanguageCode> {
        let ok = (2..=3).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase());
        ok.then(|| LanguageCode(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for LanguageCode {
    fn decode(v: &Value, _: Currency) -> Result<LanguageCode, FromJsonError> {
        LanguageCode::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not a language code"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    /// ISO 639-2 `und`, "undetermined".
    fn placeholder(_: Currency) -> Option<LanguageCode> {
        Some(LanguageCode("und".to_owned()))
    }
}

/// A model name as the inference provider spells it: 1 to 128 bytes of
/// ASCII letters, digits and `. _ : / @ + -` (P-21).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelName(String);

impl ModelName {
    /// The name `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<ModelName> {
        let ok = |b: u8| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b);
        shaped(s, 128, ok, ok).then(|| ModelName(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for ModelName {
    fn decode(v: &Value, _: Currency) -> Result<ModelName, FromJsonError> {
        ModelName::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not a model name"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    fn placeholder(_: Currency) -> Option<ModelName> {
        Some(ModelName("unset".to_owned()))
    }
}

/// An SPDX licence identifier: 1 to 64 bytes of ASCII letters, digits and
/// `. + -` (P-26).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Licence(String);

impl Licence {
    /// The identifier `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<Licence> {
        let ok = |b: u8| b.is_ascii_alphanumeric() || b".+-".contains(&b);
        shaped(s, 64, ok, ok).then(|| Licence(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for Licence {
    fn decode(v: &Value, _: Currency) -> Result<Licence, FromJsonError> {
        Licence::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not an SPDX identifier"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    fn placeholder(_: Currency) -> Option<Licence> {
        Some(Licence("NOASSERTION".to_owned()))
    }
}

/// The `TextRef` that `compile` writes into P-09 for wording that is
/// still inline. Text id 0 with an all-zero digest names no stored text.
/// [`Narrative`] refuses to decode it as a stored reference, and
/// [`crate::Compiled::ledger_ready`] is false while P-09 holds it.
pub const INLINE_TEXT: TextRef =
    TextRef::new(TextId::from_raw(0), ContentDigest::from_bytes([0; 32]));

/// A reference to narrative text held outside the ledger. It is never
/// [`INLINE_TEXT`], so a stored narrative cannot pass for inline wording,
/// and every value round-trips through the JSON form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredText(TextRef);

impl StoredText {
    /// The stored text `r`, or `None` for the reserved [`INLINE_TEXT`].
    pub fn new(r: TextRef) -> Option<StoredText> {
        (r != INLINE_TEXT).then_some(StoredText(r))
    }

    /// The reference.
    pub fn text_ref(self) -> TextRef {
        self.0
    }
}

/// Narrative text: inline in templates, the fixture and exports; a
/// [`TextRef`] in ledger bodies (ADR-007).
///
/// Inline text is a JSON string of at most [`NARRATIVE_MAX_BYTES`].
/// A stored text is `{"digest": "<64 lowercase hex>", "text": "<id>"}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Narrative {
    /// The text itself.
    Inline(String),
    /// A reference to text held outside the ledger.
    Stored(StoredText),
}

/// The 32 bytes of a 64-character lowercase hex string.
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let nibble = |b: u8| match b {
            b'0'..=b'9' | b'a'..=b'f' => char::from(b).to_digit(16),
            _ => None,
        };
        let (hi, lo) = match pair {
            [h, l] => (nibble(*h)?, nibble(*l)?),
            _ => return None,
        };
        let byte = hi.checked_mul(16)?.checked_add(lo)?;
        *slot = u8::try_from(byte).ok()?;
    }
    Some(out)
}

impl Codec for Narrative {
    fn decode(v: &Value, c: Currency) -> Result<Narrative, FromJsonError> {
        if let Some(s) = v.as_str() {
            if s.len() > NARRATIVE_MAX_BYTES {
                return Err(FromJsonError::invalid("the text is too long"));
            }
            return Ok(Narrative::Inline(s.to_owned()));
        }
        let o = object(v, &["digest", "text"])
            .map_err(|_| FromJsonError::wrong_type("a string or a stored text", v))?;
        let id = member::<RawId>(o, "text", c)?.0;
        let digest = match o.get("digest").and_then(Value::as_str).and_then(hex32) {
            Some(d) => ContentDigest::from_bytes(d),
            None => {
                return Err(FromJsonError::invalid("a digest is 64 hex digits").at_field("digest"));
            }
        };
        StoredText::new(TextRef::new(TextId::from_raw(id), digest))
            .map(Narrative::Stored)
            .ok_or_else(|| FromJsonError::invalid("text id 0 with a zero digest is reserved"))
    }
    fn encode(&self) -> Value {
        match self {
            Narrative::Inline(s) => Value::String(s.clone()),
            Narrative::Stored(StoredText(r)) => {
                let hex: String = r
                    .digest()
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                obj(vec![
                    ("digest", Value::String(hex)),
                    ("text", encode_id(r.id().raw())),
                ])
            }
        }
    }
    fn placeholder(_: Currency) -> Option<Narrative> {
        Some(Narrative::Inline(String::new()))
    }
}

impl Narrative {
    /// The `TextRef` the policy holds for this text: the stored reference,
    /// or [`INLINE_TEXT`] while the text is inline.
    pub fn policy_ref(&self) -> TextRef {
        match self {
            Narrative::Inline(_) => INLINE_TEXT,
            Narrative::Stored(r) => r.text_ref(),
        }
    }
}

/// An action number as the funder spells it, such as a grant agreement
/// number: 1 to 64 bytes of ASCII letters, digits and `- . _ /`. It holds
/// no free text. Interim, pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionNumber(String);

impl ActionNumber {
    /// The longest action number, in bytes.
    pub const MAX_BYTES: usize = 64;

    /// The action number `s`, or `None` when it is not one.
    pub fn new(s: &str) -> Option<ActionNumber> {
        let ok = |b: u8| b.is_ascii_alphanumeric() || b"-._/".contains(&b);
        shaped(s, ActionNumber::MAX_BYTES, ok, ok).then(|| ActionNumber(s.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Codec for ActionNumber {
    fn decode(v: &Value, _: Currency) -> Result<ActionNumber, FromJsonError> {
        ActionNumber::new(string(v)?).ok_or_else(|| FromJsonError::invalid("not an action number"))
    }
    fn encode(&self) -> Value {
        Value::String(self.0.clone())
    }
    fn placeholder(_: Currency) -> Option<ActionNumber> {
        Some(ActionNumber("unset".to_owned()))
    }
}

/// A raw `u128` id as a decimal string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RawId(pub(crate) u128);

impl Codec for RawId {
    fn decode(v: &Value, _: Currency) -> Result<RawId, FromJsonError> {
        decode_id(v).map(RawId)
    }
    fn encode(&self) -> Value {
        encode_id(self.0)
    }
    fn placeholder(_: Currency) -> Option<RawId> {
        Some(RawId(0))
    }
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/// A calendar date written `"YYYY-MM-DD"`, years 1970 to 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// The date, or `None` when it does not exist or lies outside 1970 to 9999.
    pub fn new(year: u16, month: u8, day: u8) -> Option<Date> {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        ((1970..=9999).contains(&year) && (1..=days).contains(&day)).then_some(Date {
            year,
            month,
            day,
        })
    }

    /// The year.
    pub fn year(self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    pub fn month(self) -> u8 {
        self.month
    }

    /// The day of the month.
    pub fn day(self) -> u8 {
        self.day
    }

    fn parse(s: &str) -> Option<Date> {
        let b = s.as_bytes();
        let digits = |r: core::ops::Range<usize>| {
            let part = s.get(r)?;
            part.bytes().all(|c| c.is_ascii_digit()).then_some(part)
        };
        if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
            return None;
        }
        let year = digits(0..4)?.parse().ok()?;
        let month = digits(5..7)?.parse().ok()?;
        let day = digits(8..10)?.parse().ok()?;
        Date::new(year, month, day)
    }
}

impl Codec for Date {
    fn decode(v: &Value, _: Currency) -> Result<Date, FromJsonError> {
        Date::parse(string(v)?).ok_or_else(|| FromJsonError::invalid("not a date YYYY-MM-DD"))
    }
    fn encode(&self) -> Value {
        Value::String(format!(
            "{:04}-{:02}-{:02}",
            self.year, self.month, self.day
        ))
    }
    fn placeholder(_: Currency) -> Option<Date> {
        Date::new(1970, 1, 1)
    }
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/// A list with no rule beyond its length, as a member of a larger value.
pub(crate) struct AnyList<T>(pub(crate) Vec<T>);

impl<T: Codec> Codec for AnyList<T> {
    fn decode(v: &Value, c: Currency) -> Result<AnyList<T>, FromJsonError> {
        list(v, c).map(AnyList)
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<AnyList<T>> {
        Some(AnyList(Vec::new()))
    }
}

/// A list with no repeated element, in the order given. Order carries
/// meaning, as in a signature cascade (P-30).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UniqueList<T>(Vec<T>);

impl<T: Ord> UniqueList<T> {
    /// The list, or `None` when an element repeats or it is too long.
    pub fn new(items: Vec<T>) -> Option<UniqueList<T>> {
        (items.len() <= MAX_LIST && distinct(items.iter())).then_some(UniqueList(items))
    }

    /// The elements in order.
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T: Codec + Ord> Codec for UniqueList<T> {
    fn decode(v: &Value, c: Currency) -> Result<UniqueList<T>, FromJsonError> {
        UniqueList::new(list(v, c)?).ok_or_else(|| FromJsonError::invalid("an element repeats"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<UniqueList<T>> {
        Some(UniqueList(Vec::new()))
    }
}

/// A set, written as a strictly ascending list so that it has one spelling.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedSet<T>(Vec<T>);

impl<T: Ord> SortedSet<T> {
    /// The set of `items`, or `None` unless they are strictly ascending.
    pub fn new(items: Vec<T>) -> Option<SortedSet<T>> {
        (items.len() <= MAX_LIST && ascending(items.iter())).then_some(SortedSet(items))
    }

    /// The elements in ascending order.
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T: Codec + Ord> Codec for SortedSet<T> {
    fn decode(v: &Value, c: Currency) -> Result<SortedSet<T>, FromJsonError> {
        SortedSet::new(list(v, c)?)
            .ok_or_else(|| FromJsonError::invalid("a set is written strictly ascending"))
    }
    fn encode(&self) -> Value {
        array(&self.0)
    }
    fn placeholder(_: Currency) -> Option<SortedSet<T>> {
        Some(SortedSet(Vec::new()))
    }
}

// ---------------------------------------------------------------------------
// Closed option lists
// ---------------------------------------------------------------------------

/// A codec over a closed list of options, each spelled as one JSON string.
macro_rules! options {
    ($t:ty, $placeholder:path, { $($v:path => $s:literal),+ $(,)? }) => {
        impl Codec for $t {
            fn decode(v: &Value, _: Currency) -> Result<$t, FromJsonError> {
                match $crate::value::string(v)? {
                    $($s => Ok($v),)+
                    _ => Err(FromJsonError::invalid("not one of the options")),
                }
            }
            fn encode(&self) -> Value {
                Value::String(match self { $($v => $s,)+ }.to_owned())
            }
            fn placeholder(_: Currency) -> Option<$t> {
                Some($placeholder)
            }
        }
    };
}

/// A closed list of options as a local enum with its codec.
macro_rules! option_enum {
    (
        $(#[$m:meta])*
        pub enum $name:ident { $($(#[$vm:meta])* $v:ident => $s:literal),+ $(,)? }
        placeholder $ph:ident
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($(#[$vm])* $v),+ }

        impl $name {
            /// Every option, in order.
            pub const ALL: &'static [$name] = &[$($name::$v),+];

            /// The JSON spelling of the option.
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$v => $s),+ }
            }
        }

        $crate::value::options!($name, $name::$ph, { $($name::$v => $s),+ });
    };
}

pub(crate) use {option_enum, options};

options!(ReadAccess, ReadAccess::AssignedReviewersOnly, {
    ReadAccess::AssignedReviewersOnly => "assigned_reviewers_only",
    ReadAccess::AllCommitteeMembers => "all_committee_members",
    ReadAccess::OperatorStaffOnly => "operator_staff_only",
});

options!(ReviewerAnonymity, ReviewerAnonymity::Anonymous, {
    ReviewerAnonymity::Anonymous => "anonymous",
    ReviewerAnonymity::Named => "named",
});

options!(EffectiveScoreRule, EffectiveScoreRule::HigherOfOriginalAndRevised, {
    EffectiveScoreRule::HigherOfOriginalAndRevised => "higher_of_original_and_revised",
});

options!(McpBindingActions, McpBindingActions::DraftOnly, {
    McpBindingActions::DraftOnly => "draft_only",
    McpBindingActions::Allowed => "allowed",
});

#[cfg(test)]
mod tests {
    use super::*;

    /// R-PG-01: every literal passed to `Token::trusted` is a token.
    #[test]
    fn r_pg_01_trusted_token_literals_are_tokens() {
        for s in ["unset", "horizon-europe"] {
            assert_eq!(Token::new(s), Some(Token::trusted(s)), "{s}");
        }
    }

    /// R-PG-01: the date grammar refuses impossible dates and other spellings.
    #[test]
    fn r_pg_01_dates_are_strict() {
        let d = |s: &str| Date::decode(&Value::String(s.to_owned()), Currency::Eur);
        assert!(d("2028-02-29").is_ok());
        for bad in [
            "2027-02-29",
            "2027-13-01",
            "2027-1-01",
            "1969-12-31",
            "2027-01-32",
        ] {
            assert!(d(bad).is_err(), "{bad} was accepted");
        }
    }

    /// R-PG-01: a stored narrative round-trips, and the inline sentinel is
    /// never read as a stored reference.
    #[test]
    fn r_pg_01_stored_narrative_round_trips() {
        let r = TextRef::new(TextId::from_raw(7), ContentDigest::from_bytes([0xab; 32]));
        let Some(stored) = StoredText::new(r) else {
            panic!("a real text reference is refused");
        };
        let n = Narrative::Stored(stored);
        assert_eq!(Narrative::decode(&n.encode(), Currency::Eur), Ok(n));
        let sentinel = obj(vec![
            ("digest", Value::String("0".repeat(64))),
            ("text", encode_id(0)),
        ]);
        assert!(Narrative::decode(&sentinel, Currency::Eur).is_err());
    }

    /// R-PG-01, ADR-007: the inline sentinel can never be built as a
    /// stored text, so every `Narrative` round-trips.
    #[test]
    fn r_pg_01_stored_text_refuses_the_inline_sentinel() {
        assert_eq!(StoredText::new(INLINE_TEXT), None);
    }

    /// R-PG-01: the action number grammar.
    #[test]
    fn r_pg_01_action_numbers_are_strict() {
        assert!(ActionNumber::new("101234567").is_some());
        assert!(ActionNumber::new("SYNTHETIC-0001").is_some());
        for bad in ["", "a b", "x\u{e9}", &"9".repeat(65)] {
            assert!(ActionNumber::new(bad).is_none(), "{bad:?} was accepted");
        }
    }
}
