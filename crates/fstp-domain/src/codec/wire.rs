//! Wire primitives shared by the codecs (design sections 2.1, 2.3 and 5.1).
//!
//! - [`Wire`] maps one value to JSON and back. Decoding takes a [`Cx`],
//!   which carries the currency of the enclosing record, so that amounts
//!   decode through `fstp_money` with that currency (ADR-006).
//! - [`Flat`] maps a struct to the members of an object, so that a record
//!   payload can share its object with the record's type tag.
//! - Every object is decoded through [`fields`], which refuses an unknown
//!   member and a missing member. An optional value is always present, as
//!   `null` when absent, so every value has exactly one spelling.
//! - Errors carry kinds, schema member names and indices only. They never
//!   carry a member name, string or number from the input (R-NF-02).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fstp_json::{FromJsonError, FromJsonErrorKind, Object, ToJson, Value};
use fstp_money::Currency;

/// The result of a decode step.
pub(crate) type R<T> = Result<T, FromJsonError>;

/// The member that names the variant of a tagged object.
pub(crate) const TAG: &str = "type";

/// The member that names the currency of a record that holds amounts.
pub(crate) const CURRENCY: &str = "currency";

/// The decode context: the currency that amounts inside the value use.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cx(Option<Currency>);

impl Cx {
    /// No currency is known. An amount decoded in this context is refused.
    pub(crate) const NONE: Cx = Cx(None);

    /// Amounts use currency `c`.
    pub(crate) const fn with(c: Currency) -> Cx {
        Cx(Some(c))
    }

    /// The currency, or a refusal when no enclosing value names one.
    pub(crate) fn currency(self) -> R<Currency> {
        self.0.ok_or_else(|| {
            FromJsonError::invalid("an amount outside a value that names its currency")
        })
    }
}

/// A value with one JSON spelling.
pub(crate) trait Wire: Sized {
    /// The JSON form.
    fn put(&self) -> Value;

    /// The value of the JSON form `v`, or a refusal without input content.
    fn take(v: &Value, cx: Cx) -> R<Self>;

    /// The currency of the first amount inside the value, if any.
    fn currency(&self) -> Option<Currency> {
        None
    }
}

/// A struct whose fields are the members of an object.
pub(crate) trait Flat: Sized {
    /// The member names, one per field.
    const NAMES: &'static [&'static str];

    /// Adds one member per field to `o`.
    fn put_into(&self, o: &mut Object);

    /// Reads the fields from members already checked by [`fields`].
    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self>;

    /// The currency of the first amount inside the value, if any.
    fn flat_currency(&self) -> Option<Currency> {
        None
    }
}

/// The members of an object whose names were checked against a schema.
pub(crate) struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    /// The member `k`.
    pub(crate) fn value(&self, k: &'static str) -> R<&'a Value> {
        self.0.get(k).ok_or_else(|| missing(k))
    }

    /// The member `k`, decoded.
    pub(crate) fn get<T: Wire>(&self, k: &'static str, cx: Cx) -> R<T> {
        let v = self.value(k)?;
        T::take(v, cx).map_err(|e| e.at_field(k))
    }
}

fn missing(k: &'static str) -> FromJsonError {
    FromJsonError::new(FromJsonErrorKind::MissingField).at_field(k)
}

/// The object inside `v`, or a wrong-type refusal.
pub(crate) fn object(v: &Value) -> R<&Object> {
    v.as_object()
        .ok_or_else(|| FromJsonError::wrong_type("an object", v))
}

/// The object inside `v`, whose member names are exactly the names in
/// `groups`. An unknown member is refused without its name (R-NF-02).
pub(crate) fn fields<'a>(v: &'a Value, groups: &[&[&'static str]]) -> R<Fields<'a>> {
    let o = object(v)?;
    let known = |k: &str| groups.iter().any(|g| g.contains(&k));
    if o.keys().any(|k| !known(k)) {
        return Err(FromJsonError::new(FromJsonErrorKind::UnknownField));
    }
    for name in groups.iter().flat_map(|g| g.iter()) {
        if !o.contains_key(name) {
            return Err(missing(name));
        }
    }
    Ok(Fields(o))
}

/// The type tag of the tagged object `v`.
pub(crate) fn tag_of(v: &Value) -> R<&str> {
    let o = object(v)?;
    let t = o.get(TAG).ok_or_else(|| missing(TAG))?;
    t.as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a type tag string", t).at_field(TAG))
}

/// The refusal of a type tag that names no variant.
pub(crate) fn unknown_tag() -> FromJsonError {
    FromJsonError::invalid("unknown type tag").at_field(TAG)
}

/// A new object holding only the type tag `name`.
pub(crate) fn tagged(name: &'static str) -> Object {
    let mut o = Object::new();
    let _ = o.insert(TAG, Value::String(name.to_owned()));
    o
}

/// The currency written for a record: that of its first amount. A record
/// with no amount at all writes EUR, the canonical code for that case.
pub(crate) fn pick_currency(found: &[Option<Currency>]) -> Currency {
    found.iter().find_map(|c| *c).unwrap_or(Currency::Eur)
}

/// Refuses a `currency` member that the encoder would not write for the
/// decoded value. A value with amounts already uses the member's currency.
/// A value with no amount must name EUR, so each such value keeps one
/// spelling once a second currency exists (ADR-007).
pub(crate) fn check_currency(written: Currency, found: &[Option<Currency>]) -> R<()> {
    if pick_currency(found) == written {
        Ok(())
    } else {
        Err(FromJsonError::invalid("currency member is not the canonical one").at_field(CURRENCY))
    }
}

/// The string inside `v`.
pub(crate) fn str_of<'a>(v: &'a Value, expected: &'static str) -> R<&'a str> {
    v.as_str()
        .ok_or_else(|| FromJsonError::wrong_type(expected, v))
}

/// Whether `s` is a canonical unsigned decimal: digits only, no leading zero.
fn canonical_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn not_decimal() -> FromJsonError {
    FromJsonError::invalid("not a canonical decimal string")
}

fn decimal_range() -> FromJsonError {
    FromJsonError::invalid("decimal string out of range")
}

/// A decimal string, the form of every id, `Seq` and other 64-bit or wider
/// integer (design section 2.1).
pub(crate) fn put_decimal(x: impl core::fmt::Display) -> Value {
    Value::String(x.to_string())
}

/// A `u128` from its canonical decimal string.
pub(crate) fn take_u128(v: &Value) -> R<u128> {
    let s = str_of(v, "a decimal string")?;
    if !canonical_digits(s) {
        return Err(not_decimal());
    }
    s.parse::<u128>().map_err(|_| decimal_range())
}

/// A `u64` from its canonical decimal string.
pub(crate) fn take_u64(v: &Value) -> R<u64> {
    let s = str_of(v, "a decimal string")?;
    if !canonical_digits(s) {
        return Err(not_decimal());
    }
    s.parse::<u64>().map_err(|_| decimal_range())
}

/// An `i64` from its canonical decimal string: an optional minus sign, no
/// leading zero and no `-0`.
pub(crate) fn take_i64(v: &Value) -> R<i64> {
    let s = str_of(v, "a decimal string")?;
    let digits = s.strip_prefix('-').unwrap_or(s);
    if !canonical_digits(digits) || s == "-0" {
        return Err(not_decimal());
    }
    s.parse::<i64>().map_err(|_| decimal_range())
}

/// A small unsigned integer from a JSON number lexeme of digits only.
fn take_small(v: &Value, target: &'static str) -> R<u64> {
    let n = v
        .as_number()
        .ok_or_else(|| FromJsonError::wrong_type("an integer", v))?;
    let s = n.as_str();
    if s.starts_with('-') {
        return Err(FromJsonError::new(FromJsonErrorKind::OutOfRange { target }));
    }
    if !canonical_digits(s) {
        return Err(FromJsonError::new(FromJsonErrorKind::NotAnInteger));
    }
    s.parse::<u64>()
        .map_err(|_| FromJsonError::new(FromJsonErrorKind::OutOfRange { target }))
}

macro_rules! small_uint {
    ($($t:ident),*) => { $(
        impl Wire for $t {
            fn put(&self) -> Value {
                ToJson::to_json(self)
            }

            fn take(v: &Value, _cx: Cx) -> R<Self> {
                let n = take_small(v, stringify!($t))?;
                $t::try_from(n).map_err(|_| {
                    FromJsonError::new(FromJsonErrorKind::OutOfRange { target: stringify!($t) })
                })
            }
        }
    )* };
}

small_uint!(u8, u16, u32);

/// Lowercase hexadecimal text of `bytes`.
pub(crate) fn put_hex(bytes: &[u8]) -> Value {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    Value::String(s)
}

fn nibble(c: u8) -> R<u8> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => Err(FromJsonError::invalid("not a lowercase hexadecimal digit")),
    }
}

/// `N` bytes from exactly `2 N` lowercase hexadecimal digits.
pub(crate) fn take_hex<const N: usize>(v: &Value) -> R<[u8; N]> {
    let s = str_of(v, "a hexadecimal string")?;
    let b = s.as_bytes();
    if b.len() != N.saturating_mul(2) {
        return Err(FromJsonError::invalid(
            "hexadecimal string of the wrong length",
        ));
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return Err(FromJsonError::invalid(
                "hexadecimal string of the wrong length",
            ));
        };
        *slot = nibble(*hi)?.wrapping_shl(4) | nibble(*lo)?;
    }
    Ok(out)
}

impl Wire for bool {
    fn put(&self) -> Value {
        Value::Bool(*self)
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        v.as_bool()
            .ok_or_else(|| FromJsonError::wrong_type("a boolean", v))
    }
}

impl Wire for String {
    fn put(&self) -> Value {
        Value::String(self.clone())
    }

    fn take(v: &Value, _cx: Cx) -> R<Self> {
        str_of(v, "a string").map(str::to_owned)
    }
}

impl<T: Wire> Wire for Box<T> {
    fn put(&self) -> Value {
        (**self).put()
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        T::take(v, cx).map(Box::new)
    }

    fn currency(&self) -> Option<Currency> {
        (**self).currency()
    }
}

/// `None` is `null`. The member is always present, so it has one spelling.
impl<T: Wire> Wire for Option<T> {
    fn put(&self) -> Value {
        match self {
            Some(x) => x.put(),
            None => Value::Null,
        }
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        match v {
            Value::Null => Ok(None),
            other => T::take(other, cx).map(Some),
        }
    }

    fn currency(&self) -> Option<Currency> {
        self.as_ref().and_then(Wire::currency)
    }
}

/// A list, in its order.
impl<T: Wire> Wire for Vec<T> {
    fn put(&self) -> Value {
        Value::Array(self.iter().map(Wire::put).collect())
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let a = v
            .as_array()
            .ok_or_else(|| FromJsonError::wrong_type("an array", v))?;
        a.iter()
            .enumerate()
            .map(|(i, x)| T::take(x, cx).map_err(|e| e.at_index(i)))
            .collect()
    }

    fn currency(&self) -> Option<Currency> {
        self.iter().find_map(Wire::currency)
    }
}

/// A set, as a list in strictly ascending order. Any other order is
/// refused, so a set has one spelling.
impl<T: Wire + Ord> Wire for BTreeSet<T> {
    fn put(&self) -> Value {
        Value::Array(self.iter().map(Wire::put).collect())
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let items: Vec<T> = Wire::take(v, cx)?;
        let ascending = items.iter().zip(items.iter().skip(1)).all(|(a, b)| a < b);
        if !ascending {
            return Err(FromJsonError::invalid(
                "set members not in strictly ascending order",
            ));
        }
        Ok(items.into_iter().collect())
    }

    fn currency(&self) -> Option<Currency> {
        self.iter().find_map(Wire::currency)
    }
}

/// A map key with one string spelling.
pub(crate) trait Key: Sized + Ord {
    /// The member name.
    fn key(&self) -> String;

    /// The key of the member name `s`, refused without its content.
    fn from_key(s: &str) -> R<Self>;
}

/// A map, as an object keyed by [`Key`]. RFC 8785 orders the members.
impl<K: Key, V: Wire> Wire for BTreeMap<K, V> {
    fn put(&self) -> Value {
        let mut o = Object::new();
        for (k, x) in self {
            let _ = o.insert(k.key(), x.put());
        }
        Value::Object(o)
    }

    fn take(v: &Value, cx: Cx) -> R<Self> {
        let o = object(v)?;
        let mut out = BTreeMap::new();
        for (k, x) in o.iter() {
            let key = K::from_key(k)?;
            let value = V::take(x, cx)?;
            if out.insert(key, value).is_some() {
                return Err(FromJsonError::invalid("a map key repeats"));
            }
        }
        Ok(out)
    }

    fn currency(&self) -> Option<Currency> {
        self.values().find_map(Wire::currency)
    }
}

/// `Wire` for a type that implements [`Flat`]: one object of its fields.
macro_rules! flat_wire {
    ($t:ty) => {
        impl $crate::codec::wire::Wire for $t {
            fn put(&self) -> fstp_json::Value {
                let mut o = fstp_json::Object::new();
                $crate::codec::wire::Flat::put_into(self, &mut o);
                fstp_json::Value::Object(o)
            }

            fn take(
                v: &fstp_json::Value,
                cx: $crate::codec::wire::Cx,
            ) -> $crate::codec::wire::R<Self> {
                let f =
                    $crate::codec::wire::fields(v, &[<$t as $crate::codec::wire::Flat>::NAMES])?;
                <$t as $crate::codec::wire::Flat>::take_from(&f, cx)
            }

            fn currency(&self) -> Option<fstp_money::Currency> {
                $crate::codec::wire::Flat::flat_currency(self)
            }
        }
    };
}
pub(crate) use flat_wire;

/// [`Flat`] and [`Wire`] for a struct with public fields. Each member is
/// named after its field.
macro_rules! flat_struct {
    ($t:ident { $($f:ident),* $(,)? }) => {
        impl $crate::codec::wire::Flat for $t {
            const NAMES: &'static [&'static str] = &[$(stringify!($f)),*];

            fn put_into(&self, o: &mut fstp_json::Object) {
                $( let _ = o.insert(stringify!($f), $crate::codec::wire::Wire::put(&self.$f)); )*
            }

            fn take_from(
                f: &$crate::codec::wire::Fields<'_>,
                cx: $crate::codec::wire::Cx,
            ) -> $crate::codec::wire::R<Self> {
                Ok($t { $( $f: f.get(stringify!($f), cx)?, )* })
            }

            fn flat_currency(&self) -> Option<fstp_money::Currency> {
                None $( .or_else(|| $crate::codec::wire::Wire::currency(&self.$f)) )*
            }
        }

        $crate::codec::wire::flat_wire!($t);
    };
}
pub(crate) use flat_struct;

/// `Wire` for a fieldless enum: the variant name as a string.
macro_rules! unit_enum {
    ($t:ident { $($v:ident),* $(,)? }) => {
        impl $crate::codec::wire::Wire for $t {
            fn put(&self) -> fstp_json::Value {
                let name = match self { $( $t::$v => stringify!($v), )* };
                fstp_json::Value::String(name.to_owned())
            }

            fn take(
                v: &fstp_json::Value,
                _cx: $crate::codec::wire::Cx,
            ) -> $crate::codec::wire::R<Self> {
                let s = $crate::codec::wire::str_of(v, "a variant name")?;
                $( if s == stringify!($v) { return Ok($t::$v); } )*
                Err(fstp_json::FromJsonError::invalid("unknown variant name"))
            }
        }
    };
}
pub(crate) use unit_enum;

/// `Wire` for a newtype over a `Wire` value: the inner value's form.
macro_rules! newtype_wire {
    ($($t:ident),* $(,)?) => { $(
        impl $crate::codec::wire::Wire for $t {
            fn put(&self) -> fstp_json::Value {
                $crate::codec::wire::Wire::put(&self.0)
            }

            fn take(
                v: &fstp_json::Value,
                cx: $crate::codec::wire::Cx,
            ) -> $crate::codec::wire::R<Self> {
                $crate::codec::wire::Wire::take(v, cx).map($t)
            }

            fn currency(&self) -> Option<fstp_money::Currency> {
                $crate::codec::wire::Wire::currency(&self.0)
            }
        }
    )* };
}
pub(crate) use newtype_wire;

/// `Wire` for an enum with data, as an object with a [`TAG`] member.
///
/// - `fields`: a struct-like variant whose fields become members.
/// - `money`: the same, plus a [`CURRENCY`] member that its amounts decode with.
/// - `tuple`: a one-field variant, whose field becomes the named member.
/// - `flat`: a one-field variant over a [`Flat`] payload, whose fields become members.
/// - `flat_money`: the same, plus a [`CURRENCY`] member.
///
/// The match in `put` is exhaustive, so a variant left out fails to compile.
macro_rules! tagged_enum {
    (
        $e:ident;
        fields { $( $v:ident { $($f:ident),* } ),* $(,)? }
        money { $( $mv:ident { $($mf:ident),* } ),* $(,)? }
        tuple { $( $tv:ident ( $tf:ident ) ),* $(,)? }
        flat { $( $nv:ident ( $nt:ty ) ),* $(,)? }
        flat_money { $( $nmv:ident ( $nmt:ty ) ),* $(,)? }
    ) => {
        impl $crate::codec::wire::Wire for $e {
            fn put(&self) -> fstp_json::Value {
                match self {
                    $( $e::$v { $($f),* } => {
                        #[allow(unused_mut)]
                        let mut o = $crate::codec::wire::tagged(stringify!($v));
                        $( let _ = o.insert(stringify!($f), $crate::codec::wire::Wire::put($f)); )*
                        fstp_json::Value::Object(o)
                    } )*
                    $( $e::$mv { $($mf),* } => {
                        let c = $crate::codec::wire::pick_currency(
                            &[$( $crate::codec::wire::Wire::currency($mf) ),*],
                        );
                        let mut o = $crate::codec::wire::tagged(stringify!($mv));
                        let _ = o.insert(
                            $crate::codec::wire::CURRENCY,
                            $crate::codec::wire::Wire::put(&c),
                        );
                        $( let _ = o.insert(stringify!($mf), $crate::codec::wire::Wire::put($mf)); )*
                        fstp_json::Value::Object(o)
                    } )*
                    $( $e::$tv($tf) => {
                        let mut o = $crate::codec::wire::tagged(stringify!($tv));
                        let _ = o.insert(stringify!($tf), $crate::codec::wire::Wire::put($tf));
                        fstp_json::Value::Object(o)
                    } )*
                    $( $e::$nv(x) => {
                        let mut o = $crate::codec::wire::tagged(stringify!($nv));
                        $crate::codec::wire::Flat::put_into(x, &mut o);
                        fstp_json::Value::Object(o)
                    } )*
                    $( $e::$nmv(x) => {
                        let c = $crate::codec::wire::pick_currency(
                            &[$crate::codec::wire::Flat::flat_currency(x)],
                        );
                        let mut o = $crate::codec::wire::tagged(stringify!($nmv));
                        let _ = o.insert(
                            $crate::codec::wire::CURRENCY,
                            $crate::codec::wire::Wire::put(&c),
                        );
                        $crate::codec::wire::Flat::put_into(x, &mut o);
                        fstp_json::Value::Object(o)
                    } )*
                }
            }

            #[allow(unused_variables)]
            fn take(
                v: &fstp_json::Value,
                cx: $crate::codec::wire::Cx,
            ) -> $crate::codec::wire::R<Self> {
                #[allow(unused_imports)]
                use $crate::codec::wire::{CURRENCY, Cx, TAG, fields};
                let tag = $crate::codec::wire::tag_of(v)?;
                $( if tag == stringify!($v) {
                    let f = fields(v, &[&[TAG], &[$(stringify!($f)),*]])?;
                    return Ok($e::$v { $( $f: f.get(stringify!($f), cx)?, )* });
                } )*
                $( if tag == stringify!($mv) {
                    let f = fields(v, &[&[TAG, CURRENCY], &[$(stringify!($mf)),*]])?;
                    let c = f.get(CURRENCY, Cx::NONE)?;
                    let cx = Cx::with(c);
                    $( let $mf = f.get(stringify!($mf), cx)?; )*
                    $crate::codec::wire::check_currency(
                        c,
                        &[$( $crate::codec::wire::Wire::currency(&$mf) ),*],
                    )?;
                    return Ok($e::$mv { $($mf),* });
                } )*
                $( if tag == stringify!($tv) {
                    let f = fields(v, &[&[TAG, stringify!($tf)]])?;
                    return Ok($e::$tv(f.get(stringify!($tf), cx)?));
                } )*
                $( if tag == stringify!($nv) {
                    let f = fields(v, &[&[TAG], <$nt as $crate::codec::wire::Flat>::NAMES])?;
                    return Ok($e::$nv(<$nt as $crate::codec::wire::Flat>::take_from(&f, cx)?));
                } )*
                $( if tag == stringify!($nmv) {
                    let f = fields(
                        v,
                        &[&[TAG, CURRENCY], <$nmt as $crate::codec::wire::Flat>::NAMES],
                    )?;
                    let c = f.get(CURRENCY, Cx::NONE)?;
                    let x = <$nmt as $crate::codec::wire::Flat>::take_from(&f, Cx::with(c))?;
                    $crate::codec::wire::check_currency(
                        c,
                        &[$crate::codec::wire::Flat::flat_currency(&x)],
                    )?;
                    return Ok($e::$nmv(x));
                } )*
                Err($crate::codec::wire::unknown_tag())
            }
        }
    };
}
pub(crate) use tagged_enum;
