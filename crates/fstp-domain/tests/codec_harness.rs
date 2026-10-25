//! Self-tests of the codec test harness in `codec_support` (design section
//! 6.1, teeth).
//!
//! A toy type holds an id, a `Seq`, amounts, a percentage, free-form text, a
//! list and an id-keyed map. A strict codec for it must pass every check.
//! Each flawed codec breaks one rule, and the matching check must fail. The
//! probe must pick a real codec when one exists and report a missing one
//! otherwise. These tests are green without the domain codec.

mod codec_support;

use std::collections::BTreeMap;

use codec_support::{Codec, Draw, G, Missing, codec_for, id, nonneg, percent, pos, seq, word};
use fstp_domain::id::{AccountId, LineId, OrganisationId, ProximityListId};
use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{FromJson, FromJsonError, FromJsonErrorKind, Number, Object, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::{
    Amount, Currency, NonNegAmount, Percent, PosAmount, nonneg_amount_from_json, percent_from_json,
    pos_amount_from_json,
};
use fstp_prop::{Config, Gen, check, run};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    line: LineId,
    amount: PosAmount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Toy {
    account: AccountId,
    seq: Seq,
    amount: NonNegAmount,
    pct: Percent,
    label: String,
    items: Vec<Item>,
    lists: BTreeMap<OrganisationId, ProximityListId>,
}

/// A type with no codec, for the probe.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NoCodec;

fn toy(g: &mut Gen, d: &mut Draw) -> G<Toy> {
    let account = id(g, d, AccountId::from_raw);
    let s = seq(g, d);
    let amount = nonneg(g)?;
    let pct = percent(g)?;
    let label = word(g);
    let mut items = Vec::new();
    for _ in 0..g.usize_in(usize::from(d.with_amounts)..=3) {
        items.push(Item {
            line: id(g, d, LineId::from_raw),
            amount: pos(g)?,
        });
    }
    let mut lists = BTreeMap::new();
    if g.bool() {
        lists.insert(
            id(g, d, OrganisationId::from_raw),
            id(g, d, ProximityListId::from_raw),
        );
    }
    Ok(Toy {
        account,
        seq: s,
        amount,
        pct,
        label,
        items,
        lists,
    })
}

// Flaws, as bits of a const parameter.
const STRICT: u8 = 0;
const ALLOW_UNKNOWN: u8 = 1;
const NUMERIC_IDS: u8 = 2;
const LENIENT_IDS: u8 = 4;
const NUMBER_AMOUNTS: u8 = 8;
const LEAK_KEYS: u8 = 16;

const FIELDS: [&str; 7] = ["account", "amount", "items", "label", "lists", "pct", "seq"];
const ITEM_FIELDS: [&str; 2] = ["amount", "line"];

fn id_value<const F: u8>(raw: u128) -> Value {
    if F & NUMERIC_IDS != 0 {
        Number::from_lexeme(&raw.to_string())
            .map(Value::Number)
            .unwrap_or(Value::Null)
    } else {
        Value::String(raw.to_string())
    }
}

fn parse_id<const F: u8>(v: &Value) -> Result<u128, FromJsonError> {
    if F & NUMERIC_IDS != 0
        && let Some(n) = v.as_number().and_then(Number::as_u128)
    {
        return Ok(n);
    }
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a decimal id string", v))?;
    parse_id_text::<F>(s)
}

fn parse_id_text<const F: u8>(s: &str) -> Result<u128, FromJsonError> {
    if F & LENIENT_IDS != 0 {
        return s
            .trim()
            .parse::<u128>()
            .map_err(|_| FromJsonError::invalid("not an id"));
    }
    let canonical = (s == "0" || (!s.starts_with('0') && !s.is_empty()))
        && s.bytes().all(|b| b.is_ascii_digit());
    if !canonical {
        return Err(FromJsonError::invalid("not a canonical decimal id"));
    }
    s.parse::<u128>()
        .map_err(|_| FromJsonError::invalid("id out of range"))
}

fn check_members<const F: u8>(o: &Object, fields: &[&str]) -> Result<(), FromJsonError> {
    if F & ALLOW_UNKNOWN != 0 {
        return Ok(());
    }
    if F & LEAK_KEYS != 0 {
        return reject_unknown(o, fields);
    }
    if o.keys().any(|k| !fields.contains(&k)) {
        return Err(FromJsonError::new(FromJsonErrorKind::UnknownField));
    }
    Ok(())
}

fn member<'a>(o: &'a Object, key: &'static str) -> Result<&'a Value, FromJsonError> {
    o.get(key)
        .ok_or_else(|| FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key))
}

fn amount_of<const F: u8>(v: &Value) -> Result<Amount, FromJsonError> {
    if F & NUMBER_AMOUNTS != 0
        && let Some(n) = v.as_number()
    {
        return Amount::parse(n.as_str(), Currency::Eur)
            .map_err(|_| FromJsonError::invalid("not an amount"));
    }
    fstp_money::amount_from_json(v, Currency::Eur)
}

fn encode<const F: u8>(t: &Toy) -> Value {
    let mut o = Object::new();
    o.insert("account", id_value::<F>(t.account.raw()));
    o.insert("seq", Value::String(t.seq.raw().to_string()));
    o.insert("amount", t.amount.to_json());
    o.insert("pct", t.pct.to_json());
    o.insert("label", Value::String(t.label.clone()));
    let items: Vec<Value> = t
        .items
        .iter()
        .map(|i| {
            let mut io = Object::new();
            io.insert("line", id_value::<F>(i.line.raw()));
            io.insert("amount", i.amount.to_json());
            Value::Object(io)
        })
        .collect();
    o.insert("items", Value::Array(items.into()));
    let mut lists = Object::new();
    for (k, v) in &t.lists {
        lists.insert(k.raw().to_string(), Value::String(v.raw().to_string()));
    }
    o.insert("lists", Value::Object(lists));
    Value::Object(o)
}

fn decode<const F: u8>(v: &Value) -> Result<Toy, FromJsonError> {
    let o = expect_object(v)?;
    check_members::<F>(o, &FIELDS)?;
    let account = AccountId::from_raw(parse_id::<F>(member(o, "account")?)?);
    let seq_text = member(o, "seq")?
        .as_str()
        .ok_or_else(|| FromJsonError::invalid("seq is not a string"))?;
    let raw_seq = u64::try_from(parse_id_text::<F>(seq_text)?)
        .map_err(|_| FromJsonError::invalid("seq out of range"))?;
    let amount = if F & NUMBER_AMOUNTS != 0 {
        NonNegAmount::new(amount_of::<F>(member(o, "amount")?)?)
            .map_err(|_| FromJsonError::invalid("negative"))?
    } else {
        nonneg_amount_from_json(member(o, "amount")?, Currency::Eur)?
    };
    let pct_value = member(o, "pct")?;
    let pct = match pct_value.as_number() {
        Some(n) if F & NUMBER_AMOUNTS != 0 => {
            Percent::parse(n.as_str()).map_err(|_| FromJsonError::invalid("not a percent"))?
        }
        _ => percent_from_json(pct_value)?,
    };
    let label = member(o, "label")?
        .as_str()
        .ok_or_else(|| FromJsonError::invalid("label is not a string"))?
        .to_owned();
    let items_value = member(o, "items")?
        .as_array()
        .ok_or_else(|| FromJsonError::invalid("items is not an array"))?;
    let mut items = Vec::new();
    for iv in items_value.iter() {
        let io = expect_object(iv)?;
        check_members::<F>(io, &ITEM_FIELDS)?;
        let line = LineId::from_raw(parse_id::<F>(member(io, "line")?)?);
        let amount = if F & NUMBER_AMOUNTS != 0 {
            PosAmount::new(amount_of::<F>(member(io, "amount")?)?)
                .map_err(|_| FromJsonError::invalid("not positive"))?
        } else {
            pos_amount_from_json(member(io, "amount")?, Currency::Eur)?
        };
        items.push(Item { line, amount });
    }
    let lists_value = expect_object(member(o, "lists")?)?;
    let mut lists = BTreeMap::new();
    for (k, lv) in lists_value.iter() {
        let key = OrganisationId::from_raw(parse_id_text::<F>(k)?);
        lists.insert(key, ProximityListId::from_raw(parse_id::<F>(lv)?));
    }
    Ok(Toy {
        account,
        seq: Seq::from_raw(raw_seq),
        amount,
        pct,
        label,
        items,
        lists,
    })
}

impl ToJson for Toy {
    fn to_json(&self) -> Value {
        encode::<STRICT>(self)
    }
}

impl FromJson for Toy {
    fn from_json(v: &Value) -> Result<Toy, FromJsonError> {
        decode::<STRICT>(v)
    }
}

fn codec<const F: u8>() -> Codec<Toy> {
    fn enc<const F: u8>(t: &Toy) -> Result<Value, Missing> {
        Ok(encode::<F>(t))
    }
    fn dec<const F: u8>(v: &Value) -> Result<Result<Toy, FromJsonError>, Missing> {
        Ok(decode::<F>(v))
    }
    Codec {
        name: "Toy",
        enc: enc::<F>,
        dec: dec::<F>,
    }
}

fn fails(name: &str, prop: impl Fn(&mut Gen) -> Result<(), String>) -> bool {
    run(name, Config::default(), prop).failure().is_some()
}

/// The probe picks the real `ToJson` and `FromJson` impls when a type has
/// both, so a correct codec round-trips through `codec_for!`.
#[test]
fn codec_harness_probe_finds_a_present_codec() {
    let c = codec_for!(Toy);
    check("codec_harness_probe_finds_a_present_codec", |g| {
        let mut d = Draw::plain();
        let t = toy(g, &mut d)?;
        c.round_trip(&t)?;
        Ok(())
    });
}

/// The probe reports a missing codec as a failure that names the lane.
#[test]
fn codec_harness_probe_reports_a_missing_codec() {
    let c = codec_for!(NoCodec);
    let err = c.round_trip(&NoCodec).err().unwrap_or_default();
    assert!(err.contains("no JSON codec for NoCodec"), "{err}");
}

/// A strict codec passes the round trip check.
#[test]
fn codec_harness_strict_codec_round_trips() {
    let c = codec::<STRICT>();
    check("codec_harness_strict_codec_round_trips", |g| {
        let mut d = Draw::plain();
        let t = toy(g, &mut d)?;
        c.round_trip(&t)?;
        Ok(())
    });
}

/// A strict codec passes the unknown member check.
#[test]
fn codec_harness_strict_codec_rejects_unknown_members() {
    let c = codec::<STRICT>();
    check("codec_harness_strict_codec_rejects_unknown_members", |g| {
        let mut d = Draw::plain();
        let t = toy(g, &mut d)?;
        c.rejects_unknown_members(&t)
    });
}

/// A strict codec passes the JSON number amount check.
#[test]
fn codec_harness_strict_codec_rejects_number_amounts() {
    let c = codec::<STRICT>();
    check("codec_harness_strict_codec_rejects_number_amounts", |g| {
        let mut d = Draw::amounts();
        let t = toy(g, &mut d)?;
        c.rejects_number_amounts(&t)
    });
}

/// A strict codec passes the amount spelling check.
#[test]
fn codec_harness_strict_codec_rejects_other_amount_spellings() {
    let c = codec::<STRICT>();
    check(
        "codec_harness_strict_codec_rejects_other_amount_spellings",
        |g| {
            let mut d = Draw::amounts();
            let t = toy(g, &mut d)?;
            c.rejects_other_amount_spellings(&t)
        },
    );
}

/// A strict codec passes the decimal id check.
#[test]
fn codec_harness_strict_codec_ids_are_decimal_strings() {
    let c = codec::<STRICT>();
    check("codec_harness_strict_codec_ids_are_decimal_strings", |g| {
        let mut d = Draw::marked();
        let t = toy(g, &mut d)?;
        c.ids_are_decimal_strings(&t, &d)
    });
}

/// A strict codec passes the one-spelling id check.
#[test]
fn codec_harness_strict_codec_ids_have_one_spelling() {
    let c = codec::<STRICT>();
    check("codec_harness_strict_codec_ids_have_one_spelling", |g| {
        let mut d = Draw::marked();
        let t = toy(g, &mut d)?;
        c.ids_have_one_spelling(&t, &d)
    });
}

/// A strict codec passes the R-NF-02 error content check.
#[test]
fn codec_harness_strict_codec_errors_hold_no_input_content() {
    let c = codec::<STRICT>();
    check(
        "codec_harness_strict_codec_errors_hold_no_input_content",
        |g| {
            let mut d = Draw::plain();
            let t = toy(g, &mut d)?;
            c.errors_hold_no_input_content(&t)
        },
    );
}

/// Teeth: a codec that ignores unknown members fails the unknown member check.
#[test]
fn codec_harness_detects_ignored_unknown_members() {
    let c = codec::<ALLOW_UNKNOWN>();
    assert!(fails("detects_ignored_unknown_members", |g| {
        let mut d = Draw::plain();
        let t = toy(g, &mut d)?;
        c.rejects_unknown_members(&t)
    }));
}

/// Teeth: a codec that writes ids as JSON numbers fails the round trip, as
/// RFC 8785 has no exact form above 2^53.
#[test]
fn codec_harness_detects_numeric_ids_in_round_trip() {
    let c = codec::<NUMERIC_IDS>();
    assert!(fails("detects_numeric_ids_in_round_trip", |g| {
        let mut d = Draw::marked();
        let t = toy(g, &mut d)?;
        c.round_trip(&t)?;
        Ok(())
    }));
}

/// Teeth: a codec that writes ids as JSON numbers fails the decimal id check.
#[test]
fn codec_harness_detects_numeric_ids() {
    let c = codec::<NUMERIC_IDS>();
    assert!(fails("detects_numeric_ids", |g| {
        let mut d = Draw::marked();
        let t = toy(g, &mut d)?;
        c.ids_are_decimal_strings(&t, &d)
    }));
}

/// Teeth: a codec that accepts `"+5"` or `"005"` for an id fails the
/// one-spelling check.
#[test]
fn codec_harness_detects_lenient_ids() {
    let c = codec::<LENIENT_IDS>();
    assert!(fails("detects_lenient_ids", |g| {
        let mut d = Draw::marked();
        let t = toy(g, &mut d)?;
        c.ids_have_one_spelling(&t, &d)
    }));
}

/// Teeth: a codec that accepts JSON numbers for amounts fails the ADR-006
/// number check.
#[test]
fn codec_harness_detects_number_amounts() {
    let c = codec::<NUMBER_AMOUNTS>();
    assert!(fails("detects_number_amounts", |g| {
        let mut d = Draw::amounts();
        let t = toy(g, &mut d)?;
        c.rejects_number_amounts(&t)
    }));
}

/// Teeth: a codec whose unknown member error holds the member name, as
/// `fstp_json::typed::reject_unknown` does in its path, fails the R-NF-02
/// check.
#[test]
fn codec_harness_detects_leaked_member_names() {
    let c = codec::<LEAK_KEYS>();
    assert!(fails("detects_leaked_member_names", |g| {
        let mut d = Draw::plain();
        let t = toy(g, &mut d)?;
        c.errors_hold_no_input_content(&t)
    }));
}
