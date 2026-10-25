//! Property tests: random values of every supported type survive INSERT
//! and SELECT through a real PostgreSQL server unchanged (test plan,
//! "Database" layer, wire protocol conformance).
//!
//! Each property inserts one generated value per case, NULL included, and
//! reads it back by id. Generators favour extremes: integer bounds, float
//! specials, the first and last valid dates and timestamps, infinities,
//! long numerics and Unicode text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::fmt::Debug;
use std::sync::Mutex;

use common::{PgClient, block_on, connect, fresh};
use fstp_json::{Array, Number, Object, Value};
use fstp_pgwire::{Date, FromSql, Numeric, Timestamptz, ToSql, ToSqlType, Uuid};
use fstp_prop::{Config as PropConfig, Gen, check_with, prop_assert};

/// First and last valid values, as the server defines them.
const MIN_TIMESTAMP: i64 = -211_813_488_000_000_000;
const END_TIMESTAMP: i64 = 9_223_371_331_200_000_000;
const MIN_DATE: i32 = -2_451_545;
const END_DATE: i32 = 2_145_031_949;

fn cases() -> PropConfig {
    PropConfig::from_env()
}

/// Runs a round-trip property for one column type. `create` and the two
/// statements are fixed per type, so no SQL is built at run time.
fn round_trip<T, G, E>(
    name: &str,
    create: &'static str,
    insert: &'static str,
    select: &'static str,
    gen_value: G,
    equal: E,
) where
    T: ToSql + ToSqlType + FromSql + Debug + Sync,
    G: Fn(&mut Gen) -> T,
    E: Fn(&T, &T) -> bool,
{
    let (_db, cfg) = fresh();
    let mut client = connect(&cfg);
    block_on(client.execute(create, &[])).unwrap();
    let client: Mutex<PgClient> = Mutex::new(client);
    check_with(name, cases(), |g| {
        let value: Option<T> = if g.weighted(&[1, 9]) == 0 {
            None
        } else {
            Some(gen_value(g))
        };
        g.note("value", &value);
        let mut c = client.lock().unwrap();
        let back: Option<T> = block_on(async {
            let id: i64 = c
                .query_one(insert, &[&value])
                .await
                .map_err(|e| format!("insert failed: {e}"))?
                .get(0)
                .map_err(|e| e.to_string())?;
            c.query_one(select, &[&id])
                .await
                .map_err(|e| format!("select failed: {e}"))?
                .get(0)
                .map_err(|e| e.to_string())
        })?;
        let same = match (&value, &back) {
            (None, None) => true,
            (Some(a), Some(b)) => equal(a, b),
            _ => false,
        };
        prop_assert!(same, "sent {value:?}, got back {back:?}");
        Ok(())
    });
}

macro_rules! table {
    ($ty:literal) => {
        (
            concat!(
                "CREATE TABLE t (id int8 GENERATED ALWAYS AS IDENTITY PRIMARY KEY, v ",
                $ty,
                ")"
            ),
            "INSERT INTO t (v) VALUES ($1) RETURNING id",
            "SELECT v FROM t WHERE id = $1",
        )
    };
}

#[test]
fn bool_round_trips() {
    let (c, i, s) = table!("bool");
    round_trip("pg_bool_round_trip", c, i, s, Gen::bool, |a, b| a == b);
}

#[test]
fn int2_round_trips() {
    let (c, i, s) = table!("int2");
    round_trip(
        "pg_int2_round_trip",
        c,
        i,
        s,
        |g| i16::try_from(g.i32_in(i32::from(i16::MIN)..=i32::from(i16::MAX))).unwrap(),
        |a, b| a == b,
    );
}

#[test]
fn int4_round_trips() {
    let (c, i, s) = table!("int4");
    round_trip("pg_int4_round_trip", c, i, s, Gen::i32, |a, b| a == b);
}

#[test]
fn int8_round_trips() {
    let (c, i, s) = table!("int8");
    round_trip("pg_int8_round_trip", c, i, s, Gen::i64, |a, b| a == b);
}

fn gen_f64(g: &mut Gen) -> f64 {
    let specials = [
        0.0,
        -0.0,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        f64::EPSILON,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        5e-324,
    ];
    if g.bool() {
        *g.pick(&specials)
    } else {
        f64::from_bits(g.u64())
    }
}

#[test]
fn float8_round_trips() {
    let (c, i, s) = table!("float8");
    round_trip(
        "pg_float8_round_trip",
        c,
        i,
        s,
        gen_f64,
        |a: &f64, b: &f64| a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()),
    );
}

/// Any Unicode text except NUL, which PostgreSQL text cannot hold.
fn gen_text(g: &mut Gen) -> String {
    let len = if g.weighted(&[9, 1]) == 0 {
        0..=64
    } else {
        0..=4000
    };
    g.string(len).replace('\0', "\u{fffd}")
}

#[test]
fn text_round_trips() {
    let (c, i, s) = table!("text");
    round_trip("pg_text_round_trip", c, i, s, gen_text, |a, b| a == b);
}

#[test]
fn varchar_round_trips() {
    let (c, i, s) = table!("varchar");
    round_trip("pg_varchar_round_trip", c, i, s, gen_text, |a, b| a == b);
}

#[test]
fn bytea_round_trips() {
    let (c, i, s) = table!("bytea");
    round_trip(
        "pg_bytea_round_trip",
        c,
        i,
        s,
        |g| {
            let len = if g.weighted(&[9, 1]) == 0 {
                0..=64
            } else {
                0..=100_000
            };
            g.bytes(len)
        },
        |a, b| a == b,
    );
}

#[test]
fn uuid_round_trips() {
    let (c, i, s) = table!("uuid");
    round_trip(
        "pg_uuid_round_trip",
        c,
        i,
        s,
        |g| Uuid::from_bytes(g.bytes(16..=16).try_into().unwrap()),
        |a, b| a == b,
    );
}

fn gen_timestamp(g: &mut Gen) -> Timestamptz {
    let micros = match g.weighted(&[1, 1, 1, 1, 6]) {
        0 => i64::MAX,
        1 => i64::MIN,
        2 => MIN_TIMESTAMP,
        3 => END_TIMESTAMP - 1,
        _ => g.i64_in(MIN_TIMESTAMP..=END_TIMESTAMP - 1),
    };
    Timestamptz::from_pg_micros(micros).unwrap()
}

#[test]
fn timestamptz_round_trips() {
    let (c, i, s) = table!("timestamptz");
    round_trip(
        "pg_timestamptz_round_trip",
        c,
        i,
        s,
        gen_timestamp,
        |a, b| a == b,
    );
}

fn gen_date(g: &mut Gen) -> Date {
    let days = match g.weighted(&[1, 1, 1, 1, 6]) {
        0 => i32::MAX,
        1 => i32::MIN,
        2 => MIN_DATE,
        3 => END_DATE - 1,
        _ => g.i32_in(MIN_DATE..=END_DATE - 1),
    };
    Date::from_pg_days(days).unwrap()
}

#[test]
fn date_round_trips() {
    let (c, i, s) = table!("date");
    round_trip("pg_date_round_trip", c, i, s, gen_date, |a, b| a == b);
}

fn digits(g: &mut Gen, max: usize) -> String {
    let n = g.usize_in(0..=max);
    (0..n).map(|_| char::from(b'0' + g.u8_in(0..=9))).collect()
}

fn gen_numeric(g: &mut Gen) -> Numeric {
    match g.weighted(&[1, 1, 1, 12, 2]) {
        0 => Numeric::nan(),
        1 => Numeric::infinity(false),
        2 => Numeric::infinity(true),
        k => {
            // Mostly short values; sometimes long ones. The server accepts
            // at most 3000 base-10000 digits in the binary format.
            let (imax, fmax) = if k == 3 { (40, 30) } else { (1000, 1000) };
            let int = digits(g, imax);
            let frac = digits(g, fmax);
            let sign = if g.bool() { "-" } else { "" };
            let text = if frac.is_empty() {
                format!("{sign}{}", if int.is_empty() { "0" } else { &int })
            } else {
                format!("{sign}{int}.{frac}")
            };
            Numeric::parse(&text).unwrap()
        }
    }
}

#[test]
fn numeric_round_trips_exactly() {
    let (c, i, s) = table!("numeric");
    round_trip("pg_numeric_round_trip", c, i, s, gen_numeric, |a, b| a == b);
}

/// A JSON number lexeme that jsonb keeps verbatim: no exponent and no
/// negative zero, since jsonb stores numbers as numeric.
fn gen_json_number(g: &mut Gen) -> Number {
    let int = g.u64_in(0..=u64::MAX).to_string();
    let lexeme = match g.u8_in(0..=2) {
        0 => int,
        1 => format!("{int}.{}", g.u32_in(0..=999_999)),
        _ => format!(
            "-{}{}",
            g.u64_in(1..=u64::MAX),
            if g.bool() { ".5" } else { "" }
        ),
    };
    Number::from_lexeme(&lexeme).unwrap()
}

fn gen_json(g: &mut Gen, depth: u32) -> Value {
    let kinds: &[u32] = if depth == 0 {
        &[1, 1, 1, 1, 0, 0]
    } else {
        &[1, 1, 2, 2, 1, 1]
    };
    match g.weighted(kinds) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => Value::Number(gen_json_number(g)),
        3 => Value::String(g.string(0..=16).replace('\0', "x")),
        4 => {
            let items: Vec<Value> = g.vec(0..=4, |g| gen_json(g, depth - 1));
            Value::Array(Array::from(items))
        }
        _ => {
            let mut obj = Object::new();
            for _ in 0..g.usize_in(0..=4) {
                let key = g.string(0..=8).replace('\0', "x");
                let v = gen_json(g, depth - 1);
                obj.insert(key, v);
            }
            Value::Object(obj)
        }
    }
}

#[test]
fn jsonb_round_trips() {
    let (c, i, s) = table!("jsonb");
    round_trip(
        "pg_jsonb_round_trip",
        c,
        i,
        s,
        |g| gen_json(g, 3),
        |a, b| a == b,
    );
}

#[test]
fn json_round_trips() {
    let (c, i, s) = table!("json");
    round_trip(
        "pg_json_round_trip",
        c,
        i,
        s,
        |g| gen_json(g, 3),
        |a, b| a == b,
    );
}

#[test]
fn text_with_nul_is_refused_before_sending() {
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    let err = block_on(c.query("SELECT $1::text", &[&"a\0b"])).unwrap_err();
    assert_eq!(err.kind(), fstp_pgwire::ErrorKind::Encode);
    let ok: String = block_on(c.query_one("SELECT $1::text", &[&"a\u{1F600}b"]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(ok, "a\u{1F600}b");
}

#[test]
fn server_text_values_decode_as_expected() {
    // Values produced by the server's own input functions decode to the
    // same values as the client's constructors.
    let (_db, cfg) = fresh();
    let mut c = connect(&cfg);
    block_on(async {
        let row = c
            .query_one(
                "SELECT '2026-10-24 12:34:56.789012+00'::timestamptz, '2026-10-24'::date, \
                 'infinity'::timestamptz, '-infinity'::date, '4713-11-24 BC'::date, \
                 '-12345.67800'::numeric, 'NaN'::numeric, '-Infinity'::numeric, \
                 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid, '{\"b\": [1, 2.50], \"a\": null}'::jsonb",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            row.get::<Timestamptz>(0).unwrap(),
            Timestamptz::from_utc(2026, 10, 24, 12, 34, 56, 789_012).unwrap()
        );
        assert_eq!(
            row.get::<Date>(1).unwrap(),
            Date::from_ymd(2026, 10, 24).unwrap()
        );
        assert_eq!(row.get::<Timestamptz>(2).unwrap(), Timestamptz::INFINITY);
        assert_eq!(row.get::<Date>(3).unwrap(), Date::NEG_INFINITY);
        assert_eq!(
            row.get::<Date>(4).unwrap(),
            Date::from_ymd(-4712, 11, 24).unwrap()
        );
        assert_eq!(row.get::<Numeric>(5).unwrap().as_str(), "-12345.67800");
        assert!(row.get::<Numeric>(6).unwrap().is_nan());
        assert_eq!(row.get::<Numeric>(7).unwrap().as_str(), "-Infinity");
        assert_eq!(
            row.get::<Uuid>(8).unwrap().to_string(),
            "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
        );
        assert_eq!(
            row.get::<Value>(9).unwrap(),
            fstp_json::parse(br#"{"a": null, "b": [1, 2.50]}"#).unwrap()
        );
    });
}
