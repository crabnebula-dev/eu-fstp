//! The decode oracle shared by the `fstp-domain` fuzz targets (TH-26, H-05,
//! design section 7).
//!
//! For any input that parses as JSON:
//!
//! - decoding never panics, and a refusal formats without panicking;
//! - an accepted value encodes to JSON with an RFC 8785 form;
//! - decode, encode, decode gives the same value;
//! - the canonical bytes are the same after a second round trip;
//! - when the input bytes are canonical, the encoding has the same bytes,
//!   so the decoder accepts one spelling per value (ADR-006, ADR-007);
//! - the encoding is an object, and an unknown member added to any object
//!   in it is refused (design section 5.1).
//!
//! The codec is the `ToJson` and `FromJson` impls of the decoded type.
//! [`codec_for!`] finds them by method resolution on the concrete type.
//! Until lane L-CODEC lands them, the probe reports a missing codec and the
//! oracle only runs the JSON parser and canonical writer, as the W0 stub did.

#![allow(
    dead_code,
    reason = "the probe keeps one of `Present` and `Absent` unused, by design"
)]

use std::fmt::Debug;
use std::marker::PhantomData;

use fstp_json::{FromJson, FromJsonError, ToJson, Value, parse, to_canonical};

/// The marker for a type that has no codec yet.
pub struct Missing;

/// A zero-sized handle on the codec of `T`.
pub struct Probe<T>(PhantomData<T>);

impl<T> Probe<T> {
    /// The probe for `T`.
    pub const fn new() -> Probe<T> {
        Probe(PhantomData)
    }
}

/// The real codec, preferred when `T` has both impls.
pub trait Present {
    /// The value type.
    type Item;
    /// Encodes through `ToJson`.
    fn encode_item(&self, t: &Self::Item) -> Result<Value, Missing>;
    /// Decodes through `FromJson`.
    fn decode_item(&self, v: &Value) -> Result<Result<Self::Item, FromJsonError>, Missing>;
}

impl<T: ToJson + FromJson> Present for Probe<T> {
    type Item = T;
    fn encode_item(&self, t: &T) -> Result<Value, Missing> {
        Ok(t.to_json())
    }
    fn decode_item(&self, v: &Value) -> Result<Result<T, FromJsonError>, Missing> {
        Ok(T::from_json(v))
    }
}

/// The fallback when `T` lacks `ToJson` or `FromJson`.
pub trait Absent {
    /// The value type.
    type Item;
    /// Always reports a missing codec.
    fn encode_item(&self, t: &Self::Item) -> Result<Value, Missing>;
    /// Always reports a missing codec.
    fn decode_item(&self, v: &Value) -> Result<Result<Self::Item, FromJsonError>, Missing>;
}

impl<T> Absent for &Probe<T> {
    type Item = T;
    fn encode_item(&self, _t: &T) -> Result<Value, Missing> {
        Err(Missing)
    }
    fn decode_item(&self, _v: &Value) -> Result<Result<T, FromJsonError>, Missing> {
        Err(Missing)
    }
}

/// The codec of one type, as two function pointers chosen by [`codec_for!`].
pub struct Codec<T> {
    /// The encoder.
    pub enc: fn(&T) -> Result<Value, Missing>,
    /// The decoder.
    pub dec: fn(&Value) -> Result<Result<T, FromJsonError>, Missing>,
}

/// The codec of a concrete type.
#[allow(
    unused_macros,
    reason = "record_decode builds its codec from the schema-aware entry point"
)]
macro_rules! codec_for {
    ($t:ty) => {{
        #[allow(unused_imports)]
        use crate::common::{Absent as _, Present as _};
        crate::common::Codec::<$t> {
            enc: |t| (&crate::common::Probe::<$t>::new()).encode_item(t),
            dec: |v| (&crate::common::Probe::<$t>::new()).decode_item(v),
        }
    }};
}
#[allow(
    unused_imports,
    reason = "record_decode builds its codec from the schema-aware entry point"
)]
pub(crate) use codec_for;

/// A member name that no schema defines and no map key can parse as.
const UNKNOWN: &str = "zz-unknown-member";

/// The result of running the oracle on one input.
pub enum Outcome<T> {
    /// The input is not JSON, or the codec refused it.
    Refused,
    /// The codec is not implemented yet.
    NoCodec,
    /// The codec accepted the input, and every check passed.
    Accepted(T),
}

/// Runs the decode oracle on `data`. Panics on any broken check.
pub fn oracle<T: PartialEq + Debug>(codec: &Codec<T>, data: &[u8]) -> Outcome<T> {
    let Ok(input) = parse(data) else {
        return Outcome::Refused;
    };
    let decoded = match (codec.dec)(&input) {
        Err(Missing) => {
            let _ = to_canonical(&input);
            return Outcome::NoCodec;
        }
        Ok(Err(e)) => {
            let _ = e.to_string();
            let _ = format!("{e:?}");
            let _ = e.path().full();
            return Outcome::Refused;
        }
        Ok(Ok(t)) => t,
    };

    let encode = |t: &T| -> Value {
        match (codec.enc)(t) {
            Ok(v) => v,
            Err(Missing) => panic!("the decoder exists but the encoder does not"),
        }
    };
    let decode = |v: &Value| -> Result<T, FromJsonError> {
        match (codec.dec)(v) {
            Ok(r) => r,
            Err(Missing) => panic!("the decoder vanished"),
        }
    };

    // Round trip through canonical text.
    let encoded = encode(&decoded);
    let text = to_canonical(&encoded).expect("a decoded value encodes with an RFC 8785 form");
    let reparsed = parse(text.as_bytes()).expect("canonical text parses");
    let again = decode(&reparsed).expect("the canonical encoding decodes");
    assert_eq!(
        again, decoded,
        "decode, encode, decode gives the same value"
    );
    let text2 = to_canonical(&encode(&again)).expect("the value encodes again");
    assert_eq!(text2, text, "canonical bytes are stable");

    // One spelling per value.
    if let Ok(input_text) = to_canonical(&input)
        && input_text.as_bytes() == data
    {
        assert_eq!(
            text.as_bytes(),
            data,
            "a canonical input encodes to the same bytes"
        );
    }

    // Unknown members are refused at every object.
    assert!(
        encoded.as_object().is_some(),
        "the top-level encoding is an object"
    );
    for path in object_paths(&encoded) {
        let mut m = encoded.clone();
        if let Some(o) = get_at_mut(&mut m, &path).and_then(Value::as_object_mut) {
            o.insert(UNKNOWN, Value::Null);
        }
        assert!(
            decode(&m).is_err(),
            "an unknown member at {path:?} was accepted"
        );
    }

    Outcome::Accepted(decoded)
}

/// One step from a JSON value to a child.
#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn object_paths(v: &Value) -> Vec<Vec<Step>> {
    fn walk(v: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
        match v {
            Value::Object(o) => {
                out.push(path.clone());
                for (k, c) in o.iter() {
                    path.push(Step::Key(k.to_owned()));
                    walk(c, path, out);
                    path.pop();
                }
            }
            Value::Array(a) => {
                for (i, c) in a.iter().enumerate() {
                    path.push(Step::Index(i));
                    walk(c, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut out);
    out
}

fn get_at_mut<'a>(v: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    let mut cur = v;
    for s in path {
        cur = match (cur, s) {
            (Value::Object(o), Step::Key(k)) => o.get_mut(k)?,
            (Value::Array(a), Step::Index(i)) => a.get_mut(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}
