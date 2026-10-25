//! Fuzz target for typed mapping with `json_struct!` (TH-26, H-05).
//!
//! Parses the input, then maps it to a sample record and to a few standard
//! types. Checks, for any input:
//! - mapping never panics, and error paths render;
//! - a value that maps converts back with `ToJson` to a value that maps to
//!   the same record, and that conversion is stable;
//! - a raw identifier field reads and writes the name without `r#`.

#![no_main]

use std::collections::BTreeMap;

use fstp_json::{Decimal, FromJson, ToJson, Value, json_struct, parse};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq)]
struct Call {
    id: u64,
    title: String,
    deadline: Option<String>,
    budget: Option<Decimal>,
    tags: Vec<String>,
    scores: BTreeMap<String, i32>,
    open: Option<bool>,
    children: Option<Vec<Call>>,
    r#type: Option<String>,
}

json_struct!(Call {
    required id,
    required title = "name",
    optional deadline,
    optional budget,
    required tags,
    required scores,
    required open,
    optional children,
    optional r#type,
});

fn check<T: FromJson + ToJson + PartialEq + std::fmt::Debug>(v: &Value) {
    match T::from_json(v) {
        Ok(t) => {
            let w = t.to_json();
            let again = T::from_json(&w).expect("ToJson output maps back");
            assert_eq!(again, t);
            assert!(again.to_json().identical(&w), "ToJson is not stable");
        }
        Err(e) => {
            let _ = e.to_string();
            let _ = e.path().full();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    check::<Call>(&v);
    if let Ok(call) = Call::from_json(&v) {
        let w = call.to_json();
        assert!(w.get("r#type").is_none(), "raw identifier prefix in output");
        assert_eq!(w.get("type"), v.get("type").filter(|t| !t.is_null()));
    }
    check::<Vec<Call>>(&v);
    check::<Vec<Option<i64>>>(&v);
    check::<BTreeMap<String, u8>>(&v);
    check::<Option<Vec<u128>>>(&v);
    check::<String>(&v);
    check::<Decimal>(&v);
    check::<i8>(&v);
    check::<bool>(&v);
    check::<Value>(&v);
});
