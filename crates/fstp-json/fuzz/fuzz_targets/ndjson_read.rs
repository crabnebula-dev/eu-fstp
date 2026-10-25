//! Fuzz target for the NDJSON reader (TH-26, H-05).
//!
//! Checks, for any input:
//! - reading never panics and stops at the first error;
//! - every line before the error yields exactly one value, so an error on
//!   line N follows N - 1 values;
//! - the result does not depend on how the input is chunked by the
//!   underlying reader;
//! - values written back with the writer read back identically.

#![no_main]

use std::io::BufReader;

use fstp_json::{NdjsonOptions, NdjsonReader, NdjsonWriter, Value};
use libfuzzer_sys::fuzz_target;

type Outcome = (Vec<Value>, Option<(u64, String)>);

fn read(reader: impl std::io::BufRead, options: NdjsonOptions) -> Outcome {
    let mut values = Vec::new();
    let mut ndjson = NdjsonReader::with_options(reader, options);
    while let Some(item) = ndjson.next_value() {
        match item {
            Ok(v) => values.push(v),
            Err(e) => {
                assert!(
                    ndjson.next_value().is_none(),
                    "reader continued after an error"
                );
                return (values, Some((e.line(), format!("{:?}", e.kind()))));
            }
        }
    }
    (values, None)
}

fn same(a: &Outcome, b: &Outcome) -> bool {
    a.1 == b.1 && a.0.len() == b.0.len() && a.0.iter().zip(&b.0).all(|(x, y)| x.identical(y))
}

fuzz_target!(|data: &[u8]| {
    let options = NdjsonOptions {
        max_line_bytes: 300,
        ..NdjsonOptions::default()
    };
    let whole = read(data, options);
    if let Some((line, _)) = &whole.1 {
        assert_eq!(
            *line,
            whole.0.len() as u64 + 1,
            "values before the error line"
        );
    }

    let capacity = 1 + usize::from(data.first().copied().unwrap_or(0) % 13);
    let chunked = read(BufReader::with_capacity(capacity, data), options);
    assert!(same(&whole, &chunked), "chunking changed the result");

    let mut writer = NdjsonWriter::new(Vec::new());
    for v in &whole.0 {
        writer.write_value(v).expect("writing to a vector");
    }
    let out = writer.into_inner();
    let unlimited = NdjsonOptions {
        max_line_bytes: usize::MAX,
        ..NdjsonOptions::default()
    };
    let again = read(&out[..], unlimited);
    assert!(again.1.is_none(), "written output failed to read");
    assert!(
        same(&(whole.0, None), &again),
        "write then read changed values"
    );
});
