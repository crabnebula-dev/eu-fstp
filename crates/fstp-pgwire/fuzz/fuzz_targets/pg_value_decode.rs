//! TH-26, H-05: `FromSql` for every supported type on arbitrary bytes.
//!
//! Properties beyond "no panic":
//!
//! - every accepted value of a type with a canonical binary form
//!   re-encodes to the same bytes;
//! - `numeric`, `json` and `jsonb` values re-encode to bytes that decode to
//!   the same value;
//! - NULL is accepted only through `Option`.
//!
//! See `harness::value_decode`.

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::value_decode(data);
});
