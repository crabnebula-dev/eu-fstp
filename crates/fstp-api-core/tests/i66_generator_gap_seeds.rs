//! The seeds of the `api_request_decode` fuzz target for the narrative
//! edit and the import removal reach their decoders (TH-26; Daniel,
//! 2026-11-15, the I-66 generator gaps).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fstp_api_core::decode::decode_request;

/// I-66, TH-26: each seed decodes to its operation, and a body with an
/// unknown member or no revision is refused before any operation runs.
#[test]
fn i66_narrative_edit_and_import_removal_seeds_decode_to_their_operations() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/api_request_decode");
    for (file, op) in [
        ("creator_edit_narrative", "creator.edit_narrative"),
        ("import_remove", "import.remove"),
    ] {
        let bytes = std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let decoded = decode_request(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        assert_eq!(decoded.name(), op, "{file}");
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replace("{\"base\"", "{\"x\":1,\"base\""),
            text.replace("\"base\":\"3.41\"", "\"base\":\"03.41\""),
        ] {
            assert!(decode_request(bad.as_bytes()).is_err(), "{file}: {bad}");
        }
    }
}
