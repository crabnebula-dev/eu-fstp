//! The branding seeds of the `api_request_decode` fuzz target reach the
//! branding decoder (TH-26, I-68, M9 lane B1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fstp_api_core::decode::decode_request;

/// I-68, TH-26: each branding seed decodes to its operation, and a body
/// whose tokens carry markup is refused before any operation runs.
#[test]
fn i68_branding_fuzz_seeds_decode_to_their_operations() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/api_request_decode");
    for (file, op) in [
        ("tenant_branding_check", "tenant.branding.check"),
        ("tenant_branding_set", "tenant.branding.set"),
    ] {
        let bytes = std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let decoded = decode_request(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        assert_eq!(decoded.name(), op, "{file}");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Harbour Fund"));
        for bad in [
            text.replace("Harbour Fund", "<script>x</script>"),
            text.replace("#1e40af", "url(x)"),
            text.replace("\"system\"", "\"serif\""),
            text.replace("{\"tokens\"", "{\"css\":\"a\",\"tokens\""),
        ] {
            assert!(decode_request(bad.as_bytes()).is_err(), "{file}: {bad}");
        }
    }
}
