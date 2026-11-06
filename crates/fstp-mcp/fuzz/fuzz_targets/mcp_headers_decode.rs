//! Fuzz target `mcp_headers_decode` of `fstp-mcp` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: transport headers, and the `Origin` rule of design
//! section 3.8. The input, split at line feeds, is the list of `Origin`
//! values of one request. No input panics. An accepted check saw either
//! no `Origin` at all, or exactly one value equal to the tenant origin.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The one tenant origin of the target.
const TENANT: &str = "https://tenant.fstp.test";

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_mcp::decode_headers(data));
    assert!(!shown.is_empty());
    let values: Vec<&[u8]> = if data.is_empty() {
        Vec::new()
    } else {
        data.split(|b| *b == b'\n').collect()
    };
    let tenant = [TENANT.to_owned()];
    match fstp_mcp::check_origin(&values, &tenant) {
        Ok(fstp_mcp::OriginSeen::Absent) => assert!(values.is_empty()),
        Ok(fstp_mcp::OriginSeen::Tenant) => {
            assert_eq!(values.len(), 1);
            assert_eq!(values.first().copied(), Some(TENANT.as_bytes()));
        }
        Err(e) => assert!(!format!("{e:?}").is_empty()),
    }
});
