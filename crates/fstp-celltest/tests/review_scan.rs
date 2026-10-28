//! Review reproducers for the W1a canary scanner (design section 14.1).
//! Each test seeds one canary in a store shape the lane tests do not use
//! and requires `scan` to find it. Written by the independent reviewer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{StoreSet, scan};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

/// Design section 14.1 (base64 and JSON string escaping): a PEM or MIME
/// body wrapped at 64 characters and stored in a JSON string carries its
/// line breaks as `\n` escapes. A canary whose base64 crosses a line break
/// is still found.
#[test]
fn review_scan_finds_line_wrapped_base64_inside_json() {
    let canary = Canary::generate(1, CanaryKind::Document).unwrap();
    // 30 bytes of context put the canary's base64 at characters 40 to 100,
    // across the line break after character 64.
    let mut doc = b"synthetic-document-header-0123".to_vec();
    doc.extend_from_slice(canary.text().as_bytes());
    doc.extend_from_slice(b"-synthetic-document-trailer");
    let b64 = base64(&doc);
    let mut json = b"{\"body\":\"".to_vec();
    for line in b64.chunks(64) {
        json.extend_from_slice(line);
        json.extend_from_slice(b"\\n");
    }
    json.extend_from_slice(b"\"}");
    let mut set = StoreSet::default();
    set.push("review", json);
    let report = scan(&set, std::slice::from_ref(&canary)).unwrap();
    assert!(
        !report.is_clean(),
        "line-wrapped base64 inside JSON was missed"
    );
}
