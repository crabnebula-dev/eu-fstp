//! Fuzz target `s3_xml_decode` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; DTDs, entities and processing instructions
//! refused (ADR-012 "S3 subset", record of lane L10). An accepted body
//! holds no `<!` at all and no `<?` after offset 0, has one root at
//! depth 1, no element deeper than 4 and at most 64 elements. The shape
//! decoders never panic either.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_backup::decode_s3_xml(data) {
        Ok(r) => {
            let text = std::str::from_utf8(data).unwrap();
            assert!(!text.contains("<!"));
            assert!(text.match_indices("<?").all(|(i, _)| i == 0));
            assert!(!r.elements.is_empty() && r.elements.len() <= 64);
            assert_eq!(r.elements[0].depth, 1);
            assert_eq!(r.elements.iter().filter(|e| e.depth == 1).count(), 1);
            assert!(r.elements.iter().all(|e| (1..=4).contains(&e.depth)));
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
    let _ = fstp_backup::xml::create_upload_id(data);
    let _ = fstp_backup::xml::complete_result(data);
    let _ = fstp_backup::xml::error_code(data);
});
