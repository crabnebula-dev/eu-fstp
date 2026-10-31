//! Fuzz target `import_record_decode` of `fstp-import` (TH-26, H-05, I-23,
//! M4 design section 9).
//!
//! Stored records never panic the decoder. An accepted record round
//! trips: its canonical text decodes to the same record and encodes to the
//! same text. Folding it into an empty store never panics, and only a
//! registration folds there.

#![no_main]

use fstp_import::{ImportRecord, ImportStore, decode_record, encode_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(r) = decode_record(data) else {
        return;
    };
    let text = encode_record(&r);
    let back = decode_record(text.as_bytes());
    assert_eq!(back.as_ref(), Ok(&r));
    if let Ok(back) = back {
        assert_eq!(encode_record(&back), text);
    }
    let mut store = ImportStore::genesis();
    let folded = store.apply(&r);
    assert_eq!(
        folded.is_ok(),
        matches!(r, ImportRecord::DocumentRegistered(_))
    );
});
