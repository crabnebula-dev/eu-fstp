//! Fuzz target `validate_total` of `fstp-creator` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: validate is total over arbitrary drafts and inputs. A
//! decoded draft history folds and validates without a panic, and every
//! report row names a check of the catalogue with its severity.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = fstp_creator::decode_draft(data) else {
        return;
    };
    for report in fstp_creator::validate_draft(&input) {
        for row in report.results() {
            assert_eq!(row.severity, row.check.severity());
        }
    }
});
