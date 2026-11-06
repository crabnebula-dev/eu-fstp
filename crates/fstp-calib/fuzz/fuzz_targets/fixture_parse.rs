//! Fuzz target `fixture_parse` of `fstp-calib` (TH-26, M12 lane
//! L12-METRICS).
//!
//! The reader must return a typed result without panicking. An accepted
//! fixture must compute and render without panicking, every report line
//! after the header must name the fixture's corpus, and the report must
//! be the same on a second run.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(d) = fstp_calib::parse(data) else {
        return;
    };
    let label = d.corpus.name();
    let again = d.clone();
    if let Ok(r) = fstp_calib::report(vec![d]) {
        assert!(r.lines().skip(1).all(|l| l.starts_with(label)));
        assert_eq!(fstp_calib::report(vec![again]).ok(), Some(r));
    }
});
