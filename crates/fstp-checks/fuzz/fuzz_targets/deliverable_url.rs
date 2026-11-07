//! M5 design section 11, TH-26: the deliverable URL parser never panics,
//! a parsed URL renders to a form that parses to the same URL, and a
//! licence file URL stays inside the subset.
#![no_main]

use fstp_checks::url::DeliverableUrl;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let (url, release) = s.split_once('\n').unwrap_or((s, "v1.0.0"));
    if let Ok(u) = DeliverableUrl::parse(url) {
        assert_eq!(DeliverableUrl::parse(&u.to_string()).as_ref(), Ok(&u));
        if let Ok(l) = u.licence_file(release) {
            assert_eq!(DeliverableUrl::parse(&l.to_string()).as_ref(), Ok(&l));
            assert_eq!(l.host(), u.host());
        }
    }
});
