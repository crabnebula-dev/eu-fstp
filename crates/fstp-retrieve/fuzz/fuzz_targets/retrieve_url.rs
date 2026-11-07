//! TH-12: the URL parser, the reference resolver, the destination policy,
//! source classing and the query decoder against arbitrary input.
//!
//! Properties checked beyond "no panic":
//!
//! - the canonical form parses to itself;
//! - an admitted host is a dotted name under `.test`, never an IP literal;
//! - a URL is applicant-controlled under its own claim;
//! - the query built for a URL decodes back to it.

#![no_main]

use fstp_retrieve::{
    ApplicantSources, DestinationPolicy, SourceClass, SourceUrl, query_for, url_param,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let (a, b) = s.split_once('\n').unwrap_or((&s, ""));
    let _ = url_param(a);
    let Ok(u) = SourceUrl::parse(a) else {
        return;
    };
    let again = SourceUrl::parse(u.as_str()).expect("canonical form parses");
    assert_eq!(again, u, "canonical form is not stable");
    let policy = DestinationPolicy::fixture();
    if policy.check(&u).is_ok() {
        let h = u.host();
        assert!(h.ends_with(".test") && h.len() > 5, "admitted {h:?}");
        assert!(!h.starts_with('['), "admitted an IPv6 literal");
    }
    let mut claimed = ApplicantSources::new();
    claimed.add(&u);
    assert_eq!(claimed.classify(&u), SourceClass::ApplicantControlled);
    assert_eq!(url_param(&query_for(&u)).as_deref(), Some(u.as_str()));
    if let Ok(j) = u.join(b) {
        let _ = policy.check(&j);
        let _ = claimed.classify(&j);
        assert_eq!(SourceUrl::parse(j.as_str()).ok(), Some(j));
    }
});
