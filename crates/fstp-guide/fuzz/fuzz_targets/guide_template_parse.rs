//! Fuzz target `guide_template_parse` of `fstp-guide` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: unknown placeholders rejected; template round trip.
//!
//! The target checks, over arbitrary bytes:
//!
//! - `parse_template` never panics, and two parses give the same result;
//! - an accepted template is UTF-8, every `{{` in it is closed by `}}`,
//!   every placeholder key has a row in `fstp_guide::RESOLVERS`, and
//!   `Template::placeholders` lists exactly those keys in order (I-51:
//!   one resolver per placeholder, unknown keys refused);
//! - an accepted template round-trips: parsing `Template::to_markdown`
//!   gives an equal template, whose spelling is the same again;
//! - a refusal of an unknown placeholder names a key that stands as
//!   `{{key}}` in the input.

#![no_main]

use fstp_guide::{GuideError, RESOLVERS};
use libfuzzer_sys::fuzz_target;

/// The keys between `{{` and `}}` in `text`, or `None` when a `{{` is
/// not closed.
fn keys(text: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let end = after.find("}}")?;
        out.push(&after[..end]);
        rest = &after[end + 2..];
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let first = fstp_guide::parse_template(data);
    let again = fstp_guide::parse_template(data);
    assert_eq!(first, again, "parse_template is not deterministic");
    match first {
        Ok(t) => {
            let text = std::str::from_utf8(data).expect("an accepted template is UTF-8");
            let found = keys(text).expect("an accepted template closes every placeholder");
            for key in &found {
                assert!(
                    RESOLVERS.iter().any(|r| r.key == *key),
                    "accepted the unknown placeholder {key:?}"
                );
            }
            assert_eq!(
                t.placeholders(),
                found,
                "the placeholders differ from the input"
            );
            let spelled = t.to_markdown();
            let back = fstp_guide::parse_template(spelled.as_bytes())
                .expect("the canonical spelling of a template parses");
            assert_eq!(back, t, "the template does not round-trip");
            assert_eq!(
                back.to_markdown(),
                spelled,
                "the canonical spelling is not stable"
            );
        }
        Err(GuideError::UnknownPlaceholder(key)) => {
            let text = std::str::from_utf8(data).expect("a key was read, so the input is UTF-8");
            let slot = format!("{{{{{}}}}}", key.as_str());
            assert!(
                text.contains(&slot),
                "refused the key {key:?}, which does not stand in the input"
            );
            assert!(
                !RESOLVERS.iter().any(|r| r.key == key.as_str()),
                "refused the known key {key:?} as unknown"
            );
        }
        Err(_) => {}
    }
});
