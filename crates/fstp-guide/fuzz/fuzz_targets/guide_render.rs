//! Fuzz target `guide_render` of `fstp-guide` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics over arbitrary bindings; output passes the fstp-html well-formedness check.
//!
//! The target checks, over arbitrary bytes taken as a template:
//!
//! - parsing and rendering never panic, and rendering one template twice
//!   gives the same result, so the Guide digest is a function of its
//!   inputs (I-52);
//! - a template with placeholders is never rendered unbound: the refusal
//!   names its first placeholder, which stands in the input (I-51);
//! - a template with no placeholder renders, its HTML passes the
//!   `fstp-html` well-formedness check through
//!   `RenderedGuide::check_wellformed`, and it binds no text.
//!
//! Seam, reported to the lead: arbitrary bindings need a compiled draft,
//! so this fuzz project needs an `fstp-programme` edge in its
//! `Cargo.toml`, which the lead owns. Until then the property test
//! `i68_arbitrary_bound_text_renders_wellformed_and_verbatim` covers
//! arbitrary bound text.

#![no_main]

use fstp_guide::GuideError;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(t) = fstp_guide::parse_template(data) else {
        return;
    };
    let first = fstp_guide::render(&t);
    let again = fstp_guide::render(&t);
    assert_eq!(first, again, "render is not deterministic");
    let keys = t.placeholders();
    match (keys.first(), first) {
        (Some(key), Err(GuideError::Unresolved { key: named, .. })) => {
            assert_eq!(named.as_str(), *key, "the refusal names another key");
            let text = std::str::from_utf8(data).expect("an accepted template is UTF-8");
            assert!(
                text.contains(&format!("{{{{{key}}}}}")),
                "the refused key {key:?} does not stand in the input"
            );
        }
        (Some(key), other) => panic!("the unbound placeholder {key:?} gave {other:?}"),
        (None, Ok(r)) => {
            if let Err(e) = r.check_wellformed() {
                panic!("the rendered Guide is not well-formed: {e}");
            }
            assert!(
                r.bound().is_empty(),
                "a template with no placeholder bound text"
            );
            assert!(!r.canonical().is_empty(), "the canonical document is empty");
        }
        (None, Err(e)) => panic!("a template with no placeholder was refused: {e}"),
    }
});
