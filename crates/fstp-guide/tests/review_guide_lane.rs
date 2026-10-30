//! Review reproducers for lane m4guide (W2c, M4 design section 3.10).
//!
//! The lane must build `parse_markdown`, `parse_template` and `render`.
//! The review found the W0 stubs, which refused every input with
//! `GuideError::NotImplemented`. Each test below failed until the parser
//! and renderer existed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_guide::{HORIZON_EUROPE, ProfileSource, ShippedProfiles};

/// The shipped Horizon Europe template, as the profile source supplies it.
fn shipped() -> String {
    ShippedProfiles
        .profile(HORIZON_EUROPE)
        .unwrap()
        .guide_template()
        .to_owned()
}

/// R-GA-01: the shipped template parses.
#[test]
fn review_lane_shipped_template_parses() {
    let parsed = fstp_guide::parse_template(shipped().as_bytes());
    assert!(
        parsed.is_ok(),
        "R-GA-01: the shipped template does not parse: {parsed:?}"
    );
}

/// R-GA-01, I-51: the shipped template renders once it is bound to a
/// synthetic draft. Corrected in fix round 1, because the first version
/// rendered the unbound template. I-51 ("Every parameter value in the
/// Guide equals the frozen call policy") and the lane scope ("every
/// placeholder resolves or is refused by name") require a refusal by key.
#[test]
fn review_lane_shipped_template_renders() {
    let t = match fstp_guide::parse_template(shipped().as_bytes()) {
        Ok(t) => t,
        Err(e) => panic!("R-GA-01: the shipped template does not parse: {e}"),
    };
    match fstp_guide::render(&t) {
        Err(e) => assert!(
            e.to_string().contains("programme.name"),
            "I-51: the unbound render is not refused by its first key: {e}"
        ),
        Ok(_) => panic!("I-51: an unbound template rendered"),
    }
    let inputs = support::supersafe_inputs().unwrap();
    let rendered = support::guide_from(shipped().as_bytes(), &inputs);
    assert!(
        rendered.is_ok(),
        "R-GA-01: the shipped template does not render: {rendered:?}"
    );
}

/// TH-26: a heading, a construct of the subset, is accepted.
#[test]
fn review_lane_markdown_subset_heading_accepted() {
    let parsed = fstp_guide::parse_markdown(b"# Guide for Applicants\n");
    assert!(
        parsed.is_ok(),
        "TH-26: a level 1 heading is refused: {parsed:?}"
    );
}

/// I-51: an unknown placeholder is refused, and the refusal names its key.
#[test]
fn review_lane_unknown_placeholder_refused_by_name() {
    match fstp_guide::parse_template(b"Call {{no.such.key}} opens.\n") {
        Ok(_) => panic!("I-51: an unknown placeholder was accepted"),
        Err(e) => assert!(
            e.to_string().contains("no.such.key"),
            "I-51: the refusal does not name the unknown key: {e}"
        ),
    }
}
