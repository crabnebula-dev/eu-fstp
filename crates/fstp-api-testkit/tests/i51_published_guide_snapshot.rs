//! The Guide of a published call reads the publication, never a live
//! value (I-51, I-53, R-GA-01, R-LA-08; P-05 and P-13 NOTE 7; M4 design
//! section 3.10).
//!
//! The world comes from `fstp_api_testkit::mc::public_model::guide_world`:
//! the compiled SuperSAFE policy, call 1 published through production
//! commands, then a live edit that raises P-05 and P-58 from `400000.00`
//! to `450000.00`. `fstp_public::published_guide` binds the shipped
//! Horizon Europe template over the same compiled spec before and after
//! the edit. Every value is synthetic.
//!
//! Status: red. The W0 stub of `published_guide` refuses with
//! `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;

use fstp_api_testkit::mc::public_model::{
    EDITED_P05, GUIDE_CALL, GuideWorld, UNPUBLISHED_CALL, guide_world,
};
use fstp_domain::State;
use fstp_guide::{HORIZON_EUROPE, NoStoredTexts, ProfileSource, ShippedProfiles, Template};
use fstp_programme::Compiled;
use fstp_public::{GuideSource, PublicError, PublicGuide, published_guide};

/// The synthetic data protection summary. Not a privacy notice.
const SUMMARY: &str = "Synthetic data protection summary for tests. It is not a privacy notice.";
/// The synthetic privacy statement address.
const PRIVACY: &str = "https://privacy.fstp.example/statement";

fn world() -> &'static GuideWorld {
    static W: OnceLock<GuideWorld> = OnceLock::new();
    W.get_or_init(|| guide_world().unwrap_or_else(|e| panic!("the Guide world: {e}")))
}

/// The shipped Horizon Europe template.
fn template() -> Template {
    let profile = ShippedProfiles
        .profile(HORIZON_EUROPE)
        .unwrap_or_else(|e| panic!("profile: {e:?}"));
    fstp_guide::parse_template(profile.guide_template().as_bytes())
        .unwrap_or_else(|e| panic!("template: {e}"))
}

/// The Guide of `call` in `core`, bound over `compiled`.
fn guide(
    core: &State,
    call: fstp_domain::id::CallId,
    compiled: &Compiled,
) -> Result<PublicGuide, PublicError> {
    let t = template();
    let id = call.raw().to_string();
    let source = GuideSource {
        template: &t,
        compiled,
        identifier: &id,
        platform_url: "https://a.fstp.example/",
        data_protection_summary: Some(SUMMARY),
        privacy_statement_url: Some(PRIVACY),
        texts: &NoStoredTexts,
    };
    published_guide(core, call, &source)
}

/// I-51, I-53, NOTE 7: a live edit of P-05 after publication leaves the
/// Guide bytes of the published call unchanged.
#[test]
fn i51_live_p05_edit_leaves_the_guide_bytes_unchanged() {
    let w = world();
    let before = guide(&w.published, GUIDE_CALL, &w.compiled).unwrap_or_else(|e| panic!("{e}"));
    let after = guide(&w.edited, GUIDE_CALL, &w.compiled).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(before.document.as_bytes(), after.document.as_bytes());
}

/// I-51, NOTE 7: the Guide shows P-05 from the publication snapshot,
/// `400000.00`, and never the live value after the edit.
#[test]
fn i51_guide_shows_p05_from_the_publication_snapshot() {
    let w = world();
    let g = guide(&w.edited, GUIDE_CALL, &w.compiled).unwrap_or_else(|e| panic!("{e}"));
    let html = g.document.as_str();
    assert!(html.contains("400000.00"), "{html}");
    assert!(
        !html.contains(EDITED_P05),
        "the live P-05 reached the Guide"
    );
}

/// I-51, R-GA-01: the Guide shows the call's frozen P-04, not a later
/// draft value. The compiled spec here holds P-04 `1234.00` to
/// `5678.00`, as a draft edited after publication would.
#[test]
fn i51_guide_shows_the_frozen_call_values() {
    let w = world();
    let mut drifted = w.compiled.clone();
    let lo = fstp_domain_testkit::r#gen::policy::eur(123_400).unwrap();
    let hi = fstp_domain_testkit::r#gen::policy::eur(567_800).unwrap();
    drifted.policy.frozen.p04 = fstp_money::AmountRange::new(lo, hi).unwrap();
    let g = guide(&w.published, GUIDE_CALL, &drifted).unwrap_or_else(|e| panic!("{e}"));
    let html = g.document.as_str();
    assert!(
        html.contains("5000.00") && html.contains("100000.00"),
        "{html}"
    );
    assert!(
        !html.contains("5678.00"),
        "the drifted draft P-04 reached the Guide"
    );
}

/// R-GA-01: the Guide of a published call in M4 is version 1.
#[test]
fn r_ga_01_published_guide_is_version_1() {
    let w = world();
    let g = guide(&w.published, GUIDE_CALL, &w.compiled).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(g.version, 1);
}

/// R-LA-08: the Guide tells applicants that an AI system reviews drafts
/// at the pre-check and that AI findings never decide.
#[test]
fn r_la_08_guide_discloses_ai_assessment() {
    let w = world();
    let g = guide(&w.published, GUIDE_CALL, &w.compiled).unwrap_or_else(|e| panic!("{e}"));
    let html = g.document.as_str();
    assert!(html.contains("An AI system reviews your draft"), "{html}");
    assert!(
        html.contains("AI findings support reviewers but never decide"),
        "{html}"
    );
}

/// R-GA-01: a call that is not published has no Guide.
#[test]
fn r_ga_01_unpublished_call_has_no_guide() {
    let w = world();
    assert_eq!(
        guide(&w.published, UNPUBLISHED_CALL, &w.compiled).map(|_| ()),
        Err(PublicError::NotFound)
    );
}

/// `w.compiled` with the live parameter `param` set to the JSON `value`,
/// as a spec the creator edited after publication would carry it.
fn with_live(param: fstp_domain::rules::ParamId, value: &str) -> Compiled {
    let w = world();
    let mut edited = w.compiled.clone();
    let v = fstp_json::parse_str(value).unwrap();
    let old = edited.policy.live.opaque.insert(
        param,
        fstp_domain::policy::OpaqueValue::from_value(&v).unwrap(),
    );
    assert!(
        old.is_some(),
        "{param:?} is a live opaque parameter of the spec"
    );
    edited
}

/// The Guide bytes over `w.published` with the caller's spec `compiled`.
fn bytes_with(compiled: &Compiled) -> Vec<u8> {
    let w = world();
    let g = guide(&w.published, GUIDE_CALL, compiled).unwrap_or_else(|e| panic!("{e}"));
    g.document.as_bytes().to_vec()
}

/// I-51, I-53: the Guide over `w.published` and `w.compiled`, as bytes.
fn published_bytes() -> Vec<u8> {
    bytes_with(&world().compiled)
}

/// I-51, I-53: `{{P-36}}` is live and not in the publication snapshot.
/// A P-36 edit the caller's spec carries leaves the Guide bytes unchanged.
#[test]
fn i51_live_p36_edit_leaves_the_guide_bytes_unchanged() {
    let edited = with_live(fstp_domain::rules::ParamId::P36, r#"{"days":21}"#);
    assert_eq!(published_bytes(), bytes_with(&edited));
}

/// I-51, I-53: `{{P-41}}` is live and not in the publication snapshot.
/// A P-41 edit the caller's spec carries leaves the Guide bytes unchanged.
#[test]
fn i51_live_p41_edit_leaves_the_guide_bytes_unchanged() {
    let edited = with_live(fstp_domain::rules::ParamId::P41, r#"{"years":7}"#);
    assert_eq!(published_bytes(), bytes_with(&edited));
}

/// I-51, I-53: `{{P-57.end}}` is live and not in the publication
/// snapshot. A P-57 edit the caller's spec carries leaves the Guide bytes
/// unchanged.
#[test]
fn i51_live_p57_edit_leaves_the_guide_bytes_unchanged() {
    let edited = with_live(
        fstp_domain::rules::ParamId::P57,
        r#"{"end":"2029-06-30","start":"2026-01-01"}"#,
    );
    assert_eq!(published_bytes(), bytes_with(&edited));
}

/// I-51, I-53: `{{P-67.description}}` is live and not in the publication
/// snapshot. A P-67 edit the caller's spec carries leaves the Guide bytes
/// unchanged.
#[test]
fn i51_live_p67_edit_leaves_the_guide_bytes_unchanged() {
    let edited = with_live(
        fstp_domain::rules::ParamId::P67,
        r#""lapse_and_report_unspent""#,
    );
    assert_eq!(published_bytes(), bytes_with(&edited));
}

/// I-51: the live values the Guide shows come from the core state, here
/// the SuperSAFE values at publication, never from the caller's spec.
#[test]
fn i51_guide_shows_live_values_from_the_core_state() {
    let edited = with_live(fstp_domain::rules::ParamId::P41, r#"{"years":7}"#);
    let html = String::from_utf8(bytes_with(&edited)).unwrap();
    assert!(
        html.contains(
            r#"Records are kept for <span class="guide-value guide-locked">1 year</span>"#
        ),
        "{html}"
    );
    assert!(
        !html.contains("7 years"),
        "the caller's P-41 reached the Guide"
    );
}
