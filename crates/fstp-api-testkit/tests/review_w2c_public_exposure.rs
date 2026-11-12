//! Reviewer reproducers for lane W2c, public exposure lens (R-PB-05,
//! I-43, I-51, I-53; M4 design section 3.10). Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::OnceLock;

use fstp_api_testkit::mc::public_model::{
    GUIDE_CALL, GuideWorld, PROGRAMME, Param, Params, PublicWorld, Stage, choice, core,
    guide_world, texts,
};
use fstp_domain::policy::OpaqueValue;
use fstp_domain::rules::ParamId;
use fstp_domain_testkit::r#gen::money::{PA, PB};
use fstp_guide::{HORIZON_EUROPE, NoStoredTexts, ProfileSource, ShippedProfiles};
use fstp_public::{GrantChoices, GuideSource, Level, public_view_with, published_guide};

fn world() -> &'static PublicWorld {
    static WORLD: OnceLock<PublicWorld> = OnceLock::new();
    WORLD.get_or_init(|| PublicWorld::build().unwrap_or_else(|e| panic!("the public worlds: {e}")))
}

fn stage(name: &str) -> &'static Stage {
    world()
        .stages
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no stage {name}"))
}

/// R-PB-05, I-43, `public-transparency.md` ("so no single grant can be
/// inferred"): PA chose `full` and PB chose `project`, so PB's granted
/// amount is hidden. With P-54 at 2 the aggregate of call 1 counts both
/// grants. Its total minus PA's shown amount then gives PB's hidden
/// amount. No aggregate may count exactly one grant whose amount the
/// view hides.
#[test]
fn review_r_pb_05_aggregate_never_reveals_one_hidden_amount() {
    let s = stage("executing");
    let params = Params {
        p54: Param::Set(2),
        ..Params::supersafe()
    };
    let w = s
        .with_params(&params, 90_001)
        .unwrap_or_else(|e| panic!("{e}"));
    let mut choices = GrantChoices::none();
    choices.insert(PA, choice(PA, Level::Full, Level::Full));
    choices.insert(PB, choice(PB, Level::Project, Level::Project));
    let view = public_view_with(core(&w), PROGRAMME, &texts(), &choices, w.now())
        .unwrap_or_else(|e| panic!("{e}"));
    for a in &view.aggregates {
        let in_call: Vec<_> = view
            .funded
            .iter()
            .chain(view.finished.iter())
            .filter(|g| g.call == a.call)
            .collect();
        let hidden = in_call.iter().filter(|g| g.amount.is_none()).count();
        let shown: Vec<&str> = in_call.iter().filter_map(|g| g.amount.as_deref()).collect();
        assert_ne!(
            hidden, 1,
            "aggregate {a:?} counts one grant with a hidden amount; its amount is the total minus the shown amounts {shown:?}"
        );
    }
}

fn guide_w() -> &'static GuideWorld {
    static W: OnceLock<GuideWorld> = OnceLock::new();
    W.get_or_init(|| guide_world().unwrap_or_else(|e| panic!("the Guide world: {e}")))
}

/// I-51, I-53, design section 3.10: P-41 is a live parameter that the
/// Guide shows ("Records are kept for {{P-41}}"). It is not in the
/// call's frozen values nor in the publication snapshot. A live edit of
/// P-41 after publication, carried by the compiled spec the caller
/// passes, must leave the published Guide bytes unchanged, as the
/// module documentation of `fstp_public::guide` claims.
#[test]
fn review_i51_live_p41_edit_leaves_the_guide_bytes_unchanged() {
    let w = guide_w();
    let profile = ShippedProfiles
        .profile(HORIZON_EUROPE)
        .unwrap_or_else(|e| panic!("profile: {e:?}"));
    let template = fstp_guide::parse_template(profile.guide_template().as_bytes())
        .unwrap_or_else(|e| panic!("template: {e}"));
    let id = GUIDE_CALL.raw().to_string();
    let render = |compiled: &fstp_programme::Compiled| {
        let source = GuideSource {
            template: &template,
            compiled,
            identifier: &id,
            platform_url: "https://a.fstp.example/",
            data_protection_summary: Some("Synthetic summary. Not a privacy notice."),
            privacy_statement_url: Some("https://privacy.fstp.example/statement"),
            texts: &NoStoredTexts,
            precheck_available: false,
        };
        published_guide(&w.published, GUIDE_CALL, &source).unwrap_or_else(|e| panic!("{e}"))
    };
    let before = render(&w.compiled);
    let mut edited = w.compiled.clone();
    let seven = fstp_json::parse_str(r#"{"years":7}"#).unwrap();
    let old = edited
        .policy
        .live
        .opaque
        .insert(ParamId::P41, OpaqueValue::from_value(&seven).unwrap());
    assert!(old.is_some(), "P-41 is a live opaque parameter of the spec");
    let after = render(&edited);
    assert_eq!(
        before.document.as_str(),
        after.document.as_str(),
        "a live P-41 edit after publication changed the published Guide"
    );
}
