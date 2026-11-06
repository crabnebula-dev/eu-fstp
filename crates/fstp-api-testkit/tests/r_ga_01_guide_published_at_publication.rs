//! The Guide for Applicants is generated and stored at publication
//! (R-GA-01, I-52, I-53; M4 design sections 3.4 D2e and 3.10).
//!
//! - `PublishCall` and `GuidePublished { call, version: 1, digest }` are
//!   one ledger entry, and the entry stores the canonical Guide and its
//!   page.
//! - The digest is SHA-256, through `fstp-crypto`, over the stored
//!   canonical document.
//! - The engine renders the Guide at publication and refuses the
//!   publication, with I-52, when the Guide lacks a required section or a
//!   placeholder does not resolve. Nothing is appended then.
//! - A second `GuidePublished` for a call is refused, and so is one whose
//!   entry publishes no such call.
//! - A live P-05 edit after publication never changes the stored Guide.
//!
//! Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "r_ga_support.rs"]
mod support;

use fstp_domain::FoldError;
use fstp_domain::id::{ContentDigest, PolicyVersionId};
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::eur;
use fstp_domain_testkit::r#gen::roster::{P1, T0, edit_policy};
use fstp_engine::{ExecError, Record};
use fstp_ledger::Seq;
use fstp_programme::Field;
use support::{GUIDE_CALL, GuideEnv, UNPUBLISHED_CALL, publish_step, world_with};

/// The `GuidePublished` record of `r`, if it is one.
fn guide_of(r: &Record) -> Option<(fstp_domain::id::CallId, u32, ContentDigest, &str, &str)> {
    match r {
        Record::Core(fstp_domain::Record::GuidePublished {
            call,
            version,
            digest,
            canonical,
            page,
        }) => Some((*call, *version, *digest, canonical.as_str(), page.as_str())),
        _ => None,
    }
}

/// R-GA-01, I-52, D2e: the publication entry holds the `CallPublished` of
/// call 1 and, after it under the same command id, its `GuidePublished`
/// of version 1.
#[test]
fn r_ga_01_publication_entry_pairs_call_published_with_guide_published() {
    let w = world_with(GuideEnv::supersafe(), true);
    let entries = w.entries();
    let at = entries
        .iter()
        .position(|e| {
            matches!(
                &e.record,
                Record::Core(fstp_domain::Record::CallPublished { call, .. }) if *call == GUIDE_CALL
            )
        })
        .expect("the CallPublished of call 1");
    let published = &entries[at];
    let guide = entries[at + 1..]
        .iter()
        .take_while(|e| e.command == published.command)
        .find_map(|e| guide_of(&e.record))
        .expect("R-GA-01: no GuidePublished in the publication entry");
    assert_eq!(guide.0, GUIDE_CALL);
    assert_eq!(guide.1, 1, "R-GA-01: the first Guide is version 1");
    let all = entries.iter().filter_map(|e| guide_of(&e.record)).count();
    assert_eq!(all, 1, "one Guide for one publication");
}

/// I-53, R-GA-01: the digest is SHA-256 through `fstp-crypto` over the
/// stored canonical document, and the stored Guide is the one the core
/// state serves.
#[test]
fn i53_digest_matches_the_stored_canonical_bytes() {
    let w = world_with(GuideEnv::supersafe(), true);
    let stored = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL)
        .expect("the stored Guide of call 1");
    let want = ContentDigest::from_bytes(fstp_crypto::sha256(stored.canonical().as_bytes()));
    assert_eq!(stored.digest(), want);
    assert_eq!(stored.version(), 1);
    assert!(stored.page().starts_with("<!DOCTYPE html>"));
    let entries = w.entries();
    let (_, _, digest, canonical, page) = entries
        .iter()
        .find_map(|e| guide_of(&e.record))
        .expect("the GuidePublished record");
    assert_eq!(digest, stored.digest());
    assert_eq!(canonical, stored.canonical());
    assert_eq!(page, stored.page());
    assert!(fstp_domain::programme::stored_guide(&w.state().core, UNPUBLISHED_CALL).is_none());
}

/// R-GA-02, R-PB-04, I-68: the stored page is well formed and carries no
/// script, and it is the Guide of the call: the snapshot P-05 and the
/// call identifier.
#[test]
fn r_ga_01_stored_page_is_wellformed_and_scriptless() {
    let w = world_with(GuideEnv::supersafe(), true);
    let stored = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL).unwrap();
    fstp_html::check_wellformed(stored.page().as_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!stored.page().contains("<script"));
    assert!(stored.page().contains("400000.00"));
    assert!(stored.page().contains(support::SUMMARY));
}

/// I-52, D2e: a template that lacks a required section gives no Guide,
/// so the publication is refused with I-52 and nothing is appended.
#[test]
fn i52_publication_recomputes_a_clean_report_missing_section() {
    let mut env = GuideEnv::supersafe();
    let text = env.template.to_markdown();
    let cut = text
        .find("## 13. Timeline")
        .and_then(|a| text[a..].find("## 14.").map(|b| (a, a + b)))
        .expect("the Timeline section");
    let without = format!("{}{}", &text[..cut.0], &text[cut.1..]);
    env.template = fstp_guide::parse_template(without.as_bytes()).unwrap();
    let mut w = world_with(env, false);
    let before = w.entries().len();
    match w.run(&publish_step(GUIDE_CALL)) {
        Err(ExecError::Refused(r)) => assert_eq!(r.rule, RuleRef::I52, "{r:?}"),
        other => panic!("I-52: published without a complete Guide: {other:?}"),
    }
    assert_eq!(
        w.entries().len(),
        before,
        "a refused publication appends nothing"
    );
    assert!(fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL).is_none());
}

/// I-52, I-51: a placeholder that does not resolve gives no Guide, so the
/// publication is refused with I-52.
#[test]
fn i52_publication_recomputes_a_clean_report_unresolved_placeholder() {
    let mut env = GuideEnv::supersafe();
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let mut spec = fixture.spec.clone();
    spec.comms.faq = Field::Unset;
    env.compiled = fstp_programme::compile(
        &spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P1, PolicyVersionId::from_raw(P1.raw()), None),
    )
    .unwrap();
    let mut w = world_with(env, false);
    let before = w.entries().len();
    match w.run(&publish_step(GUIDE_CALL)) {
        Err(ExecError::Refused(r)) => assert_eq!(r.rule, RuleRef::I52, "{r:?}"),
        other => panic!("I-52: published with an unresolved placeholder: {other:?}"),
    }
    assert_eq!(w.entries().len(), before);
}

/// I-53, section 3.10: the fold refuses a second `GuidePublished` for a
/// call, so a published Guide version is never replaced.
#[test]
fn i53_second_guide_published_is_refused() {
    let w = world_with(GuideEnv::supersafe(), true);
    let stored = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL)
        .unwrap()
        .clone();
    let second = fstp_domain::Record::GuidePublished {
        call: GUIDE_CALL,
        version: 1,
        digest: ContentDigest::from_bytes(fstp_crypto::sha256(b"another")),
        canonical: "another".to_owned(),
        page: stored.page().to_owned(),
    };
    let mut core = w.state().core.clone();
    let at = Timestamp::from_micros(T0.micros());
    assert_eq!(
        fstp_domain::apply(&mut core, Seq::from_raw(u64::MAX), at, &second),
        Err(FoldError::DuplicateId)
    );
    // The engine fold refuses it too, even in an entry of its own.
    let mut state = w.state().clone();
    assert!(
        fstp_engine::apply(
            &mut state,
            Seq::from_raw(u64::MAX),
            at,
            &Record::Core(second)
        )
        .is_err()
    );
}

/// I-52, D2e: a `GuidePublished` whose entry publishes no such call is
/// refused, even for a call that is published and has no Guide yet.
#[test]
fn i52_guide_published_outside_its_publication_entry_is_refused() {
    let w = world_with(GuideEnv::supersafe(), false);
    let at = Timestamp::from_micros(T0.micros());
    let lone = fstp_domain::Record::GuidePublished {
        call: UNPUBLISHED_CALL,
        version: 1,
        digest: ContentDigest::from_bytes(fstp_crypto::sha256(b"x")),
        canonical: "x".to_owned(),
        page: "x".to_owned(),
    };
    let mut state = w.state().clone();
    assert!(
        fstp_engine::apply(&mut state, Seq::from_raw(u64::MAX), at, &Record::Core(lone)).is_err(),
        "a Guide of an unpublished call folded"
    );
}

/// I-53, I-51, NOTE 7: a live P-05 edit after publication leaves the
/// stored Guide, its digest and its page byte for byte unchanged.
#[test]
fn i53_stored_guide_never_changes_after_a_live_p05_edit() {
    let mut w = world_with(GuideEnv::supersafe(), true);
    let before = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL)
        .unwrap()
        .clone();
    for (n, minor) in [(9_001u128, 45_000_000i64), (9_002, 35_000_000)] {
        let head = fstp_domain::policy::head(&w.state().core, P1)
            .cloned()
            .expect("head");
        let p05 = eur(minor).unwrap();
        let ceiling = eur(45_000_000).unwrap();
        let step = edit_policy(&head, PolicyVersionId::from_raw(n), |v| {
            v.live.p05 = p05;
            v.live.p58 = Some(ceiling);
        });
        w.run(&step)
            .unwrap_or_else(|e| panic!("the live P-05 edit: {e:?}"));
        let after = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL).unwrap();
        assert_eq!(after, &before, "I-53: the stored Guide changed");
    }
}
