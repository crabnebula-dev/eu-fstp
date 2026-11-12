//! The grantee choice operations of M9 lane P1 through the API, on the
//! matrix worlds (R-PB-02, R-PB-03, I-41, I-42, I-43, I-86).
//!
//! - The lead sets a funded choice in GRANTED. `grant.publicity.view`
//!   shows it with its effective level, and the public funded page shows
//!   the approved title on the next request. A withdrawal removes it from
//!   the next page at once (I-43).
//! - I-41: a funded choice before GRANTED and a finished choice before
//!   COMPLETED are refused, and so is a withdrawal with no choice.
//! - In COMPLETED the lead's binding has ended, and the lead still sets
//!   the finished choice (interim, pending Daniel).
//! - R-PB-03: a client text reference in place of a text is refused, so a
//!   choice never names proposal content.
//! - Only the lead makes the choices: the programme manager is refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

fn world(state: StateTag) -> Built {
    build(WorldKey {
        state: StateProfile::Proposal(state),
        policy: Policy::SUPERSAFE,
        variant: Variant::Main,
    })
    .unwrap_or_else(|e| panic!("world {state:?}: {e}"))
}

fn seeder(w: Built) -> Seeder {
    Seeder {
        ports: w.ports,
        core: w.core,
        now: w.now,
        command: 910_000,
        cookies: BTreeMap::new(),
        next_id: 91_000_000,
        admins: w.admins.iter().copied().collect(),
    }
}

fn choice(phase: &str, level: &str, title: &str) -> Value {
    obj(vec![
        ("phase", s(phase)),
        ("level", s(level)),
        ("title", s(title)),
        (
            "summary",
            s("Synthetic public summary, written by the grantee."),
        ),
        ("grantee", s("Synthetic Grantee Org")),
        ("deliverables", Value::Array(Array::new())),
    ])
}

/// The public page `part` of the world's programme, as the lead's browser
/// reads it.
fn page(seed: &mut Seeder, slug: &str, part: &str) -> String {
    seed.api(LEAD, GET, &format!("/p/{slug}/{part}"), &Value::Null)
        .unwrap_or_else(|e| panic!("/p/{slug}/{part}: {e}"))
        .to_compact()
}

/// Sets P-50 and P-51 of `p` to `level` with one live `EditPolicy` by the
/// programme manager.
fn set_maxima(seed: &mut Seeder, p: ProgrammeId, level: &str) {
    let head = {
        let state = seed.ports.engine.state();
        fstp_domain::policy::head(&state.core, p)
            .expect("a head policy")
            .clone()
    };
    let mut v = fstp_domain_testkit::r#gen::policy::next_version(
        &head,
        fstp_domain::id::PolicyVersionId::from_raw(seed.id()),
    );
    let x = fstp_domain::policy::OpaqueValue::from_value(&Value::String(level.to_owned()))
        .expect("an opaque level");
    for param in [
        fstp_domain::rules::ParamId::P50,
        fstp_domain::rules::ParamId::P51,
    ] {
        v.live.opaque.insert(param, x.clone());
    }
    seed.by(
        PM,
        Core::EditPolicy {
            base: head.id,
            version: Box::new(v),
        },
    )
    .unwrap_or_else(|e| panic!("P-50 and P-51: {e}"));
}

/// R-PB-02, I-43, I-86: the lead's funded choice shows in the view and on
/// the next funded page, and its withdrawal hides it on the next page.
#[test]
fn r_pb_02_i43_choice_shows_and_withdrawal_hides_at_once() {
    let w = world(StateTag::Granted);
    let x = w.targets.proposal.expect("X").raw();
    let slug = w.targets.slug.clone();
    let programme = w.targets.programme.expect("P");
    let mut seed = seeder(w);
    set_maxima(&mut seed, programme, "full");
    let title = "Synthetic Open Harbour Sensor Project";
    assert!(!page(&mut seed, &slug, "funded").contains(title));
    seed.api(
        LEAD,
        POST,
        &format!("/grants/{x}/publicity"),
        &choice("Funded", "Full", title),
    )
    .unwrap_or_else(|e| panic!("set: {e}"));
    let view = seed
        .api(LEAD, GET, &format!("/grants/{x}/publicity"), &Value::Null)
        .unwrap_or_else(|e| panic!("view: {e}"));
    let text = view.to_compact();
    assert!(text.contains(title), "{text}");
    assert!(text.contains("\"level\":\"full\""), "{text}");
    for leak in ["@", "account", "iban"] {
        assert!(!text.contains(leak), "I-86: the view names {leak}: {text}");
    }
    let funded = view
        .get("funded")
        .and_then(|f| f.get("choice"))
        .expect("a funded choice");
    let effective = str_member(funded, "effective").expect("effective");
    let max = str_member(&view, "max_funded").expect("max_funded");
    assert_eq!((effective.as_str(), max.as_str()), ("full", "full"));
    let shown = page(&mut seed, &slug, "funded");
    assert!(shown.contains(title), "R-PB-02: the funded page: {shown}");
    assert!(
        shown.contains("Synthetic Grantee Org"),
        "the grantee name at Full"
    );
    // I-43: a lower maximum narrows the next page, the choice unchanged.
    set_maxima(&mut seed, programme, "project");
    let narrowed = page(&mut seed, &slug, "funded");
    assert!(narrowed.contains(title), "Project still shows the title");
    assert!(
        !narrowed.contains("Synthetic Grantee Org"),
        "I-43: the name above the maximum: {narrowed}"
    );
    seed.api(
        LEAD,
        POST,
        &format!("/grants/{x}/publicity/withdrawal"),
        &obj(vec![("phase", s("Funded"))]),
    )
    .unwrap_or_else(|e| panic!("withdraw: {e}"));
    assert!(
        !page(&mut seed, &slug, "funded").contains(title),
        "I-43: the withdrawn grant is still on the next page"
    );
    let after = seed
        .api(LEAD, GET, &format!("/grants/{x}/publicity"), &Value::Null)
        .unwrap();
    assert_eq!(
        after.get("funded").and_then(|f| f.get("choice")),
        Some(&Value::Null)
    );
}

/// I-41: no choice before GRANTED, no finished choice before COMPLETED,
/// and no withdrawal of a choice that does not exist.
#[test]
fn i41_choice_ops_refused_before_their_states() {
    let w = world(StateTag::Negotiation);
    let x = w.targets.proposal.expect("X").raw();
    let mut seed = seeder(w);
    let e = seed
        .api(
            LEAD,
            POST,
            &format!("/grants/{x}/publicity"),
            &choice("Funded", "Full", "Synthetic title"),
        )
        .expect_err("I-41: a choice in NEGOTIATION");
    assert!(e.contains("I-41"), "{e}");
    let w = world(StateTag::Granted);
    let x = w.targets.proposal.expect("X").raw();
    let mut seed = seeder(w);
    let e = seed
        .api(
            LEAD,
            POST,
            &format!("/grants/{x}/publicity"),
            &choice("Finished", "Full", "Synthetic title"),
        )
        .expect_err("I-41: a finished choice in GRANTED");
    assert!(e.contains("I-41"), "{e}");
    let e = seed
        .api(
            LEAD,
            POST,
            &format!("/grants/{x}/publicity/withdrawal"),
            &obj(vec![("phase", s("Funded"))]),
        )
        .expect_err("a withdrawal with no choice");
    assert!(e.contains("I-41"), "{e}");
}

/// R-PB-02: in COMPLETED, after the lead's binding ended, the lead still
/// reads the view and sets the finished choice.
#[test]
fn r_pb_02_former_lead_sets_the_finished_choice() {
    let w = world(StateTag::Completed);
    let x = w.targets.proposal.expect("X").raw();
    let mut seed = seeder(w);
    seed.api(
        LEAD,
        POST,
        &format!("/grants/{x}/publicity"),
        &choice("Finished", "Project", "Synthetic finished title"),
    )
    .unwrap_or_else(|e| panic!("finished set: {e}"));
    let view = seed
        .api(LEAD, GET, &format!("/grants/{x}/publicity"), &Value::Null)
        .unwrap_or_else(|e| panic!("view: {e}"));
    assert_eq!(
        view.get("finished")
            .and_then(|f| f.get("open"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(view.to_compact().contains("Synthetic finished title"));
}

/// R-PB-03: a text reference in place of a text is refused, and nothing
/// is recorded. The programme manager cannot make the lead's choice.
#[test]
fn r_pb_03_client_text_reference_and_other_actors_refused() {
    let w = world(StateTag::Granted);
    let x = w.targets.proposal.expect("X").raw();
    let mut seed = seeder(w);
    let mut body = choice("Funded", "Full", "unused");
    if let Value::Object(o) = &mut body {
        let r = obj(vec![("digest", s(&"00".repeat(32))), ("id", s("1"))]);
        let _ = o.insert("summary", r);
    }
    let e = seed
        .api(LEAD, POST, &format!("/grants/{x}/publicity"), &body)
        .expect_err("R-PB-03: a client text reference");
    assert!(!e.is_empty());
    let e = seed
        .api(
            PM,
            POST,
            &format!("/grants/{x}/publicity"),
            &choice("Funded", "Full", "Synthetic title"),
        )
        .expect_err("the programme manager makes no choice");
    assert!(!e.contains("I-41"), "{e}");
    let view = seed
        .api(LEAD, GET, &format!("/grants/{x}/publicity"), &Value::Null)
        .unwrap();
    assert_eq!(
        view.get("funded").and_then(|f| f.get("choice")),
        Some(&Value::Null)
    );
}
