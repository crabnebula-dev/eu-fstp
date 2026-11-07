//! The route map read and the read flags of `proposal.journey` (ADR-015
//! amendment of 2026-11-06, `SPEC/12-journey-ui.md` sections 6, 8.1 and
//! 8.3, state-machine NOTE 10, O-58, I-68, I-93, I-97, TH-26; review
//! J3-R2; lane j4).
//!
//! Daniel decided on 2026-11-06 that the read returns the renderer's
//! checked element tree as data. These tests pin the reading of lane j4:
//!
//! - `proposal.route_map` (`GET /proposals/{proposal}/route-map`) is one
//!   new journey read. Its reply is `{"proposal", "tree", "nodes"}`: the
//!   tree of `fstp_html::route::tree` for the caller's projection, and
//!   the status of every node in route order (`route::statuses`). A
//!   separate read keeps `proposal.journey` a reply of tokens only, so
//!   its I-97 test (`r_jv_journey_reads.rs`) holds unchanged.
//! - `proposal.journey` gains two flags. `map` is true only for a caller
//!   who holds a Receiving binding on the proposal's team (section 8.1).
//!   `withdraw` is true only for its lead, and only in a state NOTE 10
//!   leaves open.
//! - The route map read admits exactly the callers whose `map` is true.
//!   Reviewers, committee and coordinator keep the strip of section 8.3,
//!   and IRC members get neither (O-58).
//!
//! The world is built from genesis through production commands: PR1 of
//! L1 with team member MEMBER, and PR2 of L2, both submitted in one
//! published call. R1 is assigned to PR1 and has declared no conflict,
//! the coordinator has declared on PR1, and R2 and the IRC member hold
//! programme bindings only. Every account and text is synthetic.
//!
//! Lane j4 test author. Red until the implementer adds the read, the two
//! flags and `route::tree`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_access::{Method as RegistryMethod, op};
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::FakeVault;
use fstp_api_testkit::fake::cell::class;
use fstp_api_testkit::fake::fixture::{LEAD, OTHER, OWNER, PX, START, World};
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::DeclarationSubject;
use fstp_domain::id::{AccountId, AssignmentId, CommandId, ProposalId};
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, IRC, L1, L2, MEMBER, O1, O2, PR1, PR2, R1, R2, ReviewSetup, assign,
    attest_adult_leads, declare, handle, review_truth,
};
use fstp_domain_testkit::r#gen::roster::{self, K1, SodSetup, T0};
use fstp_engine::Engine;
use fstp_html::route::{RouteDef, RouteEdge, RouteLeg, RouteNode, RouteView};
use fstp_html::{CatalogueSource, Catalogues, Label, SafeUrl};
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::MemStore;
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// The published call of the world.
const CALL: fstp_domain::id::CallId = roster::call(1);

/// R1's assignment to PR1.
const A1: AssignmentId = AssignmentId::from_raw(0x4a1);

/// The world of this file, built once per test.
fn world() -> World {
    let setup = ReviewSetup {
        base: SodSetup {
            programmes: vec![roster::P1],
            p12: 0,
            p13: [K1].into_iter().collect(),
            calls: vec![(roster::P1, CALL)],
            published: vec![CALL],
        },
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: vec![
            (COORDINATOR, Role::FstpCoordinator, None),
            (R1, Role::CommitteeMember, Some(O1)),
            (R2, Role::CommitteeMember, Some(O2)),
            (IRC, Role::IrcMember, None),
        ],
        drafts: vec![
            DraftSpec {
                lead: L1,
                proposal: PR1,
                call: CALL,
                team: vec![MEMBER],
                minor: false,
                submit: true,
            },
            DraftSpec {
                lead: L2,
                proposal: PR2,
                call: CALL,
                team: Vec::new(),
                minor: false,
                submit: true,
            },
        ],
    };
    let mut truth = review_truth(setup.accounts());
    attest_adult_leads(&mut truth, setup.drafts.iter().map(|d| (d.lead, d.minor)));
    let vault = FakeVault::new(truth.clone());
    let mut engine = Engine::open(MemStore::new(), vault.oracle()).unwrap();
    let mut steps = setup.steps().unwrap();
    steps.push(declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ));
    steps.push(assign(
        COORDINATOR,
        A1,
        PR1,
        R1,
        AssignmentKind::Reviewer,
        Some(handle(1)),
    ));
    steps.push(declare(
        R1,
        DeclarationSubject::Assignment(A1),
        false,
        false,
    ));
    for (i, step) in steps.into_iter().enumerate() {
        let mut id = *b"fixture:j4map\0\0\0";
        id[15] = u8::try_from(i).unwrap();
        let ctx = step.ctx(T0, CommandId::from_bytes(id));
        fstp_domain_testkit::activation::run_core(&mut engine, &step.cmd, ctx)
            .unwrap_or_else(|e| panic!("world step {i} {:?}: {e}", step.cmd.kind()));
    }
    let (store, _, _) = engine.into_parts();
    World {
        store,
        truth,
        start: START,
        admins: BTreeSet::new(),
    }
}

fn cell_of(world: &World) -> FakeCell {
    FakeCell::from_world(world).unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// One caller of the world: whether they are on PR1's team and whether
/// they are its lead.
#[derive(Clone, Copy, Debug)]
struct Caller {
    account: AccountId,
    what: &'static str,
    team: bool,
    lead: bool,
}

const fn caller(account: AccountId, what: &'static str, team: bool, lead: bool) -> Caller {
    Caller {
        account,
        what,
        team,
        lead,
    }
}

/// Every caller of the world, with the section 8.1 and NOTE 10 facts.
const CALLERS: [Caller; 9] = [
    caller(L1, "the lead (Applicant)", true, true),
    caller(MEMBER, "a team member (ApplicantTeamMember)", true, false),
    caller(L2, "the lead of another proposal in the call", false, false),
    caller(COORDINATOR, "the declared FSTP coordinator", false, false),
    caller(R1, "the assigned, declared reviewer", false, false),
    caller(R2, "a committee member with no assignment", false, false),
    caller(IRC, "an IRC member", false, false),
    caller(OWNER, "the programme manager", false, false),
    caller(OTHER, "the call drafter", false, false),
];

fn read(c: &FakeCell, account: AccountId, path: &str) -> Result<OpResult, ApiError> {
    let login = c.login(account, LoginMethod::Passkey);
    c.web(&login, decode_route(Method::Get, path, b""))
}

fn journey_path(p: ProposalId) -> String {
    format!("/proposals/{}/journey", p.raw())
}

fn map_path(p: ProposalId) -> String {
    format!("/proposals/{}/route-map", p.raw())
}

/// The reply body of a done read, as JSON.
fn done(r: &Result<OpResult, ApiError>) -> Option<Value> {
    match r {
        Ok(OpResult::Done { body, .. }) => Some(body.to_json()),
        _ => None,
    }
}

fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|o| o.get(k))
}

fn flag(v: &Value, k: &str) -> Option<bool> {
    match member(v, k) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// The precondition of every refusal test here: the read exists, and the
/// lead of PR1 gets its tree. Without it a refusal would prove nothing.
fn route_map_exists(c: &FakeCell) {
    assert!(
        op("proposal.route_map").is_some(),
        "ADR-015 amendment: no proposal.route_map read is registered"
    );
    let r = read(c, L1, &map_path(PR1));
    assert!(
        done(&r).is_some(),
        "ADR-015 amendment: the lead of PR1 is refused the route map: {r:?}"
    );
}

/// ADR-015 amendment, R-JV-01, I-84: the route map read is registered as
/// a GET route of the web channel under the proposal's path, a plain read.
#[test]
fn r_jv_01_route_map_read_is_registered() {
    let spec = op("proposal.route_map")
        .unwrap_or_else(|| panic!("ADR-015 amendment: no proposal.route_map read"));
    assert_eq!(
        spec.route,
        Some((RegistryMethod::Get, "/proposals/{proposal}/route-map")),
        "route of proposal.route_map"
    );
    assert!(!spec.high_risk && !spec.binding, "a read: {spec:?}");
}

/// Section 8.1, review J3-R2, I-93: over the callers of the world,
/// `proposal.journey` either refuses, or gives `map` true exactly for a
/// caller on PR1's team. The cell decides it, never the page. Each team
/// member is admitted.
#[test]
fn r_jv_01_j3r2_map_flag_is_set_only_for_the_team() {
    let c = cell_of(&world());
    check("r_jv_01_j3r2_map_flag_is_set_only_for_the_team", |g| {
        let who = *g.pick(&CALLERS);
        let r = read(&c, who.account, &journey_path(PR1));
        match done(&r) {
            Some(v) => prop_assert_eq!(
                flag(&v, "map"),
                Some(who.team),
                "map flag for {}: {}",
                who.what,
                v.to_compact()
            ),
            None => prop_assert!(!who.team, "{} is refused the journey: {r:?}", who.what),
        }
        Ok(())
    });
}

/// State-machine NOTE 10, R-SB-03, review J3-R2: over the callers of the
/// world, where `proposal.journey` answers, `withdraw` is true exactly
/// for the lead of PR1, whose SUBMITTED state NOTE 10 leaves open.
#[test]
fn r_sb_03_note10_withdraw_flag_is_set_only_for_the_lead() {
    let c = cell_of(&world());
    check(
        "r_sb_03_note10_withdraw_flag_is_set_only_for_the_lead",
        |g| {
            let who = *g.pick(&CALLERS);
            let r = read(&c, who.account, &journey_path(PR1));
            match done(&r) {
                Some(v) => prop_assert_eq!(
                    flag(&v, "withdraw"),
                    Some(who.lead),
                    "withdraw flag for {}: {}",
                    who.what,
                    v.to_compact()
                ),
                None => prop_assert!(!who.team, "{} is refused the journey: {r:?}", who.what),
            }
            Ok(())
        },
    );
}

/// NOTE 10: once the lead withdraws the draft, the route is terminal, so
/// the lead's `withdraw` flag clears while the map stays theirs.
#[test]
fn r_sb_03_note10_withdraw_flag_clears_once_withdrawn() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let before = done(&read(&c, LEAD, &journey_path(PX))).expect("the lead reads the journey");
    assert_eq!(
        flag(&before, "withdraw"),
        Some(true),
        "the draft's lead: {}",
        before.to_compact()
    );
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let path = format!("/proposals/{}/withdrawal", PX.raw());
    let w = c.web(&lead, decode_route(Method::Post, &path, b"{}"));
    assert!(matches!(w, Ok(OpResult::Done { .. })), "withdraw: {w:?}");
    let after = done(&read(&c, LEAD, &journey_path(PX))).expect("the lead reads the journey");
    assert_eq!(
        flag(&after, "withdraw"),
        Some(false),
        "WITHDRAWN: {}",
        after.to_compact()
    );
    assert_eq!(flag(&after, "map"), Some(true), "the map stays the team's");
}

/// Section 8.3, O-58, review J3-R2: over every caller outside PR1's team,
/// the route map read refuses, whatever they may read of the journey. A
/// hidden page is never the only protection.
#[test]
fn r_jv_03_o58_route_map_is_refused_outside_the_team() {
    let c = cell_of(&world());
    route_map_exists(&c);
    let outside: Vec<Caller> = CALLERS.iter().copied().filter(|w| !w.team).collect();
    check("r_jv_03_o58_route_map_is_refused_outside_the_team", |g| {
        let who = *g.pick(&outside);
        let r = read(&c, who.account, &map_path(PR1));
        prop_assert!(
            class(&r).refused(),
            "{} gets the route map: {r:?}",
            who.what
        );
        Ok(())
    });
}

/// O-58, section 8.3: the assigned reviewer reads the route and gets the
/// strip but no map, and the IRC member gets neither strip nor map.
#[test]
fn r_jv_03_o58_reviewer_and_irc_member_get_no_tree() {
    let c = cell_of(&world());
    route_map_exists(&c);
    let r1 =
        done(&read(&c, R1, &journey_path(PR1))).expect("the assigned reviewer reads the route");
    assert_eq!(
        flag(&r1, "strip"),
        Some(true),
        "section 8.3: the reviewer's strip"
    );
    assert_eq!(
        flag(&r1, "map"),
        Some(false),
        "section 8.3: no map for the reviewer"
    );
    assert!(
        class(&read(&c, R1, &map_path(PR1))).refused(),
        "the reviewer's tree"
    );
    if let Some(v) = done(&read(&c, IRC, &journey_path(PR1))) {
        assert_eq!(flag(&v, "strip"), Some(false), "O-58: no strip");
        assert_eq!(flag(&v, "map"), Some(false), "O-58: no map");
    }
    assert!(
        class(&read(&c, IRC, &map_path(PR1))).refused(),
        "O-58: the IRC member's tree"
    );
}

/// The proposal definition as the renderer reads it: the nodes and edges
/// of `crates/fstp-journey/definitions/proposal.v1.json` in file order,
/// and the "leave the route" rule into WITHDRAWN. Restated here, since
/// the test kit does not depend on `fstp-journey`.
fn reference_def() -> RouteDef {
    const NODES: [&str; 16] = [
        "DRAFT",
        "SUBMITTED",
        "INELIGIBLE",
        "STAGE1",
        "NOT_SELECTED",
        "STAGE2",
        "RANKED",
        "IRC_REVIEW",
        "DEFERRED",
        "DECLINED",
        "NEGOTIATION",
        "WITHDRAWN",
        "GRANTED",
        "IN_EXECUTION",
        "COMPLETED",
        "TERMINATED",
    ];
    const EDGES: [(&str, &str); 20] = [
        ("DRAFT", "SUBMITTED"),
        ("SUBMITTED", "INELIGIBLE"),
        ("SUBMITTED", "STAGE1"),
        ("STAGE1", "NOT_SELECTED"),
        ("STAGE1", "STAGE2"),
        ("STAGE2", "RANKED"),
        ("STAGE2", "DEFERRED"),
        ("RANKED", "NOT_SELECTED"),
        ("RANKED", "IRC_REVIEW"),
        ("IRC_REVIEW", "NEGOTIATION"),
        ("IRC_REVIEW", "DEFERRED"),
        ("IRC_REVIEW", "DECLINED"),
        ("DEFERRED", "STAGE2"),
        ("DEFERRED", "IRC_REVIEW"),
        ("NEGOTIATION", "GRANTED"),
        ("NEGOTIATION", "DECLINED"),
        ("GRANTED", "IN_EXECUTION"),
        ("GRANTED", "TERMINATED"),
        ("IN_EXECUTION", "COMPLETED"),
        ("IN_EXECUTION", "TERMINATED"),
    ];
    RouteDef {
        nodes: NODES
            .iter()
            .map(|n| RouteNode {
                state: (*n).to_owned(),
                label: Label::new(&format!("journey.node.{}", n.to_ascii_lowercase())),
            })
            .collect(),
        edges: EDGES
            .iter()
            .map(|(f, t)| RouteEdge {
                id: format!("T-{f}-{t}"),
                from: (*f).to_owned(),
                to: (*t).to_owned(),
            })
            .collect(),
        withdraw: Some("WITHDRAWN".to_owned()),
    }
}

/// The view of the caller's journey reply: the progress page of the web
/// app as the page, the proposal id as the subject.
fn view_of(journey: &Value, p: ProposalId) -> RouteView {
    let s = |v: &Value, k: &str| {
        member(v, k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let legs = match member(journey, "legs") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|l| RouteLeg {
                from: s(l, "from"),
                to: s(l, "to"),
            })
            .collect(),
        _ => Vec::new(),
    };
    RouteView {
        subject: p.raw().to_string(),
        page: SafeUrl::new(&format!("/app/proposals/{}/progress", p.raw())).unwrap(),
        position: s(journey, "state"),
        legs,
        overlay: None,
    }
}

fn english() -> Catalogues {
    Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: fstp_html::route::CATALOGUE_EN,
        },
        &[],
    )
    .unwrap()
}

/// The writer's escaping inside `svg`.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The markup of a wire tree, as the writer spells it.
fn markup(v: &Value) -> Result<String, String> {
    if let Some(t) = member(v, "text").and_then(Value::as_str) {
        return Ok(escape(t));
    }
    let tag = member(v, "tag")
        .and_then(Value::as_str)
        .ok_or("a node with no tag")?;
    let mut out = format!("<{tag}");
    if let Some(Value::Array(attrs)) = member(v, "attrs") {
        for a in attrs.iter() {
            let n = member(a, "name")
                .and_then(Value::as_str)
                .ok_or("an attribute with no name")?;
            let x = member(a, "value")
                .and_then(Value::as_str)
                .ok_or("an attribute with no value")?;
            out.push_str(&format!(" {n}=\"{}\"", escape(x)));
        }
    }
    out.push('>');
    if let Some(Value::Array(kids)) = member(v, "children") {
        for k in kids.iter() {
            out.push_str(&markup(k)?);
        }
    }
    out.push_str(&format!("</{tag}>"));
    Ok(out)
}

/// ADR-015 amendment, TH-26, R-JV-05: for each team member, the route
/// map reply holds the tree `route::tree` builds for the same definition,
/// position and legs as the caller's journey reply, the statuses of
/// `route::statuses`, and a tree whose markup the checker accepts.
#[test]
fn adr015_th26_route_map_tree_equals_the_renderer_tree() {
    let c = cell_of(&world());
    let cats = english();
    for who in CALLERS.iter().filter(|w| w.team) {
        let journey = done(&read(&c, who.account, &journey_path(PR1)))
            .unwrap_or_else(|| panic!("{} reads the journey", who.what));
        let r = read(&c, who.account, &map_path(PR1));
        let reply = done(&r).unwrap_or_else(|| panic!("{} reads the route map: {r:?}", who.what));
        let view = view_of(&journey, PR1);
        let want = fstp_html::route::tree(&reference_def(), &view, &cats)
            .unwrap_or_else(|e| panic!("route::tree refused the view of {}: {e}", who.what));
        assert_eq!(
            member(&reply, "tree"),
            Some(&want.to_json()),
            "{}: the tree differs from route::tree",
            who.what
        );
        let statuses = fstp_html::route::statuses(&reference_def(), &view).unwrap();
        let nodes: Vec<Value> = statuses
            .iter()
            .map(|(s, st)| {
                let mut o = Object::new();
                let _ = o.insert("state", Value::from(s.as_str()));
                let _ = o.insert("status", Value::from(*st));
                Value::Object(o)
            })
            .collect();
        assert_eq!(
            member(&reply, "nodes"),
            Some(&Value::Array(nodes.into_iter().collect())),
            "{}: the node statuses",
            who.what
        );
        assert_eq!(
            member(&reply, "proposal").and_then(Value::as_str),
            Some(PR1.raw().to_string().as_str()),
            "the proposal id"
        );
        // The reply's tree in a page the renderer wrote passes the checker.
        let page = fstp_html::Document::new("en")
            .title(fstp_html::Node::text("Application progress"))
            .body(
                fstp_html::Element::new("main")
                    .child(fstp_html::route::svg(&reference_def(), &view).unwrap()),
            )
            .render(&cats)
            .unwrap();
        let page = page.as_str();
        let start = page.find("<svg").unwrap();
        let end = page.find("</svg>").unwrap() + "</svg>".len();
        let tree = member(&reply, "tree").unwrap();
        let spliced = format!(
            "{}{}{}",
            &page[..start],
            markup(tree).unwrap(),
            &page[end..]
        );
        assert_eq!(
            fstp_html::check_wellformed(spliced.as_bytes()),
            Ok(()),
            "{}: the checker refuses the reply's tree",
            who.what
        );
    }
}

/// The canary text the lead saves in the workspace: untrusted submission
/// content that no route map reply may carry.
const CANARY: &str = "<script>alert('j4')</script> CANARY ROUTEMAPx5e1d";

/// I-97, I-68: after the lead saves a canary text in the workspace, the
/// route map reply holds no part of it.
#[test]
fn i97_i68_route_map_holds_no_submission_text() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let mut o = Object::new();
    for k in ["narrative", "summary", "title"] {
        let _ = o.insert(k, Value::from(CANARY));
    }
    let body = Value::Object(o).to_compact().into_bytes();
    let saved = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{}/workspace", PX.raw()),
            &body,
        ),
    );
    assert!(
        matches!(saved, Ok(OpResult::Done { .. })),
        "the canary save: {saved:?}"
    );
    let r = read(&c, LEAD, &map_path(PX));
    let reply = done(&r).unwrap_or_else(|| panic!("the lead reads the route map: {r:?}"));
    let text = reply.to_compact();
    assert!(
        member(&reply, "tree").is_some(),
        "the reply holds a tree: {text}"
    );
    for mark in ["ROUTEMAPx5e1d", "alert('j4')"] {
        assert!(
            !text.contains(mark),
            "I-97: the route map holds {mark}: {text}"
        );
    }
}

/// I-93, section 8.3, O-57, O-58: the world reads as this file says, so
/// the flag properties above range over the readers they name. The team
/// and the assigned reviewer, the declared coordinator and the programme
/// manager read PR1's route. The reviewer and the coordinator get the
/// strip. The lead of PR2, the unassigned committee member and the IRC
/// member are refused. A reference self-test: it reads no new member.
#[test]
fn i93_world_reads_are_as_described() {
    let c = cell_of(&world());
    for (who, admitted, strip) in [
        (L1, true, false),
        (MEMBER, true, false),
        (R1, true, true),
        (COORDINATOR, true, true),
        (OWNER, true, false),
        (L2, false, false),
        (R2, false, false),
        (IRC, false, false),
    ] {
        let r = read(&c, who, &journey_path(PR1));
        match done(&r) {
            Some(v) => {
                assert!(admitted, "{who:?} reads PR1's route: {}", v.to_compact());
                assert_eq!(
                    flag(&v, "strip"),
                    Some(strip),
                    "{who:?} strip: {}",
                    v.to_compact()
                );
            }
            None => assert!(!admitted, "{who:?} is refused PR1's route: {r:?}"),
        }
    }
}
