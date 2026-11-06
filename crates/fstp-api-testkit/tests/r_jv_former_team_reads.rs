//! The former team's read-only view of its own route (Daniel's decision
//! of 2026-11-06, `SPEC/12-journey-ui.md` sections 7 and 8.1, O-54, O-59,
//! `roles-and-sod.md` Receiving bindings, state-machine NOTE 10; lane j4).
//!
//! A Receiving binding still ends when its proposal reaches a terminal
//! state. The lead and the team members whose bindings ended there keep a
//! read-only view of `proposal.journey`, `proposal.diary` and
//! `proposal.route_map` of that proposal. They see the outcome with the
//! visibility they had while bound, so O-54 still hides the scores and
//! comments of a WITHDRAWN proposal. Their `map` flag stays true and
//! their `withdraw` flag is false. Every command on the proposal stays
//! refused, and nobody else gains a read.
//!
//! Two worlds, both from genesis through production commands, with
//! synthetic accounts and texts only:
//!
//! - The world of `r_jv_route_map_read.rs`: PR1 of L1 with team member
//!   MEMBER, and PR2 of L2, both submitted in one published call. R1 is
//!   assigned to PR1 and declared. The lead then withdraws PR1 through
//!   the web route, so the route is WITHDRAWN after SUBMITTED.
//! - The worlds of the authorisation matrix harness, with X in WITHDRAWN
//!   and in NOT_SELECTED. Their cells are judged by the reference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::FakeVault;
use fstp_api_testkit::fake::cell::class;
use fstp_api_testkit::fake::fixture::{START, World};
use fstp_api_testkit::matrix::{self, Observed, agrees, class_of};
use fstp_api_testkit::reference::authz::{
    Channel as Via, Expected, Login, StateProfile, Who, authz_reference,
};
use fstp_domain::StateTag;
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
use fstp_json::{ToJson, Value};
use fstp_ledger::MemStore;

/// The published call of the world.
const CALL: fstp_domain::id::CallId = roster::call(1);

/// R1's assignment to PR1.
const A1: AssignmentId = AssignmentId::from_raw(0x4a1);

/// The three journey reads, by path.
const READS: [(&str, &str); 3] = [
    ("proposal.journey", "journey"),
    ("proposal.diary", "diary"),
    ("proposal.route_map", "route-map"),
];

/// The world of `r_jv_route_map_read.rs`, PR1 still SUBMITTED.
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
        let mut id = *b"fixture:j4old\0\0\0";
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

fn get(c: &FakeCell, account: AccountId, path: &str) -> Result<OpResult, ApiError> {
    let login = c.login(account, LoginMethod::Passkey);
    c.web(&login, decode_route(Method::Get, path, b""))
}

fn post(c: &FakeCell, account: AccountId, path: &str) -> Result<OpResult, ApiError> {
    let login = c.login(account, LoginMethod::Passkey);
    c.web(&login, decode_route(Method::Post, path, b"{}"))
}

fn path(p: ProposalId, read: &str) -> String {
    format!("/proposals/{}/{read}", p.raw())
}

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

/// The rule a refusal names, or `None` for any other result.
fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(rule),
        _ => None,
    }
}

/// The world with PR1 withdrawn by its lead after submission. Before the
/// withdrawal both team members read the three reads, so every read
/// after it tests the end of the binding, not a missing setup.
fn withdrawn_world() -> FakeCell {
    let c = FakeCell::from_world(&world()).unwrap_or_else(|e| panic!("the fake cell: {e}"));
    for who in [L1, MEMBER] {
        for (op, p) in READS {
            let r = get(&c, who, &path(PR1, p));
            assert!(done(&r).is_some(), "{who:?} reads {op} while bound: {r:?}");
        }
    }
    let w = post(&c, L1, &path(PR1, "withdrawal"));
    assert!(matches!(w, Ok(OpResult::Done { .. })), "withdraw: {w:?}");
    let j = done(&get(&c, L2, &path(PR2, "journey"))).expect("L2 reads PR2");
    assert_eq!(
        member(&j, "state").and_then(Value::as_str),
        Some("SUBMITTED"),
        "PR2 stays under way"
    );
    c
}

/// Daniel 2026-11-06, section 8.1, NOTE 10, `roles-and-sod.md` line 98:
/// after the lead withdraws PR1, the former lead and the former team
/// member each read `proposal.journey`, `proposal.diary` and
/// `proposal.route_map`. The journey stands at WITHDRAWN with `map` true
/// and `withdraw` false, and the map's node statuses put WITHDRAWN last.
#[test]
fn r_jv_01_former_team_reads_its_route_after_withdrawn() {
    let c = withdrawn_world();
    for who in [L1, MEMBER] {
        let j = get(&c, who, &path(PR1, "journey"));
        let j = done(&j).unwrap_or_else(|| panic!("{who:?} reads the journey: {j:?}"));
        assert_eq!(
            member(&j, "state").and_then(Value::as_str),
            Some("WITHDRAWN"),
            "{who:?}: {}",
            j.to_compact()
        );
        assert_eq!(flag(&j, "map"), Some(true), "{who:?}: the map stays theirs");
        assert_eq!(
            flag(&j, "withdraw"),
            Some(false),
            "{who:?}: NOTE 10, no withdrawal from WITHDRAWN"
        );
        let d = get(&c, who, &path(PR1, "diary"));
        let d = done(&d).unwrap_or_else(|| panic!("{who:?} reads the diary: {d:?}"));
        let entries = match member(&d, "entries") {
            Some(Value::Array(a)) => a.iter().cloned().collect::<Vec<Value>>(),
            _ => panic!("{who:?}: a diary with no entries: {}", d.to_compact()),
        };
        let withdrawal = entries.iter().any(|e| {
            member(e, "kind").and_then(Value::as_str) == Some("state_transition")
                && d_param_state(e) == Some("WITHDRAWN")
        });
        assert!(
            withdrawal,
            "{who:?}: the log holds the withdrawal (design 02 Q3): {}",
            d.to_compact()
        );
        let m = get(&c, who, &path(PR1, "route-map"));
        let m = done(&m).unwrap_or_else(|| panic!("{who:?} reads the route map: {m:?}"));
        let current: Vec<&str> = match member(&m, "nodes") {
            Some(Value::Array(a)) => a
                .iter()
                .filter(|n| member(n, "status").and_then(Value::as_str) == Some("current"))
                .filter_map(|n| member(n, "state").and_then(Value::as_str))
                .collect(),
            _ => Vec::new(),
        };
        assert_eq!(current, vec!["WITHDRAWN"], "{who:?}: {}", m.to_compact());
    }
}

/// Whether a diary entry names a state among its parameters.
fn d_param_state(e: &Value) -> Option<&str> {
    match member(e, "params") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|p| member(p, "state").and_then(Value::as_str))
            .find(|s| *s == "WITHDRAWN"),
        _ => None,
    }
}

/// O-54: a WITHDRAWN proposal had no final decision, so the former team's
/// log holds no reviewer score or comment, as while bound.
#[test]
fn r_jv_o54_former_team_sees_no_scores_of_a_withdrawn_proposal() {
    let c = withdrawn_world();
    for who in [L1, MEMBER] {
        let d = done(&get(&c, who, &path(PR1, "diary")))
            .unwrap_or_else(|| panic!("{who:?} reads the diary"));
        let text = d.to_compact();
        assert!(
            !text.contains("\"reviewer_score\"") && !text.contains("\"score\""),
            "O-54: {who:?} sees a score of a WITHDRAWN proposal: {text}"
        );
    }
}

/// Daniel 2026-11-06, R-AC-01, O-58: the withdrawal of PR1 opens nothing
/// to anyone else. The lead of another proposal is refused each read with
/// R-AC-01, as before. The IRC member, with no IRC assignment on PR1, is
/// refused the journey and the route map, and reads no diary entry of it
/// (O-58). The assigned reviewer, the other committee member and the
/// coordinator are refused the route map, and get no map flag.
#[test]
fn r_jv_ac01_withdrawn_route_stays_closed_to_everyone_else() {
    let c = withdrawn_world();
    for (op, p) in READS {
        let r = get(&c, L2, &path(PR1, p));
        assert_eq!(rule(&r), Some("R-AC-01"), "L2 on {op}: {r:?}");
    }
    for p in ["journey", "route-map"] {
        let r = get(&c, IRC, &path(PR1, p));
        assert!(class(&r).refused(), "the IRC member on {p}: {r:?}");
    }
    if let Some(d) = done(&get(&c, IRC, &path(PR1, "diary"))) {
        assert!(
            matches!(member(&d, "entries"), Some(Value::Array(a)) if a.is_empty()),
            "O-58: the IRC member reads PR1's log: {}",
            d.to_compact()
        );
    }
    for who in [R1, R2, COORDINATOR] {
        let r = get(&c, who, &path(PR1, "route-map"));
        assert!(class(&r).refused(), "{who:?} gets the route map: {r:?}");
        if let Some(j) = done(&get(&c, who, &path(PR1, "journey"))) {
            assert_eq!(flag(&j, "map"), Some(false), "{who:?}: {}", j.to_compact());
            assert_eq!(
                flag(&j, "withdraw"),
                Some(false),
                "{who:?}: {}",
                j.to_compact()
            );
        }
    }
}

/// `roles-and-sod.md` line 98, Daniel 2026-11-06: the read-only view
/// revives no binding. A command of the former lead or the former team
/// member on PR1 is refused after WITHDRAWN.
#[test]
fn r_sb_03_former_team_commands_are_refused_after_withdrawn() {
    let c = withdrawn_world();
    for who in [L1, MEMBER] {
        let r = post(&c, who, &path(PR1, "withdrawal"));
        assert!(class(&r).refused(), "{who:?} withdraws again: {r:?}");
        let login = c.login(who, LoginMethod::Passkey);
        let save = c.web(
            &login,
            decode_route(
                Method::Put,
                &path(PR1, "workspace"),
                br#"{"title":"SYNTHETIC LATE EDIT"}"#,
            ),
        );
        assert!(
            class(&save).refused(),
            "{who:?} edits the workspace: {save:?}"
        );
    }
}

/// The matrix cell of `op` for `who` in `state`, through the web with a
/// passkey session.
fn cell(m: &matrix::Matrix, op: &str, who: Who, state: StateTag) -> matrix::Cell {
    m.cells()
        .find(|c| {
            c.op == op
                && c.who == who
                && c.state == StateProfile::Proposal(state)
                && c.session.channel == Via::Web
                && c.session.login == Some(Login::Passkey)
        })
        .unwrap_or_else(|| panic!("no matrix cell for {op}, {who:?}, {state:?}"))
}

/// The observed outcome of each cell, with the reference's verdict.
fn judged(state: StateTag, cases: &[(&str, Who)]) -> Vec<(String, Expected, Observed)> {
    let m = matrix::matrix().unwrap_or_else(|e| panic!("{e}"));
    let reference = authz_reference().unwrap_or_else(|e| panic!("{e}"));
    let mut channel = matrix::direct_channel().unwrap_or_else(|e| panic!("{e}"));
    cases
        .iter()
        .map(|(op, who)| {
            let c = cell(&m, op, *who, state);
            let expected = reference.expected(&c).expect("the reference judges it");
            let observed = channel
                .observe(&c)
                .unwrap_or_else(|e| panic!("{op} for {who:?} in {state:?}: {e:?}"));
            (format!("{op} for {who:?} in {state:?}"), expected, observed)
        })
        .collect()
}

/// Daniel 2026-11-06, over both terminal states of the decision: the
/// former lead and the former team member read the three journey reads.
/// The assigned reviewer, the IRC member and an unbound account are
/// refused the route map, and the unbound account each read. A command
/// of the former lead is refused. The reference agrees with each read.
/// The command is left out of that comparison: the reference still
/// holds the lead bound in a terminal state, which the matrix lane owns.
fn former_team_in(state: StateTag) {
    let mut cases: Vec<(&str, Who)> = Vec::new();
    for (op, _) in READS {
        cases.push((op, Who::Lead));
        cases.push((op, Who::TeamMember));
        cases.push((op, Who::Unbound));
    }
    cases.push(("proposal.route_map", Who::AssignedReviewer));
    cases.push(("proposal.route_map", Who::IrcMember));
    cases.push(("proposal.withdraw", Who::Lead));
    for (what, expected, observed) in judged(state, &cases) {
        let reads =
            matches!(what.split(' ').next(), Some(op) if READS.iter().any(|(o, _)| *o == op));
        let former = what.contains("for Lead ") || what.contains("for TeamMember ");
        if reads && former {
            assert_eq!(observed, Observed::Completed, "{what}");
            assert_eq!(expected, Expected::Allow, "the reference: {what}");
        } else {
            assert!(
                !matches!(observed, Observed::Completed | Observed::Pending),
                "{what} is not refused: {observed:?}"
            );
            assert!(
                !reads || matches!(expected, Expected::Deny(_)),
                "the reference: {what}: {expected:?}"
            );
        }
        assert!(
            !reads || agrees(expected, class_of(&observed)),
            "{what}: the reference says {expected:?}, the system {observed:?}"
        );
    }
}

/// Daniel 2026-11-06: the former team's reads after WITHDRAWN, through
/// the matrix harness.
#[test]
fn r_jv_01_former_team_reads_after_withdrawn_in_the_matrix_world() {
    former_team_in(StateTag::Withdrawn);
}

/// Daniel 2026-11-06, O-54: the former team's reads after NOT_SELECTED,
/// a final decision, through the matrix harness.
#[test]
fn r_jv_01_former_team_reads_after_not_selected_in_the_matrix_world() {
    former_team_in(StateTag::NotSelected);
}
