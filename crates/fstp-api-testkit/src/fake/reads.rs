//! Tests of the reads that lane m4disp serves through `ApiCore::dispatch`
//! on the fake cell: the assignment view, the caller's own verification
//! state, a round this core did not see opened, and the final state of a
//! withdrawn proposal (M4 design sections 2.2 J4, J5 and J7, 3.6).
//!
//! Each world is built from genesis through production commands, as the
//! I-85 world is ([`super::fixture`]).

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::model::ReadModel;
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, ErrorCode, OpResult};
use fstp_domain::id::{CommandId, OrganisationId};
use fstp_domain::oracle::Query;
use fstp_domain::policy::ReadAccess;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L1, LIST_1, O1, O2, PR1, R1, R2, R4, ReviewSetup, attest_adult_leads,
    review_truth,
};
use fstp_domain_testkit::r#gen::roster::{self, K1, SodSetup, T0};
use fstp_engine::Engine;
use fstp_json::{ToJson, Value};
use fstp_ledger::MemStore;

use super::fixture::{self, LEAD, OTHER, PX, START, World};
use super::{FakeCell, FakeVault};

/// The published call of the review world.
const CALL: fstp_domain::id::CallId = roster::call(1);

/// A review world: one programme with call 1 published, the coordinator
/// and committee members R1 and R4 of O1 and R2 of O2, and PR1 of L1
/// submitted. `p38` is the programme's P-38.
fn review_world(p38: BTreeMap<OrganisationId, fstp_domain::id::ProximityListId>) -> World {
    let setup = ReviewSetup {
        base: SodSetup {
            programmes: vec![roster::P1],
            p12: 0,
            p13: [K1].into_iter().collect(),
            calls: vec![(roster::P1, CALL)],
            published: vec![CALL],
        },
        p38,
        p10: ReadAccess::AssignedReviewersOnly,
        judges: vec![
            (COORDINATOR, Role::FstpCoordinator, None),
            (R1, Role::CommitteeMember, Some(O1)),
            (R4, Role::CommitteeMember, Some(O1)),
            (R2, Role::CommitteeMember, Some(O2)),
        ],
        drafts: vec![DraftSpec {
            lead: L1,
            proposal: PR1,
            call: CALL,
            team: Vec::new(),
            minor: false,
            submit: true,
        }],
    };
    let mut truth = review_truth(setup.accounts());
    attest_adult_leads(&mut truth, setup.drafts.iter().map(|d| (d.lead, d.minor)));
    let vault = FakeVault::new(truth.clone());
    let mut engine = Engine::open(MemStore::new(), vault.oracle()).unwrap();
    for (i, step) in setup.steps().unwrap().into_iter().enumerate() {
        let mut id = *b"fixture:m4disp\0\0";
        id[15] = u8::try_from(i).unwrap();
        let ctx = step.ctx(T0, CommandId::from_bytes(id));
        fstp_domain_testkit::activation::run_core(&mut engine, &step.cmd, ctx)
            .unwrap_or_else(|e| panic!("review world step {i} {:?}: {e}", step.cmd.kind()));
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

/// The assignment view of PR1, as JSON.
fn assignment_view(c: &FakeCell, login: &super::WebLogin) -> Value {
    let path = format!("/proposals/{}/assignments", PR1.raw());
    match c.web(login, decode_route(Method::Get, &path, &[])) {
        Ok(OpResult::Done {
            body: body @ ReadModel::AssignmentView(_),
            ..
        }) => body.to_json(),
        other => panic!("review.assignments gave {other:?}"),
    }
}

/// The outcome of one check of an assignment view.
fn check(view: &Value, name: &str) -> String {
    view.as_object()
        .and_then(|o| o.get("checks"))
        .and_then(Value::as_object)
        .and_then(|o| o.get(name))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Assigns `reviewer` to PR1 through the coordinator's page route.
fn assign(c: &FakeCell, login: &super::WebLogin, reviewer: fstp_domain::id::AccountId) {
    let path = format!("/proposals/{}/assignments", PR1.raw());
    let body = format!(
        r#"{{"reviewer":"{}","kind":{{"type":"Reviewer"}}}}"#,
        reviewer.raw()
    );
    let r = c.web(login, decode_route(Method::Post, &path, body.as_bytes()));
    assert!(matches!(r, Ok(OpResult::Done { .. })), "assign: {r:?}");
}

/// R-CF-03, SoD-10, I-34, design section 2.2 J5: the assignment view
/// lists the assignees and candidates by label, and its P-39 check
/// counts the organisations of the assignees' committee bindings. Two
/// reviewers of O1 fail P-39 = 2, and a third of O2 passes it. The
/// checks state pass or fail only.
#[test]
fn r_cf_03_assignment_view_p39_counts_the_assignees_organisations() {
    let c = cell_of(&review_world(BTreeMap::new()));
    for (a, label) in [(R1, "Member R1"), (R2, "Member R2"), (R4, "Member R4")] {
        c.ports.accounts.name(a, label);
    }
    let coordinator = c.login(COORDINATOR, LoginMethod::Passkey);
    let before = assignment_view(&c, &coordinator);
    let text = fstp_json::to_canonical(&before).unwrap();
    assert!(text.contains(r#""state":"SUBMITTED""#), "{text}");
    assert!(text.contains(r#""assigned":[]"#), "{text}");
    for label in ["Member R1", "Member R2", "Member R4"] {
        assert!(text.contains(label), "{label} is a candidate: {text}");
    }
    assert_eq!(check(&before, "p39"), "fail", "no assignee yet");
    assign(&c, &coordinator, R1);
    assign(&c, &coordinator, R4);
    let same_org = assignment_view(&c, &coordinator);
    assert_eq!(check(&same_org, "p39"), "fail", "R1 and R4 share O1");
    assign(&c, &coordinator, R2);
    let spread = assignment_view(&c, &coordinator);
    assert_eq!(check(&spread, "p39"), "pass", "O1 and O2");
    assert_eq!(check(&spread, "proximity"), "pass", "no P-38 list");
    let text = fstp_json::to_canonical(&spread).unwrap();
    assert!(text.contains(r#""label":"Member R2""#), "{text}");
    for field in ["\"email\"", "\"name\"", "\"organisation\""] {
        assert!(!text.contains(field), "{field} in {text}");
    }
}

/// SoD-11, I-35, `overview.md` NOTE 5: the proximity check asks the vault
/// whether the team declares an affiliation on the P-38 list of an
/// assignee's organisation, records each answer, and fails once the vault
/// answers yes.
#[test]
fn i35_assignment_view_proximity_asks_the_vault_and_records_the_answer() {
    let c = cell_of(&review_world([(O1, LIST_1)].into_iter().collect()));
    let coordinator = c.login(COORDINATOR, LoginMethod::Passkey);
    assign(&c, &coordinator, R1);
    let recorded = c.ports.vault_audit.records().len();
    let clear = assignment_view(&c, &coordinator);
    assert_eq!(check(&clear, "proximity"), "pass");
    let asked = |c: &FakeCell| {
        c.ports
            .vault
            .port_asks()
            .iter()
            .filter(|(q, _)| matches!(q, Query::DeclaresAffiliationOnList { list, .. } if *list == LIST_1))
            .count()
    };
    assert_eq!(asked(&c), 1, "one question for R1's list");
    assert_eq!(
        c.ports.vault_audit.records().len(),
        recorded.saturating_add(1)
    );
    c.ports.vault.change(|t| t.declare_affiliation(L1, LIST_1));
    let near = assignment_view(&c, &coordinator);
    assert_eq!(check(&near, "proximity"), "fail");
    assert_eq!(asked(&c), 2);
}

/// R-AC-01, R-EV-01: the assignment view is the coordinator's. A
/// committee member and the lead are refused under R-AC-01.
#[test]
fn r_ac_01_assignment_view_refuses_a_member_and_the_lead() {
    let c = cell_of(&review_world(BTreeMap::new()));
    let path = format!("/proposals/{}/assignments", PR1.raw());
    for who in [R1, L1] {
        let login = c.login(who, LoginMethod::Passkey);
        match c.web(&login, decode_route(Method::Get, &path, &[])) {
            Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "R-AC-01", "{who:?}"),
            other => panic!("{who:?}: {other:?}"),
        }
    }
}

/// R-EV-08, R-AC-01, change D5, `reads.rs` unknown targets: a read of a
/// round this core did not see opened fails closed. A committee member
/// and an outsider both get the COMMITTEE rule's own R-AC-01, the answer
/// an outsider of a known round gets, so no refusal shows whether a
/// round exists. Without an account the read is refused as an actor. It
/// never answers with a made-up round.
#[test]
fn r_ev_08_round_this_core_did_not_open_fails_closed() {
    let c = cell_of(&review_world(BTreeMap::new()));
    let path = "/cut-off-rounds/77";
    for who in [R1, L1, COORDINATOR] {
        let login = c.login(who, LoginMethod::Passkey);
        match c.web(&login, decode_route(Method::Get, path, &[])) {
            Err(ApiError::Refused {
                code: ErrorCode::Refused,
                rule,
                ..
            }) => assert_eq!(rule, "R-AC-01", "{who:?}"),
            other => panic!("{who:?}: {other:?}"),
        }
    }
    let r = c.call(
        fstp_api_core::Credential::None,
        decode_route(Method::Get, path, &[]),
    );
    assert!(
        matches!(
            &r,
            Err(ApiError::Refused {
                code: ErrorCode::Unauthenticated,
                ..
            })
        ),
        "{r:?}"
    );
}

/// I-86, `overview.md` NOTE 5: the caller's own verification state asks
/// the vault about the caller's account and no other, records the
/// answer, and carries the state only.
#[test]
fn i86_own_verification_state_asks_about_the_caller_only() {
    let c = FakeCell::new().unwrap();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let recorded = c.ports.vault_audit.records().len();
    let r = c.web(&lead, decode_route(Method::Get, "/me/verification", &[]));
    let body = match r {
        Ok(OpResult::Done {
            body: body @ ReadModel::Verification(_),
            ..
        }) => body,
        other => panic!("me.get_verification gave {other:?}"),
    };
    assert_eq!(
        fstp_json::to_canonical(&body.to_json()).unwrap(),
        r#"{"status":"verified"}"#
    );
    let asks = c.ports.vault.port_asks();
    assert_eq!(asks.len(), 1, "{asks:?}");
    assert!(
        matches!(&asks[0].0, Query::IsVerified { account } if *account == LEAD),
        "{asks:?}"
    );
    assert_eq!(
        c.ports.vault_audit.records().len(),
        recorded.saturating_add(1)
    );
}

/// I-86: a verification the caller began reads "pending" while the vault
/// has not verified the account.
#[test]
fn i86_begun_verification_reads_pending_until_verified() {
    let c = FakeCell::new().unwrap();
    let stranger = fixture::new_member(7);
    let login = c.login(stranger, LoginMethod::Passkey);
    let status =
        |c: &FakeCell| match c.web(&login, decode_route(Method::Get, "/me/verification", &[])) {
            Ok(OpResult::Done { body, .. }) => fstp_json::to_canonical(&body.to_json()).unwrap(),
            other => panic!("me.get_verification gave {other:?}"),
        };
    assert_eq!(status(&c), r#"{"status":"unverified"}"#);
    let r = c.web(
        &login,
        decode_route(Method::Post, "/me/verification", b"{}"),
    );
    assert!(matches!(r, Ok(OpResult::Done { .. })), "{r:?}");
    assert_eq!(status(&c), r#"{"status":"pending"}"#);
}

/// I-86: a begun verification the vault never confirms, as one it
/// rejected, stops reading "pending" once its bound of one hour has
/// passed, without a restart of the core. It reads "unverified" again.
#[test]
fn i86_unconfirmed_verification_stops_reading_pending() {
    let c = FakeCell::new().unwrap();
    let stranger = fixture::new_member(7);
    let status = |c: &FakeCell| {
        let login = c.login(stranger, LoginMethod::Passkey);
        match c.web(&login, decode_route(Method::Get, "/me/verification", &[])) {
            Ok(OpResult::Done { body, .. }) => fstp_json::to_canonical(&body.to_json()).unwrap(),
            other => panic!("me.get_verification gave {other:?}"),
        }
    };
    let login = c.login(stranger, LoginMethod::Passkey);
    let r = c.web(
        &login,
        decode_route(Method::Post, "/me/verification", b"{}"),
    );
    assert!(matches!(r, Ok(OpResult::Done { .. })), "{r:?}");
    c.ports.clock.advance(3_600_000_000 - 1);
    assert_eq!(status(&c), r#"{"status":"pending"}"#);
    c.ports.clock.advance(1);
    assert_eq!(status(&c), r#"{"status":"unverified"}"#);
}

/// R-SB-03, R-EV-04, `roles-and-sod.md` Receiving bindings: a withdrawal
/// ends the team's bindings, so `proposal.view` refuses the lead under
/// R-AC-01. The lead's own list still holds the proposal in its final
/// state, and another account's list does not.
#[test]
fn r_sb_03_withdrawn_proposal_stays_in_the_leads_own_list() {
    let c = FakeCell::new().unwrap();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let path = format!("/proposals/{}/withdrawal", PX.raw());
    let r = c.web(&lead, decode_route(Method::Post, &path, b"{}"));
    assert!(matches!(r, Ok(OpResult::Done { .. })), "withdraw: {r:?}");
    let view = format!("/proposals/{}", PX.raw());
    match c.web(&lead, decode_route(Method::Get, &view, &[])) {
        Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "R-AC-01"),
        other => panic!("proposal.view gave {other:?}"),
    }
    let own = |who| {
        let login = c.login(who, LoginMethod::Passkey);
        match c.web(&login, decode_route(Method::Get, "/me/proposals", &[])) {
            Ok(OpResult::Done {
                body: ReadModel::OwnProposals(list),
                ..
            }) => list,
            other => panic!("proposal.list_own gave {other:?}"),
        }
    };
    let mine = own(LEAD);
    let row = mine
        .iter()
        .find(|p| p.proposal == PX)
        .unwrap_or_else(|| panic!("{mine:?}"));
    assert_eq!(row.state, "WITHDRAWN");
    assert_eq!(row.role, "lead");
    assert!(
        own(OTHER).iter().all(|p| p.proposal != PX),
        "only the team lists it"
    );
}

/// I-34, SoD-10, `state-machine.md` NOTE 8: the assignment view counts
/// the assignments of the proposal's current call only, as the domain's
/// I-34 count does. In the twin witness PB is deferred with its call 1
/// reviewers still unreleased, re-enters call 2 and gets R1 and R2
/// assigned afresh there. The view lists the two call 2 assignments and
/// none of call 1.
#[test]
fn i34_assignment_view_counts_the_current_call_only() {
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain_testkit::r#gen::money::PB;
    let witness = fstp_domain_testkit::r#gen::twin::witness_run().unwrap();
    let twin = &witness.pair.a;
    let (store, _, _) = twin.scenario.engine().clone().into_parts();
    let world = World {
        store,
        truth: twin.scenario.truth().clone(),
        start: witness.ghost.now,
        admins: BTreeSet::new(),
    };
    let reviewer_assignments = |call: fstp_domain::id::CallId| -> BTreeSet<u128> {
        twin.observed
            .core
            .review()
            .assignments()
            .filter(|(_, a)| {
                a.proposal == PB
                    && a.call == call
                    && a.kind == AssignmentKind::Reviewer
                    && a.unreleased()
            })
            .map(|(id, _)| id.raw())
            .collect()
    };
    let old = reviewer_assignments(roster::call(1));
    let current = reviewer_assignments(roster::call(2));
    assert!(!old.is_empty(), "deferral released no call 1 assignment");
    assert_eq!(current.len(), 2, "{current:?}");
    let c = cell_of(&world);
    let coordinator = c.login(COORDINATOR, LoginMethod::Passkey);
    let path = format!("/proposals/{}/assignments", PB.raw());
    let view = match c.web(&coordinator, decode_route(Method::Get, &path, &[])) {
        Ok(OpResult::Done {
            body: body @ ReadModel::AssignmentView(_),
            ..
        }) => body.to_json(),
        other => panic!("review.assignments gave {other:?}"),
    };
    let listed: BTreeSet<u128> = view
        .as_object()
        .and_then(|o| o.get("assigned"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{view:?}"))
        .iter()
        .filter_map(|r| r.as_object()?.get("assignment")?.as_str()?.parse().ok())
        .collect();
    assert_eq!(listed, current, "only the call 2 assignments");
}
