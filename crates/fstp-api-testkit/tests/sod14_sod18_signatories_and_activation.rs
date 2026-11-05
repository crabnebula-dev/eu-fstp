//! Financial and Legal signatories and organisation activation through
//! `ApiCore::dispatch` (SA-01, SA-02; `SPEC/02-domain/roles-and-sod.md`
//! SoD-07, SoD-14 to SoD-18 and NOTE 5; `authentication.md` I-77 and
//! I-78; M4 design section 15.0, re-granting a role).
//!
//! Lane m4/roles, test author. The wire and the readings these tests pin
//! are listed in [`signatories`]. Until the tenant crate holds the two
//! roles and the activation request and approval, every test here is red:
//! the first new operation it sends answers that its route does not exist.
//!
//! What the signatories later approve, such as payment instructions and
//! contracts, arrives in M5. No test here names those acts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod signatories;

use fstp_api_core::OpResult;
use fstp_api_core::port::LoginMethod;
use fstp_api_testkit::fake::step_up::P71_MICROS;
use fstp_json::Value;

use signatories::{
    A1, A2, BOTH, FINANCIAL, LEGAL, OUTSIDER, S1, S2, activation, active, appended, approve,
    assert_refused, assert_rule, begun, complete, completed, done, end, ending, fresh, grant,
    granted, holders, login, member, missing_rule, onboarded, request, request_id, row,
    save_administrators, state, stepped, text, walk_to_administrators, wants_step_up, weak_login,
};

// ---------------------------------------------------------------------------
// SoD-14 and SoD-15: activation needs a holder of each signatory role
// ---------------------------------------------------------------------------

/// SoD-14: with a Legal signatory but no Financial signatory, the
/// activation request is refused naming SoD-14. It appends nothing, and
/// the organisation stays not requested.
#[test]
fn sod14_activation_request_without_a_financial_signatory_names_sod14() {
    let (c, l1, _) = onboarded(&[(S1, LEGAL)]);
    let before = appended(&c);
    assert_rule(&request(&c, &l1), "SoD-14", "SoD-14: the request");
    assert_eq!(appended(&c), before, "SoD-14: the refusal appended");
    assert_eq!(state(&c, &l1), "not_requested");
}

/// SoD-15: with a Financial signatory but no Legal signatory, the
/// activation request is refused naming SoD-15, and appends nothing.
#[test]
fn sod15_activation_request_without_a_legal_signatory_names_sod15() {
    let (c, l1, _) = onboarded(&[(S1, FINANCIAL)]);
    let before = appended(&c);
    assert_rule(&request(&c, &l1), "SoD-15", "SoD-15: the request");
    assert_eq!(appended(&c), before, "SoD-15: the refusal appended");
    assert_eq!(state(&c, &l1), "not_requested");
}

/// SoD-14, SoD-15: with no signatory at all, the request is refused
/// naming one of the two rules, and appends nothing.
#[test]
fn sod14_sod15_activation_request_without_any_signatory_names_a_missing_role() {
    let (c, l1, _) = onboarded(&[]);
    let before = appended(&c);
    let r = request(&c, &l1);
    let ok = matches!(
        &r,
        Err(fstp_api_core::ApiError::Refused { rule, .. }) if *rule == "SoD-14" || *rule == "SoD-15"
    );
    assert!(ok, "SoD-14, SoD-15: the request gave {r:?}");
    assert_eq!(appended(&c), before);
}

/// SoD-14, SoD-15: with a holder of each role, A1's request is recorded.
/// The activation read shows it as requested by A1, with a request id,
/// and the organisation is not active yet (SoD-18).
#[test]
fn sod14_sod15_activation_request_with_both_signatories_is_recorded() {
    let (c, l1, _) = onboarded(&[(S1, FINANCIAL), (S2, LEGAL)]);
    let before = appended(&c);
    let _ = done(request(&c, &l1), "SoD-14, SoD-15: the request");
    assert_eq!(appended(&c), before.saturating_add(1), "one entry");
    let v = activation(&c, &l1);
    assert_eq!(text(&v, "state"), "requested", "{v:?}");
    assert_eq!(text(&v, "requested_by"), A1.raw().to_string(), "{v:?}");
    assert!(
        !text(&v, "request").is_empty(),
        "SoD-18: no request id: {v:?}"
    );
}

/// SoD-14, SoD-15, onboarding table of `programme-creator.md`: the
/// Administrators step validates only with at least one holder of each
/// signatory role. With two admins and no signatory it saves without
/// validating. Once both roles are held, the same save validates.
#[test]
fn sod14_sod15_administrators_step_needs_both_signatories() {
    let c = fresh();
    let l1 = login(&c, A1);
    walk_to_administrators(&c, &l1);
    let none = save_administrators(&c, &l1);
    assert_ne!(
        none, "validated",
        "SoD-14: Administrators without signatories"
    );
    granted(&c, &l1, S1, FINANCIAL);
    let financial_only = save_administrators(&c, &l1);
    assert_ne!(
        financial_only, "validated",
        "SoD-15: Administrators without a Legal signatory"
    );
    granted(&c, &l1, S1, LEGAL);
    assert_eq!(save_administrators(&c, &l1), "validated", "SoD-14, SoD-15");
}

/// SoD-14, SoD-15: the approval checks the holders again. A1 requests
/// with a holder of each role, then ends the only Legal signatory, which
/// SoD-17 allows while the organisation is not active. A2's approval is
/// then refused naming SoD-15, and the organisation stays not active.
/// The same holds for the Financial signatory and SoD-14.
#[test]
fn sod14_sod15_approval_checks_the_signatories_again() {
    for role in BOTH {
        let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
        let _ = done(request(&c, &l1), "the request");
        let id = request_id(&c, &l1);
        let _ = done(
            ending(&c, &l1, S1, role),
            &format!("SoD-17: ending {role} before activation"),
        );
        let before = appended(&c);
        assert_rule(
            &approve(&c, &l2, &id),
            missing_rule(role),
            &format!("the approval with no holder of {role}"),
        );
        assert_eq!(appended(&c), before, "the refused approval appended");
        assert_ne!(state(&c, &l1), "active", "{role}");
    }
}

// ---------------------------------------------------------------------------
// SoD-16: one account may hold both roles
// ---------------------------------------------------------------------------

/// SoD-16: S1 holds both signatory roles. The list shows S1 once per
/// role, and that suffices for SoD-14 and SoD-15: A1 requests and A2
/// approves, and the organisation is active.
#[test]
fn sod16_one_account_may_hold_both_signatory_roles() {
    let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let want = [row(S1, FINANCIAL), row(S1, LEGAL)].into_iter().collect();
    assert_eq!(holders(&c, &l1), want, "SoD-16");
    let _ = done(request(&c, &l1), "SoD-16: the request");
    let id = request_id(&c, &l1);
    let _ = done(approve(&c, &l2, &id), "SoD-16: the approval");
    assert_eq!(state(&c, &l1), "active");
}

// ---------------------------------------------------------------------------
// SoD-17: the last holder stays while the organisation is active
// ---------------------------------------------------------------------------

/// SoD-17: in an active organisation where S1 is the only holder of each
/// role, ending either binding is refused naming SoD-17. The refusal
/// comes before any step-up prompt (design 3.7 step 5), appends nothing,
/// and S1 is still listed.
#[test]
fn sod17_last_holder_is_kept_while_the_organisation_is_active() {
    let (c, l1, _) = active(&[(S1, FINANCIAL), (S1, LEGAL)]);
    for role in BOTH {
        let (entries, prompts) = (appended(&c), begun(&c));
        let r = c.web(&l1, end(S1, role));
        assert_rule(&r, "SoD-17", &format!("SoD-17: ending the last {role}"));
        assert_eq!(appended(&c), entries, "SoD-17: {role}");
        assert_eq!(begun(&c), prompts, "SoD-17: a step-up began for {role}");
        assert!(holders(&c, &l1).contains(&row(S1, role)), "SoD-17: {role}");
    }
}

/// SoD-17: before the approval the organisation is not active, so the
/// last holder may end. Without a request, and again with a request open,
/// ending S1's only binding of each role completes.
#[test]
fn sod17_last_holder_may_end_before_activation() {
    for requested in [false, true] {
        let (c, l1, _) = onboarded(&[(S1, FINANCIAL), (S2, LEGAL)]);
        if requested {
            let _ = done(request(&c, &l1), "the request");
        }
        let _ = done(
            ending(&c, &l1, S1, FINANCIAL),
            &format!("SoD-17: ending the last Financial signatory, requested {requested}"),
        );
        let _ = done(
            ending(&c, &l1, S2, LEGAL),
            &format!("SoD-17: ending the last Legal signatory, requested {requested}"),
        );
        assert!(holders(&c, &l1).is_empty(), "requested {requested}");
    }
}

/// SoD-17: in an active organisation, a holder may end while another
/// holder of the same role remains. Once one holder is left, ending it
/// is refused naming SoD-17.
#[test]
fn sod17_a_holder_may_end_while_another_remains() {
    for role in BOTH {
        let (c, l1, _) = active(&[(S1, FINANCIAL), (S1, LEGAL), (S2, role)]);
        let _ = done(
            ending(&c, &l1, S1, role),
            &format!("SoD-17: ending one of two holders of {role}"),
        );
        assert!(!holders(&c, &l1).contains(&row(S1, role)), "{role}");
        assert_rule(
            &ending(&c, &l1, S2, role),
            "SoD-17",
            &format!("SoD-17: ending the last holder of {role}"),
        );
        assert!(holders(&c, &l1).contains(&row(S2, role)), "{role}");
    }
}

// ---------------------------------------------------------------------------
// SoD-18: a second tenant admin approves activation
// ---------------------------------------------------------------------------

/// SoD-18: A1 requested activation, so A1's approval is refused naming
/// SoD-18. It appends nothing and the request stays open.
#[test]
fn sod18_the_requester_cannot_approve_activation() {
    let (c, l1, _) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let _ = done(request(&c, &l1), "the request");
    let id = request_id(&c, &l1);
    let before = appended(&c);
    assert_rule(&approve(&c, &l1, &id), "SoD-18", "SoD-18: self-approval");
    assert_eq!(appended(&c), before, "SoD-18: the refusal appended");
    assert_eq!(state(&c, &l1), "requested");
}

/// SoD-18, SA-02: A2, a tenant admin other than the requester, approves
/// A1's request. The approval appends one entry, the organisation is
/// active, and the read names both the requester and the approver.
#[test]
fn sod18_a_second_tenant_admin_approves_activation() {
    let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let _ = done(request(&c, &l1), "the request");
    let id = request_id(&c, &l1);
    let before = appended(&c);
    let _ = done(approve(&c, &l2, &id), "SoD-18: A2's approval");
    assert_eq!(appended(&c), before.saturating_add(1), "SoD-18: one entry");
    let v = activation(&c, &l2);
    assert_eq!(text(&v, "state"), "active", "{v:?}");
    assert_eq!(text(&v, "requested_by"), A1.raw().to_string(), "{v:?}");
    assert_eq!(text(&v, "approved_by"), A2.raw().to_string(), "{v:?}");
}

/// SoD-18: the approval is bound to the request. With no request open,
/// an approval is refused. With A1's request open, an approval that names
/// another request id is refused. Neither appends, and only the approval
/// naming the open request activates.
#[test]
fn sod18_approval_is_bound_to_the_open_request() {
    let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let before = appended(&c);
    assert_refused(
        &approve(&c, &l2, "1"),
        "SoD-18: an approval with no request",
    );
    assert_eq!(appended(&c), before);
    let _ = done(request(&c, &l1), "the request");
    let id = request_id(&c, &l1);
    let other = format!("{id}9");
    let before = appended(&c);
    assert_refused(
        &approve(&c, &l2, &other),
        "SoD-18: an approval of another request",
    );
    assert_eq!(appended(&c), before);
    assert_eq!(state(&c, &l1), "requested");
    let _ = done(approve(&c, &l2, &id), "SoD-18: the approval of the request");
    assert_eq!(state(&c, &l1), "active");
}

/// SoD-18: one admin alone never activates the organisation. A1 sends
/// the single-step completion of before SoD-18, a request and an
/// approval of its own request, each with a step-up where asked. The
/// organisation is not active after any of them.
#[test]
fn sod18_one_admin_alone_never_activates() {
    let (c, l1, _) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let _ = stepped(&c, &l1, &complete);
    assert_ne!(
        state(&c, &l1),
        "active",
        "SoD-18: tenant.complete activated"
    );
    let _ = request(&c, &l1);
    let id = request_id(&c, &l1);
    let _ = approve(&c, &l1, &id);
    assert_ne!(state(&c, &l1), "active", "SoD-18: A1 alone activated");
}

/// SoD-18: an active organisation is activated once. A further request
/// is refused and appends nothing.
#[test]
fn sod18_an_active_organisation_takes_no_further_request() {
    let (c, _, l2) = active(&[(S1, FINANCIAL), (S1, LEGAL)]);
    let before = appended(&c);
    assert_refused(&request(&c, &l2), "SoD-18: a request after activation");
    assert_eq!(appended(&c), before);
}

// ---------------------------------------------------------------------------
// I-78 and I-77: granting and ending an Operations role is high-risk
// ---------------------------------------------------------------------------

/// I-78 (`authentication.md`, high-risk table: granting or changing an
/// Operations role): a grant of either signatory role without a proof
/// asks for a step-up and appends nothing. With a proof for the
/// challenged digest it completes once. The proof is consumed, so a
/// second grant prompts again.
#[test]
fn i78_granting_either_signatory_role_needs_a_digest_bound_step_up() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        let op = || grant(S1, role);
        let ch = match c.web(&l1, op()) {
            Ok(OpResult::StepUpRequired(ch)) => ch,
            other => panic!("I-78: a grant of {role} without a proof: {other:?}"),
        };
        assert_eq!(appended(&c), 0, "I-78: {role} appended before its step-up");
        c.ports.step_up.approve(l1.session, ch.action).unwrap();
        let _ = done(c.web(&l1, op()), &format!("I-78: {role} with its proof"));
        assert_eq!(appended(&c), 1, "I-78: {role} appended once");
        assert_eq!(holders(&c, &l1), [row(S1, role)].into_iter().collect());
        let again = c.web(&l1, grant(S2, role));
        assert!(
            wants_step_up(&again),
            "I-78: a second grant of {role} reused a consumed proof: {again:?}"
        );
        assert_eq!(appended(&c), 1);
    }
}

/// I-78: ending either signatory role is a change of an Operations role.
/// Without a proof it asks for a step-up and appends nothing. With the
/// proof it completes once.
#[test]
fn i78_ending_either_signatory_role_needs_a_digest_bound_step_up() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        granted(&c, &l1, S1, role);
        let before = appended(&c);
        let op = || end(S1, role);
        let ch = match c.web(&l1, op()) {
            Ok(OpResult::StepUpRequired(ch)) => ch,
            other => panic!("I-78: ending {role} without a proof: {other:?}"),
        };
        assert_eq!(
            appended(&c),
            before,
            "I-78: {role} ended before its step-up"
        );
        c.ports.step_up.approve(l1.session, ch.action).unwrap();
        let _ = done(
            c.web(&l1, op()),
            &format!("I-78: ending {role} with its proof"),
        );
        assert_eq!(appended(&c), before.saturating_add(1));
        assert!(holders(&c, &l1).is_empty(), "I-78: {role} still listed");
    }
}

/// I-78: the step-up must be fresh within P-71. A proof older than P-71
/// does not complete a grant or an end: the call asks for a step-up
/// again, or is refused, and appends nothing.
#[test]
fn i78_a_stale_step_up_neither_grants_nor_ends_a_signatory_role() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        let ch = match c.web(&l1, grant(S1, role)) {
            Ok(OpResult::StepUpRequired(ch)) => ch,
            other => panic!("I-78: a grant of {role} without a proof: {other:?}"),
        };
        c.ports.step_up.approve(l1.session, ch.action).unwrap();
        c.ports.clock.advance(P71_MICROS.saturating_add(1));
        let r = c.web(&l1, grant(S1, role));
        assert!(!completed(&r), "I-78: a stale proof granted {role}: {r:?}");
        assert_eq!(appended(&c), 0, "I-78: {role}");

        granted(&c, &l1, S1, role);
        let before = appended(&c);
        let ch = match c.web(&l1, end(S1, role)) {
            Ok(OpResult::StepUpRequired(ch)) => ch,
            other => panic!("I-78: ending {role} without a proof: {other:?}"),
        };
        c.ports.step_up.approve(l1.session, ch.action).unwrap();
        c.ports.clock.advance(P71_MICROS.saturating_add(1));
        let r = c.web(&l1, end(S1, role));
        assert!(!completed(&r), "I-78: a stale proof ended {role}: {r:?}");
        assert_eq!(appended(&c), before, "I-78: {role}");
    }
}

/// I-78: one step-up authorises one command, bound to its digest. A proof
/// for granting Financial signatory to S1 does not grant Legal signatory
/// to S1, nor Financial signatory to S2.
#[test]
fn i78_a_proof_for_one_signatory_grant_authorises_no_other() {
    let c = fresh();
    let l1 = login(&c, A1);
    let ch = match c.web(&l1, grant(S1, FINANCIAL)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: a grant without a proof: {other:?}"),
    };
    c.ports.step_up.approve(l1.session, ch.action).unwrap();
    for (account, role) in [(S1, LEGAL), (S2, FINANCIAL)] {
        let r = c.web(&l1, grant(account, role));
        assert!(
            wants_step_up(&r),
            "I-78: the proof for S1 Financial authorised {role} to {}: {r:?}",
            account.raw()
        );
    }
    assert_eq!(appended(&c), 0);
}

/// I-77: an admin in a magic-link session can neither grant nor end a
/// signatory role. No step-up begins and nothing is appended.
#[test]
fn i77_signatory_grant_and_end_refuse_a_weak_session() {
    let c = fresh();
    let weak = c.login(A1, LoginMethod::MagicLink);
    for role in BOTH {
        for (what, r) in [
            ("grant", c.web(&weak, grant(S1, role))),
            ("end", c.web(&weak, end(S1, role))),
        ] {
            assert!(weak_login(&r), "I-77: {what} of {role} gave {r:?}");
        }
    }
    assert_eq!(begun(&c), 0);
    assert_eq!(appended(&c), 0);
}

// ---------------------------------------------------------------------------
// SoD-07, NOTE 5, re-grants and the actor
// ---------------------------------------------------------------------------

/// SoD-07, NOTE 5: a tenant admin granting either signatory role to their
/// own account needs a second tenant admin's approval. Without one, A1's
/// grant to A1 is refused naming SoD-07, before any step-up prompt, and
/// appends nothing. A2's grant of the same role to A1 is no self-grant,
/// and completes.
#[test]
fn sod07_self_grant_of_either_signatory_role_is_refused() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        let l2 = login(&c, A2);
        let r = c.web(&l1, grant(A1, role));
        assert_rule(&r, "SoD-07", &format!("SoD-07: A1 grants {role} to A1"));
        assert_eq!(begun(&c), 0, "SoD-07: a step-up began for {role}");
        assert_eq!(appended(&c), 0, "SoD-07: {role}");
        granted(&c, &l2, A1, role);
        assert_eq!(holders(&c, &l1), [row(A1, role)].into_iter().collect());
    }
}

/// NOTE 5: a signatory binding is tenant-wide. Its row in the list names
/// no programme, and a grant whose body names a programme is refused as a
/// bad request, appending nothing.
#[test]
fn note5_a_signatory_binding_names_no_programme() {
    let c = fresh();
    let l1 = login(&c, A1);
    granted(&c, &l1, S1, FINANCIAL);
    let v = done(c.web(&l1, signatories::list_signatories()), "the list");
    let Value::Array(rows) = member(&v, "signatories") else {
        panic!("SA-01: no signatory array: {v:?}");
    };
    assert!(!rows.is_empty(), "SA-01: {v:?}");
    for r in rows.iter() {
        assert_eq!(member(r, "programme"), Value::Null, "NOTE 5: {r:?}");
    }
    let before = appended(&c);
    let body = format!(
        r#"{{"account":"{}","programme":"1","role":"{LEGAL}"}}"#,
        S1.raw()
    );
    let r = stepped(&c, &l1, &|| {
        fstp_api_core::decode::decode_route(
            fstp_api_core::decode::Method::Post,
            "/admin/signatories",
            body.as_bytes(),
        )
    });
    match &r {
        Err(fstp_api_core::ApiError::Refused { code, .. })
            if *code == fstp_api_core::ErrorCode::BadRequest => {}
        other => panic!("NOTE 5: a grant naming a programme gave {other:?}"),
    }
    assert_eq!(appended(&c), before);
}

/// NOTE 5, SoD-09: a signatory binding needs no verified identity. S2,
/// whom the vault has not verified, is granted either role.
#[test]
fn note5_a_signatory_grant_needs_no_verified_identity() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        granted(&c, &l1, S2, role);
        assert_eq!(holders(&c, &l1), [row(S2, role)].into_iter().collect());
    }
}

/// M4 design section 15.0 (Daniel, 2026-10-31): a role is granted again
/// only after the account's binding of it ends. A second grant of the
/// same role to S1 is refused and appends nothing. After the end, the
/// grant completes again.
#[test]
fn regrant_signatory_role_is_granted_again_only_after_it_ends() {
    for role in BOTH {
        let c = fresh();
        let l1 = login(&c, A1);
        granted(&c, &l1, S1, role);
        let before = appended(&c);
        assert_refused(
            &stepped(&c, &l1, &|| grant(S1, role)),
            &format!("15.0: a second grant of {role} to S1"),
        );
        assert_eq!(appended(&c), before, "15.0: {role}");
        let _ = done(ending(&c, &l1, S1, role), "the end");
        granted(&c, &l1, S1, role);
        assert_eq!(holders(&c, &l1), [row(S1, role)].into_iter().collect());
    }
}

/// Q31, SA-01: only a tenant admin grants, ends or lists signatory roles,
/// and requests or approves activation. An account outside the admin set
/// is refused each, with no step-up begun and nothing appended.
#[test]
fn q31_only_a_tenant_admin_manages_signatories_and_activation() {
    let c = fresh();
    let lo = login(&c, OUTSIDER);
    for (what, r) in [
        ("grant", c.web(&lo, grant(S1, FINANCIAL))),
        ("end", c.web(&lo, end(S1, FINANCIAL))),
        ("list", c.web(&lo, signatories::list_signatories())),
        ("read", c.web(&lo, signatories::get_activation())),
        ("request", c.web(&lo, signatories::request_activation())),
        ("approve", c.web(&lo, signatories::approve_activation("1"))),
    ] {
        assert_refused(&r, &format!("Q31: an outsider's {what}"));
    }
    assert_eq!(begun(&c), 0);
    assert_eq!(appended(&c), 0);
}
