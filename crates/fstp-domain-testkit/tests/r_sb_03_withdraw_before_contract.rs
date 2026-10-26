//! R-SB-03 and NOTE 10: withdrawal by the lead (design 3.2 row 15).
//!
//! Withdrawal is open in DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED,
//! IRC_REVIEW, DEFERRED and NOTE 10's NEGOTIATION. This lane reaches DRAFT
//! and SUBMITTED by commands. The other six states, GRANTED and
//! IN_EXECUTION are reached by folding the stage rows structurally, as the
//! teeth tests do, until lanes L-LIFE and L-MONEY record them. The batch
//! records the transition to WITHDRAWN and ends the proposal's Receiving
//! bindings in the same batch (Q11), each pinning its cooling-off bar.
//! Terminal states have no exits.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::id::ProposalId;
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::review::{
    L1, L4, MEMBER, PR1, PR4, STRANGER, machine_accounts, machine_setup, plan_of, records_of,
    review_truth, run_records, scenario_from, submit, withdraw,
};
use fstp_domain_testkit::r#gen::roster::T0;
use fstp_domain_testkit::scenario::Scenario;

fn start() -> Scenario {
    scenario_from(&machine_setup(), review_truth(machine_accounts()))
        .unwrap_or_else(|e| panic!("setup from genesis: {e}"))
}

fn receiving_bindings(s: &Scenario, proposal: ProposalId) -> Vec<fstp_domain::id::BindingId> {
    records_of(s)
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            Record::BindingGranted(g)
                if matches!(g.scope, BindingScope::Proposal { proposal: p, .. } if p == proposal)
                    && matches!(
                        g.role,
                        Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
                    ) =>
            {
                Some(g.binding)
            }
            _ => None,
        })
        .collect()
}

fn withdrawn(
    s: &mut Scenario,
    lead: fstp_domain::id::AccountId,
    proposal: ProposalId,
    from: StateTag,
) {
    let bindings = receiving_bindings(s, proposal);
    let records = run_records(s, &withdraw(lead, proposal), T0)
        .unwrap()
        .unwrap_or_else(|r| panic!("R-SB-03: the withdrawal from {from:?} was refused: {r}"));
    assert!(
        records.contains(&Record::Transitioned(Transitioned {
            proposal,
            from,
            to: StateTag::Withdrawn,
            row: Row::Withdraw,
            actor: Actor::Account(lead),
            decision: None,
        })),
        "the batch records the transition: {records:?}"
    );
    for b in bindings {
        assert!(
            records
                .iter()
                .any(|r| matches!(r, Record::BindingEnded(e) if e.binding == b)),
            "Q11: the Receiving binding {b:?} ends in the same batch: {records:?}"
        );
    }
}

/// R-SB-03, NOTE 10: the lead withdraws a draft.
#[test]
fn r_sb_03_lead_withdraws_from_draft() {
    let mut s = start();
    withdrawn(&mut s, L4, PR4, StateTag::Draft);
}

/// R-SB-03, NOTE 10: the lead withdraws a submitted proposal, and the team
/// member's binding ends with the lead's.
#[test]
fn r_sb_03_lead_withdraws_from_submitted() {
    let mut s = start();
    withdrawn(&mut s, L1, PR1, StateTag::Submitted);
}

/// R-SB-03, actor: a team member and an unbound account cannot withdraw.
#[test]
fn r_sb_03_only_the_lead_withdraws() {
    let mut s = start();
    for actor in [MEMBER, STRANGER, L4] {
        assert!(
            run_records(&mut s, &withdraw(actor, PR1), T0)
                .unwrap()
                .is_err(),
            "{actor:?} withdrew the proposal of L1"
        );
    }
    withdrawn(&mut s, L1, PR1, StateTag::Submitted);
}

/// R-SB-03, NOTE 10: WITHDRAWN is terminal. A second withdrawal and a
/// submission after it are refused.
#[test]
fn r_sb_03_withdrawn_has_no_exit() {
    let mut s = start();
    withdrawn(&mut s, L4, PR4, StateTag::Draft);
    assert!(
        run_records(&mut s, &withdraw(L4, PR4), T0)
            .unwrap()
            .is_err()
    );
    assert!(
        run_records(&mut s, &submit(L4, PR4, plan_of(PR4), false), T0)
            .unwrap()
            .is_err()
    );
}

/// The stage rows from SUBMITTED to `to`, for the folded paths below.
fn path_to(to: StateTag) -> Vec<(StateTag, StateTag, Row)> {
    let chain = [
        (
            StateTag::Submitted,
            StateTag::Stage1,
            Row::SubmittedToStage1,
        ),
        (StateTag::Stage1, StateTag::Stage2, Row::Stage1ToStage2),
        (StateTag::Stage2, StateTag::Ranked, Row::Stage2ToRanked),
        (
            StateTag::Ranked,
            StateTag::IrcReview,
            Row::RankedToIrcReview,
        ),
        (
            StateTag::IrcReview,
            StateTag::Negotiation,
            Row::IrcReviewToNegotiation,
        ),
        (
            StateTag::Negotiation,
            StateTag::Granted,
            Row::NegotiationToGranted,
        ),
        (
            StateTag::Granted,
            StateTag::InExecution,
            Row::GrantedToInExecution,
        ),
    ];
    if to == StateTag::Deferred {
        let mut out: Vec<_> = chain.iter().take(2).copied().collect();
        out.push((StateTag::Stage2, StateTag::Deferred, Row::Stage2ToDeferred));
        return out;
    }
    let mut out = Vec::new();
    for step in chain {
        out.push(step);
        if step.1 == to {
            break;
        }
    }
    out
}

/// A production world from genesis with PR1 of L1 submitted, and PR1
/// folded to `to` through the structural fold, as the teeth tests do
/// until lanes L-LIFE and L-MONEY record these rows.
fn folded(to: StateTag) -> fstp_domain_testkit::r#gen::review::ReviewWorld {
    let setup = fstp_domain_testkit::mc::conflict_model::conflict_setup();
    let mut w = fstp_domain_testkit::r#gen::review::ReviewWorld::from_setup(
        fstp_domain_testkit::r#gen::roster::Backend::Production,
        review_truth(setup.accounts()),
        &setup,
        None,
    )
    .unwrap_or_else(|e| panic!("setup: {e}"));
    for (from, next, row) in path_to(to) {
        w.commit(&[Record::Transitioned(Transitioned {
            proposal: PR1,
            from,
            to: next,
            row,
            actor: Actor::Account(fstp_domain_testkit::r#gen::review::COORDINATOR),
            decision: None,
        })])
        .unwrap_or_else(|e| panic!("fold {row:?}: {e}"));
    }
    w
}

/// R-SB-03, NOTE 10: the lead withdraws from STAGE1, STAGE2, RANKED,
/// IRC_REVIEW, DEFERRED and NEGOTIATION, and the batch records the
/// transition to WITHDRAWN.
#[test]
fn r_sb_03_lead_withdraws_from_every_state_before_the_contract() {
    for from in [
        StateTag::Stage1,
        StateTag::Stage2,
        StateTag::Ranked,
        StateTag::IrcReview,
        StateTag::Deferred,
        StateTag::Negotiation,
    ] {
        let mut w = folded(from);
        let records = w
            .exec(&withdraw(L1, PR1))
            .unwrap_or_else(|e| panic!("harness: {e}"))
            .unwrap_or_else(|r| panic!("R-SB-03: the withdrawal from {from:?} was refused: {r}"));
        assert!(
            records.contains(&Record::Transitioned(Transitioned {
                proposal: PR1,
                from,
                to: StateTag::Withdrawn,
                row: Row::Withdraw,
                actor: Actor::Account(L1),
                decision: None,
            })),
            "{from:?}: {records:?}"
        );
    }
}

/// R-SB-03, NOTE 10: once the contract is signed, withdrawal is closed.
/// GRANTED and IN_EXECUTION refuse it.
#[test]
fn r_sb_03_withdrawal_is_closed_after_the_contract() {
    for from in [StateTag::Granted, StateTag::InExecution] {
        let mut w = folded(from);
        assert!(
            matches!(w.exec(&withdraw(L1, PR1)), Ok(Err(_))),
            "R-SB-03: the lead withdrew from {from:?}"
        );
    }
}
