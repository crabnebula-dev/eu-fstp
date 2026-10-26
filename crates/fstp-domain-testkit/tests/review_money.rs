//! Review reproducers for lane L-MONEY (W5 independent review).
//!
//! Each test drives production `queries` and `decide` directly and folds
//! the records production emits, so the outcome does not depend on the
//! money reference. Each test fails against the current code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Answers;
use fstp_domain::id::{CommandId, LineId, RequestId};
use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneySetup, MoneyStory, PC, REL, accept_grant, amount_decision, approve_grant,
    contract_effective, determine, milestone_n, request_payment, start_execution,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step};

const CMD: CommandId = CommandId::from_bytes(*b"review:money:stp");

/// Production's verdict on `step`, without committing.
fn prod(s: &MoneyStory, step: &Step) -> Result<Vec<Record>, Refusal> {
    let w = &s.world;
    let state = &w.life.rev.sod.state;
    let ctx = step.ctx(w.now(), CMD);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
        let a = w.life.rev.answer(&q);
        answers.insert(q, a);
    }
    fstp_domain::decide(state, &step.cmd, &ctx, &answers)
}

/// Runs `step` on production and folds what it emits. `None` on a refusal.
fn go(s: &mut MoneyStory, step: &Step) -> Option<Vec<Record>> {
    let recs = prod(s, step).ok()?;
    s.world = s
        .world
        .inject(&recs)
        .unwrap_or_else(|e| panic!("fold of production's own batch: {e}"));
    Some(recs)
}

fn prod_state(s: &MoneyStory) -> Option<StateTag> {
    s.world.state(PC)
}

/// I-13, I-31, I-14 (contracts.md Amount and recipient cap, design 2.11
/// "the agreed plan total equals granted"): a grant determined with a
/// deduction must never let the grantee claim more than the granted amount.
/// Today the contract plan keeps the pre-deduction milestones, so a
/// request for the full plan total passes I-58 and exceeds the grant.
#[test]
fn review_payment_request_never_exceeds_granted_amount() {
    let mut setup = MoneySetup::sybil([400, 400, 400]);
    setup.drafts.retain(|d| d.proposal == PC);
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, Backend::Production)
        .unwrap_or_else(|e| panic!("c to NEGOTIATION from genesis: {e}"));
    let det = determine(R1, PC, amount_decision(PC, 1), plan_of(PC), &[100]).unwrap();
    if go(&mut s, &det).is_none() {
        // A fix that refuses a deduction the agreed plan does not carry.
        return;
    }
    for f in [
        accept_grant(LC, PC),
        approve_grant(STAFF_PM, PC),
        contract_effective(PC),
    ] {
        go(&mut s, &f);
    }
    if prod_state(&s) != Some(StateTag::Granted) {
        // A fix that refuses the grant whose agreed plan total is not the granted amount.
        return;
    }
    let granted = s
        .world
        .life
        .rev
        .sod
        .state
        .money()
        .granted(PC)
        .unwrap()
        .amount()
        .minor();
    assert_eq!(granted, 300, "4.00 minus the 1.00 deduction");
    go(&mut s, &start_execution(PC)).unwrap_or_else(|| panic!("execution starts"));
    let req = request_payment(
        LC,
        RequestId::from_raw(77_001),
        PC,
        &[(LineId::from_raw(177_001), milestone_n(PC, 0), 400)],
    )
    .unwrap();
    let out = prod(&s, &req);
    assert!(
        out.is_err(),
        "I-13/I-31: the grant is 3.00 but a request for 4.00 is accepted: {out:?}"
    );
}

/// NOTE 9, row NEGOTIATION to GRANTED: when the completing grant fact
/// meets a guard that fails only for now (the lead not yet verified), the
/// proposal must not be left with neither exit. Once the vault verifies
/// the lead, every guard of GRANTED holds, DeclineNegotiation has no
/// failure to record, and no command can reach GRANTED today.
#[test]
fn review_failed_clearance_is_not_a_dead_end() {
    let mut setup = MoneySetup::sybil([400, 400, 400]);
    setup.drafts.retain(|d| d.proposal == PC);
    setup.unverified = vec![LC];
    let mut s = MoneyStory::new(&setup, Backend::Production)
        .unwrap_or_else(|e| panic!("c to NEGOTIATION from genesis: {e}"));
    let det = determine(R1, PC, amount_decision(PC, 1), plan_of(PC), &[]).unwrap();
    go(&mut s, &det).unwrap_or_else(|| panic!("R1 determines 4.00"));
    let facts = [
        accept_grant(LC, PC),
        approve_grant(STAFF_PM, PC),
        contract_effective(PC),
    ];
    for f in &facts {
        go(&mut s, f);
    }
    assert_eq!(
        prod_state(&s),
        Some(StateTag::Negotiation),
        "SoD-09: an unverified lead is not granted"
    );
    s.world
        .vault(|t| t.verify(LC))
        .unwrap_or_else(|e| panic!("the vault verifies c: {e}"));
    let decline = fstp_domain_testkit::r#gen::money::decline_negotiation(
        fstp_domain::command::Actor::Account(STAFF_PM),
        PC,
    );
    assert!(
        prod(&s, &decline).is_err(),
        "NOTE 9: no failure holds once c is verified"
    );
    for f in facts.iter().rev() {
        if prod_state(&s) == Some(StateTag::Granted) {
            break;
        }
        go(&mut s, f);
    }
    assert_eq!(
        prod_state(&s),
        Some(StateTag::Granted),
        "every GRANTED guard holds, yet no command takes the proposal out of NEGOTIATION"
    );
}

/// NOTE 12, O-51 (design 6.1 reference twins): the money reference must
/// judge `CloseMilestone` now that the codec builds it. `ext_verdict` wants
/// a `MilestoneClosed` record but synthesises none, so every reference
/// twin that closes a milestone fails with an empty batch.
#[test]
fn review_reference_twin_closes_a_milestone() {
    let mut setup = MoneySetup::sybil([400, 400, 400]);
    setup.drafts.retain(|d| d.proposal == PC);
    let mut s = MoneyStory::new(&setup, Backend::Reference)
        .unwrap_or_else(|e| panic!("c to NEGOTIATION on the reference: {e}"));
    s.execute(PC)
        .unwrap_or_else(|e| panic!("c granted and in execution: {e}"));
    let x = fstp_domain_testkit::reference::money::Ext::CloseMilestone {
        proposal: PC,
        milestone: milestone_n(PC, 0),
    };
    let out = s.ext(fstp_domain::command::Actor::Account(STAFF_PM), x);
    assert!(
        matches!(out, Ok(Some(_))),
        "NOTE 12: the reference closes the milestone: {out:?}"
    );
}
