//! Review reproducers for lane L-MONEY, lens: model strength and races (W5 independent review).
//!
//! Each test builds its start state from genesis through the two-way
//! story, then drives production `queries` and `decide` directly for the
//! step under review. The records production emits are folded into
//! production and the reference views, so the final check reads the
//! independent money view. Each test fails against the current code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::{CommandId, LineId, RequestId};
use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::rules::StateTag;
use fstp_domain::{Answers, roles::Role};
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, LB, LC, MoneySetup, MoneyStory, MoneyWorld, PA, PB, PC, REL, accept_grant,
    accept_line, amount_decision, approve_grant, approve_payment, contract_effective,
    decline_negotiation, determine, milestone_n, release_payment, request_payment, terminate,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step};
use fstp_domain_testkit::reference::money::check_i14;

const REVIEW_COMMAND: CommandId = CommandId::from_bytes(*b"review:w5m:races");

/// Production alone on `step`: pending vault reactions first, then
/// `queries` and `decide`. Accepted records are folded into production
/// and every reference view through the structural `apply`.
fn production(w: &mut MoneyWorld, step: &Step) -> Result<Vec<Record>, Refusal> {
    w.sync().unwrap_or_else(|e| panic!("vault sync: {e}"));
    let state = &w.life.rev.sod.state;
    let ctx = step.ctx(w.now(), REVIEW_COMMAND);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
        let a = w.life.rev.answer(&q);
        answers.insert(q, a);
    }
    let records = fstp_domain::decide(state, &step.cmd, &ctx, &answers)?;
    *w = w
        .inject(&records)
        .unwrap_or_else(|e| panic!("folding production's records: {e}"));
    Ok(records)
}

/// The state of `p` in the lifecycle view, folded from production's records.
fn prod_state(w: &MoneyWorld, p: fstp_domain::id::ProposalId) -> Option<StateTag> {
    w.state(p)
}

/// Row NEGOTIATION to GRANTED, NOTE 9: a clearance that fails on a
/// transient guard (the lead is not yet verified) is recorded with the
/// last grant fact and no transition. Once the vault verifies the lead,
/// every guard holds. No command then takes the proposal out of
/// NEGOTIATION: each grant fact is refused as repeated, a new amount only
/// supersedes the old one (NOTE 9, decided 2026-10-28), and
/// DeclineNegotiation finds no failure.
#[test]
fn review_failed_grant_clearance_is_never_retried() {
    let mut setup = MoneySetup::sybil([400, 400, 300]);
    setup.drafts.retain(|d| d.proposal == PC);
    setup.unverified = vec![LC];
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 3.00: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("c accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    let _ = s
        .attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PC),
        Some(StateTag::Negotiation),
        "identity not verified yet: no GRANTED"
    );
    s.world
        .vault(|t| t.verify(LC))
        .unwrap_or_else(|e| panic!("the vault verifies c: {e}"));
    let mut w = s.world.clone();
    let tries = [
        contract_effective(PC),
        accept_grant(LC, PC),
        approve_grant(STAFF_PM, PC),
        decline_negotiation(Actor::Account(STAFF_PM), PC),
        determine(R1, PC, amount_decision(PC, 2), plan_of(PC), &[]).unwrap(),
    ];
    let mut refusals = Vec::new();
    for t in &tries {
        match production(&mut w, t) {
            Ok(_) => break,
            Err(r) => refusals.push(format!("{:?}: {r}", t.cmd)),
        }
    }
    assert_ne!(
        prod_state(&w, PC),
        Some(StateTag::Negotiation),
        "the lead is verified, consent is not needed, the amount is reserved within P-04 and \
         P-05, and the contract is EFFECTIVE, yet no command leaves NEGOTIATION: {refusals:#?}"
    );
}

/// NOTE 9, I-14, Identity discovery: leads a and b share one identity, b
/// unverified. Under P-04 = [3.00, 4.00] and P-05 = 6.00 each reserves
/// 4.00, b's cap group being b alone. The vault then verifies b. Now the
/// headroom of b is 6.00 - 4.00 = 2.00, below the P-04 minimum, so no
/// grant amount can keep I-13 and I-14. The programme manager must be
/// able to record NEGOTIATION to DECLINED. Production refuses, because it
/// skips the amount failures while a reservation is open.
#[test]
fn review_decline_when_discovery_leaves_no_cap_headroom() {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p04 = (300, 400);
    setup.unverified = vec![LB];
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b, unverified, reserves 4.00: {e}"));
    s.world
        .vault(|t| t.verify(LB))
        .unwrap_or_else(|e| panic!("the vault verifies b: {e}"));
    let mut w = s.world.clone();
    // The grant is now blocked by the cap, as it must be.
    for t in [
        accept_grant(LB, PB),
        approve_grant(STAFF_PM, PB),
        contract_effective(PB),
    ] {
        let _ = production(&mut w, &t);
    }
    assert_eq!(prod_state(&w, PB), Some(StateTag::Negotiation));
    let recs = production(&mut w, &decline_negotiation(Actor::Account(STAFF_PM), PB))
        .unwrap_or_else(|r| {
            panic!("NOTE 9: no amount of b can keep I-14 any more, yet the decline is refused: {r}")
        });
    let reason = recs.iter().find_map(|r| match r {
        Record::NegotiationDeclined { reason, .. } => Some(*reason),
        _ => None,
    });
    assert_eq!(reason, Some(NegotiationFailure::NoAmountWithinCap));
}

/// I-14 with I-64: a terminated grant counts only its paid total, which
/// frees cap headroom. A payment approved before the termination can still
/// be released afterwards, which raises the paid total again. Leads a and
/// b share one identity under P-05 = 6.00. a is granted 4.00 in one
/// milestone, the milestone is accepted and approved for payment, then the
/// grant is terminated (counted 0.00). b reserves 4.00. The release of a's
/// approved payment then takes the identity to 8.00, above P-05.
#[test]
fn review_i14_release_after_termination_exceeds_the_cap() {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.staff = vec![
        (FINREL, Role::FinanceApprover),
        (REL, Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("{e}"));
    s.execute(PA)
        .unwrap_or_else(|e| panic!("a granted 4.00 and in execution: {e}"));
    let r = RequestId::from_raw(36_001);
    let line = LineId::from_raw(136_001);
    s.run(&request_payment(LA, r, PA, &[(line, milestone_n(PA, 0), 400)]).unwrap())
        .unwrap_or_else(|e| panic!("a requests the milestone: {e}"));
    s.run(&accept_line(R1, r, line, 400, false).unwrap())
        .unwrap_or_else(|e| panic!("R1 accepts the line: {e}"));
    s.run(&approve_payment(FINREL, r))
        .unwrap_or_else(|e| panic!("the finance approver approves: {e}"));
    s.run(&terminate(STAFF_PM, PA))
        .unwrap_or_else(|e| panic!("the programme manager terminates a: {e}"));
    let mut w = s.world.clone();
    let b4 = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    let _ = production(&mut w, &b4);
    let _ = production(&mut w, &release_payment(REL, r));
    check_i14(&w.money, w.truth()).unwrap_or_else(|e| {
        panic!(
            "I-14: after the post-termination release the identity of a and b holds a's paid \
             {} plus b's {}: {e}",
            w.money.counted(PA),
            w.money.counted(PB)
        )
    });
}
