//! R-NG-03, I-13, I-14: the assigned reviewers set the grant amount, adjusted for ineligible costs, within P-04 and P-05.
//!
//! The stories run production commands from genesis to proposals in
//! NEGOTIATION under P-04 = [2.00, 4.00] and P-05 = 6.00. Leads a and b,
//! and a fourth lead d in some stories, share one verified identity. Lead
//! c is alone. Every step is compared with the money reference in both
//! directions. The `_on_the_reference` twins run the same stories on the
//! references alone and must pass now.
//!
//! The granted amount is the effective plan total minus the recorded
//! deductions, and the agreed plan's total must equal it (design 2.11).
//! The only agreed plan in M2 is the effective one, since lane L-LIFE
//! still refuses negotiated plans. So a deduction is refused, and the
//! contract never carries milestones above the granted amount (I-31).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LA, MoneyDraft, MoneySetup, MoneyStory, PA, PB, PC, amount_decision, determine,
};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, R1, R2, plan_of};
use fstp_domain_testkit::r#gen::roster::Backend;

/// The fourth proposal, of lead d, who shares the identity of a and b.
const PD: ProposalId = ProposalId::from_raw(14);
const LD: AccountId = AccountId::from_raw(404);

fn story_of(cents: [i64; 3], b: Backend) -> MoneyStory {
    MoneyStory::new(&MoneySetup::sybil(cents), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"))
}

fn story(b: Backend) -> MoneyStory {
    story_of([500, 300, 100], b)
}

fn who_sets_the_amount(b: Backend) {
    let mut s = story(b);
    for p in [PA, PB, PC] {
        assert_eq!(s.state(p), Some(StateTag::Negotiation));
    }
    for outsider in [COORDINATOR, IRC, LA] {
        let st = determine(outsider, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
        s.refused(&st)
            .unwrap_or_else(|e| panic!("R-NG-03: {outsider:?} must not set the amount: {e}"));
    }
    let st = determine(R2, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&st)
        .unwrap_or_else(|e| panic!("R-NG-03: assigned reviewer R2 sets the amount: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn the_amount_lies_within_p04(b: Backend) {
    let mut s = story_of([500, 400, 100], b);
    let five = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[]).unwrap();
    s.refused(&five)
        .unwrap_or_else(|e| panic!("I-13: 5.00 lies above the P-04 maximum 4.00: {e}"));
    let all = determine(R1, PC, amount_decision(PC, 1), plan_of(PC), &[]).unwrap();
    s.refused(&all)
        .unwrap_or_else(|e| panic!("I-13: 1.00 lies below the P-04 minimum 2.00: {e}"));
    let over = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[200, 300]).unwrap();
    s.refused(&over)
        .unwrap_or_else(|e| panic!("I-13: deductions above the plan total: {e}"));
    let four = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&four)
        .unwrap_or_else(|e| panic!("R-NG-03 AC: 4.00, the P-04 maximum, is accepted: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn a_deduction_needs_a_plan_that_carries_it(b: Backend) {
    let mut s = story(b);
    let cut = determine(R1, PA, amount_decision(PA, 1), plan_of(PA), &[100]).unwrap();
    s.refused(&cut).unwrap_or_else(|e| {
        panic!(
            "I-13, design 2.11: 5.00 minus 1.00 is 4.00, but the agreed plan still totals \
             5.00, so the contract would let the grantee claim 5.00: {e}"
        )
    });
    let cut_b = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[100]).unwrap();
    s.refused(&cut_b).unwrap_or_else(|e| {
        panic!("I-13, design 2.11: 3.00 minus 1.00 is not the agreed total 3.00: {e}")
    });
    let whole = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.run(&whole)
        .unwrap_or_else(|e| panic!("I-13: the plan total 3.00 with no deduction: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn the_cap_counts_the_sybil_reservation(b: Backend) {
    let mut setup = MoneySetup::sybil([400, 300, 100]);
    setup.drafts.push(MoneyDraft::one(LD, PD, 200));
    setup.shared.push((LA, LD));
    let mut s = MoneyStory::new(&setup, b)
        .unwrap_or_else(|e| panic!("four proposals to NEGOTIATION from genesis: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let three = determine(R1, PB, amount_decision(PB, 1), plan_of(PB), &[]).unwrap();
    s.refused(&three).unwrap_or_else(|e| {
        panic!("I-14: b shares a's identity, so 4.00 reserved plus 3.00 exceeds 6.00: {e}")
    });
    let two = determine(R1, PD, amount_decision(PD, 1), plan_of(PD), &[]).unwrap();
    s.run(&two).unwrap_or_else(|e| {
        panic!("I-14, R-NG-03 AC: d's 2.00, the P-04 minimum, makes exactly P-05: {e}")
    });
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn a_new_amount_replaces_the_reservation(b: Backend) {
    let mut s = story_of([300, 300, 100], b);
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b reserves 3.00: {e}"));
    s.determine(PB, 2, &[]).unwrap_or_else(|e| {
        panic!("design 2.11: a later amount releases and replaces the reservation: {e}")
    });
    s.determine(PA, 1, &[]).unwrap_or_else(|e| {
        panic!("I-14: b's one reservation of 3.00 plus a's 3.00 is exactly P-05: {e}")
    });
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-03, I-03: only an assigned reviewer without conflict sets the amount.
#[test]
fn r_ng_03_only_assigned_reviewers_set_the_amount() {
    who_sets_the_amount(Backend::Production);
}

/// R-NG-03, I-13: the amount lies within P-04, inclusive at the maximum.
#[test]
fn r_ng_03_i13_the_amount_lies_within_p04() {
    the_amount_lies_within_p04(Backend::Production);
}

/// R-NG-03, I-13, I-31, design 2.11: a deduction the agreed plan does not
/// carry is refused, so the grantee cannot claim more than the grant.
#[test]
fn r_ng_03_i13_a_deduction_needs_an_agreed_plan_that_carries_it() {
    a_deduction_needs_a_plan_that_carries_it(Backend::Production);
}

/// R-NG-03, I-14: a reservation of a Sybil account counts against the cap,
/// and the P-04 minimum is accepted.
#[test]
fn r_ng_03_i14_reservations_count_per_verified_identity() {
    the_cap_counts_the_sybil_reservation(Backend::Production);
}

/// R-NG-03, I-14: a later amount releases the earlier reservation in the same batch.
#[test]
fn r_ng_03_i14_a_new_amount_replaces_the_reservation() {
    a_new_amount_replaces_the_reservation(Backend::Production);
}

/// R-NG-03, I-13, I-14: the stories pass on the references alone.
#[test]
fn r_ng_03_stories_pass_on_the_reference() {
    who_sets_the_amount(Backend::Reference);
    the_amount_lies_within_p04(Backend::Reference);
    a_deduction_needs_a_plan_that_carries_it(Backend::Reference);
    the_cap_counts_the_sybil_reservation(Backend::Reference);
    a_new_amount_replaces_the_reservation(Backend::Reference);
}
