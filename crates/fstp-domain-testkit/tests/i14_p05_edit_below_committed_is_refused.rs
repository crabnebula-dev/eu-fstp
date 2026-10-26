//! I-14: an edit that lowers P-05 below any recipient's counted sum is refused (contracts.md, Q7 A, design 6.2).
//!
//! The machine draws P-05 edits to 4.00, 5.00 and 6.00 among amount
//! determinations, grant facts and exits, from four proposals in
//! NEGOTIATION, three of them of one verified identity. An edit that
//! lowers P-05 below the granted plus reserved sum of any identity must be
//! refused, and every other valid edit accepted. The stories show the
//! refusal on a reservation and on a grant, which needs the programme's
//! real committed sums in `policy::committed()`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::PolicyVersionId;
use fstp_domain_testkit::r#gen::money::{
    MoneyFocus, MoneyMachine, MoneySetup, MoneyStory, PA, PB, edit_p05,
};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_prop::{Config, check_machine_with, run_machine};

fn story(b: Backend) {
    let mut s = MoneyStory::new(&MoneySetup::sybil([400, 200, 100]), b)
        .unwrap_or_else(|e| panic!("three proposals to NEGOTIATION from genesis: {e}"));
    s.determine(PA, 1, &[])
        .unwrap_or_else(|e| panic!("a reserves 4.00: {e}"));
    let head = s.world.head.clone().unwrap();
    let to_four = edit_p05(&head, PolicyVersionId::from_raw(901), 400).unwrap();
    s.determine(PB, 1, &[])
        .unwrap_or_else(|e| panic!("b reserves 2.00, the identity holds 6.00: {e}"));
    s.refused(&to_four)
        .unwrap_or_else(|e| panic!("I-14: P-05 4.00 lies below the reserved 6.00: {e}"));
    s.grant_facts(PA)
        .unwrap_or_else(|e| panic!("a is granted 4.00: {e}"));
    s.refused(&to_four).unwrap_or_else(|e| {
        panic!("I-14: P-05 4.00 lies below the granted plus reserved 6.00: {e}")
    });
    let five = edit_p05(&head, PolicyVersionId::from_raw(901), 500).unwrap();
    s.refused(&five)
        .unwrap_or_else(|e| panic!("I-14: P-05 5.00 lies below 6.00: {e}"));
    let six = edit_p05(&head, PolicyVersionId::from_raw(901), 600).unwrap();
    s.run(&six)
        .unwrap_or_else(|e| panic!("I-14: P-05 6.00 keeps every recipient within the cap: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-14, Q7 A: P-05 cannot be lowered below a reservation or a grant of one identity.
#[test]
fn i14_p05_edit_below_reservation_and_grant_is_refused() {
    story(Backend::Production);
}

/// I-14: the story passes on the references alone.
#[test]
fn i14_p05_edit_story_passes_on_the_reference() {
    story(Backend::Reference);
}

/// I-14: production refuses exactly the P-05 edits that the reference refuses.
#[test]
fn i14_p05_edit_below_committed_is_refused() {
    let machine = MoneyMachine::new(MoneyFocus::P05, Backend::Production);
    check_machine_with(
        "i14_p05_edit_below_committed_is_refused",
        Config::default().with_cases(64),
        &machine,
    );
}

/// I-14: the P-05 machine with the reference as its own engine passes.
#[test]
fn i14_p05_edit_machine_agrees_with_its_reference() {
    let machine = MoneyMachine::new(MoneyFocus::P05, Backend::Reference);
    let outcome = run_machine(
        "i14_p05_edit_machine_agrees_with_its_reference",
        Config::default().with_cases(64),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
