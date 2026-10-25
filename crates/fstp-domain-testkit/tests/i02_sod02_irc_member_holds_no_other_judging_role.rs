//! I-02 with SoD-02, machine over grants and ends of every Judging role (design 6.2).
//!
//! I-02 concerns roles held now (`SPEC/02-domain/roles-and-sod.md` NOTE 4).
//! After every step no account holds an IRC binding beside an FSTP
//! coordinator, committee member or committee chair binding of the same
//! programme, and every grant is compared with the reference in both
//! directions. Reviewer and IRC assignments are lane L-REV's commands.
//! Their half of I-02 joins this machine in step W4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::{Backend, SodFocus, SodMachine};
use fstp_prop::{Config, check_machine_with, run_machine};

/// I-02, SoD-02: no IRC member holds another Judging role in the programme.
#[test]
fn i02_sod02_irc_member_holds_no_other_judging_role() {
    let machine = SodMachine::new(SodFocus::I02);
    check_machine_with(
        "i02_sod02_irc_member_holds_no_other_judging_role",
        Config::default().with_cases(SodFocus::I02.cases),
        &machine,
    );
}

/// I-02: the same machine with the reference as its own engine passes.
#[test]
fn i02_sod02_machine_agrees_with_its_reference() {
    let machine = SodMachine::with_backend(SodFocus::I02, Backend::Reference);
    let outcome = run_machine(
        "i02_sod02_machine_agrees_with_its_reference",
        Config::default().with_cases(SodFocus::I02.cases),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
