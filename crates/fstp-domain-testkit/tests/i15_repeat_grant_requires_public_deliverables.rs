//! I-15, R-NG-05: a repeat grant to the same applicant needs every prior accepted deliverable public under P-26 (design 6.2, Q8).
//!
//! Lead a is granted 4.00 from genesis by production commands and starts
//! execution. Lead b, another account of the same verified identity,
//! reaches NEGOTIATION. The property draws the state of a's deliverables
//! from the five of the test plan and records it through production:
//!
//! - none: no request and no deliverable;
//! - public under P-26: an accepted line and an accepted deliverable under MIT;
//! - public under another licence: the same under GPL-3.0-only, outside P-26;
//! - not accepted: a request whose line is not decided, and a deliverable
//!   the M5 checks did not accept;
//! - snapshot missing: an accepted line with no deliverable recorded, as a
//!   partial claim under the P-65 option "progress report" leaves it.
//!
//! It also draws whether b's amount is determined before or after a's
//! record changes. Under the answer to Q8, the record counts deliverables
//! accepted so far, against the P-26 of the call that funded them. So b is
//! granted exactly in the first, second and fourth states. In the others
//! GRANTED is disabled, so the completing grant fact is refused, and the
//! programme manager records NEGOTIATION to DECLINED for an incomplete
//! record. Every command is compared with the
//! money reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::{DeliverableId, LineId, RequestId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LA, LB, MoneySetup, MoneyStory, PA, PB, REL, accept_grant, accept_line, approve_grant,
    contract_effective, decline_negotiation, milestone_n, record_deliverable, request_payment,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};
use fstp_domain_testkit::vault::PriorDeliverables;
use fstp_prop::{Config, Gen, check_with, run};

/// The base story: a in IN_EXECUTION, b in NEGOTIATION, one identity.
pub fn base(b: Backend) -> Result<MoneyStory, String> {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p05 = 1_000;
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    let mut s = MoneyStory::new(&setup, b)?;
    s.execute(PA)?;
    Ok(s)
}

/// Records `state` on the grant `grant` of `lead` through production.
pub fn record_state(
    s: &mut MoneyStory,
    lead: fstp_domain::id::AccountId,
    grant: fstp_domain::id::ProposalId,
    state: PriorDeliverables,
) -> Result<(), String> {
    let r = RequestId::from_raw(33_000u128.saturating_add(grant.raw()));
    let line = LineId::from_raw(133_000u128.saturating_add(grant.raw()));
    let m = milestone_n(grant, 0);
    let d = DeliverableId::from_raw(43_000u128.saturating_add(grant.raw()));
    if state == PriorDeliverables::None {
        return Ok(());
    }
    s.run(&request_payment(lead, r, grant, &[(line, m, 400)])?)?;
    match state {
        PriorDeliverables::None => {}
        PriorDeliverables::PublicUnderP26 => {
            s.run(&accept_line(R1, r, line, 400, false)?)?;
            s.run(&record_deliverable(grant, d, m, "MIT", true))?;
        }
        PriorDeliverables::PublicUnderOtherLicence => {
            s.run(&accept_line(R1, r, line, 400, false)?)?;
            s.run(&record_deliverable(grant, d, m, "GPL-3.0-only", true))?;
        }
        PriorDeliverables::NotAccepted => {
            s.run(&record_deliverable(grant, d, m, "MIT", false))?;
        }
        PriorDeliverables::SnapshotMissing => {
            s.run(&accept_line(R1, r, line, 400, false)?)?;
        }
    }
    Ok(())
}

/// Whether the reference rule (Q8) clears `state`.
pub fn clears(state: PriorDeliverables) -> bool {
    matches!(
        state,
        PriorDeliverables::None
            | PriorDeliverables::PublicUnderP26
            | PriorDeliverables::NotAccepted
    )
}

fn case(start: &MoneyStory, g: &mut Gen) -> Result<(), String> {
    let mut s = start.clone();
    let state = *g.pick(&PriorDeliverables::ALL);
    let early = g.bool();
    g.note("prior deliverables", &state);
    g.note("b's amount determined first", &early);
    if early {
        s.determine(PB, 1, &[])?;
    }
    record_state(&mut s, LA, PA, state)?;
    if !early {
        s.determine(PB, 1, &[])?;
    }
    s.run(&accept_grant(LB, PB))?;
    s.run(&approve_grant(STAFF_PM, PB))?;
    // The completing fact is refused while a guard fails (NOTE 9).
    s.attempt(&contract_effective(PB))?;
    let granted = s.state(PB) == Some(StateTag::Granted);
    if granted != clears(state) {
        return Err(format!(
            "I-15: with prior deliverables {state:?}, b is granted: {granted}, the reference rule says {}",
            clears(state)
        ));
    }
    if !granted {
        let recs = s.run(&decline_negotiation(Actor::Account(STAFF_PM), PB))?;
        let reason = recs.iter().find_map(|r| match r {
            fstp_domain::record::Record::NegotiationDeclined { reason, .. } => Some(*reason),
            _ => None,
        });
        if reason != Some(NegotiationFailure::RepeatRecordIncomplete) {
            return Err(format!(
                "NOTE 9: b was declined for {reason:?}, the incomplete record is the only failure"
            ));
        }
    }
    s.invariants()?;
    Ok(())
}

/// I-15, R-NG-05: a repeat grant exists exactly when every prior accepted
/// deliverable is public under the funding call's P-26.
#[test]
fn i15_repeat_grant_requires_public_deliverables() {
    let start = base(Backend::Production).unwrap_or_else(|e| panic!("base from genesis: {e}"));
    check_with(
        "i15_repeat_grant_requires_public_deliverables",
        Config::default().with_cases(40),
        |g| case(&start, g),
    );
}

/// I-15: the property passes on the references alone.
#[test]
fn i15_repeat_grant_property_passes_on_the_reference() {
    let start = base(Backend::Reference).unwrap_or_else(|e| panic!("base from genesis: {e}"));
    let outcome = run(
        "i15_repeat_grant_property_passes_on_the_reference",
        Config::default().with_cases(40),
        |g| case(&start, g),
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed property failed: {}", f.message);
    }
}
