//! Review reproducers for lane W1c (test strength). Each test fails
//! against the lane's current code and passes once its finding is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::driver_model::paths;
use fstp_celltest::reference::vault::{
    Person, RefTicket, RefVault, RefWrite, RouteKind, TicketCheck, TicketKind, WriteKind,
    sign_ticket, ticket_public_key,
};
use fstp_domain::CommandKind;
use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::run_records;
use fstp_domain_testkit::scenario::Scenario;

/// I-18, ADR-009 "Write kinds" and "Tickets": a guardian consent write
/// ticket names one proposal. The reference vault origin must refuse a
/// consent for any other proposal under it. Otherwise a verified guardian
/// of one proposal can consent for every minor's proposal in the cell.
#[test]
fn review_origin_write_binds_the_ticket_proposal() {
    let seed = [0x11; 32];
    let pinned = [ticket_public_key(&seed).unwrap()];
    let cell = [0xCE; 16];
    let guardian = AccountId::from_raw(401);
    let own = ProposalId::from_raw(1);
    let other = ProposalId::from_raw(2);
    let now = Timestamp::from_micros(10_000_000_000);
    let ticket = RefTicket {
        kind: TicketKind::Write(WriteKind::GuardianConsent),
        cell,
        account: guardian,
        proposal: Some(own),
        scope: "consent".to_owned(),
        issued_at: now,
        expires_at: Timestamp::from_micros(now.micros() + 60_000_000),
        nonce: [0x01; 16],
    };
    let bytes = sign_ticket(&ticket, &seed).unwrap();
    let mut v = RefVault::default();
    v.write(RefWrite::VerificationRecorded {
        account: guardian,
        person: Person(401),
    });
    v.ack(1, 1, [0; 32]).unwrap();
    let check = TicketCheck {
        pinned: &pinned,
        cell,
        route: RouteKind::Write,
        now,
    };
    let got = v.origin_write(
        &bytes,
        RefWrite::GuardianConsent {
            proposal: other,
            guardian,
        },
        &check,
    );
    assert!(
        got.is_err(),
        "I-18: a consent ticket for {own:?} admitted a consent for {other:?}: {got:?}"
    );
}

/// I-18, design section 6.6 step 3, ADR-009 "Write kinds": the guardian
/// consent ticket goes to the guardian, a Receiving account added by
/// `AddGuardian`. `i18_cell_asks_adult_attestation_before_guardian_ticket`
/// issues the ticket command as the lead L1 on the path below and demands
/// a ticket whenever consent collection is open and the vault says no. That
/// path holds no `AddGuardian`, so the only ticket the test accepts is one
/// to an account that is not a guardian.
#[test]
fn review_guardian_ticket_test_path_has_a_guardian() {
    let path = paths::to(StateTag::Negotiation).unwrap();
    assert!(
        path.iter()
            .any(|p| p.step.cmd.kind() == CommandKind::AddGuardian),
        "I-18: the guardian ticket test runs on a path with no AddGuardian, so it demands a consent ticket for the lead"
    );
}

/// Design sections 5.2 and 14.6: `seam_driver_core_matches_reference_engine`
/// must find refusals equal. Its inputs were the fixed paths to each state,
/// with the lead attested or not, and the M2 engine accepts every step of
/// those, so the refusal comparison never ran.
///
/// Corrected by lane W1c in fix round 1: the seam now draws its inputs
/// through `paths::mutated`, since `paths::to` must stay a path the domain
/// accepts for its other users. This test checks that each mutation the
/// seam draws, applied at every step, makes the M2 engine refuse.
#[test]
fn review_seam_driver_core_inputs_include_a_refusal() {
    for m in [paths::Mutation::Repeat, paths::Mutation::Stranger] {
        let mut refused = 0usize;
        let mut steps = 0usize;
        for target in paths::STATES {
            for adult in [true, false] {
                let base = paths::to(target).unwrap();
                let path = paths::mutated(&base, &vec![m; base.len()]);
                let mut engine = Scenario::new(paths::truth(adult)).unwrap();
                for p in &path {
                    steps = steps.saturating_add(1);
                    if run_records(&mut engine, &p.step, p.at).unwrap().is_err() {
                        refused = refused.saturating_add(1);
                    }
                }
            }
        }
        assert!(
            refused > 0,
            "seam: none of the {steps} engine steps of the seam test's {m:?} inputs is refused, so refusal equality is never checked"
        );
    }
}
