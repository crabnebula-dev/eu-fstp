//! F-079 (M10 review H-07b and H-08, A-1), ADR-038: a person joins a
//! proposal team only by accepting an invitation (I-17, TH-07, TH-08,
//! R-AN-01, roles-and-sod.md "Receiving bindings").
//!
//! Each test runs production `queries`, `decide` and `apply` in a roles
//! world: one programme with one published call, and a draft whose lead
//! is C. Every account and identity is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::{BindingId, ContentDigest, ProposalId, TeamInvitationId, TextId, TextRef};
use fstp_domain::oracle::Query;
use fstp_domain::proposal::team::{INVITATION_TTL_MICROS, MAX_OPEN_PER_PROPOSAL, team_invitation};
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{
    A, Backend, C, Facts, Flags, K1, SodSetup, SodWorld, Step, T0, call, draft, sod_truth,
};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// The draft of the world.
const PX: ProposalId = ProposalId::from_raw(500);

/// A synthetic address text: only its reference reaches the ledger.
fn contact(n: u8) -> TextRef {
    TextRef::new(
        TextId::from_raw(80_000u128.saturating_add(u128::from(n))),
        ContentDigest::from_bytes([n; 32]),
    )
}

fn invitation(n: u128) -> TeamInvitationId {
    TeamInvitationId::from_raw(70_000u128.saturating_add(n))
}

/// The world: programme P1, call 1 published, and C's draft PX.
fn world(truth: GroundTruth) -> SodWorld {
    let mut setup = SodSetup::one(1, &[1]);
    setup.published = vec![call(1)];
    let mut w = SodWorld::from_setup(Backend::Production, truth, &setup)
        .unwrap_or_else(|e| panic!("roles world: {e}"));
    w.now = T0;
    let step = draft(C, PX, call(1), BindingId::from_raw(600), false);
    w.exec(&step, Facts::Effective)
        .unwrap_or_else(|e| panic!("roles world: {e}"))
        .unwrap_or_else(|r| panic!("the draft was refused: {r}"));
    w
}

fn run(w: &mut SodWorld, step: &Step) -> Result<Vec<Record>, Refusal> {
    w.exec(step, Facts::Effective)
        .unwrap_or_else(|e| panic!("roles world: {e}"))
}

fn invite(n: u128, guardian: bool) -> Step {
    Step::by(
        C,
        Flags::NONE,
        Command::InviteToTeam {
            proposal: PX,
            invitation: invitation(n),
            contact: contact(1),
            guardian,
        },
    )
}

fn accept(by: fstp_domain::id::AccountId, n: u128, binding: u128) -> Step {
    Step::by(
        by,
        Flags::NONE,
        Command::AcceptTeamInvitation {
            proposal: PX,
            invitation: invitation(n),
            binding: BindingId::from_raw(binding),
        },
    )
}

fn decline(by: fstp_domain::id::AccountId, n: u128) -> Step {
    Step::by(
        by,
        Flags::NONE,
        Command::DeclineTeamInvitation {
            proposal: PX,
            invitation: invitation(n),
        },
    )
}

fn withdraw(n: u128) -> Step {
    Step::by(
        C,
        Flags::NONE,
        Command::WithdrawTeamInvitation {
            proposal: PX,
            invitation: invitation(n),
        },
    )
}

/// The accounts bound to PX, active or not.
fn bound(w: &SodWorld) -> Vec<fstp_domain::id::AccountId> {
    w.state
        .roster()
        .bindings()
        .filter(|(_, b)| b.proposal() == Some(PX))
        .map(|(_, b)| b.account)
        .collect()
}

/// F-079, TH-07, I-17: an invitation, for a team member or the guardian,
/// binds nobody and asks the vault nothing about anyone. Only the
/// invitee's acceptance asks, and only about the accepting account.
#[test]
fn m10_f079_th07_an_invitation_binds_nobody_and_asks_the_vault_nothing_before_acceptance() {
    check(
        "m10_f079_th07_an_invitation_binds_nobody_and_asks_the_vault_nothing_before_acceptance",
        |g| {
            let mut w = world(sod_truth());
            let guardian = g.bool();
            let step = invite(1, guardian);
            let ctx = w.ctx(&step);
            let asked = fstp_domain::queries(&w.state, &step.cmd, &ctx)
                .map_err(|r| format!("the invitation was refused: {r}"))?;
            prop_assert!(asked.is_empty(), "the invitation asked {:?}", asked);
            let before = bound(&w);
            let records = run(&mut w, &step).map_err(|r| r.to_string())?;
            prop_assert!(
                records
                    .iter()
                    .all(|r| matches!(r, Record::TeamInvited { .. })),
                "the invitation recorded {:?}",
                records
            );
            prop_assert_eq!(bound(&w), before, "the invitation bound an account");

            let step = accept(A, 1, 900);
            let ctx = w.ctx(&step);
            let asked = fstp_domain::queries(&w.state, &step.cmd, &ctx)
                .map_err(|r| format!("the acceptance was refused: {r}"))?;
            for q in &asked {
                let about_a = match q {
                    Query::InExcludedClass { account, .. } => *account == A,
                    Query::SameIdentityAsAny { subject, .. } => *subject == A,
                    Query::HasConflict { team, .. } => team.contains(&A),
                    _ => false,
                };
                prop_assert!(about_a, "the acceptance asked {:?}", q);
            }
            let records = run(&mut w, &step).map_err(|r| r.to_string())?;
            let role = if guardian {
                Role::Guardian
            } else {
                Role::ApplicantTeamMember
            };
            prop_assert!(
                records.iter().any(|r| matches!(
                    r,
                    Record::BindingGranted(b) if b.account == A && b.role == role
                )),
                "the acceptance bound nobody: {:?}",
                records
            );
            prop_assert_eq!(
                team_invitation(&w.state, invitation(1)).and_then(|i| i.closed),
                Some(true)
            );
            Ok(())
        },
    );
}

/// F-079, TH-08, R-AN-01: the lead's invitation names no account, so no
/// answer to the lead can depend on one. An account in an excluded class
/// is refused only when it accepts, under SoD-06, and the refusal leaves
/// the invitation open: the lead's view does not change.
#[test]
fn m10_f079_th08_the_refusal_at_acceptance_reaches_the_invitee_only() {
    let mut truth = sod_truth();
    let id = truth
        .identity_of(A)
        .unwrap_or_else(|| panic!("A has an identity"));
    truth.exclude(id, K1);
    let mut w = world(truth);
    run(&mut w, &invite(1, false)).unwrap_or_else(|r| panic!("refused: {r}"));
    let before = team_invitation(&w.state, invitation(1)).copied();
    let r = run(&mut w, &accept(A, 1, 900));
    assert_eq!(
        r.map(|_| ()).map_err(|r| r.rule),
        Err(RuleRef::Sod06),
        "SoD-06 at acceptance"
    );
    assert_eq!(team_invitation(&w.state, invitation(1)).copied(), before);
    assert!(!bound(&w).contains(&A), "the excluded account was bound");
}

/// F-079, ADR-038: an invitation that was withdrawn, declined or has
/// expired cannot be accepted or declined, and binds nobody.
#[test]
fn m10_f079_an_expired_or_withdrawn_invitation_cannot_be_accepted() {
    let mut w = world(sod_truth());
    run(&mut w, &invite(1, false)).unwrap_or_else(|r| panic!("refused: {r}"));
    run(&mut w, &invite(2, false)).unwrap_or_else(|r| panic!("refused: {r}"));
    run(&mut w, &invite(3, false)).unwrap_or_else(|r| panic!("refused: {r}"));

    run(&mut w, &withdraw(1)).unwrap_or_else(|r| panic!("withdrawal refused: {r}"));
    let r = run(&mut w, &accept(A, 1, 901));
    assert!(r.is_err(), "a withdrawn invitation was accepted: {r:?}");

    run(&mut w, &decline(A, 2)).unwrap_or_else(|r| panic!("decline refused: {r}"));
    let r = run(&mut w, &accept(A, 2, 902));
    assert!(r.is_err(), "a declined invitation was accepted: {r:?}");

    w.now = Timestamp::from_micros(T0.micros().saturating_add(INVITATION_TTL_MICROS));
    let r = run(&mut w, &accept(A, 3, 903));
    assert_eq!(
        r.map(|_| ()).map_err(|r| r.reason),
        Err(RefusalReason::WrongState),
        "an expired invitation was accepted"
    );
    let r = run(&mut w, &decline(A, 3));
    assert!(r.is_err(), "an expired invitation was declined: {r:?}");
    assert!(!bound(&w).contains(&A), "a closed invitation bound A");
    for n in 1..=3 {
        assert_ne!(
            team_invitation(&w.state, invitation(n)).and_then(|i| i.closed),
            Some(true),
            "invitation {n} reads joined"
        );
    }
}

/// F-079, ADR-038: only the lead invites and withdraws, and the open
/// invitations of one proposal are bounded.
#[test]
fn m10_f079_only_the_lead_invites_and_open_invitations_are_bounded() {
    let mut w = world(sod_truth());
    let by_a = Step::by(A, Flags::NONE, invite(1, false).cmd);
    let r = run(&mut w, &by_a);
    assert_eq!(r.map(|_| ()).map_err(|r| r.rule), Err(RuleRef::Actor));
    let max = u128::try_from(MAX_OPEN_PER_PROPOSAL).unwrap_or(0);
    for n in 1..=max {
        run(&mut w, &invite(n, false)).unwrap_or_else(|r| panic!("invitation {n}: {r}"));
    }
    let r = run(&mut w, &invite(max.saturating_add(1), false));
    assert_eq!(
        r.map(|_| ()).map_err(|r| r.reason),
        Err(RefusalReason::GuardFailed),
        "the bound"
    );
    let by_a = Step::by(A, Flags::NONE, withdraw(1).cmd);
    assert!(
        run(&mut w, &by_a).is_err(),
        "A withdrew the lead's invitation"
    );
    run(&mut w, &withdraw(1)).unwrap_or_else(|r| panic!("withdrawal: {r}"));
    run(&mut w, &invite(max.saturating_add(1), false))
        .unwrap_or_else(|r| panic!("after a withdrawal: {r}"));
}
