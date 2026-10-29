//! The step-up branch of `gate::admit`, step 3 of M3 design section 5.4
//! (I-78, R-LG-03, TH-56, sections 8.4 and 17.2, Q15, Q37).
//!
//! For every high-risk action: no step-up, a step-up one microsecond past
//! P-71, one for another command's digest, one of another session, one
//! without UV, a consumed one, and any action from a magic-link session
//! are refused, each with its own `Deny`. A fresh, strong, unused step-up
//! of this session for this digest is admitted, at exactly P-71 too, and
//! `Admitted` carries it. A tenant P-71 may only shorten the default.
//!
//! Lane W2c's test author wrote these before the gate. They are red until
//! `admit` lands (stub `Deny::NotImplemented`). The cases that need the
//! gate's own digest are red on `common::ACTION_DIGEST_SEAM` until the
//! gate takes the command id.
//!
//! Reading, as lane W1b took it: design section 5.4 has no variant for a
//! consumed step-up, so a consumed one may be refused as any step-up
//! refusal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    MINUTE_US, NOW, P71_US, POLICY, action_digest, admit_plain, admit_with_id, cid, magic, passkey,
    plus, stepup, table_action, table_commands, with_admins,
};
use fstp_auth::AuthCommand;
use fstp_cell_core::gate::{self, Action, Admitted, Deny, LoginPolicy, StepUpUse, StepUpView};
use fstp_cell_core::{CellCommand, CellState};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN};

/// The command id of the action in these tests.
const ID: [u8; 16] = cid(0x21);

/// The cell in which ADMIN is tenant admin.
fn cell() -> CellState {
    with_admins(&[ADMIN]).unwrap()
}

/// The gate for `c` by ADMIN's passkey session at `now`, with `su`
/// offered under `policy`.
fn gate_admin(
    c: &CellCommand,
    su: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Admitted, Deny> {
    admit_with_id(
        &cell(),
        &passkey(ADMIN),
        Action::Command(c.clone()),
        ID,
        su,
        now,
        policy,
    )
    .unwrap_or_else(|s| panic!("{s}"))
}

/// A fresh step-up of ADMIN's passkey session for `c` under [`ID`],
/// asserted at `at`.
fn fresh(c: &CellCommand, at: Timestamp) -> StepUpView {
    let digest = action_digest(c, ID).unwrap_or_else(|s| panic!("{s}"));
    stepup(&passkey(ADMIN), digest, at)
}

fn any_stepup_refusal(d: &Deny) -> bool {
    matches!(
        d,
        Deny::StepUpRequired(_)
            | Deny::StepUpStale
            | Deny::StepUpMismatch
            | Deny::StepUpFromWeakMethod
    )
}

// ---------------------------------------------------------------------------
// No step-up and magic links (no digest needed).

/// I-78, R-LG-03: every high-risk command that the stubs can build is
/// refused without a step-up, naming its table action. The gate does not
/// read roles, so the refusal is the same for an account with none.
#[test]
fn i78_every_table_command_without_step_up_is_refused() {
    let s = cell();
    for (name, c) in table_commands().unwrap() {
        let want = Err(Deny::StepUpRequired(table_action(name).unwrap()));
        for who in [ADMIN, A] {
            assert_eq!(
                admit_plain(&s, &passkey(who), Action::Command(c.clone()), NOW),
                want,
                "{name} by {who:?}"
            );
        }
    }
}

/// I-78, G10, design section 5.4: a magic-link session never takes a
/// high-risk action, with or without a step-up. A holds Receiving roles
/// only, so the weak session itself is admitted for low-risk actions. A
/// already holds a passkey, so only the magic-link rule refuses adding a
/// second one (design section 8.3).
#[test]
fn i78_magic_link_session_never_takes_a_high_risk_action() {
    let s = common::state_of(
        &common::ledger(&[
            (
                fstp_domain_testkit::r#gen::roster::T0,
                cid(1),
                vec![common::admin_granted(ADMIN)],
            ),
            (
                fstp_domain_testkit::r#gen::roster::T0,
                cid(2),
                vec![fstp_cell_core::CellRecord::Auth(
                    fstp_auth::AuthRecord::CredentialRegistered {
                        account: A,
                        credential: vec![9, 0],
                        key: fstp_auth::CoseKey::Ed25519 { x: [9; 32] },
                        user_verified: true,
                    },
                )],
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    let add = CellCommand::Auth(AuthCommand::RegisterCredential {
        account: A,
        credential: vec![9],
    });
    let m = magic(A);
    assert_eq!(
        admit_plain(&s, &m, Action::Command(add.clone()), NOW),
        Err(Deny::MagicLinkSessionHighRisk)
    );
    let su = stepup(&m, [0x11; 32], NOW);
    assert_eq!(
        gate::admit(&s, &m, Action::Command(add), Some(&su), NOW, &POLICY),
        Err(Deny::MagicLinkSessionHighRisk)
    );
}

// ---------------------------------------------------------------------------
// Fresh, stale, mismatched, weak and consumed step-ups.

/// I-78, design section 8.4: a fresh, strong, unused step-up of this
/// session for this command's digest admits every high-risk command, and
/// `Admitted` carries the step-up, so the batch can consume it, with its
/// assertion instant and the P-71 it was checked under, so the commit
/// checks freshness again (ADR-008).
#[test]
fn i78_fresh_step_up_admits_and_is_carried() {
    for (name, c) in table_commands().unwrap() {
        let su = fresh(&c, NOW);
        let a = gate_admin(&c, Some(&su), NOW, &POLICY).unwrap_or_else(|d| panic!("{name}: {d:?}"));
        assert_eq!(
            a.stepup(),
            Some(StepUpUse {
                id: su.id,
                action_digest: su.action_digest,
                asserted_at: su.asserted_at,
                p71_us: P71_US,
            }),
            "{name}"
        );
    }
}

/// I-78, P-71 (proposed: 5 minutes): `now - asserted_at <= P-71`. A
/// step-up exactly P-71 old is admitted, one a microsecond older is
/// stale.
#[test]
fn i78_step_up_freshness_boundary_is_p71_inclusive() {
    for (name, c) in table_commands().unwrap() {
        let edge = fresh(&c, plus(NOW, -P71_US));
        assert!(
            gate_admin(&c, Some(&edge), NOW, &POLICY).is_ok(),
            "{name} at P-71"
        );
        let stale = fresh(&c, plus(NOW, -P71_US - 1));
        assert_eq!(
            gate_admin(&c, Some(&stale), NOW, &POLICY),
            Err(Deny::StepUpStale),
            "{name} at P-71 plus 1 µs"
        );
    }
}

/// I-78, TH-56: the step-up is bound to the command digest and its
/// session. The digest of the same command under another command id, and
/// the step-up of another session, are refused as a mismatch.
#[test]
fn i78_step_up_is_bound_to_the_digest_and_session() {
    for (name, c) in table_commands().unwrap() {
        let other_id = action_digest(&c, cid(0x22)).unwrap_or_else(|s| panic!("{s}"));
        let su = stepup(&passkey(ADMIN), other_id, NOW);
        assert_eq!(
            gate_admin(&c, Some(&su), NOW, &POLICY),
            Err(Deny::StepUpMismatch),
            "{name}: another command id"
        );
        let mut other_session = fresh(&c, NOW);
        other_session.session = [0x99; 16];
        assert_eq!(
            gate_admin(&c, Some(&other_session), NOW, &POLICY),
            Err(Deny::StepUpMismatch),
            "{name}: another session"
        );
    }
}

/// I-78, Q15: a step-up by a method that is not phishing resistant with
/// UV is refused as weak.
#[test]
fn i78_step_up_without_uv_is_refused() {
    for (name, c) in table_commands().unwrap() {
        let mut su = fresh(&c, NOW);
        su.strong = false;
        assert_eq!(
            gate_admin(&c, Some(&su), NOW, &POLICY),
            Err(Deny::StepUpFromWeakMethod),
            "{name}"
        );
    }
}

/// I-78, Q15: one step-up authorises one command. A consumed step-up is
/// refused.
#[test]
fn i78_consumed_step_up_is_refused() {
    for (name, c) in table_commands().unwrap() {
        let mut su = fresh(&c, NOW);
        su.consumed = true;
        let r = gate_admin(&c, Some(&su), NOW, &POLICY);
        assert!(
            matches!(&r, Err(d) if any_stepup_refusal(d)),
            "{name}: {r:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// P-71 may only shorten.

/// I-78, P-71 "may only shorten" (design section 8.4): a tenant value
/// above the default does not lengthen freshness, and a shorter one
/// shortens it, inclusive at its own boundary.
#[test]
fn i78_p71_may_only_shorten() {
    let c = table_commands().unwrap().remove(0).1;
    let longer = LoginPolicy {
        stepup_freshness_us: 10 * MINUTE_US,
    };
    let past_default = fresh(&c, plus(NOW, -P71_US - 1));
    assert_eq!(
        gate_admin(&c, Some(&past_default), NOW, &longer),
        Err(Deny::StepUpStale),
        "a longer tenant P-71 lengthened freshness"
    );
    let shorter = LoginPolicy {
        stepup_freshness_us: MINUTE_US,
    };
    let edge = fresh(&c, plus(NOW, -MINUTE_US));
    assert!(gate_admin(&c, Some(&edge), NOW, &shorter).is_ok());
    let past = fresh(&c, plus(NOW, -MINUTE_US - 1));
    assert_eq!(
        gate_admin(&c, Some(&past), NOW, &shorter),
        Err(Deny::StepUpStale)
    );
}
