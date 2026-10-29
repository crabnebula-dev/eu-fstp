//! Review of lane int1 (I-78, design sections 5.1, 5.4 and 8.4).
//!
//! Design section 8.4 records `StepUpGranted { id, action_digest, session }`
//! after `POST /auth/stepup` verified an assertion, so every step-up is
//! logged with the action it authorised. The action request names the
//! step-up id, the gate checks it, and the batch consumes it. A step-up id
//! that the ledger never granted is no logged step-up, so it must not admit
//! a high-risk command, and its consumption must not fold.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, POLICY, admin_granted, cid, ledger, passkey, state_of, stepup};
use fstp_auth::AuthRecord;
use fstp_cell_core::CellCommand;
use fstp_cell_core::CellRecord;
use fstp_cell_core::gate::{self, Action};
use fstp_domain_testkit::r#gen::roster::{ADMIN, ADMIN_2, T0};

/// I-78, design sections 5.4 and 8.4: the gate refuses a high-risk command
/// whose step-up id has no `StepUpGranted` record in the ledger. Today it
/// admits it, so the session and digest that the record binds are never
/// checked against the ledger.
#[test]
fn review_i78_gate_refuses_a_step_up_the_ledger_never_granted() {
    let s = state_of(&ledger(&[(T0, cid(1), vec![admin_granted(ADMIN)])]).unwrap()).unwrap();
    let c = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin {
        account: ADMIN_2,
    });
    let id = cid(0x33);
    let digest = fstp_cell_core::action_digest(&c, id);
    let mine = passkey(ADMIN);
    let su = stepup(&mine, digest, NOW);
    assert!(s.auth().stepup_grant(su.id).is_none());
    let got = gate::admit_command(&s, &mine, Action::Command(c), id, Some(&su), NOW, &POLICY);
    assert!(
        got.is_err(),
        "a step-up with no StepUpGranted record admitted a high-risk command"
    );
}

/// I-78, design section 5.1: replay refuses `StepUpConsumed` for a step-up
/// id that no earlier `StepUpGranted` record names. Today it folds.
#[test]
fn review_i78_fold_refuses_consumption_of_an_ungranted_step_up() {
    let r = state_of(
        &ledger(&[(
            T0,
            cid(1),
            vec![CellRecord::Auth(AuthRecord::StepUpConsumed {
                id: [0x5C; 16],
            })],
        )])
        .unwrap(),
    );
    assert!(
        r.is_err(),
        "StepUpConsumed folded with no StepUpGranted record"
    );
}
