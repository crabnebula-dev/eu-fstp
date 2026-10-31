//! Review of lane int3 (I-78, design sections 5.4 and 8.4).
//!
//! `POST /auth/stepup` verifies a passkey assertion with UV over the
//! challenge before `GrantStepUp` records `StepUpGranted` (design section
//! 8.4). The route admission must therefore take a proof that only that
//! verification yields. `fstp_auth::stepup::StepUp` has public fields, so
//! any caller can write one by hand with no assertion at all.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, cid, ledger, passkey, state_of};
use fstp_auth::stepup::StepUp;
use fstp_auth::{AuthRecord, CoseKey, Method};
use fstp_cell_core::CellRecord;
use fstp_cell_core::gate;
use fstp_domain_testkit::r#gen::roster::{A, T0};

/// I-78, design section 8.4: a step-up that no WebAuthn assertion ever
/// verified must not admit `GrantStepUp`. The `StepUp` below is written by
/// hand from public fields, and no assertion, challenge or signature
/// exists. Today the gate admits it, so the I-78 proof rests on route code
/// alone, and the granted step-up then admits any high-risk command.
#[test]
fn review_i78_stepup_grant_refuses_a_hand_written_step_up() {
    let s = state_of(
        &ledger(&[(
            T0,
            cid(1),
            vec![CellRecord::Auth(AuthRecord::CredentialRegistered {
                account: A,
                credential: vec![0x5E, 0],
                key: CoseKey::Ed25519 { x: [0x0D; 32] },
                user_verified: true,
            })],
        )])
        .unwrap(),
    )
    .unwrap();
    let own = passkey(A);
    let forged = StepUp {
        id: [0xC5; 16],
        session: own.id,
        action_digest: [0x46; 32],
        asserted_at: NOW,
        method: Method::Passkey,
        uv: true,
        consumed: false,
    };
    let admitted = gate::admit_stepup_grant(&s, &own, &forged, &[0x5E, 0], NOW);
    assert!(
        admitted.is_err(),
        "the gate admitted GrantStepUp for a step-up no assertion verified: {admitted:?}"
    );
}
