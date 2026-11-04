//! Review of lane int3 (I-79, SoD, design sections 8.3, 8.5 and 8.7).
//!
//! `POST /auth/recovery/{case}/complete` is a ceremony. On the
//! `SecondAdmin` path the new passkey comes "from a one-time enrolment
//! token", and on `EmailThenPasskey` it comes "in the same ceremony" as the
//! email proof (design section 8.5). So the completion must be bound to
//! whoever holds that token or ceremony. `gate::admit_recovery_completion`
//! takes no such proof: the case id, which the approving admin sees in
//! `.../{case}/approve`, is enough.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use fstp_auth::recovery::Deployment;
use fstp_auth::{AuthRecord, CoseKey, RecoveryPath};
use fstp_cell_core::gate;
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellRecord, CellState, SessionRows};
use fstp_celltest::mc::auth_model::{HarnessPasskey, RP_HOST};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN, ADMIN_2, T0};
use fstp_ledger::{MemStore, RecordStore, Seq};

const CASE: [u8; 16] = [0xCA; 16];

/// The state after each of `records` in its own batch at `T0`.
fn state(records: &[CellRecord]) -> CellState {
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (i, r) in records.iter().enumerate() {
        let id = [u8::try_from(i + 1).unwrap(); 16];
        store
            .append(store.head(), T0.micros(), id, vec![r.clone()])
            .unwrap();
    }
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    fstp_cell_core::replay(&out).unwrap()
}

/// I-79, SoD, design section 8.5: admin2 approved the recovery of admin1
/// and so knows the case id. With no enrolment token and no ceremony of
/// admin1's, admin2 must not be able to complete admin1's recovery with a
/// passkey admin2 holds. Today the gate admits that completion: the batch
/// revokes admin1's passkeys and enrols admin2's key on admin1's account.
#[test]
fn review_i79_recovery_completion_needs_proof_of_the_case() {
    let s = state(&[
        CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: ADMIN }),
        CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: ADMIN_2 }),
        CellRecord::Auth(AuthRecord::CredentialRegistered {
            account: ADMIN,
            credential: vec![0xA1, 1],
            key: CoseKey::Ed25519 { x: [0x0D; 32] },
            user_verified: true,
        }),
        CellRecord::Auth(AuthRecord::RecoveryRequested {
            case: CASE,
            account: ADMIN,
            path: RecoveryPath::SecondAdmin,
        }),
        CellRecord::Auth(AuthRecord::RecoveryEmailProven { case: CASE }),
        CellRecord::Auth(AuthRecord::RecoveryApproved {
            case: CASE,
            approver: ADMIN_2,
        }),
    ]);
    // A passkey on admin2's own authenticator, over any challenge.
    let challenge = [0x77; 32];
    let response = HarnessPasskey::of(&[0xB2, 2])
        .unwrap()
        .registration(challenge, true)
        .unwrap();
    let rp = fstp_webauthn::RelyingParty::new(RP_HOST).unwrap();
    let reg = fstp_auth::ceremony::Registration {
        response: &response,
        rp: &rp,
        challenge,
    };
    let now = Timestamp::from_micros(T0.micros() + 60_000_000);
    let admitted = gate::admit_recovery_completion(
        &s,
        CASE,
        &reg,
        SessionRows::default(),
        Deployment::Saas,
        None,
        [0x3C; 16],
        now,
    );
    assert!(
        admitted.is_err(),
        "the completion of admin1's recovery was admitted with no proof of the case: {admitted:?}"
    );
}
