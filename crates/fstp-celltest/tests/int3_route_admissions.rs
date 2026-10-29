//! The gate's route admissions of a new passkey, run with real
//! registrations (lane int3, I-78, I-79, design sections 8.3, 8.5 and
//! 8.7).
//!
//! `fstp-cell-core` cannot build a registration response, since it holds
//! no edge to `fstp-webauthn`. This crate can: `HarnessPasskey` writes
//! one from the software authenticator's builders. So the checks the gate
//! itself makes run here:
//!
//! - `gate::admit_add_passkey` verifies the registration, with UV for a
//!   management holder, refuses a credential id the cell knows, and
//!   needs the `AddPasskey` step-up in a phishing-resistant session of an
//!   account that holds a passkey already (I-78, design section 8.3).
//! - `gate::admit_recovery_completion` recomputes the path, so a role
//!   granted during an email recovery fails it, and verifies the new
//!   passkey under that path's UV rule (I-79, design section 8.5). It
//!   then fails closed, since nothing binds the caller to the case
//!   (`gate::ROUTE_ADMISSION_SEAM`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use fstp_auth::ceremony::{EnrolDeny, Registration};
use fstp_auth::recovery::{Deployment, RecoveryDeny};
use fstp_auth::{AuthCommand, AuthRecord, Method, RecoveryPath, SessionView};
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, Principal, RouteDeny, StepUpView};
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellState, SessionRows};
use fstp_celltest::mc::auth_model::{HarnessPasskey, RP_HOST};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, T0};
use fstp_ledger::{MemStore, RecordStore, Seq};
use fstp_webauthn::{RegistrationResponse, RelyingParty};

const MINUTE_US: i64 = 60_000_000;

/// The instant the admissions run at: one hour after `T0`.
const NOW: Timestamp = Timestamp::from_micros(T0.micros() + 60 * MINUTE_US);

/// P-71 at its interim default of 5 minutes.
const POLICY: LoginPolicy = LoginPolicy {
    stepup_freshness_us: 5 * MINUTE_US,
};

/// The challenge of every ceremony here.
const CHALLENGE: [u8; 32] = [0x77; 32];

/// The command id of the `AddPasskey` command.
const COMMAND: [u8; 16] = [0x3C; 16];

/// The recovery case.
const CASE: [u8; 16] = [0xCA; 16];

/// `t` moved by `us` microseconds.
fn plus(t: Timestamp, us: i64) -> Timestamp {
    Timestamp::from_micros(t.micros() + us)
}

/// The state after each `(at, record)` in its own batch.
fn state_at(records: &[(Timestamp, CellRecord)]) -> CellState {
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (i, (at, r)) in records.iter().enumerate() {
        let id = [u8::try_from(i + 1).unwrap(); 16];
        store
            .append(store.head(), at.micros(), id, vec![r.clone()])
            .unwrap();
    }
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    fstp_cell_core::replay(&out).unwrap()
}

/// The state after each of `records` in its own batch at `T0`.
fn state(records: &[CellRecord]) -> CellState {
    let at: Vec<(Timestamp, CellRecord)> = records.iter().map(|r| (T0, r.clone())).collect();
    state_at(&at)
}

fn admin(account: AccountId) -> CellRecord {
    CellRecord::Tenant(TenantRecord::TenantAdminGranted { account })
}

fn registered(account: AccountId, credential: &[u8]) -> CellRecord {
    let key = HarnessPasskey::of(credential).unwrap().public_key();
    CellRecord::Auth(AuthRecord::CredentialRegistered {
        account,
        credential: credential.to_vec(),
        key,
        user_verified: true,
    })
}

/// A session of `account` by `method`, started one minute before `NOW`.
fn session(id: u8, account: AccountId, method: Method) -> SessionView {
    SessionView {
        id: [id; 16],
        account,
        method,
        started: plus(NOW, -MINUTE_US),
        last_used: NOW,
    }
}

/// The registration of a passkey with id `credential`, with UV when `uv`.
fn response(credential: &[u8], uv: bool) -> RegistrationResponse {
    HarnessPasskey::of(credential)
        .unwrap()
        .registration(CHALLENGE, uv)
        .unwrap()
}

fn rp() -> RelyingParty {
    RelyingParty::new(RP_HOST).unwrap()
}

/// The `AddPasskey` command of `account` for credential `credential`.
fn add(account: AccountId, credential: &[u8]) -> CellCommand {
    CellCommand::Auth(AuthCommand::RegisterCredential {
        account,
        credential: credential.to_vec(),
    })
}

/// The step-up `id` the ledger granted in `session` for `cmd` under
/// [`COMMAND`], thirty seconds before `NOW`, and its view.
fn granted(id: u8, session: &SessionView, cmd: &CellCommand) -> (CellRecord, StepUpView) {
    let digest = fstp_cell_core::action_digest(cmd, COMMAND);
    let record = CellRecord::Auth(AuthRecord::StepUpGranted {
        id: [id; 16],
        action_digest: digest,
        session: session.id,
    });
    let view = StepUpView {
        id: [id; 16],
        session: session.id,
        action_digest: digest,
        asserted_at: plus(NOW, -MINUTE_US / 2),
        strong: true,
        consumed: false,
    };
    (record, view)
}

/// A tenant admin with passkey `A1 01`, in a passkey session, with a
/// step-up the ledger granted for adding credential `new`.
fn admin_world(new: &[u8]) -> (CellState, SessionView, StepUpView) {
    let sess = session(0x51, ADMIN, Method::Passkey);
    let (grant, view) = granted(0x5C, &sess, &add(ADMIN, new));
    let s = state_at(&[
        (T0, admin(ADMIN)),
        (T0, registered(ADMIN, &[0xA1, 1])),
        (plus(NOW, -MINUTE_US / 2), grant),
    ]);
    (s, sess, view)
}

/// I-78, design section 8.3: a tenant admin's `AddPasskey` with the
/// granted step-up and a UV registration is admitted for the session's own
/// account. The batch records the key the gate verified, not one the
/// caller names.
#[test]
fn i78_add_passkey_admits_the_gate_verified_key() {
    let new = [0xA1, 2];
    let (s, sess, su) = admin_world(&new);
    let resp = response(&new, true);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let a = gate::admit_add_passkey(&s, &sess, &reg, COMMAND, Some(&su), NOW, &POLICY).unwrap();
    assert_eq!(a.principal(), Principal::Account(ADMIN));
    assert_eq!(a.command_id(), Some(COMMAND));
    assert_eq!(a.action(), &Action::Command(add(ADMIN, &new)));
    let batch = fstp_cell_core::decide_with_inputs(
        &s,
        &add(ADMIN, &new),
        &CellCtx {
            actor: ADMIN,
            at: NOW.micros(),
        },
        COMMAND,
        a.inputs(),
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(
        batch,
        vec![CellRecord::Auth(AuthRecord::CredentialRegistered {
            account: ADMIN,
            credential: new.to_vec(),
            key: HarnessPasskey::of(&new).unwrap().public_key(),
            user_verified: true,
        })]
    );
}

/// I-78, ADR-008 "User verification": a management holder's new passkey
/// without UV is refused by the gate's own verification.
#[test]
fn i78_add_passkey_refuses_a_holder_passkey_without_uv() {
    let new = [0xA1, 2];
    let (s, sess, su) = admin_world(&new);
    let resp = response(&new, false);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    let got = gate::admit_add_passkey(&s, &sess, &reg, COMMAND, Some(&su), NOW, &POLICY);
    assert!(
        matches!(got, Err(RouteDeny::Enrol(EnrolDeny::Registration(_)))),
        "a holder's passkey without UV: {got:?}"
    );
}

/// I-78, WebAuthn Level 2 section 7.1 step 22: a registration whose
/// credential id the cell knows is refused, even with a valid step-up.
#[test]
fn i78_add_passkey_refuses_a_reused_credential_id() {
    let reused = [0xA1, 1];
    let (s, sess, su) = admin_world(&reused);
    let resp = response(&reused, true);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    assert_eq!(
        gate::admit_add_passkey(&s, &sess, &reg, COMMAND, Some(&su), NOW, &POLICY).err(),
        Some(RouteDeny::Enrol(EnrolDeny::CredentialRegistered))
    );
}

/// I-78, design section 8.4: `AddPasskey` is high risk. With no step-up
/// it is refused as one required, and with a step-up granted for another
/// credential it is refused as a mismatch.
#[test]
fn i78_add_passkey_needs_its_own_step_up() {
    let new = [0xA1, 2];
    let (s, sess, _) = admin_world(&new);
    let resp = response(&new, true);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    assert!(
        matches!(
            gate::admit_add_passkey(&s, &sess, &reg, COMMAND, None, NOW, &POLICY),
            Err(RouteDeny::Gate(Deny::StepUpRequired(_)))
        ),
        "AddPasskey without a step-up"
    );
    // The ledger granted a step-up for adding A1 03, not A1 02.
    let (s_other, sess_other, su_other) = admin_world(&[0xA1, 3]);
    assert_eq!(
        gate::admit_add_passkey(
            &s_other,
            &sess_other,
            &reg,
            COMMAND,
            Some(&su_other),
            NOW,
            &POLICY
        )
        .err(),
        Some(RouteDeny::Gate(Deny::StepUpMismatch))
    );
}

/// I-78, design section 8.3: a magic-link session never adds a passkey,
/// even for an account with no management role.
#[test]
fn i78_add_passkey_refuses_a_magic_link_session() {
    let new = [0xB1, 2];
    let sess = session(0x52, A, Method::MagicLink);
    let (grant, su) = granted(0x5D, &sess, &add(A, &new));
    let s = state_at(&[
        (T0, registered(A, &[0xB1, 1])),
        (plus(NOW, -MINUTE_US / 2), grant),
    ]);
    let resp = response(&new, true);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    assert_eq!(
        gate::admit_add_passkey(&s, &sess, &reg, COMMAND, Some(&su), NOW, &POLICY).err(),
        Some(RouteDeny::Gate(Deny::MagicLinkSessionHighRisk))
    );
}

/// I-78, design section 8.3: an account that holds no passkey gets its
/// first only in a logged ceremony, never as `AddPasskey`.
#[test]
fn i78_add_passkey_refuses_an_account_without_a_passkey() {
    let new = [0xB1, 2];
    let sess = session(0x53, A, Method::Passkey);
    let (grant, su) = granted(0x5E, &sess, &add(A, &new));
    let s = state_at(&[(plus(NOW, -MINUTE_US / 2), grant)]);
    let resp = response(&new, true);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    assert_eq!(
        gate::admit_add_passkey(&s, &sess, &reg, COMMAND, Some(&su), NOW, &POLICY).err(),
        Some(RouteDeny::Enrol(EnrolDeny::AddPasskey))
    );
}

/// `admit_recovery_completion` of [`CASE`] in `s` with a passkey `new`.
fn complete(s: &CellState, new: &[u8], uv: bool) -> Result<gate::Admitted, RouteDeny> {
    let resp = response(new, uv);
    let rp = rp();
    let reg = Registration {
        response: &resp,
        rp: &rp,
        challenge: CHALLENGE,
    };
    gate::admit_recovery_completion(
        s,
        CASE,
        &reg,
        SessionRows::default(),
        Deployment::Saas,
        None,
        COMMAND,
        NOW,
    )
}

/// The open email recovery of `account`, with the email proven.
fn email_recovery(account: AccountId) -> [CellRecord; 2] {
    [
        CellRecord::Auth(AuthRecord::RecoveryRequested {
            case: CASE,
            account,
            path: RecoveryPath::EmailThenPasskey,
        }),
        CellRecord::Auth(AuthRecord::RecoveryEmailProven { case: CASE }),
    ]
}

/// I-79, design section 8.5: `recovery::complete` recomputes the path at
/// completion, so a tenant admin role granted during an open email
/// recovery makes the completion fail: the path is now `SecondAdmin`,
/// which no approval completes.
#[test]
fn i79_completion_refuses_a_role_granted_during_an_email_recovery() {
    let [requested, proven] = email_recovery(A);
    let s = state(&[
        admin(ADMIN),
        registered(A, &[0xB1, 1]),
        requested,
        proven,
        admin(A),
    ]);
    assert_eq!(
        complete(&s, &[0xB1, 2], true).err(),
        Some(RouteDeny::Recovery(RecoveryDeny::PathNotSatisfied(
            RecoveryPath::SecondAdmin
        )))
    );
}

/// I-79, ADR-008 "User verification": on the `SecondAdmin` path the new
/// passkey of a management holder needs UV, and an id the cell knows is
/// refused.
#[test]
fn i79_completion_verifies_the_new_passkey_under_the_path_rule() {
    let s = state(&[
        admin(ADMIN),
        admin(ADMIN_2),
        registered(ADMIN, &[0xA1, 1]),
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
    assert_eq!(
        complete(&s, &[0xA1, 2], false).err(),
        Some(RouteDeny::Recovery(RecoveryDeny::Passkey(
            EnrolDeny::Registration(fstp_webauthn::WebAuthnError::UserVerification)
        )))
    );
    assert_eq!(
        complete(&s, &[0xA1, 1], true).err(),
        Some(RouteDeny::Recovery(RecoveryDeny::Passkey(
            EnrolDeny::CredentialRegistered
        )))
    );
}

/// I-79, design section 8.5: a completion that passes every check the
/// gate can make is still refused, since nothing binds the caller to the
/// case (`gate::ROUTE_ADMISSION_SEAM`). An unknown case is refused first.
#[test]
fn i79_completion_fails_closed_without_proof_of_the_case() {
    let [requested, proven] = email_recovery(A);
    let s = state(&[registered(A, &[0xB1, 1]), requested, proven]);
    assert_eq!(
        complete(&s, &[0xB1, 2], false).err(),
        Some(RouteDeny::Gate(Deny::NotImplemented(
            gate::ROUTE_ADMISSION_SEAM
        )))
    );
    assert_eq!(
        complete(&state(&[]), &[0xB1, 2], true).err(),
        Some(RouteDeny::UnknownCase)
    );
}
