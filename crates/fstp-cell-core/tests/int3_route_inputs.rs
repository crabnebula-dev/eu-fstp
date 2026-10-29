//! Route and task inputs, route admissions and the SoD-07 approval set
//! (lane int3, M3 design sections 4.2, 5.1, 5.4, 8.2 to 8.5).
//!
//! - With the live session rows of its route or task, a batch records the
//!   `SessionEnded` reactions of design section 5.1, `EndSession`,
//!   `RevokeCredential` and `EndSessionsAtBindingEnd` (I-77, R-LG-04).
//! - The step-up id is the challenge id end to end (I-78).
//! - The route admissions run checks of their own, and a session still
//!   never admits a route-only command (I-78, I-79). `GrantStepUp` fails
//!   closed, since a `StepUp` proves no assertion.
//! - A grantor's own approval of their grant digest never stops a second
//!   tenant admin from approving it (SoD-07, Q40).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    MINUTE_US, NOW, P71_US, POLICY, admin_granted, as_cell, cid, ledger, m2_entries, m2_run,
    m2_setup, magic, passkey, plus, session, state_of,
};
use fstp_auth::recovery::Deployment;
use fstp_auth::session::SessionLogin;
use fstp_auth::stepup::{StepUp, StepUpDeny};
use fstp_auth::{AuthCommand, AuthRecord, CoseKey, Method, RecoveryPath, SessionView};
use fstp_cell_core::driver::{DriverCore, Event, Need, Step};
use fstp_cell_core::gate::{self, Action, Deny, Principal, RouteDeny};
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::tenant::{TenantCommand, TenantRecord};
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, CellRefusal, CellState, ROUTE_INPUT_MISSING, RouteInputs,
    SessionRows, SystemCtx, SystemTask,
};
use fstp_domain::id::{BindingId, VaultEpoch};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, B, C, P1, T0, end, grant};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

fn refused(rule: RuleRef, reason: RefusalReason) -> CellRefusal {
    CellRefusal::Domain(Refusal::new(rule, reason))
}

fn ctx(actor: fstp_domain::id::AccountId, at: Timestamp) -> CellCtx {
    CellCtx {
        actor,
        at: at.micros(),
    }
}

fn ended(id: [u8; 16]) -> CellRecord {
    CellRecord::Auth(AuthRecord::SessionEnded { session: id })
}

/// The session ids that the `SessionEnded` records of `batch` name, in
/// batch order.
fn ends_of(batch: &[CellRecord]) -> Vec<[u8; 16]> {
    batch
        .iter()
        .filter_map(|r| match r {
            CellRecord::Auth(AuthRecord::SessionEnded { session }) => Some(*session),
            _ => None,
        })
        .collect()
}

fn rows(live: &[SessionView]) -> RouteInputs {
    RouteInputs::none().with_sessions(SessionRows::new(live.to_vec(), Vec::new()))
}

fn registered(account: fstp_domain::id::AccountId, credential: &[u8]) -> CellRecord {
    CellRecord::Auth(AuthRecord::CredentialRegistered {
        account,
        credential: credential.to_vec(),
        key: CoseKey::Ed25519 { x: [0x0D; 32] },
        user_verified: true,
    })
}

/// The state after each of `records` in its own batch at `T0`.
fn replay_each(records: &[CellRecord]) -> CellState {
    let batches: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(i, r)| (T0, cid(u8::try_from(i + 1).unwrap()), vec![r.clone()]))
        .collect();
    state_of(&ledger(&batches).unwrap()).unwrap()
}

/// `entries`, then each of `more` in its own batch at `at`, read back
/// from a store.
fn extended(entries: &[Entry<CellRecord>], more: &[CellRecord], at: Timestamp) -> CellState {
    let mut store: MemStore<CellRecord> = MemStore::new();
    // Entries of one command were one batch, so they are appended so again.
    let mut batches: Vec<(i64, [u8; 16], Vec<CellRecord>)> = Vec::new();
    for e in entries {
        match batches.last_mut() {
            Some((at, command, batch)) if *at == e.at && *command == e.command => {
                batch.push(e.record.clone());
            }
            _ => batches.push((e.at, e.command, vec![e.record.clone()])),
        }
    }
    for (at, command, batch) in batches {
        store.append(store.head(), at, command, batch).unwrap();
    }
    for (i, r) in more.iter().enumerate() {
        store
            .append(
                store.head(),
                at.micros(),
                cid(0xE0 + u8::try_from(i).unwrap()),
                vec![r.clone()],
            )
            .unwrap();
    }
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    state_of(&out).unwrap()
}

// ---------------------------------------------------------------------------
// SoD-07.

/// admin1's self-grant of finance approver at `at`.
fn self_grant(at: Timestamp) -> fstp_engine::Command {
    fstp_engine::Command::Core(
        grant(
            BindingId::from_raw(7_101),
            ADMIN,
            P1,
            Role::FinanceApprover,
            at,
        )
        .cmd,
    )
}

fn approve(
    s: &CellState,
    by: fstp_domain::id::AccountId,
    digest: [u8; 32],
    at: Timestamp,
) -> Result<Vec<CellRecord>, CellRefusal> {
    fstp_cell_core::decide_with_id(
        s,
        &CellCommand::Tenant(TenantCommand::ApproveSelfGrant {
            grant_digest: digest,
        }),
        &ctx(by, at),
        cid(0x71),
        &Answers::new(),
    )
}

/// SoD-07, Q40, design section 5.1: the grantor approves their own grant
/// digest first. A second tenant admin's approval of the same digest is
/// still recorded, and it admits the grant, as the W1b reference rule
/// does (`sod_07_self_grant_matches_the_reference_rule`). Before the fix
/// the second approval was refused as reused, so a grantor could block
/// their own grant.
#[test]
fn sod_07_grantors_own_approval_never_blocks_a_second_admin() {
    let id = cid(0x7A);
    let grant_at = plus(T0, MINUTE_US);
    let cmd = self_grant(grant_at);
    let digest = fstp_cell_core::self_grant_digest(&cmd, id).unwrap();
    let s = replay_each(&[admin_granted(ADMIN), admin_granted(ADMIN_2)]);
    let own = approve(&s, ADMIN, digest, T0).unwrap();
    let mut records = vec![admin_granted(ADMIN), admin_granted(ADMIN_2)];
    records.extend(own);
    let s = replay_each(&records);
    assert!(
        !fstp_cell_core::attest_at(&s, ADMIN, &cmd, id, grant_at).second_tenant_admin,
        "the grantor's own approval admitted the grant"
    );
    let second = approve(&s, ADMIN_2, digest, T0).expect("the second admin's approval was refused");
    records.extend(second);
    let s = replay_each(&records);
    assert!(
        fstp_cell_core::attest_at(&s, ADMIN, &cmd, id, grant_at).second_tenant_admin,
        "the second admin's approval did not admit the grant"
    );
}

/// SoD-07, Q40: an approval that expired does not hide a later approval
/// of the same digest by the same second admin, and once a grant used
/// the digest no further approval of it is taken (TH-05).
#[test]
fn sod_07_a_fresh_approval_follows_an_expired_one_and_a_used_digest_takes_none() {
    let id = cid(0x7B);
    let late = plus(T0, 2 * P71_US);
    let cmd = self_grant(late);
    let digest = fstp_cell_core::self_grant_digest(&cmd, id).unwrap();
    let mut records = vec![admin_granted(ADMIN), admin_granted(ADMIN_2)];
    let s = replay_each(&records);
    records.extend(approve(&s, ADMIN_2, digest, T0).unwrap());
    let s = replay_each(&records);
    assert!(
        !fstp_cell_core::attest_at(&s, ADMIN, &cmd, id, late).second_tenant_admin,
        "an approval older than P-71 admitted the grant"
    );
    // A fresh approval by the same admin, one minute before the grant.
    let fresh = approve(&s, ADMIN_2, digest, plus(late, -MINUTE_US))
        .expect("a fresh approval after an expired one was refused");
    records.extend(fresh);
    let s = replay_each(&records);
    assert!(
        fstp_cell_core::attest_at(&s, ADMIN, &cmd, id, late).second_tenant_admin,
        "the fresh approval did not admit the grant"
    );
    // A grant used the digest: no approval of it is taken again.
    records.push(CellRecord::Tenant(TenantRecord::SelfGrantApprovalUsed {
        grant_digest: digest,
    }));
    let s = replay_each(&records);
    assert!(!fstp_cell_core::attest_at(&s, ADMIN, &cmd, id, late).second_tenant_admin);
    assert_eq!(
        approve(&s, ADMIN_2, digest, late),
        Err(refused(RuleRef::Input, RefusalReason::IdReused))
    );
}

// ---------------------------------------------------------------------------
// Session reactions (design section 5.1, Q16 A).

/// I-77, design section 5.1: with the live session rows, a tenant admin
/// grant ends the account's weak sessions in the same batch, and only
/// those. Without rows the batch names none, and the gate still refuses
/// the weak session from the grant on (design section 5.4 step 2).
#[test]
fn i77_admin_grant_batch_ends_the_weak_sessions_of_its_account() {
    let s = replay_each(&[admin_granted(ADMIN)]);
    let cmd = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: A });
    let other = session(0x53, B, Method::MagicLink, plus(NOW, -MINUTE_US), NOW);
    let live = [magic(A), passkey(A), other];
    let batch = fstp_cell_core::decide_with_inputs(
        &s,
        &cmd,
        &ctx(ADMIN, NOW),
        cid(9),
        &rows(&live),
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(ends_of(&batch), vec![magic(A).id]);
    let plain = fstp_cell_core::decide_with_id(&s, &cmd, &ctx(ADMIN, NOW), cid(9), &Answers::new())
        .unwrap();
    assert!(ends_of(&plain).is_empty());
}

/// I-77, design section 5.1 (Q16 A): an ended tenant admin grant ends
/// every session of the account that started at or before the end, weak
/// or strong. A session the ledger ended already is never named again,
/// so the `auth_log.session_end` primary key holds.
#[test]
fn i77_admin_end_batch_ends_every_session_started_by_then() {
    let gone = session(0x57, ADMIN_2, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let s = replay_each(&[admin_granted(ADMIN), admin_granted(ADMIN_2), ended(gone.id)]);
    let cmd = CellCommand::Tenant(TenantCommand::EndTenantAdmin { account: ADMIN_2 });
    let strong = session(0x58, ADMIN_2, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let later = session(0x59, ADMIN_2, Method::Passkey, plus(NOW, 1), plus(NOW, 1));
    let live = [strong.clone(), later, gone, strong.clone()];
    let batch = fstp_cell_core::decide_with_inputs(
        &s,
        &cmd,
        &ctx(ADMIN, NOW),
        cid(9),
        &rows(&live),
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(ends_of(&batch), vec![strong.id]);
}

/// The M2 corpus with C granted programme manager at `T0` and a tenant
/// admin, ADMIN, recorded after it.
fn corpus_with_c() -> Vec<Entry<CellRecord>> {
    let mut s = m2_setup().unwrap();
    m2_run(
        &mut s,
        &grant(BindingId::from_raw(301), C, P1, Role::ProgrammeManager, T0),
        T0,
    )
    .unwrap();
    as_cell(&m2_entries(&s).unwrap())
}

/// I-77, design section 5.1 (Q16 A): with the live session rows, an
/// immediate end of a Drafting binding ends every session of its account
/// that started at or before the end, in the same batch.
#[test]
fn i77_role_end_batch_ends_the_sessions_of_its_account() {
    let s = extended(&corpus_with_c(), &[admin_granted(ADMIN)], T0);
    let cmd = CellCommand::Engine(fstp_engine::Command::Core(
        end(BindingId::from_raw(301), NOW).cmd,
    ));
    let c_session = session(0x5A, C, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let b_session = session(0x5B, B, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let batch = fstp_cell_core::decide_with_inputs(
        &s,
        &cmd,
        &ctx(ADMIN, NOW),
        cid(9),
        &rows(&[c_session.clone(), b_session]),
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(ends_of(&batch), vec![c_session.id]);
}

/// I-77, design sections 5.1 and 8.2: `EndSessionsAtBindingEnd`, with the
/// timeline's session rows, ends every live session of the account that
/// started before the due end instant. Without rows it is refused as a
/// missing input, and with no such session it appends nothing.
#[test]
fn i77_end_sessions_at_binding_end_names_the_sessions_the_gate_refuses() {
    let mut m2 = m2_setup().unwrap();
    m2_run(
        &mut m2,
        &grant(BindingId::from_raw(301), C, P1, Role::ProgrammeManager, T0),
        T0,
    )
    .unwrap();
    m2_run(
        &mut m2,
        &end(BindingId::from_raw(301), NOW),
        plus(NOW, -10 * MINUTE_US),
    )
    .unwrap();
    let s = state_of(&as_cell(&m2_entries(&m2).unwrap())).unwrap();
    let cmd = CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account: C });
    let x = SystemCtx {
        task: SystemTask::Timeline,
        at: NOW.micros(),
    };
    let id = fstp_cell_core::system_command_id([1; 8]);
    let before = session(0x5C, C, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let at_end = session(0x5D, C, Method::Passkey, NOW, NOW);
    let other = session(0x5E, B, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let batch = fstp_cell_core::decide_system_with_inputs(
        &s,
        &cmd,
        &x,
        id,
        &rows(&[before.clone(), at_end.clone(), other]),
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(ends_of(&batch), vec![before.id]);
    assert_eq!(
        fstp_cell_core::decide_system(&s, &cmd, &x, id, &Answers::new()),
        Err(CellRefusal::Domain(ROUTE_INPUT_MISSING))
    );
    assert_eq!(
        fstp_cell_core::decide_system_with_inputs(
            &s,
            &cmd,
            &x,
            id,
            &rows(&[at_end]),
            &Answers::new()
        ),
        Err(refused(RuleRef::Input, RefusalReason::UnknownEntity))
    );
}

// ---------------------------------------------------------------------------
// R-LG-04.

/// R-LG-04: with the session rows, `EndSession` ends the caller's own
/// live session. Another account's session reads as unknown, and without
/// rows the command is refused as a missing input.
#[test]
fn r_lg_04_end_session_ends_only_the_callers_own_live_session() {
    let s = replay_each(&[]);
    let own = passkey(A);
    let theirs = session(0x60, B, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let live = [own.clone(), theirs.clone()];
    let end_of = |id: [u8; 16], inputs: &RouteInputs| {
        fstp_cell_core::decide_with_inputs(
            &s,
            &CellCommand::Auth(AuthCommand::EndSession { session: id }),
            &ctx(A, NOW),
            cid(9),
            inputs,
            &Answers::new(),
        )
    };
    assert_eq!(end_of(own.id, &rows(&live)), Ok(vec![ended(own.id)]));
    assert_eq!(
        end_of(theirs.id, &rows(&live)),
        Err(refused(RuleRef::Input, RefusalReason::UnknownEntity))
    );
    assert_eq!(
        end_of(own.id, &RouteInputs::none()),
        Err(CellRefusal::Domain(ROUTE_INPUT_MISSING))
    );
}

/// R-LG-04: revoking a device records the revocation and ends every live
/// passkey session that device logged in, and no other session.
#[test]
fn r_lg_04_revoking_a_device_ends_the_sessions_it_logged_in() {
    let s = replay_each(&[registered(A, &[0x5E, 0]), registered(A, &[0x5E, 1])]);
    let by_device = passkey(A);
    let by_other = session(0x61, A, Method::Passkey, plus(NOW, -MINUTE_US), NOW);
    let logins = vec![
        SessionLogin {
            session: by_device.id,
            credential: vec![0x5E, 0],
        },
        SessionLogin {
            session: by_other.id,
            credential: vec![0x5E, 1],
        },
    ];
    let inputs = RouteInputs::none()
        .with_sessions(SessionRows::new(vec![by_device.clone(), by_other], logins));
    let batch = fstp_cell_core::decide_with_inputs(
        &s,
        &CellCommand::Auth(AuthCommand::RevokeCredential {
            account: A,
            credential: vec![0x5E, 0],
        }),
        &ctx(A, NOW),
        cid(9),
        &inputs,
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(
        batch,
        vec![
            CellRecord::Auth(AuthRecord::CredentialRevoked {
                account: A,
                credential: vec![0x5E, 0],
            }),
            ended(by_device.id),
        ]
    );
}

/// R-LG-04, design section 5.4: an admitted command carries the session
/// rows its route attached, and the driver appends the batch they give
/// with the ended session among its side effects.
#[test]
fn r_lg_04_driver_appends_the_sessions_its_admission_carries() {
    let s = replay_each(&[]);
    let own = passkey(A);
    let action = Action::Command(CellCommand::Auth(AuthCommand::EndSession {
        session: own.id,
    }));
    let admitted = gate::admit_command(&s, &own, action, cid(9), None, NOW, &POLICY)
        .unwrap()
        .with_sessions(SessionRows::new(vec![own.clone()], Vec::new()));
    let mut state = s.clone();
    let mut d = DriverCore::start(admitted);
    let mut ev = None;
    for _ in 0..16 {
        match d.step(&mut state, ev.take()) {
            Step::Need(Need::ReadFrom(_)) => ev = Some(Event::Read(Vec::new())),
            Step::Need(Need::Epoch) => ev = Some(Event::Epoch(Ok(VaultEpoch::from_raw(0)))),
            Step::Need(Need::Append { batch, side, .. }) => {
                assert_eq!(batch, vec![ended(own.id)]);
                assert_eq!(side.sessions_ended, vec![own.id]);
                return;
            }
            other => panic!("unexpected step {other:?}"),
        }
    }
    panic!("the driver did not append");
}

// ---------------------------------------------------------------------------
// Step-ups (I-78).

/// I-78, design sections 4.2 and 8.4: the step-up id is the challenge id
/// end to end. `GrantStepUp` under the challenge id as its command id
/// records `StepUpGranted` with that id, so `StepUpConsumed` and the
/// `auth_log.stepup_consumed.challenge_id` row name it too.
#[test]
fn i78_step_up_id_is_the_challenge_id() {
    let s = replay_each(&[]);
    let challenge = [0xC4; 16];
    let batch = fstp_cell_core::decide_with_id(
        &s,
        &CellCommand::Auth(AuthCommand::GrantStepUp {
            session: passkey(A).id,
            action_digest: [0x45; 32],
        }),
        &ctx(A, NOW),
        challenge,
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(
        batch,
        vec![CellRecord::Auth(AuthRecord::StepUpGranted {
            id: challenge,
            action_digest: [0x45; 32],
            session: passkey(A).id,
        })]
    );
    assert_eq!(
        fstp_cell_core::stepup_id(Some(challenge), A, NOW.micros(), [0; 16], [0; 32]),
        challenge
    );
}

/// A verified step-up of `session` for `digest`, asserted at `at`.
fn verified(session: &SessionView, digest: [u8; 32], at: Timestamp) -> StepUp {
    StepUp {
        id: [0xC5; 16],
        session: session.id,
        action_digest: digest,
        asserted_at: at,
        method: Method::Passkey,
        uv: true,
        consumed: false,
    }
}

/// I-78, design section 8.4: the step-up route admission refuses a
/// step-up of another account's credential, an unknown credential, a
/// magic-link session, another session, no UV, a stale assertion and an
/// ended session, each with its own cause. A step-up that passes every
/// check is still refused, since a `StepUp` proves no assertion
/// (`gate::ROUTE_ADMISSION_SEAM`). A plain session admission refuses
/// `GrantStepUp` too (`gate::admit_command`).
#[test]
fn i78_step_up_grant_admission_checks_the_route_proof() {
    let s = replay_each(&[registered(A, &[0x5E, 0]), registered(B, &[0x5E, 9])]);
    let own = passkey(A);
    let ok = verified(&own, [0x46; 32], NOW);
    assert_eq!(
        gate::admit_stepup_grant(&s, &own, &ok, &[0x5E, 0], NOW).err(),
        Some(RouteDeny::Gate(Deny::NotImplemented(
            gate::ROUTE_ADMISSION_SEAM
        )))
    );
    let deny = |u: &StepUp, cred: &[u8], sess: &SessionView, now: Timestamp| {
        gate::admit_stepup_grant(&s, sess, u, cred, now).err()
    };
    assert_eq!(
        deny(&ok, &[0x5E, 9], &own, NOW),
        Some(RouteDeny::StepUp(StepUpDeny::OtherAccount))
    );
    assert_eq!(
        deny(&ok, &[0x5E, 7], &own, NOW),
        Some(RouteDeny::UnknownCredential)
    );
    assert_eq!(
        deny(&ok, &[0x5E, 0], &magic(A), NOW),
        Some(RouteDeny::StepUp(StepUpDeny::MagicLinkSession))
    );
    let mut other_session = ok;
    other_session.session = [0x99; 16];
    assert_eq!(
        deny(&other_session, &[0x5E, 0], &own, NOW),
        Some(RouteDeny::StepUp(StepUpDeny::OtherSession))
    );
    let mut no_uv = ok;
    no_uv.uv = false;
    assert_eq!(
        deny(&no_uv, &[0x5E, 0], &own, NOW),
        Some(RouteDeny::StepUp(StepUpDeny::NoUserVerification))
    );
    assert_eq!(
        deny(
            &verified(&own, [0x46; 32], plus(NOW, -1)),
            &[0x5E, 0],
            &own,
            NOW
        ),
        Some(RouteDeny::StepUp(StepUpDeny::Stale))
    );
    let s_ended = replay_each(&[registered(A, &[0x5E, 0]), ended(own.id)]);
    assert_eq!(
        gate::admit_stepup_grant(&s_ended, &own, &ok, &[0x5E, 0], NOW).err(),
        Some(RouteDeny::Gate(Deny::SessionEnded))
    );
    let plain = Action::Command(CellCommand::Auth(AuthCommand::GrantStepUp {
        session: own.id,
        action_digest: [0x46; 32],
    }));
    assert_eq!(
        gate::admit_command(&s, &own, plain, ok.id, None, NOW, &POLICY).err(),
        Some(Deny::NotPermitted)
    );
}

// ---------------------------------------------------------------------------
// Recovery (I-79).

/// I-79, design sections 8.5 and 8.7: the public recovery request is
/// admitted for the account it names, as a ceremony principal, with the
/// deployment mode as its input. The batch records the path for that
/// mode: a sole tenant admin takes the operator process on SaaS and the
/// host console when self-hosted. A taken case id is refused.
#[test]
fn i79_recovery_request_admission_records_the_path_of_the_mode() {
    let s = replay_each(&[admin_granted(ADMIN)]);
    let case = [0xCB; 16];
    for (mode, path) in [
        (Deployment::Saas, RecoveryPath::OperatorProcess),
        (Deployment::SelfHosted, RecoveryPath::HostConsole),
    ] {
        let a = gate::admit_recovery_request(&s, case, ADMIN, mode, cid(9), NOW).unwrap();
        assert_eq!(a.principal(), Principal::Ceremony(ADMIN));
        assert_eq!(a.inputs().mode(), Some(mode));
        let Action::Command(cmd) = a.action() else {
            panic!("a read");
        };
        let batch = fstp_cell_core::decide_with_inputs(
            &s,
            cmd,
            &ctx(ADMIN, NOW),
            cid(9),
            a.inputs(),
            &Answers::new(),
        )
        .unwrap();
        assert_eq!(
            batch,
            vec![CellRecord::Auth(AuthRecord::RecoveryRequested {
                case,
                account: ADMIN,
                path,
            })]
        );
    }
    let taken = replay_each(&[
        admin_granted(ADMIN),
        CellRecord::Auth(AuthRecord::RecoveryRequested {
            case,
            account: ADMIN,
            path: RecoveryPath::OperatorProcess,
        }),
    ]);
    assert_eq!(
        gate::admit_recovery_request(&taken, case, ADMIN, Deployment::Saas, cid(9), NOW).err(),
        Some(RouteDeny::CaseTaken)
    );
}

/// I-79, design sections 5.4 and 8.5: a completion "ends every session
/// of the account", not only the rows its route read. So the gate refuses
/// every session of the account that started at or before the entry
/// instant of `RecoveryCompleted`, as it does for a binding end. A session
/// that started after it, and a session of another account, are admitted.
#[test]
fn i79_gate_refuses_sessions_started_by_a_completed_recovery() {
    let case = [0xCD; 16];
    let completed = plus(NOW, -MINUTE_US);
    let s = state_of(
        &ledger(&[
            (T0, cid(1), vec![registered(A, &[0x5E, 0])]),
            (
                T0,
                cid(2),
                vec![CellRecord::Auth(AuthRecord::RecoveryRequested {
                    case,
                    account: A,
                    path: RecoveryPath::EmailThenPasskey,
                })],
            ),
            (
                T0,
                cid(3),
                vec![CellRecord::Auth(AuthRecord::RecoveryEmailProven { case })],
            ),
            (
                completed,
                cid(4),
                vec![CellRecord::Auth(AuthRecord::RecoveryCompleted {
                    case,
                    account: A,
                    path: RecoveryPath::EmailThenPasskey,
                    shown_to_tenant: false,
                })],
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    let read = || Action::Read(gate::ReadAction::ReadContent);
    let admit = |sess: &SessionView| gate::admit(&s, sess, read(), None, NOW, &POLICY).err();
    // passkey(A) started at the completion instant.
    assert_eq!(passkey(A).started, completed);
    assert_eq!(admit(&passkey(A)), Some(Deny::SessionEnded));
    let earlier = session(0x53, A, Method::Passkey, plus(completed, -1), NOW);
    assert_eq!(admit(&earlier), Some(Deny::SessionEnded));
    let later = session(0x54, A, Method::Passkey, plus(completed, 1), NOW);
    assert_eq!(admit(&later), None);
    assert_eq!(admit(&passkey(B)), None);
}
