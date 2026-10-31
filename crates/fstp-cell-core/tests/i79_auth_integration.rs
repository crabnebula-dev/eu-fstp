//! The auth member of the cell after lanes W2b and W2c met (I-23, I-78,
//! I-79, R-LG-04, ADR-007, M3 design sections 5.1, 5.4 and 8).
//!
//! - The `auth` member of the envelope is the spelling of
//!   `fstp_auth::codec`, byte for byte, and its decoder refuses what the
//!   auth codec refuses.
//! - The fold refuses unknown and repeated references of every auth
//!   record: credentials, step-ups, recovery cases and invitations.
//! - A step-up that the ledger granted admits only its recorded session.
//!   The route-only auth commands never pass the gate through a session.
//! - `ApproveRecovery` asks the vault, needs its step-up, and records the
//!   approval of a second tenant admin only on the `SecondAdmin` path.
//! - A command whose batch needs a route input is refused with the closed
//!   refusal `ROUTE_INPUT_MISSING`, never the stub's `NotImplemented`.
//! - A recovery completion folds only when the case holds the recorded
//!   evidence of its path, and a step-up consumption only after its grant.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../../fstp-domain/tests/codec_support/mod.rs"]
#[allow(unused_macros, unused_imports)]
mod codec_support;

mod cells;
mod common;

use common::{NOW, POLICY, admin_granted, admit_plain, cid, ledger, passkey, read_all, stepup};
use fstp_auth::{AuthCommand, AuthRecord, CoseKey, RecoveryPath};
use fstp_cell_core::driver::{DriverCore, Event, ExecError, Need, Step};
use fstp_cell_core::gate::{self, Action, Deny, HighRiskAction};
use fstp_cell_core::{
    CellCommand, CellCtx, CellRecord, CellRefusal, CellState, RouteInput, decode_cell_command,
    decode_cell_record, encode_cell_command, encode_cell_record, route_inputs,
};
use fstp_domain::id::{AccountId, ContentDigest, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, T0};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_prop::{Gen, check, prop_assert_eq};

fn auth(r: AuthRecord) -> CellRecord {
    CellRecord::Auth(r)
}

fn refused(rule: RuleRef, reason: RefusalReason) -> CellRefusal {
    CellRefusal::Domain(Refusal::new(rule, reason))
}

// ---------------------------------------------------------------------------
// One spelling (ADR-007, design section 5.1).

/// `{"auth":` + `bytes` + `}`.
fn wrapped(bytes: &[u8]) -> Vec<u8> {
    let mut out = b"{\"auth\":".to_vec();
    out.extend_from_slice(bytes);
    out.push(b'}');
    out
}

/// ADR-007, I-23: an auth record inside the cell envelope is the text
/// `fstp_auth::codec::encode_auth_record` gives, byte for byte, and it
/// decodes back to itself.
#[test]
fn adr007_auth_record_member_is_the_fstp_auth_spelling() {
    check(
        "adr007_auth_record_member_is_the_fstp_auth_spelling",
        |g: &mut Gen| {
            let r = cells::auth_record(g);
            let alone = fstp_auth::codec::encode_auth_record(&r)
                .map_err(|e| format!("auth codec: {e:?}"))?;
            let bytes = encode_cell_record(&CellRecord::Auth(r.clone()));
            prop_assert_eq!(&bytes, &wrapped(&alone), "{r:?}");
            prop_assert_eq!(decode_cell_record(&bytes), Ok(CellRecord::Auth(r)));
            Ok(())
        },
    );
}

/// ADR-007, I-78: an auth command inside the cell envelope is the text
/// `fstp_auth::codec::encode_auth_command` gives, byte for byte, so the
/// step-up action digest names one spelling (design section 8.4).
#[test]
fn adr007_auth_command_member_is_the_fstp_auth_spelling() {
    check(
        "adr007_auth_command_member_is_the_fstp_auth_spelling",
        |g: &mut Gen| {
            let c = cells::auth_command(g);
            let alone = fstp_auth::codec::encode_auth_command(&c)
                .map_err(|e| format!("auth codec: {e:?}"))?;
            let bytes = encode_cell_command(&CellCommand::Auth(c.clone()));
            prop_assert_eq!(&bytes, &wrapped(&alone), "{c:?}");
            prop_assert_eq!(decode_cell_command(&bytes), Ok(CellCommand::Auth(c)));
            Ok(())
        },
    );
}

/// ADR-007, R-NF-02: the envelope refuses each auth member that
/// `fstp_auth::codec` refuses, and the error names the member only.
#[test]
fn adr007_auth_member_refuses_what_the_auth_codec_refuses() {
    let bad: [&[u8]; 5] = [
        // Not a COSE key.
        br#"{"account":"7","credential":"0102","public_key":"00","type":"CredentialRegistered","user_verified":true}"#,
        // The operator path is always shown to the tenant.
        br#"{"account":"7","case":"00000000000000000000000000000000","path":"OperatorProcess","shown_to_tenant":false,"type":"RecoveryCompleted"}"#,
        // A split token is only the first admin's.
        br#"{"account":"7","first_admin":false,"invitation":"00000000000000000000000000000000","split":true,"token_digest":"0000000000000000000000000000000000000000000000000000000000000000","type":"InvitationIssued"}"#,
        // A step-up names the session it was made in.
        br#"{"action_digest":"0000000000000000000000000000000000000000000000000000000000000000","id":"00000000000000000000000000000000","type":"StepUpGranted"}"#,
        // An unknown member.
        br#"{"session":"00000000000000000000000000000000","type":"SessionEnded","x":true}"#,
    ];
    for inner in bad {
        assert!(
            fstp_auth::codec::decode_auth_record(inner).is_err(),
            "the auth codec took {}",
            String::from_utf8_lossy(inner)
        );
        match decode_cell_record(&wrapped(inner)) {
            Err(fstp_cell_core::codec::DecodeError::Body { member, .. }) => {
                assert_eq!(member, "auth");
            }
            other => panic!("{}: {other:?}", String::from_utf8_lossy(inner)),
        }
    }
}

/// ADR-007, design section 15: the auth seeds of the decode fuzz targets
/// are stored bytes the decoders accept, so the fuzzer starts inside the
/// auth codec's schema.
#[test]
fn adr007_auth_fuzz_seeds_decode() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds");
    for name in ["auth_session", "auth_credential", "auth_recovery_completed"] {
        let bytes = std::fs::read(format!("{dir}/cell_record_decode/{name}")).unwrap();
        let r = decode_cell_record(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(encode_cell_record(&r), bytes, "{name}");
    }
    let bytes = std::fs::read(format!("{dir}/cell_command_decode/auth_approve_recovery")).unwrap();
    let c = decode_cell_command(&bytes).unwrap();
    assert_eq!(
        c,
        CellCommand::Auth(AuthCommand::ApproveRecovery { case: CASE })
    );
}

// ---------------------------------------------------------------------------
// The auth fold (I-23, design section 5.1).

fn key() -> CoseKey {
    CoseKey::Ed25519 { x: [0x0D; 32] }
}

fn registered(account: AccountId, credential: &[u8]) -> CellRecord {
    auth(AuthRecord::CredentialRegistered {
        account,
        credential: credential.to_vec(),
        key: key(),
        user_verified: true,
    })
}

fn revoked(account: AccountId, credential: &[u8]) -> CellRecord {
    auth(AuthRecord::CredentialRevoked {
        account,
        credential: credential.to_vec(),
    })
}

const CASE: [u8; 16] = [0xCA; 16];

fn requested(account: AccountId) -> CellRecord {
    auth(AuthRecord::RecoveryRequested {
        case: CASE,
        account,
        path: RecoveryPath::SecondAdmin,
    })
}

fn proven() -> CellRecord {
    auth(AuthRecord::RecoveryEmailProven { case: CASE })
}

fn approved(approver: AccountId) -> CellRecord {
    auth(AuthRecord::RecoveryApproved {
        case: CASE,
        approver,
    })
}

fn completed(account: AccountId) -> CellRecord {
    completed_by(account, RecoveryPath::SecondAdmin)
}

fn completed_by(account: AccountId, path: RecoveryPath) -> CellRecord {
    auth(AuthRecord::RecoveryCompleted {
        case: CASE,
        account,
        path,
        shown_to_tenant: path.shown_to_tenant(),
    })
}

fn issued() -> CellRecord {
    auth(AuthRecord::InvitationIssued {
        invitation: [0x1F; 16],
        account: A,
        token_digest: [0x2F; 32],
        first_admin: false,
        split: false,
    })
}

fn consumed_invitation() -> CellRecord {
    auth(AuthRecord::InvitationConsumed {
        invitation: [0x1F; 16],
    })
}

/// The tenant admin grants of `admins`, then `records`.
fn admins_then(admins: &[AccountId], records: &[CellRecord]) -> Vec<CellRecord> {
    admins
        .iter()
        .map(|a| admin_granted(*a))
        .chain(records.iter().cloned())
        .collect()
}

/// Replays `records`, each in its own batch at `T0`.
fn replay_each(records: &[CellRecord]) -> Result<CellState, String> {
    let batches: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(i, r)| (T0, cid(u8::try_from(i + 1).unwrap()), vec![r.clone()]))
        .collect();
    common::state_of(&ledger(&batches)?)
}

/// I-23, I-79, R-LG-04, design section 5.1: the auth fold refuses a
/// record that names an unknown or a used reference, and folds the same
/// records in their valid order.
#[test]
fn i23_auth_fold_refuses_unknown_and_repeated_references() {
    let cred = [0x5E, 1];
    let refused_logs: Vec<(&str, Vec<CellRecord>)> = vec![
        ("revoke unknown", vec![revoked(A, &cred)]),
        (
            "revoke twice",
            vec![registered(A, &cred), revoked(A, &cred), revoked(A, &cred)],
        ),
        (
            "revoke as another account",
            vec![registered(A, &cred), revoked(ADMIN, &cred)],
        ),
        (
            "register one id twice",
            vec![registered(A, &cred), registered(ADMIN, &cred)],
        ),
        (
            "re-register a revoked id",
            vec![
                registered(A, &cred),
                revoked(A, &cred),
                registered(A, &cred),
            ],
        ),
        (
            "suspect unknown",
            vec![auth(AuthRecord::CredentialSuspect {
                account: A,
                credential: cred.to_vec(),
            })],
        ),
        (
            "step-up granted twice",
            vec![
                auth(AuthRecord::StepUpGranted {
                    id: [1; 16],
                    action_digest: [2; 32],
                    session: [3; 16],
                }),
                auth(AuthRecord::StepUpGranted {
                    id: [1; 16],
                    action_digest: [4; 32],
                    session: [3; 16],
                }),
            ],
        ),
        ("request twice", vec![requested(ADMIN), requested(ADMIN)]),
        ("email proof of unknown case", vec![proven()]),
        (
            "email proof twice",
            vec![requested(ADMIN), proven(), proven()],
        ),
        (
            "approval before email proof",
            vec![requested(ADMIN), approved(ADMIN_2)],
        ),
        (
            "approval twice",
            vec![
                requested(ADMIN),
                proven(),
                approved(ADMIN_2),
                approved(ADMIN_2),
            ],
        ),
        (
            "completion of another account",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[requested(ADMIN), proven(), approved(ADMIN_2), completed(A)],
            ),
        ),
        (
            "completion twice",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(ADMIN),
                    proven(),
                    approved(ADMIN_2),
                    completed(ADMIN),
                    completed(ADMIN),
                ],
            ),
        ),
        (
            "second admin completion without an approval",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[requested(ADMIN), proven(), completed(ADMIN)],
            ),
        ),
        (
            "email completion without the email proof",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(A),
                    completed_by(A, RecoveryPath::EmailThenPasskey),
                ],
            ),
        ),
        (
            "operator completion without the email proof",
            admins_then(
                &[ADMIN],
                &[
                    requested(ADMIN),
                    completed_by(ADMIN, RecoveryPath::OperatorProcess),
                ],
            ),
        ),
        (
            "approval after completion",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(A),
                    proven(),
                    completed_by(A, RecoveryPath::EmailThenPasskey),
                    approved(ADMIN_2),
                ],
            ),
        ),
        ("invitation consumed unknown", vec![consumed_invitation()]),
        (
            "invitation consumed twice",
            vec![issued(), consumed_invitation(), consumed_invitation()],
        ),
        (
            "first admin twice",
            vec![
                auth(AuthRecord::FirstAdminEnrolled { account: ADMIN }),
                auth(AuthRecord::FirstAdminEnrolled { account: ADMIN }),
            ],
        ),
    ];
    for (name, log) in refused_logs {
        let r = replay_each(&log);
        assert!(r.is_err(), "{name} folded");
        assert!(!common::is_stub(&common::shown(&r)), "{name}: {r:?}");
    }
    let s = replay_each(&[
        admin_granted(ADMIN),
        admin_granted(ADMIN_2),
        registered(A, &cred),
        auth(AuthRecord::CredentialSuspect {
            account: A,
            credential: cred.to_vec(),
        }),
        revoked(A, &cred),
        requested(ADMIN),
        proven(),
        approved(ADMIN_2),
        completed(ADMIN),
        issued(),
        consumed_invitation(),
        auth(AuthRecord::FirstAdminEnrolled { account: ADMIN }),
    ])
    .unwrap();
    let a = s.auth();
    assert!(a.is_registered(&cred) && !a.has_credential(A, &cred));
    assert!(a.credential(&cred).is_some_and(|c| c.revoked && c.suspect));
    assert_eq!(a.stored_credential(&cred, 0), None);
    let case = a.recovery(CASE).unwrap();
    assert_eq!(
        (case.email_proven, case.approver, case.completed),
        (true, Some(ADMIN_2), Some(RecoveryPath::SecondAdmin))
    );
    assert!(a.invitation([0x1F; 16]).is_some_and(|i| i.consumed));
    assert!(a.first_admin_enrolled(ADMIN));
}

/// I-79, design section 8.5: a host console completion of a sole tenant
/// admin needs no email proof and no approval in the auth records, so it
/// folds on a requested case alone. The console command itself is
/// checked by its route.
#[test]
fn i79_host_console_completion_folds_without_email_proof() {
    let s = replay_each(&[
        admin_granted(ADMIN),
        requested(ADMIN),
        completed_by(ADMIN, RecoveryPath::HostConsole),
    ])
    .unwrap();
    assert_eq!(
        s.auth().recovery(CASE).and_then(|c| c.completed),
        Some(RecoveryPath::HostConsole)
    );
}

/// I-79, design section 8.5: the fold refuses a completion path that the
/// current tenant admins rule out, whatever evidence the case holds.
/// While another tenant admin exists, `HostConsole` and `OperatorProcess`
/// do not fold, so a record cannot name them to skip the approval. With
/// no other tenant admin, `SecondAdmin` does not fold. An account that
/// is a tenant admin never completes by `EmailThenPasskey`.
#[test]
fn i79_completion_path_must_fit_the_tenant_admins() {
    let refused_logs: Vec<(&str, Vec<CellRecord>)> = vec![
        (
            "host console beside another admin",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(ADMIN),
                    completed_by(ADMIN, RecoveryPath::HostConsole),
                ],
            ),
        ),
        (
            "operator process beside another admin",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(ADMIN),
                    proven(),
                    completed_by(ADMIN, RecoveryPath::OperatorProcess),
                ],
            ),
        ),
        (
            "host console for a non-admin beside an admin",
            admins_then(
                &[ADMIN_2],
                &[requested(A), completed_by(A, RecoveryPath::HostConsole)],
            ),
        ),
        (
            "second admin with no other admin",
            admins_then(
                &[ADMIN],
                &[
                    requested(ADMIN),
                    proven(),
                    approved(ADMIN_2),
                    completed(ADMIN),
                ],
            ),
        ),
        (
            "email path for a tenant admin",
            admins_then(
                &[ADMIN, ADMIN_2],
                &[
                    requested(ADMIN),
                    proven(),
                    completed_by(ADMIN, RecoveryPath::EmailThenPasskey),
                ],
            ),
        ),
    ];
    for (name, log) in refused_logs {
        let r = replay_each(&log);
        assert!(r.is_err(), "{name} folded");
        assert!(!common::is_stub(&common::shown(&r)), "{name}: {r:?}");
    }
}

/// I-79, design section 8.5: `recovery::complete` recomputes the path at
/// completion, so a completion may name another path than the request.
/// A `SecondAdmin` case whose other tenant admin left completes by the
/// operator process on its email proof.
#[test]
fn i79_completion_path_may_follow_a_change_of_tenant_admins() {
    let s = replay_each(&admins_then(
        &[ADMIN, ADMIN_2],
        &[
            requested(ADMIN),
            common::admin_ended(ADMIN_2),
            proven(),
            completed_by(ADMIN, RecoveryPath::OperatorProcess),
        ],
    ))
    .unwrap();
    let case = s.auth().recovery(CASE).unwrap();
    assert_eq!(
        (case.requested, case.completed),
        (
            RecoveryPath::SecondAdmin,
            Some(RecoveryPath::OperatorProcess)
        )
    );
}

/// I-79, design section 4.2: a replay rebuilds the stored credential of a
/// live registration from its record, with the sign count the shell
/// passes in.
#[test]
fn i79_replay_rebuilds_the_stored_credential() {
    let cred = [0x5E, 2];
    let s = replay_each(&[registered(A, &cred)]).unwrap();
    let (owner, stored) = s.auth().stored_credential(&cred, 7).unwrap();
    assert_eq!(owner, A);
    assert_eq!(
        stored,
        fstp_auth::StoredCredential {
            id: cred.to_vec(),
            key: key(),
            sign_count: 7,
        }
    );
    assert!(s.auth().credential(&cred).is_some_and(|c| c.user_verified));
}

// ---------------------------------------------------------------------------
// The gate (I-78, design sections 5.4 and 8.7).

/// I-78, design section 8.4: a step-up the ledger granted for one session
/// admits no command of another session, even with its digest and id.
/// In its own session it admits the command.
#[test]
fn i78_ledger_step_up_admits_only_its_recorded_session() {
    let c = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin {
        account: ADMIN_2,
    });
    let id = cid(0x33);
    let digest = fstp_cell_core::action_digest(&c, id);
    let mine = passkey(ADMIN);
    let su = stepup(&mine, digest, NOW);
    // The grant is recorded at the assertion instant, as the step-up
    // route records it (design section 8.4).
    let grant = |session: [u8; 16]| {
        common::state_of(
            &ledger(&[
                (T0, cid(1), vec![admin_granted(ADMIN)]),
                (
                    su.asserted_at,
                    cid(2),
                    vec![auth(AuthRecord::StepUpGranted {
                        id: su.id,
                        action_digest: digest,
                        session,
                    })],
                ),
            ])
            .unwrap(),
        )
        .unwrap()
    };
    let other = grant([0x99; 16]);
    assert_eq!(
        gate::admit_command(
            &other,
            &mine,
            Action::Command(c.clone()),
            id,
            Some(&su),
            NOW,
            &POLICY
        ),
        Err(Deny::StepUpMismatch)
    );
    let own = grant(mine.id);
    assert!(
        gate::admit_command(&own, &mine, Action::Command(c), id, Some(&su), NOW, &POLICY).is_ok()
    );
}

/// I-78, design sections 5.4 and 8.4: a step-up the ledger granted for
/// another command's digest admits no command, even when the view names
/// its id and session and carries the admitted command's digest. The
/// ledger record decides the digest, not the view the shell built.
#[test]
fn i78_ledger_step_up_admits_only_its_recorded_digest() {
    let c = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin {
        account: ADMIN_2,
    });
    let other_c =
        CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin { account: A });
    let id = cid(0x35);
    let digest = fstp_cell_core::action_digest(&c, id);
    let other_digest = fstp_cell_core::action_digest(&other_c, id);
    assert_ne!(digest, other_digest);
    let mine = passkey(ADMIN);
    let su = stepup(&mine, digest, NOW);
    let granted = |action_digest: [u8; 32]| {
        common::state_of(
            &ledger(&[
                (T0, cid(1), vec![admin_granted(ADMIN)]),
                (
                    su.asserted_at,
                    cid(2),
                    vec![auth(AuthRecord::StepUpGranted {
                        id: su.id,
                        action_digest,
                        session: mine.id,
                    })],
                ),
            ])
            .unwrap(),
        )
        .unwrap()
    };
    let other = granted(other_digest);
    assert_eq!(
        gate::admit_command(
            &other,
            &mine,
            Action::Command(c.clone()),
            id,
            Some(&su),
            NOW,
            &POLICY
        ),
        Err(Deny::StepUpMismatch)
    );
    let own = granted(digest);
    assert!(
        gate::admit_command(&own, &mine, Action::Command(c), id, Some(&su), NOW, &POLICY).is_ok()
    );
}

/// I-78, P-71, design section 8.4: freshness is checked against the
/// logged grant too. A view that claims a fresh assertion for a grant
/// the ledger logged more than P-71 ago is stale. At exactly P-71 it
/// admits, and `Admitted` carries the logged instant for the commit.
#[test]
fn i78_gate_checks_p71_against_the_logged_grant() {
    let c = CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::GrantTenantAdmin {
        account: ADMIN_2,
    });
    let id = cid(0x34);
    let mine = passkey(ADMIN);
    let su = stepup(&mine, fstp_cell_core::action_digest(&c, id), NOW);
    let granted_at = |at: fstp_domain::time::Timestamp| {
        common::state_of(
            &ledger(&[
                (T0, cid(1), vec![admin_granted(ADMIN)]),
                (at, cid(2), vec![common::grant_record(&su)]),
            ])
            .unwrap(),
        )
        .unwrap()
    };
    let admit = |s: &CellState| {
        gate::admit_command(
            s,
            &mine,
            Action::Command(c.clone()),
            id,
            Some(&su),
            NOW,
            &POLICY,
        )
    };
    let old = granted_at(common::plus(NOW, -common::P71_US - 1));
    assert_eq!(admit(&old), Err(Deny::StepUpStale));
    let edge_at = common::plus(NOW, -common::P71_US);
    let edge = admit(&granted_at(edge_at)).unwrap();
    assert_eq!(edge.stepup().map(|u| u.asserted_at), Some(edge_at));
}

/// I-78, I-79, design sections 8.4, 8.5 and 8.7: the auth commands that
/// only a route issues, after it verified what the record states, are
/// never admitted through a session.
#[test]
fn i79_route_only_auth_commands_never_pass_a_session() {
    let s = replay_each(&[admin_granted(ADMIN)]).unwrap();
    for c in [
        AuthCommand::GrantStepUp {
            session: passkey(ADMIN).id,
            action_digest: [1; 32],
        },
        AuthCommand::RequestRecovery {
            case: CASE,
            account: ADMIN,
        },
        AuthCommand::ProveRecoveryEmail { case: CASE },
        AuthCommand::CompleteRecovery {
            case: CASE,
            credential: vec![1],
        },
    ] {
        assert_eq!(
            admit_plain(
                &s,
                &passkey(ADMIN),
                Action::Command(CellCommand::Auth(c.clone())),
                NOW
            ),
            Err(Deny::NotPermitted),
            "{c:?}"
        );
    }
}

/// R-LG-04, I-78: ending a session needs a session only, and approving a
/// recovery is the high-risk action `ApproveRecovery`.
#[test]
fn r_lg_04_end_session_is_a_session_action_and_approval_is_high_risk() {
    let of = |c: AuthCommand| HighRiskAction::of(&Action::Command(CellCommand::Auth(c)));
    assert_eq!(of(AuthCommand::EndSession { session: [1; 16] }), Ok(None));
    assert_eq!(
        of(AuthCommand::ApproveRecovery { case: CASE }),
        Ok(Some(HighRiskAction::ApproveRecovery))
    );
}

// ---------------------------------------------------------------------------
// Route inputs (I-23, design section 8).

/// I-23, design section 8: a command whose batch needs a route input
/// passes the ledger checks, then is refused with the domain refusal
/// `ROUTE_INPUT_MISSING`, never with the stub's `NotImplemented`. That
/// refusal is not the one of a missing vault answer (`FactsIncomplete`),
/// so a caller tells the two apart. Lane W3a owns the routes that hold
/// those inputs.
#[test]
fn i23_route_input_commands_are_refused_as_a_missing_route_input() {
    assert_eq!(RouteInput::OWNER, "W3a");
    assert_eq!(
        fstp_cell_core::ROUTE_INPUT_MISSING,
        Refusal::new(RuleRef::Input, RefusalReason::AnswerMissing)
    );
    assert_ne!(
        fstp_cell_core::ROUTE_INPUT_MISSING,
        Refusal::new(RuleRef::FactsIncomplete, RefusalReason::AnswerMissing)
    );
    let cred = [0x5E, 3];
    let s = replay_each(&[
        admin_granted(ADMIN),
        registered(A, &cred),
        requested(ADMIN),
        proven(),
    ])
    .unwrap();
    let cases = [
        (
            A,
            AuthCommand::RegisterCredential {
                account: A,
                credential: vec![0x5E, 4],
            },
        ),
        (
            A,
            AuthCommand::RevokeCredential {
                account: A,
                credential: cred.to_vec(),
            },
        ),
        (A, AuthCommand::EndSession { session: [7; 16] }),
        (
            A,
            AuthCommand::RequestRecovery {
                case: [0xCB; 16],
                account: A,
            },
        ),
        (
            ADMIN,
            AuthCommand::CompleteRecovery {
                case: CASE,
                credential: vec![0x5E, 5],
            },
        ),
    ];
    for (actor, c) in cases {
        assert!(!route_inputs(&c).is_empty(), "{c:?}");
        let r = fstp_cell_core::decide(
            &s,
            &CellCommand::Auth(c.clone()),
            &CellCtx {
                actor,
                at: NOW.micros(),
            },
            &Answers::new(),
        );
        assert_eq!(
            r,
            Err(CellRefusal::Domain(fstp_cell_core::ROUTE_INPUT_MISSING)),
            "{c:?}"
        );
    }
}

/// R-LG-04, I-79: the ledger checks come before the route input. Only a
/// credential's own account revokes it, and a registered id is never
/// registered again (WebAuthn Level 2 section 7.1 step 22).
#[test]
fn r_lg_04_revocation_and_registration_check_the_ledger_first() {
    let cred = [0x5E, 6];
    let s = replay_each(&[admin_granted(ADMIN), registered(A, &cred)]).unwrap();
    let run = |actor: AccountId, c: AuthCommand| {
        fstp_cell_core::decide(
            &s,
            &CellCommand::Auth(c),
            &CellCtx {
                actor,
                at: NOW.micros(),
            },
            &Answers::new(),
        )
    };
    let revoke = AuthCommand::RevokeCredential {
        account: A,
        credential: cred.to_vec(),
    };
    assert_eq!(
        run(ADMIN, revoke),
        Err(refused(RuleRef::Actor, RefusalReason::WrongActor))
    );
    assert_eq!(
        run(
            A,
            AuthCommand::RevokeCredential {
                account: A,
                credential: vec![0x5E, 7],
            }
        ),
        Err(refused(RuleRef::Input, RefusalReason::UnknownEntity))
    );
    assert_eq!(
        run(
            ADMIN,
            AuthCommand::RegisterCredential {
                account: ADMIN,
                credential: cred.to_vec(),
            }
        ),
        Err(refused(RuleRef::Input, RefusalReason::IdReused))
    );
}

/// I-78, design section 8.4: `GrantStepUp` records the session it was
/// made in beside its action digest.
#[test]
fn i78_step_up_grant_records_its_session() {
    let s = replay_each(&[admin_granted(ADMIN)]).unwrap();
    let batch = fstp_cell_core::decide(
        &s,
        &CellCommand::Auth(AuthCommand::GrantStepUp {
            session: [0x44; 16],
            action_digest: [0x45; 32],
        }),
        &CellCtx {
            actor: ADMIN,
            at: NOW.micros(),
        },
        &Answers::new(),
    )
    .unwrap();
    assert!(
        matches!(
            batch.as_slice(),
            [CellRecord::Auth(AuthRecord::StepUpGranted { action_digest, session, .. })]
                if *action_digest == [0x45; 32] && *session == [0x44; 16]
        ),
        "{batch:?}"
    );
}

/// I-79, design section 8.5: only the holder records the email proof of
/// their own open case, once.
#[test]
fn i79_email_proof_is_the_holders_own_once() {
    let s = replay_each(&[admin_granted(ADMIN), requested(ADMIN)]).unwrap();
    let prove = |actor: AccountId, s: &CellState| {
        fstp_cell_core::decide(
            s,
            &CellCommand::Auth(AuthCommand::ProveRecoveryEmail { case: CASE }),
            &CellCtx {
                actor,
                at: NOW.micros(),
            },
            &Answers::new(),
        )
    };
    assert_eq!(
        prove(A, &s),
        Err(refused(RuleRef::Actor, RefusalReason::WrongActor))
    );
    assert_eq!(
        prove(ADMIN, &s),
        Ok(vec![auth(AuthRecord::RecoveryEmailProven { case: CASE })])
    );
    let again = replay_each(&[admin_granted(ADMIN), requested(ADMIN), proven()]).unwrap();
    assert_eq!(
        prove(ADMIN, &again),
        Err(refused(RuleRef::Input, RefusalReason::IdReused))
    );
}

// ---------------------------------------------------------------------------
// ApproveRecovery through the driver (I-79, design section 8.5).

/// What the vault answers in [`approve`].
#[derive(Clone, Copy)]
enum Vault {
    /// Both verified, `SameIdentityAsAny` as given.
    Verified { same: bool },
    /// Neither is verified.
    Unverified,
    /// The vault does not answer.
    Down,
}

fn answer(holds: bool) -> Answer {
    Answer {
        holds,
        accounts: None,
        epoch: VaultEpoch::from_raw(0),
        digest: ContentDigest::from_bytes([0; 32]),
    }
}

/// A ledger with tenant admins `admins` and the case of `holder` with its
/// email proof, in a store.
fn case_store(admins: &[AccountId], holder: AccountId) -> MemStore<CellRecord> {
    let mut records: Vec<CellRecord> = admins.iter().map(|a| admin_granted(*a)).collect();
    records.push(requested(holder));
    records.push(proven());
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (i, r) in records.into_iter().enumerate() {
        store
            .append(
                store.head(),
                T0.micros(),
                cid(u8::try_from(i + 1).unwrap()),
                vec![r],
            )
            .unwrap();
    }
    store
}

/// Runs `ApproveRecovery` of [`CASE`] by `approver` through the gate,
/// with a fresh step-up, and the driver over `store`. Returns the result
/// and the batch appended for the command, if any.
fn approve(
    store: &mut MemStore<CellRecord>,
    approver: AccountId,
    vault: Vault,
) -> (Result<(), String>, Option<Vec<CellRecord>>) {
    let c = CellCommand::Auth(AuthCommand::ApproveRecovery { case: CASE });
    let id = cid(0x77);
    let session = passkey(approver);
    let su = stepup(&session, fstp_cell_core::action_digest(&c, id), NOW);
    // The step-up route recorded the grant at the assertion instant
    // (design section 8.4). Every approver's passkey session has one id,
    // so a store reused for another approver holds that grant already.
    let entries: Vec<Entry<CellRecord>> = read_all(store).unwrap();
    if fstp_cell_core::replay(&entries)
        .unwrap()
        .auth()
        .stepup_grant(su.id)
        .is_none()
    {
        store
            .append(
                store.head(),
                su.asserted_at.micros(),
                common::GRANT_COMMAND,
                vec![common::grant_record(&su)],
            )
            .unwrap();
    }
    let entries: Vec<Entry<CellRecord>> = read_all(store).unwrap();
    let mut s = fstp_cell_core::replay(&entries).unwrap();
    let admitted = match gate::admit_command(
        &s,
        &session,
        Action::Command(c),
        id,
        Some(&su),
        NOW,
        &POLICY,
    ) {
        Ok(a) => a,
        Err(d) => return (Err(format!("gate: {d:?}")), None),
    };
    let mut d = DriverCore::start(admitted);
    let mut ev = None;
    let mut appended = None;
    for _ in 0..64 {
        match d.step(&mut s, ev.take()) {
            Step::Done(r) => return (r.map(|_| ()).map_err(|e| format!("{e:?}")), appended),
            Step::Need(Need::ReadFrom(after)) => {
                let mut out = Vec::new();
                store
                    .read(Seq::from_raw(after.raw() + 1), usize::MAX, &mut out)
                    .unwrap();
                ev = Some(Event::Read(out));
            }
            Step::Need(Need::Epoch) => ev = Some(Event::Epoch(Ok(VaultEpoch::from_raw(0)))),
            Step::Need(Need::Ask { queries, .. }) => {
                ev = Some(Event::Answers(match vault {
                    Vault::Down => Err(fstp_cell_core::driver::VaultFault::Unavailable),
                    v => {
                        let mut a = Answers::new();
                        for q in queries {
                            let holds = match (v, &q) {
                                (Vault::Verified { .. }, Query::IsVerified { .. }) => true,
                                (Vault::Verified { same }, Query::SameIdentityAsAny { .. }) => same,
                                _ => false,
                            };
                            a.insert(q, answer(holds));
                        }
                        Ok(a)
                    }
                }));
            }
            Step::Need(Need::Append {
                expected,
                at,
                command,
                batch,
                ..
            }) => {
                appended = Some(batch.clone());
                ev = Some(Event::Appended(
                    store
                        .append(expected, at, command, batch)
                        .map(|seq| (seq, [0; 32])),
                ));
            }
            Step::Need(Need::Ack { .. }) => ev = Some(Event::Acked(Ok(()))),
        }
    }
    panic!("the driver did not finish");
}

/// I-79, I-78, design section 8.5: a second tenant admin approves the
/// recovery of a tenant admin with a step-up, the vault asked. The batch
/// records the approval and consumes the step-up.
#[test]
fn i79_second_admin_approval_records_the_approval_and_consumes_the_step_up() {
    let mut store = case_store(&[ADMIN, ADMIN_2], ADMIN);
    let (r, batch) = approve(&mut store, ADMIN_2, Vault::Verified { same: false });
    assert_eq!(r, Ok(()));
    let batch = batch.unwrap();
    assert_eq!(batch[0], approved(ADMIN_2));
    assert_eq!(
        batch[1],
        auth(AuthRecord::StepUpConsumed { id: [0x5C; 16] })
    );
    let s = fstp_cell_core::replay(&read_all(&store).unwrap()).unwrap();
    assert_eq!(s.auth().recovery(CASE).unwrap().approver, Some(ADMIN_2));
    // Unverified accounts skip the identity check (design section 8.5).
    let mut store = case_store(&[ADMIN, ADMIN_2], ADMIN);
    assert_eq!(approve(&mut store, ADMIN_2, Vault::Unverified).0, Ok(()));
}

/// I-79, design section 8.5: when both are verified, an approver who
/// shares the holder's identity is refused, and a vault outage refuses
/// the approval (fail closed). Neither appends anything.
#[test]
fn i79_same_identity_and_vault_outage_refuse_the_approval() {
    let mut store = case_store(&[ADMIN, ADMIN_2], ADMIN);
    let (r, batch) = approve(&mut store, ADMIN_2, Vault::Verified { same: true });
    assert_eq!(
        r,
        Err(format!(
            "{:?}",
            ExecError::Refused(refused(RuleRef::Actor, RefusalReason::GuardFailed))
        ))
    );
    assert_eq!(batch, None);
    let (r, batch) = approve(&mut store, ADMIN_2, Vault::Down);
    assert_eq!(r, Err(format!("{:?}", ExecError::VaultFault)));
    assert_eq!(batch, None);
}

/// I-79, design section 8.5: only a different current tenant admin
/// approves, and only on the `SecondAdmin` path. A holder of Receiving
/// roles only takes `EmailThenPasskey`, which takes no approval.
#[test]
fn i79_approval_needs_another_admin_and_the_second_admin_path() {
    let wrong_actor = Err(format!(
        "{:?}",
        ExecError::Refused(refused(RuleRef::Actor, RefusalReason::WrongActor))
    ));
    let mut store = case_store(&[ADMIN, ADMIN_2], ADMIN);
    assert_eq!(
        approve(&mut store, ADMIN, Vault::Unverified).0,
        wrong_actor,
        "self approval"
    );
    assert_eq!(
        approve(&mut store, A, Vault::Unverified).0,
        wrong_actor,
        "not a tenant admin"
    );
    let mut store = case_store(&[ADMIN, ADMIN_2], A);
    assert_eq!(
        approve(&mut store, ADMIN_2, Vault::Unverified).0,
        Err(format!(
            "{:?}",
            ExecError::Refused(refused(RuleRef::Input, RefusalReason::WrongState))
        )),
        "EmailThenPasskey"
    );
}

/// I-79, I-78: without its step-up, `ApproveRecovery` is refused by
/// `decide` too, so no caller records an approval around the gate.
#[test]
fn i79_approval_without_step_up_is_refused() {
    let s =
        fstp_cell_core::replay(&read_all(&case_store(&[ADMIN, ADMIN_2], ADMIN)).unwrap()).unwrap();
    let c = CellCommand::Auth(AuthCommand::ApproveRecovery { case: CASE });
    let x = CellCtx {
        actor: ADMIN_2,
        at: NOW.micros(),
    };
    let qs: Vec<Query> = fstp_cell_core::queries(&s, &c, &x).unwrap();
    assert_eq!(qs.len(), 3, "{qs:?}");
    let mut a = Answers::new();
    for q in qs {
        a.insert(q, answer(false));
    }
    assert_eq!(
        fstp_cell_core::decide(&s, &c, &x, &a),
        Err(refused(RuleRef::I78, RefusalReason::GuardFailed))
    );
}
