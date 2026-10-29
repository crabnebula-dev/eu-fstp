//! System tasks, crash retries, the decide-sequence seeds and the
//! fail-closed step-up digest (I-23, I-24, I-78, SoD-05, ADR-007, M3
//! design sections 3.5, 5.1, 5.2, 8.4 and 15).
//!
//! These are the regression tests of review fix round 1 of lane W2c that
//! run without `fstp-auth` (lane W2b). The erasure runner's admission
//! needs no session, so the driver runs here through the gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

#[path = "../fuzz/fuzz_targets/decide_frames.rs"]
mod decide_frames;

#[path = "../fuzz/fuzz_targets/driver_events.rs"]
mod driver_events;

use common::{MINUTE_US, NOW, as_cell, cid, ledger, m2_entries, m2_run, m2_setup, passkey, plus};
use fstp_auth::AuthCommand;
use fstp_cell_core::driver::{DriverCore, Event, ExecError, Need, Step};
use fstp_cell_core::gate::{self, Action, Deny, ReadAction};
use fstp_cell_core::ops::{OpsCommand, OpsRecord};
use fstp_cell_core::release::ReleaseCommand;
use fstp_cell_core::tenant::{
    P71_DEFAULT_US, P72_ABSOLUTE_DEFAULT_US, P72_IDLE_DEFAULT_US, TenantCommand, TenantLoginPolicy,
};
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{
    ACCOUNT_ERASURE_CAUSES, CellCommand, CellCtx, CellRecord, CellRefusal, ERASURE_CAUSES,
    KeyCommand, KeyRecord, SystemCtx, SystemTask, decide, decide_system, decode_cell_record,
    encode_cell_record, try_action_digest,
};
use fstp_domain::id::{BindingId, VaultEpoch};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, C, P1, T0, end, grant};
use fstp_ledger::{MemStore, RecordStore, Seq};

fn destroy(epoch: u64) -> CellCommand {
    CellCommand::Key(KeyCommand::RecordEpochDestroyed {
        epoch,
        receipt: [0xD5; 32],
    })
}

fn refused(r: &Result<Vec<CellRecord>, CellRefusal>, rule: RuleRef, reason: RefusalReason) -> bool {
    matches!(r, Err(CellRefusal::Domain(f)) if f.rule == rule && f.reason == reason)
}

/// I-24, I-81, ADR-007, design section 3.5: the erasure runner decides key
/// records, and no other caller does. The timeline is refused them, and so
/// is an account.
#[test]
fn i24_key_records_are_decided_by_the_erasure_runner_only() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    let runner = SystemCtx {
        task: SystemTask::ErasureRunner,
        at: NOW.micros(),
    };
    let got = decide_system(&s, &destroy(3), &runner, cid(1), &Answers::new()).unwrap();
    assert_eq!(
        got,
        vec![CellRecord::Key(KeyRecord::EpochDestroyed {
            epoch: 3,
            receipt: [0xD5; 32],
        })]
    );
    let timeline = SystemCtx {
        task: SystemTask::Timeline,
        at: NOW.micros(),
    };
    let r = decide_system(&s, &destroy(3), &timeline, cid(1), &Answers::new());
    assert!(
        refused(&r, RuleRef::Actor, RefusalReason::WrongActor),
        "{r:?}"
    );
    let x = CellCtx {
        actor: ADMIN,
        at: NOW.micros(),
    };
    let r = decide(&s, &destroy(3), &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Actor, RefusalReason::WrongActor),
        "{r:?}"
    );
}

/// I-78, I-24, design sections 5.4 and 8.4: a session is never admitted
/// for a command that only a system path issues, nor for `GrantStepUp`,
/// which only the step-up route records. The refusal reads no session.
#[test]
fn i78_a_session_is_never_admitted_for_a_system_command() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    for c in [
        destroy(1),
        CellCommand::Key(KeyCommand::RecordKeyOp { op: b"{}".to_vec() }),
        CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account: A }),
        CellCommand::Ops(OpsCommand::ApplyOperatorTicket {
            ticket: b"{}".to_vec(),
        }),
        CellCommand::Release(ReleaseCommand::RecordRelationship {
            relationship: b"{}".to_vec(),
        }),
        CellCommand::Auth(AuthCommand::GrantStepUp {
            session: passkey(A).id,
            action_digest: [0; 32],
        }),
    ] {
        let r = gate::admit_command(
            &s,
            &passkey(A),
            Action::Command(c.clone()),
            cid(2),
            None,
            NOW,
            &common::POLICY,
        );
        assert_eq!(r.err(), Some(Deny::NotPermitted), "{c:?}");
    }
}

/// I-24, design sections 3.5 and 5.1: `admit_system` admits each task its
/// own commands only, never a read, and never `VaultChanged`, which only
/// the driver's reaction runs.
#[test]
fn i24_admit_system_admits_each_task_its_own_commands_only() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    let admit = |a: Action, t: SystemTask| gate::admit_system(&s, a, t, cid(3), NOW);
    assert!(admit(Action::Command(destroy(1)), SystemTask::ErasureRunner).is_ok());
    let end_sessions = CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account: A });
    assert!(admit(Action::Command(end_sessions.clone()), SystemTask::Timeline).is_ok());
    let vault_changed = CellCommand::Engine(fstp_cell_core::vault_changed(
        VaultEpoch::from_raw(1),
        Default::default(),
    ));
    let put = CellCommand::Text(TextCommand::PutText { id: [1; 16] });
    for (a, t) in [
        (Action::Command(destroy(1)), SystemTask::Timeline),
        (Action::Command(end_sessions), SystemTask::ErasureRunner),
        (Action::Command(vault_changed), SystemTask::Timeline),
        (Action::Command(put), SystemTask::Timeline),
        (
            Action::Read(ReadAction::ReadAudit),
            SystemTask::ErasureRunner,
        ),
    ] {
        assert_eq!(admit(a.clone(), t).err(), Some(Deny::NotPermitted), "{a:?}");
    }
}

/// I-23, ADR-007 ("a retry after a lost acknowledgement is reported as a
/// duplicate"), design section 5.2: a crash retry under the same command
/// id finds its earlier commit in the catch-up and finishes with that
/// stored result. It decides nothing again and appends nothing. Before the
/// fix the driver decided again and refused the epoch as reused. The
/// result names the stored entry, so the caller tells the retry from a
/// fresh commit (review fix round 2).
#[test]
fn i23_driver_crash_retry_finishes_with_the_stored_result() {
    let id = fstp_cell_core::system_command_id([0x42; 8]);
    let mut store: MemStore<CellRecord> = MemStore::new();
    store
        .append(
            Seq::ZERO,
            NOW.micros(),
            id,
            vec![CellRecord::Key(KeyRecord::EpochDestroyed {
                epoch: 1,
                receipt: [0xD5; 32],
            })],
        )
        .unwrap();
    let mut state = fstp_cell_core::replay(&[]).unwrap();
    let admitted = gate::admit_system(
        &state,
        Action::Command(destroy(1)),
        SystemTask::ErasureRunner,
        id,
        NOW,
    )
    .unwrap();
    let mut d = DriverCore::start(admitted);
    let mut ev = None;
    for _ in 0..32 {
        match d.step(&mut state, ev.take()) {
            Step::Done(r) => {
                assert_eq!(
                    r.map(|d| (d.head, d.duplicate)),
                    Ok((Seq::from_raw(1), Some(Seq::from_raw(1))))
                );
                assert_eq!(RecordStore::head(&store), Seq::from_raw(1));
                return;
            }
            Step::Need(Need::ReadFrom(from)) => {
                let mut out = Vec::new();
                store
                    .read(Seq::from_raw(from.raw() + 1), usize::MAX, &mut out)
                    .unwrap();
                ev = Some(Event::Read(out));
            }
            Step::Need(Need::Epoch) => ev = Some(Event::Epoch(Ok(VaultEpoch::from_raw(0)))),
            Step::Need(n) => panic!("the retry needed {n:?}"),
        }
    }
    panic!("the driver did not finish");
}

/// SoD-05, the Cooling-off NOTE, design sections 5.1 and 8.2: while a
/// scheduled binding end is overdue, an account's cell command is refused
/// as M2 refuses its own. The timeline then records the due end with a
/// System actor, and the cell decides again. A command that is not due is
/// refused to the timeline.
#[test]
fn sod05_overdue_end_refuses_cell_commands_until_the_timeline_ends_it() {
    let mut sc = m2_setup().unwrap();
    let ops = BindingId::from_raw(31);
    m2_run(&mut sc, &grant(ops, C, P1, Role::FinanceApprover, T0), T0).unwrap();
    m2_run(&mut sc, &end(ops, plus(T0, MINUTE_US)), T0).unwrap();
    let entries = as_cell(&m2_entries(&sc).unwrap());
    let s = common::state_of(&entries).unwrap();
    let after = plus(T0, 2 * MINUTE_US);
    let put = CellCommand::Text(TextCommand::PutText { id: [9; 16] });
    let x = CellCtx {
        actor: A,
        at: after.micros(),
    };
    let r = decide(&s, &put, &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Sod05, RefusalReason::WrongState),
        "{r:?}"
    );
    let before = CellCtx {
        actor: A,
        at: plus(T0, 30_000_000).micros(),
    };
    assert!(decide(&s, &put, &before, &Answers::new()).is_ok());
    let timeline = SystemCtx {
        task: SystemTask::Timeline,
        at: after.micros(),
    };
    let due = CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::Command::EndScheduledRole { binding: ops },
    ));
    let batch = decide_system(&s, &due, &timeline, cid(0x51), &Answers::new()).unwrap();
    assert!(!batch.is_empty());
    let not_due = CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::Command::EndScheduledRole {
            binding: BindingId::from_raw(9_999),
        },
    ));
    let r = decide_system(&s, &not_due, &timeline, cid(0x52), &Answers::new());
    assert!(
        refused(&r, RuleRef::Actor, RefusalReason::WrongActor),
        "{r:?}"
    );
    // Fold the end, and the account's command is decided again.
    let mut ended = s.clone();
    let mut seq = ended.head();
    for record in batch {
        seq = Seq::from_raw(seq.raw() + 1);
        let mut e = entries.last().cloned().unwrap();
        e.seq = seq;
        e.at = after.micros();
        e.command = cid(0x51);
        e.record = record;
        fstp_cell_core::apply(&mut ended, &e).unwrap();
    }
    assert!(decide(&ended, &put, &x, &Answers::new()).is_ok());
}

/// I-78, design section 8.4: the step-up digest names one command. A
/// command whose canonical encoding does not decode back to it, such as
/// opaque bytes that are not UTF-8, has no digest, so no step-up admits
/// it. A canonical command's digest is `action_digest`.
#[test]
fn i78_step_up_digest_refuses_a_command_its_encoding_does_not_name() {
    let bad = [vec![0xFF, 0xFE], vec![0xC3]];
    let digests: Vec<_> = bad
        .iter()
        .map(|p| {
            try_action_digest(
                &CellCommand::Tenant(TenantCommand::SetLoginPolicy { policy: p.clone() }),
                cid(1),
            )
        })
        .collect();
    assert_eq!(digests, vec![None, None]);
    let good = CellCommand::Tenant(TenantCommand::SetLoginPolicy {
        policy: TenantLoginPolicy::default().encode(),
    });
    assert_eq!(
        try_action_digest(&good, cid(1)),
        Some(fstp_cell_core::action_digest(&good, cid(1)))
    );
}

/// I-23, Q37, design section 8.4: a stored policy value above this
/// build's default is folded as stored and clamped to the default where it
/// is used, so it may only shorten.
#[test]
fn i78_stored_login_policy_is_clamped_to_the_defaults_where_used() {
    let long = TenantLoginPolicy {
        p71_us: Some(P71_DEFAULT_US + 1),
        p72_idle_us: Some(P72_IDLE_DEFAULT_US + 1),
        p72_absolute_us: Some(P72_ABSOLUTE_DEFAULT_US + 1),
    };
    assert_eq!(TenantLoginPolicy::decode_stored(&long.encode()), Ok(long));
    assert!(TenantLoginPolicy::decode(&long.encode()).is_err());
    assert_eq!(long.p71_us(), P71_DEFAULT_US);
    assert_eq!(long.p72_idle_us(), P72_IDLE_DEFAULT_US);
    assert_eq!(long.p72_absolute_us(), P72_ABSOLUTE_DEFAULT_US);
    let short = TenantLoginPolicy {
        p71_us: Some(MINUTE_US),
        ..TenantLoginPolicy::default()
    };
    assert_eq!(short.p71_us(), MINUTE_US);
}

/// Design sections 5.1 and 8.3, Q14 (interim): a cell that never had a
/// tenant admin still takes its first one by the bootstrap grant.
#[test]
fn sod07_bootstrap_grant_holds_only_in_a_cell_that_never_had_an_admin() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    let cmd = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: A });
    let x = CellCtx {
        actor: A,
        at: NOW.micros(),
    };
    assert!(decide(&s, &cmd, &x, &Answers::new()).is_ok());
    let had = common::state_of(
        &ledger(&[
            (T0, cid(1), vec![common::admin_granted(ADMIN)]),
            (T0, cid(2), vec![common::admin_ended(ADMIN)]),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(had.tenant().ever_had_admin() && had.tenant().admins().is_empty());
    let r = decide(&had, &cmd, &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Actor, RefusalReason::WrongActor),
        "{r:?}"
    );
}

/// Design section 15, `cell_decide_sequence`: the seed `m2_setup` holds
/// the tenant admin bootstrap and the M2 corpus setup (`SodSetup::one`),
/// and every one of its frames is decided, so the target reaches the M2
/// programme, role and call paths.
#[test]
fn i23_decide_sequence_m2_seed_decides_the_corpus_setup() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/cell_decide_sequence/m2_setup"
    );
    let data = std::fs::read(path).unwrap();
    let frames = decide_frames::frames(&data).len();
    assert!(frames > 2, "{frames} frames");
    assert_eq!(decide_frames::run(&data), frames);
}

// ---------------------------------------------------------------------------
// Review fix round 2.

/// ADR-007, design section 5.2: a system task's command runs only under
/// an id in the system task namespace `fstp:st:`. Under any other id the
/// driver refuses it before it reads, asks or appends anything, so a task
/// never meets an account's entry as its own crash retry.
#[test]
fn adr007_driver_refuses_a_system_task_command_outside_its_namespace() {
    let mut state = fstp_cell_core::replay(&[]).unwrap();
    let admitted = gate::admit_system(
        &state,
        Action::Command(destroy(1)),
        SystemTask::ErasureRunner,
        cid(0x43),
        NOW,
    )
    .unwrap();
    let mut d = DriverCore::start(admitted);
    match d.step(&mut state, None) {
        Step::Done(r) => assert_eq!(r, Err(ExecError::NotASystemCommandId)),
        Step::Need(n) => panic!("the driver needed {n:?}"),
    }
}

/// NOTE 4, design section 15, `driver_core_sequence`: the seed
/// `reaction_path` answers the change query, so the driver decides the
/// reaction, appends it, acknowledges it with its link, and then commits
/// the command. The fuzz target thus reaches the reaction paths.
#[test]
fn i23_driver_sequence_reaction_seed_appends_and_acks_a_reaction() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/driver_core_sequence/reaction_path"
    );
    let data = std::fs::read(path).unwrap();
    let outcome = driver_events::run(&data);
    assert_eq!(outcome.reaction_acks, 1, "{outcome:?}");
    let done = outcome.done.unwrap().unwrap();
    assert_eq!(done.duplicate, None);
    // The reaction batch holds two records, and the command one.
    assert_eq!(done.head, Seq::from_raw(3));
}

/// ADR-007 "Erasure-log entries", design section 5.6: a tenant admin is
/// the authoriser of an erasure request and of a cell erasure only. A
/// retention expiry (P-41) and a completed verification (R-ID-03) have the
/// system or the vault as authoriser, so an account is refused them.
#[test]
fn adr007_account_records_only_request_and_cell_erasure_causes() {
    let entries = ledger(&[
        (T0, cid(1), vec![common::admin_granted(ADMIN)]),
        (
            T0,
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: [0x7A; 16] })],
        ),
    ])
    .unwrap();
    let s = common::state_of(&entries).unwrap();
    let x = CellCtx {
        actor: ADMIN,
        at: T0.micros(),
    };
    let erase = |cause: u16| {
        CellCommand::Text(TextCommand::EraseTexts {
            ids: vec![[0x7A; 16]],
            cause,
        })
    };
    let mut got = Vec::new();
    for cause in ERASURE_CAUSES {
        got.push((
            cause,
            decide(&s, &erase(cause), &x, &Answers::new()).is_ok(),
        ));
    }
    let want: Vec<(u16, bool)> = ERASURE_CAUSES
        .iter()
        .map(|c| (*c, ACCOUNT_ERASURE_CAUSES.contains(c)))
        .collect();
    assert_eq!(got, want);
    assert_eq!(ACCOUNT_ERASURE_CAUSES, [2, 3]);
    let r = decide(&s, &erase(1), &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Actor, RefusalReason::WrongActor),
        "{r:?}"
    );
}

/// I-23, design sections 5.3 and 5.6: an erasure of more texts than the
/// codec bound `MAX_TEXT_IDS` is refused, and one at the bound decides
/// into records that read back from their stored bytes.
#[test]
fn i23_erasure_at_the_codec_bound_reads_back_and_beyond_is_refused() {
    let n = fstp_cell_core::codec::MAX_TEXT_IDS;
    let id = |i: usize| {
        let mut id = [0x7B; 16];
        id[8..].copy_from_slice(&(i as u64).to_be_bytes());
        id
    };
    let puts: Vec<CellRecord> = (0..=n)
        .map(|i| CellRecord::Text(TextRecord::TextPut { id: id(i) }))
        .collect();
    let entries = ledger(&[
        (T0, cid(1), vec![common::admin_granted(ADMIN)]),
        (T0, cid(2), puts),
    ])
    .unwrap();
    let s = common::state_of(&entries).unwrap();
    let x = CellCtx {
        actor: ADMIN,
        at: T0.micros(),
    };
    let erase = |k: usize| {
        CellCommand::Text(TextCommand::EraseTexts {
            ids: (0..k).map(id).collect(),
            cause: 2,
        })
    };
    let r = decide(&s, &erase(n + 1), &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Input, RefusalReason::InvalidValue),
        "{r:?}"
    );
    let batch = decide(&s, &erase(n), &x, &Answers::new()).unwrap();
    for r in &batch {
        assert_eq!(decode_cell_record(&encode_cell_record(r)).as_ref(), Ok(r));
    }
}

/// SoD-05, SoD-08, design sections 5.1 and 8.6: while a scheduled binding
/// end is overdue, a tenant admin may still end break-glass access and end
/// another tenant admin. Both read no binding and only reduce access. A
/// command that grants access stays refused until the timeline ends the
/// binding.
#[test]
fn sod05_overdue_end_leaves_the_commands_that_end_access_open() {
    let mut sc = m2_setup().unwrap();
    let ops = BindingId::from_raw(31);
    m2_run(&mut sc, &grant(ops, C, P1, Role::FinanceApprover, T0), T0).unwrap();
    m2_run(&mut sc, &end(ops, plus(T0, MINUTE_US)), T0).unwrap();
    let mut entries = as_cell(&m2_entries(&sc).unwrap());
    let other = fstp_domain::id::AccountId::from_raw(7_701);
    let grant_id = [0x6B; 16];
    for (k, record) in [
        common::admin_granted(ADMIN),
        common::admin_granted(other),
        CellRecord::Ops(OpsRecord::BreakGlassApproved { grant: grant_id }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = entries.last().cloned().unwrap();
        e.seq = Seq::from_raw(e.seq.raw() + 1);
        e.command = cid(0x60 + k as u8);
        e.record = record;
        entries.push(e);
    }
    let s = common::state_of(&entries).unwrap();
    let x = CellCtx {
        actor: ADMIN,
        at: plus(T0, 2 * MINUTE_US).micros(),
    };
    let end_glass = CellCommand::Ops(OpsCommand::EndBreakGlass { grant: grant_id });
    let end_admin = CellCommand::Tenant(TenantCommand::EndTenantAdmin { account: other });
    let approve = CellCommand::Ops(OpsCommand::ApproveBreakGlass {
        request: [0x6C; 16],
    });
    let r = decide(&s, &end_glass, &x, &Answers::new());
    assert!(r.is_ok(), "{r:?}");
    let r = decide(&s, &end_admin, &x, &Answers::new());
    assert!(r.is_ok(), "{r:?}");
    let r = decide(&s, &approve, &x, &Answers::new());
    assert!(
        refused(&r, RuleRef::Sod05, RefusalReason::WrongState),
        "{r:?}"
    );
}
