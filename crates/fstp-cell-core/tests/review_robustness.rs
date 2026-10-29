//! Review reproducers for lane W2c (robustness and test strength lens).
//! Each test fails against the reviewed code and passes once its defect
//! is fixed. Fixtures come from the synthetic corpus only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

#[path = "../fuzz/fuzz_targets/decide_frames.rs"]
mod decide_frames;

use common::{admin_ended, admin_granted, as_cell, cid, ledger, m2_entries, m2_run, m2_setup};
use fstp_cell_core::release::ReleaseCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellCtx, CellRefusal, KeyCommand, decide, decode_cell_command};
use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, C, P1, T0, call, draft, end, grant};

/// I-24, I-81, design sections 3.5 and 5.1: key records come from the
/// erasure runner only. An account with no role must not record that a
/// root epoch was destroyed, or a key operation. Otherwise it forges the
/// erasure evidence, and the runner's own record is refused as reused.
#[test]
fn review_rb_key_records_refused_from_an_ordinary_account() {
    let s =
        common::state_of(&ledger(&[(T0, cid(1), vec![admin_granted(ADMIN)])]).unwrap()).unwrap();
    let x = CellCtx {
        actor: A,
        at: T0.micros(),
    };
    for cmd in [
        KeyCommand::RecordEpochDestroyed {
            epoch: 5,
            receipt: [0x11; 32],
        },
        KeyCommand::RecordKeyOp {
            op: b"{\"k\":1}".to_vec(),
        },
    ] {
        let r = decide(&s, &CellCommand::Key(cmd.clone()), &x, &Answers::new());
        assert!(
            r.is_err(),
            "an account with no role recorded a key record {cmd:?}: {r:?}"
        );
    }
}

/// Design sections 5.1 and 8.3, Q14: the first tenant admin of a cell is
/// a bootstrap. Once the cell had a tenant admin, ending the last one must
/// not let any account grant itself the role.
#[test]
fn review_rb_last_admin_end_does_not_reopen_the_bootstrap() {
    let entries = ledger(&[
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (T0, cid(2), vec![admin_ended(ADMIN)]),
    ])
    .unwrap();
    let s = common::state_of(&entries).unwrap();
    let x = CellCtx {
        actor: A,
        at: T0.micros(),
    };
    let cmd = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: A });
    let r = decide(&s, &cmd, &x, &Answers::new());
    assert!(
        r.is_err(),
        "an applicant granted itself tenant admin after the last admin ended: {r:?}"
    );
}

/// I-17, design sections 6.5 and 8.2: an Operations binding counts until
/// its scheduled end instant, as the gate's Auditor check reads it. After
/// that instant the release rule must refuse its holder. The reviewed rule
/// reads `active_at` only, so the holder passes and the command reaches
/// the proposal state check instead.
#[test]
fn review_rb_release_holder_check_honours_a_scheduled_end() {
    let mut s = m2_setup().unwrap();
    let ops = BindingId::from_raw(31);
    m2_run(&mut s, &grant(ops, C, P1, Role::FinanceApprover, T0), T0).unwrap();
    let proposal = ProposalId::from_raw(1);
    m2_run(
        &mut s,
        &draft(A, proposal, call(1), BindingId::from_raw(201), false),
        T0,
    )
    .unwrap();
    let end_at = Timestamp::from_micros(T0.micros() + 1_000);
    m2_run(&mut s, &end(ops, end_at), T0).unwrap();
    let state = common::state_of(&as_cell(&m2_entries(&s).unwrap())).unwrap();
    let cmd = CellCommand::Release(ReleaseCommand::IssueReleaseTicket {
        proposal: proposal.raw(),
    });
    let state_refusal = |r: &Result<_, CellRefusal>| {
        matches!(r, Err(CellRefusal::Domain(f))
            if f.rule == RuleRef::Input && f.reason == RefusalReason::WrongState)
    };
    // Control: before the end instant the holder passes, and the draft is
    // refused for its state.
    let before = decide(
        &state,
        &cmd,
        &CellCtx {
            actor: C,
            at: T0.micros(),
        },
        &Answers::new(),
    );
    assert!(state_refusal(&before), "control: {before:?}");
    let after = decide(
        &state,
        &cmd,
        &CellCtx {
            actor: C,
            at: end_at.micros() + 1,
        },
        &Answers::new(),
    );
    assert!(
        after.is_err() && !state_refusal(&after),
        "a holder past its scheduled end passed the release holder check: {after:?}"
    );
}

/// I-23, design section 8.4, Q37: P-71 and P-72 are proposed defaults
/// that Daniel may still shorten. The fold must stay structural, so a
/// stored `LoginPolicySet` replays whatever this build's defaults are,
/// and the "may only shorten" rule applies when the value is used. The
/// reviewed fold checks the value against the current defaults. A build
/// with a shorter default would then refuse to replay every cell whose
/// tenant set a value between the old and the new default.
#[test]
fn review_rb_login_policy_fold_does_not_depend_on_build_defaults() {
    use fstp_cell_core::CellRecord;
    use fstp_cell_core::tenant::{P71_DEFAULT_US, TenantLoginPolicy, TenantRecord};
    // A value one microsecond above this build's default stands for a
    // value that an earlier build, with a longer default, accepted.
    let earlier = TenantLoginPolicy {
        p71_us: Some(P71_DEFAULT_US + 1),
        ..TenantLoginPolicy::default()
    };
    let entries = ledger(&[
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (
            T0,
            cid(2),
            vec![CellRecord::Tenant(TenantRecord::LoginPolicySet {
                policy: earlier.encode(),
            })],
        ),
    ])
    .unwrap();
    let s = fstp_cell_core::replay(&entries);
    assert!(
        s.is_ok(),
        "a stored login policy no longer replays under this build's defaults: {s:?}"
    );
}

/// ADR-007 ("a retry after a lost acknowledgement is reported as a
/// duplicate"), design section 5.2: a crash retry runs under the same
/// command id. The driver catches up first, so the earlier commit is in
/// the state when it decides. The reviewed driver then decides again and
/// refuses the text id as reused, so the store never reports the
/// duplicate and the caller sees a refusal instead of the stored result.
///
/// Today the gate stops at the `fstp-auth` stub (lane W2b) before the
/// driver runs, so this test also fails there until W2b lands.
#[test]
fn review_rb_crash_retry_reports_the_stored_result() {
    use fstp_cell_core::CellRecord;
    use fstp_cell_core::driver::{DriverCore, Event, Need, Step};
    use fstp_cell_core::gate::{self, Action};
    use fstp_cell_core::text::{TextCommand, TextRecord};
    use fstp_domain::id::VaultEpoch;
    use fstp_ledger::{MemStore, RecordStore, Seq};
    let now = common::NOW;
    let id = cid(0x42);
    let text = [0x7E; 16];
    // The first run committed under `id`, and its acknowledgement was lost.
    let mut store: MemStore<CellRecord> = MemStore::new();
    store
        .append(
            Seq::ZERO,
            now.micros(),
            id,
            vec![CellRecord::Text(TextRecord::TextPut { id: text })],
        )
        .unwrap();
    let mut state = fstp_cell_core::replay(&[]).unwrap();
    let cmd = CellCommand::Text(TextCommand::PutText { id: text });
    let admitted = gate::admit_command(
        &state,
        &common::passkey(A),
        Action::Command(cmd),
        id,
        None,
        now,
        &common::POLICY,
    )
    .unwrap_or_else(|d| panic!("gate: {d:?}"));
    let mut d = DriverCore::start_with_id(admitted, id);
    let mut ev = None;
    for _ in 0..32 {
        match d.step(&mut state, ev.take()) {
            Step::Done(r) => {
                assert!(
                    r.is_ok(),
                    "the crash retry was not its stored result: {r:?}"
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
            Step::Need(Need::Append {
                expected,
                at,
                command,
                batch,
                ..
            }) => {
                let r = store.append(expected, at, command, batch);
                ev = Some(Event::Appended(r.map(|h| (h, [0; 32]))));
            }
            Step::Need(n) => panic!("unexpected need {n:?}"),
        }
    }
    panic!("the driver did not finish");
}

/// Design section 15, `cell_decide_sequence`: "replay equals incremental
/// state" needs inputs with more than one decided command. The shipped
/// seed `two_admins` holds two tenant commands. Under the reviewed framing
/// (64-byte frames: one control byte, then the body) the first body
/// carried zero padding and never decoded, so the seed decided at most one
/// command.
///
/// The fix gives the target length-prefixed frames, which this test reads
/// through the target's own frame module (`decide_frames.rs`), so seed and
/// target cannot drift apart. The reproducer read the 64-byte framing.
#[test]
fn review_rb_decide_sequence_seed_decodes_both_commands() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/cell_decide_sequence/two_admins"
    );
    let data = std::fs::read(path).unwrap();
    let decoded = decide_frames::frames(&data)
        .iter()
        .filter(|f| decode_cell_command(f.body).is_ok())
        .count();
    assert!(
        decoded >= 2,
        "the seed decodes {decoded} command(s) under the target's framing"
    );
    let decided = decide_frames::run(&data);
    assert!(decided >= 2, "the seed decides {decided} command(s)");
}
