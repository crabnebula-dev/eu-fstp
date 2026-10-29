//! `queries`, `decide`, `apply`, `replay` and `attest` of the cell core
//! (I-23, SoD-07, I-78, M3 design sections 2.2, 5.1 and 14.6).
//!
//! - The cell fold of an M2-only ledger is the M2 fold, state and refusal
//!   alike (the M2 `Engine` is the reference oracle, section 5.2).
//! - `replay` equals `apply` entry by entry, for ledgers of every member.
//! - The ledger stays time-monotone across every member (section 2.2).
//! - `decide` on an M2 command gives the M2 records, with the `Ctx`
//!   attestations read from the tenant fold (section 5.1).
//! - `attest` reads the tenant fold only, and a SoD-07 approval admits one
//!   matching grant before it lapses (section 5.1, Q40, TH-05).
//! - A step-up is consumed once, by structure (section 5.1, I-78).
//!
//! Lane W2c's test author wrote these before the fold. They are red until
//! the fold lands (stub `NotImplemented`) and the seams of `common` close.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../../fstp-domain/tests/codec_support/mod.rs"]
#[allow(unused_macros, unused_imports)]
mod codec_support;

mod cells;
mod common;

use cells::any_command;
use common::{
    admin_ended, admin_granted, as_cell, attest_at, attest_of, cid, is_step_up_consumed, is_stub,
    ledger, m2_entries, m2_run, m2_setup, plus, self_grant_digest, shown, state_of,
    step_up_consumed, with_admins,
};
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{
    Attestation, CellCommand, CellCtx, CellRecord, FoldError, apply, decide, queries, replay,
};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{BindingId, CommandId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2, B, P1, STAFF_PM, SodSetup, T0, grant};
use fstp_engine::Decider;
use fstp_ledger::{Entry, Seq};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The cell replay of `entries` and the M2 replay of the same records,
/// with the M2 error mapped into the cell's.
fn both(
    m2: &[Entry<fstp_engine::Record>],
) -> (
    Result<fstp_engine::EngineState, FoldError>,
    Result<fstp_engine::EngineState, FoldError>,
) {
    let cell = replay(&as_cell(m2)).map(|s| s.engine().clone());
    let engine = fstp_engine::replay(m2).map_err(FoldError::Engine);
    (cell, engine)
}

/// The M2 corpus ledger, with a committee member granted to A.
fn m2_ledger() -> Vec<Entry<fstp_engine::Record>> {
    let mut s = m2_setup().unwrap();
    m2_run(
        &mut s,
        &grant(BindingId::from_raw(4_001), A, P1, Role::CommitteeMember, T0),
        T0,
    )
    .unwrap();
    m2_entries(&s).unwrap()
}

// ---------------------------------------------------------------------------
// The fold.

/// I-23: `replay` of the genesis ledger succeeds, and its M2 part is the
/// M2 genesis state.
#[test]
fn i23_cell_replay_of_genesis_is_the_m2_genesis() {
    let s = replay(&[]).unwrap();
    assert_eq!(s.engine(), &fstp_engine::EngineState::genesis());
}

/// I-23, design sections 5.2 and 14.6: for every prefix of an M2 ledger,
/// the cell fold's M2 state equals `fstp_engine::replay`.
#[test]
fn i23_cell_replay_of_m2_ledger_equals_engine_replay() {
    let entries = m2_ledger();
    check(
        "i23_cell_replay_of_m2_ledger_equals_engine_replay",
        |g: &mut Gen| {
            let k = g.usize_in(0..=entries.len());
            let (cell, engine) = both(&entries[..k]);
            prop_assert_eq!(cell, engine, "prefix of {k} entries");
            Ok(())
        },
    );
}

/// I-23, design section 14.6: the cell fold refuses exactly what the M2
/// fold refuses, with the same error. The ledgers are M2 ledgers with one
/// entry dropped, repeated, swapped with its neighbour or renumbered.
#[test]
fn i23_cell_replay_refuses_what_the_engine_refuses() {
    let entries = m2_ledger();
    check(
        "i23_cell_replay_refuses_what_the_engine_refuses",
        |g: &mut Gen| {
            let mut m = entries.clone();
            let i = g.usize_in(0..=m.len() - 2);
            let how = g.u8_in(0..=3);
            match how {
                0 => {
                    m.remove(i);
                }
                1 => {
                    let e = m[i].clone();
                    m.insert(i + 1, e);
                }
                2 => m.swap(i, i + 1),
                _ => m[i].seq = Seq::from_raw(m[i].seq.raw() + 2),
            }
            let (cell, engine) = both(&m);
            prop_assert!(engine.is_err(), "mutation {how} at {i} left a valid ledger");
            prop_assert_eq!(cell, engine, "mutation {how} at {i}");
            Ok(())
        },
    );
}

/// The batches of a mixed ledger: the M2 corpus batches with tenant,
/// text and auth batches between them, all at `T0`.
fn mixed_batches(g: &mut Gen) -> Result<Vec<common::Batch>, String> {
    let m2 = m2_ledger();
    let mut out: Vec<common::Batch> = Vec::new();
    let mut n = 0u8;
    let mut previous: Option<[u8; 16]> = None;
    for e in m2 {
        // An extra batch goes only between two M2 batches. Inside one it
        // would split the batch into two under one command id, which the
        // store refuses as a duplicate.
        let boundary = previous != Some(e.command);
        previous = Some(e.command);
        if boundary && g.weighted(&[3, 1]) == 1 {
            n = n.wrapping_add(1);
            let extra = match g.u8_in(0..=3) {
                0 => admin_granted(ADMIN_2),
                1 => admin_ended(ADMIN_2),
                2 => CellRecord::Text(TextRecord::TextPut { id: [n; 16] }),
                _ => CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session: [n; 16] }),
            };
            out.push((
                T0,
                [0xD0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                vec![extra],
            ));
        }
        match out.last_mut() {
            Some(last) if last.1 == e.command => last.2.push(CellRecord::Engine(e.record)),
            _ => out.push((
                Timestamp::from_micros(e.at),
                e.command,
                vec![CellRecord::Engine(e.record)],
            )),
        }
    }
    Ok(out)
}

/// I-23: `replay` equals `apply` entry by entry from genesis, for ledgers
/// that mix the M2 members with the tenant, text and auth members.
#[test]
fn i23_cell_replay_equals_incremental_apply() {
    check("i23_cell_replay_equals_incremental_apply", |g: &mut Gen| {
        let entries = ledger(&mixed_batches(g)?)?;
        let whole = replay(&entries).map_err(|e| format!("replay: {e:?}"))?;
        let mut s = replay(&[]).map_err(|e| format!("genesis: {e:?}"))?;
        for e in &entries {
            apply(&mut s, e).map_err(|err| format!("apply at {}: {err:?}", e.seq.raw()))?;
        }
        prop_assert_eq!(s, whole);
        Ok(())
    });
}

/// I-23, design section 2.2: the ledger stays time-monotone across every
/// member. An entry of a cell member that is earlier than an M2 entry
/// before it is refused, and so is an M2 entry earlier than a cell entry.
#[test]
fn i23_cell_fold_refuses_time_backwards_across_members() {
    let later = plus(T0, 10);
    let text = CellRecord::Text(TextRecord::TextPut { id: [1; 16] });
    let first = m2_ledger().remove(0).record;
    let cases = [
        vec![
            (later, cid(1), vec![CellRecord::Engine(first.clone())]),
            (T0, cid(2), vec![text.clone()]),
        ],
        vec![
            (later, cid(1), vec![text.clone()]),
            (T0, cid(2), vec![CellRecord::Engine(first)]),
        ],
        vec![
            (later, cid(1), vec![text.clone()]),
            (T0, cid(2), vec![admin_granted(A)]),
        ],
    ];
    for batches in cases {
        let entries = ledger(&batches).unwrap();
        let r = replay(&entries);
        assert_eq!(
            r.map(|_| ()),
            Err(FoldError::Engine(fstp_domain::FoldError::TimeBackwards)),
            "{batches:?}"
        );
    }
}

/// I-23: the cell fold refuses a ledger whose sequence numbers do not run
/// from 1 without gaps, whatever member the entries hold.
#[test]
fn i23_cell_replay_refuses_a_sequence_gap_in_cell_members() {
    let mut entries = ledger(&[
        (T0, cid(1), vec![admin_granted(A)]),
        (T0, cid(2), vec![admin_granted(B)]),
    ])
    .unwrap();
    entries[1].seq = Seq::from_raw(3);
    assert_eq!(
        replay(&entries).map(|_| ()),
        Err(FoldError::Engine(fstp_domain::FoldError::OutOfOrder))
    );
}

// ---------------------------------------------------------------------------
// queries and decide.

/// The M2 context of `ctx` for an M2 step, with the attestations the M2
/// corpus gives it.
fn m2_ctx(step: &fstp_domain_testkit::r#gen::roster::Step, at: Timestamp) -> Ctx {
    step.ctx(at, CommandId::from_bytes([0x33; 16]))
}

/// A cell and the M2 reference side by side, each with its own head.
struct Twin {
    cell: fstp_cell_core::CellState,
    cell_head: u64,
    engine: fstp_engine::EngineState,
    engine_head: u64,
}

impl Twin {
    /// Folds `batch` at `at`: the whole batch into the cell, and its M2
    /// records into the reference.
    fn fold(&mut self, at: Timestamp, batch: &[CellRecord]) -> Result<(), String> {
        let entries = ledger(&[(at, cid(0x40), batch.to_vec())])?;
        for mut e in entries {
            self.cell_head += 1;
            e.seq = Seq::from_raw(self.cell_head);
            apply(&mut self.cell, &e).map_err(|x| format!("cell apply: {x:?}"))?;
            if let CellRecord::Engine(r) = &e.record {
                self.engine_head += 1;
                fstp_engine::apply(&mut self.engine, Seq::from_raw(self.engine_head), at, r)
                    .map_err(|x| format!("M2 apply: {x:?}"))?;
            }
        }
        Ok(())
    }
}

/// Design sections 5.1 and 14.6: on a cell where ADMIN is tenant admin,
/// `queries` and `decide` on each M2 setup step give exactly what the M2
/// decider gives with the corpus attestations, at the corpus time `T0`
/// and with the corpus vault's answers (`sod_truth`). The M2 records of
/// the batch come first and in order. Any other record of the batch belongs
/// to a cell member, such as the step-up consumption of a high-risk
/// command.
#[test]
fn seam_decide_engine_commands_match_m2_decide() {
    let mut setup = SodSetup::one(2, &[1]);
    setup.published = vec![fstp_domain_testkit::r#gen::roster::call(1)];
    let steps = setup.steps().unwrap();
    let mut t = Twin {
        cell: with_admins(&[ADMIN]).unwrap(),
        cell_head: 1,
        engine: fstp_engine::EngineState::genesis(),
        engine_head: 0,
    };
    // The corpus runs its setup at T0: M2 refuses a grant that starts
    // before the command's instant.
    let at = T0;
    let truth = fstp_domain_testkit::r#gen::roster::sod_truth();
    for (i, step) in steps.iter().enumerate() {
        let Actor::Account(actor) = step.actor else {
            panic!("system step {i}");
        };
        let m2c = fstp_engine::Command::Core(step.cmd.clone());
        let c = CellCommand::Engine(m2c.clone());
        let x = CellCtx {
            actor,
            at: at.micros(),
        };
        let ctx = m2_ctx(step, at);
        let want_q = fstp_engine::DomainDecider.queries(&t.engine, &m2c, &ctx);
        assert_eq!(
            queries(&t.cell, &c, &x),
            want_q.clone().map_err(fstp_cell_core::CellRefusal::Domain),
            "step {i}"
        );
        let mut answers = Answers::new();
        for q in want_q.unwrap() {
            // The twin processes no vault change, so the answer carries the
            // state's epoch and the corpus vault's facts.
            let mut a = truth.answer(&q);
            a.epoch = t.engine.epoch();
            answers.insert(q, a);
        }
        let want = fstp_engine::DomainDecider
            .decide(&t.engine, &m2c, &ctx, &answers)
            .unwrap();
        let got = decide(&t.cell, &c, &x, &answers).unwrap();
        let (m2_part, rest) = got.split_at(want.len().min(got.len()));
        let m2_part: Vec<fstp_engine::Record> = m2_part
            .iter()
            .filter_map(|r| match r {
                CellRecord::Engine(e) => Some(e.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(m2_part, want, "step {i} {:?}", step.cmd.kind());
        assert!(
            rest.iter().all(|r| !matches!(r, CellRecord::Engine(_))),
            "step {i}: extra M2 records {rest:?}"
        );
        t.fold(at, &got).unwrap();
    }
}

/// Design section 5.1: a refused M2 command gives the M2 refusal. A has
/// no tenant admin binding in the tenant fold, so `CreateProgramme` by A
/// is refused exactly as M2 refuses it without the attestation.
#[test]
fn seam_decide_refuses_an_m2_command_as_m2_does() {
    let steps = SodSetup::one(2, &[1]).steps().unwrap();
    let create = steps[0].cmd.clone();
    let cell = with_admins(&[ADMIN]).unwrap();
    let engine = fstp_engine::EngineState::genesis();
    let at = plus(T0, 1);
    let ctx = Ctx {
        now: at,
        actor: Actor::Account(A),
        command: CommandId::from_bytes([0x34; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let m2c = fstp_engine::Command::Core(create.clone());
    let want = fstp_engine::DomainDecider
        .decide(&engine, &m2c, &ctx, &Answers::new())
        .unwrap_err();
    let got = decide(
        &cell,
        &CellCommand::Engine(m2c),
        &CellCtx {
            actor: A,
            at: at.micros(),
        },
        &Answers::new(),
    );
    assert_eq!(got, Err(fstp_cell_core::CellRefusal::Domain(want)));
}

/// Design section 2.2: `decide` refuses a command earlier than the latest
/// recorded time of any member, as M2 does (`Ledger`, `ClockBackwards`).
#[test]
fn i23_decide_refuses_a_time_before_the_ledger_floor() {
    let entries = ledger(&[(plus(T0, 10), cid(1), vec![admin_granted(ADMIN)])]).unwrap();
    let s = state_of(&entries).unwrap();
    let put = CellCommand::Text(TextCommand::PutText { id: [9; 16] });
    let r = decide(
        &s,
        &put,
        &CellCtx {
            actor: A,
            at: T0.micros(),
        },
        &Answers::new(),
    );
    assert_eq!(
        r,
        Err(fstp_cell_core::CellRefusal::Domain(
            fstp_domain::Refusal::new(RuleRef::Ledger, RefusalReason::ClockBackwards)
        ))
    );
}

/// I-23, design section 15: on genesis and on the M2 corpus state,
/// `queries` and `decide` answer every command of every member with
/// records or a typed refusal, never the stub's, and every decided batch
/// folds. A batch the fold refuses would never be appended (section 5.2).
#[test]
fn i23_every_decided_batch_folds() {
    let m2 = as_cell(&m2_ledger());
    let corpus = state_of(&m2).ok().map(|s| (s, m2.len() as u64));
    check("i23_every_decided_batch_folds", |g: &mut Gen| {
        let (s, head) = match (&corpus, g.bool()) {
            (Some(c), true) => c.clone(),
            _ => (replay(&[]).map_err(|e| format!("genesis: {e:?}"))?, 0),
        };
        let c = any_command(g)?;
        let actor = *g.pick(&[A, B, ADMIN, STAFF_PM]);
        let x = CellCtx {
            actor,
            at: plus(T0, 1).micros(),
        };
        let q = queries(&s, &c, &x);
        prop_assert!(!is_stub(&shown(&q)), "queries: {q:?}");
        let d = decide(&s, &c, &x, &Answers::new());
        prop_assert!(!is_stub(&shown(&d)), "decide: {d:?}");
        if let Ok(batch) = d {
            prop_assert!(!batch.is_empty(), "an accepted command records nothing");
            let entries = ledger(&[(plus(T0, 1), cid(0x77), batch)])?;
            let mut next = s.clone();
            for (k, mut e) in entries.into_iter().enumerate() {
                e.seq = Seq::from_raw(head + k as u64 + 1);
                let r = apply(&mut next, &e);
                prop_assert!(r.is_ok(), "{c:?} decided a batch the fold refuses: {r:?}");
            }
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// attest (SoD-07).

fn grant_of(
    account: fstp_domain::id::AccountId,
    second: Option<fstp_domain::id::AccountId>,
) -> fstp_engine::Command {
    let mut step = grant(
        BindingId::from_raw(5_001),
        account,
        P1,
        Role::ProgrammeManager,
        T0,
    );
    if let fstp_domain::Command::GrantRole { second_admin, .. } = &mut step.cmd {
        *second_admin = second;
    }
    fstp_engine::Command::Core(step.cmd)
}

/// SoD-07, design section 5.1: on genesis `attest` attests nothing, for
/// any actor and command.
#[test]
fn sod_07_attest_on_genesis_attests_nothing() {
    let s = replay(&[]).unwrap();
    for actor in [A, ADMIN] {
        assert_eq!(
            attest_of(&s, actor, &grant_of(B, None)),
            Ok(Attestation::default())
        );
    }
}

/// SoD-07, design section 5.1: `Ctx::tenant_admin` and
/// `binds_tenant_admin` come from the tenant fold. A grant to a current
/// tenant admin binds one, and an ended tenant admin is no longer one.
#[test]
fn sod_07_tenant_admin_attestation_comes_from_the_tenant_fold() {
    let granted = ledger(&[
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (T0, cid(2), vec![admin_granted(ADMIN_2)]),
    ])
    .unwrap();
    let s = state_of(&granted).unwrap();
    let to_b = attest_of(&s, ADMIN, &grant_of(B, None)).unwrap();
    assert!(to_b.tenant_admin && !to_b.binds_tenant_admin, "{to_b:?}");
    let to_admin2 = attest_of(&s, ADMIN, &grant_of(ADMIN_2, None)).unwrap();
    assert!(
        to_admin2.tenant_admin && to_admin2.binds_tenant_admin,
        "{to_admin2:?}"
    );
    let by_a = attest_of(&s, A, &grant_of(B, None)).unwrap();
    assert!(!by_a.tenant_admin, "{by_a:?}");
    let ended = ledger(&[
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (T0, cid(2), vec![admin_granted(ADMIN_2)]),
        (plus(T0, 1), cid(3), vec![admin_ended(ADMIN)]),
    ])
    .unwrap();
    let s = state_of(&ended).unwrap();
    let after = attest_of(&s, ADMIN, &grant_of(B, None)).unwrap();
    assert!(!after.tenant_admin, "{after:?}");
    assert!(
        attest_of(&s, ADMIN_2, &grant_of(ADMIN, None))
            .unwrap()
            .tenant_admin
    );
}

/// The approval lifetime of the tests: P-71 from the approval (Q40).
const APPROVED_AT: Timestamp = Timestamp::from_micros(2_000_000);

/// The cell after ADMIN and ADMIN_2 became tenant admins and `approver`
/// approved the self-grant digest `digest`, lapsing at `expires_at`.
fn approved(
    approver: fstp_domain::id::AccountId,
    digest: [u8; 32],
    extra: Vec<CellRecord>,
) -> fstp_cell_core::CellState {
    let mut batches = vec![
        (T0, cid(1), vec![admin_granted(ADMIN)]),
        (T0, cid(2), vec![admin_granted(ADMIN_2)]),
        (
            APPROVED_AT,
            cid(3),
            vec![CellRecord::Tenant(TenantRecord::SelfGrantApproved {
                approver,
                grant_digest: digest,
                expires_at: plus(APPROVED_AT, common::P71_US).micros(),
            })],
        ),
    ];
    if !extra.is_empty() {
        batches.push((plus(APPROVED_AT, 1), cid(4), extra));
    }
    state_of(&ledger(&batches).unwrap()).unwrap()
}

/// SoD-07, TH-05, design section 5.1: a self-grant by ADMIN is attested
/// as approved only for an unconsumed, unexpired approval by a different
/// current tenant admin of the same grant digest. The digest holds the
/// command id, so the same grant under another id is not approved.
#[test]
fn sod_07_second_admin_attested_only_for_a_matching_approval() {
    let self_grant = grant_of(ADMIN, Some(ADMIN_2));
    let id = cid(0x61);
    let digest = self_grant_digest(&self_grant, id).unwrap();
    let now = plus(APPROVED_AT, 1_000);
    let s = approved(ADMIN_2, digest, Vec::new());
    assert!(
        attest_at(&s, ADMIN, &self_grant, id, now)
            .unwrap()
            .second_tenant_admin
    );
    assert!(
        !attest_at(&s, ADMIN, &self_grant, cid(0x62), now)
            .unwrap()
            .second_tenant_admin,
        "another command id"
    );
    let other = grant_of(ADMIN, None);
    assert!(
        !attest_at(&s, ADMIN, &other, id, now)
            .unwrap()
            .second_tenant_admin,
        "another grant"
    );
    let by_self = approved(ADMIN, digest, Vec::new());
    assert!(
        !attest_at(&by_self, ADMIN, &self_grant, id, now)
            .unwrap()
            .second_tenant_admin,
        "approved by the grantee"
    );
    let approver_gone = approved(ADMIN_2, digest, vec![admin_ended(ADMIN_2)]);
    assert!(
        !attest_at(&approver_gone, ADMIN, &self_grant, id, now)
            .unwrap()
            .second_tenant_admin,
        "the approver is no longer a tenant admin"
    );
}

/// SoD-07, TH-05, Q40: one approval admits one grant. Once the grant
/// batch records `SelfGrantApprovalUsed`, the approval attests nothing.
#[test]
fn sod_07_used_approval_admits_no_second_grant() {
    let self_grant = grant_of(ADMIN, Some(ADMIN_2));
    let id = cid(0x61);
    let digest = self_grant_digest(&self_grant, id).unwrap();
    let used = approved(
        ADMIN_2,
        digest,
        vec![CellRecord::Tenant(TenantRecord::SelfGrantApprovalUsed {
            grant_digest: digest,
        })],
    );
    let now = plus(APPROVED_AT, 1_000);
    assert!(
        !attest_at(&used, ADMIN, &self_grant, id, now)
            .unwrap()
            .second_tenant_admin
    );
}

/// SoD-07, Q40: the approval lapses P-71 after it was given. It counts up
/// to and including `expires_at`, and not one microsecond after.
#[test]
fn sod_07_approval_lapses_after_its_expiry() {
    let self_grant = grant_of(ADMIN, Some(ADMIN_2));
    let id = cid(0x61);
    let digest = self_grant_digest(&self_grant, id).unwrap();
    let s = approved(ADMIN_2, digest, Vec::new());
    let expiry = plus(APPROVED_AT, common::P71_US);
    assert!(
        attest_at(&s, ADMIN, &self_grant, id, expiry)
            .unwrap()
            .second_tenant_admin
    );
    assert!(
        !attest_at(&s, ADMIN, &self_grant, id, plus(expiry, 1))
            .unwrap()
            .second_tenant_admin
    );
}

// ---------------------------------------------------------------------------
// Step-up consumption (I-78).

/// I-78, design sections 5.1 and 8.4: the fold refuses a second
/// consumption of one step-up, so replay checks single use by structure.
/// Each ledger first records the grant, since every step-up is logged
/// with the action it authorised.
#[test]
fn i78_fold_refuses_a_second_step_up_consumption() {
    let id = [0x5C; 16];
    let granted = CellRecord::Auth(fstp_auth::AuthRecord::StepUpGranted {
        id,
        action_digest: [0x5D; 32],
        session: [0x51; 16],
    });
    let consumed = step_up_consumed(id).unwrap();
    assert!(is_step_up_consumed(&consumed, id).unwrap());
    let once = ledger(&[
        (T0, cid(3), vec![granted.clone()]),
        (T0, cid(1), vec![consumed.clone()]),
    ])
    .unwrap();
    assert!(replay(&once).is_ok());
    let twice = ledger(&[
        (T0, cid(3), vec![granted]),
        (T0, cid(1), vec![consumed.clone()]),
        (T0, cid(2), vec![consumed]),
    ])
    .unwrap();
    let r = replay(&twice);
    assert!(r.is_err(), "a second consumption folded");
    assert!(!is_stub(&shown(&r)), "{r:?}");
}
