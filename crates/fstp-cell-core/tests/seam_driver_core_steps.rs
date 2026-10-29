//! `DriverCore`, the sans-IO driver of one admitted command (M3 design
//! section 5.2, I-23, NOTE 2 to NOTE 4, ADR-007, I-78).
//!
//! An in-test shell meets each `Need` from a `MemStore<CellRecord>` and a
//! scripted vault, and feeds back the `Event`. The shell can make an
//! append stale by writing a foreign entry first, as a second process
//! contending through the expected head would (ADR-007).
//!
//! Readings, as lane W1c's reference driver takes them
//! (`fstp_celltest::mc::driver_model::RefDriver`):
//! - `ReadFrom(s)` asks for the entries after `s`;
//! - the first need is a catch-up from the store;
//! - an acknowledgement that fails ends the command as a vault fault;
//! - a duplicate command id ends the command with its stored result.
//!
//! Lane W2c's test author wrote these before the driver. They are red
//! until `gate::admit` gives an `Admitted` and `DriverCore::step` lands
//! (stub `NotImplemented`). The cases that need the caller's command id
//! are red on `common::COMMAND_ID_SEAM`.
//!
//! Gaps, reported: `Event::Read` carries no chain links, so a restarted
//! driver cannot name the link of a reaction it acknowledges again; the
//! test checks the epoch and sequence only. `Done::receipt` has no source
//! among the events, since `Event::Appended` carries a sequence and a
//! link only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{
    NOW, POLICY, action_digest, admit_with_id, cid, is_step_up_consumed, is_stub, ledger, passkey,
    read_all, shown, start_with_id, stepup,
};
use fstp_cell_core::driver::{DriverCore, Event, ExecError, Link, Need, Step, VaultFault};
use fstp_cell_core::gate::{Action, Admitted};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{CellCommand, CellRecord, CellState};
use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, ADMIN_2};
use fstp_ledger::{AppendError, Entry, MemStore, RecordStore, Seq, StoreError};
use fstp_prop::{Gen, check, prop_assert};

/// The reserved prefix of the driver's own command ids (design section
/// 5.2).
const RESERVED: [u8; 8] = *b"fstp:vc:";

/// The most decide attempts of one command (`fstp_engine::MAX_ATTEMPTS`).
const MAX_ATTEMPTS: usize = fstp_engine::MAX_ATTEMPTS;

/// The step budget of one run. A run past it does not terminate.
const BUDGET: usize = 512;

/// The link the shell gives the entry at `seq`.
fn link_of(seq: Seq) -> Link {
    let mut l = [0u8; 32];
    l[..8].copy_from_slice(&seq.raw().to_be_bytes());
    l[31] = 0x4C;
    l
}

/// The shell: a store and a scripted vault.
struct Shell {
    store: MemStore<CellRecord>,
    /// The epoch the vault reports, or its fault.
    epoch: Result<u64, VaultFault>,
    /// A fault for every `Ask`.
    answer_fault: Option<VaultFault>,
    /// A fault for every `Ack`.
    ack_fault: Option<VaultFault>,
    /// How many appends to make stale, each by a foreign entry first.
    interfere: usize,
    /// Whether the first append meets a twin: the same batch under the
    /// same command id, committed by another process just before it.
    twin: bool,
    /// Every need, in order.
    needs: Vec<Need>,
    /// Every acknowledgement taken: epoch, sequence and link.
    acked: Vec<(u64, u64, Link)>,
    foreign: u8,
}

impl Shell {
    fn new(epoch: u64) -> Shell {
        Shell {
            store: MemStore::new(),
            epoch: Ok(epoch),
            answer_fault: None,
            ack_fault: None,
            interfere: 0,
            twin: false,
            needs: Vec::new(),
            acked: Vec::new(),
            foreign: 0,
        }
    }

    fn put_foreign(&mut self) {
        self.foreign += 1;
        let id = [0xF0, self.foreign, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let r = CellRecord::Text(TextRecord::TextPut { id });
        self.store
            .append(self.store.head(), NOW.micros(), id, vec![r])
            .unwrap();
    }

    fn answer(&self, q: &Query) -> Answer {
        let epoch = VaultEpoch::from_raw(*self.epoch.as_ref().unwrap_or(&0));
        Answer {
            holds: false,
            accounts: matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new),
            epoch,
            digest: ContentDigest::from_bytes([0; 32]),
        }
    }

    fn meet(&mut self, need: &Need) -> Event {
        self.needs.push(need.clone());
        match need {
            Need::ReadFrom(after) => {
                let mut out = Vec::new();
                let from = Seq::from_raw(after.raw() + 1);
                self.store.read(from, usize::MAX, &mut out).unwrap();
                Event::Read(out)
            }
            Need::Epoch => Event::Epoch(self.epoch.map(VaultEpoch::from_raw)),
            Need::Ask { queries, .. } => Event::Answers(match self.answer_fault {
                Some(f) => Err(f),
                None => {
                    let mut a = Answers::new();
                    for q in queries {
                        a.insert(q.clone(), self.answer(q));
                    }
                    Ok(a)
                }
            }),
            Need::Append {
                expected,
                at,
                command,
                batch,
                ..
            } => {
                if self.twin {
                    self.twin = false;
                    self.store
                        .append(*expected, *at, *command, batch.clone())
                        .unwrap();
                }
                if self.interfere > 0 {
                    self.interfere -= 1;
                    self.put_foreign();
                }
                Event::Appended(
                    self.store
                        .append(*expected, *at, *command, batch.clone())
                        .map(|s| (s, link_of(s))),
                )
            }
            Need::Ack { epoch, seq, link } => {
                self.acked.push((epoch.raw(), seq.raw(), *link));
                Event::Acked(match self.ack_fault {
                    Some(f) => Err(f),
                    None => Ok(()),
                })
            }
        }
    }

    /// Runs `d` to its end over `state`.
    fn run(
        &mut self,
        d: &mut DriverCore,
        state: &mut CellState,
    ) -> Result<fstp_cell_core::driver::Done, ExecError> {
        let mut ev = None;
        for _ in 0..BUDGET {
            match d.step(state, ev.take()) {
                Step::Done(r) => return r,
                Step::Need(n) => ev = Some(self.meet(&n)),
            }
        }
        panic!(
            "the driver did not finish within {BUDGET} steps: {:?}",
            self.needs
        );
    }

    fn appends(&self) -> Vec<&Need> {
        self.needs
            .iter()
            .filter(|n| matches!(n, Need::Append { .. }))
            .collect()
    }

    fn entries(&self) -> Vec<Entry<CellRecord>> {
        read_all(&self.store).unwrap()
    }
}

/// A text write by A, admitted from a passkey session at [`NOW`] on
/// genesis under the caller's command id [`PUT_ID`]. It asks the vault
/// nothing. The driver runs a command only under the caller's id
/// (`DriverCore::start`, I-23).
fn put_text() -> (CellState, Admitted) {
    put_text_with(PUT_ID)
}

/// [`put_text`] under the caller's command id `id`.
fn put_text_with(id: [u8; 16]) -> (CellState, Admitted) {
    let s = fstp_cell_core::replay(&[]).unwrap();
    let c = CellCommand::Text(TextCommand::PutText { id: [0x7E; 16] });
    let a = admit_with_id(&s, &passkey(A), Action::Command(c), id, None, NOW, &POLICY)
        .unwrap()
        .unwrap();
    (s, a)
}

/// The caller's command id of [`put_text`].
const PUT_ID: [u8; 16] = cid(0x7E);

/// The driver's result as text, failing on a stub refusal.
fn not_stub<T: std::fmt::Debug>(r: &Result<T, ExecError>) {
    assert!(!is_stub(&shown(r)), "{r:?}");
}

// ---------------------------------------------------------------------------
// One command, no queries.

/// I-23, design section 5.2: a command that asks the vault nothing is
/// caught up, checked against the vault epoch, appended once with the
/// expected head and the admission time, and done at the new head. The
/// state afterwards is the replay of the store.
#[test]
fn i23_driver_commits_a_command_without_queries_once() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(0);
    let mut d = DriverCore::start(a);
    let done = sh.run(&mut d, &mut s).unwrap();
    assert_eq!(done.head, Seq::from_raw(1));
    assert!(
        matches!(sh.needs.first(), Some(Need::ReadFrom(z)) if *z == Seq::ZERO),
        "{:?}",
        sh.needs
    );
    let epoch_at = sh.needs.iter().position(|n| matches!(n, Need::Epoch));
    let append_at = sh
        .needs
        .iter()
        .position(|n| matches!(n, Need::Append { .. }));
    assert!(epoch_at < append_at && epoch_at.is_some(), "{:?}", sh.needs);
    assert!(
        !sh.needs
            .iter()
            .any(|n| matches!(n, Need::Ask { .. } | Need::Ack { .. }))
    );
    let appends = sh.appends();
    assert_eq!(appends.len(), 1);
    let Need::Append {
        expected,
        at,
        batch,
        ..
    } = appends[0]
    else {
        unreachable!()
    };
    assert_eq!((*expected, *at), (Seq::ZERO, NOW.micros()));
    assert!(batch.contains(&CellRecord::Text(TextRecord::TextPut { id: [0x7E; 16] })));
    let entries = sh.entries();
    assert_eq!(entries.len(), batch.len());
    assert_eq!(s, fstp_cell_core::replay(&entries).unwrap());
}

/// I-23, ADR-007: entries another writer appended are folded before the
/// command, so its append expects their head.
#[test]
fn i23_driver_folds_other_writers_entries_first() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(0);
    sh.put_foreign();
    sh.put_foreign();
    let done = sh.run(&mut DriverCore::start(a), &mut s).unwrap();
    let Need::Append { expected, .. } = sh.appends()[0] else {
        unreachable!()
    };
    assert_eq!(*expected, Seq::from_raw(2));
    assert_eq!(done.head, Seq::from_raw(3));
    assert_eq!(s, fstp_cell_core::replay(&sh.entries()).unwrap());
}

/// I-23, ADR-007: a stale head is retried after a fresh catch-up, and the
/// retry commits once.
#[test]
fn i23_driver_retries_a_stale_head_then_commits() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(0);
    sh.interfere = 1;
    let done = sh.run(&mut DriverCore::start(a), &mut s).unwrap();
    assert_eq!(sh.appends().len(), 2);
    assert_eq!(done.head, Seq::from_raw(2));
    let mine: Vec<_> = sh
        .entries()
        .into_iter()
        .filter(|e| e.record == CellRecord::Text(TextRecord::TextPut { id: [0x7E; 16] }))
        .collect();
    assert_eq!(mine.len(), 1, "the command committed more than once");
}

/// I-23, design section 5.2: under contention on every attempt the driver
/// gives up after `MAX_ATTEMPTS` appends, with a refusal that is not the
/// stub's, and its command is not in the store.
#[test]
fn i23_driver_gives_up_after_max_attempts_of_stale_heads() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(0);
    sh.interfere = usize::MAX;
    let r = sh.run(&mut DriverCore::start(a), &mut s);
    not_stub(&r);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(sh.appends().len(), MAX_ATTEMPTS);
    assert!(
        !sh.entries()
            .iter()
            .any(|e| e.record == CellRecord::Text(TextRecord::TextPut { id: [0x7E; 16] }))
    );
}

/// I-23: a catch-up read whose sequence numbers skip one is refused, and
/// nothing is appended.
#[test]
fn i23_driver_refuses_a_read_with_a_sequence_gap() {
    let (mut s, a) = put_text();
    let mut gap = ledger(&[
        (
            NOW,
            cid(1),
            vec![CellRecord::Text(TextRecord::TextPut { id: [1; 16] })],
        ),
        (
            NOW,
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: [2; 16] })],
        ),
    ])
    .unwrap();
    gap.remove(0);
    let mut d = DriverCore::start(a);
    let first = d.step(&mut s, None);
    assert!(matches!(first, Step::Need(Need::ReadFrom(_))), "{first:?}");
    let r = loop_until_done(&mut d, &mut s, Event::Read(gap));
    not_stub(&r);
    assert!(r.is_err(), "{r:?}");
}

/// Steps `d` with `first` and then with fault events for every further
/// need, so the run ends without an append succeeding.
fn loop_until_done(
    d: &mut DriverCore,
    s: &mut CellState,
    first: Event,
) -> Result<fstp_cell_core::driver::Done, ExecError> {
    let mut ev = Some(first);
    for _ in 0..BUDGET {
        match d.step(s, ev.take()) {
            Step::Done(r) => return r,
            Step::Need(Need::Append { .. }) => panic!("the driver appended after a refused read"),
            Step::Need(Need::ReadFrom(_)) => ev = Some(Event::Read(Vec::new())),
            Step::Need(Need::Epoch) => ev = Some(Event::Epoch(Err(VaultFault::Unavailable))),
            Step::Need(Need::Ask { .. }) => ev = Some(Event::Answers(Err(VaultFault::Unavailable))),
            Step::Need(Need::Ack { .. }) => ev = Some(Event::Acked(Err(VaultFault::Unavailable))),
        }
    }
    panic!("no end within {BUDGET} steps");
}

// ---------------------------------------------------------------------------
// The vault (NOTE 2 to NOTE 4).

/// NOTE 2: a vault that cannot report its epoch fails the command closed,
/// and nothing is appended.
#[test]
fn seam_note2_epoch_fault_fails_closed_and_appends_nothing() {
    for fault in [VaultFault::Unavailable, VaultFault::Refused] {
        let (mut s, a) = put_text();
        let mut sh = Shell::new(0);
        sh.epoch = Err(fault);
        let r = sh.run(&mut DriverCore::start(a), &mut s);
        assert_eq!(r, Err(ExecError::VaultFault), "{fault:?}");
        assert!(sh.appends().is_empty());
        assert!(sh.entries().is_empty());
    }
}

/// NOTE 2, NOTE 3: when the vault is ahead, the driver asks for the
/// change first. A fault on that ask fails the command closed, and
/// nothing is appended.
#[test]
fn seam_note2_reaction_ask_fault_fails_closed_and_appends_nothing() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(1);
    sh.answer_fault = Some(VaultFault::Unavailable);
    let r = sh.run(&mut DriverCore::start(a), &mut s);
    assert_eq!(r, Err(ExecError::VaultFault));
    assert!(sh.appends().is_empty());
}

/// NOTE 3, NOTE 4, design section 5.2: with the vault one epoch ahead,
/// the driver asks `ChangedSince` with `reaction_for` set, appends the
/// reaction under a reserved command id, acknowledges it with its
/// sequence and link, and only then commits the command after it. The
/// state then holds the vault's epoch.
#[test]
fn seam_note4_reaction_is_appended_under_a_reserved_id_then_acked() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(1);
    let done = sh.run(&mut DriverCore::start(a), &mut s).unwrap();
    let ask = sh
        .needs
        .iter()
        .find_map(|n| match n {
            Need::Ask {
                queries,
                reaction_for,
            } => Some((queries.clone(), *reaction_for)),
            _ => None,
        })
        .expect("no ask");
    assert_eq!(ask.1, Some(VaultEpoch::from_raw(1)));
    assert!(ask.0.contains(&Query::ChangedSince {
        epoch: VaultEpoch::from_raw(0)
    }));
    let appends = sh.appends();
    assert_eq!(appends.len(), 2, "{appends:?}");
    let Need::Append { command, batch, .. } = appends[0] else {
        unreachable!()
    };
    assert!(command.starts_with(&RESERVED), "{command:?}");
    assert!(!batch.is_empty() && batch.iter().all(|r| matches!(r, CellRecord::Engine(_))));
    // The acknowledgement names the last entry of the reaction's batch
    // (`Need::Ack`). The M2 reaction records its `ChangedSince` outcome
    // before `EpochAdvanced`, so the batch may hold more than one entry.
    let last = Seq::from_raw(batch.len() as u64);
    assert!(!sh.acked.is_empty(), "no acknowledgement");
    assert!(
        sh.acked
            .iter()
            .all(|x| *x == (1, last.raw(), link_of(last))),
        "{:?}",
        sh.acked
    );
    let ack_at = sh.needs.iter().position(|n| matches!(n, Need::Ack { .. }));
    let second = sh
        .needs
        .iter()
        .enumerate()
        .filter(|(_, n)| matches!(n, Need::Append { .. }))
        .nth(1)
        .map(|(i, _)| i);
    assert!(ack_at < second, "the command was appended before the ack");
    let Need::Append {
        command, expected, ..
    } = appends[1]
    else {
        unreachable!()
    };
    assert!(!command.starts_with(&RESERVED));
    assert_eq!(*expected, last);
    assert!(done.head > last);
    assert_eq!(s.engine().epoch(), VaultEpoch::from_raw(1));
}

/// NOTE 4: an acknowledgement the vault does not take ends the command as
/// a vault fault. The reaction stays committed, and the command is not
/// appended.
#[test]
fn seam_note4_ack_fault_fails_the_command_closed() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(1);
    sh.ack_fault = Some(VaultFault::Unavailable);
    let r = sh.run(&mut DriverCore::start(a), &mut s);
    assert_eq!(r, Err(ExecError::VaultFault));
    let appends = sh.appends();
    assert_eq!(appends.len(), 1, "{appends:?}");
    assert!(matches!(appends[0], Need::Append { command, .. } if command.starts_with(&RESERVED)));
}

/// NOTE 4, design section 5.2 (restart): a committed reaction whose epoch
/// the vault still reports is acknowledged again by the next run, before
/// that run's command commits. Acks are idempotent.
#[test]
fn seam_note4_restart_acks_a_committed_reaction_again() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(1);
    sh.ack_fault = Some(VaultFault::Unavailable);
    let _ = sh.run(&mut DriverCore::start(a.clone()), &mut s);
    // The committed reaction ends at the store's head (`Need::Ack` names
    // the last entry of its batch).
    let reaction = sh.store.head();
    sh.ack_fault = None;
    sh.acked.clear();
    sh.needs.clear();
    let mut fresh = fstp_cell_core::replay(&[]).unwrap();
    let done = sh.run(&mut DriverCore::start(a), &mut fresh).unwrap();
    assert!(
        sh.acked
            .iter()
            .any(|(e, q, _)| (*e, *q) == (1, reaction.raw())),
        "no ack of the committed reaction: {:?}",
        sh.acked
    );
    assert_eq!(sh.appends().len(), 1, "the reaction was appended again");
    assert_eq!(done.head, Seq::from_raw(reaction.raw() + 1));
}

// ---------------------------------------------------------------------------
// The caller's command id (seams).

/// Design section 5.2, I-23: the driver refuses a caller command id with
/// the reserved prefix `fstp:vc:`, before it asks or appends anything.
#[test]
fn seam_driver_refuses_a_reserved_command_id() {
    let (mut s, a) = put_text();
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&RESERVED);
    id[15] = 1;
    let mut d = start_with_id(a, id).unwrap_or_else(|e| panic!("{e}"));
    let mut sh = Shell::new(0);
    let r = sh.run(&mut d, &mut s);
    assert_eq!(r, Err(ExecError::ReservedCommandId));
    assert!(sh.appends().is_empty());
    assert!(!sh.needs.iter().any(|n| matches!(n, Need::Ask { .. })));
}

/// ADR-007, design section 5.2: an account command under the system task
/// prefix `fstp:st:` is refused before anything is read or appended. So
/// no account commits first under an id a system task will use, and a
/// task's crash retry never finds an account's entry as its own.
#[test]
fn adr007_driver_refuses_an_account_command_under_a_system_task_id() {
    let id = fstp_cell_core::system_command_id([0x01; 8]);
    let (mut s, a) = put_text_with(id);
    let mut d = start_with_id(a, id).unwrap_or_else(|e| panic!("{e}"));
    let mut sh = Shell::new(0);
    let r = sh.run(&mut d, &mut s);
    assert_eq!(r, Err(ExecError::ReservedCommandId));
    assert!(sh.needs.is_empty(), "{:?}", sh.needs);
}

/// Design section 5.2, I-23: the command is appended under the caller's
/// command id, not one the driver makes up.
#[test]
fn seam_driver_appends_under_the_caller_command_id() {
    let id = cid(0x31);
    let (mut s, a) = put_text_with(id);
    let mut sh = Shell::new(0);
    let mut d = start_with_id(a, id).unwrap_or_else(|e| panic!("{e}"));
    let _ = sh.run(&mut d, &mut s).unwrap();
    let Need::Append { command, .. } = sh.appends()[0] else {
        unreachable!()
    };
    assert_eq!(*command, id);
}

/// ADR-007, I-23: when another process commits the same command id
/// between the driver's catch-up and its append, the store refuses the
/// append as a duplicate, and the driver ends with the stored result. It
/// appends nothing more, and the store holds the command once.
#[test]
fn adr007_driver_reports_a_duplicate_command_as_its_stored_result() {
    let (mut s, a) = put_text();
    let mut sh = Shell::new(0);
    sh.twin = true;
    let r = sh.run(&mut DriverCore::start(a), &mut s);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(sh.appends().len(), 1);
    let Need::Append { command, .. } = sh.appends()[0] else {
        unreachable!()
    };
    let stored: BTreeSet<[u8; 16]> = sh.entries().iter().map(|e| e.command).collect();
    assert_eq!(stored, BTreeSet::from([*command]));
}

// ---------------------------------------------------------------------------
// Step-up consumption (I-78).

/// I-78, design sections 5.1 and 5.3: the append of a high-risk command
/// carries the consumption of its step-up, as a record of the batch and
/// as the insert-only side effect `stepup_consumed`.
#[test]
fn i78_driver_append_consumes_the_step_up() {
    let mut sh = Shell::new(0);
    sh.store
        .append(
            Seq::ZERO,
            NOW.micros(),
            cid(0xA0),
            vec![common::admin_granted(ADMIN)],
        )
        .unwrap();
    let s = fstp_cell_core::replay(&sh.entries()).unwrap();
    let c = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN_2 });
    let id = cid(0x32);
    let sess = passkey(ADMIN);
    let su = stepup(
        &sess,
        action_digest(&c, id).unwrap_or_else(|e| panic!("{e}")),
        NOW,
    );
    let a = admit_with_id(&s, &sess, Action::Command(c), id, Some(&su), NOW, &POLICY)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap();
    let mut state = s;
    let mut d = start_with_id(a, id).unwrap_or_else(|e| panic!("{e}"));
    let _ = sh.run(&mut d, &mut state).unwrap();
    let Need::Append { batch, side, .. } = sh.appends()[0] else {
        unreachable!()
    };
    assert_eq!(side.stepup_consumed, Some(su.id));
    let consumed = batch
        .iter()
        .filter(|r| is_step_up_consumed(r, su.id).unwrap_or_else(|e| panic!("{e}")))
        .count();
    assert_eq!(consumed, 1);
}

// ---------------------------------------------------------------------------
// Arbitrary events (design section 15, driver_core_sequence).

fn any_event(g: &mut Gen, entries: &[Entry<CellRecord>]) -> Event {
    let fault = if g.bool() {
        VaultFault::Unavailable
    } else {
        VaultFault::Refused
    };
    match g.u8_in(0..=4) {
        0 => {
            let k = g.usize_in(0..=entries.len());
            Event::Read(entries[..k].to_vec())
        }
        1 => Event::Epoch(if g.bool() {
            Ok(VaultEpoch::from_raw(g.u64_in(0..=3)))
        } else {
            Err(fault)
        }),
        2 => Event::Answers(if g.bool() {
            Ok(Answers::new())
        } else {
            Err(fault)
        }),
        3 => Event::Appended(match g.u8_in(0..=3) {
            0 => {
                let s = Seq::from_raw(g.u64_in(0..=4));
                Ok((s, link_of(s)))
            }
            1 => Err(AppendError::StaleHead {
                head: Seq::from_raw(g.u64_in(0..=4)),
            }),
            2 => Err(AppendError::DuplicateCommand {
                at: Seq::from_raw(g.u64_in(1..=4)),
            }),
            _ => Err(AppendError::Store(StoreError::Unavailable)),
        }),
        _ => Event::Acked(if g.bool() { Ok(()) } else { Err(fault) }),
    }
}

/// Design section 15 (`driver_core_sequence`): arbitrary events in any
/// order, including events that fit no need, never make the driver panic.
/// A run that ends does not end with the stub's refusal. The driver asks
/// for an append only with an expected head that a read or an append showed
/// it, never with a head from a stale-head refusal it did not read up to.
#[test]
fn seam_driver_core_never_panics_on_arbitrary_events() {
    let base = ledger(&[
        (
            NOW,
            cid(1),
            vec![CellRecord::Text(TextRecord::TextPut { id: [1; 16] })],
        ),
        (
            NOW,
            cid(2),
            vec![CellRecord::Text(TextRecord::TextPut { id: [2; 16] })],
        ),
    ])
    .unwrap();
    let (s0, a) = put_text();
    check(
        "seam_driver_core_never_panics_on_arbitrary_events",
        |g: &mut Gen| {
            let mut s = s0.clone();
            let mut d = DriverCore::start(a.clone());
            let mut ev = None;
            let mut heads: BTreeMap<u64, ()> = BTreeMap::new();
            heads.insert(0, ());
            for _ in 0..64 {
                match d.step(&mut s, ev.take()) {
                    Step::Done(r) => {
                        prop_assert!(!is_stub(&shown(&r)), "{r:?}");
                        return Ok(());
                    }
                    Step::Need(n) => {
                        if let Need::Append { expected, .. } = &n {
                            prop_assert!(
                                heads.contains_key(&expected.raw()),
                                "expected {expected:?}"
                            );
                        }
                        let e = any_event(g, &base);
                        match &e {
                            Event::Read(es) => {
                                for x in es {
                                    heads.insert(x.seq.raw(), ());
                                }
                            }
                            Event::Appended(Ok((sq, _))) => {
                                heads.insert(sq.raw(), ());
                            }
                            _ => {}
                        }
                        ev = Some(e);
                    }
                }
            }
            Ok(())
        },
    );
}
