//! I-23 and ADR-007: the insert-only record store (`docs/handoff/m2-design.md`
//! sections 5.1 and 6.1).
//!
//! An append is an atomic batch. It succeeds only while the head is the one
//! the writer expected, and a repeated command id is refused. A refused
//! append changes nothing. Every earlier read is a prefix of every later
//! read, and `verify_append_only` accepts each step.
//!
//! Readings taken where the design is silent, raised in the lane report:
//! - a successful append returns the new head;
//! - `DuplicateCommand::at` names an entry of the earlier batch;
//! - when the head is stale and the command repeats, either refusal is right;
//! - a read from one past the head returns no entries and no error.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeMap;

use common::{Parts, Rec, gen_record, parts};
use fstp_ledger::{AppendError, Entry, MemStore, RecordStore, Seq, StoreError, verify_append_only};
use fstp_prop::{Gen, StateMachine, check, check_machine, prop_assert, prop_assert_eq};

/// Reads every entry of a store.
fn read_all(store: &MemStore<Rec>) -> Result<Vec<Entry<Rec>>, String> {
    let mut out = Vec::new();
    store
        .read(Seq::from_raw(1), usize::MAX, &mut out)
        .map_err(|e| format!("a full read failed: {e:?}"))?;
    Ok(out)
}

/// What the model knows of one entry. The schema version is left out:
/// the store chooses it.
fn summary(p: &Parts) -> (u64, i64, [u8; 16], Rec) {
    (p.seq, p.at, p.command, p.record.clone())
}

/// The reference model: the entries appended so far and, per command id,
/// the first and last sequence number of its batch.
#[derive(Clone, Debug, Default)]
struct Model {
    entries: Vec<(u64, i64, [u8; 16], Rec)>,
    batches: BTreeMap<[u8; 16], (u64, u64)>,
}

impl Model {
    fn head(&self) -> u64 {
        self.entries.len() as u64
    }

    fn last_at(&self) -> i64 {
        self.entries.last().map_or(1_700_000_000_000_000, |e| e.1)
    }

    fn accepts(&self, expected: u64, command: &[u8; 16]) -> bool {
        expected == self.head() && !self.batches.contains_key(command)
    }
}

#[derive(Debug)]
enum Cmd {
    Append {
        expected: u64,
        at: i64,
        command: [u8; 16],
        batch: Vec<Rec>,
    },
    Read {
        from: u64,
        limit: usize,
    },
}

#[derive(Debug)]
enum Out {
    Append {
        result: Result<Seq, AppendError>,
        before: Result<Vec<Entry<Rec>>, String>,
        after: Result<Vec<Entry<Rec>>, String>,
        head_after: Seq,
    },
    Read {
        result: Result<(), StoreError>,
        out: Vec<Entry<Rec>>,
    },
}

/// A small command alphabet, so repeats happen often.
fn gen_command(g: &mut Gen) -> [u8; 16] {
    let mut c = [0u8; 16];
    if g.weighted(&[4, 1]) == 0 {
        c[0] = g.u8_in(0..=5);
    } else {
        for b in c.iter_mut() {
            *b = g.u8();
        }
    }
    c
}

struct Ledger;

impl StateMachine for Ledger {
    type Model = Model;
    type Sut = MemStore<Rec>;
    type Command = Cmd;
    type Output = Out;

    fn init_model(&self) -> Model {
        Model::default()
    }

    fn init_sut(&self) -> MemStore<Rec> {
        MemStore::new()
    }

    fn command(&self, g: &mut Gen, model: &Model) -> Cmd {
        let head = model.head();
        if g.weighted(&[3, 1]) == 0 {
            let expected = match g.weighted(&[4, 1, 1, 1]) {
                0 => head,
                1 => head.saturating_sub(1),
                2 => head + 1,
                _ => g.u64(),
            };
            Cmd::Append {
                expected,
                at: model.last_at() + g.i64_in(0..=3),
                command: gen_command(g),
                batch: g.vec(1..=3, gen_record),
            }
        } else {
            Cmd::Read {
                from: g.u64_in(1..=head + 1),
                limit: g.usize_in(0..=usize::try_from(head).unwrap_or(0) + 1),
            }
        }
    }

    fn run(&self, sut: &mut MemStore<Rec>, cmd: &Cmd) -> Out {
        match cmd {
            Cmd::Append {
                expected,
                at,
                command,
                batch,
            } => {
                let before = read_all(sut);
                let result = sut.append(Seq::from_raw(*expected), *at, *command, batch.clone());
                let after = read_all(sut);
                Out::Append {
                    result,
                    before,
                    after,
                    head_after: sut.head(),
                }
            }
            Cmd::Read { from, limit } => {
                let mut out = Vec::new();
                let result = sut.read(Seq::from_raw(*from), *limit, &mut out);
                Out::Read { result, out }
            }
        }
    }

    fn next_state(&self, model: &mut Model, cmd: &Cmd) {
        if let Cmd::Append {
            expected,
            at,
            command,
            batch,
        } = cmd
            && model.accepts(*expected, command)
        {
            let first = model.head() + 1;
            for r in batch {
                let seq = model.head() + 1;
                model.entries.push((seq, *at, *command, r.clone()));
            }
            model.batches.insert(*command, (first, model.head()));
        }
    }

    fn postcondition(&self, model: &Model, cmd: &Cmd, out: &Out) -> Result<(), String> {
        match (cmd, out) {
            (
                Cmd::Append {
                    expected,
                    at,
                    command,
                    batch,
                },
                Out::Append {
                    result,
                    before,
                    after,
                    head_after,
                },
            ) => {
                let before = before.as_ref()?;
                let after = after.as_ref()?;
                let head = model.head();
                let stale = *expected != head;
                let repeat = model.batches.get(command).copied();
                if !stale && repeat.is_none() {
                    let new_head = head + batch.len() as u64;
                    prop_assert_eq!(
                        result,
                        &Ok(Seq::from_raw(new_head)),
                        "an append at the current head with a fresh command was refused"
                    );
                    prop_assert_eq!(after.len(), before.len() + batch.len());
                    for (i, r) in batch.iter().enumerate() {
                        let p = parts(&after[before.len() + i]);
                        let want = (head + i as u64 + 1, *at, *command, r.clone());
                        prop_assert_eq!(summary(&p), want, "appended entry {i} of the batch");
                    }
                    prop_assert_eq!(*head_after, Seq::from_raw(new_head));
                } else {
                    let stale_ok = matches!(
                        result,
                        Err(AppendError::StaleHead { head: h }) if h.raw() == head
                    );
                    let repeat_ok = match (result, repeat) {
                        (Err(AppendError::DuplicateCommand { at }), Some((lo, hi))) => {
                            (lo..=hi).contains(&at.raw())
                        }
                        _ => false,
                    };
                    let fine = match (stale, repeat.is_some()) {
                        (true, false) => stale_ok,
                        (false, true) => repeat_ok,
                        _ => stale_ok || repeat_ok,
                    };
                    prop_assert!(
                        fine,
                        "wrong refusal {result:?} (head {head}, stale {stale}, earlier batch {repeat:?})"
                    );
                    prop_assert_eq!(after, before, "a refused append changed the ledger");
                    prop_assert_eq!(*head_after, Seq::from_raw(head));
                }
                // The earlier read is always a prefix of the later read.
                prop_assert!(after.len() >= before.len() && after[..before.len()] == before[..]);
                prop_assert_eq!(verify_append_only(before, after), Ok(()));
                Ok(())
            }
            (Cmd::Read { from, limit }, Out::Read { result, out }) => {
                prop_assert_eq!(result, &Ok(()), "a read inside the ledger failed");
                let start = usize::try_from(*from - 1).expect("small ledger");
                let end = start.saturating_add(*limit).min(model.entries.len());
                let want = &model.entries[start..end];
                let got: Vec<_> = out.iter().map(|e| summary(&parts(e))).collect();
                prop_assert_eq!(&got[..], want);
                Ok(())
            }
            _ => Err("output does not match the command".to_owned()),
        }
    }

    fn invariant(&self, model: &Model, sut: &MemStore<Rec>) -> Result<(), String> {
        prop_assert_eq!(sut.head(), Seq::from_raw(model.head()));
        let all = read_all(sut)?;
        let got: Vec<_> = all.iter().map(|e| summary(&parts(e))).collect();
        prop_assert_eq!(got, model.entries);
        Ok(())
    }
}

/// I-23 and ADR-007: appends against an expected head with an idempotency
/// key. Stale heads and repeated command ids are refused and change nothing.
/// Every earlier read is a prefix of every later read.
#[test]
fn i23_ledger_prefix_and_idempotency() {
    check_machine("i23_ledger_prefix_and_idempotency", &Ledger);
}

/// Appends honest batches with fresh command ids and returns, per batch, its
/// command id and its first and last sequence number.
fn fill(
    g: &mut Gen,
    store: &mut MemStore<Rec>,
    min: usize,
) -> Result<Vec<([u8; 16], u64, u64)>, String> {
    let mut out = Vec::new();
    let mut at = 1_700_000_000_000_000_i64;
    for b in 0..g.usize_in(min..=5) {
        let mut command = [0u8; 16];
        command[0] = u8::try_from(b).expect("few batches");
        command[1] = g.u8();
        at += g.i64_in(0..=1_000);
        let batch = g.vec(1..=3, gen_record);
        let head = store.head();
        let len = batch.len() as u64;
        let got = store.append(head, at, command, batch);
        prop_assert_eq!(got, Ok(Seq::from_raw(head.raw() + len)));
        out.push((command, head.raw() + 1, head.raw() + len));
    }
    Ok(out)
}

/// I-23 and ADR-007: an append against a stale head is refused with the
/// current head and changes nothing. The same command then succeeds against
/// the current head, so the refusal did not consume the command id.
#[test]
fn i23_ledger_stale_head_append_changes_nothing() {
    check("i23_ledger_stale_head_append_changes_nothing", |g| {
        let mut store = MemStore::new();
        fill(g, &mut store, 0)?;
        let head = store.head();
        let stale = match g.weighted(&[1, 1, 1, 1]) {
            0 => head.raw().wrapping_sub(1),
            1 => head.raw() + 1,
            2 => u64::MAX,
            _ => g.u64(),
        };
        g.assume(stale != head.raw());
        let before = read_all(&store)?;
        let command = [0xee; 16];
        let at = 1_800_000_000_000_000;
        let batch = g.vec(1..=3, gen_record);
        let refused = store.append(Seq::from_raw(stale), at, command, batch.clone());
        prop_assert_eq!(refused, Err(AppendError::StaleHead { head }));
        prop_assert_eq!(store.head(), head);
        prop_assert_eq!(read_all(&store)?, before);
        let len = batch.len() as u64;
        let accepted = store.append(head, at, command, batch);
        prop_assert_eq!(accepted, Ok(Seq::from_raw(head.raw() + len)));
        Ok(())
    });
}

/// I-23 and ADR-007: a repeated command id is refused at the current head,
/// names an entry of the earlier batch and changes nothing. A fresh command
/// id then succeeds.
#[test]
fn i23_ledger_repeated_command_is_refused() {
    check("i23_ledger_repeated_command_is_refused", |g| {
        let mut store = MemStore::new();
        let batches = fill(g, &mut store, 1)?;
        let &(command, lo, hi) = g.pick(&batches);
        let head = store.head();
        let before = read_all(&store)?;
        let at = 1_800_000_000_000_000;
        let batch = g.vec(1..=3, gen_record);
        let refused = store.append(head, at, command, batch.clone());
        let named = match refused {
            Err(AppendError::DuplicateCommand { at }) => at.raw(),
            other => return Err(format!("a repeated command gave {other:?}")),
        };
        prop_assert!(
            (lo..=hi).contains(&named),
            "the refusal names entry {named}, not one of {lo}..={hi}"
        );
        prop_assert_eq!(store.head(), head);
        prop_assert_eq!(read_all(&store)?, before);
        let len = batch.len() as u64;
        let accepted = store.append(head, at, [0xee; 16], batch);
        prop_assert_eq!(accepted, Ok(Seq::from_raw(head.raw() + len)));
        Ok(())
    });
}
