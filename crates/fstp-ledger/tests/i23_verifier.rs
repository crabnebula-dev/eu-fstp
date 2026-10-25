//! I-23: the append-only verifier (`docs/handoff/m2-design.md` sections 5.1
//! and 6.2, ADR-007, test plan row "I-23, I-24").
//!
//! A ledger is generated honestly. An earlier read is a prefix of it. The
//! verifier must accept every honest extension and must report every byte
//! change, deletion, swap, truncation and mid-ledger insertion. The
//! reference [`common::extends`] decides what counts as a mutation, so a
//! generated change that leaves the ledger honest is discarded rather than
//! counted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{Parts, Rec, extends, forge_all, gen_ledger, gen_other_record, int};
use fstp_json::{Number, Object, Value};
use fstp_ledger::{Divergence, Seq, verify_append_only};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The kinds of mutation the verifier must report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// One changed record inside the earlier read.
    RecordBytes,
    /// One changed time inside the earlier read.
    AtBytes,
    /// One flipped command bit inside the earlier read.
    CommandBytes,
    /// One changed schema version inside the earlier read.
    SchemaBytes,
    /// One changed sequence number inside the earlier read.
    SeqBytes,
    /// An entry of the earlier read removed, later numbers kept.
    Delete,
    /// An entry of the earlier read removed, later entries renumbered.
    DeleteRenumber,
    /// Two entries swapped, each keeping its own number.
    Swap,
    /// Two entries swapped, the numbers staying in place.
    SwapRenumber,
    /// The later read cut below the length of the earlier read.
    Truncate,
    /// A new entry inside the earlier read, later numbers kept.
    Insert,
    /// A new entry inside the earlier read, later entries renumbered.
    InsertRenumber,
    /// A new entry after the earlier read that breaks the numbering.
    TailInsert,
    /// An entry after the earlier read removed, later numbers kept.
    TailDelete,
}

const KINDS: [Kind; 14] = [
    Kind::RecordBytes,
    Kind::AtBytes,
    Kind::CommandBytes,
    Kind::SchemaBytes,
    Kind::SeqBytes,
    Kind::Delete,
    Kind::DeleteRenumber,
    Kind::Swap,
    Kind::SwapRenumber,
    Kind::Truncate,
    Kind::Insert,
    Kind::InsertRenumber,
    Kind::TailInsert,
    Kind::TailDelete,
];

fn renumber(ps: &mut [Parts]) {
    for (i, p) in ps.iter_mut().enumerate() {
        p.seq = i as u64 + 1;
    }
}

fn fresh_entry(g: &mut Gen, near: &Parts) -> Parts {
    let mut command = near.command;
    command[15] ^= 1 << g.u8_in(0..=7);
    command[0] = 0xff;
    Parts {
        seq: near.seq,
        at: near.at,
        command,
        schema: near.schema,
        record: common::gen_record(g),
    }
}

/// Applies a mutation of `kind` to `new`. `k` is the length of the earlier
/// read. Returns false when the kind does not apply to this ledger shape.
fn mutate(g: &mut Gen, kind: Kind, new: &mut Vec<Parts>, k: usize) -> bool {
    let n = new.len();
    let in_old = |g: &mut Gen| g.usize_in(0..=k - 1);
    match kind {
        Kind::RecordBytes if k > 0 => {
            let i = in_old(g);
            new[i].record = gen_other_record(g, &new[i].record);
        }
        Kind::AtBytes if k > 0 => {
            let i = in_old(g);
            let delta = g.i64_in(1..=1_000_000);
            new[i].at = if g.bool() {
                new[i].at - delta
            } else {
                new[i].at + delta
            };
        }
        Kind::CommandBytes if k > 0 => {
            let i = in_old(g);
            let byte = g.usize_in(0..=15);
            new[i].command[byte] ^= 1 << g.u8_in(0..=7);
        }
        Kind::SchemaBytes if k > 0 => {
            let i = in_old(g);
            // Schema 0 and sequence 0 stay out: the decoder may refuse them.
            let other = g.u16_in(1..=u16::MAX);
            new[i].schema = if other == new[i].schema {
                if other == u16::MAX { 1 } else { other + 1 }
            } else {
                other
            };
        }
        Kind::SeqBytes if k > 0 => {
            let i = in_old(g);
            let other = *g.pick(&[1, 2, n as u64, n as u64 + 1, u64::MAX]);
            let other = if other == new[i].seq {
                if other == u64::MAX { 1 } else { other + 1 }
            } else {
                other
            };
            new[i].seq = other;
        }
        Kind::Delete if k > 0 => {
            let i = in_old(g);
            new.remove(i);
        }
        Kind::DeleteRenumber if k > 0 => {
            let i = in_old(g);
            new.remove(i);
            renumber(new);
        }
        Kind::Swap | Kind::SwapRenumber if k > 0 && n >= 2 => {
            let i = in_old(g);
            let j = g.usize_in(0..=n - 1);
            let j = if j == i { (i + 1) % n } else { j };
            new.swap(i, j);
            if kind == Kind::SwapRenumber {
                renumber(new);
            }
        }
        Kind::Truncate if k > 0 => {
            let t = g.usize_in(0..=k - 1);
            new.truncate(t);
        }
        Kind::Insert | Kind::InsertRenumber if k > 0 => {
            let i = in_old(g);
            let e = fresh_entry(g, &new[i]);
            new.insert(i, e);
            if kind == Kind::InsertRenumber {
                renumber(new);
            }
        }
        Kind::TailInsert if n > 0 => {
            let i = g.usize_in(k..=n);
            let near = new[i.min(n - 1)].clone();
            let e = fresh_entry(g, &near);
            new.insert(i, e);
        }
        Kind::TailDelete if n > k + 1 => {
            let i = g.usize_in(k..=n - 2);
            new.remove(i);
        }
        _ => return false,
    }
    true
}

/// I-23: every byte change, deletion, swap, truncation and mid-ledger
/// insertion between an earlier and a later read is reported, and every
/// honest extension is accepted.
#[test]
fn i23_verifier_flags_every_mutation() {
    check("i23_verifier_flags_every_mutation", |g| {
        let kind = *g.pick(&KINDS);
        let tail = matches!(kind, Kind::TailInsert | Kind::TailDelete);
        // Kinds that touch the earlier read need it to hold an entry.
        let honest = gen_ledger(g, usize::from(!tail), 6);
        let k = g.usize_in(usize::from(!tail)..=honest.len());
        let old = honest[..k].to_vec();
        g.note("kind", &kind);
        g.note("earlier length", &k);
        g.note("honest", &honest);

        let old_e = forge_all(&old)?;
        let honest_e = forge_all(&honest)?;
        prop_assert_eq!(
            verify_append_only(&old_e, &honest_e),
            Ok(()),
            "an honest extension was refused"
        );

        let mut mutated = honest.clone();
        let applied = mutate(g, kind, &mut mutated, k);
        g.assume(applied);
        // A change that leaves an honest extension is not a mutation.
        g.assume(!extends(&old, &mutated));
        g.note("mutated", &mutated);
        let mutated_e = forge_all(&mutated)?;
        let verdict = verify_append_only(&old_e, &mutated_e);
        g.note("verdict", &verdict);
        prop_assert!(verdict.is_err(), "a {kind:?} mutation passed the verifier");

        match kind {
            Kind::RecordBytes | Kind::AtBytes | Kind::CommandBytes | Kind::SchemaBytes => {
                let i = (0..k)
                    .find(|&i| !old[i].same_stored(&mutated[i]))
                    .expect("the mutation changed one entry");
                prop_assert_eq!(
                    verdict,
                    Err(Divergence::Changed {
                        seq: Seq::from_raw(i as u64 + 1)
                    }),
                    "a changed entry must be named by its sequence number"
                );
            }
            Kind::Truncate => {
                prop_assert_eq!(
                    verdict,
                    Err(Divergence::Truncated {
                        old_len: k as u64,
                        new_len: mutated.len() as u64,
                    })
                );
            }
            _ => {}
        }
        Ok(())
    });
}

/// I-23: an earlier read verifies against every later honest read, against
/// itself and as an extension of the empty ledger.
#[test]
fn i23_verifier_accepts_every_honest_extension() {
    check("i23_verifier_accepts_every_honest_extension", |g| {
        let honest = gen_ledger(g, 0, 6);
        let k = g.usize_in(0..=honest.len());
        let old = forge_all(&honest[..k])?;
        let new = forge_all(&honest)?;
        prop_assert_eq!(verify_append_only(&old, &new), Ok(()));
        prop_assert_eq!(verify_append_only(&new, &new), Ok(()));
        prop_assert_eq!(verify_append_only(&[], &new), Ok(()));
        Ok(())
    });
}

/// Rewrites a value with members in reverse order and every integer spelled
/// with a fraction. The RFC 8785 text stays the same.
fn respell(v: &Value) -> Value {
    match v {
        Value::Number(n) if n.is_integer() => Value::Number(
            Number::from_lexeme(&format!("{}.0", n.as_str())).expect("a decimal lexeme"),
        ),
        Value::Array(a) => Value::Array(a.iter().map(respell).collect()),
        Value::Object(o) => {
            let mut out = Object::new();
            for (key, value) in o.iter().rev() {
                out.insert(key, respell(value));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// I-23 and ADR-007: records are compared by their canonical bytes, so a
/// later read that spells the same records differently still verifies.
#[test]
fn i23_verifier_compares_records_by_canonical_bytes() {
    check("i23_verifier_compares_records_by_canonical_bytes", |g| {
        let honest = gen_ledger(g, 1, 6);
        let respelled: Vec<Parts> = honest
            .iter()
            .map(|p| Parts {
                record: Rec(respell(&p.record.0)),
                ..p.clone()
            })
            .collect();
        let a = forge_all(&honest)?;
        let b = forge_all(&respelled)?;
        prop_assert_eq!(verify_append_only(&a, &b), Ok(()));
        prop_assert_eq!(verify_append_only(&b, &a), Ok(()));
        // The same check must still see a real change through the respelling.
        let mut changed = respelled.clone();
        changed[0].record = Rec(Value::Array(
            vec![int(1), changed[0].record.0.clone()].into(),
        ));
        let c = forge_all(&changed)?;
        prop_assert_eq!(
            verify_append_only(&a, &c),
            Err(Divergence::Changed {
                seq: Seq::from_raw(1)
            })
        );
        Ok(())
    });
}
