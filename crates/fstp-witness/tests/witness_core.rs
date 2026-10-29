//! I-24: the witness core of the strict tail D (ADR-010 "Prepare,
//! receipt, commit", "One outstanding prepare per chain", "Abort", "In
//! doubt" and "Witnesses").
//!
//! Readings, as in the W1e reference (`fstp_celltest::reference::audit`):
//!
//! - A prepare names the head it extends and the stored hashes of its
//!   rows, so the witness recomputes the link (ADR-010 open point 3).
//! - The witness checks the sender of every message, not only of a
//!   prepare. A cell certificate binds its cell.
//! - A prepare whose `(n, link)` was withdrawn is refused. ADR-010 allows
//!   the same `n` again only "with another link".
//! - Once a later prepare extends a prepared head, that head is confirmed
//!   and can no longer be aborted.
//!
//! Red until lane W2g lands the witness core (`WITNESS_SEAM` in M-AUDIT).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::answered;
use common::api::{self, Chain, Core, Hash, Prepare, Refusal, Sender};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

const CELL: [u8; 16] = [0x11; 16];
const OTHER: [u8; 16] = [0x22; 16];

/// The composite signature length of draft 19 (ML-DSA-65 3309 plus
/// Ed25519 64).
const SIG_LEN: usize = 3373;

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

fn gen_chain(g: &mut Gen) -> Chain {
    *g.pick(&Chain::ALL)
}

/// A prepare after `prev` of rows with `stored`, its link recomputed.
fn prepare(chain: Chain, prev: (u64, Hash), stored: &[Hash], at: i64) -> Result<Prepare, String> {
    let (mut n, mut l) = prev;
    for sh in stored {
        n += 1;
        l = api::link(&l, CELL, chain, n, sh)?;
    }
    Ok(Prepare {
        cell: CELL,
        chain,
        prev,
        stored_hashes: stored.to_vec(),
        n,
        link: l,
        at,
        signature: vec![0; SIG_LEN],
    })
}

/// The genesis head of `chain`.
fn genesis(chain: Chain) -> Result<(u64, Hash), String> {
    Ok((0, api::genesis(CELL, chain)?))
}

fn core(chain: Chain) -> Result<Core, String> {
    answered("witness genesis", Core::genesis(CELL, chain))
}

/// A prepare from the chain's writer that must be receipted.
fn receipted(w: &mut Core, p: &Prepare, at: i64) -> Result<api::Receipt, String> {
    match answered("prepare", w.prepare(Sender::writer(CELL, p.chain), p, at))? {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("prepare {p:?} refused: {e:?}")),
    }
}

// ---------------------------------------------------------------------------
// Senders.

/// I-24, ADR-010 "Witnesses": the witness takes a `cell-witness`
/// certificate only for the App chain of its own cell, and a
/// `vault-witness` certificate only for that cell's Vault chain. The
/// control plane never writes a chain.
#[test]
fn i24_witness_accepts_only_the_writer_of_each_chain() {
    let mut got = Vec::new();
    let mut want = Vec::new();
    for chain in Chain::ALL {
        for s in Sender::all(CELL, OTHER) {
            got.push(api::accepts_sender(s, CELL, chain));
            want.push(Ok(s == Sender::writer(CELL, chain)));
        }
    }
    assert_eq!(got, want);
}

/// I-24, ADR-010 "Witnesses": a prepare from any sender but the chain's
/// writer is refused as `WrongSender`.
#[test]
fn i24_witness_refuses_a_prepare_from_any_other_sender() {
    check("i24_witness_refuses_a_prepare_from_any_other_sender", |g| {
        let chain = gen_chain(g);
        let p = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
        for s in Sender::all(CELL, OTHER) {
            if s == Sender::writer(CELL, chain) {
                continue;
            }
            let mut w = core(chain)?;
            let got = answered("prepare", w.prepare(s, &p, 2))?;
            prop_assert_eq!(got, Err(Refusal::WrongSender), "sender {:?}", s);
        }
        Ok(())
    });
}

/// I-24, ADR-010 "Witnesses": an abort or an in-doubt record from any
/// sender but the writer is refused, and leaves the prepare outstanding.
#[test]
fn i24_witness_refuses_a_withdrawal_from_any_other_sender() {
    check(
        "i24_witness_refuses_a_withdrawal_from_any_other_sender",
        |g| {
            let chain = gen_chain(g);
            let p = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
            let mut w = core(chain)?;
            receipted(&mut w, &p, 2)?;
            for s in Sender::all(CELL, OTHER) {
                if s == Sender::writer(CELL, chain) {
                    continue;
                }
                let a = answered("abort", w.abort(s, p.n, &p.link))?;
                let d = answered("in doubt", w.in_doubt_absent(s, p.n, &p.link))?;
                prop_assert_eq!(
                    (a, d),
                    (Err(Refusal::WrongSender), Err(Refusal::WrongSender))
                );
            }
            let own = answered("abort", w.abort(Sender::writer(CELL, chain), p.n, &p.link))?;
            prop_assert_eq!(own, Ok(()), "the prepare is no longer outstanding");
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Prepare and receipt.

/// I-24, ADR-010 "Receipt": a prepare that extends genesis is receipted
/// for its `n` and link, with the time it was received.
#[test]
fn i24_witness_receipts_a_prepare_that_extends_genesis() {
    check("i24_witness_receipts_a_prepare_that_extends_genesis", |g| {
        let chain = gen_chain(g);
        let stored = g.vec(1..=4, gen_hash);
        let p = prepare(chain, genesis(chain)?, &stored, 5)?;
        let at = g.i64();
        let mut w = core(chain)?;
        let r = receipted(&mut w, &p, at)?;
        prop_assert_eq!((r.n, r.link, r.received_at), (p.n, p.link, at));
        Ok(())
    });
}

/// I-24, ADR-010 "Receipt": the witness appends each prepare to its own
/// chain. Witness sequences rise and witness links differ across
/// receipts, through aborts and in-doubt records.
#[test]
fn i24_witness_sequence_rises_across_receipts() {
    check("i24_witness_sequence_rises_across_receipts", |g| {
        let chain = gen_chain(g);
        let writer = Sender::writer(CELL, chain);
        let mut w = core(chain)?;
        let mut head = genesis(chain)?;
        let mut receipts: Vec<api::Receipt> = Vec::new();
        let steps = g.usize_in(1..=6);
        for i in 0..steps {
            let p = prepare(chain, head, &[gen_hash(g)], i64::try_from(i).unwrap())?;
            receipts.push(receipted(&mut w, &p, 0)?);
            match g.u8_in(0..=2) {
                0 => {
                    let r = answered("abort", w.abort(writer, p.n, &p.link))?;
                    prop_assert_eq!(r, Ok(()));
                }
                1 => {
                    let r = answered("in doubt", w.in_doubt_absent(writer, p.n, &p.link))?;
                    prop_assert_eq!(r, Ok(()));
                }
                _ => head = (p.n, p.link),
            }
        }
        for pair in receipts.windows(2) {
            prop_assert!(pair[0].witness_seq < pair[1].witness_seq, "{pair:?}");
        }
        for (i, a) in receipts.iter().enumerate() {
            prop_assert!(
                receipts[i + 1..]
                    .iter()
                    .all(|b| b.witness_link != a.witness_link),
                "{receipts:?}"
            );
        }
        Ok(())
    });
}

/// I-24, ADR-010 "One outstanding prepare per chain": while a prepare is
/// outstanding, a prepare that does not extend it is refused as
/// `Outstanding`.
#[test]
fn i24_witness_refuses_a_second_prepare_while_one_is_outstanding() {
    check(
        "i24_witness_refuses_a_second_prepare_while_one_is_outstanding",
        |g| {
            let chain = gen_chain(g);
            let p1 = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
            let mut other = gen_hash(g);
            if Some(&other) == p1.stored_hashes.first() {
                other[0] ^= 1;
            }
            let p2 = prepare(chain, genesis(chain)?, &[other], 2)?;
            let mut w = core(chain)?;
            receipted(&mut w, &p1, 1)?;
            let got = answered("prepare", w.prepare(Sender::writer(CELL, chain), &p2, 2))?;
            prop_assert_eq!(got, Err(Refusal::Outstanding));
            Ok(())
        },
    );
}

/// I-24, ADR-010 "Extended means that the new prepare's history contains
/// the previous prepared link": a prepare after the outstanding head is
/// receipted.
#[test]
fn i24_witness_accepts_a_prepare_that_extends_the_outstanding_one() {
    check(
        "i24_witness_accepts_a_prepare_that_extends_the_outstanding_one",
        |g| {
            let chain = gen_chain(g);
            let p1 = prepare(chain, genesis(chain)?, &g.vec(1..=3, gen_hash), 1)?;
            let p2 = prepare(chain, (p1.n, p1.link), &g.vec(1..=3, gen_hash), 2)?;
            let mut w = core(chain)?;
            receipted(&mut w, &p1, 1)?;
            let r = receipted(&mut w, &p2, 2)?;
            prop_assert_eq!((r.n, r.link), (p2.n, p2.link));
            Ok(())
        },
    );
}

/// I-24, ADR-010: with no prepare outstanding, a prepare that does not
/// extend the last confirmed head is refused as `NotExtending`.
#[test]
fn i24_witness_refuses_a_prepare_that_does_not_extend() {
    check("i24_witness_refuses_a_prepare_that_does_not_extend", |g| {
        let chain = gen_chain(g);
        let (n, l) = genesis(chain)?;
        let prev = if g.bool() {
            (n + g.u64_in(1..=5), l)
        } else {
            let mut wrong = l;
            wrong[0] ^= 1;
            (n, wrong)
        };
        let p = prepare(chain, prev, &[gen_hash(g)], 1)?;
        let mut w = core(chain)?;
        let got = answered("prepare", w.prepare(Sender::writer(CELL, chain), &p, 1))?;
        prop_assert_eq!(got, Err(Refusal::NotExtending));
        Ok(())
    });
}

/// I-24, ADR-010 open point 3: a prepare whose rows do not recompute to
/// its anchor's link or `n` is refused as `LinkMismatch`.
#[test]
fn i24_witness_refuses_rows_that_do_not_recompute_the_link() {
    check(
        "i24_witness_refuses_rows_that_do_not_recompute_the_link",
        |g| {
            let chain = gen_chain(g);
            let mut p = prepare(chain, genesis(chain)?, &g.vec(1..=3, gen_hash), 1)?;
            match g.u8_in(0..=2) {
                0 => p.link[g.usize_in(0..=31)] ^= 1,
                1 => p.n += 1,
                _ => p.stored_hashes[0][0] ^= 1,
            }
            let mut w = core(chain)?;
            let got = answered("prepare", w.prepare(Sender::writer(CELL, chain), &p, 1))?;
            prop_assert_eq!(got, Err(Refusal::LinkMismatch));
            Ok(())
        },
    );
}

/// I-24: a prepare with no rows is refused. Every prepare commits at
/// least one row.
#[test]
fn i24_witness_refuses_an_empty_prepare() {
    check("i24_witness_refuses_an_empty_prepare", |g| {
        let chain = gen_chain(g);
        let mut p = prepare(chain, genesis(chain)?, &[], 1)?;
        if g.bool() {
            p.n = 1;
            p.link = gen_hash(g);
        }
        let mut w = core(chain)?;
        let got = answered("prepare", w.prepare(Sender::writer(CELL, chain), &p, 1))?;
        prop_assert_eq!(got, Err(Refusal::LinkMismatch));
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Abort and in doubt.

/// I-24, design section 15 ("an abort for an unknown prepare refused"):
/// an abort names the outstanding `(n, link)` or is refused as
/// `UnknownPrepare`.
#[test]
fn i24_witness_refuses_an_abort_for_an_unknown_prepare() {
    check("i24_witness_refuses_an_abort_for_an_unknown_prepare", |g| {
        let chain = gen_chain(g);
        let writer = Sender::writer(CELL, chain);
        let p = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
        let mut w = core(chain)?;
        let before = answered("abort", w.abort(writer, p.n, &p.link))?;
        receipted(&mut w, &p, 1)?;
        let mut other = p.link;
        other[0] ^= 1;
        let wrong_link = answered("abort", w.abort(writer, p.n, &other))?;
        let wrong_n = answered("abort", w.abort(writer, p.n + 1, &p.link))?;
        prop_assert_eq!(
            (before, wrong_link, wrong_n),
            (
                Err(Refusal::UnknownPrepare),
                Err(Refusal::UnknownPrepare),
                Err(Refusal::UnknownPrepare)
            )
        );
        Ok(())
    });
}

/// I-24, ADR-010 "In doubt": an in-doubt record names the outstanding
/// `(n, link)` or is refused as `UnknownPrepare`.
#[test]
fn i24_witness_refuses_an_in_doubt_record_for_an_unknown_prepare() {
    check(
        "i24_witness_refuses_an_in_doubt_record_for_an_unknown_prepare",
        |g| {
            let chain = gen_chain(g);
            let writer = Sender::writer(CELL, chain);
            let p = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
            let mut w = core(chain)?;
            let before = answered("in doubt", w.in_doubt_absent(writer, p.n, &p.link))?;
            receipted(&mut w, &p, 1)?;
            let mut other = p.link;
            other[31] ^= 1;
            let wrong = answered("in doubt", w.in_doubt_absent(writer, p.n, &other))?;
            prop_assert_eq!(
                (before, wrong),
                (Err(Refusal::UnknownPrepare), Err(Refusal::UnknownPrepare))
            );
            Ok(())
        },
    );
}

/// I-24, ADR-010 "Only after the witness has recorded the abort may the
/// cell prepare the same `n` again with another link". Before the abort
/// that prepare is refused; after it, it is receipted.
#[test]
fn i24_abort_recorded_before_the_same_n_is_prepared_again() {
    check(
        "i24_abort_recorded_before_the_same_n_is_prepared_again",
        |g| {
            let chain = gen_chain(g);
            let writer = Sender::writer(CELL, chain);
            let p1 = prepare(chain, genesis(chain)?, &[[0xA1; 32]], 1)?;
            let p2 = prepare(chain, genesis(chain)?, &[[0xB2; 32]], 2)?;
            let mut w = core(chain)?;
            receipted(&mut w, &p1, 1)?;
            let early = answered("prepare", w.prepare(writer, &p2, 2))?;
            prop_assert_eq!(early, Err(Refusal::Outstanding));
            let withdraw = if g.bool() {
                w.abort(writer, p1.n, &p1.link)
            } else {
                w.in_doubt_absent(writer, p1.n, &p1.link)
            };
            prop_assert_eq!(answered("withdraw", withdraw)?, Ok(()));
            let r = receipted(&mut w, &p2, 3)?;
            prop_assert_eq!((r.n, r.link), (p2.n, p2.link));
            Ok(())
        },
    );
}

/// I-24, ADR-010 "with another link": a withdrawn `(n, link)` is never
/// receipted again, so an abort cannot hide a later commit of that link.
#[test]
fn i24_witness_refuses_a_withdrawn_link_prepared_again() {
    check("i24_witness_refuses_a_withdrawn_link_prepared_again", |g| {
        let chain = gen_chain(g);
        let writer = Sender::writer(CELL, chain);
        let p = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
        let mut w = core(chain)?;
        receipted(&mut w, &p, 1)?;
        let withdraw = if g.bool() {
            w.abort(writer, p.n, &p.link)
        } else {
            w.in_doubt_absent(writer, p.n, &p.link)
        };
        prop_assert_eq!(answered("withdraw", withdraw)?, Ok(()));
        let again = answered("prepare", w.prepare(writer, &p, 2))?;
        prop_assert_eq!(again, Err(Refusal::Withdrawn));
        Ok(())
    });
}

/// I-24: once a later prepare extends a prepared head, that head is
/// confirmed. An abort or in-doubt record for it is then refused, so a
/// committed row can never be withdrawn at the witness.
#[test]
fn i24_witness_refuses_to_withdraw_an_extended_prepare() {
    check("i24_witness_refuses_to_withdraw_an_extended_prepare", |g| {
        let chain = gen_chain(g);
        let writer = Sender::writer(CELL, chain);
        let p1 = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
        let p2 = prepare(chain, (p1.n, p1.link), &[gen_hash(g)], 2)?;
        let mut w = core(chain)?;
        receipted(&mut w, &p1, 1)?;
        receipted(&mut w, &p2, 2)?;
        let a = answered("abort", w.abort(writer, p1.n, &p1.link))?;
        let d = answered("in doubt", w.in_doubt_absent(writer, p1.n, &p1.link))?;
        prop_assert_eq!(
            (a, d),
            (Err(Refusal::UnknownPrepare), Err(Refusal::UnknownPrepare))
        );
        Ok(())
    });
}

/// I-24: a refused message changes nothing. After one refused message of
/// any kind, the outstanding prepare can still be extended.
#[test]
fn i24_witness_refusal_changes_nothing() {
    check("i24_witness_refusal_changes_nothing", |g| {
        let chain = gen_chain(g);
        let writer = Sender::writer(CELL, chain);
        let p1 = prepare(chain, genesis(chain)?, &[gen_hash(g)], 1)?;
        let mut w = core(chain)?;
        receipted(&mut w, &p1, 1)?;
        let mut bad_link = p1.link;
        bad_link[0] ^= 1;
        let refused = match g.u8_in(0..=4) {
            0 => w
                .prepare(
                    Sender::ControlPlane,
                    &prepare(chain, (p1.n, p1.link), &[[1; 32]], 2)?,
                    2,
                )
                .map(|r| r.map(|_| ())),
            1 => w
                .prepare(writer, &prepare(chain, genesis(chain)?, &[[2; 32]], 2)?, 2)
                .map(|r| r.map(|_| ())),
            2 => w.abort(writer, p1.n, &bad_link),
            3 => w.in_doubt_absent(Sender::ControlPlane, p1.n, &p1.link),
            _ => {
                let mut p = prepare(chain, (p1.n, p1.link), &[[3; 32]], 2)?;
                p.link[5] ^= 1;
                w.prepare(writer, &p, 2).map(|r| r.map(|_| ()))
            }
        };
        prop_assert!(
            answered("refused message", refused)?.is_err(),
            "the message must be refused"
        );
        let p2 = prepare(chain, (p1.n, p1.link), &[gen_hash(g)], 3)?;
        let r = receipted(&mut w, &p2, 3)?;
        prop_assert_eq!((r.n, r.link), (p2.n, p2.link));
        Ok(())
    });
}

/// I-24, ADR-010 "Witnesses": the witness keeps each cell's chains apart.
/// A prepare of the App chain does not make a Vault chain prepare
/// outstanding, and each writer's prepare is receipted.
#[test]
fn i24_witness_keeps_the_two_chains_apart() {
    check("i24_witness_keeps_the_two_chains_apart", |g| {
        let mut app = core(Chain::App)?;
        let mut vault = core(Chain::Vault)?;
        let pa = prepare(Chain::App, genesis(Chain::App)?, &[gen_hash(g)], 1)?;
        let pv = prepare(Chain::Vault, genesis(Chain::Vault)?, &[gen_hash(g)], 1)?;
        receipted(&mut app, &pa, 1)?;
        let cross = answered(
            "prepare",
            vault.prepare(Sender::writer(CELL, Chain::App), &pv, 1),
        )?;
        prop_assert_eq!(cross, Err(Refusal::WrongSender));
        let r = receipted(&mut vault, &pv, 1)?;
        prop_assert_eq!((r.n, r.link), (pv.n, pv.link));
        Ok(())
    });
}
