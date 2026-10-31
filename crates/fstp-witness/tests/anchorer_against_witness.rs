//! I-24, ADR-010 "Abort": the production anchorer core driven against
//! the production witness core through the prepare faults that leave the
//! witness holding nothing, and through a lost answer that leaves it
//! holding the prepare.
//!
//! - A refused prepare ends the append with no abort.
//! - A prepare lost before it reached the witness goes to `MustAbort`.
//!   The witness answers the abort as `UnknownPrepare`, and the core then
//!   ends the append.
//! - A prepare whose answer was lost is held at the witness. The abort is
//!   recorded, and the same `n` is prepared again with another link.
//! - A retransmit of a held prepare gets its first receipt, and the
//!   append commits.
//! - An in-doubt record whose answer was lost is answered as
//!   `UnknownPrepare` on retry. The core ends the resolution after the
//!   alert, and the same `n` is prepared again with another link.
//!
//! In each case the next append begins and is receipted without a
//! restart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_audit::anchorer::{AfterCommit, Anchorer, Next, Step};
use fstp_audit::chain::{genesis, link_of};
use fstp_audit::{Anchor, CellId, ChainId, Link, Prepare};
use fstp_witness::{ChainWitness, Refusal, Sender};

const CELL: CellId = CellId([0x22; 16]);
const CHAIN: ChainId = ChainId::Vault;

fn prepare_after(prev: (u64, Link), sh: [u8; 32]) -> Prepare {
    let n = prev.0 + 1;
    let link = link_of(&prev.1, CELL, CHAIN, n, &sh);
    Prepare {
        prev,
        stored_hashes: vec![sh],
        anchor: Anchor {
            cell: CELL,
            chain: CHAIN,
            n,
            link,
            at: 0,
            signature: Vec::new(),
        },
    }
}

fn head_of(p: &Prepare) -> (u64, Link) {
    (p.anchor.n, p.anchor.link)
}

/// A core with steps 1 to 6 done and the prepare of `p` sent.
fn prepared(p: &Prepare) -> Anchorer {
    let mut a = Anchorer::new();
    a.begin(true).unwrap();
    for s in Step::ALL {
        a.step_done(s).unwrap();
    }
    a.prepared(head_of(p)).unwrap();
    a
}

/// Drives one honest append of `p` through the witness to COMMIT.
fn honest_append(w: &mut ChainWitness, p: &Prepare, at: i64) {
    let writer = Sender::writer(CELL, CHAIN);
    let mut a = prepared(p);
    let receipt = w.prepare(writer, p, at).unwrap();
    a.receipt(&receipt).unwrap();
    a.anchor_inserted().unwrap();
    a.commit_sent().unwrap();
    assert_eq!(
        a.outcome(fstp_audit::anchorer::CommitOutcome::Committed),
        Ok(AfterCommit::Done)
    );
}

/// I-24, ADR-010 "Abort": a prepare the witness refused ends the append
/// with no abort, and the next append is receipted.
#[test]
fn i24_refused_prepare_ends_the_append_without_an_abort() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let first = prepare_after(g, [0xA1; 32]);
    honest_append(&mut w, &first, 1);
    let stale = prepare_after(g, [0xB2; 32]);
    let mut a = prepared(&stale);
    assert_eq!(w.prepare(writer, &stale, 2), Err(Refusal::Outstanding));
    a.prepare_refused().unwrap();
    assert_eq!(a.next(), Next::Nothing);
    let second = prepare_after(head_of(&first), [0xC3; 32]);
    honest_append(&mut w, &second, 3);
    assert_eq!(w.state().outstanding, Some(head_of(&second)));
}

/// I-24, ADR-010 "Abort": a prepare lost before it reached the witness
/// goes to `MustAbort`. The witness answers the abort as `UnknownPrepare`
/// and records nothing, and the core then ends the append.
#[test]
fn i24_prepare_lost_before_the_witness_ends_on_an_unknown_abort() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let lost = prepare_after(g, [0xD4; 32]);
    let mut a = prepared(&lost);
    assert_eq!(a.failed(), Ok(AfterCommit::SendAbort));
    let Next::SendAbort { head } = a.next() else {
        panic!("no abort demanded: {:?}", a.next());
    };
    let before = w.state().clone();
    assert_eq!(
        w.abort(writer, head.0, &head.1),
        Err(Refusal::UnknownPrepare)
    );
    assert_eq!(w.state(), &before, "a refused abort changed the witness");
    a.abort_unknown_at_witness().unwrap();
    assert_eq!(a.next(), Next::Nothing);
    let retry = prepare_after(g, [0xE5; 32]);
    honest_append(&mut w, &retry, 4);
    assert_eq!(w.state().outstanding, Some(head_of(&retry)));
}

/// I-24, ADR-010 "Abort": a prepare whose answer was lost is held at the
/// witness. The abort is recorded, and the same `n` is then prepared
/// again with another link.
#[test]
fn i24_prepare_with_a_lost_answer_is_aborted_at_the_witness() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let held = prepare_after(g, [0xF6; 32]);
    let mut a = prepared(&held);
    w.prepare(writer, &held, 5).unwrap();
    assert_eq!(a.failed(), Ok(AfterCommit::SendAbort));
    let Next::SendAbort { head } = a.next() else {
        panic!("no abort demanded: {:?}", a.next());
    };
    w.abort(writer, head.0, &head.1).unwrap();
    a.abort_recorded().unwrap();
    assert!(w.state().withdrawn.contains(&head_of(&held)));
    let retry = prepare_after(g, [0x07; 32]);
    assert_eq!(retry.anchor.n, held.anchor.n);
    honest_append(&mut w, &retry, 6);
    assert_eq!(w.state().outstanding, Some(head_of(&retry)));
}

/// I-24, ADR-010 "One outstanding prepare per chain": a retransmit of the
/// outstanding prepare, after its answer was lost, gets the receipt the
/// witness gave first and changes nothing. A core resumed with that
/// receipt gives it again, and one resumed without it rebuilds the same
/// witness sequence and link. Once a later prepare extends the head, or
/// once it is aborted, the copy is refused.
#[test]
fn i24_witness_answers_a_retransmit_with_its_first_receipt() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let p = prepare_after(g, [0x18; 32]);
    let first = w.prepare(writer, &p, 7).unwrap();
    let held = w.state().clone();
    assert_eq!(w.prepare(writer, &p, 8), Ok(first), "the retransmit");
    assert_eq!(w.state(), &held, "a retransmit wrote a record");

    let mut resumed = ChainWitness::resume_holding(CELL, CHAIN, held.clone(), Some(first));
    assert_eq!(resumed.prepare(writer, &p, 9), Ok(first));
    let mut bare = ChainWitness::resume(CELL, CHAIN, held.clone());
    let rebuilt = bare.prepare(writer, &p, 9).unwrap();
    assert_eq!(
        (
            rebuilt.n,
            rebuilt.link,
            rebuilt.witness_seq,
            rebuilt.witness_link
        ),
        (first.n, first.link, first.witness_seq, first.witness_link)
    );
    assert_eq!(bare.state(), &held);

    let mut extended = w.clone();
    let next = prepare_after(head_of(&p), [0x19; 32]);
    extended.prepare(writer, &next, 10).unwrap();
    assert_eq!(extended.prepare(writer, &p, 11), Err(Refusal::Outstanding));
    let mut aborted = w.clone();
    aborted.abort(writer, p.anchor.n, &p.anchor.link).unwrap();
    assert_eq!(aborted.prepare(writer, &p, 11), Err(Refusal::Withdrawn));
}

/// I-24, ADR-010 "In doubt": the witness records `InDoubtAbsent` and its
/// answer is lost. The retry is answered as `UnknownPrepare`, since the
/// record withdrew the prepare. The core raised `PossibleDeletion` before
/// the record, ends the resolution on that answer, and the same `n` is
/// prepared again with another link without a restart.
#[test]
fn i24_lost_in_doubt_answer_ends_on_an_unknown_prepare() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let p = prepare_after(g, [0x28; 32]);
    w.prepare(writer, &p, 1).unwrap();
    // The cell crashed after the receipt. The chain holds no row 1.
    let mut a = Anchorer::restart(w.state().outstanding);
    assert_eq!(a.next(), Next::ReadChain { head: head_of(&p) });
    a.chain_read(None).unwrap();
    assert_eq!(a.next(), Next::RaisePossibleDeletion { head: head_of(&p) });
    a.possible_deletion_raised().unwrap();
    let Next::SendInDoubtAbsent { head } = a.next() else {
        panic!("no in-doubt record demanded: {:?}", a.next());
    };
    // The witness records it. The answer is lost, and the store retries.
    w.in_doubt_absent(writer, head.0, &head.1).unwrap();
    assert_eq!(
        w.in_doubt_absent(writer, head.0, &head.1),
        Err(Refusal::UnknownPrepare)
    );
    a.in_doubt_unknown_at_witness().unwrap();
    assert_eq!(a.next(), Next::Nothing);
    assert!(w.state().withdrawn.contains(&head_of(&p)));
    let retry = prepare_after(g, [0x29; 32]);
    honest_append(&mut w, &retry, 2);
    assert_eq!(w.state().outstanding, Some(head_of(&retry)));
}
