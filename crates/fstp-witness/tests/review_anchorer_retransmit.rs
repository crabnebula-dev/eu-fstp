//! Review reproducer, I-24 and ADR-010 "Abort" and "One outstanding
//! prepare per chain": a retried prepare whose first answer was lost.
//!
//! The witness records the first prepare and the answer is lost. The
//! store, still waiting for the receipt (`Next::AwaitReceipt`), sends the
//! same prepare again, as design risk R8 suggests retries. The witness
//! refuses the copy as `Outstanding`, because it holds that very prepare.
//! `PrepareWitness::prepare` can pass only `WitnessFault::Refused`, and
//! the doc of `Anchorer::prepare_refused` says a refusal the witness sent
//! leaves no prepare of this head at the witness. So the store ends the
//! append with no abort. The witness keeps the prepare outstanding, and
//! every later prepare of the chain is refused until a restart. The
//! restart then reads the head as in doubt and raises a false
//! `PossibleDeletion`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_audit::anchorer::{Anchorer, Next, Step, WitnessFault};
use fstp_audit::chain::{genesis, link_of};
use fstp_audit::{Anchor, CellId, ChainId, Link, Prepare};
use fstp_witness::{ChainWitness, Refusal, Sender};

const CELL: CellId = CellId([0x33; 16]);
const CHAIN: ChainId = ChainId::App;

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

fn prepared(p: &Prepare) -> Anchorer {
    let mut a = Anchorer::new();
    a.begin(true).unwrap();
    for s in Step::ALL {
        a.step_done(s).unwrap();
    }
    a.prepared(head_of(p)).unwrap();
    a
}

/// The fault a store can pass for a witness answer: the trait carries no
/// refusal reason but `UnknownPrepare`.
fn fault_of(r: Refusal) -> WitnessFault {
    match r {
        Refusal::UnknownPrepare => WitnessFault::UnknownPrepare,
        _ => WitnessFault::Refused,
    }
}

/// I-24, ADR-010 "Abort": after a retried prepare that the witness
/// already holds, the core's documented path for the witness's answer
/// must not leave that prepare outstanding at the witness while the core
/// is idle. The next append must be receipted without a restart.
#[test]
fn review_i24_retried_prepare_does_not_strand_an_outstanding_prepare() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut w = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));
    let p = prepare_after(g, [0x41; 32]);
    let mut a = prepared(&p);

    // The witness records the prepare. Its answer is lost.
    w.prepare(writer, &p, 1).unwrap();
    assert_eq!(a.next(), Next::AwaitReceipt);

    // The store sends the same prepare again and follows the core.
    match w.prepare(writer, &p, 2) {
        Ok(receipt) => {
            // An idempotent witness answers the retry with the receipt.
            a.receipt(&receipt).unwrap();
            return;
        }
        Err(refusal) => match fault_of(refusal) {
            WitnessFault::Refused => a.prepare_refused().unwrap(),
            WitnessFault::UnknownPrepare | WitnessFault::Unreachable => {
                a.failed().unwrap();
            }
        },
    }
    // Follow any abort the core demands.
    if let Next::SendAbort { head } = a.next() {
        match w.abort(writer, head.0, &head.1) {
            Ok(_) => a.abort_recorded().unwrap(),
            Err(_) => a.abort_unknown_at_witness().unwrap(),
        }
    }
    assert_eq!(a.next(), Next::Nothing);
    assert_ne!(
        w.state().outstanding,
        Some(head_of(&p)),
        "the core is idle with nothing to resolve, but the witness still holds {:?} \
         outstanding: no abort was sent for it",
        head_of(&p)
    );

    // The transaction rolled back. The next append prepares n = 1 again.
    let next = prepare_after(g, [0x42; 32]);
    let mut b = Anchorer::new();
    b.begin(true).unwrap();
    let answer = w.prepare(writer, &next, 3);
    assert!(
        answer.is_ok(),
        "the next append is refused ({answer:?}): writes on this chain stay refused until a \
         restart"
    );
}
