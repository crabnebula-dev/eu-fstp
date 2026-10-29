//! Review reproducer, I-24 and ADR-010 "Abort": a prepare the witness
//! refused, or never received, leaves nothing at the witness to abort.
//! The M-AUDIT model (W1e) ends such an append without an abort. The
//! production anchorer core demanded `Abort { n, link }`, which the
//! production witness core refuses as `UnknownPrepare`, and had no step
//! out of `MustAbort` but `abort_recorded`. Fixed: a refused prepare goes
//! to `Anchorer::prepare_refused`, which ends the append with no abort.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_audit::anchorer::{Anchorer, Next, Step};
use fstp_audit::chain::{genesis, link_of};
use fstp_audit::{Anchor, CellId, ChainId, Link, Prepare};
use fstp_witness::{ChainWitness, Refusal, Sender};

const CELL: CellId = CellId([0x11; 16]);
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

fn open_core() -> Anchorer {
    let mut a = Anchorer::new();
    a.begin(true).unwrap();
    for s in Step::ALL {
        a.step_done(s).unwrap();
    }
    a
}

/// I-24, ADR-010 "Abort": after the witness refuses a prepare, the
/// anchorer core never demands an abort the witness will refuse, and the
/// next append can begin without a restart.
#[test]
fn review_i24_refused_prepare_does_not_wedge_the_anchorer() {
    let writer = Sender::writer(CELL, CHAIN);
    let mut witness = ChainWitness::genesis(CELL, CHAIN);
    let g = (0, genesis(CELL, CHAIN));

    // An honest first append: prepared, receipted and committed.
    let first = prepare_after(g, [0xA1; 32]);
    witness.prepare(writer, &first, 1).unwrap();

    // A second append over a stale head. The witness refuses it.
    let stale = prepare_after(g, [0xB2; 32]);
    let head = (stale.anchor.n, stale.anchor.link);
    let mut core = open_core();
    core.prepared(head).unwrap();
    assert_eq!(
        witness.prepare(writer, &stale, 2),
        Err(Refusal::Outstanding)
    );
    // The core step for a prepare the witness refused.
    core.prepare_refused().unwrap();

    match core.next() {
        Next::SendAbort { head: h } => {
            let answer = witness.abort(writer, h.0, &h.1);
            assert!(
                answer.is_ok(),
                "the core demands Abort {h:?}, the witness answers {answer:?}, and no core step \
                 leaves MustAbort: writes are refused until a restart"
            );
        }
        other => {
            assert!(
                core.begin(true).is_ok(),
                "after a refused prepare the next append cannot begin ({other:?})"
            );
        }
    }
}
