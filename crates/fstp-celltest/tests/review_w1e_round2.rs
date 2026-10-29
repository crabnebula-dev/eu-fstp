//! Review reproducers for lane W1e, second round. Each test fails against
//! the current lane work and passes once the finding it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::audit::{
    self as r, Keys, Mutation, RefChain, RowSpec, SymChain, SymWitnessRecord, WitnessRefusal,
};

const CELL_A: [u8; 16] = [0xAA; 16];
const CELL_B: [u8; 16] = [0xBB; 16];

fn ev(at: i64, b: &[u8]) -> RowSpec {
    RowSpec::Event {
        at,
        body: b.to_vec(),
    }
}

/// I-24, ADR-010 "Witnesses", ADR-009: the witness pins each cell CA. It
/// accepts a `cell-witness` certificate only for the App chain of that
/// cell, and a `vault-witness` certificate only for that cell's Vault
/// chain.
///
/// The reference sender carries no cell, so the witness core cannot tell
/// cell B's certificate from cell A's. Cell B then records an
/// `InDoubtAbsent` for cell A's committed head. A database owner of cell
/// A deletes that batch, the verifier accepts the chain, and cell A
/// raises no `PossibleDeletion`, since it never sent the record. This is
/// the earlier foreign-certificate finding through another cell.
#[test]
fn review_i24_in_doubt_from_another_cells_certificate_hides_a_deletion() {
    let keys = Keys::new().unwrap();
    for chain in RefChain::ALL {
        let mut a = SymChain::genesis(CELL_A, chain);
        a.append(&[ev(1, b"login")], 2).unwrap();
        let head = a.append(&[ev(3, b"step-up")], 4).unwrap();
        let (n, l) = (head.anchor.n, head.anchor.link);
        let foreign = SymChain::genesis(CELL_B, chain).sender();
        let own = a.sender();
        let answers = [
            (
                "an in-doubt record",
                r::witness_in_doubt_absent(&a.witness_state, a.cell, a.chain, foreign, n, &l),
            ),
            (
                "an abort",
                r::witness_abort(&a.witness_state, a.cell, a.chain, foreign, n, &l),
            ),
        ];
        for (what, got) in answers {
            match got {
                Err(e) => assert_eq!(e, WitnessRefusal::WrongSender, "{what} from cell B"),
                Ok(st) => {
                    let mut t = a.clone();
                    t.witness_state = st;
                    t.witness
                        .push(SymWitnessRecord::InDoubtAbsent { n, link: l });
                    let t = r::apply(&t, Mutation::TruncateWithAnchors(1)).unwrap();
                    let verdict = r::verify(&keys.materialize(&t).unwrap(), &keys);
                    panic!(
                        "I-24: the witness took {what} for cell A's {chain:?} head from cell B's \
                         certificate ({foreign:?}, indistinguishable from cell A's {own:?}). \
                         After a database owner deleted that batch, verify answered {verdict:?}"
                    );
                }
            }
        }
    }
}
