//! Review reproducers for lane W1e (I-24 test strength). Each test fails
//! against the current lane work and passes once the finding is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::mc::audit_model::attacks;
use fstp_celltest::reference::audit::{
    self as r, Keys, RefChain, RefChainView, RefKeyOp, RefLedgerEntry, RefRowKind, RefTamper,
    RowSpec, SymChain,
};

fn ledger(at: i64, k: u8) -> RowSpec {
    RowSpec::Ledger {
        at,
        command: [k; 16],
        schema: 1,
        key_ix: u32::from(k),
        body: vec![0xB0, k],
    }
}

fn event(at: i64, k: u8) -> RowSpec {
    RowSpec::Event {
        at,
        body: vec![0xE0, k],
    }
}

/// Honest chains of both chains, with aborts, so every mutation kind of
/// `r::mutations` applies somewhere.
fn honest_chains() -> Vec<SymChain> {
    let mut out = Vec::new();
    for chain in RefChain::ALL {
        let mut s = SymChain::genesis([0x24; 16], chain);
        s.append(&[ledger(100, 1), event(101, 1)], 102).unwrap();
        s.aborted(&[event(110, 9)], 111).unwrap();
        s.append(&[ledger(110, 2)], 112).unwrap();
        s.append(&[event(120, 3), ledger(121, 3)], 122).unwrap();
        s.aborted(&[ledger(130, 8)], 131).unwrap();
        out.push(s);
    }
    out
}

/// A verifier that skips the ledger coverage check of ADR-010
/// (`LedgerWithoutRow`): it ignores every stored ledger entry that no
/// kind 1 row names, and every duplicate entry.
fn verify_without_ledger_coverage(view: &RefChainView, keys: &Keys) -> bool {
    let named: BTreeSet<u64> = view
        .rows
        .iter()
        .filter_map(|row| match row.kind {
            RefRowKind::Ledger { seq } => Some(seq),
            RefRowKind::Event { .. } => None,
        })
        .collect();
    let mut seen = BTreeSet::new();
    let ledger: Vec<RefLedgerEntry> = view
        .ledger
        .iter()
        .filter(|e| named.contains(&e.seq) && seen.insert(e.seq))
        .cloned()
        .collect();
    let defective = RefChainView {
        ledger,
        ..view.clone()
    };
    r::verify(&defective, keys).is_ok()
}

/// I-24, design section 14.4: the mutation sweep of
/// `i24_verifier_flags_every_mutation` (`r::mutations`) and the M-AUDIT
/// attacker (`attacks`) must have teeth for the `LedgerWithoutRow` check.
/// Neither inserts a ledger entry, so a verifier that ignores a forged
/// entry with no chain row passes both.
#[test]
fn review_mutations_never_insert_a_ledger_entry() {
    let keys = Keys::new().unwrap();
    // The attack is real: a forged entry with no row is a tamper that
    // only the coverage check reports.
    let s = honest_chains().remove(0);
    let mut forged = s.clone();
    forged.store.ledger.push(RefLedgerEntry {
        seq: 99,
        at: 140,
        command: [0x66; 16],
        schema: 1,
        key_ix: 0,
        body: b"forged decision".to_vec(),
    });
    let view = keys.materialize(&forged).unwrap();
    assert_eq!(
        r::verify(&view, &keys),
        Err(RefTamper::LedgerWithoutRow { seq: 99 })
    );
    assert!(verify_without_ledger_coverage(&view, &keys));

    // Neither mutation set can produce that attack.
    let mut missed_by_sweep = Vec::new();
    let mut missed_by_model = Vec::new();
    for s in honest_chains() {
        assert!(r::verify(&keys.materialize(&s).unwrap(), &keys).is_ok());
        let st = &s.store;
        for m in r::mutations(
            st.rows.len(),
            st.ledger.len(),
            st.anchors.len(),
            s.wal.len(),
        ) {
            let Some(t) = r::apply(&s, m) else { continue };
            if verify_without_ledger_coverage(&keys.materialize(&t).unwrap(), &keys) {
                missed_by_sweep.push((s.chain, m));
            }
        }
        for m in attacks(&s) {
            let Some(t) = r::apply(&s, m) else { continue };
            if verify_without_ledger_coverage(&keys.materialize(&t).unwrap(), &keys) {
                missed_by_model.push((s.chain, m));
            }
        }
    }
    assert!(
        !missed_by_sweep.is_empty() && !missed_by_model.is_empty(),
        "a verifier without the LedgerWithoutRow check passes every mutation of \
         r::mutations ({missed_by_sweep:?}) and every M-AUDIT attack ({missed_by_model:?}): \
         no mutation inserts a ledger entry"
    );
}

/// The check of `i24_custody_ops_reconcile_with_key_records` after the
/// fix, with the reference reader and reconciliation in place of the
/// production seams. It reads the `KeyOp` events from the chain rows.
fn custody_test_check(usage: &[RefKeyOp], chain: &SymChain) -> bool {
    !usage.is_empty() && r::reconcile(usage, &r::key_ops_of_rows(&chain.store.rows)).is_empty()
}

/// I-24, ADR-004 "Reconciliation", design section 14.4: the production
/// custody test must compare the simulator's usage log with the `KeyOp`
/// events the cell wrote to its chain. Before the fix it never read the
/// chain, so it passed for a cell that writes no `KeyOp` event at all.
#[test]
fn review_custody_reconcile_test_never_reads_key_op_events() {
    let usage = vec![
        RefKeyOp {
            request_id: [1; 16],
            op: b"create".to_vec(),
        },
        RefKeyOp {
            request_id: [2; 16],
            op: b"destroy".to_vec(),
        },
    ];
    // A cell that writes no KeyOp event: the property fails.
    let mut silent = SymChain::genesis([0x24; 16], RefChain::App);
    silent.append(&[ledger(100, 1)], 101).unwrap();
    assert_eq!(
        r::reconcile(&usage, &r::key_ops_of_rows(&silent.store.rows)),
        usage
    );
    assert!(
        !custody_test_check(&usage, &silent),
        "i24_custody_ops_reconcile_with_key_records passes for a cell that writes no KeyOp event"
    );
    // A cell that writes both events passes.
    let mut honest = SymChain::genesis([0x24; 16], RefChain::App);
    for (k, u) in usage.iter().enumerate() {
        let at = 100 + 10 * k as i64;
        honest
            .append(
                &[RowSpec::Event {
                    at,
                    body: r::key_op_event(u),
                }],
                at + 1,
            )
            .unwrap();
    }
    assert!(custody_test_check(&usage, &honest));
}
