//! Review reproducers for lane W1e (reference fidelity). Each test fails
//! against the current reference, and passes once the defect it names is
//! fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::audit::{
    self as r, Keys, Mutation, RefChain, RefSender, RowSpec, SymChain, WitnessRefusal,
};

/// I-24, ADR-010 "Witnesses": the witness accepts a `cell-witness`
/// certificate only for the App chain, a `vault-witness` certificate only
/// for the Vault chain, and the control plane never sends a prepare.
///
/// Before the fix the witness core checked the sender of a prepare only.
/// It recorded an `InDoubtAbsent` for the App chain's committed head from
/// the control-plane certificate. A database owner then deleted that
/// batch, and the verifier accepted the chain. The cell raised no
/// `PossibleDeletion`, since it never sent the record.
///
/// Now `witness_abort` and `witness_in_doubt_absent` take the sender. A
/// foreign certificate is refused, the prepare stays outstanding, and the
/// deletion is detected.
#[test]
fn review_i24_in_doubt_from_a_foreign_certificate_hides_a_deletion() {
    let keys = Keys::new().unwrap();
    let mut s = SymChain::genesis([0x24; 16], RefChain::App);
    let ev = |at: i64, b: &[u8]| RowSpec::Event {
        at,
        body: b.to_vec(),
    };
    s.append(&[ev(1, b"login")], 2).unwrap();
    let head = s.append(&[ev(3, b"step-up")], 4).unwrap();
    for sender in [
        RefSender::ControlPlane,
        RefSender::VaultWitness { cell: s.cell },
    ] {
        assert!(
            !r::witness_accepts_sender(sender, s.cell, RefChain::App),
            "{sender:?} may not write the App chain"
        );
        let in_doubt = r::witness_in_doubt_absent(
            &s.witness_state,
            s.cell,
            s.chain,
            sender,
            head.anchor.n,
            &head.anchor.link,
        );
        assert_eq!(
            in_doubt.map(|_| ()),
            Err(WitnessRefusal::WrongSender),
            "InDoubtAbsent for the App chain from {sender:?}"
        );
        let abort = r::witness_abort(
            &s.witness_state,
            s.cell,
            s.chain,
            sender,
            head.anchor.n,
            &head.anchor.link,
        );
        assert_eq!(
            abort.map(|_| ()),
            Err(WitnessRefusal::WrongSender),
            "Abort for the App chain from {sender:?}"
        );
    }
    let t = r::apply(&s, Mutation::TruncateWithAnchors(1)).unwrap();
    let view = keys.materialize(&t).unwrap();
    assert!(
        r::verify(&view, &keys).is_err(),
        "I-24: a committed batch was deleted undetected"
    );
}
