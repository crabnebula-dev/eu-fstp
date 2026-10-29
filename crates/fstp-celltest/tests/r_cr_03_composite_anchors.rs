//! R-CR-03: audit chain anchors carry composite Ed25519 plus ML-DSA-65
//! signatures (ADR-001, ADR-010, I-90). These are T-CR-COMPOSITE tests for
//! TH-67. M3 claims R-CR-03 for anchors only (design section 20).
//!
//! Lane W1e wrote these tests before the production code. They are red
//! until `fstp-audit` and `fstp-witness` sign anchors and receipts (lane
//! W2g). `fstp_crypto::composite` signs and exposes its public key since
//! lane dsa merged. They use the
//! `fstp_crypto::composite` API only and assume no byte layout of the
//! composite signature: draft-ietf-lamps-pq-composite-sigs-19 is
//! transcribed by ADR-010, not here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_audit::anchor::{ANCHOR_CONTEXT, RECEIPT_CONTEXT};
use fstp_celltest::mc::audit_model::{
    prod_composite_public_key, prod_sign_anchor, prod_sign_receipt,
};
use fstp_celltest::reference::audit::{
    self as r, KeyRole, Keys, ReceiptFields, RefChain, RowSpec, SymChain, SymWitnessRecord,
};
use fstp_crypto::composite::{self, CompositeSigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use fstp_crypto::sig::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey};

const CELL: [u8; 16] = [0x03; 16];
const LINK: [u8; 32] = [0x5C; 32];

fn key() -> CompositeSigningKey {
    composite::generate().unwrap_or_else(|e| panic!("fstp_crypto::composite::generate: {e}"))
}

fn public_key(k: &CompositeSigningKey) -> Vec<u8> {
    prod_composite_public_key(k).unwrap_or_else(|e| panic!("{}", e.operation))
}

/// R-CR-03, ADR-010 "Anchors": an anchor of either chain carries a
/// composite signature of `SIGNATURE_LEN` bytes over the ADR-010 anchor
/// message, which verifies under the chain's composite key and binds the
/// chain. It is signed under the anchor context ADR-010 records.
#[test]
fn r_cr_03_anchors_carry_composite_signatures() {
    let k = key();
    let pk = public_key(&k);
    assert_eq!(pk.len(), PUBLIC_KEY_LEN);
    for chain in RefChain::ALL {
        let sig = prod_sign_anchor(&k, CELL, chain, 3, &LINK, 1_000)
            .unwrap_or_else(|e| panic!("{}", e.operation));
        assert_eq!(
            sig.len(),
            SIGNATURE_LEN,
            "{chain:?} anchor signature length"
        );
        let msg = r::anchor_message(CELL, chain, 3, &LINK, 1_000);
        composite::verify_with_context(&pk, &msg, ANCHOR_CONTEXT, &sig)
            .unwrap_or_else(|e| panic!("the {chain:?} anchor does not verify: {e}"));
        let other = r::anchor_message(CELL, chain.other(), 3, &LINK, 1_000);
        assert!(
            composite::verify_with_context(&pk, &other, ANCHOR_CONTEXT, &sig).is_err(),
            "a {chain:?} anchor verified as a {:?} anchor",
            chain.other()
        );
    }
}

/// R-CR-03, ADR-010 "Receipt": a witness receipt carries a composite
/// signature over the receipt message, which verifies under the
/// witness's composite key, under the receipt context ADR-010 records.
#[test]
fn r_cr_03_receipts_carry_composite_signatures() {
    let k = key();
    let pk = public_key(&k);
    let receipt = ReceiptFields {
        n: 3,
        link: LINK,
        witness_seq: 9,
        witness_link: [0x77; 32],
        received_at: 1_001,
    };
    for chain in RefChain::ALL {
        let sig = prod_sign_receipt(&k, CELL, chain, &receipt)
            .unwrap_or_else(|e| panic!("{}", e.operation));
        assert_eq!(
            sig.len(),
            SIGNATURE_LEN,
            "{chain:?} receipt signature length"
        );
        let msg = r::receipt_message(CELL, chain, &receipt);
        composite::verify_with_context(&pk, &msg, RECEIPT_CONTEXT, &sig)
            .unwrap_or_else(|e| panic!("the {chain:?} receipt does not verify: {e}"));
    }
}

/// R-CR-03, ADR-001: a composite signature has room for both halves and
/// verifies under its own public key only.
#[test]
fn r_cr_03_composite_signature_holds_both_halves() {
    const { assert!(SIGNATURE_LEN >= fstp_crypto::mldsa::SIGNATURE_LEN + ED25519_SIGNATURE_LEN) };
    const { assert!(PUBLIC_KEY_LEN >= fstp_crypto::mldsa::PUBLIC_KEY_LEN + ED25519_PUBLIC_KEY_LEN) };
    let (k, other) = (key(), key());
    let msg = b"fstp r_cr_03 composite";
    let sig = k
        .sign(msg)
        .unwrap_or_else(|e| panic!("composite sign: {e}"))
        .to_bytes();
    composite::verify(&public_key(&k), msg, &sig).unwrap_or_else(|e| panic!("own key: {e}"));
    assert!(
        composite::verify(&public_key(&other), msg, &sig).is_err(),
        "a composite signature verified under another key"
    );
}

/// R-CR-03, I-90: an Ed25519 signature alone never passes as a composite
/// one, bare or padded at either end to the composite length.
#[test]
fn r_cr_03_ed25519_signature_alone_is_refused() {
    let k = key();
    let pk = public_key(&k);
    let msg = b"fstp r_cr_03 anchor";
    let sig = k.sign(msg).unwrap_or_else(|e| panic!("{e}")).to_bytes();
    composite::verify(&pk, msg, &sig).unwrap_or_else(|e| panic!("the valid signature: {e}"));
    let ed = Ed25519SigningKey::generate().unwrap();
    let ed_sig = ed.sign(msg).unwrap();
    let mut front = vec![0u8; SIGNATURE_LEN];
    front[..ED25519_SIGNATURE_LEN].copy_from_slice(&ed_sig);
    let mut back = vec![0u8; SIGNATURE_LEN];
    back[SIGNATURE_LEN - ED25519_SIGNATURE_LEN..].copy_from_slice(&ed_sig);
    for (what, s) in [("bare", ed_sig.to_vec()), ("front", front), ("back", back)] {
        assert!(
            composite::verify(&pk, msg, &s).is_err(),
            "{what} Ed25519 signature"
        );
        assert!(
            composite::verify(&ed.public_key(), msg, &s).is_err(),
            "{what} Ed25519 signature under its own Ed25519 key"
        );
    }
}

/// R-CR-03 on the reference: every anchor and receipt of an honest chain
/// carries both halves, and each half verifies under its own key.
#[test]
fn r_cr_03_reference_anchors_carry_composite_signatures() {
    let keys = Keys::new().unwrap();
    for chain in RefChain::ALL {
        let mut s = SymChain::genesis(CELL, chain);
        s.append(
            &[RowSpec::Event {
                at: 1,
                body: b"login".to_vec(),
            }],
            2,
        )
        .unwrap();
        let view = keys.materialize(&s).unwrap();
        assert!(matches!(
            s.witness.first(),
            Some(SymWitnessRecord::Prepare { .. })
        ));
        for row in &view.anchors {
            let a = &row.anchor;
            let msg = r::anchor_message(a.cell, a.chain, a.fields.n, &a.fields.link, a.fields.at);
            let pk = keys.signer(KeyRole::Anchor(chain)).public();
            assert!(
                r::ed25519_half_verifies(pk, &msg, &a.sig),
                "{chain:?} Ed25519 half"
            );
            assert!(
                r::mldsa_half_verifies(pk, &msg, &a.sig),
                "{chain:?} ML-DSA-65 half"
            );
            let other = keys.signer(KeyRole::Anchor(chain.other())).public();
            assert!(
                !r::composite_verifies(other, &msg, &a.sig),
                "{chain:?} under the other key"
            );
            let rc = &row.receipt;
            let rmsg = r::receipt_message(rc.cell, rc.chain, &rc.fields);
            let wk = keys.signer(KeyRole::Witness).public();
            assert!(
                r::composite_verifies(wk, &rmsg, &rc.sig),
                "{chain:?} receipt"
            );
        }
    }
}
