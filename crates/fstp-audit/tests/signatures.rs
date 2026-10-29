//! R-CR-03, I-90, I-24: anchor signing and the verifier's signature
//! checks (ADR-010 "Anchors", "Receipt", "Keys", "Verifier" and
//! "Composite encoding", design sections 7.2 and 7.4). These are
//! T-CR-COMPOSITE tests for TH-67.
//!
//! Daniel accepted the ADR-010 composite encoding table on 2026-10-29
//! (design section 21.0). So `fstp_audit::anchor::sign_anchor` signs under
//! the chain's composite `Anchor` key, and `fstp_audit::verify` checks
//! every anchor against the anchor key history and every receipt against
//! the pinned witness keys.
//!
//! Readings these tests pin:
//!
//! - The application context of draft 19 is `common::ANCHOR_CTX` for
//!   anchors and `common::RECEIPT_CTX` for receipts (interim reading of
//!   lane W2g, ADR-010 open point 2). A signature under any other context
//!   is refused.
//! - Any key of the anchor key history verifies an anchor, since old
//!   public keys stay in the history (ADR-010 "Keys"). The same holds for
//!   the pinned witness keys and receipts.
//! - A signature change that leaves every structural check intact is
//!   named `BadSignature { n }`, with `n` the head of the anchor or
//!   receipt. It is checked in both stored copies: the `audit.anchor` row
//!   and the witness log's prepare record, which also covers aborted and
//!   in-doubt prepares.
//!
//! Lane W2g landed signing and the verifier's signature step. A
//! refusal that still names the old acceptance stub fails every test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::reference::{self as r, CELL, Chain, Hash};
use common::signing::{self as s, HalfForgery, Store};
use common::view::{self, AnchorRow, Mutation, Sigs, View, WitnessRec};
use common::{ANCHOR_CTX, RECEIPT_CTX, answered, api, real_refusal};
use fstp_audit::{AuditError, Tamper};
use fstp_crypto::composite::{self, CompositeSigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Signing is slow next to hashing, so the signed properties run fewer
/// cases and shrink less.
fn cfg() -> Config {
    Config::default().with_cases(8).with_max_shrink_steps(64)
}

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

fn gen_cell(g: &mut Gen) -> [u8; 16] {
    let mut c = [0u8; 16];
    for b in &mut c {
        *b = g.u8();
    }
    c
}

fn gen_chain(g: &mut Gen) -> Chain {
    *g.pick(&Chain::ALL)
}

/// A second handle on the same composite key.
fn twin(k: &CompositeSigningKey) -> CompositeSigningKey {
    CompositeSigningKey::from_bytes(&k.to_bytes().expect("key bytes")[..]).expect("same key")
}

/// An honest view signed with `anchor` and `witness`.
fn signed_view(
    g: &mut Gen,
    chain: Chain,
    anchor: &CompositeSigningKey,
    witness: &CompositeSigningKey,
) -> View {
    let sigs = Sigs::Composite {
        anchor: Box::new(twin(anchor)),
        witness: Box::new(twin(witness)),
    };
    view::gen_view(g, CELL, chain, sigs)
}

/// `Ok` when `v` verifies.
fn verifies(what: &str, v: &View) -> Result<(), String> {
    let got = api::verify(v);
    let rows = u64::try_from(v.rows.len()).expect("small view");
    if got == Ok(rows) {
        Ok(())
    } else {
        Err(format!("{what}: an honest signed view got {got:?}"))
    }
}

/// `Ok` when `v` is `BadSignature { n }`.
fn bad_signature_at(what: &str, v: &View, n: u64) -> Result<(), String> {
    let got = api::verify(v);
    if got == Err(AuditError::Tamper(Tamper::BadSignature { n })) {
        Ok(())
    } else {
        Err(format!(
            "{what}: must get BadSignature {{ n: {n} }}, got {got:?}"
        ))
    }
}

/// The heads with a prepare record and the stores that hold a copy of
/// each: the witness log always, and `audit.anchor` when committed.
fn signed_copies(v: &View) -> Vec<(u64, Hash, Store)> {
    let mut out = Vec::new();
    for (n, link) in s::prepared_heads(v) {
        out.push((n, link, Store::WitnessLog));
        if v.anchors
            .iter()
            .any(|a| a.anchor.n == n && a.anchor.link == link)
        {
            out.push((n, link, Store::AnchorTable));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Signing (`fstp_audit::anchor::sign_anchor`).

/// R-CR-03, ADR-010 "Anchors": `sign_anchor` returns the anchor of the
/// head it was given, for either chain, with a composite signature of the
/// draft 19 length.
#[test]
fn r_cr_03_sign_anchor_returns_the_anchor_it_signed() {
    let k = s::key();
    check_with(
        "r_cr_03_sign_anchor_returns_the_anchor_it_signed",
        cfg(),
        |g| {
            let (cell, chain, n, link, at) = (
                gen_cell(g),
                gen_chain(g),
                g.u64_in(1..=u64::MAX),
                gen_hash(g),
                g.i64(),
            );
            let a = answered(
                "sign_anchor",
                api::sign_anchor_rec(&k, cell, chain, n, &link, at),
            )?;
            prop_assert_eq!(
                (a.cell, a.chain, a.n, a.link, a.at),
                (cell, chain, n, link, at)
            );
            prop_assert_eq!(a.signature.len(), SIGNATURE_LEN);
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Composite encoding" (open point 2): an anchor
/// signature verifies with `fstp_crypto::composite` over the ADR-010
/// anchor message of the test reference, under the chain's key and the
/// pinned context `fstp-anchor-v1`. It does not verify under the empty
/// default context, the receipt context or another key.
#[test]
fn r_cr_03_anchor_signature_verifies_under_the_anchor_context_only() {
    let (k, other) = (s::key(), s::key());
    let (pk, other_pk) = (s::public(&k), s::public(&other));
    check_with(
        "r_cr_03_anchor_signature_verifies_under_the_anchor_context_only",
        cfg(),
        |g| {
            let (cell, chain, n, link, at) = (
                gen_cell(g),
                gen_chain(g),
                g.u64_in(1..=u64::MAX),
                gen_hash(g),
                g.i64(),
            );
            let sig = answered(
                "sign_anchor",
                api::sign_anchor(&k, cell, chain, n, &link, at),
            )?;
            let msg = r::anchor_message(cell, chain, n, &link, at);
            let check = |pk: &[u8], ctx: &[u8]| composite::verify_with_context(pk, &msg, ctx, &sig);
            prop_assert!(check(&pk, ANCHOR_CTX).is_ok(), "the anchor context");
            prop_assert!(check(&pk, &[]).is_err(), "the empty context");
            prop_assert!(check(&pk, RECEIPT_CTX).is_err(), "the receipt context");
            prop_assert!(check(&other_pk, ANCHOR_CTX).is_err(), "another key");
            Ok(())
        },
    );
}

/// R-CR-03, I-24: an anchor signature binds the cell, the chain, `n`,
/// the link and `at`. It verifies over no message with one of them
/// changed.
#[test]
fn r_cr_03_anchor_signature_binds_every_field() {
    let k = s::key();
    let pk = s::public(&k);
    check_with("r_cr_03_anchor_signature_binds_every_field", cfg(), |g| {
        let (cell, chain, n, link, at) = (
            gen_cell(g),
            gen_chain(g),
            g.u64_in(1..=u64::MAX - 1),
            gen_hash(g),
            g.i64(),
        );
        let sig = answered(
            "sign_anchor",
            api::sign_anchor(&k, cell, chain, n, &link, at),
        )?;
        let mut cell2 = cell;
        cell2[0] ^= 1;
        let mut link2 = link;
        link2[31] ^= 1;
        let others = [
            r::anchor_message(cell2, chain, n, &link, at),
            r::anchor_message(cell, chain.other(), n, &link, at),
            r::anchor_message(cell, chain, n + 1, &link, at),
            r::anchor_message(cell, chain, n, &link2, at),
            r::anchor_message(cell, chain, n, &link, at.wrapping_add(1)),
        ];
        for (i, m) in others.iter().enumerate() {
            prop_assert!(
                composite::verify_with_context(&pk, m, ANCHOR_CTX, &sig).is_err(),
                "field {} not bound",
                i
            );
        }
        Ok(())
    });
}

/// R-CR-03, ADR-010 "Anchors": a chain row number starts at 1, so an
/// anchor of row 0 is refused for real, not by a stub. No anchor of row
/// 0 could be encoded or stored.
#[test]
fn r_cr_03_sign_anchor_refuses_row_zero() {
    let k = s::key();
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let r = api::sign_anchor(&k, CELL, chain, 0, &[0x5C; 32], 1);
        got.push(real_refusal(&format!("{chain:?} anchor of row 0"), &r));
    }
    assert_eq!(got, vec![Ok(()), Ok(())]);
}

/// R-CR-03, ADR-010 "Anchors": an anchor that `sign_anchor` made, with a
/// receipt signed under the witness key, verifies in a one-row chain of
/// either chain. Signing and verifying agree on the message and context.
#[test]
fn r_cr_03_sign_anchor_output_verifies_in_the_chain_verifier() {
    let (anchor_key, witness_key) = (s::key(), s::key());
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let mut v = view::Builder::new(CELL, chain, Sigs::Placeholder);
        v.commit(&[view::RowSpec::Event { body: vec![1] }], 10);
        let mut v = v.finish();
        v.anchor_keys = vec![s::public(&anchor_key)];
        v.witness_keys = vec![s::public(&witness_key)];
        let (n, link, at) = {
            let a = &v.anchors[0].anchor;
            (a.n, a.link, a.at)
        };
        let signed = api::sign_anchor(&anchor_key, CELL, chain, n, &link, at);
        let Ok(sig) = signed else {
            got.push(Err(format!("{chain:?}: sign_anchor gave {signed:?}")));
            continue;
        };
        s::edit_both(&mut v, n, &link, &|row: &mut AnchorRow| {
            row.anchor.signature = sig.clone();
            s::resign_receipt(row, &witness_key);
        });
        got.push(verifies(&format!("{chain:?}"), &v));
    }
    assert_eq!(got, vec![Ok(()), Ok(())]);
}

// ---------------------------------------------------------------------------
// The verifier over signed chains.

/// I-24, R-CR-03, ADR-010 "Verifier": on a signed chain of either chain,
/// every attacker step gets its exact tamper. Each structural change gets
/// the tamper `common::view` fixes, and a changed byte of an anchor or
/// receipt signature gets `BadSignature { n }` of its head. The honest
/// chain verifies first, so no tamper is an artefact of unsigned anchors.
#[test]
fn i24_verify_names_each_mutation_of_a_signed_chain() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "i24_verify_names_each_mutation_of_a_signed_chain",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            verifies("the honest view", &v)?;
            for m in view::mutations(&v) {
                let Some((w, expect)) = view::apply_signed(&v, m) else {
                    continue;
                };
                let got = api::verify(&w);
                let tamper = match &got {
                    Err(AuditError::Tamper(t)) => Some(t.clone()),
                    _ => None,
                };
                let ok = match &expect {
                    view::Expect::Exact(t) => tamper.as_ref() == Some(t),
                    view::Expect::OneOf(ts) => tamper.as_ref().is_some_and(|t| ts.contains(t)),
                    view::Expect::AnyTamper | view::Expect::NotOk => tamper.is_some(),
                };
                prop_assert!(ok, "I-24: {:?} must get {:?}, got {:?}", m, expect, got);
            }
            Ok(())
        },
    );
}

/// I-24, ADR-010 "In doubt": a signed chain verifies with every
/// `InDoubtAbsent` record listed as a possible deletion, in witness
/// order, and no `Abort`.
#[test]
fn i24_verify_lists_the_in_doubt_records_of_a_signed_chain() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "i24_verify_lists_the_in_doubt_records_of_a_signed_chain",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let want: Vec<(u64, Hash)> = v
                .witness
                .iter()
                .filter_map(|w| match w {
                    WitnessRec::InDoubtAbsent { n, link } => Some((*n, *link)),
                    WitnessRec::Prepare(_) | WitnessRec::Abort { .. } => None,
                })
                .collect();
            let got = answered("verify", api::verify_full(&v))?;
            prop_assert_eq!(got.1, want);
            Ok(())
        },
    );
}

/// R-CR-03, I-24: a changed `at` of an anchor, in either stored copy of
/// any prepared head, committed or withdrawn, is `BadSignature { n }`.
/// No structural check reads `at`, so only the signature catches it.
#[test]
fn r_cr_03_verify_names_a_changed_anchor_time() {
    let (anchor, witness) = (s::key(), s::key());
    check_with("r_cr_03_verify_names_a_changed_anchor_time", cfg(), |g| {
        let chain = gen_chain(g);
        let v = signed_view(g, chain, &anchor, &witness);
        for (n, link, store) in signed_copies(&v) {
            let mut w = v.clone();
            let row = s::row_mut(&mut w, store, n, &link).expect("stored copy");
            row.anchor.at = row.anchor.at.wrapping_add(1);
            bad_signature_at(&format!("anchor at of {n} in {store:?}"), &w, n)?;
        }
        Ok(())
    });
}

/// R-CR-03, I-24: a changed witness sequence, witness link or receipt
/// time, in either stored copy of any prepared head, is
/// `BadSignature { n }`. The verifier does not recompute the witness
/// chain, so only the receipt signature catches them.
#[test]
fn r_cr_03_verify_names_a_changed_receipt_field() {
    let (anchor, witness) = (s::key(), s::key());
    check_with("r_cr_03_verify_names_a_changed_receipt_field", cfg(), |g| {
        let chain = gen_chain(g);
        let v = signed_view(g, chain, &anchor, &witness);
        for (n, link, store) in signed_copies(&v) {
            for field in 0..3 {
                let mut w = v.clone();
                let f = &mut s::row_mut(&mut w, store, n, &link)
                    .expect("stored copy")
                    .receipt
                    .fields;
                match field {
                    0 => f.witness_seq = f.witness_seq.wrapping_add(1).max(1),
                    1 => f.witness_link[0] ^= 1,
                    _ => f.received_at = f.received_at.wrapping_add(1),
                }
                bad_signature_at(&format!("receipt field {field} of {n} in {store:?}"), &w, n)?;
            }
        }
        Ok(())
    });
}

/// R-CR-03, I-24: one flipped signature byte, at a random offset, of an
/// anchor or a receipt in either stored copy of any prepared head is
/// `BadSignature { n }`. The witness log copy covers aborted and in-doubt
/// prepares, which have no `audit.anchor` row.
#[test]
fn r_cr_03_verify_names_a_flipped_signature_byte_in_either_copy() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "r_cr_03_verify_names_a_flipped_signature_byte_in_either_copy",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            for (n, link, store) in signed_copies(&v) {
                for receipt in [false, true] {
                    let at = g.usize_in(0..=SIGNATURE_LEN - 1);
                    let bit = 1u8 << g.u8_in(0..=7);
                    let mut w = v.clone();
                    let row = s::row_mut(&mut w, store, n, &link).expect("stored copy");
                    let sig = if receipt {
                        &mut row.receipt.signature
                    } else {
                        &mut row.anchor.signature
                    };
                    sig[at] ^= bit;
                    let what = format!("receipt {receipt}, byte {at}, head {n} in {store:?}");
                    bad_signature_at(&what, &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// I-90, design section 7.4: an anchor whose ML-DSA-65 or Ed25519 half
/// is taken from the same key's signature over another anchor, or is
/// zeroed, is `BadSignature { n }` in either stored copy. The other half
/// still verifies on its own, and that is not enough.
#[test]
fn i90_verify_rejects_an_anchor_with_either_half_alone() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "i90_verify_rejects_an_anchor_with_either_half_alone",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            for (n, link, store) in signed_copies(&v) {
                for forgery in HalfForgery::ALL {
                    let mut w = v.clone();
                    let row = s::row_mut(&mut w, store, n, &link).expect("stored copy");
                    let mut moved = row.clone();
                    moved.anchor.at = moved.anchor.at.wrapping_add(1);
                    let other = s::sign(&anchor, &s::anchor_message_of(&moved), ANCHOR_CTX);
                    row.anchor.signature = forgery.apply(&row.anchor.signature, &other);
                    bad_signature_at(&format!("{forgery:?} at {n} in {store:?}"), &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// I-90, design section 7.4: a receipt whose ML-DSA-65 or Ed25519 half
/// is taken from the witness's signature over another receipt, or is
/// zeroed, is `BadSignature { n }` in either stored copy.
#[test]
fn i90_verify_rejects_a_receipt_with_either_half_alone() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "i90_verify_rejects_a_receipt_with_either_half_alone",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            for (n, link, store) in signed_copies(&v) {
                for forgery in HalfForgery::ALL {
                    let mut w = v.clone();
                    let row = s::row_mut(&mut w, store, n, &link).expect("stored copy");
                    let mut moved = row.clone();
                    moved.receipt.fields.received_at =
                        moved.receipt.fields.received_at.wrapping_add(1);
                    let other = s::sign(&witness, &s::receipt_message_of(&moved), RECEIPT_CTX);
                    row.receipt.signature = forgery.apply(&row.receipt.signature, &other);
                    bad_signature_at(&format!("{forgery:?} at {n} in {store:?}"), &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 open point 2: an anchor signed by the right key over
/// the right message, but under the empty default context or the receipt
/// context, is `BadSignature { n }`. So is a receipt signed under the
/// empty context or the anchor context.
#[test]
fn r_cr_03_verify_refuses_a_signature_under_another_context() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_a_signature_under_another_context",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let k = g.usize_in(0..=v.anchors.len() - 1);
            let (n, link) = (v.anchors[k].anchor.n, v.anchors[k].anchor.link);
            for (receipt, ctx) in [
                (false, &[][..]),
                (false, RECEIPT_CTX),
                (true, &[][..]),
                (true, ANCHOR_CTX),
            ] {
                let mut w = v.clone();
                s::edit_both(&mut w, n, &link, &|row: &mut AnchorRow| {
                    if receipt {
                        row.receipt.signature = s::sign(&witness, &s::receipt_message_of(row), ctx);
                    } else {
                        row.anchor.signature = s::sign(&anchor, &s::anchor_message_of(row), ctx);
                    }
                });
                bad_signature_at(&format!("receipt {receipt}, context {ctx:?}"), &w, n)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Keys": the anchor key is replaced yearly and old
/// public keys stay in the history. A chain whose earlier heads are
/// signed by an old key and later ones by the current key verifies under
/// the history of both, in either order.
#[test]
fn r_cr_03_verify_accepts_anchors_under_every_key_of_the_history() {
    let (old, current, witness) = (s::key(), s::key(), s::key());
    check_with(
        "r_cr_03_verify_accepts_anchors_under_every_key_of_the_history",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let mut v = signed_view(g, chain, &current, &witness);
            let heads = s::prepared_heads(&v);
            let cut = g.usize_in(0..=heads.len());
            for (n, link) in &heads[..cut] {
                s::edit_both(&mut v, *n, link, &|row: &mut AnchorRow| {
                    s::resign_anchor(row, &old);
                });
            }
            v.anchor_keys = vec![s::public(&old), s::public(&current)];
            verifies("old then current", &v)?;
            v.anchor_keys.reverse();
            verifies("current then old", &v)
        },
    );
}

/// R-CR-03, ADR-010 "Keys": an anchor signed by a composite key outside
/// the chain's anchor key history is `BadSignature { n }`, in either
/// stored copy. So is one signed by the witness key, which is pinned for
/// receipts only.
#[test]
fn r_cr_03_verify_refuses_an_anchor_under_a_key_outside_the_history() {
    let (anchor, witness, stranger) = (s::key(), s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_an_anchor_under_a_key_outside_the_history",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            for (n, link, store) in signed_copies(&v) {
                for (who, key) in [("stranger", &stranger), ("witness", &witness)] {
                    let mut w = v.clone();
                    s::resign_anchor(s::row_mut(&mut w, store, n, &link).expect("copy"), key);
                    bad_signature_at(&format!("{who} key at {n} in {store:?}"), &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Keys": a receipt signed by a key outside the pinned
/// witness keys is `BadSignature { n }`, in either stored copy. So is one
/// signed by the chain's anchor key.
#[test]
fn r_cr_03_verify_refuses_a_receipt_under_an_unpinned_witness_key() {
    let (anchor, witness, stranger) = (s::key(), s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_a_receipt_under_an_unpinned_witness_key",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            for (n, link, store) in signed_copies(&v) {
                for (who, key) in [("stranger", &stranger), ("anchor", &anchor)] {
                    let mut w = v.clone();
                    s::resign_receipt(s::row_mut(&mut w, store, n, &link).expect("copy"), key);
                    bad_signature_at(&format!("{who} key at {n} in {store:?}"), &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Verifier": the anchor key history and the pinned
/// witness keys are not interchangeable. With the two lists swapped, an
/// honest signed chain is `BadSignature` at one of its prepared heads.
#[test]
fn r_cr_03_verify_refuses_swapped_key_roles() {
    let (anchor, witness) = (s::key(), s::key());
    check_with("r_cr_03_verify_refuses_swapped_key_roles", cfg(), |g| {
        let chain = gen_chain(g);
        let mut v = signed_view(g, chain, &anchor, &witness);
        std::mem::swap(&mut v.anchor_keys, &mut v.witness_keys);
        let got = api::verify(&v);
        let heads: Vec<u64> = s::prepared_heads(&v).iter().map(|h| h.0).collect();
        prop_assert!(
            matches!(&got, Err(AuditError::Tamper(Tamper::BadSignature { n })) if heads.contains(n)),
            "swapped key lists got {got:?}"
        );
        Ok(())
    });
}

/// R-CR-03, I-90: a signed chain checked against no usable key is
/// `BadSignature` at one of its prepared heads, never `Ok`. The cases are
/// an empty list, and a list of malformed keys only: a wrong length, a
/// key of zeros, and the real key cut short or padded.
#[test]
fn r_cr_03_verify_refuses_signed_rows_without_a_usable_key() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_signed_rows_without_a_usable_key",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let heads: Vec<u64> = s::prepared_heads(&v).iter().map(|h| h.0).collect();
            let unusable = |real: &[u8]| -> Vec<Vec<Vec<u8>>> {
                let mut padded = real.to_vec();
                padded.push(0);
                vec![
                    Vec::new(),
                    vec![vec![0x42; 32]],
                    vec![vec![0; PUBLIC_KEY_LEN]],
                    vec![real[..PUBLIC_KEY_LEN - 1].to_vec()],
                    vec![padded],
                ]
            };
            for witness_side in [false, true] {
                let real = if witness_side {
                    v.witness_keys[0].clone()
                } else {
                    v.anchor_keys[0].clone()
                };
                for keys in unusable(&real) {
                    let mut w = v.clone();
                    if witness_side {
                        w.witness_keys = keys.clone();
                    } else {
                        w.anchor_keys = keys.clone();
                    }
                    let got = api::verify(&w);
                    prop_assert!(
                        matches!(&got, Err(AuditError::Tamper(Tamper::BadSignature { n }))
                            if heads.contains(n)),
                        "witness side {}, {} keys: got {:?}",
                        witness_side,
                        keys.len(),
                        got
                    );
                }
            }
            Ok(())
        },
    );
}

/// R-CR-03, I-24: a valid signature moved from one head to another is
/// `BadSignature { n }` of the head it was moved to. The anchor message
/// binds `n` and the link, so another head's anchor signature does not
/// verify, and neither does a receipt signature put in an anchor's place.
#[test]
fn r_cr_03_verify_refuses_a_signature_moved_from_another_head() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_a_signature_moved_from_another_head",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let heads = s::prepared_heads(&v);
            for (i, (n, link)) in heads.iter().enumerate() {
                let donor = &heads[(i + 1) % heads.len()];
                let mut w = v.clone();
                let from = s::row_mut(&mut w, Store::WitnessLog, donor.0, &donor.1)
                    .expect("donor")
                    .clone();
                let row = s::row_mut(&mut w, Store::WitnessLog, *n, link).expect("target");
                if donor != &(*n, *link) {
                    row.anchor.signature = from.anchor.signature.clone();
                    bad_signature_at(&format!("anchor signature of {donor:?}"), &w, *n)?;
                }
                let mut w = v.clone();
                let row = s::row_mut(&mut w, Store::WitnessLog, *n, link).expect("target");
                row.anchor.signature = row.receipt.signature.clone();
                bad_signature_at(&format!("receipt signature as anchor at {n}"), &w, *n)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, TH-26: a stored signature of another length than the draft
/// 19 composite length is `BadSignature { n }`, never a panic: empty, one
/// byte short, one byte long, and the Ed25519 half alone.
#[test]
fn r_cr_03_verify_refuses_a_signature_of_another_length() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "r_cr_03_verify_refuses_a_signature_of_another_length",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let k = g.usize_in(0..=v.anchors.len() - 1);
            let (n, link) = (v.anchors[k].anchor.n, v.anchors[k].anchor.link);
            let store = *g.pick(&Store::ALL);
            for receipt in [false, true] {
                for len in [0, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1, 64] {
                    let mut w = v.clone();
                    let row = s::row_mut(&mut w, store, n, &link).expect("stored copy");
                    let sig = if receipt {
                        &mut row.receipt.signature
                    } else {
                        &mut row.anchor.signature
                    };
                    if len == 64 {
                        sig.drain(..s::MLDSA_SIG_LEN);
                    } else {
                        sig.resize(len, 0);
                    }
                    let what = format!("receipt {receipt}, {len} bytes in {store:?}");
                    bad_signature_at(&what, &w, n)?;
                }
            }
            Ok(())
        },
    );
}

/// I-24, R-CR-03: a signed chain whose committed head carries no witness
/// copy of its signatures is caught. Deleting a committed prepare from
/// the witness log is `AnchorMismatch { n }`, as in `common::view`, and
/// the signatures of the remaining copies do not mask it.
#[test]
fn i24_verify_names_a_deleted_signed_prepare() {
    let (anchor, witness) = (s::key(), s::key());
    check_with("i24_verify_names_a_deleted_signed_prepare", cfg(), |g| {
        let chain = gen_chain(g);
        let v = signed_view(g, chain, &anchor, &witness);
        let k = g.usize_in(0..=v.anchors.len() - 1);
        let (n, link) = (v.anchors[k].anchor.n, v.anchors[k].anchor.link);
        let mut w = v.clone();
        let i = s::witness_index(&w, n, &link).expect("prepare");
        w.witness.remove(i);
        let got = api::verify(&w);
        prop_assert_eq!(got, Err(AuditError::Tamper(Tamper::AnchorMismatch { n })));
        Ok(())
    });
}

/// I-24: the mutation list of `common::view` covers both signature kinds
/// of every anchor row, so `i24_verify_names_each_mutation_of_a_signed_chain`
/// reaches the signature step for each head. A guard on the fixture.
#[test]
fn i24_signed_mutations_cover_every_anchor_signature() {
    let (anchor, witness) = (s::key(), s::key());
    check_with(
        "i24_signed_mutations_cover_every_anchor_signature",
        cfg(),
        |g| {
            let chain = gen_chain(g);
            let v = signed_view(g, chain, &anchor, &witness);
            let ms = view::mutations(&v);
            for k in 0..v.anchors.len() {
                prop_assert!(ms.contains(&Mutation::AnchorSignature(k)), "anchor {}", k);
                prop_assert!(ms.contains(&Mutation::ReceiptSignature(k)), "receipt {}", k);
            }
            Ok(())
        },
    );
}
