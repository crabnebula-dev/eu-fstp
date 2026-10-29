//! R-CR-03, I-90, I-24: receipt signing and the anchor signature check at
//! the witness (ADR-010 "Receipt", "Keys" and "Composite encoding",
//! design sections 7.2 and 7.4). These are T-CR-COMPOSITE tests for
//! TH-67.
//!
//! Daniel accepted the ADR-010 composite encoding table on 2026-10-29
//! (design section 21.0). So `fstp_witness::sign_receipt` signs under the
//! witness's composite receipt key, and
//! `fstp_witness::receipt::check_anchor_signature` checks a prepare's
//! anchor against the chain's anchor key history before the witness core
//! sees it. The interim test that wanted receipt signing to refuse is
//! gone.
//!
//! Readings these tests pin:
//!
//! - Anchors are signed under the context `common::ANCHOR_CTX` and
//!   receipts under `common::RECEIPT_CTX` (interim reading of lane W2g,
//!   ADR-010 open point 2). The receipt context is pinned through
//!   `fstp_audit::verify`, whose own tests pin it against
//!   `fstp_crypto::composite`.
//! - Any key of the anchor key history verifies an anchor, and any pinned
//!   witness key verifies a receipt (ADR-010 "Keys").
//! - A receipt the witness signs for the receipt fields its core gave
//!   verifies in the chain verifier, so the cell can store it.
//!
//! Lane W2g landed receipt signing and the anchor signature check. A
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

use common::api::{
    self, Chain, Hash, Key, MLDSA_SIG_LEN, OneRow, PUBLIC_KEY_LEN, Receipt, SIGNATURE_LEN, Sender,
    SignedAnchor, SignedReceipt, Verdict,
};
use common::{ANCHOR_CTX, RECEIPT_CTX, answered, real_refusal};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

const CELL: [u8; 16] = [0x11; 16];

/// Seeds of the fixed test keys.
const ANCHOR_SEED: u8 = 0xA1;
const OLD_ANCHOR_SEED: u8 = 0xA0;
const WITNESS_SEED: u8 = 0x3E;
const OLD_WITNESS_SEED: u8 = 0x3D;
const STRANGER_SEED: u8 = 0x77;

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

fn gen_receipt(g: &mut Gen) -> Receipt {
    Receipt {
        n: g.u64_in(1..=u64::MAX),
        link: gen_hash(g),
        witness_seq: g.u64_in(1..=u64::MAX),
        witness_link: gen_hash(g),
        received_at: g.i64(),
    }
}

/// A random anchor of `cell`'s `chain`, signed in the test with `k`
/// under `ctx`.
fn gen_anchor(g: &mut Gen, k: &Key, ctx: &[u8]) -> SignedAnchor {
    let (cell, chain) = (gen_cell(g), gen_chain(g));
    let (n, link, at) = (g.u64_in(1..=u64::MAX - 1), gen_hash(g), g.i64());
    SignedAnchor::signed(k, ctx, cell, chain, n, link, at)
}

/// `Ok` when the witness refuses `a` under `keys` for real.
fn refused(what: &str, a: &SignedAnchor, keys: &[Vec<u8>]) -> Result<(), String> {
    real_refusal(what, &api::check_anchor_signature(a, keys))
}

/// One honest append of `chain`: its row, its anchor signed with
/// `anchor_key`, and the receipt fields the witness core gives for its
/// prepare.
fn honest_append(
    chain: Chain,
    anchor_key: &Key,
) -> Result<(OneRow, SignedAnchor, Receipt), String> {
    let row = api::one_row(CELL, chain, 10);
    let anchor = SignedAnchor::signed(anchor_key, ANCHOR_CTX, CELL, chain, row.n, row.link, 10);
    let mut core = answered("witness genesis", api::Core::genesis(CELL, chain))?;
    let fields = answered(
        "prepare",
        core.prepare(Sender::writer(CELL, chain), &row.prepare(&anchor), 11),
    )?
    .map_err(|e| format!("the witness core refused an honest prepare: {e:?}"))?;
    Ok((row, anchor, fields))
}

/// The witness's receipt of `fields`, signed with `k`.
fn receipt(k: &Key, chain: Chain, fields: &Receipt) -> Result<SignedReceipt, String> {
    answered("sign_receipt", api::sign_receipt(k, CELL, chain, fields))
}

// ---------------------------------------------------------------------------
// Receipt signing (`fstp_witness::sign_receipt`).

/// R-CR-03, ADR-010 "Receipt": `sign_receipt` returns the receipt of the
/// fields it was given, for either chain, with a composite signature of
/// the draft 19 length.
#[test]
fn r_cr_03_sign_receipt_returns_the_receipt_it_signed() {
    let k = api::key(WITNESS_SEED);
    check_with(
        "r_cr_03_sign_receipt_returns_the_receipt_it_signed",
        cfg(),
        |g| {
            let (cell, chain, fields) = (gen_cell(g), gen_chain(g), gen_receipt(g));
            let r = answered("sign_receipt", api::sign_receipt(&k, cell, chain, &fields))?;
            prop_assert_eq!((r.cell, r.chain, r.fields), (cell, chain, fields));
            prop_assert_eq!(r.signature.len(), SIGNATURE_LEN);
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Receipt": a receipt of row 0 or of witness sequence
/// 0 is refused for real, not by a stub. Neither could be encoded or
/// stored.
#[test]
fn r_cr_03_sign_receipt_refuses_row_zero_and_witness_sequence_zero() {
    let k = api::key(WITNESS_SEED);
    let fields = Receipt {
        n: 2,
        link: [0x5C; 32],
        witness_seq: 9,
        witness_link: [0xA5; 32],
        received_at: 1_700_000_000_000_005,
    };
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let zero_n = Receipt { n: 0, ..fields };
        let zero_seq = Receipt {
            witness_seq: 0,
            ..fields
        };
        for (what, f) in [("row 0", zero_n), ("witness sequence 0", zero_seq)] {
            let r = api::sign_receipt(&k, CELL, chain, &f);
            got.push(real_refusal(&format!("{chain:?} receipt of {what}"), &r));
        }
    }
    assert_eq!(got, vec![Ok(()); 4]);
}

/// R-CR-03, I-24, ADR-010 "Prepare, receipt, commit": for either chain,
/// the receipt the witness signs for the fields its core gave an honest
/// prepare verifies in `fstp_audit::verify`, beside the anchor, under the
/// pinned witness key. The cell can store it and commit.
#[test]
fn r_cr_03_witness_receipts_verify_in_the_chain_verifier() {
    let (anchor_key, witness_key) = (api::key(ANCHOR_SEED), api::key(WITNESS_SEED));
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let verdict = honest_append(chain, &anchor_key).and_then(|(row, anchor, fields)| {
            let rc = receipt(&witness_key, chain, &fields)?;
            Ok(api::verify_one_row(
                &row,
                &anchor,
                &rc,
                &[api::public(&anchor_key)],
                &[api::public(&witness_key)],
            ))
        });
        got.push(verdict);
    }
    assert_eq!(
        got,
        vec![Ok(Verdict::Verified(1)), Ok(Verdict::Verified(1))]
    );
}

/// R-CR-03, ADR-010 "Keys": a receipt signed by a key that the cell has
/// not pinned is `BadSignature { n }`. So is a pinned set that holds only
/// the chain's anchor key, since the anchor key never signs receipts.
#[test]
fn r_cr_03_witness_receipt_does_not_verify_under_another_witness_key() {
    let (anchor_key, witness_key) = (api::key(ANCHOR_SEED), api::key(WITNESS_SEED));
    let stranger = api::key(STRANGER_SEED);
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let verdicts = honest_append(chain, &anchor_key).and_then(|(row, anchor, fields)| {
            let rc = receipt(&witness_key, chain, &fields)?;
            let anchor_keys = [api::public(&anchor_key)];
            Ok([
                api::verify_one_row(&row, &anchor, &rc, &anchor_keys, &[api::public(&stranger)]),
                api::verify_one_row(&row, &anchor, &rc, &anchor_keys, &anchor_keys),
            ])
        });
        got.push(verdicts);
    }
    let want = Ok([Verdict::BadSignature(1), Verdict::BadSignature(1)]);
    assert_eq!(got, vec![want.clone(), want]);
}

/// R-CR-03, I-24: the receipt signature binds the witness sequence, the
/// witness link and the receipt time. Stored beside fields with one of
/// them changed, it is `BadSignature { n }`.
#[test]
fn r_cr_03_witness_receipt_signature_binds_every_signed_field() {
    let (anchor_key, witness_key) = (api::key(ANCHOR_SEED), api::key(WITNESS_SEED));
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let verdicts = honest_append(chain, &anchor_key).and_then(|(row, anchor, fields)| {
            let rc = receipt(&witness_key, chain, &fields)?;
            let mut out = Vec::new();
            for field in 0..3 {
                let mut moved = rc.clone();
                let f = &mut moved.fields;
                match field {
                    0 => f.witness_seq += 1,
                    1 => f.witness_link[0] ^= 1,
                    _ => f.received_at = f.received_at.wrapping_add(1),
                }
                out.push(api::verify_one_row(
                    &row,
                    &anchor,
                    &moved,
                    &[api::public(&anchor_key)],
                    &[api::public(&witness_key)],
                ));
            }
            Ok(out)
        });
        got.push(verdicts);
    }
    let want = Ok(vec![Verdict::BadSignature(1); 3]);
    assert_eq!(got, vec![want.clone(), want]);
}

/// R-CR-03, ADR-010 open point 2: a receipt signature never stands for an
/// anchor signature. Even with the witness key in the anchor key history,
/// an anchor that carries the receipt's signature is `BadSignature`.
#[test]
fn r_cr_03_witness_receipt_signature_is_no_anchor_signature() {
    let (anchor_key, witness_key) = (api::key(ANCHOR_SEED), api::key(WITNESS_SEED));
    let mut got = Vec::new();
    for chain in Chain::ALL {
        let verdict = honest_append(chain, &anchor_key).and_then(|(row, anchor, fields)| {
            let rc = receipt(&witness_key, chain, &fields)?;
            let forged = SignedAnchor {
                signature: rc.signature.clone(),
                ..anchor
            };
            let keys = [api::public(&anchor_key), api::public(&witness_key)];
            Ok(api::verify_one_row(&row, &forged, &rc, &keys, &keys))
        });
        got.push(verdict);
    }
    let want = Ok(Verdict::BadSignature(1));
    assert_eq!(got, vec![want.clone(), want]);
}

/// R-CR-03, ADR-010 "Keys": the witness receipt key is replaced yearly,
/// and cells pin a set of witness keys. A receipt signed by the old key
/// or by the new one verifies under the pinned set of both.
#[test]
fn r_cr_03_witness_receipt_verifies_under_every_pinned_witness_key() {
    let anchor_key = api::key(ANCHOR_SEED);
    let (old, new) = (api::key(OLD_WITNESS_SEED), api::key(WITNESS_SEED));
    let pinned = [api::public(&old), api::public(&new)];
    let mut got = Vec::new();
    for chain in Chain::ALL {
        for k in [&old, &new] {
            let verdict = honest_append(chain, &anchor_key).and_then(|(row, anchor, fields)| {
                let rc = receipt(k, chain, &fields)?;
                Ok(api::verify_one_row(
                    &row,
                    &anchor,
                    &rc,
                    &[api::public(&anchor_key)],
                    &pinned,
                ))
            });
            got.push(verdict);
        }
    }
    assert_eq!(got, vec![Ok(Verdict::Verified(1)); 4]);
}

// ---------------------------------------------------------------------------
// The anchor signature check (`fstp_witness::receipt::check_anchor_signature`).

/// R-CR-03, ADR-010 "Keys": the witness accepts an anchor signed under
/// the anchor context by any key of the chain's anchor key history, the
/// old key or the current one, in either order of the history.
#[test]
fn r_cr_03_witness_accepts_an_anchor_under_any_key_of_the_history() {
    let (old, current) = (api::key(OLD_ANCHOR_SEED), api::key(ANCHOR_SEED));
    check_with(
        "r_cr_03_witness_accepts_an_anchor_under_any_key_of_the_history",
        cfg(),
        |g| {
            let signer = if g.bool() { &old } else { &current };
            let a = gen_anchor(g, signer, ANCHOR_CTX);
            let mut history = vec![api::public(&old), api::public(&current)];
            if g.bool() {
                history.reverse();
            }
            let got = api::check_anchor_signature(&a, &history);
            prop_assert!(got.is_ok(), "an honest anchor got {:?}", got);
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 "Keys": the witness refuses an anchor signed by a key
/// outside the chain's anchor key history, the witness's own key
/// included.
#[test]
fn r_cr_03_witness_refuses_an_anchor_under_a_key_outside_the_history() {
    let (anchor_key, witness_key) = (api::key(ANCHOR_SEED), api::key(WITNESS_SEED));
    let stranger = api::key(STRANGER_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_under_a_key_outside_the_history",
        cfg(),
        |g| {
            let history = [api::public(&anchor_key)];
            for (who, k) in [("stranger", &stranger), ("witness", &witness_key)] {
                let a = gen_anchor(g, k, ANCHOR_CTX);
                refused(&format!("anchor by the {who} key"), &a, &history)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, ADR-010 open point 2: the witness refuses an anchor signed by
/// the right key over the right message under the empty default context
/// or the receipt context.
#[test]
fn r_cr_03_witness_refuses_an_anchor_signed_under_another_context() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_signed_under_another_context",
        cfg(),
        |g| {
            let history = [api::public(&k)];
            for ctx in [&[][..], RECEIPT_CTX] {
                let a = gen_anchor(g, &k, ctx);
                refused(&format!("anchor under context {ctx:?}"), &a, &history)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, I-24: the anchor signature binds the cell, the chain, `n`,
/// the link and `at`. The witness refuses the signature beside any one of
/// them changed.
#[test]
fn r_cr_03_witness_refuses_an_anchor_with_a_changed_signed_field() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_with_a_changed_signed_field",
        cfg(),
        |g| {
            let history = [api::public(&k)];
            let a = gen_anchor(g, &k, ANCHOR_CTX);
            for field in 0..5 {
                let mut b = a.clone();
                match field {
                    0 => b.cell[0] ^= 1,
                    1 => {
                        b.chain = match b.chain {
                            Chain::App => Chain::Vault,
                            Chain::Vault => Chain::App,
                        }
                    }
                    2 => b.n += 1,
                    3 => b.link[31] ^= 1,
                    _ => b.at = b.at.wrapping_add(1),
                }
                refused(&format!("anchor with field {field} changed"), &b, &history)?;
            }
            Ok(())
        },
    );
}

/// I-90, design section 7.4: the witness refuses an anchor whose ML-DSA-65
/// or Ed25519 half is taken from the same key's signature over another
/// anchor, or is zeroed. The other half verifies on its own, and that is
/// not enough.
#[test]
fn i90_witness_refuses_an_anchor_with_either_half_alone() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "i90_witness_refuses_an_anchor_with_either_half_alone",
        cfg(),
        |g| {
            let history = [api::public(&k)];
            let a = gen_anchor(g, &k, ANCHOR_CTX);
            let other = SignedAnchor::signed(
                &k,
                ANCHOR_CTX,
                a.cell,
                a.chain,
                a.n,
                a.link,
                a.at.wrapping_add(1),
            );
            for half in 0..4 {
                let mut b = a.clone();
                let s = &mut b.signature;
                match half {
                    0 => s[..MLDSA_SIG_LEN].copy_from_slice(&other.signature[..MLDSA_SIG_LEN]),
                    1 => s[MLDSA_SIG_LEN..].copy_from_slice(&other.signature[MLDSA_SIG_LEN..]),
                    2 => s[..MLDSA_SIG_LEN].fill(0),
                    _ => s[MLDSA_SIG_LEN..].fill(0),
                }
                refused(&format!("half forgery {half}"), &b, &history)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, I-90: the witness refuses an anchor with one flipped bit at
/// any offset of its signature.
#[test]
fn r_cr_03_witness_refuses_an_anchor_with_a_flipped_signature_bit() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_with_a_flipped_signature_bit",
        cfg(),
        |g| {
            let history = [api::public(&k)];
            let mut a = gen_anchor(g, &k, ANCHOR_CTX);
            let at = g.usize_in(0..=SIGNATURE_LEN - 1);
            a.signature[at] ^= 1u8 << g.u8_in(0..=7);
            refused(&format!("bit flipped at byte {at}"), &a, &history)
        },
    );
}

/// R-CR-03, I-90: with no usable anchor key the witness refuses every
/// anchor, never accepts and never panics. The cases are an empty
/// history and histories of malformed keys only: a wrong length, a key
/// of zeros, and the real key cut short or padded.
#[test]
fn r_cr_03_witness_refuses_an_anchor_without_a_usable_key() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_without_a_usable_key",
        cfg(),
        |g| {
            let a = gen_anchor(g, &k, ANCHOR_CTX);
            let real = api::public(&k);
            let mut padded = real.clone();
            padded.push(0);
            let histories: [Vec<Vec<u8>>; 5] = [
                Vec::new(),
                vec![vec![0x42; 32]],
                vec![vec![0; PUBLIC_KEY_LEN]],
                vec![real[..PUBLIC_KEY_LEN - 1].to_vec()],
                vec![padded],
            ];
            for (i, h) in histories.iter().enumerate() {
                refused(&format!("history {i}"), &a, h)?;
            }
            Ok(())
        },
    );
}

/// R-CR-03, TH-26: the witness refuses an anchor signature of another
/// length than the draft 19 composite length, and never panics: empty,
/// one byte short, one byte long, and the Ed25519 half alone.
#[test]
fn r_cr_03_witness_refuses_an_anchor_signature_of_another_length() {
    let k = api::key(ANCHOR_SEED);
    check_with(
        "r_cr_03_witness_refuses_an_anchor_signature_of_another_length",
        cfg(),
        |g| {
            let history = [api::public(&k)];
            let a = gen_anchor(g, &k, ANCHOR_CTX);
            for len in [0, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1, 64] {
                let mut b = a.clone();
                if len == 64 {
                    b.signature.drain(..MLDSA_SIG_LEN);
                } else {
                    b.signature.resize(len, 0);
                }
                refused(&format!("a {len}-byte signature"), &b, &history)?;
            }
            Ok(())
        },
    );
}
