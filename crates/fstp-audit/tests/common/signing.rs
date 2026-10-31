//! Composite signatures made in the test, and the forgeries the verifier
//! must name (R-CR-03, I-90, ADR-010 "Composite encoding").
//!
//! Signatures come from `fstp_crypto::composite`, the draft 19
//! construction that ADR-010 transcribes and Daniel accepted on
//! 2026-10-29. Each signs under the pinned application context of its
//! message, `common::ANCHOR_CTX` or `common::RECEIPT_CTX`.
//!
//! The half forgeries use the draft 19 signature layout of ADR-010, row
//! "Signature": `mldsaSig || tradSig`, with the ML-DSA-65 half first
//! (`fstp_crypto::composite::MLDSA_SIGNATURE_LEN` bytes) and the Ed25519 half last.

use fstp_crypto::composite::{self, CompositeSigningKey};

use super::reference as r;
use super::view::{AnchorRow, View, WitnessRec};
use super::{ANCHOR_CTX, RECEIPT_CTX};

/// The length of the ML-DSA-65 half (ADR-010, row "Signature").
pub(crate) const MLDSA_SIG_LEN: usize = fstp_crypto::composite::MLDSA_SIGNATURE_LEN;

/// A fresh composite key.
pub(crate) fn key() -> CompositeSigningKey {
    composite::generate().expect("composite keygen")
}

/// The encoded public key of `k`.
pub(crate) fn public(k: &CompositeSigningKey) -> Vec<u8> {
    k.public_key().to_bytes().to_vec()
}

/// A composite signature over `msg` under the application context `ctx`.
pub(crate) fn sign(k: &CompositeSigningKey, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    k.sign_with_context(msg, ctx)
        .expect("composite sign")
        .to_bytes()
        .to_vec()
}

/// The ADR-010 anchor message of `row`'s anchor.
pub(crate) fn anchor_message_of(row: &AnchorRow) -> Vec<u8> {
    let a = &row.anchor;
    r::anchor_message(a.cell, a.chain, a.n, &a.link, a.at)
}

/// The receipt message of `row`'s receipt.
pub(crate) fn receipt_message_of(row: &AnchorRow) -> Vec<u8> {
    let rc = &row.receipt;
    r::receipt_message(rc.cell, rc.chain, &rc.fields)
}

/// `row`'s anchor signed again with `k`, under [`ANCHOR_CTX`].
pub(crate) fn resign_anchor(row: &mut AnchorRow, k: &CompositeSigningKey) {
    row.anchor.signature = sign(k, &anchor_message_of(row), ANCHOR_CTX);
}

/// `row`'s receipt signed again with `k`, under [`RECEIPT_CTX`].
pub(crate) fn resign_receipt(row: &mut AnchorRow, k: &CompositeSigningKey) {
    row.receipt.signature = sign(k, &receipt_message_of(row), RECEIPT_CTX);
}

/// Where a signed anchor row is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Store {
    /// The row of `audit.anchor`, which the cell's database owner holds.
    AnchorTable,
    /// The prepare record of the witness log, which the witness holds.
    WitnessLog,
}

impl Store {
    /// Both copies.
    pub(crate) const ALL: [Store; 2] = [Store::AnchorTable, Store::WitnessLog];
}

/// The index in `v.witness` of the prepare record for head `(n, link)`.
pub(crate) fn witness_index(v: &View, n: u64, link: &r::Hash) -> Option<usize> {
    v.witness.iter().position(|w| match w {
        WitnessRec::Prepare(p) => p.anchor.n == n && p.anchor.link == *link,
        WitnessRec::Abort { .. } | WitnessRec::InDoubtAbsent { .. } => false,
    })
}

/// The `(n, link)` of every prepare record in the witness log, committed
/// or withdrawn, in witness order.
pub(crate) fn prepared_heads(v: &View) -> Vec<(u64, r::Hash)> {
    v.witness
        .iter()
        .filter_map(|w| match w {
            WitnessRec::Prepare(p) => Some((p.anchor.n, p.anchor.link)),
            WitnessRec::Abort { .. } | WitnessRec::InDoubtAbsent { .. } => None,
        })
        .collect()
}

/// The stored copy of the anchor row for head `(n, link)`. The witness
/// log holds a prepare for every head, and `audit.anchor` only for the
/// committed ones.
pub(crate) fn row_mut<'a>(
    v: &'a mut View,
    store: Store,
    n: u64,
    link: &r::Hash,
) -> Option<&'a mut AnchorRow> {
    match store {
        Store::AnchorTable => v
            .anchors
            .iter_mut()
            .find(|a| a.anchor.n == n && a.anchor.link == *link),
        Store::WitnessLog => {
            let i = witness_index(v, n, link)?;
            match v.witness.get_mut(i)? {
                WitnessRec::Prepare(p) => Some(p),
                WitnessRec::Abort { .. } | WitnessRec::InDoubtAbsent { .. } => None,
            }
        }
    }
}

/// Applies `f` to both stored copies of the anchor row for head
/// `(n, link)`: an honest re-signing, as a key rotation makes.
pub(crate) fn edit_both(v: &mut View, n: u64, link: &r::Hash, f: &dyn Fn(&mut AnchorRow)) {
    for store in Store::ALL {
        if let Some(row) = row_mut(v, store, n, link) {
            f(row);
        }
    }
}

/// A forgery of one half of a composite signature, made without the key
/// (I-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HalfForgery {
    /// The ML-DSA-65 half taken from a signature over another message.
    MlDsaFromAnotherMessage,
    /// The Ed25519 half taken from a signature over another message.
    Ed25519FromAnotherMessage,
    /// The ML-DSA-65 half zeroed.
    MlDsaZeroed,
    /// The Ed25519 half zeroed.
    Ed25519Zeroed,
}

impl HalfForgery {
    /// Every half forgery.
    pub(crate) const ALL: [HalfForgery; 4] = [
        HalfForgery::MlDsaFromAnotherMessage,
        HalfForgery::Ed25519FromAnotherMessage,
        HalfForgery::MlDsaZeroed,
        HalfForgery::Ed25519Zeroed,
    ];

    /// `sig` with one half replaced. `other` is a valid signature by the
    /// same key over another message, under the same context.
    pub(crate) fn apply(self, sig: &[u8], other: &[u8]) -> Vec<u8> {
        let mut out = sig.to_vec();
        match self {
            HalfForgery::MlDsaFromAnotherMessage => {
                out[..MLDSA_SIG_LEN].copy_from_slice(&other[..MLDSA_SIG_LEN]);
            }
            HalfForgery::Ed25519FromAnotherMessage => {
                out[MLDSA_SIG_LEN..].copy_from_slice(&other[MLDSA_SIG_LEN..]);
            }
            HalfForgery::MlDsaZeroed => out[..MLDSA_SIG_LEN].fill(0),
            HalfForgery::Ed25519Zeroed => out[MLDSA_SIG_LEN..].fill(0),
        }
        out
    }
}
