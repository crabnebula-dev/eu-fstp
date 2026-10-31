//! I-24: `fstp_audit::verify` (design section 7.1, ADR-010 "Verifier").
//!
//! Daniel accepted the ADR-010 composite encoding table on 2026-10-29
//! (design section 21.0), so the verifier checks every anchor and receipt
//! signature. It answers `Ok` only for an untampered, fully signed chain.
//! The signature tests themselves are in `signatures.rs`.
//!
//! Readings these tests build on (see `common::view`):
//!
//! - Row order, ledger coverage, stored hashes and links need no key. A
//!   change there is reported as its tamper before any signature check.
//! - Every structural change to the tail, the anchor rows and the witness
//!   log gets its exact tamper too. Over placeholder signatures a changed
//!   signature byte gets anything but `Ok` or a stub refusal.
//! - An honest chain whose anchors carry placeholder signatures is
//!   `BadSignature`, never `Ok`.
//!
//! Lane W2g landed the verifier's signature step. A refusal that still
//! names the old acceptance stub fails every test here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::reference::{CELL, Chain, OTHER_CELL};
use common::view::{self, Expect, Mutation, Sigs, View};
use common::{api, is_stub_or_gap};
use fstp_audit::{AuditError, Tamper};
use fstp_prop::{Config, Gen, check, check_with, prop_assert};

fn gen_chain(g: &mut Gen) -> Chain {
    *g.pick(&Chain::ALL)
}

/// The heads that the witness log prepared, committed or withdrawn.
fn prepared(v: &View) -> Vec<u64> {
    common::signing::prepared_heads(v)
        .into_iter()
        .map(|(n, _)| n)
        .collect()
}

/// `Ok` when the verifier's answer for `v` meets `expect`.
fn meets(v: &View, m: Mutation, expect: &Expect) -> Result<(), String> {
    let got = api::verify(v);
    let tamper = match &got {
        Err(AuditError::Tamper(t)) => Some(t.clone()),
        _ => None,
    };
    let ok = match expect {
        Expect::Exact(t) => tamper.as_ref() == Some(t),
        Expect::OneOf(ts) => tamper.as_ref().is_some_and(|t| ts.contains(t)),
        Expect::AnyTamper => tamper.is_some(),
        Expect::NotOk => matches!(&got, Err(e) if !is_stub_or_gap(e)),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("I-24: {m:?} must get {expect:?}, got {got:?}"))
    }
}

/// Whether `m` changes only rows or ledger entries, so needs no key.
fn keyless(m: Mutation) -> bool {
    matches!(
        m,
        Mutation::RowAt(_)
            | Mutation::EventBody(_)
            | Mutation::StoredHashColumn(_)
            | Mutation::LinkColumn(_)
            | Mutation::Entry(..)
            | Mutation::DeleteRow(_)
            | Mutation::SwapRows(_)
            | Mutation::DeleteEntry(_)
            | Mutation::DuplicateEntry(_)
            | Mutation::ExtraEntry
    )
}

/// I-90, R-CR-03: an honest chain of either chain, with aborted and
/// in-doubt batches at the witness, whose anchors and receipts carry
/// placeholder signatures that no key made, is `BadSignature` at one of
/// its prepared heads. It is never `Ok`. This replaces the interim test
/// that wanted the acceptance refusal.
#[test]
fn i90_verify_refuses_an_honest_chain_with_placeholder_signatures() {
    check(
        "i90_verify_refuses_an_honest_chain_with_placeholder_signatures",
        |g| {
            let chain = gen_chain(g);
            let v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
            let got = api::verify(&v);
            prop_assert!(
                matches!(&got, Err(AuditError::Tamper(Tamper::BadSignature { n }))
                    if prepared(&v).contains(n)),
                "unsigned anchors got {got:?}"
            );
            Ok(())
        },
    );
}

/// I-24, I-90, R-CR-03: an honest chain of either chain, with aborted
/// and in-doubt batches at the witness, whose anchors and receipts are
/// composite-signed under the pinned contexts, verifies. The answer
/// counts every row. This replaces the interim test that wanted the
/// acceptance refusal.
#[test]
fn i24_verify_accepts_every_honest_signed_chain() {
    check_with(
        "i24_verify_accepts_every_honest_signed_chain",
        Config::default().with_cases(16),
        |g| {
            let chain = gen_chain(g);
            let v = view::gen_view(g, CELL, chain, Sigs::composite());
            let got = api::verify(&v);
            let rows = u64::try_from(v.rows.len()).expect("small view");
            prop_assert!(got == Ok(rows), "an honest signed chain got {got:?}");
            Ok(())
        },
    );
}

/// I-24: an empty chain with an empty witness log verifies with no rows.
#[test]
fn i24_verify_reports_no_tamper_for_an_empty_chain() {
    let v = view::Builder::new(CELL, Chain::App, Sigs::Placeholder).finish();
    let got = api::verify(&v);
    assert_eq!(got, Ok(0), "an empty chain got {got:?}");
}

/// I-24, ADR-010 "Verifier": a change to rows or ledger entries that
/// needs no key is reported as its tamper: `Changed`, `Gap`,
/// `Reordered`, `LedgerWithoutRow`, `RowWithoutLedger` or
/// `StoredHashMismatch`, with its row number or sequence.
#[test]
fn i24_verify_reports_each_keyless_mutation_as_its_tamper() {
    check(
        "i24_verify_reports_each_keyless_mutation_as_its_tamper",
        |g| {
            let chain = gen_chain(g);
            let v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
            let ms: Vec<Mutation> = view::mutations(&v)
                .into_iter()
                .filter(|m| keyless(*m))
                .collect();
            let m = *g.pick(&ms);
            g.note("mutation", &m);
            let Some((w, expect)) = view::apply(&v, m) else {
                g.reject();
            };
            meets(&w, m, &expect)
        },
    );
}

/// I-24, design section 14.4 `i24_verifier_flags_every_mutation` at crate
/// level: every attacker step against a random chain of either chain is
/// flagged. Change, deletion, insertion, reordering, truncation and a
/// consistent recomputation of rows, ledger entries, anchor rows,
/// signatures and witness records each get anything but `Ok`. Every
/// mutation but a changed signature byte gets a tamper, its exact one
/// where `common::view` fixes it. So the structural checks are tested
/// whatever the signature state.
#[test]
fn i24_verifier_flags_every_mutation() {
    check("i24_verifier_flags_every_mutation", |g| {
        let chain = gen_chain(g);
        let v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
        for m in view::mutations(&v) {
            let Some((w, expect)) = view::apply(&v, m) else {
                continue;
            };
            meets(&w, m, &expect)?;
        }
        Ok(())
    });
}

/// I-24: the rows of one chain read as the other chain fail at row 1,
/// since genesis binds the chain.
#[test]
fn i24_verify_refuses_rows_read_as_the_other_chain() {
    check("i24_verify_refuses_rows_read_as_the_other_chain", |g| {
        let chain = gen_chain(g);
        let mut v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
        v.chain = v.chain.other();
        prop_assert!(
            matches!(
                api::verify(&v),
                Err(AuditError::Tamper(Tamper::Changed { n: 1 }))
            ),
            "got {:?}",
            api::verify(&v)
        );
        Ok(())
    });
}

/// I-24: the rows of one cell read as another cell fail at row 1, since
/// genesis binds the cell.
#[test]
fn i24_verify_refuses_rows_read_as_another_cell() {
    check("i24_verify_refuses_rows_read_as_another_cell", |g| {
        let chain = gen_chain(g);
        let mut v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
        v.cell = OTHER_CELL;
        prop_assert!(
            matches!(
                api::verify(&v),
                Err(AuditError::Tamper(Tamper::Changed { n: 1 }))
            ),
            "got {:?}",
            api::verify(&v)
        );
        Ok(())
    });
}

/// I-24, ADR-010 "Verifier": rows with no anchor row and no witness
/// record are never `Ok`. A committed entry always holds its receipt.
#[test]
fn i24_verify_refuses_rows_without_any_receipt() {
    check("i24_verify_refuses_rows_without_any_receipt", |g| {
        let chain = gen_chain(g);
        let mut v = view::gen_view(g, CELL, chain, Sigs::Placeholder);
        v.anchors.clear();
        v.witness.clear();
        let got = api::verify(&v);
        prop_assert!(
            matches!(&got, Err(e) if !is_stub_or_gap(e)),
            "unreceipted rows got {got:?}"
        );
        Ok(())
    });
}
