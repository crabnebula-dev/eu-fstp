//! I-24: the audit log is tamper-evident. Any modification or deletion of
//! a past entry is detectable (design section 14.4, T-AUDIT, ADR-010).
//!
//! Lane W1e wrote these tests before the production code. They are red
//! until `fstp-audit` and `fstp-witness` (lane W2g), the store and its
//! migrations (lane W2e), the composite signature (lane dsa) and the
//! M-AUDIT tripwire count (lane W4) land. Each production test names the
//! seam or stub it waits for. Each `_on_the_reference` twin runs the same
//! check over the reference of `fstp_celltest::reference::audit` and the
//! aws-lc-rs oracles.
//!
//! Anchor signatures: until the moduletto ML-DSA-65 pull request lands,
//! these tests sign with the aws-lc-rs ML-DSA test oracle through
//! `fstp-celltest` (design section 14.4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{CellCommand, CellRecord, KeyCommand, KeyRecord};
use fstp_celltest::custody_sim::CustodySim;
use fstp_celltest::mc::audit_model::{
    AuditBackend, AuditDefect, AuditModel, AuditState, CELL, Mutant, PrepareAnswer, Production,
    Reference, build_with, ids, prod_cell_custody_round, prod_key_ops_of_chain, prod_reconcile,
    prod_store_batch, prod_usage_log, properties, specs,
};
use fstp_celltest::mc::auth_model::ProdCell;
use fstp_celltest::mc::tripwires::{M_AUDIT, NOT_MEASURED, tripwire};
use fstp_celltest::reference::audit::{
    self as r, AdmitRefusal, AnchorFields, CellBytes, Hash, Keys, LinkField, LinkInput, Mutation,
    RefChain, RefKeyOp, RefLedgerEntry, RefOp, RefPrepare, RefRowKind, RefSender, RefTamper,
    Resolution, RowSpec, SymChain, SymStore, SymWitnessRecord, WitnessRefusal,
};
use fstp_custody::{Custody as _, UsageCursor};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN, T0};
use fstp_domain_testkit::harness::teeth::{expect_prop_failure, expect_violation};
use fstp_mc::{Config, Verdict, check, explore};
use fstp_prop::Gen;
use fstp_rt::future::block_on;

// ---------------------------------------------------------------------------
// Helpers.

/// Panics with the operation a stub refused.
fn stub<T>(e: fstp_celltest::NotImplemented) -> T {
    panic!("{} is NotImplemented", e.operation)
}

fn keys() -> Keys {
    Keys::new().unwrap_or_else(|e| panic!("test keys: {e}"))
}

fn bound() -> Config {
    assert_ne!(
        M_AUDIT, NOT_MEASURED,
        "the M-AUDIT tripwire is not recorded yet (lane W4); \
         i24_m_audit_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_AUDIT))
}

fn model<B: AuditBackend>(backend: B) -> AuditModel<B> {
    AuditModel::new(backend).unwrap_or_else(|e| panic!("M-AUDIT keys: {e}"))
}

fn outcome_of<B: AuditBackend>(
    m: &AuditModel<B>,
) -> fstp_mc::Outcome<AuditState, fstp_celltest::mc::audit_model::AuditAction> {
    let props = properties(m);
    check(m, &props, &bound())
}

fn passes<B: AuditBackend>(backend: B) {
    let m = model(backend);
    let outcome = outcome_of(&m);
    assert!(
        outcome.exhaustive,
        "M-AUDIT did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

/// The run must answer every backend call, then violate `id`.
fn caught<B: AuditBackend>(backend: B, id: &str) {
    let m = model(backend);
    let outcome = outcome_of(&m);
    if let Some(Verdict::Violated(v)) = outcome.verdict(ids::BACKEND_ANSWERS) {
        panic!("the backend did not answer: {v:?}");
    }
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn ledger_spec(at: i64, k: u8, body: &[u8]) -> RowSpec {
    RowSpec::Ledger {
        at,
        command: [k; 16],
        schema: 1,
        key_ix: u32::from(k),
        body: body.to_vec(),
    }
}

fn event_spec(at: i64, body: &[u8]) -> RowSpec {
    RowSpec::Event {
        at,
        body: body.to_vec(),
    }
}

/// A random spec of either kind.
fn gen_spec(g: &mut Gen, at: i64) -> RowSpec {
    if g.bool() {
        RowSpec::Ledger {
            at,
            command: g.u8().to_be_bytes().repeat(16).try_into().unwrap(),
            schema: g.u16_in(1..=3),
            key_ix: g.u32_in(0..=3),
            body: g.bytes(0..=12),
        }
    } else {
        RowSpec::Event {
            at,
            body: g.bytes(0..=12),
        }
    }
}

/// A random honest chain of `chain`: one to three committed batches of
/// one or two rows. Before a batch, an aborted attempt or an in-doubt
/// attempt whose row was missing. Maybe a trailing aborted attempt.
fn gen_chain(g: &mut Gen, chain: RefChain) -> SymChain {
    let cell: CellBytes = g.bytes(16..=16).try_into().unwrap();
    let mut s = SymChain::genesis(cell, chain);
    let batches = g.usize_in(1..=3);
    let mut at = g.i64_in(0..=1_000_000);
    for _ in 0..batches {
        at += 10;
        let rows = g.usize_in(1..=2);
        let specs: Vec<RowSpec> = (0..rows).map(|i| gen_spec(g, at + i as i64)).collect();
        match g.u8_in(0..=2) {
            1 => {
                let mut other = specs.clone();
                other.push(event_spec(at, b"aborted"));
                s.aborted(&other, at).unwrap();
            }
            2 => {
                let a = s.attempt(&[event_spec(at, b"in doubt")], at).unwrap();
                s.prepare(&a, at).unwrap();
                s.in_doubt_absent(&a).unwrap();
            }
            _ => {}
        }
        s.append(&specs, at + 5).unwrap();
    }
    if g.bool() {
        s.aborted(&[event_spec(at + 20, b"trailing")], at + 20)
            .unwrap();
    }
    s
}

/// One mutation that applies to `s`, and its result.
fn gen_mutation(g: &mut Gen, s: &SymChain) -> (Mutation, SymChain) {
    let st = &s.store;
    let applicable: Vec<(Mutation, SymChain)> = r::mutations(
        st.rows.len(),
        st.ledger.len(),
        st.anchors.len(),
        s.wal.len(),
    )
    .into_iter()
    .filter_map(|m| r::apply(s, m).map(|t| (m, t)))
    .collect();
    g.pick(&applicable).clone()
}

/// The predicate of `i24_verifier_flags_every_mutation`: an honest chain
/// verifies, and the chain after one attacker mutation does not.
fn flags_every_mutation<B: AuditBackend>(b: &B, keys: &Keys, g: &mut Gen) -> Result<(), String> {
    let chain = *g.pick(&RefChain::ALL);
    let s = gen_chain(g, chain);
    let honest = keys.materialize(&s).map_err(|e| e.to_string())?;
    match b.verify(&honest, keys) {
        Err(e) => return Err(format!("{} is NotImplemented", e.operation)),
        Ok(Err(t)) => return Err(format!("two-way: an untouched chain was refused: {t}")),
        Ok(Ok(())) => {}
    }
    let (m, t) = gen_mutation(g, &s);
    g.note("mutation", &m);
    let view = keys.materialize(&t).map_err(|e| e.to_string())?;
    match b.verify(&view, keys) {
        Err(e) => Err(format!("{} is NotImplemented", e.operation)),
        Ok(Ok(())) => Err(format!(
            "I-24: {m:?} on the {chain:?} chain went undetected"
        )),
        Ok(Err(_)) => Ok(()),
    }
}

/// A random link input of either kind.
fn gen_link_input(g: &mut Gen) -> LinkInput {
    let kind_is_ledger = g.bool();
    let seq = g.u64_in(1..=1_000);
    let entry = kind_is_ledger.then(|| RefLedgerEntry {
        seq,
        at: g.i64(),
        command: g.bytes(16..=16).try_into().unwrap(),
        schema: g.u16(),
        key_ix: g.u32(),
        body: g.bytes(0..=24),
    });
    LinkInput {
        cell: g.bytes(16..=16).try_into().unwrap(),
        chain: *g.pick(&RefChain::ALL),
        prev: g.bytes(32..=32).try_into().unwrap(),
        n: g.u64_in(1..=u64::MAX),
        at: g.i64(),
        kind: if kind_is_ledger {
            RefRowKind::Ledger { seq }
        } else {
            RefRowKind::Event {
                body: g.bytes(0..=24),
            }
        },
        entry,
    }
}

/// The link of `x` through `b`: its stored hash, then its link.
fn backend_link<B: AuditBackend>(b: &B, x: &LinkInput) -> Result<Hash, String> {
    let sh = b
        .stored_hash(x.at, &x.kind, x.entry.as_ref())
        .map_err(|e| format!("{} is NotImplemented", e.operation))?;
    b.link(&x.prev, x.cell, x.chain, x.n, x.at, &x.kind, &sh)
        .map_err(|e| format!("{} is NotImplemented", e.operation))
}

/// A chain of three committed batches, of both row kinds.
fn three_batches(chain: RefChain) -> SymChain {
    let mut s = SymChain::genesis([0x24; 16], chain);
    s.append(
        &[ledger_spec(100, 1, b"one"), event_spec(101, b"login")],
        102,
    )
    .unwrap();
    s.append(&[ledger_spec(110, 2, b"two")], 112).unwrap();
    s.append(
        &[event_spec(120, b"step-up"), ledger_spec(121, 3, b"three")],
        122,
    )
    .unwrap();
    s
}

fn answer<B: AuditBackend>(b: &B, keys: &Keys, s: &SymChain) -> Result<(), String> {
    let view = keys.materialize(s).unwrap();
    b.verify(&view, keys)
        .unwrap_or_else(|e| panic!("{} is NotImplemented", e.operation))
}

// ---------------------------------------------------------------------------
// The verifier.

/// I-24, design section 14.4: over random chains of both chains, one
/// change, deletion, insertion, reordering, truncation or consistent
/// recomputation at any row, ledger entry, anchor or receipt is flagged
/// by `fstp_audit::verify`. The untouched chain verifies.
///
/// Gap: the stub verifier takes no anchor key history and no witness log
/// (`VERIFY_SEAM`).
#[test]
fn i24_verifier_flags_every_mutation() {
    let keys = keys();
    fstp_prop::check("i24_verifier_flags_every_mutation", |g: &mut Gen| {
        flags_every_mutation(&Production, &keys, g)
    });
}

/// I-24: the same property over the reference verifier.
#[test]
fn i24_verifier_flags_every_mutation_on_the_reference() {
    let keys = keys();
    fstp_prop::check(
        "i24_verifier_flags_every_mutation_on_the_reference",
        |g: &mut Gen| flags_every_mutation(&Reference, &keys, g),
    );
}

/// I-24 teeth: a verifier that skips the comparison with the witness's
/// receipts misses a deletion, and the mutation property catches it.
#[test]
fn i24_teeth_verifier_without_receipt_check_is_caught() {
    let keys = keys();
    let defective = Mutant::new(Reference, AuditDefect::VerifierSkipsReceiptComparison);
    let outcome = fstp_prop::run(
        "i24_teeth_verifier_without_receipt_check_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| flags_every_mutation(&defective, &keys, g),
    );
    if let Err(e) = expect_prop_failure(&outcome, ids::I24) {
        panic!("{e}");
    }
}

// ---------------------------------------------------------------------------
// The link function.

/// I-24, ADR-010 "Link function": the production genesis and link equal
/// the reference's for random inputs, given the same stored hash.
#[test]
fn i24_link_matches_reference() {
    fstp_prop::check("i24_link_matches_reference", |g: &mut Gen| {
        let x = gen_link_input(g);
        let sh = x.stored_hash().ok_or("no row bytes")?;
        let ni = |e: fstp_celltest::NotImplemented| format!("{} is NotImplemented", e.operation);
        let genesis = Production.genesis(x.cell, x.chain).map_err(ni)?;
        fstp_prop::prop_assert_eq!(genesis, r::genesis(x.cell, x.chain), "genesis");
        let got = Production
            .link(&x.prev, x.cell, x.chain, x.n, x.at, &x.kind, &sh)
            .map_err(ni)?;
        fstp_prop::prop_assert_eq!(got, r::link(&x.prev, x.cell, x.chain, x.n, &sh), "link");
        Ok(())
    });
}

/// I-24, ADR-010 "Proposed byte layouts": the production stored hash of
/// a row equals the reference's, for both kinds.
///
/// Gap: `fstp-audit` exposes no stored-hash function (`STORED_HASH_SEAM`).
#[test]
fn i24_stored_hash_matches_reference() {
    fstp_prop::check("i24_stored_hash_matches_reference", |g: &mut Gen| {
        let x = gen_link_input(g);
        let got = Production
            .stored_hash(x.at, &x.kind, x.entry.as_ref())
            .map_err(|e| format!("{} is NotImplemented", e.operation))?;
        fstp_prop::prop_assert_eq!(Some(got), x.stored_hash(), "stored hash");
        Ok(())
    });
}

/// I-24, ADR-010: the production link binds every column of the chain
/// row apart from `stored_hash` and `link`, every column of the ledger
/// entry, the cell, the chain, `n` and the previous link.
#[test]
fn i24_link_binds_every_field() {
    fstp_prop::check("i24_link_binds_every_field", |g: &mut Gen| {
        let x = gen_link_input(g);
        r::binds_every_field(&x, &|y| backend_link(&Production, y))
    });
}

/// I-24: the same property over the reference link.
#[test]
fn i24_link_binds_every_field_on_the_reference() {
    fstp_prop::check(
        "i24_link_binds_every_field_on_the_reference",
        |g: &mut Gen| {
            let x = gen_link_input(g);
            r::binds_every_field(&x, &|y| backend_link(&Reference, y))
        },
    );
}

/// I-24 teeth, ADR-010: a link that omits any one field is caught by the
/// binding predicate. Every field of `LinkField::ALL` has its twin.
#[test]
fn i24_teeth_link_omitting_a_field_is_caught() {
    let ledger = LinkInput {
        cell: [0x24; 16],
        chain: RefChain::App,
        prev: [0x42; 32],
        n: 7,
        at: 1_000,
        kind: RefRowKind::Ledger { seq: 3 },
        entry: Some(RefLedgerEntry {
            seq: 3,
            at: 999,
            command: [9; 16],
            schema: 2,
            key_ix: 1,
            body: b"sealed".to_vec(),
        }),
    };
    let event = LinkInput {
        kind: RefRowKind::Event {
            body: b"event".to_vec(),
        },
        entry: None,
        ..ledger.clone()
    };
    for input in [&ledger, &event] {
        r::binds_every_field(input, &|y| y.link().ok_or_else(|| "no link".to_owned()))
            .unwrap_or_else(|e| panic!("the reference itself: {e}"));
    }
    for field in LinkField::ALL {
        let input = if ledger.pair(field).is_some() {
            &ledger
        } else {
            &event
        };
        let twin = |y: &LinkInput| {
            y.link_omitting(Some(field))
                .ok_or_else(|| "no link".to_owned())
        };
        let found = r::binds_every_field(input, &twin);
        let named = format!("does not bind {field:?}:");
        assert!(
            found.as_ref().is_err_and(|e| e.contains(&named)),
            "the twin omitting {field:?} went undetected: {found:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// M-AUDIT.

/// I-24, M-AUDIT over production: `fstp_audit` and `fstp_witness`.
#[test]
fn i24_m_audit() {
    passes(Production);
}

/// I-24, M-AUDIT over the reference: every property and witness holds.
#[test]
fn i24_m_audit_on_the_reference() {
    passes(Reference);
}

/// I-24, design section 14.1: the recorded tripwire count is the measured
/// state count of M-AUDIT over the reference.
#[test]
fn i24_m_audit_tripwire_records_the_measured_count() {
    let space = explore(&model(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-AUDIT over the reference did not finish"
    );
    assert_eq!(
        M_AUDIT,
        space.len(),
        "record the measured M-AUDIT count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-24 teeth, M-AUDIT: a verifier that skips the receipt comparison is
/// caught over production.
#[test]
fn i24_teeth_m_audit_verifier_skips_receipt_comparison_is_caught() {
    caught(
        Mutant::new(Production, AuditDefect::VerifierSkipsReceiptComparison),
        ids::I24,
    );
}

/// I-24 teeth: the same defect is caught on the reference.
#[test]
fn i24_teeth_m_audit_verifier_skips_receipt_comparison_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuditDefect::VerifierSkipsReceiptComparison),
        ids::I24,
    );
}

/// I-24 teeth, M-AUDIT: a verifier that accepts an abort for a present
/// row misses an aborted attempt put back from the WAL.
#[test]
fn i24_teeth_m_audit_abort_accepted_for_present_row_is_caught() {
    caught(
        Mutant::new(Production, AuditDefect::AbortAcceptedForPresentRow),
        ids::I24,
    );
}

/// I-24 teeth: the same defect is caught on the reference.
#[test]
fn i24_teeth_m_audit_abort_accepted_for_present_row_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuditDefect::AbortAcceptedForPresentRow),
        ids::I24,
    );
}

/// I-24 teeth, M-AUDIT: an anchorer that commits before the receipt
/// breaks `no-unwitnessed-commit`.
#[test]
fn i24_teeth_m_audit_commit_before_receipt_is_caught() {
    caught(
        Mutant::new(Production, AuditDefect::CommitBeforeReceipt),
        ids::NO_UNWITNESSED_COMMIT,
    );
}

/// I-24 teeth: the same defect is caught on the reference.
#[test]
fn i24_teeth_m_audit_commit_before_receipt_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuditDefect::CommitBeforeReceipt),
        ids::NO_UNWITNESSED_COMMIT,
    );
}

/// I-24 teeth, M-AUDIT, ADR-010 "Abort": an anchorer that treats a known
/// commit failure as an unknown outcome raises `PossibleDeletion` where
/// it should abort. Production anchorer core.
#[test]
fn i24_teeth_m_audit_failed_commit_treated_as_in_doubt_is_caught() {
    caught(
        Mutant::new(Production, AuditDefect::FailedCommitTreatedAsInDoubt),
        ids::ALERT_ONLY_AFTER_UNKNOWN_OUTCOME,
    );
}

/// I-24 teeth: the same defect is caught on the reference.
#[test]
fn i24_teeth_m_audit_failed_commit_treated_as_in_doubt_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuditDefect::FailedCommitTreatedAsInDoubt),
        ids::ALERT_ONLY_AFTER_UNKNOWN_OUTCOME,
    );
}

/// I-24 teeth, M-AUDIT, ADR-010 "Witness unavailable": a cell that also
/// refuses reads while the witness is down is caught. Production
/// admission.
#[test]
fn i24_teeth_m_audit_reads_refused_while_witness_down_is_caught() {
    caught(
        Mutant::new(Production, AuditDefect::ReadsRefusedWhileWitnessDown),
        ids::WITNESS_DOWN_ADMISSION,
    );
}

/// I-24 teeth: the same defect is caught on the reference.
#[test]
fn i24_teeth_m_audit_reads_refused_while_witness_down_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuditDefect::ReadsRefusedWhileWitnessDown),
        ids::WITNESS_DOWN_ADMISSION,
    );
}

/// The admission rule: reads are always served, writes only while the
/// witness is up, and a refused write names the witness.
fn admission<B: AuditBackend>(b: &B) {
    for witness_up in [true, false] {
        for op in RefOp::ALL {
            let want = if op == RefOp::Write && !witness_up {
                Err(AdmitRefusal::WitnessUnavailable)
            } else {
                Ok(())
            };
            assert_eq!(
                b.admit(op, witness_up).unwrap_or_else(stub),
                want,
                "{op:?} with the witness up={witness_up}"
            );
        }
    }
}

/// I-24, ADR-010 "Witness unavailable": without a reachable witness the
/// cell refuses writes, naming the witness, and keeps serving reads.
/// Production admission.
#[test]
fn i24_witness_unavailable_refuses_writes_and_serves_reads() {
    admission(&Production);
}

/// I-24: the same rule over the reference admission.
#[test]
fn i24_witness_unavailable_refuses_writes_and_serves_reads_on_the_reference() {
    admission(&Reference);
}

// ---------------------------------------------------------------------------
// The tail D protocol.

/// The run of `i24_no_commit_without_a_receipt_for_its_link`: M-AUDIT's
/// faults at every step of design section 5.3 (refused and lost
/// prepares, failures before COMMIT, COMMIT errors, unknown outcomes and
/// crashes), checked for `no-unwitnessed-commit` alone.
fn no_commit_without_receipt<B: AuditBackend>(backend: B) {
    let m = model(backend);
    let all = properties(&m);
    let props: Vec<_> = all
        .into_iter()
        .filter(|p| [ids::BACKEND_ANSWERS, ids::NO_UNWITNESSED_COMMIT].contains(&p.id()))
        .collect();
    let outcome = check(&m, &props, &bound());
    assert!(outcome.exhaustive, "{outcome}");
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

/// I-24, design section 7.2: no append commits before the witness has
/// receipted its link, under crash and fault injection at every step of
/// the append. Production anchorer core.
///
/// Gap: the crash injection after every SQL statement over a real store
/// waits for lane W2e (`i24_ledger_and_chain_commit_together`).
#[test]
fn i24_no_commit_without_a_receipt_for_its_link() {
    no_commit_without_receipt(Production);
}

/// I-24: the same run over the reference anchorer.
#[test]
fn i24_no_commit_without_a_receipt_for_its_link_on_the_reference() {
    no_commit_without_receipt(Reference);
}

/// The witness core's abort rule. A second prepare of the same `n` with
/// another link is refused until the first is aborted, and an abort names
/// only the outstanding prepare. The aborted link itself is never
/// prepared again, and the retry with another link then succeeds.
fn abort_before_reprepare<B: AuditBackend>(b: &B) {
    let chain = RefChain::App;
    let cw = RefSender::writer(CELL, chain);
    let st = r::RefWitnessState::genesis(CELL, chain);
    let head = (
        0,
        b.genesis(CELL, chain)
            .unwrap_or_else(|e| panic!("{}", e.operation)),
    );
    let build = |k: u8| {
        build_with(b, CELL, chain, head, 1, &specs(k), 10)
            .unwrap_or_else(|e| panic!("{} is NotImplemented", e.operation))
            .unwrap()
    };
    let (first, second) = (build(0), build(1));
    assert_eq!(first.anchor.n, second.anchor.n);
    assert_ne!(first.anchor.link, second.anchor.link);
    let prepare = |st: &r::RefWitnessState, a: &r::Attempt| {
        b.witness_prepare(st, CELL, chain, cw, &a.prepare(), 10)
            .unwrap_or_else(|e| panic!("{} is NotImplemented", e.operation))
    };
    let (st, _receipt) = prepare(&st, &first).unwrap_or_else(|e| panic!("first prepare: {e:?}"));
    assert_eq!(
        prepare(&st, &second).map(|_| ()),
        Err(WitnessRefusal::Outstanding),
        "a second prepare of the same n before the abort"
    );
    let wrong = b
        .witness_abort(&st, CELL, chain, cw, second.anchor.n, &second.anchor.link)
        .unwrap_or_else(stub);
    assert_eq!(wrong.map(|_| ()), Err(WitnessRefusal::UnknownPrepare));
    let st = b
        .witness_abort(&st, CELL, chain, cw, first.anchor.n, &first.anchor.link)
        .unwrap_or_else(stub)
        .unwrap_or_else(|e| panic!("abort of the outstanding prepare: {e:?}"));
    assert_eq!(
        prepare(&st, &first).map(|_| ()),
        Err(WitnessRefusal::Withdrawn),
        "the aborted link prepared again"
    );
    let (st, _receipt) = prepare(&st, &second).unwrap_or_else(|e| panic!("the retry: {e:?}"));
    // The same rule after an in-doubt record: its link never comes back.
    let st = b
        .witness_in_doubt_absent(&st, CELL, chain, cw, second.anchor.n, &second.anchor.link)
        .unwrap_or_else(stub)
        .unwrap_or_else(|e| panic!("in-doubt record of the retry: {e:?}"));
    assert_eq!(
        prepare(&st, &second).map(|_| ()),
        Err(WitnessRefusal::Withdrawn),
        "the in-doubt link prepared again"
    );
    assert_eq!(
        prepare(&st, &first).map(|_| ()),
        Err(WitnessRefusal::Withdrawn),
        "the aborted link prepared again after another withdrawal"
    );
}

/// I-24, design section 7.2: the abort is recorded before the same `n`
/// is prepared again. Production witness core.
#[test]
fn i24_abort_recorded_before_the_same_n_is_prepared_again() {
    abort_before_reprepare(&Production);
}

/// I-24: the same rule over the reference witness core.
#[test]
fn i24_abort_recorded_before_the_same_n_is_prepared_again_on_the_reference() {
    abort_before_reprepare(&Reference);
}

/// The witness core's extension rule (ADR-010 "One outstanding prepare
/// per chain", reading of open point 3). With nothing outstanding, a
/// prepare must extend the confirmed head. The witness recomputes the
/// link from the stored hashes, and a prepare needs at least one.
fn prepare_extends<B: AuditBackend>(b: &B) -> Result<(), String> {
    for chain in RefChain::ALL {
        let w = RefSender::writer(CELL, chain);
        let genesis = (0, b.genesis(CELL, chain).unwrap_or_else(stub));
        let build = |head: (u64, Hash), seq: u64, k: u8| {
            build_with(b, CELL, chain, head, seq, &specs(k), 10)
                .unwrap_or_else(stub)
                .unwrap()
        };
        let prepare = |st: &r::RefWitnessState, p: &RefPrepare| -> PrepareAnswer {
            b.witness_prepare(st, CELL, chain, w, p, 10)
                .unwrap_or_else(stub)
        };
        let refused = |what: &str, got: PrepareAnswer, want: WitnessRefusal| match got {
            Err(e) if e == want => Ok(()),
            Ok(_) => Err(format!("{what} on the {chain:?} chain: accepted")),
            Err(e) => Err(format!(
                "{what} on the {chain:?} chain: refused as {e:?}, not {want:?}"
            )),
        };
        let st = r::RefWitnessState::genesis(CELL, chain);
        let first = build(genesis, 1, 0);
        let (st, _) = prepare(&st, &first.prepare())
            .map_err(|e| format!("the first {chain:?} prepare: {e:?}"))?;
        let confirmed = (first.anchor.n, first.anchor.link);
        let second = build(confirmed, 3, 1);
        let (st, _) = prepare(&st, &second.prepare())
            .map_err(|e| format!("the second {chain:?} prepare: {e:?}"))?;
        let st = b
            .witness_abort(&st, CELL, chain, w, second.anchor.n, &second.anchor.link)
            .unwrap_or_else(stub)
            .map_err(|e| format!("the abort of the second {chain:?} prepare: {e:?}"))?;
        // Nothing is outstanding now, and the first prepare is confirmed.
        let stale = build(genesis, 1, 2);
        refused(
            "a prepare over the stale head before the confirmed one",
            prepare(&st, &stale.prepare()),
            WitnessRefusal::NotExtending,
        )?;
        let third = build(confirmed, 3, 2);
        let mut changed = third.prepare();
        changed.stored_hashes[1][0] ^= 0x01;
        refused(
            "a prepare with one stored hash changed",
            prepare(&st, &changed),
            WitnessRefusal::LinkMismatch,
        )?;
        let empty = RefPrepare {
            prev: confirmed,
            stored_hashes: Vec::new(),
            anchor: AnchorFields {
                n: confirmed.0,
                link: confirmed.1,
                at: 10,
            },
        };
        refused(
            "a prepare with no stored hashes",
            prepare(&st, &empty),
            WitnessRefusal::LinkMismatch,
        )?;
        prepare(&st, &third.prepare())
            .map_err(|e| format!("the honest third {chain:?} prepare: {e:?}"))?;
    }
    Ok(())
}

/// I-24, ADR-010 "One outstanding prepare per chain": the witness refuses
/// a prepare over a stale head as `NotExtending`. It refuses one whose
/// stored hashes do not recompute to its link, or that has none, as
/// `LinkMismatch`. Production witness core.
#[test]
fn i24_witness_refuses_a_prepare_that_does_not_extend() {
    prepare_extends(&Production).unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24: the same rule over the reference witness core.
#[test]
fn i24_witness_refuses_a_prepare_that_does_not_extend_on_the_reference() {
    prepare_extends(&Reference).unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24 teeth: a witness that takes a prepare's `prev` on trust once
/// nothing is outstanding is caught.
#[test]
fn i24_teeth_witness_prepare_over_a_stale_head_is_caught() {
    let found = prepare_extends(&Mutant::new(
        Reference,
        AuditDefect::PrepareOverAnyConfirmedHead,
    ));
    assert!(
        found
            .as_ref()
            .is_err_and(|e| e.contains("stale head") && e.contains("accepted")),
        "the defect went undetected: {found:?}"
    );
}

/// I-24 teeth: a witness that receipts the anchor's link without
/// recomputing it from the stored hashes is caught.
#[test]
fn i24_teeth_witness_receipts_a_link_its_rows_do_not_recompute_is_caught() {
    let found = prepare_extends(&Mutant::new(Reference, AuditDefect::LinkNotRecomputed));
    assert!(
        found
            .as_ref()
            .is_err_and(|e| e.contains("one stored hash changed") && e.contains("accepted")),
        "the defect went undetected: {found:?}"
    );
}

/// I-24 teeth: a witness that receipts a prepare with no stored hashes
/// is caught.
#[test]
fn i24_teeth_witness_receipts_an_empty_prepare_is_caught() {
    let found = prepare_extends(&Mutant::new(Reference, AuditDefect::EmptyPrepareReceipted));
    assert!(
        found
            .as_ref()
            .is_err_and(|e| e.contains("no stored hashes") && e.contains("accepted")),
        "the defect went undetected: {found:?}"
    );
}

/// The in-doubt rule: a missing row raises `PossibleDeletion` and sends
/// `InDoubtAbsent`, a present row resolves as committed, and the
/// verifier needs the in-doubt record to accept the missing row.
fn in_doubt<B: AuditBackend>(b: &B) {
    let keys = keys();
    let mut s = three_batches(RefChain::App);
    let at = 130;
    let a = s.attempt(&[event_spec(at, b"in doubt")], at).unwrap();
    s.prepare(&a, at).unwrap();
    let l = a.anchor.link;
    assert_eq!(
        b.resolve(Some(l), &l).unwrap_or_else(stub),
        Resolution::Committed
    );
    for seen in [None, Some([0x77; 32])] {
        assert_eq!(
            b.resolve(seen, &l).unwrap_or_else(stub),
            Resolution::AbsentRaisePossibleDeletion,
            "row {} reads {seen:?}",
            a.anchor.n
        );
    }
    let wrong = b
        .witness_in_doubt_absent(
            &s.witness_state,
            s.cell,
            s.chain,
            s.sender(),
            a.anchor.n,
            &[0x77; 32],
        )
        .unwrap_or_else(stub);
    assert_eq!(wrong.map(|_| ()), Err(WitnessRefusal::UnknownPrepare));
    assert!(
        answer(b, &keys, &s).is_err(),
        "a receipted link with no row and no in-doubt record verified"
    );
    let st = b
        .witness_in_doubt_absent(
            &s.witness_state,
            s.cell,
            s.chain,
            s.sender(),
            a.anchor.n,
            &l,
        )
        .unwrap_or_else(stub)
        .unwrap_or_else(|e| panic!("in-doubt record refused: {e:?}"));
    s.witness_state = st;
    s.witness.push(SymWitnessRecord::InDoubtAbsent {
        n: a.anchor.n,
        link: l,
    });
    assert_eq!(
        answer(b, &keys, &s),
        Ok(()),
        "the in-doubt record covers the missing row"
    );
}

/// I-24, design section 7.2: an in-doubt prepare whose row is missing
/// raises `PossibleDeletion`. Production anchorer and witness.
#[test]
fn i24_in_doubt_missing_row_raises_possible_deletion() {
    in_doubt(&Production);
}

/// I-24: the same rule over the reference.
#[test]
fn i24_in_doubt_missing_row_raises_possible_deletion_on_the_reference() {
    in_doubt(&Reference);
}

/// The tail rule: every truncation of the last rows after their commit,
/// with or without their anchor rows, is detected, for both chains.
fn tail_deletion<B: AuditBackend>(b: &B) {
    let keys = keys();
    for chain in RefChain::ALL {
        let s = three_batches(chain);
        assert_eq!(
            answer(b, &keys, &s),
            Ok(()),
            "the untouched {chain:?} chain"
        );
        for k in 1..=s.store.rows.len() {
            for m in [Mutation::Truncate(k), Mutation::TruncateWithAnchors(k)] {
                let t = r::apply(&s, m).unwrap();
                assert!(
                    answer(b, &keys, &t).is_err(),
                    "{m:?} on the {chain:?} chain went undetected"
                );
            }
        }
    }
}

/// I-24, design section 14.4: deleting the tail after its commit is
/// detected, for both chains. Production verifier.
#[test]
fn i24_tail_deletion_after_commit_is_detected() {
    tail_deletion(&Production);
}

/// I-24: the same check over the reference verifier.
#[test]
fn i24_tail_deletion_after_commit_is_detected_on_the_reference() {
    tail_deletion(&Reference);
}

/// Another cell, whose certificates the witness also pins.
const OTHER_CELL: CellBytes = [0xC2; 16];

/// Whose certificate `sender` is, seen from `CELL`.
fn whose(sender: RefSender) -> &'static str {
    match sender {
        RefSender::CellWitness { cell } | RefSender::VaultWitness { cell } if cell == CELL => {
            "this cell's"
        }
        RefSender::CellWitness { .. } | RefSender::VaultWitness { .. } => "another cell's",
        RefSender::ControlPlane => "the control plane's",
    }
}

/// The sender rule, both directions and for every message: the witness
/// takes App chain prepares, aborts and in-doubt records from the cell's
/// own `cell-witness` certificate only. It takes Vault chain ones from
/// the same cell's `vault-witness` certificate only. It takes none from
/// another cell's certificates or from the control plane. A refused
/// withdrawal leaves the prepare outstanding.
fn vault_only<B: AuditBackend>(b: &B) -> Result<(), String> {
    for chain in RefChain::ALL {
        let st = r::RefWitnessState::genesis(CELL, chain);
        let head = (0, r::genesis(CELL, chain));
        let a = r::build_attempt(CELL, chain, head, 1, &specs(0), 10).unwrap();
        let own = SymChain::genesis(CELL, chain).sender();
        if own != RefSender::writer(CELL, chain) {
            return Err(format!("the {chain:?} chain's writer sends as {own:?}"));
        }
        let (prepared, _receipt) = b
            .witness_prepare(&st, CELL, chain, own, &a.prepare(), 10)
            .unwrap_or_else(stub)
            .map_err(|e| format!("the {chain:?} chain's own prepare: {e:?}"))?;
        let (n, l) = (a.anchor.n, a.anchor.link);
        for sender in RefSender::all(CELL, OTHER_CELL) {
            let want = sender == own;
            let from = whose(sender);
            let accepts = b.accepts_sender(sender, CELL, chain).unwrap_or_else(stub);
            if accepts != want {
                return Err(format!(
                    "accepts_sender for the {chain:?} chain from {from} {sender:?}: \
                     accepted={accepts}"
                ));
            }
            let got = b
                .witness_prepare(&st, CELL, chain, sender, &a.prepare(), 10)
                .unwrap_or_else(stub);
            let answers = [
                ("a prepare", got.map(|_| ())),
                (
                    "an abort",
                    b.witness_abort(&prepared, CELL, chain, sender, n, &l)
                        .unwrap_or_else(stub)
                        .map(|_| ()),
                ),
                (
                    "an in-doubt record",
                    b.witness_in_doubt_absent(&prepared, CELL, chain, sender, n, &l)
                        .unwrap_or_else(stub)
                        .map(|_| ()),
                ),
            ];
            for (what, answer) in answers {
                let ok = match answer {
                    Ok(()) => true,
                    Err(WitnessRefusal::WrongSender) => false,
                    Err(other) => {
                        return Err(format!(
                            "{what} of the {chain:?} chain from {from} {sender:?} refused as \
                             {other:?}"
                        ));
                    }
                };
                if ok != want {
                    return Err(format!(
                        "{what} of the {chain:?} chain from {from} {sender:?}: accepted={ok}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// I-24, ADR-010, ADR-009: the vault chain is anchored by the vault only,
/// and the cell's chain by the cell only, for prepares, aborts and
/// in-doubt records. Another cell's certificates write neither. Production
/// witness core.
#[test]
fn i24_vault_chain_anchored_by_the_vault_only() {
    vault_only(&Production).unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24: the same rule over the reference witness core.
#[test]
fn i24_vault_chain_anchored_by_the_vault_only_on_the_reference() {
    vault_only(&Reference).unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24 teeth, ADR-010 "Witnesses": a witness that takes an abort or an
/// in-doubt record from any certificate is caught by the sender rule.
#[test]
fn i24_teeth_witness_takes_withdrawal_from_any_sender_is_caught() {
    let defective = Mutant::new(Reference, AuditDefect::WithdrawalFromAnySender);
    let found = vault_only(&defective);
    assert!(
        found.as_ref().is_err_and(|e| e.contains("accepted=true")),
        "the defect went undetected: {found:?}"
    );
}

/// I-24 teeth, ADR-009 and ADR-010 "Witnesses": a witness that checks a
/// certificate's role but not the cell that issued it is caught. Another
/// cell's certificate would otherwise withdraw this cell's committed head
/// and hide its deletion.
#[test]
fn i24_teeth_witness_ignores_the_sender_cell_is_caught() {
    let defective = Mutant::new(Reference, AuditDefect::SenderCellIgnored);
    let found = vault_only(&defective);
    assert!(
        found
            .as_ref()
            .is_err_and(|e| e.contains("another cell's") && e.contains("accepted=true")),
        "the defect went undetected: {found:?}"
    );
}

/// The key rule: a chain's anchors verify only under that chain's own
/// anchor key, so the other process's key cannot anchor it.
fn other_key_refused<B: AuditBackend>(b: &B) {
    let keys = keys();
    for chain in RefChain::ALL {
        let s = three_batches(chain);
        let own = keys.materialize(&s).unwrap();
        assert_eq!(
            b.verify(&own, &keys).unwrap_or_else(stub),
            Ok(()),
            "{chain:?} own key"
        );
        let other = keys.materialize_signed_by(&s, chain.other()).unwrap();
        assert!(
            b.verify(&other, &keys).unwrap_or_else(stub).is_err(),
            "the {chain:?} chain verified under the {:?} anchor key",
            chain.other()
        );
    }
}

/// I-24, ADR-010: an anchor of either chain signed with the other
/// chain's anchor key is refused. Production verifier.
#[test]
fn i24_vault_chain_anchor_under_the_cell_key_is_refused() {
    other_key_refused(&Production);
}

/// I-24: the same rule over the reference verifier.
#[test]
fn i24_vault_chain_anchor_under_the_cell_key_is_refused_on_the_reference() {
    other_key_refused(&Reference);
}

// ---------------------------------------------------------------------------
// The erasure log and custody.

/// I-24, ADR-007, design section 7.3: an erasure request and a destroyed
/// key epoch are ledger records, and each sits in the chain.
///
/// Gaps: the stubs name `TextsErased` only, not `TextErasureRequested`,
/// `TextErased` and `DocumentErased`. `fstp-pgstore` exposes no append
/// that writes chain rows (`STORE_SEAM`).
#[test]
fn i24_erasure_entries_are_chained() {
    let mut cell = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    let text = [0x7E; 16];
    let t = |s: i64| Timestamp::from_micros(T0.micros() + s);
    cell.exec(
        CellCommand::Text(TextCommand::PutText { id: text }),
        ADMIN,
        t(1),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let mut batch = cell
        .exec(
            CellCommand::Text(TextCommand::EraseTexts {
                ids: vec![text],
                cause: 1,
            }),
            ADMIN,
            t(2),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    batch.extend(
        cell.exec(
            CellCommand::Key(KeyCommand::RecordEpochDestroyed {
                epoch: 1,
                receipt: [0xD5; 32],
            }),
            ADMIN,
            t(3),
        )
        .unwrap_or_else(|e| panic!("{e}")),
    );
    let erasures: Vec<&CellRecord> = batch
        .iter()
        .filter(|rec| {
            matches!(
                rec,
                CellRecord::Text(TextRecord::TextsErased { .. })
                    | CellRecord::Key(KeyRecord::EpochDestroyed { .. })
            )
        })
        .collect();
    assert_eq!(erasures.len(), 2, "the erasure records: {batch:?}");
    let stored = prod_store_batch(&batch).unwrap_or_else(|e| panic!("{}", e.operation));
    assert_eq!(stored.seqs.len(), batch.len(), "one ledger seq per record");
    let s = &stored.chain;
    let keys = keys();
    assert_eq!(answer(&Production, &keys, s), Ok(()), "the stored batch");
    let named: BTreeSet<u64> = s
        .store
        .rows
        .iter()
        .filter_map(|row| match row.kind {
            RefRowKind::Ledger { seq } => Some(seq),
            RefRowKind::Event { .. } => None,
        })
        .collect();
    assert_eq!(named.len(), batch.len(), "one kind 1 row per ledger record");
    let mut checked = 0;
    for (rec, seq) in batch.iter().zip(&stored.seqs) {
        if !erasures.contains(&rec) {
            continue;
        }
        let row = s
            .store
            .rows
            .iter()
            .position(|row| row.kind == RefRowKind::Ledger { seq: *seq })
            .unwrap_or_else(|| panic!("no kind 1 row for {rec:?} (seq {seq})"));
        let entry = s
            .store
            .ledger
            .iter()
            .position(|e| e.seq == *seq)
            .unwrap_or_else(|| panic!("no ledger entry for {rec:?} (seq {seq})"));
        for m in [
            Mutation::DeleteRow(row),
            Mutation::DeleteEntry(entry),
            Mutation::EntryBody(entry),
        ] {
            let t = r::apply(s, m).unwrap();
            assert!(
                answer(&Production, &keys, &t).is_err(),
                "{m:?} of the erasure record {rec:?} verified"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, erasures.len(), "every erasure record was checked");
}

/// I-24: on the reference, the four erasure-log records of ADR-007 sit
/// in the chain. Deleting one's row, its entry or changing its body is
/// flagged.
#[test]
fn i24_erasure_entries_are_chained_on_the_reference() {
    let keys = keys();
    let mut s = SymChain::genesis([0xE5; 16], RefChain::App);
    let names: [&[u8]; 4] = [
        b"TextErasureRequested",
        b"TextErased",
        b"DocumentErased",
        b"KeyEpochDestroyed",
    ];
    for (k, name) in names.iter().enumerate() {
        let at = 200 + 10 * k as i64;
        s.append(&[ledger_spec(at, k as u8, name)], at + 1).unwrap();
    }
    assert_eq!(answer(&Reference, &keys, &s), Ok(()));
    for j in 0..names.len() {
        for (m, want) in [
            (Mutation::DeleteRow(j), "a deleted erasure row"),
            (Mutation::DeleteEntry(j), "a deleted erasure entry"),
            (Mutation::EntryBody(j), "a changed erasure entry"),
        ] {
            let t = r::apply(&s, m).unwrap();
            let view = keys.materialize(&t).unwrap();
            let got = r::verify(&view, &keys);
            assert!(got.is_err(), "{want} ({m:?}) verified");
        }
    }
    let t = r::apply(&s, Mutation::DeleteEntry(0)).unwrap();
    let view = keys.materialize(&t).unwrap();
    assert_eq!(
        r::verify(&view, &keys),
        Err(RefTamper::RowWithoutLedger { n: 1 })
    );
}

/// A reconciliation of a usage log with `KeyOp` events.
type Reconcile = dyn Fn(&[RefKeyOp], &[RefKeyOp]) -> Vec<RefKeyOp>;

/// The `KeyOp` records of a store, by some reader.
type KeyOpsOf<'a> = dyn Fn(&SymStore) -> Vec<RefKeyOp> + 'a;

/// The custody rule over one chain (ADR-004 "Reconciliation"). The
/// `KeyOp` records read from the chain's store reconcile with the backend
/// usage log. A record may be a kind 2 event row, or a kind 1 row with
/// its ledger entry. With one record deleted from the chain, exactly its
/// usage entry is reported, and the verifier flags the deletion.
fn custody_reconciles<B: AuditBackend>(
    b: &B,
    chain: &SymChain,
    usage: &[RefKeyOp],
    key_ops_of: &KeyOpsOf<'_>,
    reconcile: &Reconcile,
) -> Result<(), String> {
    if usage.is_empty() {
        return Err("the backend usage log is empty".to_owned());
    }
    let events = key_ops_of(&chain.store);
    let anomalies = reconcile(usage, &events);
    if !anomalies.is_empty() {
        return Err(format!(
            "usage entries without a KeyOp record in the chain: {anomalies:?}"
        ));
    }
    let keys = keys();
    let mut removed = 0;
    for (i, row) in chain.store.rows.iter().enumerate() {
        let entry = match row.kind {
            RefRowKind::Ledger { seq } => chain.store.ledger.iter().position(|e| e.seq == seq),
            RefRowKind::Event { .. } => None,
        };
        let alone = SymStore {
            rows: vec![row.clone()],
            ledger: entry
                .and_then(|j| chain.store.ledger.get(j))
                .cloned()
                .into_iter()
                .collect(),
            anchors: Vec::new(),
        };
        let own = key_ops_of(&alone);
        if own.is_empty() {
            continue;
        }
        let mut t = r::apply(chain, Mutation::DeleteRow(i)).ok_or("DeleteRow did not apply")?;
        if let Some(j) = entry {
            t = r::apply(&t, Mutation::DeleteEntry(j)).ok_or("DeleteEntry did not apply")?;
        }
        let missing = reconcile(usage, &key_ops_of(&t.store));
        if missing != own {
            return Err(format!(
                "row {} held {own:?}; with it deleted, reconciliation reported {missing:?}",
                row.n
            ));
        }
        if answer(b, &keys, &t).is_ok() {
            return Err(format!("the deleted KeyOp row {} verified", row.n));
        }
        removed += 1;
    }
    if removed == 0 {
        return Err("the chain holds no KeyOp record".to_owned());
    }
    Ok(())
}

/// I-24, ADR-004 "Reconciliation": the production cell makes its custody
/// calls through the simulator, each with a request id, and writes a
/// `KeyOp` record per call to its App chain. The simulator's usage log
/// reconciles with the records read from the chain's store.
///
/// Gaps: no cell keystore writes `KeyOp` records and no reader decodes
/// them (`KEY_OPS_SEAM`). Whether a record is an event or a ledger record
/// is open (see `prod_key_ops_of_chain`). The simulator's usage log
/// carries no request id, and no reconciliation task exists
/// (`RECONCILE_SEAM`).
#[test]
fn i24_custody_ops_reconcile_with_key_records() {
    let sim = CustodySim::for_cell(2);
    let round = prod_cell_custody_round(&sim).unwrap_or_else(|e| panic!("{}", e.operation));
    let mut usage = Vec::new();
    for root in &round.roots {
        let page = block_on(sim.usage_since(root, UsageCursor::default())).unwrap();
        usage.extend(prod_usage_log(&page).unwrap_or_else(|e| panic!("{}", e.operation)));
    }
    let key_ops_of = |store: &SymStore| {
        prod_key_ops_of_chain(&round, store).unwrap_or_else(|e| panic!("{}", e.operation))
    };
    let reconcile = |u: &[RefKeyOp], k: &[RefKeyOp]| {
        prod_reconcile(u, k).unwrap_or_else(|e| panic!("{}", e.operation))
    };
    custody_reconciles(&Production, &round.chain, &usage, &key_ops_of, &reconcile)
        .unwrap_or_else(|e| panic!("I-24: {e}"));
}

/// I-24, ADR-004: on the reference, custody calls with request ids and
/// their `KeyOp` events in the App chain reconcile. A deleted event row is
/// reported, and so is a chain with no `KeyOp` event at all. Each event
/// covers one usage entry, so a replayed call is reported too.
#[test]
fn i24_custody_ops_reconcile_with_key_records_on_the_reference() {
    let op = |id: u8, name: &str| RefKeyOp {
        request_id: [id; 16],
        op: name.as_bytes().to_vec(),
    };
    let usage = vec![
        op(1, "create"),
        op(2, "wrap"),
        op(3, "unwrap"),
        op(4, "destroy"),
    ];
    // The cell writes each KeyOp event before its call, among its other
    // records.
    let mut s = SymChain::genesis([0xC0; 16], RefChain::App);
    for (k, u) in usage.iter().enumerate() {
        let at = 300 + 10 * k as i64;
        s.append(
            &[
                event_spec(at, &r::key_op_event(u)),
                ledger_spec(at + 1, k as u8, b"keyed record"),
            ],
            at + 2,
        )
        .unwrap();
    }
    let key_ops_of = |store: &SymStore| r::key_ops_of_rows(&store.rows);
    let reconcile = |u: &[RefKeyOp], k: &[RefKeyOp]| r::reconcile(u, k);
    custody_reconciles(&Reference, &s, &usage, &key_ops_of, &reconcile)
        .unwrap_or_else(|e| panic!("I-24: {e}"));

    // A cell that writes no KeyOp event fails the same check.
    let mut silent = SymChain::genesis([0xC0; 16], RefChain::App);
    silent
        .append(&[ledger_spec(300, 1, b"keyed record")], 301)
        .unwrap();
    let found = custody_reconciles(&Reference, &silent, &usage, &key_ops_of, &reconcile);
    assert!(
        found
            .as_ref()
            .is_err_and(|e| e.contains("without a KeyOp record")),
        "a chain with no KeyOp event reconciled: {found:?}"
    );

    // Matching by request id and operation, one event per usage entry.
    let events = vec![
        op(1, "create"),
        op(3, "unwrap"),
        op(4, "destroy"),
        op(5, "wrap"),
    ];
    assert_eq!(r::reconcile(&usage, &events), vec![op(2, "wrap")]);
    let renamed = vec![
        op(1, "create"),
        op(2, "unwrap"),
        op(3, "unwrap"),
        op(4, "destroy"),
    ];
    assert_eq!(r::reconcile(&usage, &renamed), vec![op(2, "wrap")]);
    let mut replayed = usage.clone();
    replayed.push(op(3, "unwrap"));
    assert_eq!(r::reconcile(&replayed, &usage), vec![op(3, "unwrap")]);
}

// ---------------------------------------------------------------------------
// The database (lane W2e).

fn catalogue_lists(schema: &str, name: &str) {
    let found = fstp_pgstore::CATALOGUE
        .iter()
        .any(|t| t.schema == schema && t.name == name);
    assert!(
        found,
        "fstp_pgstore::CATALOGUE lists no {schema}.{name} (lane W2e)"
    );
}

/// I-24, ADR-010: the `audit.check_link` trigger, `fstp-audit` and the
/// reference compute the same stored hash and link bytes.
///
/// Gap: `fstp-pgstore` exposes no cell migrations, so no row can be
/// inserted through the trigger yet (lane W2e). The reference vectors
/// are checked against PostgreSQL's own `sha256()` by
/// `i24_reference_link_matches_postgres_sha256`.
#[test]
fn i24_pg_chain_equals_reference_chain() {
    catalogue_lists("audit", "chain");
    catalogue_lists("audit", "anchor");
    panic!(
        "fstp-pgstore exposes no cell migrations to insert chain rows through audit.check_link (lane W2e, W1e gap)"
    );
}

/// I-24, ADR-010 "Database link trigger": a wrong link is refused by the
/// trigger, the writer gets SQLSTATE 42501 on UPDATE, DELETE and
/// TRUNCATE, the owner gets the trigger's exception, and a superuser's
/// edit is then detected by the verifier.
///
/// Gap: as above, the migrations and roles wait for lane W2e.
#[test]
fn i24_database_refuses_bad_link_and_mutation() {
    catalogue_lists("audit", "chain");
    catalogue_lists("audit", "anchor");
    panic!(
        "fstp-pgstore exposes no cell migrations, writer role or owner role to test (lane W2e, W1e gap)"
    );
}

/// I-24, design section 5.3: the ledger entries and their chain rows
/// commit together, under a crash after every statement of the append.
///
/// Gap: `PgRecordStore` has no pool constructor and no append yet (lane
/// W2e).
#[test]
fn i24_ledger_and_chain_commit_together() {
    catalogue_lists("ledger", "entry");
    catalogue_lists("audit", "chain");
    panic!(
        "fstp-pgstore exposes no pool constructor or append to crash after each statement (lane W2e, W1e gap)"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytea(b: &[u8]) -> String {
    format!("'\\x{}'::bytea", hex(b))
}

/// I-24, ADR-010: the reference stored hash, link and genesis equal what
/// PostgreSQL computes with `sha256()`, `int2send()`, `int4send()` and
/// `int8send()`, the encodings the `audit.check_link` trigger uses. These
/// are the vectors lane W2e's trigger must reproduce.
#[test]
fn i24_reference_link_matches_postgres_sha256() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let s = three_batches(RefChain::Vault);
    let genesis = r::genesis(s.cell, s.chain);
    let sql_genesis = format!(
        "SELECT encode(sha256(convert_to('fstp-audit-genesis-v1', 'UTF8') || {} || '\\x02'::bytea), 'hex');",
        bytea(&s.cell)
    );
    assert_eq!(
        server.psql(&db.dbname, &sql_genesis).unwrap(),
        hex(&genesis)
    );
    let mut prev = genesis;
    for row in &s.store.rows {
        let payload = match &row.kind {
            RefRowKind::Ledger { seq } => {
                let e = s.store.ledger.iter().find(|e| e.seq == *seq).unwrap();
                format!(
                    "int2send(1::int2) || int8send({}::int8) || int8send({}::int8) || int8send({}::int8) || {} || int2send({}::int2) || int4send({}::int4) || int4send({}::int4) || {}",
                    row.at,
                    seq,
                    e.at,
                    bytea(&e.command),
                    e.schema,
                    e.key_ix,
                    e.body.len(),
                    bytea(&e.body)
                )
            }
            RefRowKind::Event { body } => format!(
                "int2send(2::int2) || int8send({}::int8) || int4send({}::int4) || {}",
                row.at,
                body.len(),
                bytea(body)
            ),
        };
        let sql_stored = format!(
            "SELECT encode(sha256(convert_to('fstp-audit-row-v1', 'UTF8') || {payload}), 'hex');"
        );
        assert_eq!(
            server.psql(&db.dbname, &sql_stored).unwrap(),
            hex(&row.stored_hash),
            "stored hash of row {}",
            row.n
        );
        let sql_link = format!(
            "SELECT encode(sha256(convert_to('fstp-audit-v1', 'UTF8') || {} || '\\x02'::bytea || int8send({}::int8) || {} || {}), 'hex');",
            bytea(&s.cell),
            row.n,
            bytea(&prev),
            bytea(&row.stored_hash)
        );
        assert_eq!(
            server.psql(&db.dbname, &sql_link).unwrap(),
            hex(&row.link),
            "link of row {}",
            row.n
        );
        prev = row.link;
    }
}
