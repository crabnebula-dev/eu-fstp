//! Adapters from the tests to `fstp-audit`. This is the only file of the
//! tests that names a production item other than `AuditError`, `Tamper`
//! and `fstp_crypto`.
//!
//! Lane W2g re-pointed each adapter at its production call and deleted
//! the gap constants of the W0 stub. The test files are unchanged.

use fstp_audit::anchor::{self, Anchor, AnchorRow, Receipt};
use fstp_audit::anchorer;
use fstp_audit::chain::{self, StoredEntry, StoredRow};
use fstp_audit::verify::ChainView;
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{AuditError, CellId, ChainId, ChainRow, ChainWriter, Link, RowKind};

use super::reference::{Chain, Entry, Hash, Kind, ReceiptFields, RowCols};
use super::view::{AnchorRec, ReceiptRec, View, WitnessRec};

// ---------------------------------------------------------------------------
// Conversions.

/// The production chain id.
pub(crate) fn prod_chain(c: Chain) -> ChainId {
    match c {
        Chain::App => ChainId::App,
        Chain::Vault => ChainId::Vault,
    }
}

fn from_prod_chain(c: ChainId) -> Chain {
    match c {
        ChainId::App => Chain::App,
        ChainId::Vault => Chain::Vault,
    }
}

/// The production row kind.
pub(crate) fn prod_kind(k: &Kind) -> RowKind {
    match k {
        Kind::Ledger { seq } => RowKind::Ledger { seq: *seq },
        Kind::Event { body } => RowKind::Event { body: body.clone() },
    }
}

fn from_prod_kind(k: RowKind) -> Kind {
    match k {
        RowKind::Ledger { seq } => Kind::Ledger { seq },
        RowKind::Event { body } => Kind::Event { body },
    }
}

fn prod_row(c: &RowCols) -> ChainRow {
    ChainRow {
        n: c.n,
        at: c.at,
        kind: prod_kind(&c.kind),
        stored_hash: c.stored_hash,
    }
}

fn prod_entry(e: &Entry) -> StoredEntry {
    StoredEntry {
        seq: e.seq,
        at: e.at,
        command: e.command,
        schema: e.schema,
        key_ix: e.key_ix,
        body: e.body.clone(),
    }
}

fn prod_fields(f: &ReceiptFields) -> anchor::ReceiptFields {
    anchor::ReceiptFields {
        n: f.n,
        link: Link(f.link),
        witness_seq: f.witness_seq,
        witness_link: Link(f.witness_link),
        received_at: f.received_at,
    }
}

fn prod_anchor(a: &AnchorRec) -> Anchor {
    Anchor {
        cell: CellId(a.cell),
        chain: prod_chain(a.chain),
        n: a.n,
        link: Link(a.link),
        at: a.at,
        signature: a.signature.clone(),
    }
}

fn prod_receipt(r: &ReceiptRec) -> Receipt {
    Receipt {
        cell: CellId(r.cell),
        chain: prod_chain(r.chain),
        fields: prod_fields(&r.fields),
        signature: r.signature.clone(),
    }
}

// ---------------------------------------------------------------------------
// Chain format.

/// `fstp_audit::chain::genesis`.
pub(crate) fn genesis(cell: [u8; 16], chain: Chain) -> Result<Hash, AuditError> {
    Ok(chain::genesis(CellId(cell), prod_chain(chain)).0)
}

/// `fstp_audit::chain::link` over a row with these columns.
pub(crate) fn link(
    prev: &Hash,
    cell: [u8; 16],
    chain: Chain,
    row: &RowCols,
) -> Result<Hash, AuditError> {
    Ok(chain::link(
        &Link(*prev),
        CellId(cell),
        prod_chain(chain),
        &prod_row(row),
    )
    .0)
}

/// `fstp_audit::chain::row_bytes`.
pub(crate) fn row_bytes(
    at: i64,
    kind: &Kind,
    entry: Option<&Entry>,
) -> Result<Vec<u8>, AuditError> {
    chain::row_bytes(at, &prod_kind(kind), entry.map(prod_entry).as_ref())
}

/// `fstp_audit::chain::stored_hash`.
pub(crate) fn stored_hash(at: i64, kind: &Kind, entry: Option<&Entry>) -> Result<Hash, AuditError> {
    chain::stored_hash(at, &prod_kind(kind), entry.map(prod_entry).as_ref())
}

/// `fstp_audit::ChainId::byte`.
pub(crate) fn chain_byte(chain: Chain) -> Result<u8, AuditError> {
    Ok(prod_chain(chain).byte())
}

/// The head a `ChainWriter` resumed at `(n, link)` reports.
pub(crate) fn writer_resume_head(n: u64, link: Hash) -> (u64, Hash) {
    let (n, l) = ChainWriter::resume(n, Link(link)).head();
    (n, l.0)
}

/// Appends one row after `head` through `ChainWriter` and returns the new
/// head, after checking that the returned row carries that head.
pub(crate) fn writer_append(
    head: (u64, Hash),
    cell: [u8; 16],
    chain: Chain,
    at: i64,
    kind: &Kind,
    entry: Option<&Entry>,
) -> Result<(u64, Hash), AuditError> {
    let mut w = ChainWriter::resume(head.0, Link(head.1));
    let StoredRow { row, link } = w.append(
        CellId(cell),
        prod_chain(chain),
        at,
        prod_kind(kind),
        entry.map(prod_entry).as_ref(),
    )?;
    let (n, l) = w.head();
    assert_eq!((row.n, link), (n, l), "the appended row is the new head");
    Ok((n, l.0))
}

/// `fstp_audit::chain::decode_chain_row`.
pub(crate) fn decode_chain_row(bytes: &[u8]) -> Result<RowCols, AuditError> {
    chain::decode_chain_row(bytes).map(|r| RowCols {
        n: r.n,
        at: r.at,
        kind: from_prod_kind(r.kind),
        stored_hash: r.stored_hash,
    })
}

/// `fstp_audit::chain::encode_chain_row`.
pub(crate) fn encode_chain_row(row: &RowCols) -> Result<Vec<u8>, AuditError> {
    chain::encode_chain_row(&prod_row(row))
}

// ---------------------------------------------------------------------------
// Anchors and receipts.

/// `fstp_audit::anchor::anchor_message`.
pub(crate) fn anchor_message(
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Result<Vec<u8>, AuditError> {
    Ok(anchor::anchor_message(
        CellId(cell),
        prod_chain(chain),
        n,
        &Link(*link),
        at,
    ))
}

/// `fstp_audit::anchor::receipt_message`.
pub(crate) fn receipt_message(
    cell: [u8; 16],
    chain: Chain,
    r: &ReceiptFields,
) -> Result<Vec<u8>, AuditError> {
    Ok(anchor::receipt_message(
        CellId(cell),
        prod_chain(chain),
        &prod_fields(r),
    ))
}

/// `fstp_audit::anchor::decode_anchor`.
pub(crate) fn decode_anchor(bytes: &[u8]) -> Result<AnchorRec, AuditError> {
    anchor::decode_anchor(bytes).map(|a| AnchorRec {
        cell: a.cell.0,
        chain: from_prod_chain(a.chain),
        n: a.n,
        link: a.link.0,
        at: a.at,
        signature: a.signature,
    })
}

/// `fstp_audit::anchor::encode_anchor`.
pub(crate) fn encode_anchor(a: &AnchorRec) -> Result<Vec<u8>, AuditError> {
    anchor::encode_anchor(&prod_anchor(a))
}

/// `fstp_audit::anchor::decode_receipt`.
pub(crate) fn decode_receipt(bytes: &[u8]) -> Result<ReceiptRec, AuditError> {
    anchor::decode_receipt(bytes).map(|r| ReceiptRec {
        cell: r.cell.0,
        chain: from_prod_chain(r.chain),
        fields: ReceiptFields {
            n: r.fields.n,
            link: r.fields.link.0,
            witness_seq: r.fields.witness_seq,
            witness_link: r.fields.witness_link.0,
            received_at: r.fields.received_at,
        },
        signature: r.signature,
    })
}

/// `fstp_audit::anchor::encode_receipt`.
pub(crate) fn encode_receipt(r: &ReceiptRec) -> Result<Vec<u8>, AuditError> {
    anchor::encode_receipt(&prod_receipt(r))
}

/// `fstp_audit::anchor::sign_anchor` with the chain's composite `Anchor`
/// key: the signature bytes. It signs under the anchor context and
/// refuses row 0, or a composite signer failure, as `fstp_audit` does.
pub(crate) fn sign_anchor(
    key: &fstp_crypto::composite::CompositeSigningKey,
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Result<Vec<u8>, AuditError> {
    sign_anchor_rec(key, cell, chain, n, link, at).map(|a| a.signature)
}

/// `fstp_audit::anchor::sign_anchor`: the whole anchor it returns.
pub(crate) fn sign_anchor_rec(
    key: &fstp_crypto::composite::CompositeSigningKey,
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Result<AnchorRec, AuditError> {
    anchor::sign_anchor(key, CellId(cell), prod_chain(chain), n, &Link(*link), at).map(|a| {
        AnchorRec {
            cell: a.cell.0,
            chain: from_prod_chain(a.chain),
            n: a.n,
            link: a.link.0,
            at: a.at,
            signature: a.signature,
        }
    })
}

// ---------------------------------------------------------------------------
// The verifier.

fn prod_anchor_row(a: &super::view::AnchorRow) -> AnchorRow {
    AnchorRow {
        anchor: prod_anchor(&a.anchor),
        receipt: prod_receipt(&a.receipt),
    }
}

/// `fstp_audit::verify::verify` over everything `view` holds. It answers
/// the number of verified rows.
pub(crate) fn verify(view: &View) -> Result<u64, AuditError> {
    verify_full(view).map(|(rows, _)| rows)
}

/// `fstp_audit::verify::verify` over everything `view` holds. It answers
/// the number of verified rows and the `(n, link)` of every possible
/// deletion it lists.
pub(crate) fn verify_full(view: &View) -> Result<(u64, Vec<(u64, Hash)>), AuditError> {
    let rows: Vec<StoredRow> = view
        .rows
        .iter()
        .map(|r| StoredRow {
            row: prod_row(&r.cols),
            link: Link(r.link),
        })
        .collect();
    let ledger: Vec<StoredEntry> = view.ledger.iter().map(prod_entry).collect();
    let anchors: Vec<AnchorRow> = view.anchors.iter().map(prod_anchor_row).collect();
    let witness: Vec<WitnessRecord> = view
        .witness
        .iter()
        .map(|w| match w {
            WitnessRec::Prepare(a) => WitnessRecord::Prepare(prod_anchor_row(a)),
            WitnessRec::Abort { n, link } => WitnessRecord::Abort {
                n: *n,
                link: Link(*link),
            },
            WitnessRec::InDoubtAbsent { n, link } => WitnessRecord::InDoubtAbsent {
                n: *n,
                link: Link(*link),
            },
        })
        .collect();
    let v = ChainView {
        cell: CellId(view.cell),
        chain: prod_chain(view.chain),
        rows: &rows,
        ledger: &ledger,
        anchors: &anchors,
        witness: &witness,
        anchor_keys: &view.anchor_keys,
        witness_keys: &view.witness_keys,
    };
    fstp_audit::verify::verify(&v).map(|ok| {
        let gone = ok
            .possible_deletions
            .into_iter()
            .map(|(n, l)| (n, l.0))
            .collect();
        (ok.rows, gone)
    })
}

// ---------------------------------------------------------------------------
// The anchorer core (design sections 5.3 and 7.2).

/// The outcome of COMMIT, as the cell sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    /// COMMIT succeeded.
    Committed,
    /// The transaction failed before COMMIT was sent, or COMMIT returned
    /// an error.
    Failed,
    /// The outcome is unknown: a lost connection or a crash.
    Unknown,
}

impl CommitOutcome {
    /// Every outcome.
    pub(crate) const ALL: [CommitOutcome; 3] = [
        CommitOutcome::Committed,
        CommitOutcome::Failed,
        CommitOutcome::Unknown,
    ];
}

/// What the anchorer does after a commit outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AfterCommit {
    /// Nothing more.
    Done,
    /// Send `Abort { n, link }` before the same `n` is prepared again.
    SendAbort,
    /// Read the chain at reconnect or restart, then resolve.
    InDoubt,
}

/// How the anchorer resolves an in-doubt prepare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// The row holds the prepared link: it committed.
    Committed,
    /// The row is missing: send `InDoubtAbsent` and raise
    /// `PossibleDeletion`.
    AbsentRaisePossibleDeletion,
}

/// A request kind for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// Reads only.
    Read,
    /// Appends to the chain.
    Write,
}

/// Why admission refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmitRefusal {
    /// The witness is unreachable. The refusal names it.
    WitnessUnavailable,
}

/// A prospective head for the `may_commit` adapter.
const HEAD: (u64, Link) = (3, Link([0x3C; 32]));

/// `fstp_audit::anchorer::may_commit` for a prospective head, with or
/// without the receipt for that head.
pub(crate) fn may_commit(receipted: bool) -> Result<bool, AuditError> {
    let receipt = anchor::ReceiptFields {
        n: HEAD.0,
        link: HEAD.1,
        witness_seq: 1,
        witness_link: Link([0x77; 32]),
        received_at: 1,
    };
    Ok(anchorer::may_commit(HEAD, receipted.then_some(&receipt)))
}

/// `fstp_audit::anchorer::after_commit`.
pub(crate) fn after_commit(outcome: CommitOutcome) -> Result<AfterCommit, AuditError> {
    let o = match outcome {
        CommitOutcome::Committed => anchorer::CommitOutcome::Committed,
        CommitOutcome::Failed => anchorer::CommitOutcome::Failed,
        CommitOutcome::Unknown => anchorer::CommitOutcome::Unknown,
    };
    Ok(match anchorer::after_commit(o) {
        anchorer::AfterCommit::Done => AfterCommit::Done,
        anchorer::AfterCommit::SendAbort => AfterCommit::SendAbort,
        anchorer::AfterCommit::InDoubt => AfterCommit::InDoubt,
    })
}

/// `fstp_audit::anchorer::resolve_in_doubt` of `prepared`, given the link
/// the chain holds at its row.
pub(crate) fn resolve_in_doubt(
    link_at_n: Option<Hash>,
    prepared: &Hash,
) -> Result<Resolution, AuditError> {
    let at_n = link_at_n.map(Link);
    Ok(
        match anchorer::resolve_in_doubt(at_n.as_ref(), &Link(*prepared)) {
            anchorer::Resolution::Committed => Resolution::Committed,
            anchorer::Resolution::AbsentRaisePossibleDeletion => {
                Resolution::AbsentRaisePossibleDeletion
            }
        },
    )
}

/// `fstp_audit::anchorer::admit` of `op` while the witness is or is not
/// reachable.
pub(crate) fn admit(op: Op, witness_up: bool) -> Result<Result<(), AdmitRefusal>, AuditError> {
    let op = match op {
        Op::Read => anchorer::Op::Read,
        Op::Write => anchorer::Op::Write,
    };
    Ok(anchorer::admit(op, witness_up).map_err(|e| match e {
        anchorer::AdmitRefusal::WitnessUnavailable => AdmitRefusal::WitnessUnavailable,
    }))
}
