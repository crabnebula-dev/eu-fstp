//! Adapters from the tests to `fstp-witness` and to the one link function
//! of `fstp-audit`. This is the only file of the tests that names a
//! production item other than `WitnessError`.
//!
//! The witness core of ADR-010 is sans-IO: for one cell and chain it
//! takes a prepare, an abort or an in-doubt record from a sender, and
//! answers a receipt, a recorded withdrawal or a refusal. The test-local
//! types below are the shapes the tests read. Lane W2g mapped its own
//! types onto them here and deleted the gap constants of the W0 stub.

use fstp_audit::anchor::Anchor;
use fstp_audit::witness::Prepare as ProdPrepare;
use fstp_audit::{CellId, ChainId, ChainRow, Link, RowKind};
use fstp_witness::file_store::FileRecord;
use fstp_witness::{ChainWitness, WitnessError, WitnessMessage};

/// A SHA-256 value.
pub(crate) type Hash = [u8; 32];

// ---------------------------------------------------------------------------
// Test-local shapes.

/// The two chains of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Chain {
    /// The application chain.
    App,
    /// The vault chain.
    Vault,
}

impl Chain {
    /// Both chains.
    pub(crate) const ALL: [Chain; 2] = [Chain::App, Chain::Vault];
}

/// Who sends a message, by client certificate (ADR-010 "Witnesses").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sender {
    /// A `cell-witness` certificate issued by `cell`'s CA.
    CellWitness {
        /// The issuing cell.
        cell: [u8; 16],
    },
    /// A `vault-witness` certificate issued by `cell`'s CA.
    VaultWitness {
        /// The issuing cell.
        cell: [u8; 16],
    },
    /// A control-plane CA certificate. It only sends restore declarations.
    ControlPlane,
}

impl Sender {
    /// Every sender over the cells `own` and `other`.
    pub(crate) fn all(own: [u8; 16], other: [u8; 16]) -> [Sender; 5] {
        [
            Sender::CellWitness { cell: own },
            Sender::VaultWitness { cell: own },
            Sender::CellWitness { cell: other },
            Sender::VaultWitness { cell: other },
            Sender::ControlPlane,
        ]
    }

    /// The writer of `cell`'s `chain`.
    pub(crate) fn writer(cell: [u8; 16], chain: Chain) -> Sender {
        match chain {
            Chain::App => Sender::CellWitness { cell },
            Chain::Vault => Sender::VaultWitness { cell },
        }
    }
}

/// A prepare: the head it extends, the stored hashes of its rows, and the
/// anchor (ADR-010 "Prepare", reading of open point 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Prepare {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The head this prepare extends.
    pub(crate) prev: (u64, Hash),
    /// The stored hashes of the rows after `prev`, in order.
    pub(crate) stored_hashes: Vec<Hash>,
    /// The anchor's head row number.
    pub(crate) n: u64,
    /// The anchor's head link.
    pub(crate) link: Hash,
    /// The anchor's `at`.
    pub(crate) at: i64,
    /// The anchor's composite signature bytes.
    pub(crate) signature: Vec<u8>,
}

/// A message to the witness (design section 15:
/// `witness_message_decode` covers prepare, abort and in-doubt).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Msg {
    /// Prepare an anchor and ask for its receipt.
    Prepare(Prepare),
    /// Abort a prepare whose commit failed.
    Abort {
        /// The cell.
        cell: [u8; 16],
        /// The chain.
        chain: Chain,
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
    /// A prepare whose commit outcome was unknown and whose row was
    /// missing at reconnect.
    InDoubtAbsent {
        /// The cell.
        cell: [u8; 16],
        /// The chain.
        chain: Chain,
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
}

/// The signed fields of a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    /// The head row number.
    pub(crate) n: u64,
    /// The head link.
    pub(crate) link: Hash,
    /// The witness sequence.
    pub(crate) witness_seq: u64,
    /// The witness chain link.
    pub(crate) witness_link: Hash,
    /// UTC microseconds.
    pub(crate) received_at: i64,
}

/// Why the witness refused a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The sender may not write this cell's chain.
    WrongSender,
    /// Another prepare is outstanding and this one does not extend it.
    Outstanding,
    /// The prepare does not extend the last confirmed head.
    NotExtending,
    /// The rows do not recompute to the anchor's link, or there are none.
    LinkMismatch,
    /// An abort or in-doubt record names no outstanding prepare.
    UnknownPrepare,
    /// The `(n, link)` was already withdrawn by an abort or in-doubt
    /// record.
    Withdrawn,
    /// Added by lane W2g: the message names another cell or chain than
    /// the witness state. No test sends one.
    WrongChain,
    /// Added by lane W2g: the witness sequence is at `u64::MAX`.
    Exhausted,
}

/// One record of the append-only file store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRec {
    /// The witness sequence.
    pub(crate) witness_seq: u64,
    /// The record bytes.
    pub(crate) bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Links (`fstp-audit`).

/// `fstp_audit::chain::genesis`.
pub(crate) fn genesis(cell: [u8; 16], chain: Chain) -> Result<Hash, String> {
    Ok(fstp_audit::chain::genesis(CellId(cell), prod_chain(chain)).0)
}

/// `fstp_audit::chain::link` of row `n` with `stored_hash` after `prev`.
pub(crate) fn link(
    prev: &Hash,
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    stored_hash: &Hash,
) -> Result<Hash, String> {
    let row = ChainRow {
        n,
        at: 0,
        kind: RowKind::Event { body: Vec::new() },
        stored_hash: *stored_hash,
    };
    Ok(fstp_audit::chain::link(&Link(*prev), CellId(cell), prod_chain(chain), &row).0)
}

fn prod_chain(c: Chain) -> ChainId {
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

fn prod_sender(s: Sender) -> fstp_witness::Sender {
    match s {
        Sender::CellWitness { cell } => fstp_witness::Sender::CellWitness { cell: CellId(cell) },
        Sender::VaultWitness { cell } => fstp_witness::Sender::VaultWitness { cell: CellId(cell) },
        Sender::ControlPlane => fstp_witness::Sender::ControlPlane,
    }
}

fn from_refusal(r: fstp_witness::Refusal) -> Refusal {
    match r {
        fstp_witness::Refusal::WrongSender => Refusal::WrongSender,
        fstp_witness::Refusal::WrongChain => Refusal::WrongChain,
        fstp_witness::Refusal::Outstanding => Refusal::Outstanding,
        fstp_witness::Refusal::NotExtending => Refusal::NotExtending,
        fstp_witness::Refusal::LinkMismatch => Refusal::LinkMismatch,
        fstp_witness::Refusal::UnknownPrepare => Refusal::UnknownPrepare,
        fstp_witness::Refusal::Withdrawn => Refusal::Withdrawn,
        fstp_witness::Refusal::Exhausted => Refusal::Exhausted,
    }
}

fn prod_prepare(p: &Prepare) -> ProdPrepare {
    ProdPrepare {
        prev: (p.prev.0, Link(p.prev.1)),
        stored_hashes: p.stored_hashes.clone(),
        anchor: Anchor {
            cell: CellId(p.cell),
            chain: prod_chain(p.chain),
            n: p.n,
            link: Link(p.link),
            at: p.at,
            signature: p.signature.clone(),
        },
    }
}

fn from_prod_prepare(p: ProdPrepare) -> Prepare {
    Prepare {
        cell: p.anchor.cell.0,
        chain: from_prod_chain(p.anchor.chain),
        prev: (p.prev.0, p.prev.1.0),
        stored_hashes: p.stored_hashes,
        n: p.anchor.n,
        link: p.anchor.link.0,
        at: p.anchor.at,
        signature: p.anchor.signature,
    }
}

// ---------------------------------------------------------------------------
// The witness core.

/// `fstp_witness::accepts_sender`.
pub(crate) fn accepts_sender(
    sender: Sender,
    cell: [u8; 16],
    chain: Chain,
) -> Result<bool, WitnessError> {
    Ok(fstp_witness::accepts_sender(
        prod_sender(sender),
        CellId(cell),
        prod_chain(chain),
    ))
}

/// The witness core's state for one cell and chain.
#[derive(Debug)]
pub(crate) struct Core {
    inner: ChainWitness,
}

impl Core {
    /// `fstp_witness::ChainWitness::genesis`.
    pub(crate) fn genesis(cell: [u8; 16], chain: Chain) -> Result<Core, WitnessError> {
        Ok(Core {
            inner: ChainWitness::genesis(CellId(cell), prod_chain(chain)),
        })
    }

    /// `fstp_witness::ChainWitness::prepare`.
    pub(crate) fn prepare(
        &mut self,
        sender: Sender,
        p: &Prepare,
        received_at: i64,
    ) -> Result<Result<Receipt, Refusal>, WitnessError> {
        Ok(self
            .inner
            .prepare(prod_sender(sender), &prod_prepare(p), received_at)
            .map(|r| Receipt {
                n: r.n,
                link: r.link.0,
                witness_seq: r.witness_seq,
                witness_link: r.witness_link.0,
                received_at: r.received_at,
            })
            .map_err(from_refusal))
    }

    /// `fstp_witness::ChainWitness::abort`.
    pub(crate) fn abort(
        &mut self,
        sender: Sender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<(), Refusal>, WitnessError> {
        Ok(self
            .inner
            .abort(prod_sender(sender), n, &Link(*link))
            .map(|_| ())
            .map_err(from_refusal))
    }

    /// `fstp_witness::ChainWitness::in_doubt_absent`.
    pub(crate) fn in_doubt_absent(
        &mut self,
        sender: Sender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<(), Refusal>, WitnessError> {
        Ok(self
            .inner
            .in_doubt_absent(prod_sender(sender), n, &Link(*link))
            .map(|_| ())
            .map_err(from_refusal))
    }
}

// ---------------------------------------------------------------------------
// Codecs.

fn prod_message(m: &Msg) -> WitnessMessage {
    match m {
        Msg::Prepare(p) => WitnessMessage::Prepare(prod_prepare(p)),
        Msg::Abort {
            cell,
            chain,
            n,
            link,
        } => WitnessMessage::Abort {
            cell: CellId(*cell),
            chain: prod_chain(*chain),
            n: *n,
            link: Link(*link),
        },
        Msg::InDoubtAbsent {
            cell,
            chain,
            n,
            link,
        } => WitnessMessage::InDoubtAbsent {
            cell: CellId(*cell),
            chain: prod_chain(*chain),
            n: *n,
            link: Link(*link),
        },
    }
}

/// `fstp_witness::decode_witness_message`.
pub(crate) fn decode_message(bytes: &[u8]) -> Result<Msg, WitnessError> {
    Ok(match fstp_witness::decode_witness_message(bytes)? {
        WitnessMessage::Prepare(p) => Msg::Prepare(from_prod_prepare(p)),
        WitnessMessage::Abort {
            cell,
            chain,
            n,
            link,
        } => Msg::Abort {
            cell: cell.0,
            chain: from_prod_chain(chain),
            n,
            link: link.0,
        },
        WitnessMessage::InDoubtAbsent {
            cell,
            chain,
            n,
            link,
        } => Msg::InDoubtAbsent {
            cell: cell.0,
            chain: from_prod_chain(chain),
            n,
            link: link.0,
        },
    })
}

/// `fstp_witness::encode_witness_message`.
pub(crate) fn encode_message(m: &Msg) -> Result<Vec<u8>, WitnessError> {
    fstp_witness::encode_witness_message(&prod_message(m))
}

/// `fstp_witness::decode_file_store`.
pub(crate) fn decode_file_store(bytes: &[u8]) -> Result<Vec<FileRec>, WitnessError> {
    fstp_witness::decode_file_store(bytes).map(|rs| {
        rs.into_iter()
            .map(|r| FileRec {
                witness_seq: r.witness_seq,
                bytes: r.bytes,
            })
            .collect()
    })
}

/// `fstp_witness::encode_file_store`.
pub(crate) fn encode_file_store(records: &[FileRec]) -> Result<Vec<u8>, WitnessError> {
    let rs: Vec<FileRecord> = records
        .iter()
        .map(|r| FileRecord {
            witness_seq: r.witness_seq,
            bytes: r.bytes.clone(),
        })
        .collect();
    fstp_witness::encode_file_store(&rs)
}

// ---------------------------------------------------------------------------
// Signatures (ADR-010 "Receipt", "Keys" and "Composite encoding",
// R-CR-03, I-90).

/// A composite signing key, `fstp_audit`'s re-export of
/// `fstp_crypto::composite::CompositeSigningKey`.
pub(crate) type Key = fstp_audit::CompositeSigningKey;

/// The draft 19 composite signature length (ADR-010, row "Signature").
pub(crate) const SIGNATURE_LEN: usize = fstp_audit::SIGNATURE_LEN;

/// The length of the ML-DSA-65 half, first in the signature (ADR-010,
/// row "Signature").
pub(crate) const MLDSA_SIG_LEN: usize = 3309;

/// The draft 19 composite public key length (ADR-010, row "Public key").
pub(crate) const PUBLIC_KEY_LEN: usize = fstp_audit::PUBLIC_KEY_LEN;

/// A composite key from the fixed test seed `seed`: 64 bytes of `seed`,
/// the ML-DSA-65 seed then the Ed25519 private key (draft 19 section
/// 4.2). Test keys only.
pub(crate) fn key(seed: u8) -> Key {
    Key::from_bytes(&[seed; 64]).expect("test composite key")
}

/// The encoded public key of `k`.
pub(crate) fn public(k: &Key) -> Vec<u8> {
    k.public_key().to_bytes().to_vec()
}

/// A composite signature made in the test over `msg` under the
/// application context `ctx`.
pub(crate) fn sign(k: &Key, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    k.sign_with_context(msg, ctx)
        .expect("composite sign")
        .to_bytes()
        .to_vec()
}

/// The ADR-010 anchor message, `fstp_audit::anchor::anchor_message`. Its
/// bytes are pinned by vectors in the `fstp-audit` tests.
pub(crate) fn anchor_message(
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Vec<u8> {
    fstp_audit::anchor::anchor_message(CellId(cell), prod_chain(chain), n, &Link(*link), at)
}

/// The receipt message, `fstp_audit::anchor::receipt_message`. Its bytes
/// are pinned by vectors in the `fstp-audit` tests.
pub(crate) fn receipt_message(cell: [u8; 16], chain: Chain, r: &Receipt) -> Vec<u8> {
    fstp_audit::anchor::receipt_message(CellId(cell), prod_chain(chain), &prod_fields(r))
}

fn prod_fields(r: &Receipt) -> fstp_audit::anchor::ReceiptFields {
    fstp_audit::anchor::ReceiptFields {
        n: r.n,
        link: Link(r.link),
        witness_seq: r.witness_seq,
        witness_link: Link(r.witness_link),
        received_at: r.received_at,
    }
}

/// A signed anchor, as a prepare carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedAnchor {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The head row number.
    pub(crate) n: u64,
    /// The head link.
    pub(crate) link: Hash,
    /// UTC microseconds.
    pub(crate) at: i64,
    /// The composite signature bytes.
    pub(crate) signature: Vec<u8>,
}

impl SignedAnchor {
    /// The anchor of `(n, link)` at `at`, signed in the test with `k`
    /// under `ctx`.
    pub(crate) fn signed(
        k: &Key,
        ctx: &[u8],
        cell: [u8; 16],
        chain: Chain,
        n: u64,
        link: Hash,
        at: i64,
    ) -> SignedAnchor {
        let signature = sign(k, &anchor_message(cell, chain, n, &link, at), ctx);
        SignedAnchor {
            cell,
            chain,
            n,
            link,
            at,
            signature,
        }
    }

    fn prod(&self) -> Anchor {
        Anchor {
            cell: CellId(self.cell),
            chain: prod_chain(self.chain),
            n: self.n,
            link: Link(self.link),
            at: self.at,
            signature: self.signature.clone(),
        }
    }
}

/// A signed receipt, as `fstp_witness::sign_receipt` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedReceipt {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The signed fields.
    pub(crate) fields: Receipt,
    /// The witness's composite signature bytes.
    pub(crate) signature: Vec<u8>,
}

impl SignedReceipt {
    fn prod(&self) -> fstp_audit::anchor::Receipt {
        fstp_audit::anchor::Receipt {
            cell: CellId(self.cell),
            chain: prod_chain(self.chain),
            fields: prod_fields(&self.fields),
            signature: self.signature.clone(),
        }
    }
}

/// `fstp_witness::sign_receipt` of `fields` for `cell`'s `chain` with
/// the witness's composite receipt key `k`. It signs under the receipt
/// context and refuses row 0, witness sequence 0, or a composite signer
/// failure, as `fstp_witness` does.
pub(crate) fn sign_receipt(
    k: &Key,
    cell: [u8; 16],
    chain: Chain,
    fields: &Receipt,
) -> Result<SignedReceipt, WitnessError> {
    fstp_witness::sign_receipt(k, CellId(cell), prod_chain(chain), &prod_fields(fields)).map(|r| {
        SignedReceipt {
            cell: r.cell.0,
            chain: from_prod_chain(r.chain),
            fields: Receipt {
                n: r.fields.n,
                link: r.fields.link.0,
                witness_seq: r.fields.witness_seq,
                witness_link: r.fields.witness_link.0,
                received_at: r.fields.received_at,
            },
            signature: r.signature,
        }
    })
}

/// `fstp_witness::receipt::check_anchor_signature` of `a` under the
/// chain's anchor key history `keys`. `Ok` only when one key of the
/// history verifies both halves under the anchor context (I-90).
pub(crate) fn check_anchor_signature(
    a: &SignedAnchor,
    keys: &[Vec<u8>],
) -> Result<(), WitnessError> {
    fstp_witness::receipt::check_anchor_signature(&a.prod(), keys)
}

/// One event row appended to an empty chain through
/// `fstp_audit::chain::ChainWriter`.
#[derive(Clone, Debug)]
pub(crate) struct OneRow {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The genesis head it extends.
    pub(crate) prev: (u64, Hash),
    /// Its stored hash.
    pub(crate) stored_hash: Hash,
    /// Its row number, 1.
    pub(crate) n: u64,
    /// Its link.
    pub(crate) link: Hash,
    row: fstp_audit::StoredRow,
}

/// The first row of `cell`'s `chain`: an event at `at`.
pub(crate) fn one_row(cell: [u8; 16], chain: Chain, at: i64) -> OneRow {
    let mut w = fstp_audit::ChainWriter::genesis(CellId(cell), prod_chain(chain));
    let prev = w.head();
    let row = w
        .append(
            CellId(cell),
            prod_chain(chain),
            at,
            RowKind::Event {
                body: b"login".to_vec(),
            },
            None,
        )
        .expect("an event row");
    OneRow {
        cell,
        chain,
        prev: (prev.0, prev.1.0),
        stored_hash: row.row.stored_hash,
        n: row.row.n,
        link: row.link.0,
        row,
    }
}

impl OneRow {
    /// The prepare of this row, carrying `anchor`.
    pub(crate) fn prepare(&self, anchor: &SignedAnchor) -> Prepare {
        Prepare {
            cell: self.cell,
            chain: self.chain,
            prev: self.prev,
            stored_hashes: vec![self.stored_hash],
            n: anchor.n,
            link: anchor.link,
            at: anchor.at,
            signature: anchor.signature.clone(),
        }
    }
}

/// What `fstp_audit::verify` answered, in the terms these tests read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The chain verified, with this many rows.
    Verified(u64),
    /// `Tamper::BadSignature { n }`.
    BadSignature(u64),
    /// Anything else, as text.
    Other(String),
}

/// `fstp_audit::verify` over `row`, with `anchor` and `receipt` in both
/// stored copies: the `audit.anchor` row and the witness log's prepare
/// record. The anchor key history is `anchor_keys`, and the pinned
/// witness keys are `witness_keys`.
pub(crate) fn verify_one_row(
    row: &OneRow,
    anchor: &SignedAnchor,
    receipt: &SignedReceipt,
    anchor_keys: &[Vec<u8>],
    witness_keys: &[Vec<u8>],
) -> Verdict {
    let anchor_row = fstp_audit::AnchorRow {
        anchor: anchor.prod(),
        receipt: receipt.prod(),
    };
    let rows = [row.row.clone()];
    let anchors = [anchor_row.clone()];
    let witness = [fstp_audit::WitnessRecord::Prepare(anchor_row)];
    let view = fstp_audit::ChainView {
        cell: CellId(row.cell),
        chain: prod_chain(row.chain),
        rows: &rows,
        ledger: &[],
        anchors: &anchors,
        witness: &witness,
        anchor_keys,
        witness_keys,
    };
    match fstp_audit::verify::verify(&view) {
        Ok(v) => Verdict::Verified(v.rows),
        Err(fstp_audit::AuditError::Tamper(fstp_audit::Tamper::BadSignature { n })) => {
            Verdict::BadSignature(n)
        }
        Err(e) => Verdict::Other(format!("{e:?}")),
    }
}
