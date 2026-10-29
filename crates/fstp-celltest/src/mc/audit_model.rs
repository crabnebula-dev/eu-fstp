//! M-AUDIT (design section 14.2, I-24). Lane W1e owns this file.
//!
//! The universe: one cell and one chain. The App chain and the Vault
//! chain are two initial states. There are up to three append attempts
//! of three rows each, two kind 1 ledger rows around a kind 2 event row.
//! Up to two commits leave up to six committed entries under two
//! anchors. The strict tail D of ADR-010 holds: prepare, witness
//! receipt, commit. Environment faults: a refused or lost prepare, a
//! failure before COMMIT, a COMMIT error, an unknown COMMIT outcome that
//! did or did not commit, one crash of the cell, one crash of the
//! witness. One attacker step, by a database owner or superuser who holds
//! no key. The steps are those of [`attacks`]: modify, delete, insert,
//! reorder, truncate, a consistent recomputation after a change, a forged
//! or duplicated ledger entry, and an aborted attempt put back from the
//! WAL. The cell keeps appending after the attack, over the head it reads
//! from its store, so the witness meets a tampered head.
//!
//! The model runs over an [`AuditBackend`]: [`Reference`], [`Production`]
//! (`fstp_audit` and `fstp_witness`) or a [`Mutant`] with one seeded
//! defect. The backend computes every link, answers every witness and
//! anchorer decision, admits or refuses each write, and verifies. The
//! model holds the environment, the honest store and the attacker.
//!
//! Signatures are symbolic in the state. [`Keys`] signs them when a view
//! is materialized for the verifier, with the aws-lc-rs oracles (design
//! section 14.4: "these tests sign with the aws-lc-rs ML-DSA test oracle
//! through `fstp-celltest`").
//!
//! Those reference signatures never reach production code. A backend
//! signs with its own keys through [`AuditBackend::sign_view`] and
//! verifies those bytes through [`AuditBackend::verify_opaque`]. The keys
//! stay inside the backend, and no test reads a layout in the bytes.
//! [`verify_by_translation`] maps a reference view onto the backend's own
//! signatures. Each reference signature the oracle refuses becomes the
//! backend's signature over another message, so a forgery stays invalid.
//! The I-90 half forgeries reach production through the layout-free
//! sweep of `i90_composite_verify.rs` instead.
//!
//! # Removing the seams
//!
//! [`Production`] and the `prod_*` functions refuse with a seam constant
//! until their lane lands. A seam stays red after its lane merges until
//! someone edits this file, so each merge must replace its seams here:
//!
//! - Lane W2g replaced its seams. [`Production`] reaches `fstp_audit` for
//!   the stored hash, the link, the admission decision and the verifier,
//!   and `fstp_witness` for the sender rule and the witness core. Its
//!   `may_commit`, `after_commit` and `resolve` drive the production
//!   anchorer step function, `fstp_audit::anchorer::Anchorer`, through
//!   design section 5.3 up to COMMIT. The model's own steps are W1e's and
//!   stay unchanged. `Production::verify_opaque` passes the signatures
//!   and keys of [`OpaqueSigs`], the ledger, the link column and the
//!   witness log, and maps `Ok` and `Tamper` to answers.
//! - Lane W2g closed its last three seams once Daniel accepted the
//!   ADR-010 composite encoding table on 2026-10-29. [`prod_sign_anchor`]
//!   and [`prod_sign_receipt`] return production composite signatures,
//!   and `fstp_audit::verify` checks every signature. [`ANCHOR_SIGN_SEAM`],
//!   [`RECEIPT_SIGN_SEAM`] and [`VERIFY_SEAM`] now name only a refusal
//!   that the model never provokes, so each stops a run as a backend that
//!   did not answer.
//! - Lane dsa merged on 2026-10-29. Its two seams are gone:
//!   `fstp_crypto::composite::generate` succeeds, and
//!   [`prod_composite_public_key`] returns `key.public_key().to_bytes()`.
//! - W2e replaces [`STORE_SEAM`]. W2f replaces [`KEY_OPS_SEAM`]. W2f and
//!   W1a replace [`RECONCILE_SEAM`].

use fstp_audit::chain::{self as pchain, ChainRow, Link, RowKind};
use fstp_audit::{AuditError, CellId, ChainId};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::reference::audit::{
    self as r, AdmitRefusal, AfterCommit, Attempt, CellBytes, CommitOutcome, Hash, KeyRole, Keys,
    Mutation, ReceiptFields, RefAnchorRow, RefChain, RefChainView, RefKeyOp, RefLedgerEntry, RefOp,
    RefPrepare, RefPublicKey, RefRowKind, RefSender, RefSig, RefWitnessRecord, RefWitnessState,
    Resolution, RowSpec, SigCheck, SymAnchorRow, SymChain, SymStore, SymWitnessRecord,
    WitnessRefusal, test_encoding as enc,
};
use crate::reference::hybrid::OracleError;

// ---------------------------------------------------------------------------
// Production seams. The harness owns them; each names the lane that
// removes it.

/// Not a seam since lane W2g: `fstp_audit::chain::stored_hash` refused a
/// row, a kind 1 row without its entry or a body over its limit. The model
/// never builds one, so this stops the run as a backend that did not
/// answer.
pub const STORED_HASH_SEAM: &str = "fstp_celltest::mc::audit_model::Production::stored_hash: fstp_audit::chain::stored_hash refused the row (a kind 1 row without its entry, or a body over its limit)";

/// Not a seam since lane W2g: `fstp_audit::verify` checks rows, ledger,
/// anchor rows, the witness log and every signature.
/// `Production::verify_opaque` answers `Ok` and `Tamper`. Any other
/// refusal stops the run as a backend that did not answer, under this
/// name.
pub const VERIFY_SEAM: &str = "fstp_celltest::mc::audit_model::Production::verify: fstp_audit::verify refused with neither Ok nor a tamper";

/// Not a seam since lane W2g: `fstp_audit::anchor::sign_anchor` refused
/// an anchor. It refuses only row 0, which the model never signs, or a
/// failed composite signer. Either stops the run.
pub const ANCHOR_SIGN_SEAM: &str = "fstp_celltest::mc::audit_model::prod_sign_anchor: fstp_audit::anchor::sign_anchor refused (row 0, or the composite signer failed)";

/// Not a seam since lane W2g: `fstp_witness::sign_receipt` refused a
/// receipt. It refuses only row 0 or witness sequence 0, which the model
/// never signs, or a failed composite signer. Either stops the run.
pub const RECEIPT_SIGN_SEAM: &str = "fstp_celltest::mc::audit_model::prod_sign_receipt: fstp_witness::sign_receipt refused (row 0, witness sequence 0, or the composite signer failed)";

/// No crate has the reconciliation task of ADR-004, and neither the
/// `Custody` trait nor the custody simulator's usage log carries a
/// request id (lanes W2f and W1a).
pub const RECONCILE_SEAM: &str = "fstp_celltest::mc::audit_model::prod_reconcile: no reconciliation task exists, and Custody calls and the simulator usage log carry no request id (ADR-004 Reconciliation, lanes W2f and W1a)";

/// `fstp-pgstore` exposes no append that chains ledger entries, so no
/// production chain row of an erasure entry can be read (lane W2e).
pub const STORE_SEAM: &str = "fstp_celltest::mc::audit_model::prod_store_batch: fstp-pgstore exposes no append that writes ledger entries, chain rows and anchor rows (design section 5.3, lane W2e)";

/// No cell keystore makes custody calls with request ids or writes their
/// `KeyOp` events to the chain, and no reader decodes those events (ADR-004
/// Reconciliation, lane W2f).
pub const KEY_OPS_SEAM: &str = "fstp_celltest::mc::audit_model::prod_cell_custody_round: no cell keystore makes custody calls with request ids and writes KeyOp events to its chain, and no reader decodes them (ADR-004 Reconciliation, lane W2f)";

/// A production refusal as `NotImplemented`: the stub's own operation, or
/// `op` for any other refusal, such as a failed composite signer.
fn ni(e: AuditError, op: &'static str) -> NotImplemented {
    match e {
        AuditError::NotImplemented(op) => NotImplemented::new(op),
        AuditError::Tamper(_)
        | AuditError::Decode(_)
        | AuditError::Invalid(_)
        | AuditError::Signing(_) => NotImplemented::new(op),
    }
}

/// The production chain id of `c`.
pub fn prod_chain(c: RefChain) -> ChainId {
    match c {
        RefChain::App => ChainId::App,
        RefChain::Vault => ChainId::Vault,
    }
}

/// The production row kind of `k`.
pub fn prod_kind(k: &RefRowKind) -> RowKind {
    match k {
        RefRowKind::Ledger { seq } => RowKind::Ledger { seq: *seq },
        RefRowKind::Event { body } => RowKind::Event { body: body.clone() },
    }
}

/// A production composite signature over the ADR-010 anchor message,
/// through `fstp_audit::anchor::sign_anchor`, under the anchor context of
/// ADR-010 open point 2. A refusal is [`ANCHOR_SIGN_SEAM`].
pub fn prod_sign_anchor(
    key: &fstp_crypto::composite::CompositeSigningKey,
    cell: CellBytes,
    chain: RefChain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Result<Vec<u8>, NotImplemented> {
    fstp_audit::anchor::sign_anchor(key, CellId(cell), prod_chain(chain), n, &Link(*link), at)
        .map(|a| a.signature)
        .map_err(|e| ni(e, ANCHOR_SIGN_SEAM))
}

/// A production composite signature over the receipt message, through
/// `fstp_witness::sign_receipt`, under the receipt context of ADR-010
/// open point 2. A refusal is [`RECEIPT_SIGN_SEAM`].
pub fn prod_sign_receipt(
    key: &fstp_crypto::composite::CompositeSigningKey,
    cell: CellBytes,
    chain: RefChain,
    receipt: &ReceiptFields,
) -> Result<Vec<u8>, NotImplemented> {
    fstp_witness::sign_receipt(
        key,
        CellId(cell),
        prod_chain(chain),
        &prod_receipt_fields(receipt),
    )
    .map(|r| r.signature)
    .map_err(|_| NotImplemented::new(RECEIPT_SIGN_SEAM))
}

/// The encoded public key `mldsaPK || tradPK` of a production composite
/// key (draft 19 section 4.1, ADR-010). It keeps the `Result` of the other
/// `prod_*` functions, so callers stay unchanged.
pub fn prod_composite_public_key(
    key: &fstp_crypto::composite::CompositeSigningKey,
) -> Result<Vec<u8>, NotImplemented> {
    Ok(key.public_key().to_bytes().to_vec())
}

/// The production reconciliation of a backend usage log with the
/// chain's `KeyOp` events. Refuses with [`RECONCILE_SEAM`].
pub fn prod_reconcile(
    usage: &[RefKeyOp],
    key_ops: &[RefKeyOp],
) -> Result<Vec<RefKeyOp>, NotImplemented> {
    let _ = (usage, key_ops);
    Err(NotImplemented::new(RECONCILE_SEAM))
}

/// A batch of ledger records as the production store wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBatch {
    /// The chain after the append: rows, ledger entries, anchor rows and
    /// the witness log.
    pub chain: SymChain,
    /// The ledger `seq` of each record of the batch, in batch order.
    pub seqs: Vec<u64>,
}

/// Appends `batch` through the production store and anchorer, against a
/// fresh App chain. Refuses with [`STORE_SEAM`].
pub fn prod_store_batch(
    batch: &[fstp_cell_core::CellRecord],
) -> Result<StoredBatch, NotImplemented> {
    let _ = batch;
    Err(NotImplemented::new(STORE_SEAM))
}

/// One custody round of the production cell keystore: the roots it used,
/// and the App chain it wrote with its `KeyOp` records. W2f adds what
/// the `KeyOp` reader needs, such as a content-key handle.
#[derive(Debug)]
pub struct CustodyRound {
    /// The roots the round created, whose usage logs the test reads.
    pub roots: Vec<fstp_custody::RootRef>,
    /// The App chain after the round.
    pub chain: SymChain,
}

/// The production cell keystore creates a root, wraps under it and
/// destroys it, through `sim`. Refuses with [`KEY_OPS_SEAM`].
pub fn prod_cell_custody_round(
    sim: &crate::custody_sim::CustodySim,
) -> Result<CustodyRound, NotImplemented> {
    let _ = sim;
    Err(NotImplemented::new(KEY_OPS_SEAM))
}

/// The `KeyOp` records of `store`, read by the production reader with
/// what `round` holds for it. Refuses with [`KEY_OPS_SEAM`].
///
/// The reader gets the whole store, rows and ledger entries, since the
/// spec leaves open whether a `KeyOp` is a kind 2 event or a ledger
/// record. Design section 3.3 and ADR-004 say "KeyOp audit event".
/// Design section 5.1 also defines `KeyCommand::RecordKeyOp`, a ledger
/// record. The lead settles this with Daniel. Design section 7.1 seals
/// event bodies under the `Ledger` purpose, so either reading needs a
/// content-key handle, which W2f adds to [`CustodyRound`]. The reference
/// reads unsealed kind 2 events.
pub fn prod_key_ops_of_chain(
    round: &CustodyRound,
    store: &SymStore,
) -> Result<Vec<RefKeyOp>, NotImplemented> {
    let _ = (round, store);
    Err(NotImplemented::new(KEY_OPS_SEAM))
}

/// The usage entries of a backend usage page, each with its request id.
/// Refuses with [`RECONCILE_SEAM`]: the simulator's records carry none.
pub fn prod_usage_log(page: &fstp_custody::UsagePage) -> Result<Vec<RefKeyOp>, NotImplemented> {
    let _ = page;
    Err(NotImplemented::new(RECONCILE_SEAM))
}

// ---------------------------------------------------------------------------
// Backends.

/// A verifier's answer: `Ok` when the chain verifies, else the change it
/// reported, as text.
pub type VerifyAnswer = Result<(), String>;

/// The two signatures of one anchor row as a backend's own bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueRowSigs {
    /// The anchor signature.
    pub anchor: Vec<u8>,
    /// The receipt signature.
    pub receipt: Vec<u8>,
}

/// Every signature and key of a view as one backend's own bytes (I-90).
/// A test reads no layout in them. It changes them only by flipping
/// bytes and by splicing in [`OpaqueSigs::other`], as the sweep of
/// `i90_composite_verify.rs` does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueSigs {
    /// The chain's anchor public key history, encoded by the backend.
    pub anchor_keys: Vec<Vec<u8>>,
    /// The pinned witness public keys, encoded by the backend.
    pub witness_keys: Vec<Vec<u8>>,
    /// One entry per row of the view's `anchors`, in order.
    pub anchors: Vec<OpaqueRowSigs>,
    /// One entry per `Prepare` record of the view's witness log, in order.
    pub prepares: Vec<OpaqueRowSigs>,
    /// The same two keys over [`OTHER_MESSAGE`].
    pub other: OpaqueRowSigs,
}

/// The message of [`OpaqueSigs::other`].
pub const OTHER_MESSAGE: &[u8] = b"fstp-celltest audit another message";

/// Not a seam: `fstp_crypto::composite` generated or signed nothing in the
/// production backend. Since lane dsa this means a crypto failure, which
/// stops the run as a backend that did not answer.
pub const PROD_KEYGEN_FAILED: &str = "fstp_celltest::mc::audit_model::Production::sign_view: fstp_crypto::composite key generation or signing failed";

/// The witness core's answer to a prepare.
pub type PrepareAnswer = Result<(RefWitnessState, ReceiptFields), WitnessRefusal>;

/// What M-AUDIT and the I-24 tests ask of a backend.
pub trait AuditBackend {
    /// The genesis link of `cell` and `chain`.
    fn genesis(&self, cell: CellBytes, chain: RefChain) -> Result<Hash, NotImplemented>;

    /// The stored hash of a row.
    fn stored_hash(
        &self,
        at: i64,
        kind: &RefRowKind,
        entry: Option<&RefLedgerEntry>,
    ) -> Result<Hash, NotImplemented>;

    /// The link of row `n` after `prev`, with the row's stored hash.
    #[allow(
        clippy::too_many_arguments,
        reason = "the link inputs of ADR-010, one per field"
    )]
    fn link(
        &self,
        prev: &Hash,
        cell: CellBytes,
        chain: RefChain,
        n: u64,
        at: i64,
        kind: &RefRowKind,
        stored_hash: &Hash,
    ) -> Result<Hash, NotImplemented>;

    /// Whether the witness takes messages for `chain` from `sender`.
    fn accepts_sender(
        &self,
        sender: RefSender,
        cell: CellBytes,
        chain: RefChain,
    ) -> Result<bool, NotImplemented>;

    /// The witness core's answer to a prepare.
    fn witness_prepare(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        p: &RefPrepare,
        received_at: i64,
    ) -> Result<PrepareAnswer, NotImplemented>;

    /// The witness core's answer to an abort.
    fn witness_abort(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented>;

    /// The witness core's answer to an in-doubt record.
    fn witness_in_doubt_absent(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented>;

    /// Whether the anchorer commits, given whether it holds the receipt.
    fn may_commit(&self, receipted: bool) -> Result<bool, NotImplemented>;

    /// The cell's admission of `op` while the witness is up or down.
    fn admit(
        &self,
        op: RefOp,
        witness_up: bool,
    ) -> Result<Result<(), AdmitRefusal>, NotImplemented>;

    /// The anchorer's step after a commit outcome.
    fn after_commit(&self, outcome: CommitOutcome) -> Result<AfterCommit, NotImplemented>;

    /// The anchorer's resolution of an in-doubt prepare.
    fn resolve(
        &self,
        link_at_n: Option<Hash>,
        prepared: &Hash,
    ) -> Result<Resolution, NotImplemented>;

    /// The verifier's answer for `view`, signed with `keys`.
    fn verify(&self, view: &RefChainView, keys: &Keys) -> Result<VerifyAnswer, NotImplemented>;

    /// This backend's own signatures and keys for `view`. Each anchor and
    /// receipt is signed from its fields as they stand, with the
    /// backend's anchor key for the view's chain and its witness key.
    /// The keys never leave the backend.
    fn sign_view(&self, view: &RefChainView, keys: &Keys) -> Result<OpaqueSigs, NotImplemented>;

    /// The verifier's answer for `view`, with every signature and key
    /// read from `sigs` in place of the view's own.
    fn verify_opaque(
        &self,
        view: &RefChainView,
        sigs: &OpaqueSigs,
        keys: &Keys,
    ) -> Result<VerifyAnswer, NotImplemented>;
}

/// `view` with every signature and key replaced by the reference
/// decoding of `sigs`. Bytes that do not decode become an empty
/// signature or key, which never verifies. `None` when `sigs` does not
/// cover the view.
pub fn view_with_opaque_sigs(view: &RefChainView, sigs: &OpaqueSigs) -> Option<RefChainView> {
    let sig = |b: &[u8]| {
        enc::decode_sig(b).unwrap_or(RefSig {
            ed25519: Vec::new(),
            mldsa: Vec::new(),
        })
    };
    let pk = |b: &Vec<u8>| {
        enc::decode_pk(b).unwrap_or(RefPublicKey {
            ed25519: Vec::new(),
            mldsa: Vec::new(),
        })
    };
    let resign = |row: &RefAnchorRow, s: &OpaqueRowSigs| {
        let mut row = row.clone();
        row.anchor.sig = sig(&s.anchor);
        row.receipt.sig = sig(&s.receipt);
        row
    };
    if sigs.anchors.len() != view.anchors.len() {
        return None;
    }
    let anchors = view
        .anchors
        .iter()
        .zip(&sigs.anchors)
        .map(|(row, s)| resign(row, s))
        .collect();
    let mut prepares = sigs.prepares.iter();
    let mut witness = Vec::new();
    for w in &view.witness {
        witness.push(match w {
            RefWitnessRecord::Prepare(row) => {
                RefWitnessRecord::Prepare(resign(row, prepares.next()?))
            }
            other => other.clone(),
        });
    }
    if prepares.next().is_some() {
        return None;
    }
    Some(RefChainView {
        anchors,
        witness,
        anchor_keys: sigs.anchor_keys.iter().map(pk).collect(),
        witness_keys: sigs.witness_keys.iter().map(pk).collect(),
        ..view.clone()
    })
}

/// The anchor and receipt messages of one anchor row.
fn row_messages(row: &RefAnchorRow) -> (Vec<u8>, Vec<u8>) {
    let a = &row.anchor;
    let rc = &row.receipt;
    (
        r::anchor_message(a.cell, a.chain, a.fields.n, &a.fields.link, a.fields.at),
        r::receipt_message(rc.cell, rc.chain, &rc.fields),
    )
}

/// The anchor rows of `view` that [`OpaqueSigs`] covers: its `anchors`,
/// then the `Prepare` records of its witness log.
fn signed_rows(view: &RefChainView) -> (Vec<&RefAnchorRow>, Vec<&RefAnchorRow>) {
    let prepares = view
        .witness
        .iter()
        .filter_map(|w| match w {
            RefWitnessRecord::Prepare(row) => Some(row),
            _ => None,
        })
        .collect();
    (view.anchors.iter().collect(), prepares)
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl AuditBackend for Reference {
    fn genesis(&self, cell: CellBytes, chain: RefChain) -> Result<Hash, NotImplemented> {
        Ok(r::genesis(cell, chain))
    }

    fn stored_hash(
        &self,
        at: i64,
        kind: &RefRowKind,
        entry: Option<&RefLedgerEntry>,
    ) -> Result<Hash, NotImplemented> {
        r::stored_hash(at, kind, entry).ok_or(NotImplemented::new(
            "fstp_celltest::reference::audit::stored_hash: no row bytes for this row",
        ))
    }

    fn link(
        &self,
        prev: &Hash,
        cell: CellBytes,
        chain: RefChain,
        n: u64,
        _at: i64,
        _kind: &RefRowKind,
        stored_hash: &Hash,
    ) -> Result<Hash, NotImplemented> {
        Ok(r::link(prev, cell, chain, n, stored_hash))
    }

    fn accepts_sender(
        &self,
        sender: RefSender,
        cell: CellBytes,
        chain: RefChain,
    ) -> Result<bool, NotImplemented> {
        Ok(r::witness_accepts_sender(sender, cell, chain))
    }

    fn witness_prepare(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        p: &RefPrepare,
        received_at: i64,
    ) -> Result<PrepareAnswer, NotImplemented> {
        Ok(r::witness_prepare(st, cell, chain, sender, p, received_at))
    }

    fn witness_abort(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        Ok(r::witness_abort(st, cell, chain, sender, n, link))
    }

    fn witness_in_doubt_absent(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        Ok(r::witness_in_doubt_absent(st, cell, chain, sender, n, link))
    }

    fn may_commit(&self, receipted: bool) -> Result<bool, NotImplemented> {
        Ok(r::may_commit(receipted))
    }

    fn admit(
        &self,
        op: RefOp,
        witness_up: bool,
    ) -> Result<Result<(), AdmitRefusal>, NotImplemented> {
        Ok(r::admit(op, witness_up))
    }

    fn after_commit(&self, outcome: CommitOutcome) -> Result<AfterCommit, NotImplemented> {
        Ok(r::after_commit(outcome))
    }

    fn resolve(
        &self,
        link_at_n: Option<Hash>,
        prepared: &Hash,
    ) -> Result<Resolution, NotImplemented> {
        Ok(r::resolve_in_doubt(link_at_n, prepared))
    }

    fn verify(&self, view: &RefChainView, keys: &Keys) -> Result<VerifyAnswer, NotImplemented> {
        Ok(r::verify(view, keys)
            .map(|_| ())
            .map_err(|t| format!("{t:?}")))
    }

    fn sign_view(&self, view: &RefChainView, keys: &Keys) -> Result<OpaqueSigs, NotImplemented> {
        let oracle = |_| NotImplemented::new(ORACLE_SIGN_FAILED);
        let anchor_role = KeyRole::Anchor(view.chain);
        let sign_row = |row: &RefAnchorRow| {
            let (amsg, rmsg) = row_messages(row);
            Ok(OpaqueRowSigs {
                anchor: enc::encode_sig(&keys.sign(anchor_role, &amsg).map_err(oracle)?),
                receipt: enc::encode_sig(&keys.sign(KeyRole::Witness, &rmsg).map_err(oracle)?),
            })
        };
        let (anchors, prepares) = signed_rows(view);
        Ok(OpaqueSigs {
            anchor_keys: vec![enc::encode_pk(keys.signer(anchor_role).public())],
            witness_keys: vec![enc::encode_pk(keys.signer(KeyRole::Witness).public())],
            anchors: anchors
                .into_iter()
                .map(sign_row)
                .collect::<Result<_, _>>()?,
            prepares: prepares
                .into_iter()
                .map(sign_row)
                .collect::<Result<_, _>>()?,
            other: OpaqueRowSigs {
                anchor: enc::encode_sig(&keys.sign(anchor_role, OTHER_MESSAGE).map_err(oracle)?),
                receipt: enc::encode_sig(
                    &keys.sign(KeyRole::Witness, OTHER_MESSAGE).map_err(oracle)?,
                ),
            },
        })
    }

    fn verify_opaque(
        &self,
        view: &RefChainView,
        sigs: &OpaqueSigs,
        keys: &Keys,
    ) -> Result<VerifyAnswer, NotImplemented> {
        match view_with_opaque_sigs(view, sigs) {
            Some(v) => self.verify(&v, keys),
            None => Ok(Err("the signatures do not cover the view".to_owned())),
        }
    }
}

/// The reference oracle failed to sign.
const ORACLE_SIGN_FAILED: &str =
    "fstp_celltest::reference::audit::Keys::sign: the aws-lc-rs ML-DSA-65 oracle failed";

/// The production backend: `fstp_audit` for the chain functions, the
/// anchorer core and the verifier, and `fstp_witness` for the witness
/// core (lane W2g).
///
/// Since Daniel accepted the ADR-010 composite encoding table, it signs
/// and checks for real. [`AuditBackend::sign_view`] signs every anchor
/// with `fstp_audit::anchor::sign_anchor` and every receipt with
/// `fstp_witness::sign_receipt`, under the composite keys of
/// [`ProdSigner`]. Then [`AuditBackend::verify_opaque`] runs
/// `fstp_audit::verify` over those signatures and keys, and
/// [`AuditBackend::verify`] reaches it by translation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Production;

/// Which key of [`ProdSigner`] signs a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SignerKey {
    /// The anchor key of every chain.
    Anchor,
    /// The witness key.
    Witness,
}

/// Signatures by key and message.
type SignatureMemo = std::collections::HashMap<(SignerKey, Vec<u8>), Vec<u8>>;

/// The production backend's two composite keys, generated once per
/// process, and every signature made with them, by key and message.
///
/// M-AUDIT verifies many states, and most share their anchors and
/// receipts. Fresh keys and signatures for each call kept the production
/// run going for over an hour in a debug build. With this memo it takes
/// about 20 seconds. A composite signature
/// stays valid for its message and key, so one signature per message
/// serves every view. Every check still runs `fstp_audit::verify` over
/// production signatures. The keys never leave the backend.
struct ProdSigner {
    anchor: fstp_crypto::composite::CompositeSigningKey,
    witness: fstp_crypto::composite::CompositeSigningKey,
    memo: std::sync::Mutex<SignatureMemo>,
}

static PROD_SIGNER: std::sync::OnceLock<Option<ProdSigner>> = std::sync::OnceLock::new();

/// The process's [`ProdSigner`]. A failed key generation is
/// [`PROD_KEYGEN_FAILED`].
fn prod_signer() -> Result<&'static ProdSigner, NotImplemented> {
    PROD_SIGNER
        .get_or_init(|| {
            Some(ProdSigner {
                anchor: fstp_crypto::composite::generate().ok()?,
                witness: fstp_crypto::composite::generate().ok()?,
                memo: std::sync::Mutex::new(std::collections::HashMap::new()),
            })
        })
        .as_ref()
        .ok_or_else(|| NotImplemented::new(PROD_KEYGEN_FAILED))
}

impl ProdSigner {
    /// The signature of `message` under `key`, made by `sign` the first
    /// time only. A refusal is not kept, so it repeats on the next call.
    fn memo(
        &self,
        key: SignerKey,
        message: Vec<u8>,
        sign: impl FnOnce() -> Result<Vec<u8>, NotImplemented>,
    ) -> Result<Vec<u8>, NotImplemented> {
        let slot = (key, message);
        // A poisoned lock only follows a panic in another test thread.
        // The map holds whole entries only, so it stays usable.
        let cached = self
            .memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&slot)
            .cloned();
        if let Some(sig) = cached {
            return Ok(sig);
        }
        let sig = sign()?;
        self.memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(slot, sig.clone());
        Ok(sig)
    }
}

/// Not a seam: the production anchorer core refused a step that the
/// model drives in order. It stops the run as a backend that did not
/// answer.
pub const PROD_ANCHORER_OUT_OF_ORDER: &str = "fstp_celltest::mc::audit_model::Production: fstp_audit::anchorer::Anchorer refused a step driven in order";

/// Not a seam: the production witness core refused for a reason the
/// reference has no variant for (`WrongChain` or `Exhausted`).
pub const PROD_WITNESS_UNMAPPED: &str = "fstp_celltest::mc::audit_model::Production: fstp_witness refused with a reason the reference does not model";

fn anchorer_ni<T>(_: fstp_audit::anchorer::OutOfOrder) -> Result<T, NotImplemented> {
    Err(NotImplemented::new(PROD_ANCHORER_OUT_OF_ORDER))
}

/// A production anchorer core driven through design section 5.3 steps 1
/// to 6 and the prepare of `head`.
fn prepared_anchorer(head: (u64, Link)) -> Result<fstp_audit::anchorer::Anchorer, NotImplemented> {
    use fstp_audit::anchorer::{Anchorer, Step};
    let mut a = Anchorer::new();
    if let Err(e) = a.begin(true) {
        return anchorer_ni(e);
    }
    for step in Step::ALL {
        if let Err(e) = a.step_done(step) {
            return anchorer_ni(e);
        }
    }
    if let Err(e) = a.prepared(head) {
        return anchorer_ni(e);
    }
    Ok(a)
}

/// The prospective head the anchorer seam methods drive. The decisions do
/// not depend on its value.
const DRIVEN_HEAD: (u64, Link) = (1, Link([0xD5; 32]));

/// The receipt for [`DRIVEN_HEAD`].
const DRIVEN_RECEIPT: fstp_audit::ReceiptFields = fstp_audit::ReceiptFields {
    n: DRIVEN_HEAD.0,
    link: DRIVEN_HEAD.1,
    witness_seq: 1,
    witness_link: Link([0xD6; 32]),
    received_at: 0,
};

fn prod_sender(s: RefSender) -> fstp_witness::Sender {
    match s {
        RefSender::CellWitness { cell } => fstp_witness::Sender::CellWitness { cell: CellId(cell) },
        RefSender::VaultWitness { cell } => {
            fstp_witness::Sender::VaultWitness { cell: CellId(cell) }
        }
        RefSender::ControlPlane => fstp_witness::Sender::ControlPlane,
    }
}

fn ref_refusal(r: fstp_witness::Refusal) -> Result<WitnessRefusal, NotImplemented> {
    Ok(match r {
        fstp_witness::Refusal::WrongSender => WitnessRefusal::WrongSender,
        fstp_witness::Refusal::Outstanding => WitnessRefusal::Outstanding,
        fstp_witness::Refusal::NotExtending => WitnessRefusal::NotExtending,
        fstp_witness::Refusal::LinkMismatch => WitnessRefusal::LinkMismatch,
        fstp_witness::Refusal::UnknownPrepare => WitnessRefusal::UnknownPrepare,
        fstp_witness::Refusal::Withdrawn => WitnessRefusal::Withdrawn,
        fstp_witness::Refusal::WrongChain | fstp_witness::Refusal::Exhausted => {
            return Err(NotImplemented::new(PROD_WITNESS_UNMAPPED));
        }
    })
}

/// The production witness core for `cell`'s `chain` in the reference
/// state `st`.
fn prod_witness(
    st: &RefWitnessState,
    cell: CellBytes,
    chain: RefChain,
) -> fstp_witness::ChainWitness {
    let link = |(n, l): (u64, Hash)| (n, Link(l));
    fstp_witness::ChainWitness::resume(
        CellId(cell),
        prod_chain(chain),
        fstp_witness::WitnessState {
            confirmed: link(st.confirmed),
            outstanding: st.outstanding.map(link),
            withdrawn: st.withdrawn.iter().copied().map(link).collect(),
            seq: st.seq,
            head: Link(st.head),
        },
    )
}

/// The reference state of a production witness core.
fn ref_witness_state(w: &fstp_witness::ChainWitness) -> RefWitnessState {
    let s = w.state();
    let hash = |(n, l): (u64, Link)| (n, l.0);
    RefWitnessState {
        confirmed: hash(s.confirmed),
        outstanding: s.outstanding.map(hash),
        withdrawn: s.withdrawn.iter().copied().map(hash).collect(),
        seq: s.seq,
        head: s.head.0,
    }
}

fn ref_receipt(f: &fstp_audit::ReceiptFields) -> ReceiptFields {
    ReceiptFields {
        n: f.n,
        link: f.link.0,
        witness_seq: f.witness_seq,
        witness_link: f.witness_link.0,
        received_at: f.received_at,
    }
}

fn prod_receipt_fields(f: &ReceiptFields) -> fstp_audit::ReceiptFields {
    fstp_audit::ReceiptFields {
        n: f.n,
        link: Link(f.link),
        witness_seq: f.witness_seq,
        witness_link: Link(f.witness_link),
        received_at: f.received_at,
    }
}

fn prod_entry(e: &RefLedgerEntry) -> fstp_audit::StoredEntry {
    fstp_audit::StoredEntry {
        seq: e.seq,
        at: e.at,
        command: e.command,
        schema: e.schema,
        key_ix: e.key_ix,
        body: e.body.clone(),
    }
}

impl AuditBackend for Production {
    fn genesis(&self, cell: CellBytes, chain: RefChain) -> Result<Hash, NotImplemented> {
        Ok(pchain::genesis(CellId(cell), prod_chain(chain)).0)
    }

    fn stored_hash(
        &self,
        at: i64,
        kind: &RefRowKind,
        entry: Option<&RefLedgerEntry>,
    ) -> Result<Hash, NotImplemented> {
        pchain::stored_hash(at, &prod_kind(kind), entry.map(prod_entry).as_ref())
            .map_err(|e| ni(e, STORED_HASH_SEAM))
    }

    fn link(
        &self,
        prev: &Hash,
        cell: CellBytes,
        chain: RefChain,
        n: u64,
        at: i64,
        kind: &RefRowKind,
        stored_hash: &Hash,
    ) -> Result<Hash, NotImplemented> {
        let row = ChainRow {
            n,
            at,
            kind: prod_kind(kind),
            stored_hash: *stored_hash,
        };
        Ok(pchain::link(&Link(*prev), CellId(cell), prod_chain(chain), &row).0)
    }

    fn accepts_sender(
        &self,
        sender: RefSender,
        cell: CellBytes,
        chain: RefChain,
    ) -> Result<bool, NotImplemented> {
        Ok(fstp_witness::accepts_sender(
            prod_sender(sender),
            CellId(cell),
            prod_chain(chain),
        ))
    }

    fn witness_prepare(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        p: &RefPrepare,
        received_at: i64,
    ) -> Result<PrepareAnswer, NotImplemented> {
        let mut w = prod_witness(st, cell, chain);
        // The core reads no signature: the service checks the anchor
        // before it. So the reference prepare's symbolic anchor carries
        // none.
        let prepare = fstp_audit::Prepare {
            prev: (p.prev.0, Link(p.prev.1)),
            stored_hashes: p.stored_hashes.clone(),
            anchor: fstp_audit::Anchor {
                cell: CellId(cell),
                chain: prod_chain(chain),
                n: p.anchor.n,
                link: Link(p.anchor.link),
                at: p.anchor.at,
                signature: Vec::new(),
            },
        };
        match w.prepare(prod_sender(sender), &prepare, received_at) {
            Ok(receipt) => Ok(Ok((ref_witness_state(&w), ref_receipt(&receipt)))),
            Err(refusal) => Ok(Err(ref_refusal(refusal)?)),
        }
    }

    fn witness_abort(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        let mut w = prod_witness(st, cell, chain);
        match w.abort(prod_sender(sender), n, &Link(*link)) {
            Ok(_) => Ok(Ok(ref_witness_state(&w))),
            Err(refusal) => Ok(Err(ref_refusal(refusal)?)),
        }
    }

    fn witness_in_doubt_absent(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        let mut w = prod_witness(st, cell, chain);
        match w.in_doubt_absent(prod_sender(sender), n, &Link(*link)) {
            Ok(_) => Ok(Ok(ref_witness_state(&w))),
            Err(refusal) => Ok(Err(ref_refusal(refusal)?)),
        }
    }

    /// Drives the production anchorer step function through design
    /// section 5.3 to COMMIT: with the receipt, the anchor row is inserted
    /// and COMMIT is allowed; without it, COMMIT is refused.
    fn may_commit(&self, receipted: bool) -> Result<bool, NotImplemented> {
        let mut a = prepared_anchorer(DRIVEN_HEAD)?;
        if receipted {
            if let Err(e) = a.receipt(&DRIVEN_RECEIPT) {
                return anchorer_ni(e);
            }
            if let Err(e) = a.anchor_inserted() {
                return anchorer_ni(e);
            }
        }
        Ok(a.commit_sent().is_ok())
    }

    fn admit(
        &self,
        op: RefOp,
        witness_up: bool,
    ) -> Result<Result<(), AdmitRefusal>, NotImplemented> {
        let op = match op {
            RefOp::Read => fstp_audit::anchorer::Op::Read,
            RefOp::Write => fstp_audit::anchorer::Op::Write,
        };
        Ok(
            fstp_audit::anchorer::admit(op, witness_up).map_err(|e| match e {
                fstp_audit::anchorer::AdmitRefusal::WitnessUnavailable => {
                    AdmitRefusal::WitnessUnavailable
                }
            }),
        )
    }

    /// Drives the production anchorer step function through COMMIT and
    /// reports `outcome` to it.
    fn after_commit(&self, outcome: CommitOutcome) -> Result<AfterCommit, NotImplemented> {
        use fstp_audit::anchorer as a;
        let mut core = prepared_anchorer(DRIVEN_HEAD)?;
        let driven = core
            .receipt(&DRIVEN_RECEIPT)
            .and_then(|()| core.anchor_inserted())
            .and_then(|()| core.commit_sent());
        if let Err(e) = driven {
            return anchorer_ni(e);
        }
        let o = match outcome {
            CommitOutcome::Committed => a::CommitOutcome::Committed,
            CommitOutcome::Failed => a::CommitOutcome::Failed,
            CommitOutcome::Unknown => a::CommitOutcome::Unknown,
        };
        match core.outcome(o) {
            Ok(a::AfterCommit::Done) => Ok(AfterCommit::Done),
            Ok(a::AfterCommit::SendAbort) => Ok(AfterCommit::SendAbort),
            Ok(a::AfterCommit::InDoubt) => Ok(AfterCommit::InDoubt),
            Err(e) => anchorer_ni(e),
        }
    }

    /// Resolves through the production anchorer core in doubt about
    /// `prepared`.
    fn resolve(
        &self,
        link_at_n: Option<Hash>,
        prepared: &Hash,
    ) -> Result<Resolution, NotImplemented> {
        use fstp_audit::anchorer as a;
        let mut core = a::Anchorer::in_doubt((DRIVEN_HEAD.0, Link(*prepared)));
        let at_n = link_at_n.map(Link);
        match core.chain_read(at_n.as_ref()) {
            Ok(a::Resolution::Committed) => Ok(Resolution::Committed),
            Ok(a::Resolution::AbsentRaisePossibleDeletion) => {
                Ok(Resolution::AbsentRaisePossibleDeletion)
            }
            Err(e) => anchorer_ni(e),
        }
    }

    fn verify(&self, view: &RefChainView, keys: &Keys) -> Result<VerifyAnswer, NotImplemented> {
        verify_by_translation(self, view, keys)
    }

    /// Signs with the process's [`ProdSigner`] keys. Each message is
    /// signed once, through `fstp_audit::anchor::sign_anchor` or
    /// `fstp_witness::sign_receipt`, and later views reuse that signature.
    fn sign_view(&self, view: &RefChainView, keys: &Keys) -> Result<OpaqueSigs, NotImplemented> {
        let _ = keys;
        let signer = prod_signer()?;
        let anchor_key = &signer.anchor;
        let witness_key = &signer.witness;
        let sign_row = |row: &RefAnchorRow| {
            let a = &row.anchor;
            let rc = &row.receipt;
            let amsg = fstp_audit::anchor::anchor_message(
                CellId(a.cell),
                prod_chain(a.chain),
                a.fields.n,
                &Link(a.fields.link),
                a.fields.at,
            );
            let rmsg = fstp_audit::anchor::receipt_message(
                CellId(rc.cell),
                prod_chain(rc.chain),
                &prod_receipt_fields(&rc.fields),
            );
            Ok(OpaqueRowSigs {
                anchor: signer.memo(SignerKey::Anchor, amsg, || {
                    prod_sign_anchor(
                        anchor_key,
                        a.cell,
                        a.chain,
                        a.fields.n,
                        &a.fields.link,
                        a.fields.at,
                    )
                })?,
                receipt: signer.memo(SignerKey::Witness, rmsg, || {
                    prod_sign_receipt(witness_key, rc.cell, rc.chain, &rc.fields)
                })?,
            })
        };
        let other = |role: SignerKey, k: &fstp_crypto::composite::CompositeSigningKey| {
            signer.memo(role, OTHER_MESSAGE.to_vec(), || {
                k.sign(OTHER_MESSAGE)
                    .map(|s| s.to_bytes().to_vec())
                    .map_err(|_| NotImplemented::new(PROD_KEYGEN_FAILED))
            })
        };
        let (anchors, prepares) = signed_rows(view);
        Ok(OpaqueSigs {
            anchor_keys: vec![prod_composite_public_key(anchor_key)?],
            witness_keys: vec![prod_composite_public_key(witness_key)?],
            anchors: anchors
                .into_iter()
                .map(sign_row)
                .collect::<Result<_, _>>()?,
            prepares: prepares
                .into_iter()
                .map(sign_row)
                .collect::<Result<_, _>>()?,
            other: OpaqueRowSigs {
                anchor: other(SignerKey::Anchor, anchor_key)?,
                receipt: other(SignerKey::Witness, witness_key)?,
            },
        })
    }

    /// `fstp_audit::verify::verify` over `view`, with every signature and
    /// key read from `sigs`. `Ok` and `Tamper` are answers. Any other
    /// refusal is `NotImplemented` naming [`VERIFY_SEAM`].
    fn verify_opaque(
        &self,
        view: &RefChainView,
        sigs: &OpaqueSigs,
        keys: &Keys,
    ) -> Result<VerifyAnswer, NotImplemented> {
        let _ = keys;
        prod_verify(view, sigs)
    }
}

/// The production anchor row of `row`, signed with `sigs`.
fn prod_anchor_row(row: &RefAnchorRow, sigs: &OpaqueRowSigs) -> fstp_audit::AnchorRow {
    let a = &row.anchor;
    let rc = &row.receipt;
    fstp_audit::AnchorRow {
        anchor: fstp_audit::Anchor {
            cell: CellId(a.cell),
            chain: prod_chain(a.chain),
            n: a.fields.n,
            link: Link(a.fields.link),
            at: a.fields.at,
            signature: sigs.anchor.clone(),
        },
        receipt: fstp_audit::Receipt {
            cell: CellId(rc.cell),
            chain: prod_chain(rc.chain),
            fields: prod_receipt_fields(&rc.fields),
            signature: sigs.receipt.clone(),
        },
    }
}

/// Calls `fstp_audit::verify::verify` over `view` with the signatures and
/// keys of `sigs`, the ledger, the link column and the witness log.
fn prod_verify(view: &RefChainView, sigs: &OpaqueSigs) -> Result<VerifyAnswer, NotImplemented> {
    if sigs.anchors.len() != view.anchors.len() {
        return Ok(Err("the signatures do not cover the view".to_owned()));
    }
    let rows: Vec<fstp_audit::StoredRow> = view
        .rows
        .iter()
        .map(|r| fstp_audit::StoredRow {
            row: ChainRow {
                n: r.n,
                at: r.at,
                kind: prod_kind(&r.kind),
                stored_hash: r.stored_hash,
            },
            link: Link(r.link),
        })
        .collect();
    let ledger: Vec<fstp_audit::StoredEntry> = view.ledger.iter().map(prod_entry).collect();
    let anchors: Vec<fstp_audit::AnchorRow> = view
        .anchors
        .iter()
        .zip(&sigs.anchors)
        .map(|(row, s)| prod_anchor_row(row, s))
        .collect();
    let mut prepares = sigs.prepares.iter();
    let mut witness = Vec::new();
    for w in &view.witness {
        witness.push(match w {
            RefWitnessRecord::Prepare(row) => {
                let Some(s) = prepares.next() else {
                    return Ok(Err("the signatures do not cover the view".to_owned()));
                };
                fstp_audit::WitnessRecord::Prepare(prod_anchor_row(row, s))
            }
            RefWitnessRecord::Abort { n, link } => fstp_audit::WitnessRecord::Abort {
                n: *n,
                link: Link(*link),
            },
            RefWitnessRecord::InDoubtAbsent { n, link } => {
                fstp_audit::WitnessRecord::InDoubtAbsent {
                    n: *n,
                    link: Link(*link),
                }
            }
        });
    }
    if prepares.next().is_some() {
        return Ok(Err("the signatures do not cover the view".to_owned()));
    }
    let v = fstp_audit::ChainView {
        cell: CellId(view.cell),
        chain: prod_chain(view.chain),
        rows: &rows,
        ledger: &ledger,
        anchors: &anchors,
        witness: &witness,
        anchor_keys: &sigs.anchor_keys,
        witness_keys: &sigs.witness_keys,
    };
    match fstp_audit::verify::verify(&v) {
        Ok(_) => Ok(Ok(())),
        Err(AuditError::Tamper(t)) => Ok(Err(format!("{t:?}"))),
        Err(e) => Err(ni(e, VERIFY_SEAM)),
    }
}

/// The verifier's answer for a view of reference signatures, through
/// `b`'s own keys. `b` signs every anchor and receipt of `view` from its
/// fields. Each signature the reference oracle refuses under the view's
/// keys is then replaced by `b`'s signature over [`OTHER_MESSAGE`], so
/// it stays invalid. A key history of several keys collapses to `b`'s
/// one key. Half forgeries are checked layout-free through
/// [`AuditBackend::verify_opaque`] instead.
///
/// # Errors
///
/// `b`'s refusal to sign or verify.
pub fn verify_by_translation<B: AuditBackend + ?Sized>(
    b: &B,
    view: &RefChainView,
    keys: &Keys,
) -> Result<VerifyAnswer, NotImplemented> {
    let mut sigs = b.sign_view(view, keys)?;
    let ok = |pks: &[RefPublicKey], msg: &[u8], sig: &RefSig| {
        pks.iter().any(|k| keys.verifies(k, msg, sig))
    };
    let other = sigs.other.clone();
    let (anchors, prepares) = signed_rows(view);
    let rows = anchors
        .into_iter()
        .zip(sigs.anchors.iter_mut())
        .chain(prepares.into_iter().zip(sigs.prepares.iter_mut()));
    for (row, s) in rows {
        let (amsg, rmsg) = row_messages(row);
        if !ok(&view.anchor_keys, &amsg, &row.anchor.sig) {
            s.anchor.clone_from(&other.anchor);
        }
        if !ok(&view.witness_keys, &rmsg, &row.receipt.sig) {
            s.receipt.clone_from(&other.receipt);
        }
    }
    b.verify_opaque(view, &sigs, keys)
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditDefect {
    /// The verifier skips the comparison with the witness's receipts: it
    /// sees only the anchor rows the cell stores.
    VerifierSkipsReceiptComparison,
    /// The verifier accepts an abort or in-doubt record for a present row.
    AbortAcceptedForPresentRow,
    /// The anchorer commits before it holds the receipt.
    CommitBeforeReceipt,
    /// The anchorer treats a known commit failure as an unknown outcome.
    /// It then raises `PossibleDeletion` where it should send `Abort`.
    FailedCommitTreatedAsInDoubt,
    /// The cell refuses reads as well as writes while the witness is
    /// down.
    ReadsRefusedWhileWitnessDown,
    /// The witness takes an `Abort` or an `InDoubtAbsent` from any
    /// sender, as if the chain's own writer had sent it.
    WithdrawalFromAnySender,
    /// The witness checks the certificate's role only, not the cell
    /// that issued it. Another cell's certificate then writes this
    /// cell's chains, for every message.
    SenderCellIgnored,
    /// With nothing outstanding, the witness takes the prepare's `prev`
    /// on trust instead of comparing it with the confirmed head.
    PrepareOverAnyConfirmedHead,
    /// The witness receipts the anchor's link when the stored hashes do
    /// not recompute to it.
    LinkNotRecomputed,
    /// The witness receipts a prepare that carries no stored hashes.
    EmptyPrepareReceipted,
    /// The anchor verifier accepts a signature when either half verifies
    /// (I-90). It replaces the inner verifier with the reference verifier
    /// under that check, so it is seeded over [`Reference`] only.
    OneHalfAccepted,
}

/// `inner` with one seeded defect.
#[derive(Clone, Copy, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: AuditDefect,
}

impl<B: AuditBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: AuditDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }

    /// The sender the inner backend sees for any message to `cell`.
    fn any_sender(&self, sender: RefSender, cell: CellBytes) -> RefSender {
        if self.defect != AuditDefect::SenderCellIgnored {
            return sender;
        }
        match sender {
            RefSender::CellWitness { .. } => RefSender::CellWitness { cell },
            RefSender::VaultWitness { .. } => RefSender::VaultWitness { cell },
            RefSender::ControlPlane => RefSender::ControlPlane,
        }
    }

    /// The sender the inner backend sees for an abort or an in-doubt
    /// record to `cell`'s `chain`.
    fn withdrawal_sender(&self, sender: RefSender, cell: CellBytes, chain: RefChain) -> RefSender {
        if self.defect != AuditDefect::WithdrawalFromAnySender {
            return self.any_sender(sender, cell);
        }
        RefSender::writer(cell, chain)
    }
}

impl<B: AuditBackend> AuditBackend for Mutant<B> {
    fn genesis(&self, cell: CellBytes, chain: RefChain) -> Result<Hash, NotImplemented> {
        self.inner.genesis(cell, chain)
    }

    fn stored_hash(
        &self,
        at: i64,
        kind: &RefRowKind,
        entry: Option<&RefLedgerEntry>,
    ) -> Result<Hash, NotImplemented> {
        self.inner.stored_hash(at, kind, entry)
    }

    fn link(
        &self,
        prev: &Hash,
        cell: CellBytes,
        chain: RefChain,
        n: u64,
        at: i64,
        kind: &RefRowKind,
        stored_hash: &Hash,
    ) -> Result<Hash, NotImplemented> {
        self.inner.link(prev, cell, chain, n, at, kind, stored_hash)
    }

    fn accepts_sender(
        &self,
        sender: RefSender,
        cell: CellBytes,
        chain: RefChain,
    ) -> Result<bool, NotImplemented> {
        self.inner
            .accepts_sender(self.any_sender(sender, cell), cell, chain)
    }

    fn witness_prepare(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        p: &RefPrepare,
        received_at: i64,
    ) -> Result<PrepareAnswer, NotImplemented> {
        let sender = self.any_sender(sender, cell);
        let mut trusted = st.clone();
        if self.defect == AuditDefect::PrepareOverAnyConfirmedHead && st.outstanding.is_none() {
            trusted.confirmed = p.prev;
        }
        let answer = self
            .inner
            .witness_prepare(&trusted, cell, chain, sender, p, received_at)?;
        let skips = match self.defect {
            AuditDefect::LinkNotRecomputed => !p.stored_hashes.is_empty(),
            AuditDefect::EmptyPrepareReceipted => p.stored_hashes.is_empty(),
            _ => false,
        };
        if skips && matches!(answer, Err(WitnessRefusal::LinkMismatch)) {
            let (n, l) = (p.anchor.n, p.anchor.link);
            return Ok(Ok(r::witness_record_prepare(
                &trusted,
                cell,
                chain,
                n,
                &l,
                received_at,
            )));
        }
        Ok(answer)
    }

    fn witness_abort(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        let sender = self.withdrawal_sender(sender, cell, chain);
        self.inner.witness_abort(st, cell, chain, sender, n, link)
    }

    fn witness_in_doubt_absent(
        &self,
        st: &RefWitnessState,
        cell: CellBytes,
        chain: RefChain,
        sender: RefSender,
        n: u64,
        link: &Hash,
    ) -> Result<Result<RefWitnessState, WitnessRefusal>, NotImplemented> {
        let sender = self.withdrawal_sender(sender, cell, chain);
        self.inner
            .witness_in_doubt_absent(st, cell, chain, sender, n, link)
    }

    fn may_commit(&self, receipted: bool) -> Result<bool, NotImplemented> {
        if self.defect == AuditDefect::CommitBeforeReceipt {
            return Ok(true);
        }
        self.inner.may_commit(receipted)
    }

    fn admit(
        &self,
        op: RefOp,
        witness_up: bool,
    ) -> Result<Result<(), AdmitRefusal>, NotImplemented> {
        if self.defect == AuditDefect::ReadsRefusedWhileWitnessDown && !witness_up {
            return Ok(Err(AdmitRefusal::WitnessUnavailable));
        }
        self.inner.admit(op, witness_up)
    }

    fn after_commit(&self, outcome: CommitOutcome) -> Result<AfterCommit, NotImplemented> {
        if self.defect == AuditDefect::FailedCommitTreatedAsInDoubt
            && outcome == CommitOutcome::Failed
        {
            return Ok(AfterCommit::InDoubt);
        }
        self.inner.after_commit(outcome)
    }

    fn resolve(
        &self,
        link_at_n: Option<Hash>,
        prepared: &Hash,
    ) -> Result<Resolution, NotImplemented> {
        self.inner.resolve(link_at_n, prepared)
    }

    fn verify(&self, view: &RefChainView, keys: &Keys) -> Result<VerifyAnswer, NotImplemented> {
        match self.defect {
            AuditDefect::VerifierSkipsReceiptComparison => self
                .inner
                .verify(&r::without_witness_comparison(view), keys),
            AuditDefect::AbortAcceptedForPresentRow => self
                .inner
                .verify(&r::without_aborts_for_present_rows(view), keys),
            AuditDefect::CommitBeforeReceipt
            | AuditDefect::FailedCommitTreatedAsInDoubt
            | AuditDefect::ReadsRefusedWhileWitnessDown
            | AuditDefect::WithdrawalFromAnySender
            | AuditDefect::SenderCellIgnored
            | AuditDefect::PrepareOverAnyConfirmedHead
            | AuditDefect::LinkNotRecomputed
            | AuditDefect::EmptyPrepareReceipted => self.inner.verify(view, keys),
            AuditDefect::OneHalfAccepted => Ok(one_half_verify(view)),
        }
    }

    fn sign_view(&self, view: &RefChainView, keys: &Keys) -> Result<OpaqueSigs, NotImplemented> {
        self.inner.sign_view(view, keys)
    }

    /// The verifier defects that rewrite the view act on
    /// [`AuditBackend::verify`] only. [`AuditDefect::OneHalfAccepted`]
    /// acts on both.
    fn verify_opaque(
        &self,
        view: &RefChainView,
        sigs: &OpaqueSigs,
        keys: &Keys,
    ) -> Result<VerifyAnswer, NotImplemented> {
        if self.defect == AuditDefect::OneHalfAccepted {
            return Ok(match view_with_opaque_sigs(view, sigs) {
                Some(v) => one_half_verify(&v),
                None => Err("the signatures do not cover the view".to_owned()),
            });
        }
        self.inner.verify_opaque(view, sigs, keys)
    }
}

/// The I-90 teeth check: a signature verifies when either half does.
struct EitherHalf;

impl SigCheck for EitherHalf {
    fn verifies(&self, pk: &RefPublicKey, message: &[u8], sig: &RefSig) -> bool {
        r::either_half_verifies(pk, message, sig)
    }
}

/// The reference verifier under the one-half check.
fn one_half_verify(view: &RefChainView) -> VerifyAnswer {
    r::verify(view, &EitherHalf)
        .map(|_| ())
        .map_err(|t| format!("{t:?}"))
}

/// Numbers and links `specs` after `prev` through `backend`, as
/// `ChainWriter` would. `Ok(None)` when the chain would overflow.
///
/// # Errors
///
/// The backend's `NotImplemented`.
pub fn build_with<B: AuditBackend + ?Sized>(
    backend: &B,
    cell: CellBytes,
    chain: RefChain,
    prev: (u64, Hash),
    seq: u64,
    specs: &[RowSpec],
    at: i64,
) -> Result<Option<Attempt>, NotImplemented> {
    // Each production chain function is asked once before any row, so a
    // stub refuses at its own entry point first.
    let _ = backend.genesis(cell, chain)?;
    let Some(reference) = r::build_attempt(cell, chain, prev, seq, specs, at) else {
        return Ok(None);
    };
    let mut l = prev.1;
    let mut rows = Vec::new();
    for row in &reference.rows {
        let entry = match row.kind {
            RefRowKind::Ledger { seq } => reference.ledger.iter().find(|e| e.seq == seq),
            RefRowKind::Event { .. } => None,
        };
        let sh = backend.stored_hash(row.at, &row.kind, entry)?;
        l = backend.link(&l, cell, chain, row.n, row.at, &row.kind, &sh)?;
        let mut row = row.clone();
        row.stored_hash = sh;
        row.link = l;
        rows.push(row);
    }
    let Some(last) = rows.last() else {
        return Ok(None);
    };
    let anchor = r::AnchorFields {
        n: last.n,
        link: last.link,
        at,
    };
    Ok(Some(Attempt {
        rows,
        ledger: reference.ledger,
        prev,
        anchor,
    }))
}

// ---------------------------------------------------------------------------
// The universe.

/// The cell of the model.
pub const CELL: CellBytes = [0xCE; 16];

/// The first instant of the model, in UTC microseconds.
pub const T0: i64 = 1_800_000_000_000_000;

/// The most append attempts of a run.
pub const MAX_ATTEMPTS: u8 = 3;
/// The most commits of a run.
pub const MAX_COMMITS: usize = 2;

/// The rows of attempt `k`: a ledger entry, an event and a second ledger
/// entry, each naming `k`.
pub fn specs(k: u8) -> [RowSpec; 3] {
    let at = T0.saturating_add(i64::from(k).saturating_mul(10));
    [
        RowSpec::Ledger {
            at,
            command: [k; 16],
            schema: 1,
            key_ix: 0,
            body: vec![0xB0, k],
        },
        RowSpec::Event {
            at: at.saturating_add(1),
            body: vec![0xE0, k],
        },
        RowSpec::Ledger {
            at: at.saturating_add(2),
            command: [k; 16],
            schema: 1,
            key_ix: 1,
            body: vec![0xB1, k],
        },
    ]
}

/// The attacker steps of design section 14.2 over `world`. They modify a
/// row or an entry, delete, insert, reorder and truncate. They also
/// recompute links after a change, forge or duplicate a ledger entry,
/// delete an anchor row, and put an aborted attempt back from the WAL.
/// Forged signatures and
/// single-field changes are swept by `i24_verifier_flags_every_mutation`
/// instead.
pub fn attacks(world: &SymChain) -> Vec<Mutation> {
    let st = &world.store;
    let mut out = Vec::new();
    for i in 0..st.rows.len() {
        out.extend([
            Mutation::RowBody(i),
            Mutation::DeleteRow(i),
            Mutation::DeleteRowRecomputed(i),
            Mutation::SwapRows(i),
            Mutation::ChangeRecomputed(i),
        ]);
    }
    for i in 0..=st.rows.len() {
        out.push(Mutation::InsertRowRecomputed(i));
    }
    for k in 1..=st.rows.len() {
        out.extend([Mutation::Truncate(k), Mutation::TruncateWithAnchors(k)]);
    }
    for j in 0..st.ledger.len() {
        out.extend([Mutation::EntryBody(j), Mutation::DuplicateEntry(j)]);
    }
    for j in 0..=st.ledger.len() {
        out.push(Mutation::InsertEntry(j));
    }
    for a in 0..st.anchors.len() {
        out.push(Mutation::DeleteAnchor(a));
    }
    for x in 0..world.wal.len() {
        out.push(Mutation::ResurrectAborted(x));
    }
    out
}

/// The anchor instant of attempt `k`.
pub fn anchor_at(k: u8) -> i64 {
    T0.saturating_add(i64::from(k).saturating_mul(10))
        .saturating_add(3)
}

// ---------------------------------------------------------------------------
// The model.

/// Where an append attempt stands.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Rows inserted in the open transaction; no prepare sent.
    Built,
    /// The witness receipted the prepare.
    Receipted(ReceiptFields),
    /// Nothing was committed, and the witness holds the prepare: the
    /// cell must abort it.
    NeedAbort,
    /// The commit outcome is unknown. The cell resolves at reconnect.
    InDoubt,
}

/// The append in flight.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pending {
    /// The attempt.
    pub attempt: Attempt,
    /// Where it stands.
    pub phase: Phase,
}

/// A committed batch: its first row and its head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Committed {
    /// The first row number.
    pub first_n: u64,
    /// The head row number.
    pub n: u64,
    /// The head link.
    pub link: Hash,
}

/// The state of M-AUDIT.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuditState {
    /// What the cell's databases, the witness and the WAL hold.
    pub world: SymChain,
    /// The store as the honest cell wrote it. A `PossibleDeletion` that
    /// covers the attack resets it to the store the cell read, since that
    /// alert is the detection.
    pub honest: SymStore,
    /// The append in flight.
    pub pending: Option<Pending>,
    /// The attempts made.
    pub attempts: u8,
    /// The committed batches, in order.
    pub commits: Vec<Committed>,
    /// Whether the witness answers.
    pub witness_up: bool,
    /// Cell crashes so far.
    pub cell_crashes: u8,
    /// Witness crashes so far.
    pub witness_crashes: u8,
    /// The attacker's step, once taken.
    pub attack: Option<Mutation>,
    /// The first row of a `PossibleDeletion` alert.
    pub alert: Option<u64>,
    /// Whether that alert was raised after the attack and names exactly
    /// the rows the attack removed.
    pub alert_covers: bool,
    /// Whether a commit outcome was ever unknown to the cell: COMMIT with
    /// a lost answer, or a crash after the prepare.
    pub unknown_outcome: bool,
    /// Whether an in-doubt prepare resolved as committed (witness).
    pub resolved_committed: bool,
    /// Whether a commit reused an aborted row number (witness).
    pub retried_after_abort: bool,
    /// Whether the witness refused a prepare after the attack (witness).
    pub refused_after_attack: bool,
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

impl AuditState {
    /// Whether no append is in flight.
    pub fn quiescent(&self) -> bool {
        self.pending.is_none()
    }

    /// Whether the stored chain differs from what the honest cell wrote.
    pub fn tampered(&self) -> bool {
        self.world.store != self.honest
    }

    /// Whether a `PossibleDeletion` alert covers the attack: it was
    /// raised after it, and the attack removed exactly the alerted rows.
    pub fn alert_covers_attack(&self) -> bool {
        self.alert_covers
    }
}

/// The action of M-AUDIT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditAction {
    /// The cell admits a write, opens an append and inserts the next
    /// attempt's rows over the head it reads from its store.
    Begin,
    /// The prepare reaches the witness, which answers.
    Prepare,
    /// The witness records the prepare, and its receipt is lost.
    PrepareLost,
    /// The transaction fails before COMMIT is sent.
    FailBeforeCommit,
    /// COMMIT succeeds.
    Commit,
    /// COMMIT returns an error; nothing was committed.
    CommitError,
    /// The outcome of COMMIT is unknown; it did or did not commit.
    CommitUnknown {
        /// Whether the database committed.
        committed: bool,
    },
    /// The cell sends `Abort { n, link }`.
    SendAbort,
    /// The cell crashes and restarts.
    CrashCell,
    /// The cell reads its chain and resolves an in-doubt prepare.
    Resolve,
    /// The witness crashes.
    WitnessDown,
    /// The witness is back.
    WitnessUp,
    /// The attacker's step.
    Attack(Mutation),
}

/// M-AUDIT over a backend.
pub struct AuditModel<B> {
    backend: B,
    keys: Keys,
    chains: Vec<RefChain>,
}

impl<B> std::fmt::Debug for AuditModel<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditModel")
            .field("chains", &self.chains)
            .finish_non_exhaustive()
    }
}

impl<B: AuditBackend> AuditModel<B> {
    /// The model over `backend`, for both chains.
    ///
    /// # Errors
    ///
    /// Refuses when an oracle rejects a test key seed.
    pub fn new(backend: B) -> Result<AuditModel<B>, OracleError> {
        AuditModel::for_chains(backend, &RefChain::ALL)
    }

    /// The model over `backend`, for `chains`.
    ///
    /// # Errors
    ///
    /// Refuses when an oracle rejects a test key seed.
    pub fn for_chains(backend: B, chains: &[RefChain]) -> Result<AuditModel<B>, OracleError> {
        Ok(AuditModel {
            backend,
            keys: Keys::new()?,
            chains: chains.to_vec(),
        })
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The backend's verifier answer for the world of `s`.
    ///
    /// # Errors
    ///
    /// A text naming the operation that did not answer.
    pub fn verify(&self, s: &AuditState) -> Result<VerifyAnswer, String> {
        let view = self
            .keys
            .materialize(&s.world)
            .map_err(|e| format!("materialize: {e}"))?;
        self.backend
            .verify(&view, &self.keys)
            .map_err(|e| format!("the backend did not answer: {}", e.operation))
    }

    fn halted(s: &AuditState, e: NotImplemented) -> AuditState {
        let mut next = s.clone();
        next.halt = Some(e.operation);
        next
    }

    fn begin(&self, s: &AuditState) -> Option<AuditState> {
        if s.pending.is_some() || s.commits.len() >= MAX_COMMITS || s.attempts >= MAX_ATTEMPTS {
            return None;
        }
        match self.backend.admit(RefOp::Write, s.witness_up) {
            Err(e) => return Some(AuditModel::<B>::halted(s, e)),
            Ok(Err(_refused)) => return None,
            Ok(Ok(())) => {}
        }
        // The cell builds over the head it reads from its own store. After
        // an attack that is the tampered head.
        let w = &s.world;
        let built = build_with(
            &self.backend,
            w.cell,
            w.chain,
            w.store.head(w.cell, w.chain),
            w.store.next_seq(),
            &specs(s.attempts),
            anchor_at(s.attempts),
        );
        let mut next = s.clone();
        match built {
            Err(e) => Some(AuditModel::<B>::halted(s, e)),
            Ok(None) => None,
            Ok(Some(attempt)) => {
                next.attempts = s.attempts.saturating_add(1);
                next.pending = Some(Pending {
                    attempt,
                    phase: Phase::Built,
                });
                Some(next)
            }
        }
    }

    fn prepare(&self, s: &AuditState, lost: bool) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        if p.phase != Phase::Built || !s.witness_up {
            return None;
        }
        let w = &s.world;
        let answer = self.backend.witness_prepare(
            &w.witness_state,
            w.cell,
            w.chain,
            w.sender(),
            &p.attempt.prepare(),
            p.attempt.anchor.at,
        );
        let mut next = s.clone();
        match answer {
            Err(e) => Some(AuditModel::<B>::halted(s, e)),
            Ok(Err(_refused)) if lost => None,
            Ok(Err(_refused)) => {
                next.world.wal.push(p.attempt.clone());
                next.pending = None;
                next.refused_after_attack |= s.attack.is_some();
                Some(next)
            }
            Ok(Ok((st, receipt))) => {
                next.world.witness_state = st;
                next.world.witness.push(SymWitnessRecord::Prepare {
                    anchor: p.attempt.anchor,
                    receipt,
                });
                next.pending = Some(Pending {
                    attempt: p.attempt.clone(),
                    phase: if lost {
                        Phase::NeedAbort
                    } else {
                        Phase::Receipted(receipt)
                    },
                });
                Some(next)
            }
        }
    }

    fn commit_rows(next: &mut AuditState, a: &Attempt, receipt: Option<ReceiptFields>) {
        for store in [&mut next.world.store, &mut next.honest] {
            store.rows.extend(a.rows.iter().cloned());
            store.ledger.extend(a.ledger.iter().cloned());
            if let Some(receipt) = receipt {
                store.anchors.push(SymAnchorRow {
                    anchor: a.anchor,
                    receipt,
                    forgery: None,
                });
            }
        }
        let aborted_before = next.world.witness.iter().any(|w| match w {
            SymWitnessRecord::Abort { n, link } => *n == a.anchor.n && *link != a.anchor.link,
            _ => false,
        });
        next.retried_after_abort |= aborted_before;
        next.commits.push(Committed {
            first_n: a.first_n(),
            n: a.anchor.n,
            link: a.anchor.link,
        });
    }

    fn commit(&self, s: &AuditState) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        let receipt = match &p.phase {
            Phase::Receipted(r) => Some(*r),
            Phase::Built => None,
            Phase::NeedAbort | Phase::InDoubt => return None,
        };
        match self.backend.may_commit(receipt.is_some()) {
            Err(e) => return Some(AuditModel::<B>::halted(s, e)),
            Ok(false) => return None,
            Ok(true) => {}
        }
        match self.backend.after_commit(CommitOutcome::Committed) {
            Err(e) => Some(AuditModel::<B>::halted(s, e)),
            Ok(AfterCommit::Done) => {
                let mut next = s.clone();
                AuditModel::<B>::commit_rows(&mut next, &p.attempt, receipt);
                next.pending = None;
                Some(next)
            }
            Ok(_) => Some(AuditModel::<B>::halted(
                s,
                NotImplemented::new("the anchorer did not finish a committed append"),
            )),
        }
    }

    fn failed(
        &self,
        s: &AuditState,
        outcome: CommitOutcome,
        committed: bool,
    ) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        let Phase::Receipted(receipt) = p.phase else {
            return None;
        };
        let mut next = s.clone();
        let phase = match self.backend.after_commit(outcome) {
            Err(e) => return Some(AuditModel::<B>::halted(s, e)),
            Ok(AfterCommit::SendAbort) => Phase::NeedAbort,
            Ok(AfterCommit::InDoubt) => Phase::InDoubt,
            Ok(AfterCommit::Done) => {
                // The anchorer believes an unfinished append is done.
                return Some(AuditModel::<B>::halted(
                    s,
                    NotImplemented::new("the anchorer took a failed commit for a finished one"),
                ));
            }
        };
        if committed {
            AuditModel::<B>::commit_rows(&mut next, &p.attempt, Some(receipt));
        }
        next.unknown_outcome |= outcome == CommitOutcome::Unknown;
        next.pending = Some(Pending {
            attempt: p.attempt.clone(),
            phase,
        });
        Some(next)
    }

    /// The transaction fails before COMMIT. Before the prepare nothing
    /// reached the witness. After the receipt the anchorer decides, as
    /// for a COMMIT error.
    fn fail_before_commit(&self, s: &AuditState) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        match p.phase {
            Phase::Built => {
                let mut next = s.clone();
                next.world.wal.push(p.attempt.clone());
                next.pending = None;
                Some(next)
            }
            Phase::Receipted(_) => self.failed(s, CommitOutcome::Failed, false),
            Phase::NeedAbort | Phase::InDoubt => None,
        }
    }

    fn send_abort(&self, s: &AuditState) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        if p.phase != Phase::NeedAbort || !s.witness_up {
            return None;
        }
        let w = &s.world;
        let a = &p.attempt;
        match self.backend.witness_abort(
            &w.witness_state,
            w.cell,
            w.chain,
            w.sender(),
            a.anchor.n,
            &a.anchor.link,
        ) {
            Err(e) => Some(AuditModel::<B>::halted(s, e)),
            Ok(Err(_)) => None,
            Ok(Ok(st)) => {
                let mut next = s.clone();
                next.world.witness_state = st;
                next.world.witness.push(SymWitnessRecord::Abort {
                    n: a.anchor.n,
                    link: a.anchor.link,
                });
                next.world.wal.push(a.clone());
                next.pending = None;
                Some(next)
            }
        }
    }

    fn crash_cell(s: &AuditState) -> Option<AuditState> {
        if s.cell_crashes >= 1 {
            return None;
        }
        let p = s.pending.as_ref()?;
        let mut next = s.clone();
        next.cell_crashes = s.cell_crashes.saturating_add(1);
        match p.phase {
            Phase::Built => {
                next.world.wal.push(p.attempt.clone());
                next.pending = None;
            }
            Phase::Receipted(_) | Phase::NeedAbort => {
                next.unknown_outcome = true;
                next.pending = Some(Pending {
                    attempt: p.attempt.clone(),
                    phase: Phase::InDoubt,
                });
            }
            Phase::InDoubt => return None,
        }
        Some(next)
    }

    fn resolve(&self, s: &AuditState) -> Option<AuditState> {
        let p = s.pending.as_ref()?;
        if p.phase != Phase::InDoubt || !s.witness_up {
            return None;
        }
        let w = &s.world;
        let a = &p.attempt;
        let mut next = s.clone();
        match self
            .backend
            .resolve(w.store.link_at(a.anchor.n), &a.anchor.link)
        {
            Err(e) => Some(AuditModel::<B>::halted(s, e)),
            Ok(Resolution::Committed) => {
                next.resolved_committed = true;
                next.pending = None;
                Some(next)
            }
            Ok(Resolution::AbsentRaisePossibleDeletion) => {
                match self.backend.witness_in_doubt_absent(
                    &w.witness_state,
                    w.cell,
                    w.chain,
                    w.sender(),
                    a.anchor.n,
                    &a.anchor.link,
                ) {
                    Err(e) => Some(AuditModel::<B>::halted(s, e)),
                    Ok(Err(_)) => None,
                    Ok(Ok(st)) => {
                        next.world.witness_state = st;
                        next.world.witness.push(SymWitnessRecord::InDoubtAbsent {
                            n: a.anchor.n,
                            link: a.anchor.link,
                        });
                        next.world.wal.push(a.clone());
                        next.alert = Some(a.first_n());
                        let covers =
                            s.attack.is_some() && w.store == s.honest.truncated_from(a.first_n());
                        if covers {
                            // The alert reported the deletion. Later
                            // appends are compared with the store the cell
                            // read.
                            next.alert_covers = true;
                            next.honest = w.store.clone();
                        }
                        next.pending = None;
                        Some(next)
                    }
                }
            }
        }
    }

    fn attack(s: &AuditState, m: Mutation) -> Option<AuditState> {
        if s.attack.is_some() {
            return None;
        }
        if let Some(p) = &s.pending
            && p.phase != Phase::InDoubt
        {
            return None;
        }
        let world = r::apply(&s.world, m)?;
        let mut next = s.clone();
        next.world = world;
        next.attack = Some(m);
        Some(next)
    }
}

impl<B: AuditBackend> Model for AuditModel<B> {
    type State = AuditState;
    type Action = AuditAction;

    fn init(&self) -> Vec<AuditState> {
        self.chains
            .iter()
            .map(|c| AuditState {
                world: SymChain::genesis(CELL, *c),
                honest: SymStore::default(),
                pending: None,
                attempts: 0,
                commits: Vec::new(),
                witness_up: true,
                cell_crashes: 0,
                witness_crashes: 0,
                attack: None,
                alert: None,
                alert_covers: false,
                unknown_outcome: false,
                resolved_committed: false,
                retried_after_abort: false,
                refused_after_attack: false,
                halt: None,
            })
            .collect()
    }

    fn actions(&self, s: &AuditState, out: &mut Vec<AuditAction>) {
        if s.halt.is_some() {
            return;
        }
        out.extend([
            AuditAction::Begin,
            AuditAction::Prepare,
            AuditAction::PrepareLost,
            AuditAction::FailBeforeCommit,
            AuditAction::Commit,
            AuditAction::CommitError,
            AuditAction::CommitUnknown { committed: true },
            AuditAction::CommitUnknown { committed: false },
            AuditAction::SendAbort,
            AuditAction::CrashCell,
            AuditAction::Resolve,
            AuditAction::WitnessDown,
            AuditAction::WitnessUp,
        ]);
        if s.attack.is_none() {
            for m in attacks(&s.world) {
                out.push(AuditAction::Attack(m));
            }
        }
    }

    fn step(&self, s: &AuditState, a: &AuditAction) -> Option<AuditState> {
        match *a {
            AuditAction::Begin => self.begin(s),
            AuditAction::Prepare => self.prepare(s, false),
            AuditAction::PrepareLost => self.prepare(s, true),
            AuditAction::FailBeforeCommit => self.fail_before_commit(s),
            AuditAction::Commit => self.commit(s),
            AuditAction::CommitError => self.failed(s, CommitOutcome::Failed, false),
            AuditAction::CommitUnknown { committed } => {
                self.failed(s, CommitOutcome::Unknown, committed)
            }
            AuditAction::SendAbort => self.send_abort(s),
            AuditAction::CrashCell => AuditModel::<B>::crash_cell(s),
            AuditAction::Resolve => self.resolve(s),
            AuditAction::WitnessDown => {
                if !s.witness_up || s.witness_crashes >= 1 {
                    return None;
                }
                let mut next = s.clone();
                next.witness_up = false;
                next.witness_crashes = s.witness_crashes.saturating_add(1);
                Some(next)
            }
            AuditAction::WitnessUp => {
                if s.witness_up {
                    return None;
                }
                let mut next = s.clone();
                next.witness_up = true;
                Some(next)
            }
            AuditAction::Attack(m) => AuditModel::<B>::attack(s, m),
        }
    }

    fn is_terminal(&self, s: &AuditState) -> bool {
        s.halt.is_some() || s.quiescent()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-AUDIT.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-24: every change to a committed entry is reported, as a tamper
    /// or as `PossibleDeletion`.
    pub const I24: &str = "I-24";
    /// I-24: every committed batch's head was receipted before commit.
    pub const NO_UNWITNESSED_COMMIT: &str = "no-unwitnessed-commit";
    /// Two-way: an untouched chain verifies, so no tamper is invented.
    pub const TWO_WAY: &str = "two-way";
    /// ADR-010 "Abort": a known commit failure is aborted, so
    /// `PossibleDeletion` is raised only after an unknown outcome.
    pub const ALERT_ONLY_AFTER_UNKNOWN_OUTCOME: &str =
        "possible-deletion-only-after-an-unknown-outcome";
    /// ADR-010 "Witness unavailable": while the witness is down, writes
    /// are refused naming the witness and reads are served.
    pub const WITNESS_DOWN_ADMISSION: &str = "witness-down-refuses-writes-and-serves-reads";
    /// Witness: an abort, then a commit at the same row number.
    pub const W_ABORT_THEN_RETRY: &str = "witness-abort-then-retry-at-the-same-n";
    /// Witness: an in-doubt prepare resolved as committed.
    pub const W_IN_DOUBT_COMMITTED: &str = "witness-in-doubt-resolved-as-committed";
    /// Witness: a deletion reported by `PossibleDeletion` alone.
    pub const W_POSSIBLE_DELETION: &str = "witness-possible-deletion-reports-a-deletion";
    /// Witness: the verifier reports an attack.
    pub const W_TAMPER_REPORTED: &str = "witness-tamper-reported";
    /// Witness: the witness refuses a prepare over a tampered head.
    pub const W_TAMPERED_HEAD_REFUSED: &str = "witness-prepare-over-a-tampered-head-refused";
}

/// The I-24 check of one state.
fn i24<B: AuditBackend>(m: &AuditModel<B>, s: &AuditState) -> Result<(), String> {
    if s.halt.is_some() || !s.quiescent() || !s.tampered() || s.alert_covers_attack() {
        return Ok(());
    }
    match m.verify(s) {
        Err(why) => Err(format!("I-24: {why}")),
        Ok(Err(_tamper)) => Ok(()),
        Ok(Ok(())) => Err(format!(
            "I-24: the attack {:?} on {:?} went unreported",
            s.attack, s.world.chain
        )),
    }
}

/// The two-way check of one state.
fn two_way<B: AuditBackend>(m: &AuditModel<B>, s: &AuditState) -> Result<(), String> {
    if s.halt.is_some() || !s.quiescent() || s.tampered() {
        return Ok(());
    }
    match m.verify(s) {
        Err(why) => Err(format!("two-way: {why}")),
        Ok(Ok(())) => Ok(()),
        Ok(Err(t)) => Err(format!("two-way: an untouched chain was refused: {t}")),
    }
}

/// The admission check of one state: reads are always served, and writes
/// only while the witness is up.
fn admission<B: AuditBackend>(m: &AuditModel<B>, s: &AuditState) -> Result<(), String> {
    for op in RefOp::ALL {
        let want = r::admit(op, s.witness_up);
        match m.backend.admit(op, s.witness_up) {
            Err(e) => {
                return Err(format!(
                    "witness-down: the backend did not answer: {}",
                    e.operation
                ));
            }
            Ok(got) if got == want => {}
            Ok(got) => {
                return Err(format!(
                    "witness-down: {op:?} with the witness up={} answered {got:?}, not {want:?}",
                    s.witness_up
                ));
            }
        }
    }
    Ok(())
}

/// Every property of M-AUDIT.
pub fn properties<B: AuditBackend>(m: &AuditModel<B>) -> Vec<Property<'_, AuditModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &AuditState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::always_with(ids::I24, move |s: &AuditState| i24(m, s)),
        Property::always_with(ids::NO_UNWITNESSED_COMMIT, |s: &AuditState| {
            for c in &s.commits {
                let receipted = s.world.witness.iter().any(|w| match w {
                    SymWitnessRecord::Prepare { anchor, .. } => {
                        anchor.n == c.n && anchor.link == c.link
                    }
                    _ => false,
                });
                if !receipted {
                    return Err(format!(
                        "no-unwitnessed-commit: rows {} to {} committed with no receipt for their head",
                        c.first_n, c.n
                    ));
                }
            }
            Ok(())
        }),
        Property::always_with(ids::TWO_WAY, move |s: &AuditState| two_way(m, s)),
        Property::always_with(
            ids::ALERT_ONLY_AFTER_UNKNOWN_OUTCOME,
            |s: &AuditState| match s.alert {
                Some(first) if !s.unknown_outcome => Err(format!(
                    "{}: PossibleDeletion from row {first} with every commit outcome known",
                    ids::ALERT_ONLY_AFTER_UNKNOWN_OUTCOME
                )),
                _ => Ok(()),
            },
        ),
        Property::always_with(ids::WITNESS_DOWN_ADMISSION, move |s: &AuditState| {
            admission(m, s)
        }),
        Property::reachable(ids::W_ABORT_THEN_RETRY, |s: &AuditState| {
            s.retried_after_abort
        }),
        Property::reachable(ids::W_IN_DOUBT_COMMITTED, |s: &AuditState| {
            s.resolved_committed
        }),
        Property::reachable(ids::W_POSSIBLE_DELETION, |s: &AuditState| {
            s.quiescent() && s.alert_covers_attack()
        }),
        Property::reachable(ids::W_TAMPER_REPORTED, move |s: &AuditState| {
            s.halt.is_none() && s.quiescent() && s.tampered() && matches!(m.verify(s), Ok(Err(_)))
        }),
        Property::reachable(ids::W_TAMPERED_HEAD_REFUSED, |s: &AuditState| {
            s.refused_after_attack
        }),
    ]
}
