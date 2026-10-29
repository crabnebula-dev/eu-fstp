//! Honest chains, their anchor rows and witness log, and attacker
//! mutations with the verdict each must get (I-24, ADR-010 "Verifier").
//!
//! An honest chain follows the strict tail D: every committed batch has a
//! receipted prepare and an anchor row. An aborted batch leaves a prepare
//! and an `Abort` at the witness and no row. An in-doubt batch whose row
//! is missing leaves a prepare and an `InDoubtAbsent`.
//!
//! Readings, as in the W1e reference (`fstp_celltest::reference::audit`):
//!
//! - A kind 1 row's stored hash binds its own columns and its entry's
//!   columns. A changed `at` or stored hash of a kind 1 row may be
//!   reported as `StoredHashMismatch { seq }` or as `Changed { n }`.
//! - Row order, ledger coverage, stored hashes and links need no key. The
//!   verifier reports a change there as a tamper even while the signature
//!   checks refuse.
//! - So does every structural change to the tail, the anchor rows and the
//!   witness log: truncation, a consistent recomputation, an unwitnessed
//!   row, a deleted or changed anchor row, a deleted withdrawal and an
//!   abort of a present head. Each gets its exact tamper, so a missed one
//!   fails whatever the signature state.
//! - Only a changed signature byte needs the signature path. Over
//!   placeholder signatures [`apply`] requires only "never `Ok`" for it,
//!   since the honest chain is unsigned too. Over composite signatures
//!   [`apply_signed`] requires exactly `BadSignature { n }` of its head
//!   (ADR-010 "Verifier").

use fstp_audit::Tamper;
use fstp_prop::Gen;

use super::reference::{self as r, Chain, Entry, Hash, Kind, ReceiptFields, Row, RowCols};

/// A signed anchor as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnchorRec {
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

/// A signed receipt as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptRec {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The signed fields.
    pub(crate) fields: ReceiptFields,
    /// The composite signature bytes.
    pub(crate) signature: Vec<u8>,
}

/// One row of `audit.anchor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnchorRow {
    /// The anchor.
    pub(crate) anchor: AnchorRec,
    /// Its receipt.
    pub(crate) receipt: ReceiptRec,
}

/// One record of the witness log for one cell and chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WitnessRec {
    /// A receipted prepare.
    Prepare(AnchorRow),
    /// An abort of a prepare.
    Abort {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
    /// An in-doubt prepare whose row was missing at reconnect.
    InDoubtAbsent {
        /// The row number.
        n: u64,
        /// The prepared link.
        link: Hash,
    },
}

/// Everything the verifier reads for one cell and chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct View {
    /// The cell.
    pub(crate) cell: [u8; 16],
    /// The chain.
    pub(crate) chain: Chain,
    /// The stored rows, in stored order.
    pub(crate) rows: Vec<Row>,
    /// The stored ledger entries.
    pub(crate) ledger: Vec<Entry>,
    /// The rows of `audit.anchor`.
    pub(crate) anchors: Vec<AnchorRow>,
    /// The witness log, in witness order.
    pub(crate) witness: Vec<WitnessRec>,
    /// The anchor public key history.
    pub(crate) anchor_keys: Vec<Vec<u8>>,
    /// The pinned witness public keys.
    pub(crate) witness_keys: Vec<Vec<u8>>,
}

/// How a builder signs anchors and receipts.
pub(crate) enum Sigs {
    /// Zero bytes of the composite signature length. No key verifies them.
    Placeholder,
    /// Real composite signatures over the ADR-010 messages, made in the
    /// test with `fstp_crypto::composite` under the pinned application
    /// contexts `common::ANCHOR_CTX` and `common::RECEIPT_CTX`. The
    /// verifier must accept them.
    Composite {
        /// The chain's anchor key.
        anchor: Box<fstp_crypto::composite::CompositeSigningKey>,
        /// The witness receipt key.
        witness: Box<fstp_crypto::composite::CompositeSigningKey>,
    },
}

impl Sigs {
    /// Two fresh composite keys.
    pub(crate) fn composite() -> Sigs {
        Sigs::Composite {
            anchor: Box::new(fstp_crypto::composite::generate().expect("anchor keygen")),
            witness: Box::new(fstp_crypto::composite::generate().expect("witness keygen")),
        }
    }

    fn sign_anchor(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Sigs::Placeholder => vec![0; fstp_crypto::composite::SIGNATURE_LEN],
            Sigs::Composite { anchor, .. } => super::signing::sign(anchor, msg, super::ANCHOR_CTX),
        }
    }

    fn sign_receipt(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Sigs::Placeholder => vec![0; fstp_crypto::composite::SIGNATURE_LEN],
            Sigs::Composite { witness, .. } => {
                super::signing::sign(witness, msg, super::RECEIPT_CTX)
            }
        }
    }

    fn keys(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        match self {
            Sigs::Placeholder => (
                vec![vec![0; fstp_crypto::composite::PUBLIC_KEY_LEN]],
                vec![vec![0; fstp_crypto::composite::PUBLIC_KEY_LEN]],
            ),
            Sigs::Composite { anchor, witness } => (
                vec![anchor.public_key().to_bytes().to_vec()],
                vec![witness.public_key().to_bytes().to_vec()],
            ),
        }
    }
}

/// One row of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RowSpec {
    /// A ledger entry row. The builder gives it the next `seq`.
    Ledger {
        /// The command id.
        command: [u8; 16],
        /// The schema version.
        schema: u16,
        /// The key index.
        key_ix: u32,
        /// The sealed body.
        body: Vec<u8>,
    },
    /// An event row.
    Event {
        /// The sealed body.
        body: Vec<u8>,
    },
}

/// Builds an honest view batch by batch.
pub(crate) struct Builder {
    view: View,
    sigs: Sigs,
    next_seq: u64,
    witness_seq: u64,
    witness_link: Hash,
}

impl Builder {
    /// An empty chain for `cell` and `chain`.
    pub(crate) fn new(cell: [u8; 16], chain: Chain, sigs: Sigs) -> Builder {
        let (anchor_keys, witness_keys) = sigs.keys();
        Builder {
            view: View {
                cell,
                chain,
                rows: Vec::new(),
                ledger: Vec::new(),
                anchors: Vec::new(),
                witness: Vec::new(),
                anchor_keys,
                witness_keys,
            },
            sigs,
            next_seq: 1,
            witness_seq: 0,
            witness_link: r::sha256(&[b"fstp-audit-test-witness", &cell, &[chain.byte()]]),
        }
    }

    /// The head row number and link.
    pub(crate) fn head(&self) -> (u64, Hash) {
        match self.view.rows.last() {
            Some(row) => (row.cols.n, row.link),
            None => (0, r::genesis(self.view.cell, self.view.chain)),
        }
    }

    /// The rows and entries `specs` would add at `at`.
    fn rows_for(&self, specs: &[RowSpec], at: i64) -> (Vec<Row>, Vec<Entry>) {
        let (mut n, mut prev) = self.head();
        let mut seq = self.next_seq;
        let mut rows = Vec::new();
        let mut entries = Vec::new();
        for spec in specs {
            n += 1;
            let (kind, entry) = match spec {
                RowSpec::Ledger {
                    command,
                    schema,
                    key_ix,
                    body,
                } => {
                    let e = Entry {
                        seq,
                        at,
                        command: *command,
                        schema: *schema,
                        key_ix: *key_ix,
                        body: body.clone(),
                    };
                    seq += 1;
                    (Kind::Ledger { seq: e.seq }, Some(e))
                }
                RowSpec::Event { body } => (Kind::Event { body: body.clone() }, None),
            };
            let sh = r::stored_hash(at, &kind, entry.as_ref()).expect("row bytes");
            let l = r::link(&prev, self.view.cell, self.view.chain, n, &sh);
            rows.push(Row {
                cols: RowCols {
                    n,
                    at,
                    kind,
                    stored_hash: sh,
                },
                link: l,
            });
            entries.extend(entry);
            prev = l;
        }
        (rows, entries)
    }

    fn witness_step(&mut self, tag: u8, n: u64, link: &Hash) {
        self.witness_seq += 1;
        self.witness_link = r::sha256(&[
            &self.witness_link,
            &[tag],
            &self.witness_seq.to_be_bytes(),
            &n.to_be_bytes(),
            link,
        ]);
    }

    /// Prepares the head `(n, link)` at `at` and returns its anchor row.
    fn prepare(&mut self, n: u64, link: Hash, at: i64) -> AnchorRow {
        self.witness_step(1, n, &link);
        let (cell, chain) = (self.view.cell, self.view.chain);
        let fields = ReceiptFields {
            n,
            link,
            witness_seq: self.witness_seq,
            witness_link: self.witness_link,
            received_at: at + 1,
        };
        let row = AnchorRow {
            anchor: AnchorRec {
                cell,
                chain,
                n,
                link,
                at,
                signature: self
                    .sigs
                    .sign_anchor(&r::anchor_message(cell, chain, n, &link, at)),
            },
            receipt: ReceiptRec {
                cell,
                chain,
                fields,
                signature: self
                    .sigs
                    .sign_receipt(&r::receipt_message(cell, chain, &fields)),
            },
        };
        self.view.witness.push(WitnessRec::Prepare(row.clone()));
        row
    }

    /// Prepare, receipt, commit of one batch. An empty batch does nothing.
    pub(crate) fn commit(&mut self, specs: &[RowSpec], at: i64) {
        let (rows, entries) = self.rows_for(specs, at);
        let Some(last) = rows.last() else {
            return;
        };
        let row = self.prepare(last.cols.n, last.link, at);
        self.next_seq += u64::try_from(entries.len()).expect("small batch");
        self.view.rows.extend(rows);
        self.view.ledger.extend(entries);
        self.view.anchors.push(row);
    }

    /// Prepare and receipt of one batch whose COMMIT failed: an `Abort`
    /// follows and no row is stored.
    pub(crate) fn abort(&mut self, specs: &[RowSpec], at: i64) {
        let (rows, _) = self.rows_for(specs, at);
        let Some(last) = rows.last() else {
            return;
        };
        let (n, link) = (last.cols.n, last.link);
        self.prepare(n, link, at);
        self.witness_step(2, n, &link);
        self.view.witness.push(WitnessRec::Abort { n, link });
    }

    /// Prepare and receipt of one batch whose COMMIT outcome was unknown
    /// and whose row was missing at reconnect.
    pub(crate) fn in_doubt_absent(&mut self, specs: &[RowSpec], at: i64) {
        let (rows, _) = self.rows_for(specs, at);
        let Some(last) = rows.last() else {
            return;
        };
        let (n, link) = (last.cols.n, last.link);
        self.prepare(n, link, at);
        self.witness_step(3, n, &link);
        self.view
            .witness
            .push(WitnessRec::InDoubtAbsent { n, link });
    }

    /// The view.
    pub(crate) fn finish(self) -> View {
        self.view
    }
}

/// A random row of a batch.
pub(crate) fn gen_spec(g: &mut Gen) -> RowSpec {
    if g.bool() {
        let mut command = [0u8; 16];
        for b in &mut command {
            *b = g.u8();
        }
        RowSpec::Ledger {
            command,
            schema: g.u16_in(1..=4),
            key_ix: g.u32_in(0..=3),
            body: g.bytes(0..=24),
        }
    } else {
        RowSpec::Event {
            body: g.bytes(0..=24),
        }
    }
}

/// A random honest view: one to three committed batches of one to three
/// rows, with an aborted or in-doubt batch between some of them.
pub(crate) fn gen_view(g: &mut Gen, cell: [u8; 16], chain: Chain, sigs: Sigs) -> View {
    let mut b = Builder::new(cell, chain, sigs);
    let mut at = g.i64_in(1..=1_000_000);
    let batches = g.usize_in(1..=3);
    for _ in 0..batches {
        match g.u8_in(0..=3) {
            0 => {
                let specs = g.vec(1..=2, gen_spec);
                b.abort(&specs, at);
                at += 1;
            }
            1 => {
                let specs = g.vec(1..=2, gen_spec);
                b.in_doubt_absent(&specs, at);
                at += 1;
            }
            _ => {}
        }
        let specs = g.vec(1..=3, gen_spec);
        b.commit(&specs, at);
        at += g.i64_in(1..=1_000);
    }
    b.finish()
}

/// A field of a ledger entry other than `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryField {
    /// `at`.
    At,
    /// The command id.
    Command,
    /// The schema version.
    Schema,
    /// The key index.
    KeyIx,
    /// The sealed body.
    Body,
}

impl EntryField {
    /// Every field.
    pub(crate) const ALL: [EntryField; 5] = [
        EntryField::At,
        EntryField::Command,
        EntryField::Schema,
        EntryField::KeyIx,
        EntryField::Body,
    ];
}

/// One attacker step by a database owner who holds no key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mutation {
    /// Change the `at` column of row `i`.
    RowAt(usize),
    /// Change the body of event row `i`.
    EventBody(usize),
    /// Change the stored hash column of row `i`.
    StoredHashColumn(usize),
    /// Change the link column of row `i`.
    LinkColumn(usize),
    /// Change one field of ledger entry `j`.
    Entry(usize, EntryField),
    /// Delete row `i`.
    DeleteRow(usize),
    /// Swap rows `i` and `i + 1`.
    SwapRows(usize),
    /// Delete ledger entry `j`.
    DeleteEntry(usize),
    /// Store ledger entry `j` twice.
    DuplicateEntry(usize),
    /// Insert a ledger entry no row names.
    ExtraEntry,
    /// Keep the first `k` rows and their entries, and delete the rest.
    TruncateTail(usize),
    /// Change event row `i`, then recompute its stored hash and every link
    /// from it on.
    RecomputeAfterChange(usize),
    /// Append an event row with a correct link that no prepare covers.
    AppendUnwitnessed,
    /// Delete anchor row `k`.
    DeleteAnchorRow(usize),
    /// Change the link of anchor row `k`.
    AnchorRowLink(usize),
    /// Change one byte of anchor row `k`'s anchor signature.
    AnchorSignature(usize),
    /// Change one byte of anchor row `k`'s receipt signature.
    ReceiptSignature(usize),
    /// Delete witness record `w`, an `Abort` or an `InDoubtAbsent`.
    DeleteWithdrawal(usize),
    /// Add an `Abort` at the witness for anchor row `k`'s present head.
    AbortForPresent(usize),
}

/// The verdict a mutated view must get.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// Exactly this tamper.
    Exact(Tamper),
    /// One of these tampers.
    OneOf(Vec<Tamper>),
    /// Some tamper.
    AnyTamper,
    /// Anything but `Ok`, and not a stub refusal.
    NotOk,
}

/// Every mutation that applies to `v`.
pub(crate) fn mutations(v: &View) -> Vec<Mutation> {
    let rows = v.rows.len();
    let mut out = Vec::new();
    for i in 0..rows {
        out.push(Mutation::RowAt(i));
        out.push(Mutation::StoredHashColumn(i));
        out.push(Mutation::LinkColumn(i));
        out.push(Mutation::DeleteRow(i));
        if i + 1 < rows {
            out.push(Mutation::SwapRows(i));
        }
        if matches!(v.rows[i].cols.kind, Kind::Event { .. }) {
            out.push(Mutation::EventBody(i));
            out.push(Mutation::RecomputeAfterChange(i));
        }
    }
    for j in 0..v.ledger.len() {
        for f in EntryField::ALL {
            out.push(Mutation::Entry(j, f));
        }
        out.push(Mutation::DeleteEntry(j));
        out.push(Mutation::DuplicateEntry(j));
    }
    out.push(Mutation::ExtraEntry);
    for k in 0..rows {
        out.push(Mutation::TruncateTail(k));
    }
    out.push(Mutation::AppendUnwitnessed);
    for k in 0..v.anchors.len() {
        out.push(Mutation::DeleteAnchorRow(k));
        out.push(Mutation::AnchorRowLink(k));
        out.push(Mutation::AnchorSignature(k));
        out.push(Mutation::ReceiptSignature(k));
        out.push(Mutation::AbortForPresent(k));
    }
    for (w, rec) in v.witness.iter().enumerate() {
        if !matches!(rec, WitnessRec::Prepare(_)) {
            out.push(Mutation::DeleteWithdrawal(w));
        }
    }
    out
}

fn flip(h: &mut Hash) {
    h[0] ^= 0x01;
}

fn change(body: &mut Vec<u8>) {
    match body.first_mut() {
        Some(b) => *b ^= 0x01,
        None => body.push(0),
    }
}

/// The verdict for a change to row `i`'s own columns.
fn row_column_verdict(row: &Row) -> Expect {
    let n = row.cols.n;
    match row.cols.kind {
        Kind::Ledger { seq } => Expect::OneOf(vec![
            Tamper::StoredHashMismatch { seq },
            Tamper::Changed { n },
        ]),
        Kind::Event { .. } => Expect::Exact(Tamper::Changed { n }),
    }
}

/// Recomputes stored hashes and links from row index `from` on.
fn recompute(v: &mut View, from: usize) {
    let mut prev = if from == 0 {
        r::genesis(v.cell, v.chain)
    } else {
        v.rows[from - 1].link
    };
    for i in from..v.rows.len() {
        let entry = match v.rows[i].cols.kind {
            Kind::Ledger { seq } => v.ledger.iter().find(|e| e.seq == seq).cloned(),
            Kind::Event { .. } => None,
        };
        let c = &v.rows[i].cols;
        let sh = r::stored_hash(c.at, &c.kind, entry.as_ref()).expect("row bytes");
        let l = r::link(&prev, v.cell, v.chain, c.n, &sh);
        v.rows[i].cols.stored_hash = sh;
        v.rows[i].link = l;
        prev = l;
    }
}

/// `v` after `m`, with the verdict it must get. `None` when `m` does not
/// apply.
pub(crate) fn apply(v: &View, m: Mutation) -> Option<(View, Expect)> {
    let mut w = v.clone();
    let expect = match m {
        Mutation::RowAt(i) => {
            w.rows.get_mut(i)?.cols.at += 1;
            row_column_verdict(&v.rows[i])
        }
        Mutation::EventBody(i) => {
            let Kind::Event { body } = &mut w.rows.get_mut(i)?.cols.kind else {
                return None;
            };
            change(body);
            Expect::Exact(Tamper::Changed {
                n: v.rows[i].cols.n,
            })
        }
        Mutation::StoredHashColumn(i) => {
            flip(&mut w.rows.get_mut(i)?.cols.stored_hash);
            row_column_verdict(&v.rows[i])
        }
        Mutation::LinkColumn(i) => {
            flip(&mut w.rows.get_mut(i)?.link);
            Expect::Exact(Tamper::Changed {
                n: v.rows[i].cols.n,
            })
        }
        Mutation::Entry(j, f) => {
            let e = w.ledger.get_mut(j)?;
            match f {
                EntryField::At => e.at += 1,
                EntryField::Command => e.command[0] ^= 0x01,
                EntryField::Schema => e.schema = e.schema.wrapping_add(1),
                EntryField::KeyIx => e.key_ix = e.key_ix.wrapping_add(1),
                EntryField::Body => change(&mut e.body),
            }
            Expect::Exact(Tamper::StoredHashMismatch { seq: e.seq })
        }
        Mutation::DeleteRow(i) => {
            let row = w.rows.get(i)?.clone();
            w.rows.remove(i);
            if i + 1 < v.rows.len() {
                Expect::Exact(Tamper::Gap { n: row.cols.n })
            } else {
                match row.cols.kind {
                    Kind::Ledger { seq } => Expect::Exact(Tamper::LedgerWithoutRow { seq }),
                    // The last anchor row names the lost row.
                    Kind::Event { .. } => Expect::Exact(Tamper::Truncated {
                        witnessed: row.cols.n,
                        have: row.cols.n - 1,
                    }),
                }
            }
        }
        Mutation::SwapRows(i) => {
            if i + 1 >= w.rows.len() {
                return None;
            }
            w.rows.swap(i, i + 1);
            Expect::Exact(Tamper::Reordered {
                n: v.rows[i].cols.n,
            })
        }
        Mutation::DeleteEntry(j) => {
            let e = w.ledger.get(j)?.clone();
            w.ledger.remove(j);
            let n = v
                .rows
                .iter()
                .find(|row| row.cols.kind == Kind::Ledger { seq: e.seq })?
                .cols
                .n;
            Expect::Exact(Tamper::RowWithoutLedger { n })
        }
        Mutation::DuplicateEntry(j) => {
            let e = w.ledger.get(j)?.clone();
            w.ledger.push(e);
            Expect::AnyTamper
        }
        Mutation::ExtraEntry => {
            let seq = v.ledger.iter().map(|e| e.seq).max().unwrap_or(0) + 100;
            w.ledger.push(Entry {
                seq,
                at: 1,
                command: [0x5A; 16],
                schema: 1,
                key_ix: 0,
                body: b"forged".to_vec(),
            });
            Expect::Exact(Tamper::LedgerWithoutRow { seq })
        }
        Mutation::TruncateTail(k) => {
            if k >= w.rows.len() {
                return None;
            }
            let gone: Vec<u64> = w.rows[k..]
                .iter()
                .filter_map(|row| match row.cols.kind {
                    Kind::Ledger { seq } => Some(seq),
                    Kind::Event { .. } => None,
                })
                .collect();
            w.rows.truncate(k);
            w.ledger.retain(|e| !gone.contains(&e.seq));
            // The first anchor row beyond the kept rows.
            let have = u64::try_from(k).ok()?;
            let witnessed = v.anchors.iter().map(|a| a.anchor.n).find(|n| *n > have)?;
            Expect::Exact(Tamper::Truncated { witnessed, have })
        }
        Mutation::RecomputeAfterChange(i) => {
            let Kind::Event { body } = &mut w.rows.get_mut(i)?.cols.kind else {
                return None;
            };
            change(body);
            recompute(&mut w, i);
            // Every link from row i on changed, so the first anchor row at
            // or after it no longer matches the chain.
            let from = v.rows[i].cols.n;
            let n = v.anchors.iter().map(|a| a.anchor.n).find(|n| *n >= from)?;
            Expect::Exact(Tamper::AnchorMismatch { n })
        }
        Mutation::AppendUnwitnessed => {
            let (n, prev) = match v.rows.last() {
                Some(row) => (row.cols.n, row.link),
                None => (0, r::genesis(v.cell, v.chain)),
            };
            let kind = Kind::Event {
                body: b"unwitnessed".to_vec(),
            };
            let at = 2_000_000_000;
            let sh = r::stored_hash(at, &kind, None)?;
            let l = r::link(&prev, v.cell, v.chain, n + 1, &sh);
            w.rows.push(Row {
                cols: RowCols {
                    n: n + 1,
                    at,
                    kind,
                    stored_hash: sh,
                },
                link: l,
            });
            Expect::Exact(Tamper::Unwitnessed { n: n + 1 })
        }
        Mutation::DeleteAnchorRow(k) => {
            let n = w.anchors.get(k)?.anchor.n;
            w.anchors.remove(k);
            // Its prepare at the witness names a present row that has no
            // anchor row.
            Expect::Exact(Tamper::AnchorMismatch { n })
        }
        Mutation::AnchorRowLink(k) => {
            let a = &mut w.anchors.get_mut(k)?.anchor;
            flip(&mut a.link);
            // The anchor no longer matches its own receipt.
            Expect::Exact(Tamper::AnchorMismatch { n: a.n })
        }
        Mutation::AnchorSignature(k) => {
            let s = &mut w.anchors.get_mut(k)?.anchor.signature;
            *s.first_mut()? ^= 0x01;
            Expect::NotOk
        }
        Mutation::ReceiptSignature(k) => {
            let s = &mut w.anchors.get_mut(k)?.receipt.signature;
            *s.first_mut()? ^= 0x01;
            Expect::NotOk
        }
        Mutation::DeleteWithdrawal(i) => {
            let n = match w.witness.get(i)? {
                WitnessRec::Prepare(_) => return None,
                WitnessRec::Abort { n, .. } | WitnessRec::InDoubtAbsent { n, .. } => *n,
            };
            w.witness.remove(i);
            // The prepare it withdrew now has no row and no withdrawal.
            // Inside the chain it reads as deleted, beyond it as a lost
            // tail.
            let have = u64::try_from(v.rows.len()).ok()?;
            if n <= have {
                Expect::Exact(Tamper::Deleted { n })
            } else {
                Expect::Exact(Tamper::Truncated { witnessed: n, have })
            }
        }
        Mutation::AbortForPresent(k) => {
            let a = &v.anchors.get(k)?.anchor;
            w.witness.push(WitnessRec::Abort {
                n: a.n,
                link: a.link,
            });
            Expect::Exact(Tamper::AbortedButPresent { n: a.n })
        }
    };
    Some((w, expect))
}

/// [`apply`] over a view whose anchors and receipts carry composite
/// signatures ([`Sigs::Composite`]). The honest view then verifies, so a
/// changed signature byte of anchor row `k` must get exactly
/// `BadSignature { n }` of its head. Every other verdict is [`apply`]'s.
pub(crate) fn apply_signed(v: &View, m: Mutation) -> Option<(View, Expect)> {
    let (w, expect) = apply(v, m)?;
    let expect = match m {
        Mutation::AnchorSignature(k) | Mutation::ReceiptSignature(k) => {
            Expect::Exact(Tamper::BadSignature {
                n: v.anchors.get(k)?.anchor.n,
            })
        }
        _ => expect,
    };
    Some((w, expect))
}
