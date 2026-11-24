//! The pure witness core for one cell and chain (I-24, ADR-010 "Prepare,
//! receipt, commit", "One outstanding prepare per chain", "Abort", "In
//! doubt" and "Witnesses"). It does no I/O.
//!
//! Readings, as in the W1e reference:
//!
//! - The witness checks the sender of every message, not only of a
//!   prepare. A cell certificate binds the cell whose CA issued it.
//! - A prepare names the head it extends and the stored hashes of its
//!   rows, and the witness recomputes the link (ADR-010 open point 3).
//! - A withdrawn `(n, link)` is never receipted again. ADR-010 allows the
//!   same `n` again only "with another link".
//! - Once a later prepare extends a prepared head, that head is confirmed
//!   and can no longer be withdrawn.
//! - A retransmit of the outstanding prepare, after its answer was lost,
//!   gets the receipt the witness gave first, and no new record (reading
//!   of lane W2g). A refusal would leave the cell no way to tell a held
//!   prepare from one never received. ADR-010 refuses a *new* prepare
//!   while one is outstanding, and a retransmit is not new.
//!
//! The core reads no signature. The service runs
//! [`crate::receipt::check_anchor_signature`] before
//! [`ChainWitness::prepare`], and signs the fields it returns with
//! [`crate::receipt::sign_receipt`]. A prepare whose anchor does not
//! verify never reaches the core, and no receipt leaves the witness
//! unsigned.

use std::collections::BTreeSet;

use fstp_audit::anchor::ReceiptFields;
use fstp_audit::chain::genesis;
use fstp_audit::witness::{
    DeclarationFields, Live, MAX_DECLARATIONS, Prepare, RecordKind, WitnessRecord,
    declaration_link, witness_genesis, witness_link,
};
use fstp_audit::{CellId, ChainId, Link};

/// Who sends a message to the witness, by client certificate (ADR-009
/// "Cell CA", ADR-010 "Witnesses").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sender {
    /// A `cell-witness` certificate issued by `cell`'s CA.
    CellWitness {
        /// The issuing cell.
        cell: CellId,
    },
    /// A `vault-witness` certificate issued by `cell`'s CA.
    VaultWitness {
        /// The issuing cell.
        cell: CellId,
    },
    /// A control-plane CA certificate. It never writes a chain.
    ControlPlane,
}

impl Sender {
    /// The writer of `cell`'s `chain`.
    pub const fn writer(cell: CellId, chain: ChainId) -> Sender {
        match chain {
            ChainId::App => Sender::CellWitness { cell },
            ChainId::Vault => Sender::VaultWitness { cell },
        }
    }
}

/// Whether the witness takes messages for `cell`'s `chain` from `sender`:
/// a `cell-witness` certificate only for the App chain of its own cell,
/// and a `vault-witness` certificate only for that cell's Vault chain.
pub fn accepts_sender(sender: Sender, cell: CellId, chain: ChainId) -> bool {
    match (sender, chain) {
        (Sender::CellWitness { cell: from }, ChainId::App)
        | (Sender::VaultWitness { cell: from }, ChainId::Vault) => from == cell,
        _ => false,
    }
}

/// Why the witness refused a message. A refused message changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The sender may not write this cell's chain.
    WrongSender,
    /// The message names another cell or chain than this witness state.
    WrongChain,
    /// Another prepare is outstanding, and this one neither extends it nor
    /// retransmits it.
    Outstanding,
    /// No prepare is outstanding and this one does not extend the last
    /// confirmed head.
    NotExtending,
    /// The prepare has no rows, or its rows do not recompute to the
    /// anchor's `n` and link.
    LinkMismatch,
    /// An abort or in-doubt record names no outstanding prepare.
    UnknownPrepare,
    /// The prepare's `(n, link)` was already withdrawn.
    Withdrawn,
    /// The witness sequence is at `u64::MAX`.
    Exhausted,
}

/// The witness state for one cell and chain. The witness rebuilds it from
/// its store at start-up.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WitnessState {
    /// The last head known committed: extended by a later prepare, or
    /// genesis.
    pub confirmed: (u64, Link),
    /// The outstanding prepare, if any.
    pub outstanding: Option<(u64, Link)>,
    /// The prepares withdrawn by an `Abort` or an `InDoubtAbsent`.
    pub withdrawn: BTreeSet<(u64, Link)>,
    /// The witness sequence of the last record, 0 before the first.
    pub seq: u64,
    /// The witness chain head.
    pub head: Link,
}

/// What the witness appended for a withdrawal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Withdrawal {
    /// The witness sequence of the record.
    pub witness_seq: u64,
    /// The witness chain link after it.
    pub witness_link: Link,
}

/// The witness core for one cell and chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainWitness {
    cell: CellId,
    chain: ChainId,
    state: WitnessState,
    /// The receipt of the outstanding prepare, when this core gave it or
    /// was resumed with it.
    held: Option<ReceiptFields>,
}

impl ChainWitness {
    /// The empty witness for `cell`'s `chain`.
    pub fn genesis(cell: CellId, chain: ChainId) -> ChainWitness {
        ChainWitness {
            cell,
            chain,
            state: WitnessState {
                confirmed: (0, genesis(cell, chain)),
                outstanding: None,
                withdrawn: BTreeSet::new(),
                seq: 0,
                head: witness_genesis(cell, chain),
            },
            held: None,
        }
    }

    /// The witness for `cell`'s `chain` in `state`, as rebuilt from the
    /// store, without the receipt of the outstanding prepare. A
    /// retransmit then gets a receipt rebuilt from the state, with the
    /// retransmit's `received_at` (see [`ChainWitness::prepare`]).
    pub const fn resume(cell: CellId, chain: ChainId, state: WitnessState) -> ChainWitness {
        ChainWitness {
            cell,
            chain,
            state,
            held: None,
        }
    }

    /// The witness for `cell`'s `chain` in `state`, with `held`, the
    /// receipt that the store's last prepare record holds. The service
    /// resumes this way. A receipt that is not for the outstanding
    /// prepare, or not for the last witness record, is dropped.
    pub fn resume_holding(
        cell: CellId,
        chain: ChainId,
        state: WitnessState,
        held: Option<ReceiptFields>,
    ) -> ChainWitness {
        let held = held.filter(|r| {
            state.outstanding == Some((r.n, r.link))
                && r.witness_seq == state.seq
                && r.witness_link == state.head
        });
        ChainWitness {
            cell,
            chain,
            state,
            held,
        }
    }

    /// The receipt of the outstanding prepare `o`, for a retransmit. The
    /// outstanding prepare is always the last witness record, since an
    /// abort or an in-doubt record clears it. So its witness sequence and
    /// link are the state's.
    fn receipt_of_outstanding(&self, o: (u64, Link), received_at: i64) -> ReceiptFields {
        match self.held {
            Some(r) if (r.n, r.link) == o => r,
            _ => ReceiptFields {
                n: o.0,
                link: o.1,
                witness_seq: self.state.seq,
                witness_link: self.state.head,
                received_at,
            },
        }
    }

    /// The cell.
    pub const fn cell(&self) -> CellId {
        self.cell
    }

    /// The chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// The state.
    pub const fn state(&self) -> &WitnessState {
        &self.state
    }

    fn check_sender(&self, sender: Sender) -> Result<(), Refusal> {
        if accepts_sender(sender, self.cell, self.chain) {
            Ok(())
        } else {
            Err(Refusal::WrongSender)
        }
    }

    /// The next witness sequence and link for a record of `kind`.
    fn advance(&self, kind: RecordKind, n: u64, link: &Link) -> Result<(u64, Link), Refusal> {
        let seq = self.state.seq.checked_add(1).ok_or(Refusal::Exhausted)?;
        let head = witness_link(&self.state.head, self.cell, self.chain, kind, seq, n, link);
        Ok((seq, head))
    }

    /// The witness's answer to a prepare received at `received_at`: the
    /// receipt's signed fields. The checks run in this order: the sender,
    /// the cell and chain, the extension rule, the recomputed link, the
    /// withdrawn set. The outstanding prepare, if any, becomes confirmed.
    ///
    /// A retransmit of the outstanding prepare passes the sender and chain
    /// checks, extends the confirmed head and recomputes to the
    /// outstanding `(n, link)`. It gets that prepare's receipt again and
    /// changes nothing. The witness sequence does not rise, so the service
    /// writes no record for it. A core resumed without the receipt
    /// rebuilds it from the state, with this `received_at`.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]. The state is unchanged.
    pub fn prepare(
        &mut self,
        sender: Sender,
        p: &Prepare,
        received_at: i64,
    ) -> Result<ReceiptFields, Refusal> {
        self.check_sender(sender)?;
        if p.anchor.cell != self.cell || p.anchor.chain != self.chain {
            return Err(Refusal::WrongChain);
        }
        if let Some(o) = self.state.outstanding
            && p.prev == self.state.confirmed
            && (p.anchor.n, p.anchor.link) == o
            && p.check_shape().is_ok()
            && p.recomputed_head() == Some(o)
        {
            return Ok(self.receipt_of_outstanding(o, received_at));
        }
        let expected = self.state.outstanding.unwrap_or(self.state.confirmed);
        if p.prev != expected {
            return Err(if self.state.outstanding.is_some() {
                Refusal::Outstanding
            } else {
                Refusal::NotExtending
            });
        }
        p.check_shape().map_err(|_| Refusal::LinkMismatch)?;
        let head = p.recomputed_head().ok_or(Refusal::LinkMismatch)?;
        if head != (p.anchor.n, p.anchor.link) {
            return Err(Refusal::LinkMismatch);
        }
        if self.state.withdrawn.contains(&head) {
            return Err(Refusal::Withdrawn);
        }
        let (seq, witness_head) = self.advance(RecordKind::Prepare, head.0, &head.1)?;
        if let Some(o) = self.state.outstanding {
            self.state.confirmed = o;
        }
        self.state.outstanding = Some(head);
        self.state.seq = seq;
        self.state.head = witness_head;
        let receipt = ReceiptFields {
            n: head.0,
            link: head.1,
            witness_seq: seq,
            witness_link: witness_head,
            received_at,
        };
        self.held = Some(receipt);
        Ok(receipt)
    }

    fn withdraw(
        &mut self,
        sender: Sender,
        kind: RecordKind,
        n: u64,
        link: &Link,
    ) -> Result<Withdrawal, Refusal> {
        self.check_sender(sender)?;
        if self.state.outstanding != Some((n, *link)) {
            return Err(Refusal::UnknownPrepare);
        }
        let (seq, head) = self.advance(kind, n, link)?;
        self.state.outstanding = None;
        self.held = None;
        self.state.withdrawn.insert((n, *link));
        self.state.seq = seq;
        self.state.head = head;
        Ok(Withdrawal {
            witness_seq: seq,
            witness_link: head,
        })
    }

    /// The witness's answer to `Abort { n, link }`: only the chain's
    /// writer may abort, and only the outstanding prepare.
    ///
    /// # Errors
    ///
    /// [`Refusal::WrongSender`], then [`Refusal::UnknownPrepare`] unless
    /// `(n, link)` is outstanding. The state is unchanged.
    pub fn abort(&mut self, sender: Sender, n: u64, link: &Link) -> Result<Withdrawal, Refusal> {
        self.withdraw(sender, RecordKind::Abort, n, link)
    }

    /// The witness's answer to `InDoubtAbsent { n, link }`, under the
    /// rules of [`ChainWitness::abort`].
    ///
    /// # Errors
    ///
    /// As [`ChainWitness::abort`].
    pub fn in_doubt_absent(
        &mut self,
        sender: Sender,
        n: u64,
        link: &Link,
    ) -> Result<Withdrawal, Refusal> {
        self.withdraw(sender, RecordKind::InDoubtAbsent, n, link)
    }
}

/// Why the witness refused a restore declaration (ADR-012 record of lane
/// m10/declared-restore). A refused declaration changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeclareRefusal {
    /// The head is neither genesis nor a live receipted prepare.
    NotLive,
    /// The chain holds [`MAX_DECLARATIONS`] declarations already.
    TooMany,
    /// The witness sequence is at `u64::MAX`.
    Exhausted,
}

impl ChainWitness {
    /// Records a declared restore of this chain to `head` by `job`,
    /// received at `received_at`, over `log`, the chain's witness log
    /// before it (ADR-012 record of lane m10/declared-restore). It
    /// returns the fields to sign.
    ///
    /// `head` must be genesis or a live prepare of `log`
    /// ([`Live::accepts`]). The lost window runs to the highest live row
    /// beyond it. Afterwards `head` is the confirmed head and nothing is
    /// outstanding, so the next prepare must extend `head`. The withdrawn
    /// set stays, so a withdrawn link is never receipted again.
    ///
    /// The caller is root through the console command. No [`Sender`]
    /// stands for it, since no connection carries a declaration.
    ///
    /// # Errors
    ///
    /// The [`DeclareRefusal`]. The state is unchanged.
    pub fn declare_restore(
        &mut self,
        log: &[WitnessRecord],
        head: (u64, Link),
        job: [u8; 16],
        received_at: i64,
    ) -> Result<DeclarationFields, DeclareRefusal> {
        let live = Live::of(self.cell, self.chain, log);
        if !live.accepts(&head) {
            return Err(DeclareRefusal::NotLive);
        }
        let declared = log
            .iter()
            .filter(|r| matches!(r, WitnessRecord::RestoreDeclared(_)))
            .count();
        if declared >= MAX_DECLARATIONS {
            return Err(DeclareRefusal::TooMany);
        }
        let lost_to = live.lost_to(&head);
        let seq = self
            .state
            .seq
            .checked_add(1)
            .ok_or(DeclareRefusal::Exhausted)?;
        let witness_head = declaration_link(
            &self.state.head,
            self.cell,
            self.chain,
            seq,
            &head,
            lost_to,
            &job,
        );
        self.state.confirmed = head;
        self.state.outstanding = None;
        self.state.seq = seq;
        self.state.head = witness_head;
        self.held = None;
        Ok(DeclarationFields {
            head,
            lost_to,
            job,
            witness_seq: seq,
            witness_link: witness_head,
            received_at,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use fstp_audit::anchor::{Anchor, AnchorRow, Receipt};
    use fstp_audit::chain::link_of;
    use fstp_audit::witness::Declaration;

    use super::*;

    const CELL: CellId = CellId([4; 16]);

    fn prepare_of(prev: (u64, Link), rows: u64) -> Prepare {
        let stored_hashes = (0..rows)
            .map(|i| [u8::try_from(i).unwrap(); 32])
            .collect::<Vec<_>>();
        let mut head = prev;
        for sh in &stored_hashes {
            head = (
                head.0 + 1,
                link_of(&head.1, CELL, ChainId::App, head.0 + 1, sh),
            );
        }
        Prepare {
            prev,
            stored_hashes,
            anchor: Anchor {
                cell: CELL,
                chain: ChainId::App,
                n: head.0,
                link: head.1,
                at: 0,
                signature: Vec::new(),
            },
        }
    }

    fn record(p: &Prepare, f: ReceiptFields) -> WitnessRecord {
        WitnessRecord::Prepare(AnchorRow {
            anchor: p.anchor.clone(),
            receipt: Receipt {
                cell: CELL,
                chain: ChainId::App,
                fields: f,
                signature: Vec::new(),
            },
        })
    }

    /// I-24, ADR-012 record of lane m10/declared-restore: a declaration of
    /// a live head records the lost window and clears the outstanding
    /// prepare. The next prepare must extend the declared head, and a
    /// prepare from the lost tail is refused.
    #[test]
    fn i24_declaration_resets_the_head_the_next_prepare_extends() {
        let writer = Sender::writer(CELL, ChainId::App);
        let mut w = ChainWitness::genesis(CELL, ChainId::App);
        let mut log = Vec::new();
        let p1 = prepare_of(w.state().confirmed, 2);
        let f1 = w.prepare(writer, &p1, 1).unwrap();
        log.push(record(&p1, f1));
        let p2 = prepare_of((f1.n, f1.link), 3);
        let f2 = w.prepare(writer, &p2, 2).unwrap();
        log.push(record(&p2, f2));
        let p3 = prepare_of((f2.n, f2.link), 1);
        let f3 = w.prepare(writer, &p3, 3).unwrap();
        log.push(record(&p3, f3));
        assert_eq!(
            w.clone()
                .declare_restore(&log, (2, Link([0; 32])), [1; 16], 9),
            Err(DeclareRefusal::NotLive)
        );
        let before = w.state().clone();
        let d = w
            .declare_restore(&log, (f1.n, f1.link), [1; 16], 9)
            .unwrap();
        assert_eq!((d.head, d.lost_to, d.witness_seq), ((2, f1.link), 6, 4));
        assert_eq!(d.lost(), Some((3, 6)));
        assert_eq!(w.state().confirmed, (2, f1.link));
        assert_eq!(w.state().outstanding, None);
        assert_ne!(w.state().head, before.head);
        assert_eq!(
            w.prepare(writer, &p3, 10),
            Err(Refusal::NotExtending),
            "the lost tail extends nothing"
        );
        let p4 = prepare_of((f1.n, f1.link), 1);
        let f4 = w.prepare(writer, &p4, 11).unwrap();
        assert_eq!((f4.n, f4.witness_seq), (3, 5));
    }

    /// I-24, ADR-012: a declaration of the outstanding head loses nothing,
    /// genesis may be declared, and the witness refuses the declaration
    /// after the last one a chain may hold.
    #[test]
    fn i24_declaration_of_genesis_and_the_declaration_limit() {
        let writer = Sender::writer(CELL, ChainId::App);
        let mut w = ChainWitness::genesis(CELL, ChainId::App);
        let p1 = prepare_of(w.state().confirmed, 1);
        let f1 = w.prepare(writer, &p1, 1).unwrap();
        let log = vec![record(&p1, f1)];
        let d = w
            .clone()
            .declare_restore(&log, (f1.n, f1.link), [2; 16], 2)
            .unwrap();
        assert_eq!(d.lost(), None);
        let g = (0, fstp_audit::chain::genesis(CELL, ChainId::App));
        let d = w.clone().declare_restore(&log, g, [2; 16], 2).unwrap();
        assert_eq!(d.lost(), Some((1, 1)));
        let full: Vec<WitnessRecord> = (0..MAX_DECLARATIONS)
            .map(|_| {
                WitnessRecord::RestoreDeclared(Declaration {
                    fields: DeclarationFields { lost_to: 0, ..d },
                    signature: Vec::new(),
                })
            })
            .collect();
        assert_eq!(
            w.declare_restore(&full, g, [2; 16], 2),
            Err(DeclareRefusal::TooMany)
        );
    }
}
