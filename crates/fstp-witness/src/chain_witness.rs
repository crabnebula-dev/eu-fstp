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
use fstp_audit::witness::{Prepare, RecordKind, witness_genesis, witness_link};
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
