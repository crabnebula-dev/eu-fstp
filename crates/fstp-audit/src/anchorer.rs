//! The anchorer core of the strict tail D: prepare, witness receipt,
//! commit (design sections 5.3 and 7.2, ADR-010 "Prepare, receipt,
//! commit").
//!
//! It is sans-IO. The store drives it through one append, step by step,
//! and reports each outcome. The core answers what to do next and refuses
//! every step out of order. The rules it holds:
//!
//! - COMMIT is sent only with the receipt for the prospective head's own
//!   `(n, link)` (`no-unwitnessed-commit`).
//! - The service takes a receipt through [`Anchorer::signed_receipt`]: for
//!   this cell and chain, signed by a pinned witness key. A receipt that
//!   fails that check is never committed on, and the prepare is aborted.
//! - A known failure after the prepare sends `Abort { n, link }`, and no
//!   new append begins until the witness records it, or answers that it
//!   holds no such outstanding prepare.
//! - A prepare the witness refused leaves nothing at the witness, so the
//!   append ends with no abort (W1e M-AUDIT, `AuditModel::prepare`). The
//!   witness answers a retransmit of the prepare it holds with that
//!   prepare's receipt, never with a refusal (`fstp_witness`
//!   `ChainWitness::prepare`). So a refusal never hides a held prepare.
//! - An unknown outcome reads the chain. A row that holds the prepared
//!   link was committed. A missing row first raises `PossibleDeletion`,
//!   which is the detection, and then sends `InDoubtAbsent { n, link }`.
//!   The alert is durable before the witness forgets the prepare, so a
//!   crash between the two cannot lose it.
//! - Without a reachable witness, writes are refused and reads served.
//!
//! A crash loses the core's memory. The restarted cell learns the open
//! prepare from the witness at start-up and resumes with
//! [`Anchorer::in_doubt`] before it serves requests (ADR-010 "Start-up").

use std::future::Future;

use crate::CellId;
use crate::anchor::{Receipt, ReceiptFields, receipt_signature_verifies};
use crate::chain::{ChainId, Link};
use crate::witness::Prepare;

/// A request kind, for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// A request that reads only.
    Read,
    /// A request that appends to a chain.
    Write,
}

/// Why admission refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmitRefusal {
    /// The witness is unreachable. The refusal names it (design risk R8).
    WitnessUnavailable,
}

/// ADR-010 "Witness unavailable": without a reachable witness the cell
/// refuses writes, naming the witness, and keeps serving reads.
///
/// # Errors
///
/// [`AdmitRefusal::WitnessUnavailable`] for a write while the witness is
/// unreachable.
pub fn admit(op: Op, witness_reachable: bool) -> Result<(), AdmitRefusal> {
    match op {
        Op::Read => Ok(()),
        Op::Write if witness_reachable => Ok(()),
        Op::Write => Err(AdmitRefusal::WitnessUnavailable),
    }
}

/// The outcome of COMMIT, as the cell sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitOutcome {
    /// COMMIT succeeded.
    Committed,
    /// The transaction failed before COMMIT was sent, or COMMIT returned
    /// an error. Nothing was committed.
    Failed,
    /// The outcome is unknown: a lost connection or a crash.
    Unknown,
}

/// What the anchorer does after a commit outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AfterCommit {
    /// Nothing more: the committed entry holds its receipt.
    Done,
    /// Send `Abort { n, link }` before the same `n` is prepared again.
    SendAbort,
    /// Read the chain at reconnect or restart, then resolve.
    InDoubt,
}

/// The anchorer's step after `outcome`.
pub const fn after_commit(outcome: CommitOutcome) -> AfterCommit {
    match outcome {
        CommitOutcome::Committed => AfterCommit::Done,
        CommitOutcome::Failed => AfterCommit::SendAbort,
        CommitOutcome::Unknown => AfterCommit::InDoubt,
    }
}

/// How the anchorer resolves an in-doubt prepare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Row `n` holds the prepared link: it committed, and the next
    /// prepare extends it.
    Committed,
    /// The row is missing or holds another link: raise `PossibleDeletion`
    /// to tenant admins and the auditor view, then send
    /// `InDoubtAbsent { n, link }`.
    AbsentRaisePossibleDeletion,
}

/// The resolution of an in-doubt prepare of `prepared`, given the link
/// the chain holds at its row, if any.
pub fn resolve_in_doubt(link_at_n: Option<&Link>, prepared: &Link) -> Resolution {
    if link_at_n == Some(prepared) {
        Resolution::Committed
    } else {
        Resolution::AbsentRaisePossibleDeletion
    }
}

/// Whether COMMIT may be sent for the prospective head `head`: only with
/// a receipt for that same `(n, link)`.
pub fn may_commit(head: (u64, Link), receipt: Option<&ReceiptFields>) -> bool {
    receipt.is_some_and(|r| r.n == head.0 && r.link == head.1)
}

/// A step of one append (design section 5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// 1. `pg_advisory_xact_lock(1)`.
    Lock,
    /// 2. The command id is new.
    CommandCheck,
    /// 3. The head is the expected one.
    HeadCheck,
    /// 4. Ledger entries sealed and inserted.
    SealLedger,
    /// 5. Chain rows inserted.
    InsertChain,
    /// 6. Side-effect rows inserted.
    SideEffects,
}

impl Step {
    /// The steps before the prepare, in order.
    pub const ALL: [Step; 6] = [
        Step::Lock,
        Step::CommandCheck,
        Step::HeadCheck,
        Step::SealLedger,
        Step::InsertChain,
        Step::SideEffects,
    ];

    const fn next(self) -> Option<Step> {
        match self {
            Step::Lock => Some(Step::CommandCheck),
            Step::CommandCheck => Some(Step::HeadCheck),
            Step::HeadCheck => Some(Step::SealLedger),
            Step::SealLedger => Some(Step::InsertChain),
            Step::InsertChain => Some(Step::SideEffects),
            Step::SideEffects => None,
        }
    }
}

/// Where the anchorer stands.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// No append in flight, and nothing to resolve.
    Idle,
    /// The transaction is open. `done` is the last step completed.
    Open {
        /// The last step completed, if any.
        done: Option<Step>,
    },
    /// The prepare of `(n, link)` was sent. No receipt yet.
    Prepared {
        /// The prospective head.
        head: (u64, Link),
    },
    /// The receipt for `head` is held. The anchor row is not inserted yet.
    Receipted {
        /// The prospective head.
        head: (u64, Link),
        /// The receipt.
        receipt: ReceiptFields,
    },
    /// The anchor row is inserted. COMMIT may be sent.
    AnchorInserted {
        /// The prospective head.
        head: (u64, Link),
        /// The receipt.
        receipt: ReceiptFields,
    },
    /// COMMIT was sent. The outcome is not known yet.
    CommitSent {
        /// The prospective head.
        head: (u64, Link),
    },
    /// Nothing was committed. `Abort { n, link }` must be recorded before
    /// any new append.
    MustAbort {
        /// The prepared head.
        head: (u64, Link),
    },
    /// The outcome is unknown. The chain must be read and the prepare
    /// resolved before any new append.
    InDoubt {
        /// The prepared head.
        head: (u64, Link),
    },
    /// The row is missing. `PossibleDeletion` must be raised durably
    /// before `InDoubtAbsent { n, link }` is sent.
    MustRaise {
        /// The prepared head.
        head: (u64, Link),
    },
    /// `PossibleDeletion` is raised. `InDoubtAbsent { n, link }` must be
    /// recorded before any new append.
    MustRecordInDoubt {
        /// The prepared head.
        head: (u64, Link),
    },
}

/// The name of a [`Phase`], without its head and receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PhaseName {
    /// [`Phase::Idle`].
    Idle,
    /// [`Phase::Open`].
    Open,
    /// [`Phase::Prepared`].
    Prepared,
    /// [`Phase::Receipted`].
    Receipted,
    /// [`Phase::AnchorInserted`].
    AnchorInserted,
    /// [`Phase::CommitSent`].
    CommitSent,
    /// [`Phase::MustAbort`].
    MustAbort,
    /// [`Phase::InDoubt`].
    InDoubt,
    /// [`Phase::MustRaise`].
    MustRaise,
    /// [`Phase::MustRecordInDoubt`].
    MustRecordInDoubt,
}

impl Phase {
    /// The name of this phase.
    pub const fn name(&self) -> PhaseName {
        match self {
            Phase::Idle => PhaseName::Idle,
            Phase::Open { .. } => PhaseName::Open,
            Phase::Prepared { .. } => PhaseName::Prepared,
            Phase::Receipted { .. } => PhaseName::Receipted,
            Phase::AnchorInserted { .. } => PhaseName::AnchorInserted,
            Phase::CommitSent { .. } => PhaseName::CommitSent,
            Phase::MustAbort { .. } => PhaseName::MustAbort,
            Phase::InDoubt { .. } => PhaseName::InDoubt,
            Phase::MustRaise { .. } => PhaseName::MustRaise,
            Phase::MustRecordInDoubt { .. } => PhaseName::MustRecordInDoubt,
        }
    }
}

/// A step the core refuses in its current phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfOrder {
    /// The phase the core was in. It is unchanged.
    pub phase: PhaseName,
    /// What was asked.
    pub asked: Asked,
}

/// Why [`Anchorer::signed_receipt`] refused a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRefused {
    /// The step is out of order, or the receipt is for another head. The
    /// phase is unchanged.
    OutOfOrder(OutOfOrder),
    /// The receipt names another cell or chain, or no pinned witness key
    /// verifies its signature. The core must abort the prepare.
    NotSigned,
}

/// What a caller asked of the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// [`Anchorer::begin`].
    Begin,
    /// [`Anchorer::step_done`].
    Step(Step),
    /// [`Anchorer::prepared`].
    Prepare,
    /// [`Anchorer::receipt`].
    Receipt,
    /// [`Anchorer::anchor_inserted`].
    InsertAnchor,
    /// [`Anchorer::commit_sent`].
    Commit,
    /// [`Anchorer::outcome`].
    Outcome,
    /// [`Anchorer::failed`].
    Fail,
    /// [`Anchorer::prepare_refused`].
    PrepareRefused,
    /// [`Anchorer::abort_recorded`].
    AbortRecorded,
    /// [`Anchorer::abort_unknown_at_witness`].
    AbortUnknown,
    /// [`Anchorer::chain_read`].
    ChainRead,
    /// [`Anchorer::possible_deletion_raised`].
    Raised,
    /// [`Anchorer::in_doubt_recorded`].
    InDoubtRecorded,
    /// [`Anchorer::in_doubt_unknown_at_witness`].
    InDoubtUnknown,
}

/// What the store must do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Next {
    /// Nothing: the append is finished, or no append is open.
    Nothing,
    /// Run this step of the open transaction.
    Run(Step),
    /// Send the prepare of the prospective head.
    SendPrepare,
    /// Wait for the receipt of the prepare.
    AwaitReceipt,
    /// Insert the anchor and the receipt into `audit.anchor`.
    InsertAnchor,
    /// Send COMMIT.
    SendCommit,
    /// Wait for the outcome of COMMIT.
    AwaitOutcome,
    /// Send `Abort { n, link }` and wait until the witness records it.
    /// Then call [`Anchorer::abort_recorded`]. When the witness answers
    /// that it holds no outstanding prepare of this head
    /// ([`WitnessFault::UnknownPrepare`]), call
    /// [`Anchorer::abort_unknown_at_witness`] instead.
    SendAbort {
        /// The prepared head.
        head: (u64, Link),
    },
    /// Read the chain at row `n`, then call [`Anchorer::chain_read`].
    ///
    /// The read must see every transaction that may still commit. After
    /// a lost connection the old backend can still be finishing COMMIT.
    /// So the store reads in a new transaction after it takes
    /// `pg_advisory_xact_lock(1)`, which the old transaction holds until
    /// it ends. Reading after the old backend is known to have ended also
    /// serves (W2e obligation). An earlier plain read can miss a row that
    /// then commits.
    ReadChain {
        /// The prepared head.
        head: (u64, Link),
    },
    /// Raise `PossibleDeletion` for `(n, link)` from row `n`, durably, then
    /// call [`Anchorer::possible_deletion_raised`].
    ///
    /// The alert comes before `InDoubtAbsent`, since the row is missing
    /// either way. Once the witness records `InDoubtAbsent` it holds no
    /// open prepare, so a restart would not find the head again. A crash
    /// after the alert and before that record finds the head again, and
    /// raises the same alert a second time. The store keys the alert by
    /// `(n, link)`, so the second raise changes nothing (W2e obligation).
    RaisePossibleDeletion {
        /// The prepared head.
        head: (u64, Link),
    },
    /// Send `InDoubtAbsent { n, link }` and wait until the witness records
    /// it. Then call [`Anchorer::in_doubt_recorded`]. When the witness
    /// answers that it holds no outstanding prepare of this head
    /// ([`WitnessFault::UnknownPrepare`]), an earlier copy of the record
    /// was recorded and only its answer was lost. Call
    /// [`Anchorer::in_doubt_unknown_at_witness`] then. Retrying that
    /// answer would refuse writes for good.
    SendInDoubtAbsent {
        /// The prepared head.
        head: (u64, Link),
    },
}

/// The anchorer core for one chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Anchorer {
    phase: Phase,
}

impl Default for Anchorer {
    fn default() -> Anchorer {
        Anchorer::new()
    }
}

impl Anchorer {
    /// An anchorer with nothing in flight.
    pub const fn new() -> Anchorer {
        Anchorer { phase: Phase::Idle }
    }

    /// An anchorer after a restart, when the witness holds the open
    /// prepare `head`. The chain must be read first (ADR-010 "Start-up").
    pub const fn in_doubt(head: (u64, Link)) -> Anchorer {
        Anchorer {
            phase: Phase::InDoubt { head },
        }
    }

    /// Where the anchorer stands.
    pub const fn phase(&self) -> &Phase {
        &self.phase
    }

    /// What the store must do next.
    pub fn next(&self) -> Next {
        match &self.phase {
            Phase::Idle => Next::Nothing,
            Phase::Open { done: None } => Next::Run(Step::Lock),
            Phase::Open { done: Some(s) } => s.next().map_or(Next::SendPrepare, Next::Run),
            Phase::Prepared { .. } => Next::AwaitReceipt,
            Phase::Receipted { .. } => Next::InsertAnchor,
            Phase::AnchorInserted { .. } => Next::SendCommit,
            Phase::CommitSent { .. } => Next::AwaitOutcome,
            Phase::MustAbort { head } => Next::SendAbort { head: *head },
            Phase::InDoubt { head } => Next::ReadChain { head: *head },
            Phase::MustRaise { head } => Next::RaisePossibleDeletion { head: *head },
            Phase::MustRecordInDoubt { head } => Next::SendInDoubtAbsent { head: *head },
        }
    }

    fn refuse<T>(&self, asked: Asked) -> Result<T, OutOfOrder> {
        Err(OutOfOrder {
            phase: self.phase.name(),
            asked,
        })
    }

    /// Opens an append. Refused while anything is in flight or waits for
    /// an abort or an in-doubt resolution, and for a write that admission
    /// refuses.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless the core is idle and the witness reachable.
    pub fn begin(&mut self, witness_reachable: bool) -> Result<(), OutOfOrder> {
        if self.phase != Phase::Idle || admit(Op::Write, witness_reachable).is_err() {
            return self.refuse(Asked::Begin);
        }
        self.phase = Phase::Open { done: None };
        Ok(())
    }

    /// Records that `step` of the open transaction completed. Steps come
    /// in the order of [`Step::ALL`].
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] for any other step.
    pub fn step_done(&mut self, step: Step) -> Result<(), OutOfOrder> {
        let want = match &self.phase {
            Phase::Open { done: None } => Some(Step::Lock),
            Phase::Open { done: Some(s) } => s.next(),
            _ => None,
        };
        if want != Some(step) {
            return self.refuse(Asked::Step(step));
        }
        self.phase = Phase::Open { done: Some(step) };
        Ok(())
    }

    /// Records that the prepare of the prospective head `head` was sent.
    /// Allowed once every step before it completed.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] in any other phase.
    pub fn prepared(&mut self, head: (u64, Link)) -> Result<(), OutOfOrder> {
        if self.phase
            != (Phase::Open {
                done: Some(Step::SideEffects),
            })
        {
            return self.refuse(Asked::Prepare);
        }
        self.phase = Phase::Prepared { head };
        Ok(())
    }

    /// Records the witness's receipt. It must be for the prepared head's
    /// own `(n, link)`.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] when no prepare waits or the receipt is for another
    /// head. The phase is unchanged.
    pub fn receipt(&mut self, receipt: &ReceiptFields) -> Result<(), OutOfOrder> {
        let Phase::Prepared { head } = self.phase else {
            return self.refuse(Asked::Receipt);
        };
        if !may_commit(head, Some(receipt)) {
            return self.refuse(Asked::Receipt);
        }
        self.phase = Phase::Receipted {
            head,
            receipt: *receipt,
        };
        Ok(())
    }

    /// Records the witness's signed receipt, after checking it. The
    /// receipt must name `cell` and `chain`, and its signature must
    /// verify under one key of `witness_keys`, the witness keys the cell
    /// pins (ADR-010 "Keys", I-90). Then it goes to [`Anchorer::receipt`].
    /// The cell service takes every receipt through this call, never
    /// through [`Anchorer::receipt`] alone (W3a obligation).
    ///
    /// A receipt that fails the check came from no pinned witness, or was
    /// garbled on the way. The witness may still hold the prepare, so the
    /// core moves to [`Phase::MustAbort`], as [`Anchorer::failed`] does.
    /// No COMMIT is sent on it.
    ///
    /// # Errors
    ///
    /// [`ReceiptRefused::OutOfOrder`] when no prepare waits or a verified
    /// receipt is for another head. The phase is unchanged.
    /// [`ReceiptRefused::NotSigned`] when the check fails. The next step
    /// is [`Next::SendAbort`].
    pub fn signed_receipt(
        &mut self,
        cell: CellId,
        chain: ChainId,
        receipt: &Receipt,
        witness_keys: &[Vec<u8>],
    ) -> Result<(), ReceiptRefused> {
        let Phase::Prepared { head } = self.phase else {
            return self
                .refuse(Asked::Receipt)
                .map_err(ReceiptRefused::OutOfOrder);
        };
        if receipt.cell != cell
            || receipt.chain != chain
            || !receipt_signature_verifies(receipt, witness_keys)
        {
            self.phase = Phase::MustAbort { head };
            return Err(ReceiptRefused::NotSigned);
        }
        self.receipt(&receipt.fields)
            .map_err(ReceiptRefused::OutOfOrder)
    }

    /// Records that the anchor and the receipt are inserted into
    /// `audit.anchor` in the open transaction.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless a receipt is held.
    pub fn anchor_inserted(&mut self) -> Result<(), OutOfOrder> {
        let Phase::Receipted { head, receipt } = self.phase else {
            return self.refuse(Asked::InsertAnchor);
        };
        self.phase = Phase::AnchorInserted { head, receipt };
        Ok(())
    }

    /// Records that COMMIT is about to be sent. This is the only way to
    /// [`Phase::CommitSent`], and it needs the receipt and the inserted
    /// anchor row (`no-unwitnessed-commit`).
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] in any other phase: COMMIT must not be sent.
    pub fn commit_sent(&mut self) -> Result<(), OutOfOrder> {
        let Phase::AnchorInserted { head, receipt } = self.phase else {
            return self.refuse(Asked::Commit);
        };
        if !may_commit(head, Some(&receipt)) {
            return self.refuse(Asked::Commit);
        }
        self.phase = Phase::CommitSent { head };
        Ok(())
    }

    /// Records the outcome of COMMIT and answers the next step.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless COMMIT was sent.
    pub fn outcome(&mut self, outcome: CommitOutcome) -> Result<AfterCommit, OutOfOrder> {
        let Phase::CommitSent { head } = self.phase else {
            return self.refuse(Asked::Outcome);
        };
        let after = after_commit(outcome);
        self.phase = match after {
            AfterCommit::Done => Phase::Idle,
            AfterCommit::SendAbort => Phase::MustAbort { head },
            AfterCommit::InDoubt => Phase::InDoubt { head },
        };
        Ok(after)
    }

    /// Records that a statement failed before COMMIT was sent, or that the
    /// prepare's answer was lost ([`WitnessFault::Unreachable`]). Nothing
    /// was committed. Before the prepare nothing reached the witness, so
    /// the append just ends. After it the witness may hold the prepare,
    /// so it must be aborted. A prepare that the witness answered with a
    /// refusal goes to [`Anchorer::prepare_refused`] instead.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] when no transaction is open before COMMIT.
    pub fn failed(&mut self) -> Result<AfterCommit, OutOfOrder> {
        match self.phase {
            Phase::Open { .. } => {
                self.phase = Phase::Idle;
                Ok(AfterCommit::Done)
            }
            Phase::Prepared { head }
            | Phase::Receipted { head, .. }
            | Phase::AnchorInserted { head, .. } => {
                self.phase = Phase::MustAbort { head };
                Ok(AfterCommit::SendAbort)
            }
            _ => self.refuse(Asked::Fail),
        }
    }

    /// Records that the witness answered the prepare with a refusal
    /// ([`WitnessFault::Refused`]). A refused message changes nothing at
    /// the witness. The append ends with no abort, and nothing was
    /// committed (W1e M-AUDIT, `AuditModel::prepare`).
    ///
    /// The witness holds no prepare of this head after any refusal. A
    /// refusal as `Outstanding` names another head: the witness answers
    /// a retransmit of the prepare it holds, after a lost answer, with
    /// that prepare's receipt (`fstp_witness` `ChainWitness::prepare`).
    /// So a retry under [`Next::AwaitReceipt`] goes to
    /// [`Anchorer::receipt`]. Only a refusal that the witness sent counts.
    /// A lost answer goes to [`Anchorer::failed`].
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless a prepare waits for its receipt.
    pub fn prepare_refused(&mut self) -> Result<(), OutOfOrder> {
        let Phase::Prepared { .. } = self.phase else {
            return self.refuse(Asked::PrepareRefused);
        };
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Records that the witness recorded the abort of the prepared head.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless an abort was due.
    pub fn abort_recorded(&mut self) -> Result<(), OutOfOrder> {
        let Phase::MustAbort { .. } = self.phase else {
            return self.refuse(Asked::AbortRecorded);
        };
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Records that the witness refused the abort because it holds no
    /// outstanding prepare of this head ([`WitnessFault::UnknownPrepare`]).
    /// Either the prepare never reached it, or an earlier abort of it was
    /// recorded and only that answer was lost. Nothing was committed and
    /// the witness holds nothing to withdraw, so the append ends.
    ///
    /// The store sends the abort over the connection that carried the
    /// prepare, or after that connection has closed. A delayed prepare then
    /// cannot reach the witness after this answer.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless an abort was due.
    pub fn abort_unknown_at_witness(&mut self) -> Result<(), OutOfOrder> {
        let Phase::MustAbort { .. } = self.phase else {
            return self.refuse(Asked::AbortUnknown);
        };
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Resolves an in-doubt prepare from the link the chain holds at its
    /// row. The store reads under the rule of [`Next::ReadChain`]: in a new
    /// transaction after `pg_advisory_xact_lock(1)`, or after the old
    /// backend has ended. Otherwise a row whose COMMIT was still in flight
    /// reads as absent. The core would then record `InDoubtAbsent` for a
    /// link that appears later.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless a prepare is in doubt.
    pub fn chain_read(&mut self, link_at_n: Option<&Link>) -> Result<Resolution, OutOfOrder> {
        let Phase::InDoubt { head } = self.phase else {
            return self.refuse(Asked::ChainRead);
        };
        let r = resolve_in_doubt(link_at_n, &head.1);
        self.phase = match r {
            Resolution::Committed => Phase::Idle,
            Resolution::AbsentRaisePossibleDeletion => Phase::MustRaise { head },
        };
        Ok(r)
    }

    /// Records that `PossibleDeletion` for the missing row is raised and
    /// durable (ADR-010 "In doubt": "That alert is the detection"). Only
    /// then may `InDoubtAbsent` be sent.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless that alert was due.
    pub fn possible_deletion_raised(&mut self) -> Result<(), OutOfOrder> {
        let Phase::MustRaise { head } = self.phase else {
            return self.refuse(Asked::Raised);
        };
        self.phase = Phase::MustRecordInDoubt { head };
        Ok(())
    }

    /// Records that the witness recorded `InDoubtAbsent` for the missing
    /// row.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless that record was due.
    pub fn in_doubt_recorded(&mut self) -> Result<(), OutOfOrder> {
        let Phase::MustRecordInDoubt { .. } = self.phase else {
            return self.refuse(Asked::InDoubtRecorded);
        };
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Records that the witness refused `InDoubtAbsent` because it holds no
    /// outstanding prepare of this head ([`WitnessFault::UnknownPrepare`]).
    /// The head came from the witness, as its open prepare at start-up or
    /// as a receipt, and only this core withdraws it. So an earlier copy
    /// of the record was recorded and only that answer was lost. The
    /// alert is already raised, so the resolution ends.
    ///
    /// # Errors
    ///
    /// [`OutOfOrder`] unless that record was due.
    pub fn in_doubt_unknown_at_witness(&mut self) -> Result<(), OutOfOrder> {
        let Phase::MustRecordInDoubt { .. } = self.phase else {
            return self.refuse(Asked::InDoubtUnknown);
        };
        self.phase = Phase::Idle;
        Ok(())
    }

    /// The core after a crash and restart, where the witness at start-up
    /// reports `open` as its outstanding prepare for this chain. Before
    /// COMMIT the database rolls back, but the restarted cell cannot know
    /// that, so any reported prepare is in doubt.
    pub fn restart(open: Option<(u64, Link)>) -> Anchorer {
        match open {
            Some(head) => Anchorer::in_doubt(head),
            None => Anchorer::new(),
        }
    }
}

/// Why a witness call gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WitnessFault {
    /// The witness could not be reached, or the answer was lost.
    Unreachable,
    /// The witness refused the message. A refused message changes nothing
    /// at the witness.
    Refused,
    /// The witness refused an abort or an in-doubt record because it holds
    /// no outstanding prepare of that head.
    UnknownPrepare,
}

/// The witness as the anchorer reaches it (design section 5.3). `fstp-cell`
/// and `fstp-vault` implement it over their witness client. The core
/// above decides what to send; this trait only carries it.
pub trait PrepareWitness {
    /// Sends a prepare and waits for its receipt. A retry of a prepare
    /// whose answer was lost gets the receipt the witness gave first.
    fn prepare(&self, p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send;

    /// Sends `Abort { n, link }` for the prepared head and waits until
    /// the witness records it. A witness that holds no outstanding prepare
    /// of `head` answers [`WitnessFault::UnknownPrepare`].
    fn abort(&self, head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send;

    /// Sends `InDoubtAbsent { n, link }` and waits until the witness
    /// records it. A witness that holds no outstanding prepare of `head`
    /// answers [`WitnessFault::UnknownPrepare`]. For a retry, that means
    /// the first copy was recorded, so the store calls
    /// [`Anchorer::in_doubt_unknown_at_witness`].
    fn in_doubt_absent(
        &self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use super::*;
    use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

    fn head(k: u8) -> (u64, Link) {
        (u64::from(k) + 1, Link([k; 32]))
    }

    fn receipt_for(h: (u64, Link)) -> ReceiptFields {
        ReceiptFields {
            n: h.0,
            link: h.1,
            witness_seq: 1,
            witness_link: Link([0xEE; 32]),
            received_at: 0,
        }
    }

    /// One call the store may make, in or out of order.
    #[derive(Clone, Copy, Debug)]
    enum Call {
        Begin(bool),
        Step(Step),
        Prepared(u8),
        Receipt(u8),
        AnchorInserted,
        CommitSent,
        Outcome(CommitOutcome),
        Failed,
        PrepareRefused,
        AbortRecorded,
        AbortUnknown,
        ChainRead(Option<u8>),
        Raised,
        InDoubtRecorded,
        InDoubtUnknown,
    }

    fn gen_call(g: &mut Gen) -> Call {
        match g.u8_in(0..=14) {
            0 => Call::Begin(g.bool()),
            1 => Call::Step(*g.pick(&Step::ALL)),
            2 => Call::Prepared(g.u8_in(0..=2)),
            3 => Call::Receipt(g.u8_in(0..=2)),
            4 => Call::AnchorInserted,
            5 => Call::CommitSent,
            6 => Call::Outcome(*g.pick(&[
                CommitOutcome::Committed,
                CommitOutcome::Failed,
                CommitOutcome::Unknown,
            ])),
            7 => Call::Failed,
            8 => Call::AbortRecorded,
            9 => Call::ChainRead(if g.bool() { None } else { Some(g.u8_in(0..=2)) }),
            10 => Call::PrepareRefused,
            11 => Call::AbortUnknown,
            12 => Call::Raised,
            13 => Call::InDoubtUnknown,
            _ => Call::InDoubtRecorded,
        }
    }

    fn apply(a: &mut Anchorer, c: Call) -> bool {
        match c {
            Call::Begin(up) => a.begin(up).is_ok(),
            Call::Step(s) => a.step_done(s).is_ok(),
            Call::Prepared(k) => a.prepared(head(k)).is_ok(),
            Call::Receipt(k) => a.receipt(&receipt_for(head(k))).is_ok(),
            Call::AnchorInserted => a.anchor_inserted().is_ok(),
            Call::CommitSent => a.commit_sent().is_ok(),
            Call::Outcome(o) => a.outcome(o).is_ok(),
            Call::Failed => a.failed().is_ok(),
            Call::PrepareRefused => a.prepare_refused().is_ok(),
            Call::AbortRecorded => a.abort_recorded().is_ok(),
            Call::AbortUnknown => a.abort_unknown_at_witness().is_ok(),
            Call::ChainRead(k) => a.chain_read(k.map(|k| head(k).1).as_ref()).is_ok(),
            Call::Raised => a.possible_deletion_raised().is_ok(),
            Call::InDoubtRecorded => a.in_doubt_recorded().is_ok(),
            Call::InDoubtUnknown => a.in_doubt_unknown_at_witness().is_ok(),
        }
    }

    /// I-24, design section 7.2 `no-unwitnessed-commit`: under any call
    /// sequence, COMMIT is accepted only after the receipt for the
    /// prepared head's own `(n, link)` and the anchor row insert.
    #[test]
    fn i24_anchorer_core_never_commits_without_its_receipt() {
        check("i24_anchorer_core_never_commits_without_its_receipt", |g| {
            let mut a = Anchorer::new();
            for _ in 0..g.usize_in(1..=40) {
                let before = a.phase().clone();
                let c = gen_call(g);
                let accepted = apply(&mut a, c);
                if matches!(c, Call::CommitSent) && accepted {
                    let Phase::AnchorInserted { head, receipt } = before else {
                        return Err(format!("COMMIT accepted in {before:?}"));
                    };
                    prop_assert!(may_commit(head, Some(&receipt)), "{before:?}");
                }
                if !accepted {
                    prop_assert_eq!(a.phase(), &before, "a refused call changed the phase");
                }
            }
            Ok(())
        });
    }

    /// I-24, ADR-010 "Abort" and "In doubt": once a prepare was sent, no
    /// new append begins until it is committed, aborted at the witness or
    /// recorded in doubt.
    #[test]
    fn i24_anchorer_core_resolves_every_prepare_before_the_next() {
        check(
            "i24_anchorer_core_resolves_every_prepare_before_the_next",
            |g| {
                let mut a = Anchorer::new();
                let mut open: Option<(u64, Link)> = None;
                for _ in 0..g.usize_in(1..=40) {
                    let c = gen_call(g);
                    let before = a.phase().clone();
                    let accepted = apply(&mut a, c);
                    match (c, accepted) {
                        (Call::Prepared(k), true) => open = Some(head(k)),
                        (Call::Begin(_), true) => {
                            prop_assert!(open.is_none(), "begin while {:?} is open", open);
                        }
                        (Call::Outcome(CommitOutcome::Committed), true)
                        | (
                            Call::AbortRecorded
                            | Call::AbortUnknown
                            | Call::PrepareRefused
                            | Call::InDoubtRecorded
                            | Call::InDoubtUnknown,
                            true,
                        ) => open = None,
                        (Call::ChainRead(_), true) if a.phase() == &Phase::Idle => open = None,
                        (Call::Failed, true) if matches!(before, Phase::Open { .. }) => {
                            prop_assert!(open.is_none(), "{:?}", before);
                        }
                        _ => {}
                    }
                }
                Ok(())
            },
        );
    }

    /// I-24, design section 5.3: the honest sequence runs every step in
    /// order and ends idle, and each failure point leads to its ADR-010
    /// follow-up.
    #[test]
    fn i24_anchorer_core_follows_each_failure_point_to_its_follow_up() {
        let h = head(0);
        let open = || {
            let mut a = Anchorer::new();
            a.begin(true).unwrap();
            for s in Step::ALL {
                assert_eq!(a.next(), Next::Run(s));
                a.step_done(s).unwrap();
            }
            assert_eq!(a.next(), Next::SendPrepare);
            a
        };
        let mut a = open();
        assert_eq!(a.failed(), Ok(AfterCommit::Done));
        assert_eq!(a.next(), Next::Nothing);
        let mut a = open();
        a.prepared(h).unwrap();
        assert!(
            a.receipt(&receipt_for(head(1))).is_err(),
            "another head's receipt"
        );
        assert_eq!(a.failed(), Ok(AfterCommit::SendAbort));
        assert_eq!(a.next(), Next::SendAbort { head: h });
        assert!(a.begin(true).is_err(), "begin before the abort is recorded");
        a.abort_recorded().unwrap();
        let mut a = open();
        a.prepared(h).unwrap();
        a.receipt(&receipt_for(h)).unwrap();
        a.anchor_inserted().unwrap();
        a.commit_sent().unwrap();
        assert_eq!(a.outcome(CommitOutcome::Unknown), Ok(AfterCommit::InDoubt));
        assert_eq!(a.next(), Next::ReadChain { head: h });
        assert_eq!(
            a.chain_read(None),
            Ok(Resolution::AbsentRaisePossibleDeletion)
        );
        assert_eq!(a.next(), Next::RaisePossibleDeletion { head: h });
        assert!(
            a.in_doubt_recorded().is_err(),
            "the record before the alert"
        );
        a.possible_deletion_raised().unwrap();
        assert_eq!(a.next(), Next::SendInDoubtAbsent { head: h });
        a.in_doubt_recorded().unwrap();
        assert_eq!(a.phase(), &Phase::Idle);
        let mut a = Anchorer::restart(Some(h));
        assert_eq!(a.chain_read(Some(&h.1)), Ok(Resolution::Committed));
        assert!(
            Anchorer::new().begin(false).is_err(),
            "a write while the witness is down"
        );
    }

    /// I-24, ADR-010 "Abort" (W1e M-AUDIT `AuditModel::prepare`): a
    /// prepare the witness refused ends the append with no abort. An abort
    /// the witness answers as unknown also ends it. Neither step is
    /// accepted in any other phase.
    #[test]
    fn i24_anchorer_core_ends_an_append_the_witness_holds_nothing_of() {
        let h = head(0);
        let prepared = || {
            let mut a = Anchorer::new();
            a.begin(true).unwrap();
            for s in Step::ALL {
                a.step_done(s).unwrap();
            }
            a.prepared(h).unwrap();
            a
        };
        let mut a = prepared();
        a.prepare_refused().unwrap();
        assert_eq!(a.next(), Next::Nothing);
        assert!(a.begin(true).is_ok(), "a refused prepare wedged the core");
        let mut a = prepared();
        assert_eq!(a.failed(), Ok(AfterCommit::SendAbort));
        assert!(a.prepare_refused().is_err(), "refused after MustAbort");
        a.abort_unknown_at_witness().unwrap();
        assert!(a.begin(true).is_ok(), "an unknown abort wedged the core");
        let mut a = prepared();
        a.receipt(&receipt_for(h)).unwrap();
        assert!(a.prepare_refused().is_err(), "refused after the receipt");
        assert!(a.abort_unknown_at_witness().is_err(), "no abort was due");
        assert!(Anchorer::new().prepare_refused().is_err());
        assert!(Anchorer::new().abort_unknown_at_witness().is_err());
    }
    /// I-24, ADR-010 "In doubt" ("That alert is the detection"): under
    /// any call sequence, the core lets the witness forget an in-doubt
    /// prepare only after `PossibleDeletion` for that head is raised.
    /// A witness answer of `UnknownPrepare` to the record also ends the
    /// resolution, and only then.
    #[test]
    fn i24_anchorer_core_raises_possible_deletion_before_the_in_doubt_record() {
        check(
            "i24_anchorer_core_raises_possible_deletion_before_the_in_doubt_record",
            |g| {
                let mut a = Anchorer::restart(Some(head(g.u8_in(0..=2))));
                let mut raised: Option<(u64, Link)> = None;
                for _ in 0..g.usize_in(1..=40) {
                    let before = a.phase().clone();
                    let c = gen_call(g);
                    let accepted = apply(&mut a, c);
                    match (c, accepted, &before) {
                        (Call::Raised, true, Phase::MustRaise { head }) => raised = Some(*head),
                        (
                            Call::InDoubtRecorded | Call::InDoubtUnknown,
                            true,
                            Phase::MustRecordInDoubt { head },
                        ) => {
                            prop_assert_eq!(raised, Some(*head), "record before its alert");
                            prop_assert_eq!(a.phase(), &Phase::Idle);
                            raised = None;
                        }
                        (Call::InDoubtRecorded | Call::InDoubtUnknown | Call::Raised, true, _) => {
                            return Err(format!("{c:?} accepted in {before:?}"));
                        }
                        _ => {}
                    }
                }
                Ok(())
            },
        );
    }
}
