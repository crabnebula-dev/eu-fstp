//! I-24: the anchorer core of the strict tail D (design sections 5.3 and
//! 7.2, ADR-010 "Prepare, receipt, commit").
//!
//! The crash test drives the production `fstp_audit::anchorer::Anchorer`
//! through the append of design section 5.3 step by step. It injects a
//! crash after any step, each fault of the prepare and of COMMIT, and
//! lost answers to withdrawals. A crash restarts the core with
//! `Anchorer::restart` from the witness's open prepare. The test holds
//! the environment: the transaction, the chain and a witness that
//! records what it is sent. Every decision comes from the core. The
//! checks:
//!
//! - no COMMIT without the receipt for its link, and no receipt for
//!   another head taken (`no-unwitnessed-commit`).
//! - a known failure sends `Abort` before the same `n` is prepared again.
//! - an unknown outcome reads the chain: a present row resolves as
//!   committed with no withdrawal. A missing row raises
//!   `PossibleDeletion`, then sends `InDoubtAbsent`.
//! - no prepared link is left without a row or a withdrawal.
//! - no withdrawal names a present row.
//!
//! Red until lane W2g lands the anchorer core and its admission decision.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::answered;
use common::api::{self, AdmitRefusal, AfterCommit, CommitOutcome, Op, Resolution};
use common::reference::{self as r, Hash};
use fstp_audit::anchorer::{
    AfterCommit as CoreAfter, Anchorer, CommitOutcome as CoreOutcome, Next, OutOfOrder,
    Resolution as CoreResolution, Step as CoreStep,
};
use fstp_audit::{Link, ReceiptFields};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

/// I-24, design section 7.2: the anchorer commits only once it holds the
/// receipt for its link.
#[test]
fn i24_anchorer_commits_only_with_the_receipt() {
    let got = [api::may_commit(true), api::may_commit(false)];
    assert_eq!(got, [Ok(true), Ok(false)]);
}

/// I-24, design section 7.2: after COMMIT succeeds nothing more is sent;
/// after a known failure an `Abort`; after an unknown outcome the chain
/// is read.
#[test]
fn i24_anchorer_step_after_each_commit_outcome() {
    let got = CommitOutcome::ALL.map(api::after_commit);
    assert_eq!(
        got,
        [
            Ok(AfterCommit::Done),
            Ok(AfterCommit::SendAbort),
            Ok(AfterCommit::InDoubt)
        ]
    );
}

/// I-24, ADR-010 "In doubt": a row that holds the prepared link was
/// committed, and the next prepare extends it.
#[test]
fn i24_in_doubt_present_row_resolves_as_committed() {
    check("i24_in_doubt_present_row_resolves_as_committed", |g| {
        let l = gen_hash(g);
        let got = answered("resolve", api::resolve_in_doubt(Some(l), &l))?;
        prop_assert_eq!(got, Resolution::Committed);
        Ok(())
    });
}

/// I-24, ADR-010 "In doubt": a missing row, or a row that holds another
/// link, cannot be told from a deletion. The anchorer sends
/// `InDoubtAbsent` and raises `PossibleDeletion`.
#[test]
fn i24_in_doubt_missing_row_raises_possible_deletion() {
    check("i24_in_doubt_missing_row_raises_possible_deletion", |g| {
        let prepared = gen_hash(g);
        let at_n = if g.bool() {
            None
        } else {
            let mut other = gen_hash(g);
            if other == prepared {
                other[0] ^= 1;
            }
            Some(other)
        };
        let got = answered("resolve", api::resolve_in_doubt(at_n, &prepared))?;
        prop_assert_eq!(got, Resolution::AbsentRaisePossibleDeletion);
        Ok(())
    });
}

/// I-24, ADR-010 "Witness unavailable": without a reachable witness the
/// cell refuses writes, naming the witness, and keeps serving reads.
#[test]
fn i24_witness_unavailable_refuses_writes_and_serves_reads() {
    let got = [
        api::admit(Op::Read, true),
        api::admit(Op::Write, true),
        api::admit(Op::Read, false),
        api::admit(Op::Write, false),
    ];
    assert_eq!(
        got,
        [
            Ok(Ok(())),
            Ok(Ok(())),
            Ok(Ok(())),
            Ok(Err(AdmitRefusal::WitnessUnavailable))
        ]
    );
}

// ---------------------------------------------------------------------------
// Crash and fault injection over the steps of design section 5.3, driving
// the production anchorer core `fstp_audit::anchorer::Anchorer`.

/// Where a fault strikes in one append (design section 5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// After or at one of steps 1 to 6 of the open transaction.
    Pre(CoreStep),
    /// The prepare.
    Prepare,
    /// The anchor row insert.
    InsertAnchor,
    /// COMMIT.
    CommitSent,
}

const PRE_AND_ANCHOR: [At; 7] = [
    At::Pre(CoreStep::Lock),
    At::Pre(CoreStep::CommandCheck),
    At::Pre(CoreStep::HeadCheck),
    At::Pre(CoreStep::SealLedger),
    At::Pre(CoreStep::InsertChain),
    At::Pre(CoreStep::SideEffects),
    At::InsertAnchor,
];

const CRASH_POINTS: [At; 9] = [
    At::Pre(CoreStep::Lock),
    At::Pre(CoreStep::CommandCheck),
    At::Pre(CoreStep::HeadCheck),
    At::Pre(CoreStep::SealLedger),
    At::Pre(CoreStep::InsertChain),
    At::Pre(CoreStep::SideEffects),
    At::Prepare,
    At::InsertAnchor,
    At::CommitSent,
];

/// One fault of one append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Every step succeeds.
    None,
    /// A statement fails at `At` before COMMIT is sent.
    FailAt(At),
    /// The witness refuses the prepare and records nothing.
    Refused,
    /// The prepare is lost before it reaches the witness.
    LostBeforeWitness,
    /// The witness records the prepare and its answer is lost. The store
    /// gives up on it.
    AnswerLost,
    /// The witness records the prepare and its answer is lost. The store
    /// sends the prepare again.
    Retransmit,
    /// COMMIT returns an error.
    CommitError,
    /// The cell crashes after `At`. After `CommitSent` the database may or
    /// may not have committed.
    CrashAfter(At, bool),
    /// The connection is lost after COMMIT is sent.
    CommitLost(bool),
}

fn gen_fault(g: &mut Gen) -> Fault {
    match g.u8_in(0..=8) {
        0 => Fault::None,
        1 => Fault::FailAt(*g.pick(&PRE_AND_ANCHOR)),
        2 => Fault::Refused,
        3 => Fault::LostBeforeWitness,
        4 => Fault::AnswerLost,
        5 => Fault::Retransmit,
        6 => Fault::CommitError,
        7 => Fault::CrashAfter(*g.pick(&CRASH_POINTS), g.bool()),
        _ => Fault::CommitLost(g.bool()),
    }
}

/// What the witness recorded, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Prepare(u64, Hash),
    Abort(u64, Hash),
    InDoubtAbsent(u64, Hash),
}

/// The witness of one chain, with the ADR-010 rules: one outstanding
/// prepare, a retransmit answered with its first receipt, and a
/// withdrawal only of the outstanding prepare.
#[derive(Debug, Default)]
struct Witness {
    confirmed: (u64, Hash),
    outstanding: Option<(u64, Hash)>,
    held: Option<ReceiptFields>,
    withdrawn: Vec<(u64, Hash)>,
    log: Vec<Sent>,
}

impl Witness {
    fn prepare(&mut self, prev: (u64, Hash), head: (u64, Hash)) -> Option<ReceiptFields> {
        if self.outstanding == Some(head) && prev == self.confirmed {
            return self.held;
        }
        if prev != self.outstanding.unwrap_or(self.confirmed) || self.withdrawn.contains(&head) {
            return None;
        }
        if let Some(o) = self.outstanding {
            self.confirmed = o;
        }
        self.outstanding = Some(head);
        self.log.push(Sent::Prepare(head.0, head.1));
        let seq = u64::try_from(self.log.len()).unwrap();
        self.held = Some(ReceiptFields {
            n: head.0,
            link: Link(head.1),
            witness_seq: seq,
            witness_link: Link(r::sha256(&[&seq.to_be_bytes(), &head.1])),
            received_at: 0,
        });
        self.held
    }

    /// `true` when recorded, `false` for `UnknownPrepare`.
    fn withdraw(&mut self, head: (u64, Hash), abort: bool) -> bool {
        if self.outstanding != Some(head) {
            return false;
        }
        self.outstanding = None;
        self.held = None;
        self.withdrawn.push(head);
        self.log.push(if abort {
            Sent::Abort(head.0, head.1)
        } else {
            Sent::InDoubtAbsent(head.0, head.1)
        });
        true
    }
}

/// The environment: the committed chain, the witness and the alerts.
#[derive(Debug, Default)]
struct World {
    /// Committed links, row 1 first.
    rows: Vec<Hash>,
    witness: Witness,
    /// `PossibleDeletion` alerts raised, by head.
    alerts: Vec<(u64, Hash)>,
    /// Whether the witness's answers to withdrawals are lost once.
    lose_withdrawal_answer: bool,
}

impl World {
    fn link_at(&self, n: u64) -> Option<Hash> {
        let i = usize::try_from(n.checked_sub(1)?).ok()?;
        self.rows.get(i).copied()
    }

    fn head(&self) -> (u64, Hash) {
        (
            u64::try_from(self.rows.len()).unwrap(),
            self.rows.last().copied().unwrap_or([0; 32]),
        )
    }
}

fn core_ok<T>(what: &str, r: Result<T, OutOfOrder>) -> Result<T, String> {
    r.map_err(|e| format!("the core refused {what} driven in order: {e:?}"))
}

/// Follows the core from any phase to idle: aborts, chain reads, alerts
/// and in-doubt records, as `Next` demands. A withdrawal whose answer is
/// lost is sent again and answered as `UnknownPrepare`.
fn resolve(w: &mut World, a: &mut Anchorer) -> Result<(), String> {
    for _ in 0..8 {
        match a.next() {
            Next::Nothing => return Ok(()),
            Next::SendAbort { head } => {
                let h = (head.0, head.1.0);
                let recorded = w.witness.withdraw(h, true);
                if recorded && !w.lose_withdrawal_answer {
                    core_ok("abort_recorded", a.abort_recorded())?;
                } else {
                    // The first answer is lost, or the prepare never got
                    // there. The retry is answered as unknown.
                    prop_assert!(!w.witness.withdraw(h, true), "abort recorded twice");
                    core_ok("abort_unknown", a.abort_unknown_at_witness())?;
                }
            }
            Next::ReadChain { head } => {
                let at_n = w.link_at(head.0).map(Link);
                let res = core_ok("chain_read", a.chain_read(at_n.as_ref()))?;
                let present = w.link_at(head.0) == Some(head.1.0);
                prop_assert_eq!(
                    res == CoreResolution::Committed,
                    present,
                    "in doubt about {:?}: {:?}",
                    head,
                    res
                );
            }
            Next::RaisePossibleDeletion { head } => {
                prop_assert!(
                    w.link_at(head.0) != Some(head.1.0),
                    "PossibleDeletion for the present row {}",
                    head.0
                );
                let h = (head.0, head.1.0);
                if !w.alerts.contains(&h) {
                    w.alerts.push(h);
                }
                core_ok("possible_deletion_raised", a.possible_deletion_raised())?;
            }
            Next::SendInDoubtAbsent { head } => {
                let h = (head.0, head.1.0);
                prop_assert!(w.alerts.contains(&h), "InDoubtAbsent before its alert");
                let recorded = w.witness.withdraw(h, false);
                prop_assert!(recorded, "the in-doubt head {:?} was not outstanding", h);
                if w.lose_withdrawal_answer {
                    prop_assert!(!w.witness.withdraw(h, false), "recorded twice");
                    core_ok("in_doubt_unknown", a.in_doubt_unknown_at_witness())?;
                } else {
                    core_ok("in_doubt_recorded", a.in_doubt_recorded())?;
                }
            }
            other => return Err(format!("the core waits on {other:?} after the append")),
        }
    }
    Err(format!("the core did not settle: {:?}", a.phase()))
}

/// A crash: the core's memory is lost. The database rolls back unless
/// COMMIT went through. The restarted core learns the open prepare from
/// the witness and resolves it before it serves (ADR-010 "Start-up").
fn crash(w: &mut World) -> Result<(), String> {
    let mut a = Anchorer::restart(w.witness.outstanding.map(|(n, l)| (n, Link(l))));
    resolve(w, &mut a)
}

/// One append with `fault`, every decision taken by the production core.
#[allow(clippy::too_many_lines, reason = "one append, step by step")]
fn append(w: &mut World, fault: Fault, salt: u64) -> Result<(), String> {
    let prev = w.head();
    let n = prev.0 + 1;
    let link = r::sha256(&[&prev.1, &salt.to_be_bytes()]);
    let head = (n, Link(link));
    let mut a = Anchorer::new();
    core_ok("begin", a.begin(true))?;
    for s in CoreStep::ALL {
        prop_assert_eq!(a.next(), Next::Run(s));
        if fault == Fault::FailAt(At::Pre(s)) {
            prop_assert_eq!(core_ok("failed", a.failed())?, CoreAfter::Done);
            return resolve(w, &mut a);
        }
        core_ok("step_done", a.step_done(s))?;
        if matches!(fault, Fault::CrashAfter(At::Pre(c), _) if c == s) {
            return crash(w);
        }
    }
    prop_assert_eq!(a.next(), Next::SendPrepare);
    core_ok("prepared", a.prepared(head))?;
    prop_assert!(a.commit_sent().is_err(), "COMMIT before the receipt");
    // A receipt for another head: the same n with another link, or the
    // next row with this link. Neither is taken.
    let mut other = link;
    other[0] ^= 1;
    for wrong in [(n, Link(other)), (n + 1, Link(link))] {
        let fake = ReceiptFields {
            n: wrong.0,
            link: wrong.1,
            witness_seq: 1,
            witness_link: Link([0; 32]),
            received_at: 0,
        };
        prop_assert!(a.receipt(&fake).is_err(), "a receipt for {:?} taken", wrong);
    }
    let receipt = match fault {
        Fault::Refused => {
            core_ok("prepare_refused", a.prepare_refused())?;
            return resolve(w, &mut a);
        }
        Fault::LostBeforeWitness => {
            prop_assert_eq!(core_ok("failed", a.failed())?, CoreAfter::SendAbort);
            return resolve(w, &mut a);
        }
        _ => w.witness.prepare(prev, (n, link)),
    };
    let Some(mut receipt) = receipt else {
        return Err(format!("the witness refused the honest prepare of row {n}"));
    };
    match fault {
        Fault::AnswerLost => {
            prop_assert_eq!(core_ok("failed", a.failed())?, CoreAfter::SendAbort);
            return resolve(w, &mut a);
        }
        Fault::Retransmit => {
            let again = w.witness.prepare(prev, (n, link));
            prop_assert_eq!(again, Some(receipt), "the retransmit got another answer");
            receipt = again.unwrap();
        }
        Fault::CrashAfter(At::Prepare, _) => return crash(w),
        _ => {}
    }
    core_ok("receipt", a.receipt(&receipt))?;
    if fault == Fault::FailAt(At::InsertAnchor) {
        prop_assert_eq!(core_ok("failed", a.failed())?, CoreAfter::SendAbort);
        return resolve(w, &mut a);
    }
    core_ok("anchor_inserted", a.anchor_inserted())?;
    if let Fault::CrashAfter(At::InsertAnchor, _) = fault {
        return crash(w);
    }
    core_ok("commit_sent", a.commit_sent())?;
    // I-24 no-unwitnessed-commit: COMMIT went out, so the witness holds
    // the prepare of this very head.
    prop_assert_eq!(w.witness.outstanding, Some((n, link)));
    let (seen, done) = match fault {
        Fault::CommitError => (CoreOutcome::Failed, false),
        Fault::CommitLost(done) => (CoreOutcome::Unknown, done),
        Fault::CrashAfter(At::CommitSent, done) => {
            if done {
                w.rows.push(link);
            }
            return crash(w);
        }
        _ => (CoreOutcome::Committed, true),
    };
    if done {
        w.rows.push(link);
    }
    core_ok("outcome", a.outcome(seen))?;
    resolve(w, &mut a)
}

/// The I-24 checks once the core is idle: every committed row is
/// receipted, every prepare ends as a row or a withdrawal, no withdrawal
/// names a present row, and every `InDoubtAbsent` has its alert.
fn settled(w: &World) -> Result<(), String> {
    for (i, l) in w.rows.iter().enumerate() {
        let n = u64::try_from(i).unwrap() + 1;
        let covered = w.witness.log.contains(&Sent::Prepare(n, *l));
        prop_assert!(covered, "row {} committed unreceipted", n);
    }
    for s in &w.witness.log {
        match *s {
            Sent::Prepare(n, l) => {
                let present = w.link_at(n) == Some(l);
                let out = w.witness.withdrawn.contains(&(n, l));
                prop_assert!(present || out, "prepare of row {} left open", n);
            }
            Sent::Abort(n, l) | Sent::InDoubtAbsent(n, l) => {
                prop_assert!(
                    w.link_at(n) != Some(l),
                    "withdrawal of the present row {}",
                    n
                );
            }
        }
        if let Sent::InDoubtAbsent(n, l) = *s {
            prop_assert!(
                w.alerts.contains(&(n, l)),
                "InDoubtAbsent {} without alert",
                n
            );
        }
    }
    Ok(())
}

/// I-24, design section 14.4 `i24_no_commit_without_a_receipt_for_its_link`
/// and `i24_ledger_and_chain_commit_together` at crate level. It drives
/// the production `Anchorer` through up to four appends, with a fault or
/// a crash after any step of design section 5.3. A crash restarts the
/// core with `Anchorer::restart` from the witness's open prepare. The
/// core takes no receipt for another head, and sends no COMMIT before
/// the receipt for its own. Every prepared link ends as a committed row,
/// an `Abort`, or an `InDoubtAbsent` after its `PossibleDeletion` alert,
/// before the next prepare. Lost answers to withdrawals are retried.
#[test]
fn i24_anchorer_crash_at_every_step_leaves_no_unwitnessed_commit() {
    check(
        "i24_anchorer_crash_at_every_step_leaves_no_unwitnessed_commit",
        |g| {
            let mut w = World {
                lose_withdrawal_answer: g.bool(),
                ..World::default()
            };
            let appends = g.usize_in(1..=4);
            for i in 0..appends {
                let fault = gen_fault(g);
                g.note("fault", &fault);
                append(&mut w, fault, u64::try_from(i).unwrap())?;
                settled(&w)?;
                // The witness holds at most the committed head open.
                if let Some((n, l)) = w.witness.outstanding {
                    prop_assert_eq!(w.link_at(n), Some(l), "open prepare beyond the chain");
                }
            }
            Ok(())
        },
    );
}
