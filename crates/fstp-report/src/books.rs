//! The reconciliation fold (I-44, R-RP-02).
//!
//! The fold reads the core records of a snapshot into the books every
//! output takes its figures from: calls, proposals, contract amounts,
//! payment requests and payments. It lists each record that does not
//! reconcile with what the ledger recorded before it:
//!
//! - a call, proposal, grant or request that names an unknown parent;
//! - a second grant decision of one proposal;
//! - a line approved above its request, or on an unknown line;
//! - a release of an unknown, withdrawn, already released or unapproved
//!   request, or of another grant's request;
//! - a paid total above the effective contract amount (I-31);
//! - a confirmation of a request that was never released;
//! - an amount in another currency than its programme's.
//!
//! The fold never trusts a figure it did not add up itself.

use std::collections::BTreeMap;

use fstp_domain::Record;
use fstp_domain::id::{
    CallId, CallSeq, LineId, PolicyVersionId, ProgrammeId, ProposalId, RequestId,
};
use fstp_domain::payment::PaymentKind;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;
use fstp_money::{Amount, Currency, NonNegAmount};

use crate::ReportError;
use crate::snapshot::Snapshot;

/// A record that does not reconcile (I-44).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The sequence number of the record.
    pub seq: Seq,
    /// What does not reconcile.
    pub rule: &'static str,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "seq {}: {}", self.seq.raw(), self.rule)
    }
}

/// A call as the ledger records it.
#[derive(Clone, Debug)]
pub(crate) struct CallBook {
    pub(crate) programme: ProgrammeId,
    pub(crate) opens: Timestamp,
    pub(crate) deadline: Timestamp,
    pub(crate) zone: String,
    pub(crate) budget: NonNegAmount,
    pub(crate) published: Option<(PolicyVersionId, CallSeq, Timestamp)>,
}

/// A decided grant.
#[derive(Clone, Debug)]
pub(crate) struct GrantBook {
    pub(crate) call: CallId,
    pub(crate) committed: Amount,
    pub(crate) decided: Timestamp,
    pub(crate) closed: Option<Timestamp>,
    pub(crate) paid: Amount,
}

/// A payment request.
#[derive(Clone, Debug)]
pub(crate) struct RequestBook {
    pub(crate) grant: ProposalId,
    pub(crate) hardship: bool,
    lines: BTreeMap<LineId, (Amount, Option<Amount>)>,
    pub(crate) released: Option<Timestamp>,
    withdrawn: bool,
    confirmed: bool,
}

impl RequestBook {
    /// The sum of the approved lines, or `None` when no line was approved.
    pub(crate) fn approved(&self, c: Currency) -> Option<Amount> {
        let mut any = false;
        let mut sum = Amount::zero(c);
        for (_, a) in self.lines.values() {
            if let Some(a) = a {
                any = true;
                sum = sum.checked_add(*a).ok()?;
            }
        }
        any.then_some(sum)
    }
}

/// The books of a snapshot.
#[derive(Clone, Debug, Default)]
pub(crate) struct Books {
    pub(crate) programmes: BTreeMap<ProgrammeId, Currency>,
    pub(crate) calls: BTreeMap<CallId, CallBook>,
    pub(crate) proposals: BTreeMap<ProposalId, CallId>,
    pub(crate) grants: BTreeMap<ProposalId, GrantBook>,
    pub(crate) requests: BTreeMap<RequestId, RequestBook>,
}

impl Books {
    /// The currency of the programme of `call`.
    pub(crate) fn currency_of_call(&self, call: CallId) -> Option<Currency> {
        let p = self.calls.get(&call)?.programme;
        self.programmes.get(&p).copied()
    }
}

/// Folds `snap` and lists every mismatch.
pub(crate) fn fold(snap: &Snapshot) -> (Books, Vec<Mismatch>) {
    let mut b = Books::default();
    let mut out = Vec::new();
    for e in snap.entries() {
        let mut miss = |rule: &'static str| out.push(Mismatch { seq: e.seq, rule });
        match &e.record {
            Record::ProgrammeCreated {
                programme,
                currency,
                ..
            } => {
                if b.programmes.insert(*programme, *currency).is_some() {
                    miss("a programme was created twice");
                }
            }
            Record::CallDrafted {
                call,
                programme,
                opens,
                deadline,
                deadline_zone,
                budget,
                ..
            } => {
                match b.programmes.get(programme) {
                    None => miss("a call of an unknown programme"),
                    Some(c) if *c != budget.amount().currency() => {
                        miss("a call budget in another currency than its programme")
                    }
                    Some(_) => {}
                }
                b.calls.insert(
                    *call,
                    CallBook {
                        programme: *programme,
                        opens: *opens,
                        deadline: *deadline,
                        zone: deadline_zone.as_str().to_owned(),
                        budget: *budget,
                        published: None,
                    },
                );
            }
            Record::CallEdited {
                call,
                opens,
                deadline,
                deadline_zone,
                budget,
                ..
            } => match b.calls.get_mut(call) {
                Some(c) if c.published.is_none() => {
                    c.opens = *opens;
                    c.deadline = *deadline;
                    c.zone = deadline_zone.as_str().to_owned();
                    c.budget = *budget;
                }
                Some(_) => miss("a published call was edited"),
                None => miss("an edit of an unknown call"),
            },
            Record::CallPublished {
                call, policy, seq, ..
            } => match b.calls.get_mut(call) {
                Some(c) if c.published.is_none() => c.published = Some((*policy, *seq, e.at)),
                Some(_) => miss("a call was published twice"),
                None => miss("a publication of an unknown call"),
            },
            Record::ProposalCreated { proposal, call, .. } => {
                if !b.calls.contains_key(call) {
                    miss("a proposal in an unknown call");
                }
                b.proposals.insert(*proposal, *call);
            }
            Record::GrantDecided(g) => {
                let p = g.proposal();
                let Some(call) = b.proposals.get(&p).copied() else {
                    miss("a grant of an unknown proposal");
                    continue;
                };
                if b.grants.contains_key(&p) {
                    miss("a second grant decision for one proposal");
                    continue;
                }
                let committed = g.granted().amount();
                if b.currency_of_call(call) != Some(committed.currency()) {
                    miss("a grant in another currency than its programme");
                    continue;
                }
                b.grants.insert(
                    p,
                    GrantBook {
                        call,
                        committed,
                        decided: e.at,
                        closed: None,
                        paid: Amount::zero(committed.currency()),
                    },
                );
            }
            Record::Transitioned(t)
                if matches!(t.to, StateTag::Completed | StateTag::Terminated) =>
            {
                if let Some(g) = b.grants.get_mut(&t.proposal) {
                    g.closed = Some(e.at);
                }
            }
            Record::PaymentRequested {
                request,
                grant,
                kind,
                lines,
            } => {
                let Some(g) = b.grants.get(grant) else {
                    miss("a payment request on a grant with no contract amount");
                    continue;
                };
                if b.requests.contains_key(request) {
                    miss("a payment request id used twice");
                    continue;
                }
                let c = g.committed.currency();
                if lines.iter().any(|l| l.amount.amount().currency() != c) {
                    miss("a payment line in another currency than its grant");
                    continue;
                }
                b.requests.insert(
                    *request,
                    RequestBook {
                        grant: *grant,
                        hardship: matches!(kind, PaymentKind::Hardship(_)),
                        lines: lines
                            .iter()
                            .map(|l| (l.line, (l.amount.amount(), None)))
                            .collect(),
                        released: None,
                        withdrawn: false,
                        confirmed: false,
                    },
                );
            }
            Record::LineAccepted {
                request,
                line,
                approved,
                ..
            } => {
                let Some(r) = b.requests.get_mut(request) else {
                    miss("a line decision on an unknown request");
                    continue;
                };
                let Some((requested, decision)) = r.lines.get_mut(line) else {
                    miss("a decision on a line the request does not hold");
                    continue;
                };
                match approved.amount().cmp_same(*requested) {
                    Ok(std::cmp::Ordering::Greater) => miss("a line approved above its request"),
                    Ok(_) => *decision = Some(approved.amount()),
                    Err(_) => miss("a line approved in another currency"),
                }
            }
            Record::PaymentRequestWithdrawn { request, .. }
            | Record::PaymentRequestClosed { request, .. } => match b.requests.get_mut(request) {
                Some(r) if r.released.is_none() => r.withdrawn = true,
                Some(_) => miss("a released request was withdrawn or closed"),
                None => miss("a withdrawal of an unknown request"),
            },
            Record::PaymentReleased(rel) => {
                let Some(r) = b.requests.get_mut(&rel.request()) else {
                    miss("a release of an unknown request");
                    continue;
                };
                if r.grant != rel.grant() {
                    miss("a release names another grant than its request");
                    continue;
                }
                if r.withdrawn {
                    miss("a release of a withdrawn request");
                    continue;
                }
                if r.released.is_some() {
                    miss("a request was released twice");
                    continue;
                }
                let Some(g) = b.grants.get_mut(&r.grant) else {
                    miss("a release on a grant with no contract amount");
                    continue;
                };
                let Some(amount) = r.approved(g.committed.currency()) else {
                    miss("a release of a request with no approved line");
                    continue;
                };
                let Ok(paid) = g.paid.checked_add(amount) else {
                    miss("a paid total overflowed");
                    continue;
                };
                if paid.cmp_same(g.committed) == Ok(std::cmp::Ordering::Greater) {
                    miss("paid above the effective contract amount");
                    continue;
                }
                g.paid = paid;
                r.released = Some(e.at);
            }
            Record::PaymentConfirmed { request, .. } => match b.requests.get_mut(request) {
                Some(r) if r.released.is_some() && !r.confirmed => r.confirmed = true,
                Some(_) => miss("a confirmation of a request not released, or twice"),
                None => miss("a confirmation of an unknown request"),
            },
            _ => {}
        }
    }
    (b, out)
}

/// The books of `snap`, or every mismatch (I-44).
pub(crate) fn reconcile(snap: &Snapshot) -> Result<Books, ReportError> {
    let (books, mismatches) = fold(snap);
    if mismatches.is_empty() {
        Ok(books)
    } else {
        Err(ReportError::Reconciliation(mismatches))
    }
}
