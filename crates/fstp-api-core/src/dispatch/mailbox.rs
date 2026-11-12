//! `me.mailbox`: the caller's own messages, derived from existing state
//! (lane m6/mailbox, `docs/handoff/mailbox-design.md` sections 2 and 3).
//!
//! Each source below yields the work of the caller's account only (I-86),
//! from bindings active at the read instant. A message is then kept only
//! when `fstp_access::authorize_read` admits the caller to the read behind
//! its page, with the caller's own principal, state and clock (D11). So
//! the mailbox never points at a page the read rules close to the caller.
//!
//! Nothing here writes. A message whose work is done is simply not
//! derived on the next read (MB-D1, MB-D2).

use std::collections::BTreeSet;

use fstp_access::{ReadOp, ReadTarget};
use fstp_contract::{PartyRole, VersionState};
use fstp_domain::StateTag;
use fstp_domain::assignment::{AssignmentKind, AssignmentStatus};
use fstp_domain::id::{AccountId, AssignmentId, CallId, ProgrammeId, ProposalId};
use fstp_domain::payment::RequestStatus;
use fstp_domain::programme::CallStatus;
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::scoring::{ScoreKey, Stage};

use super::{Call, Seams, lock};
use crate::mailbox::{MailItem, MailKind, MailRefs, MailboxView};
use crate::pending::PendingStatus;

/// The caller's mailbox at the read instant.
pub(super) fn read<P: Seams>(call: &Call<'_, P>, account: AccountId) -> MailboxView {
    let mut out = Vec::new();
    pending(call, account, &mut out);
    receiving(call, account, &mut out);
    assignments(call, account, &mut out);
    staff(call, account, &mut out);
    approvals(call, account, &mut out);
    contracts(call, account, &mut out);
    payments(call, account, &mut out);
    notices(call, account, &mut out);
    out.retain(|m| admitted(call, m));
    MailboxView::new(out)
}

/// The target of the read behind `m`'s page (design section 3).
fn target(m: &MailItem) -> ReadTarget {
    let r = &m.refs;
    match m.kind {
        MailKind::ReviewScore | MailKind::IrcReview => r.assignment.map_or(ReadTarget::None, |a| {
            ReadTarget::Assignment(AssignmentId::from_raw(a))
        }),
        MailKind::IntakeKnockOut | MailKind::RoundVote => r
            .call
            .map_or(ReadTarget::None, |c| ReadTarget::Call(CallId::from_raw(c))),
        MailKind::ProposalSubmit
        | MailKind::Stage2Respond
        | MailKind::NegotiationAcknowledge
        | MailKind::ContractSign => r.proposal.map_or(ReadTarget::None, |p| {
            ReadTarget::Proposal(ProposalId::from_raw(p))
        }),
        _ => ReadTarget::None,
    }
}

/// Whether the read behind `m`'s page admits the caller (D11).
fn admitted<P: Seams>(call: &Call<'_, P>, m: &MailItem) -> bool {
    let op = ReadOp {
        kind: m.kind.read(),
        target: target(m),
    };
    fstp_access::authorize_read(&op, &call.caller.p, &call.state, call.now).is_ok()
}

fn refs() -> MailRefs {
    MailRefs::default()
}

/// The proposal state of `p`.
fn state_of<P: Seams>(call: &Call<'_, P>, p: ProposalId) -> Option<StateTag> {
    fstp_domain::view::proposal_state(&call.state.core, p)
}

/// I-85: each open, unexpired pending action of the caller's agents.
fn pending<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    for v in lock(&call.st.pending).list(account, call.now) {
        if v.status != PendingStatus::Open {
            continue;
        }
        let mut m = MailItem::new(
            MailKind::PendingConfirm,
            MailRefs {
                pending: Some(v.id.raw()),
                ..refs()
            },
        );
        m.since = Some(v.created);
        m.due = Some(v.expires);
        out.push(m);
    }
}

/// The work of the caller's active Receiving bindings: submit a draft,
/// respond in stage 2, acknowledge the negotiation notice.
fn receiving<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    let core = &call.state.core;
    let mut seen = BTreeSet::new();
    for (_, b) in core.roster().bindings() {
        if b.account != account || !b.active_at(call.now) {
            continue;
        }
        let BindingScope::Proposal { proposal, call: c } = b.scope else {
            continue;
        };
        if !seen.insert((proposal, b.role)) {
            continue;
        }
        let at = MailRefs {
            proposal: Some(proposal.raw()),
            ..refs()
        };
        match (state_of(call, proposal), b.role) {
            (Some(StateTag::Draft), Role::Applicant) => {
                if let Some(v) = core.calls().get(c).filter(|v| v.is_open_at(call.now)) {
                    let mut m = MailItem::new(MailKind::ProposalSubmit, at);
                    m.due = Some(v.deadline());
                    out.push(m);
                }
            }
            (Some(StateTag::Stage2), Role::Applicant) => {
                out.push(MailItem::new(MailKind::Stage2Respond, at));
            }
            (Some(StateTag::Negotiation), _)
                if !lock(&call.st.content).acknowledged(account, proposal) =>
            {
                out.push(MailItem::new(MailKind::NegotiationAcknowledge, at));
            }
            _ => {}
        }
    }
}

/// The caller's reviewer and IRC assignments: declare, score, review.
fn assignments<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    let core = &call.state.core;
    for (id, a) in core.review().assignments() {
        if a.reviewer != account || !a.unreleased() {
            continue;
        }
        let at = MailRefs {
            assignment: Some(id.raw()),
            proposal: Some(a.proposal.raw()),
            ..refs()
        };
        let awaiting = matches!(a.status, AssignmentStatus::AwaitingDeclaration);
        let state = state_of(call, a.proposal);
        match a.kind {
            AssignmentKind::Reviewer if awaiting => {
                out.push(MailItem::new(MailKind::ReviewDeclare, at));
            }
            AssignmentKind::Reviewer if a.active() => {
                let stage = match state {
                    Some(StateTag::Stage1) => Stage::One,
                    Some(StateTag::Stage2) => Stage::Two,
                    _ => continue,
                };
                if !scored(call, id, a.proposal, stage) {
                    out.push(MailItem::new(MailKind::ReviewScore, at));
                }
            }
            AssignmentKind::Irc if awaiting => {
                out.push(MailItem::new(MailKind::IrcDeclare, at));
            }
            AssignmentKind::Irc
                if a.active()
                    && state == Some(StateTag::IrcReview)
                    && !fstp_domain::decision::irc_review_recorded(core, a.proposal, id) =>
            {
                out.push(MailItem::new(MailKind::IrcReview, at));
            }
            _ => {}
        }
    }
}

/// Whether assignment `a` holds a score for the plan of `stage`, as the
/// score sheet reads it. A history the journal does not hold counts as
/// not scored, so the work stays listed and its page says why it cannot
/// load.
fn scored<P: Seams>(call: &Call<'_, P>, a: AssignmentId, p: ProposalId, stage: Stage) -> bool {
    let journal = lock(&call.st.journal);
    let Ok(submitted) = journal.submitted_plan(p) else {
        return false;
    };
    let plan = match stage {
        Stage::Two => journal.last_revision(p).ok().flatten().or(submitted),
        Stage::One => submitted,
    };
    plan.is_some_and(|plan| {
        journal
            .score(&ScoreKey {
                assignment: a,
                stage,
                plan,
            })
            .is_some()
    })
}

/// The programmes where the caller holds `role` through an active
/// programme binding.
fn programmes_of<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    roles: &[Role],
) -> BTreeSet<ProgrammeId> {
    call.state
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| {
            b.account == account
                && roles.contains(&b.role)
                && b.scope == BindingScope::Programme
                && b.active_at(call.now)
        })
        .map(|(_, b)| b.programme)
        .collect()
}

/// The published calls of `programmes`.
fn published<P: Seams>(call: &Call<'_, P>, programmes: &BTreeSet<ProgrammeId>) -> Vec<CallId> {
    call.state
        .core
        .calls()
        .iter()
        .filter(|(_, v)| v.status() == CallStatus::Published && programmes.contains(&v.programme()))
        .map(|(c, _)| c)
        .collect()
}

/// The coordinator's intake (R-EV-01) and the committee's open rounds
/// (R-EV-08).
fn staff<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    let coordinated = programmes_of(call, account, &[Role::FstpCoordinator]);
    for c in published(call, &coordinated) {
        let waiting = super::proposals_of_call(&call.state, c)
            .into_iter()
            .any(|p| state_of(call, p) == Some(StateTag::Submitted));
        if waiting {
            out.push(MailItem::new(
                MailKind::IntakeKnockOut,
                MailRefs {
                    call: Some(c.raw()),
                    ..refs()
                },
            ));
        }
    }
    let committee = programmes_of(
        call,
        account,
        &[Role::CommitteeMember, Role::CommitteeChair],
    );
    let journal = lock(&call.st.journal);
    for c in published(call, &committee) {
        let Some(r) = journal.open_round(c) else {
            continue;
        };
        let Some(facts) = journal.round(r) else {
            continue;
        };
        if facts.cast.contains_key(&account) || facts.delegated.contains_key(&account) {
            continue;
        }
        out.push(MailItem::new(
            MailKind::RoundVote,
            MailRefs {
                call: Some(c.raw()),
                round: Some(r.raw()),
                ..refs()
            },
        ));
    }
}

/// I-67: each live activation request a tenant admin who built nothing in
/// the draft may approve, as the approval inbox marks it approvable.
fn approvals<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    if !call.caller.p.tenant_admin() {
        return;
    }
    for (programme, d) in call.state.creator.drafts() {
        if d.active().is_none() && d.request_live() && !d.builders().contains(&account) {
            out.push(MailItem::new(
                MailKind::AdminApproveActivation,
                MailRefs {
                    programme: Some(programme.raw()),
                    ..refs()
                },
            ));
        }
    }
}

/// R-CT-02: each latest contract version the caller signs next. The
/// signatory signs once every grantee-side party has (`contracts.md`).
fn contracts<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    for (id, c) in call.state.contracts.contracts() {
        let Some(v) = c.latest() else {
            continue;
        };
        if !matches!(
            v.state(),
            VersionState::Sent | VersionState::SignedByGrantee
        ) {
            continue;
        }
        let mine = v.parties().iter().any(|p| {
            p.account == account
                && !v.signed(&p.field)
                && (p.role != PartyRole::Signatory || v.signed_by_grantee())
        });
        if mine {
            out.push(MailItem::new(
                MailKind::ContractSign,
                MailRefs {
                    proposal: Some(c.proposal().raw()),
                    contract: Some(id.raw()),
                    version: Some(v.number),
                    ..refs()
                },
            ));
        }
    }
}

/// The caller's payment work, as `payment.queue` gives it, with SoD-04
/// and I-05 applied to the release: the releaser accepted no line of the
/// request and did not approve it.
fn payments<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    let state = &call.state;
    let core = &state.core;
    let reviews: BTreeSet<ProposalId> = core
        .review()
        .assignments()
        .map(|(_, a)| a)
        .filter(|a| {
            a.reviewer == account
                && a.kind == AssignmentKind::Reviewer
                && a.status == AssignmentStatus::Active
        })
        .map(|a| a.proposal)
        .collect();
    let finance = programmes_of(call, account, &[Role::FinanceApprover]);
    let releaser = programmes_of(call, account, &[Role::PaymentReleaser]);
    let payments = core.payments();
    for s in payments.summaries() {
        let programme = super::grant::programme_of(state, s.grant);
        let holds = |set: &BTreeSet<ProgrammeId>| programme.is_some_and(|p| set.contains(&p));
        let kind = match s.status {
            RequestStatus::UnderReview if reviews.contains(&s.grant) => MailKind::PaymentReview,
            RequestStatus::Accepted if holds(&finance) => MailKind::PaymentApprove,
            RequestStatus::PaymentApproved if holds(&releaser) => {
                let accepted = s
                    .lines
                    .iter()
                    .filter_map(|l| l.decision)
                    .any(|(by, a)| by == account && a.amount().minor() > 0);
                if accepted || payments.approver(s.request) == Some(account) {
                    continue;
                }
                MailKind::PaymentRelease
            }
            RequestStatus::Released if holds(&finance) => MailKind::PaymentConfirm,
            _ => continue,
        };
        out.push(MailItem::new(
            kind,
            MailRefs {
                proposal: Some(s.grant.raw()),
                request: Some(s.request.raw()),
                ..refs()
            },
        ));
    }
}

/// R-EV-04, R-IR-02: the caller's notices, as `me.notices` derives them.
/// A proposal the journal does not hold gives no concern notice here, and
/// `me.notices` itself refuses it.
fn notices<P: Seams>(call: &Call<'_, P>, account: AccountId, out: &mut Vec<MailItem>) {
    let roster = call.state.core.roster();
    let mine: BTreeSet<ProposalId> = roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
        .filter(|b| b.account == account)
        .filter_map(|b| match b.scope {
            BindingScope::Proposal { proposal, .. } => Some(proposal),
            BindingScope::Programme => None,
        })
        .collect();
    let journal = lock(&call.st.journal);
    for p in mine {
        let tag = state_of(call, p);
        if tag.is_none_or(|t| t == StateTag::Draft) {
            continue;
        }
        let at = MailRefs {
            proposal: Some(p.raw()),
            ..refs()
        };
        if tag == Some(StateTag::NotSelected) {
            out.push(MailItem::new(MailKind::NoticeOutcome, at));
        }
        if let Ok(Some(t)) = journal.concern(p) {
            let mut m = MailItem::new(MailKind::NoticeIrcConcern, at);
            m.since = Some(t);
            out.push(m);
        }
    }
}
