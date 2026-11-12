//! The record codec (design sections 2.10, 5.1 and 7, I-23, ADR-007).
//!
//! - A record is one object. Its `type` member names the variant. The
//!   other members are the variant's fields, named after them.
//! - A record that holds amounts has a `currency` member with the
//!   programme currency code. Its amounts decode with that currency.
//! - Free text appears only as a `TextRef` of id and digest (ADR-007).
//! - The four payloads that only a witness builds decode through their
//!   crate-private `from_decoded` seams. Their witnesses have no codec.
//!   The activation payload of M4 change D2 decodes the same way.

use std::collections::BTreeSet;

use fstp_json::{FromJson, FromJsonError, Object, ToJson, Value};
use fstp_money::{Currency, NonNegAmount, Percent, Ratio};

use super::wire::{Cx, Fields, Flat, R, Wire, flat_struct, tagged_enum};
use crate::decision::{Basis, EffectiveScoreSet, Stage1Closed};
use crate::grant::GrantDecided;
use crate::id::VaultEpoch;
use crate::id::{
    AccountId, ContentDigest, ContractId, DecisionId, PlanVersionId, ProgrammeId, ProposalId,
    RequestId,
};
use crate::payment::PaymentReleased;
use crate::policy::activation::{ProgrammeActivated, ReportDigest};
use crate::record::{
    Assigned, AssignmentReleased, BindingEnded, BindingGranted, BindingReinstated,
    BindingSuspended, BindingVoided, ConflictDeclared, ConflictDetected, ContentRead,
    CutOffRecorded, DeliverableRecorded, PlanVersionRecorded, Record, RulesVersion, ScoreRecorded,
    ScoreVoided, Transitioned,
};
use crate::scoring::ScoreKey;

flat_struct!(BindingGranted {
    binding,
    account,
    programme,
    role,
    scope,
    start,
    granted_by,
    second_admin,
    confidentiality,
    organisation,
    verified_epoch,
});
flat_struct!(BindingEnded {
    binding,
    at,
    barred_through,
    p12
});
flat_struct!(BindingSuspended {
    binding,
    rule,
    epoch
});
flat_struct!(BindingVoided {
    binding,
    rule,
    epoch
});
flat_struct!(BindingReinstated {
    binding,
    by,
    reason
});
flat_struct!(Assigned {
    assignment,
    proposal,
    call,
    reviewer,
    kind,
    handle,
    by,
    epoch,
});
flat_struct!(ConflictDeclared {
    subject,
    conflicted,
    notifiable
});
flat_struct!(ConflictDetected {
    account,
    proposal,
    notifiable,
    epoch
});
flat_struct!(AssignmentReleased { assignment, cause });
flat_struct!(ContentRead { account, proposal });
flat_struct!(PlanVersionRecorded {
    plan,
    proposal,
    origin,
    supersedes,
    tasks,
    content,
});
flat_struct!(ScoreRecorded {
    key,
    values,
    supersedes,
    reason
});
flat_struct!(ScoreVoided { key, cause });
flat_struct!(CutOffRecorded {
    decision,
    call,
    order,
    nominated,
    rationale,
    tie_breaks,
    ballots,
    recused,
    remaining_budget,
    recorder,
    rules,
});
flat_struct!(DeliverableRecorded {
    deliverable,
    grant,
    milestone,
    public_location,
    release,
    licence,
    snapshot,
    accepted,
});
flat_struct!(Transitioned {
    proposal,
    from,
    to,
    row,
    actor,
    decision
});

/// The stage 1 exit payload. Its fields are private, so it is written from
/// its accessors and read through `Stage1Closed::from_decoded`.
impl Flat for Stage1Closed {
    const NAMES: &'static [&'static str] = &[
        "proposal",
        "recorder",
        "score",
        "threshold",
        "counted",
        "passed",
        "rules",
    ];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("proposal", self.proposal().put());
        let _ = o.insert("recorder", self.recorder().put());
        let _ = o.insert("score", self.score().put());
        let _ = o.insert("threshold", self.threshold().put());
        let _ = o.insert("counted", self.counted().put());
        let _ = o.insert("passed", self.passed().put());
        let _ = o.insert("rules", self.rules().put());
    }

    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self> {
        let proposal: ProposalId = f.get("proposal", cx)?;
        let recorder: AccountId = f.get("recorder", cx)?;
        let score: Ratio = f.get("score", cx)?;
        let threshold: Percent = f.get("threshold", cx)?;
        let counted: BTreeSet<ScoreKey> = f.get("counted", cx)?;
        let passed: bool = f.get("passed", cx)?;
        let rules: RulesVersion = f.get("rules", cx)?;
        Ok(Stage1Closed::from_decoded(
            proposal, recorder, score, threshold, counted, passed, rules,
        ))
    }
}

/// The effective score payload, read through `EffectiveScoreSet::from_decoded`.
impl Flat for EffectiveScoreSet {
    const NAMES: &'static [&'static str] =
        &["proposal", "plan", "value", "basis", "counted", "rules"];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("proposal", self.proposal().put());
        let _ = o.insert("plan", self.plan().put());
        let _ = o.insert("value", self.value().put());
        let _ = o.insert("basis", self.basis().put());
        let _ = o.insert("counted", self.counted().put());
        let _ = o.insert("rules", self.rules().put());
    }

    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self> {
        let proposal: ProposalId = f.get("proposal", cx)?;
        let plan: PlanVersionId = f.get("plan", cx)?;
        let value: Ratio = f.get("value", cx)?;
        let basis: Basis = f.get("basis", cx)?;
        let counted: BTreeSet<ScoreKey> = f.get("counted", cx)?;
        let rules: RulesVersion = f.get("rules", cx)?;
        Ok(EffectiveScoreSet::from_decoded(
            proposal, plan, value, basis, counted, rules,
        ))
    }
}

/// The grant payload, read through `GrantDecided::from_decoded`.
impl Flat for GrantDecided {
    const NAMES: &'static [&'static str] = &[
        "proposal",
        "granted",
        "agreed_plan",
        "acceptance",
        "approval",
        "contract",
        "epoch",
        "rules",
    ];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("proposal", self.proposal().put());
        let _ = o.insert("granted", self.granted().put());
        let _ = o.insert("agreed_plan", self.agreed_plan().put());
        let _ = o.insert("acceptance", self.acceptance().put());
        let _ = o.insert("approval", self.approval().put());
        let _ = o.insert("contract", self.contract().put());
        let _ = o.insert("epoch", self.epoch().put());
        let _ = o.insert("rules", self.rules().put());
    }

    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self> {
        let proposal: ProposalId = f.get("proposal", cx)?;
        let granted: NonNegAmount = f.get("granted", cx)?;
        let agreed_plan: PlanVersionId = f.get("agreed_plan", cx)?;
        let acceptance: DecisionId = f.get("acceptance", cx)?;
        let approval: DecisionId = f.get("approval", cx)?;
        let contract: ContractId = f.get("contract", cx)?;
        let epoch: VaultEpoch = f.get("epoch", cx)?;
        let rules: RulesVersion = f.get("rules", cx)?;
        Ok(GrantDecided::from_decoded(
            proposal,
            granted,
            agreed_plan,
            acceptance,
            approval,
            contract,
            epoch,
            rules,
        ))
    }

    fn flat_currency(&self) -> Option<Currency> {
        Wire::currency(&self.granted())
    }
}

/// The activation payload (M4 change D2), read through
/// `ProgrammeActivated::from_decoded`. It holds no amount, so it has no
/// `currency` member.
impl Flat for ProgrammeActivated {
    const NAMES: &'static [&'static str] = &[
        "programme",
        "decision",
        "report",
        "revision",
        "approver",
        "builders",
        "rules",
    ];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("programme", self.programme().put());
        let _ = o.insert("decision", self.decision().put());
        let _ = o.insert("report", self.report().put());
        let _ = o.insert("revision", self.revision().put());
        let _ = o.insert("approver", self.approver().put());
        let _ = o.insert("builders", self.builders().put());
        let _ = o.insert("rules", self.rules().put());
    }

    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self> {
        let programme: ProgrammeId = f.get("programme", cx)?;
        let decision: DecisionId = f.get("decision", cx)?;
        let report: ReportDigest = f.get("report", cx)?;
        let revision: u32 = f.get("revision", cx)?;
        let approver: AccountId = f.get("approver", cx)?;
        let builders: BTreeSet<AccountId> = f.get("builders", cx)?;
        let rules: RulesVersion = f.get("rules", cx)?;
        Ok(ProgrammeActivated::from_decoded(
            programme, decision, report, revision, approver, builders, rules,
        ))
    }
}

/// The release payload, read through `PaymentReleased::from_decoded`.
impl Flat for PaymentReleased {
    const NAMES: &'static [&'static str] = &[
        "request",
        "grant",
        "acceptors",
        "approver",
        "releaser",
        "record_file",
    ];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("request", self.request().put());
        let _ = o.insert("grant", self.grant().put());
        let _ = o.insert("acceptors", self.acceptors().put());
        let _ = o.insert("approver", self.approver().put());
        let _ = o.insert("releaser", self.releaser().put());
        let _ = o.insert("record_file", self.record_file().put());
    }

    fn take_from(f: &Fields<'_>, cx: Cx) -> R<Self> {
        let request: RequestId = f.get("request", cx)?;
        let grant: ProposalId = f.get("grant", cx)?;
        let acceptors: BTreeSet<AccountId> = f.get("acceptors", cx)?;
        let approver: AccountId = f.get("approver", cx)?;
        let releaser: AccountId = f.get("releaser", cx)?;
        let record_file: ContentDigest = f.get("record_file", cx)?;
        Ok(PaymentReleased::from_decoded(
            request,
            grant,
            acceptors,
            approver,
            releaser,
            record_file,
        ))
    }
}

tagged_enum! {
    Record;
    fields {
        ProgrammeCreated { programme, currency, by },
        PolicyVersionRecorded { version, author },
        CallApproved { call, decision, approver },
        CallPublished { call, policy, seq, config, by },
        GuidePublished { call, version, digest, canonical, page },
        VaultEpochProcessed { epoch },
        BindingEndScheduled { binding, at },
        ProposalCreated { proposal, call, lead, minor },
        Submitted { proposal, plan, ethics, notice },
        KnockOutRecorded { decision, proposal, coordinator, outcomes, reason, rules },
        RankingSummaryRecorded { proposal, assignment, title, neutral_summary, rationale },
        QuestionAsked { proposal, assignment, text },
        NoQuestionsRecorded { proposal, assignment },
        AnswersRecorded { proposal, text },
        RevisionSubmitted { proposal, plan },
        CutOffRoundOpened { round, call, order, nominated, rationale, tie_breaks, by },
        BallotCast { round, voter, vote },
        VoteDelegated { round, from, to },
        IrcReviewRecorded { assignment, verdict },
        DeferralRecorded { proposal, from_call, left },
        ReEntered { proposal, from_call, to_call, stage },
        GrantAccepted { decision, proposal, by },
        GrantApproved { decision, proposal, by },
        ContractFactRecorded { proposal, contract, event },
        NegotiationDeclined { proposal, reason, rules },
        TerminationRecorded { decision, proposal, by, reason },
        VaultOutcome { kind, digest, holds, epoch },
        TermsAccepted { account, programme, role, invitation, version, terms },
        PaymentApproved { request, by },
        PaymentConfirmed { request, by },
        PaymentRequestWithdrawn { request, by },
        PaymentChangesRequested { request, by, reason },
        AmendmentProposed { amendment, grant, plan, by },
        AmendmentRouted { amendment, route, by },
        AmendmentActivated { amendment, plan, route, contract },
        MilestoneClosed { proposal, milestone, by, reason },
        PaymentRequestClosed { request, by, reason },
        ChecksRecorded { request, phase, results, snapshot },
        CalibrationConsentRequested { proposal, notice, by },
        CalibrationConsentGiven { proposal, wording, by },
        CalibrationConsentRevoked { proposal, by },
        PublicChoiceSet { proposal, phase, level, title, summary, grantee, deliverables, by },
        PublicChoiceWithdrawn { proposal, phase, by },
    }
    money {
        CallDrafted { call, programme, opens, deadline, deadline_zone, budget, text, author },
        CallEdited { call, opens, deadline, deadline_zone, budget, text, author },
        AmountDetermined { decision, proposal, plan_total, deductions, granted, agreed, by, rules },
        CapReserved { proposal, amount, epoch },
        CapReleased { proposal, amount },
        PaymentRequested { request, grant, kind, lines },
        LineAccepted { request, line, by, approved, reason },
    }
    tuple { OutboxEnqueued(event) }
    flat {
        BindingGranted(BindingGranted),
        BindingEnded(BindingEnded),
        BindingSuspended(BindingSuspended),
        BindingVoided(BindingVoided),
        BindingReinstated(BindingReinstated),
        Assigned(Assigned),
        ConflictDeclared(ConflictDeclared),
        ConflictDetected(ConflictDetected),
        AssignmentReleased(AssignmentReleased),
        ContentRead(ContentRead),
        ScoreRecorded(ScoreRecorded),
        ScoreVoided(ScoreVoided),
        ProgrammeActivated(ProgrammeActivated),
        Stage1Closed(Stage1Closed),
        EffectiveScoreSet(EffectiveScoreSet),
        Transitioned(Transitioned),
        PaymentReleased(PaymentReleased),
        DeliverableRecorded(DeliverableRecorded),
    }
    flat_money {
        PlanVersionRecorded(PlanVersionRecorded),
        CutOffRecorded(CutOffRecorded),
        GrantDecided(GrantDecided),
    }
}

/// The JSON form of a record at the current schema version (design section 5.1).
impl ToJson for Record {
    fn to_json(&self) -> Value {
        self.put()
    }
}

/// Decodes a record at the current schema version. Unknown and missing
/// members are refused, and every value has one spelling, so stored bytes
/// are unique (ADR-007). Errors hold no input content (R-NF-02).
impl FromJson for Record {
    fn from_json(value: &Value) -> Result<Record, FromJsonError> {
        <Record as Wire>::take(value, Cx::NONE)
    }
}
