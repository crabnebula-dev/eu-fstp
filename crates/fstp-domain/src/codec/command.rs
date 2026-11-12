//! The command codec (design sections 3.3 and 7, TH-26).
//!
//! - A command is one object. Its `type` member names the variant. The
//!   other members are the variant's fields, named after them.
//! - A command carries no programme context, so a command that holds
//!   amounts has a `currency` member, as a record does. Its amounts decode
//!   with that currency (ADR-006).
//! - The command context `Ctx` is not part of the command. The shell
//!   supplies it with each command.

use fstp_json::{FromJson, FromJsonError, ToJson, Value};

use super::wire::{Cx, Wire, tagged_enum};
use crate::command::Command;

tagged_enum! {
    Command;
    fields {
        CreateProgramme { policy },
        ActivateProgramme { programme, decision, report, revision, creator_builders },
        EditPolicy { base, version },
        ApproveCallPublication { call, decision },
        PublishCall { call, config, config_model },
        GrantRole {
            binding, account, programme, role, start, second_admin, confidentiality, organisation,
            end
        },
        EndRole { binding, at },
        EndScheduledRole { binding },
        ReinstateBinding { binding, reason },
        VaultChanged { epoch, changed },
        CreateDraft { proposal, call, binding, minor },
        AddTeamMember { proposal, account, binding },
        AddGuardian { proposal, account, binding },
        Submit { proposal, plan, ethics, notice },
        DeclareConflict { subject, conflicted, notifiable },
        Assign { assignment, proposal, reviewer, kind, handle },
        Unassign { assignment },
        ReadContent { proposal },
        RecordKnockOut { decision, proposal, outcomes, reason },
        AdmitToStage1 { decision, proposal },
        RecordScore { key, values },
        CorrectScore { key, values, reason },
        RecordRankingSummary { proposal, assignment, title, neutral_summary, rationale },
        CloseStage1 { proposal },
        AskQuestion { proposal, assignment, text },
        RecordNoQuestions { proposal, assignment },
        AnswerQuestions { proposal, text },
        SubmitRevision { proposal, plan },
        RankAfterStage2 { proposal },
        ExpireStage2 { proposal },
        OpenCutOffRound { round, call, order, nominated, rationale, tie_breaks },
        CastBallot { round, vote },
        DelegateVote { round, to },
        RecordCutOff { round },
        RecordIrcReview { assignment, verdict },
        DeclineAfterConcern { proposal },
        ReEnter { proposal, call },
        AcceptGrant { decision, proposal, determination },
        ApproveGrant { decision, proposal, determination },
        ContractFact { proposal, contract, event },
        DeclineNegotiation { proposal },
        Withdraw { proposal },
        RequestCopy { proposal, address },
        StartExecution { proposal },
        Complete { proposal },
        Terminate { decision, proposal, reason },
        ApprovePayment { request },
        ReleasePayment { request, record_file },
        ConfirmPaid { request },
        WithdrawPaymentRequest { request },
        RequestPaymentChanges { request, reason },
        RecordChecks { request, phase, results, snapshot },
        RecordDeliverable {
            deliverable, grant, milestone, public_location, release, licence, snapshot, accepted
        },
        ProposeAmendment { amendment, grant, plan },
        RouteAmendment { amendment, route },
        ActivateAmendment { amendment, contract },
        CloseMilestone { proposal, milestone, reason },
        ClosePaymentRequest { request, reason },
        RequestCalibrationConsent { proposal },
        GiveCalibrationConsent { proposal, wording },
        RevokeCalibrationConsent { proposal },
        SetPublicChoice { proposal, phase, level, title, summary, grantee, deliverables },
        WithdrawPublicChoice { proposal, phase },
    }
    money {
        DraftCall { call, programme, opens, deadline, deadline_zone, budget, text },
        EditCall { call, opens, deadline, deadline_zone, budget, text },
        RecordPlanVersion { plan, proposal, origin, supersedes, tasks, content },
        DetermineAmount { decision, proposal, agreed, deductions },
        RequestPayment { request, grant, kind, lines, replaces },
        AcceptLine { request, line, approved, reason },
    }
    tuple {}
    flat {}
    flat_money {}
}

/// The JSON form of a command.
impl ToJson for Command {
    fn to_json(&self) -> Value {
        self.put()
    }
}

/// Decodes a command. Unknown and missing members are refused, and every
/// value has one spelling. Errors hold no input content (R-NF-02).
impl FromJson for Command {
    fn from_json(value: &Value) -> Result<Command, FromJsonError> {
        <Command as Wire>::take(value, Cx::NONE)
    }
}
