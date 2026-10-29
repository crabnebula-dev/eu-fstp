//! Refusals: closed rule references and reasons, with no account ids or free text (design section 3.1).
//!
//! A refusal names the rule that refused and a closed reason. It never names
//! an account and never carries text, so a refusal shown to a Judging role
//! discloses no identity (R-CF-03, `SPEC/03-architecture/overview.md` NOTE 5).

use crate::rules::ParamId;

/// The rule behind a refusal or a guard.
///
/// Every variant except the non-spec ones names an identifier that exists
/// in `SPEC/`. The test `spec_rule_refs_exist` checks this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleRef {
    /// I-01: no person holds roles from more than one of Drafting, Judging and Receiving.
    I01,
    /// I-02: no IRC member holds another Judging role.
    I02,
    /// I-03: a conflicted person neither reads nor acts as a reviewer.
    I03,
    /// I-04: no excluded person holds a Receiving role.
    I04,
    /// I-05: the milestone acceptor never releases the payment.
    I05,
    /// I-06: I-01 over verified identities.
    I06,
    /// I-07: at least P-03 assigned reviewers' scores before leaving stage 1.
    I07,
    /// I-08: passing stage 1 needs a weighted score strictly above P-02.
    I08,
    /// I-09: the effective score after stage 2 follows P-24 and names one plan.
    I09,
    /// I-10: findings never cause a transition, score or decision.
    I10,
    /// I-11: one pinned configuration per call.
    I11,
    /// I-12: frozen parameters are immutable for a published call.
    I12,
    /// I-13: granted amounts lie within P-04 after deductions.
    I13,
    /// I-14: the cumulative cap P-05 per recipient.
    I14,
    /// I-15: repeat grants and amendments need public prior deliverables.
    I15,
    /// I-18: a minor's proposal needs verified guardian consent before negotiation.
    I18,
    /// I-23: append-only records.
    I23,
    /// I-34: assigned reviewers from at least P-39 organisations.
    I34,
    /// I-35: no reviewer on a proposal declaring an affiliation on the reviewer's proximity list.
    I35,
    /// I-36: a former reviewer holds no Receiving role in a call evaluating that proposal.
    I36,
    /// I-50: P-05 never exceeds P-58.
    I50,
    /// I-64: committed amounts drop to the paid total at closure.
    I64,
    /// I-65: every imported value is confirmed or edited by a named
    /// programme manager before it takes effect.
    I65,
    /// I-66: no activation while the validation report shows a failure.
    I66,
    /// I-67: activation needs a second person who did not build the programme.
    I67,
    /// I-78: high-risk actions need a step-up.
    I78,
    /// I-84: MCP calls pass the same checks as the web interface.
    I84,
    /// I-85: high-risk actions cannot complete through MCP.
    I85,
    /// SoD-01: one of Drafting, Judging and Receiving per programme.
    Sod01,
    /// SoD-02: an IRC member holds no other Judging role.
    Sod02,
    /// SoD-03: Operations and Receiving never combine.
    Sod03,
    /// SoD-04: finance approver and payment releaser differ.
    Sod04,
    /// SoD-05: cooling-off between groups.
    Sod05,
    /// SoD-06: excluded affiliation classes hold no Receiving role.
    Sod06,
    /// SoD-07: a tenant admin's self-grant needs a second admin.
    Sod07,
    /// SoD-09: verified identity for Drafting and Judging, checked again at negotiation.
    Sod09,
    /// SoD-10: reviewers from at least P-39 organisations.
    Sod10,
    /// SoD-11: proximity lists.
    Sod11,
    /// SoD-12: mentors' Judging roles towards their grantees.
    Sod12,
    /// R-PC-01: several programmes with their own policy.
    Rpc01,
    /// R-PC-02: a published call carries a frozen policy version.
    Rpc02,
    /// R-PC-03: publication approved by a person other than its drafter.
    Rpc03,
    /// R-SB-01: only evaluation data before negotiation.
    Rsb01,
    /// R-SB-02: minors submit without guardian consent.
    Rsb02,
    /// R-SB-03: withdrawal before contract signature.
    Rsb03,
    /// R-SB-05: ethics self-declaration.
    Rsb05,
    /// R-EV-01: a failed knock-out ends review.
    Rev01,
    /// R-EV-02: at least P-03 conflict-free reviewers.
    Rev02,
    /// R-EV-03: stage 1 outcome follows the weighted score and P-02.
    Rev03,
    /// R-EV-05: stage 2 questions and revised plans.
    Rev05,
    /// R-EV-06: effective score after stage 2 follows P-24.
    Rev06,
    /// R-EV-07: no stage 2 answers within P-07 moves the proposal on.
    Rev07,
    /// R-EV-08: cut-off with remaining budget visible and rationale recorded.
    Rev08,
    /// R-EV-09: committee decisions follow P-16.
    Rev09,
    /// R-IR-01: at least P-15 IRC members review.
    Rir01,
    /// R-IR-02: an IRC concern defers or declines the proposal.
    Rir02,
    /// R-IR-04: amendments meeting P-14 skip IRC review.
    Rir04,
    /// R-NG-02: guardian consent before negotiation.
    Rng02,
    /// R-NG-03: grant amount set by the assigned reviewers within P-04 and P-05.
    Rng03,
    /// R-NG-05: repeat grants and amendments need public prior deliverables.
    Rng05,
    /// R-NG-06: data protection notice at submission and negotiation.
    Rng06,
    /// R-CF-02: declare conflicts before full content.
    Rcf02,
    /// R-CF-04: notifiable conflicts.
    Rcf04,
    /// R-AC-01: read access follows P-10.
    Rac01,
    /// R-AN-01: reviewer anonymity follows P-11.
    Ran01,
    /// R-LA-03: a named human records every decision.
    Rla03,
    /// R-LA-05: model, prompt and rubric pinned per call.
    Rla05,
    /// R-EX-04: milestone acceptance and payment release by different persons.
    Rex04,
    /// R-MC-05: binding actions through MCP follow P-77.
    Rmc05,
    /// A policy parameter (`SPEC/02-domain/policy-parameters.md`).
    Param(ParamId),
    /// Not a spec identifier: no transition row permits the change from the current state.
    Row,
    /// Not a spec identifier: the actor does not satisfy the command's actor rule.
    Actor,
    /// Not a spec identifier: a vault answer the command needs is missing.
    FactsIncomplete,
    /// Not a spec identifier: a vault answer is at another epoch than the state.
    StaleFacts,
    /// Not a spec identifier: the vault could not answer, so the command fails closed.
    OracleDown,
    /// Not a spec identifier: the structure of the ledger, such as id reuse or time order.
    Ledger,
    /// Not a spec identifier: the command input is malformed or refers to nothing.
    Input,
    /// Not a spec identifier: the lane that implements this path has not landed yet.
    NotImplemented,
}

impl RuleRef {
    /// Every variant except `Param`, in declaration order.
    /// `Param` variants are covered by `crate::rules::CATALOGUE`.
    pub const ALL_FIXED: [RuleRef; 77] = [
        RuleRef::I01,
        RuleRef::I02,
        RuleRef::I03,
        RuleRef::I04,
        RuleRef::I05,
        RuleRef::I06,
        RuleRef::I07,
        RuleRef::I08,
        RuleRef::I09,
        RuleRef::I10,
        RuleRef::I11,
        RuleRef::I12,
        RuleRef::I13,
        RuleRef::I14,
        RuleRef::I15,
        RuleRef::I18,
        RuleRef::I23,
        RuleRef::I34,
        RuleRef::I35,
        RuleRef::I36,
        RuleRef::I50,
        RuleRef::I64,
        RuleRef::I65,
        RuleRef::I66,
        RuleRef::I67,
        RuleRef::I78,
        RuleRef::I84,
        RuleRef::I85,
        RuleRef::Sod01,
        RuleRef::Sod02,
        RuleRef::Sod03,
        RuleRef::Sod04,
        RuleRef::Sod05,
        RuleRef::Sod06,
        RuleRef::Sod07,
        RuleRef::Sod09,
        RuleRef::Sod10,
        RuleRef::Sod11,
        RuleRef::Sod12,
        RuleRef::Rpc01,
        RuleRef::Rpc02,
        RuleRef::Rpc03,
        RuleRef::Rsb01,
        RuleRef::Rsb02,
        RuleRef::Rsb03,
        RuleRef::Rsb05,
        RuleRef::Rev01,
        RuleRef::Rev02,
        RuleRef::Rev03,
        RuleRef::Rev05,
        RuleRef::Rev06,
        RuleRef::Rev07,
        RuleRef::Rev08,
        RuleRef::Rev09,
        RuleRef::Rir01,
        RuleRef::Rir02,
        RuleRef::Rir04,
        RuleRef::Rng02,
        RuleRef::Rng03,
        RuleRef::Rng05,
        RuleRef::Rng06,
        RuleRef::Rcf02,
        RuleRef::Rcf04,
        RuleRef::Rac01,
        RuleRef::Ran01,
        RuleRef::Rla03,
        RuleRef::Rla05,
        RuleRef::Rex04,
        RuleRef::Rmc05,
        RuleRef::Row,
        RuleRef::Actor,
        RuleRef::FactsIncomplete,
        RuleRef::StaleFacts,
        RuleRef::OracleDown,
        RuleRef::Ledger,
        RuleRef::Input,
        RuleRef::NotImplemented,
    ];

    /// The spec identifier this rule names, such as `"I-01"`, `"SoD-09"`,
    /// `"R-PC-03"` or `"P-12"`. `None` for the non-spec variants.
    pub const fn spec_id(self) -> Option<&'static str> {
        let id = match self {
            RuleRef::I01 => "I-01",
            RuleRef::I02 => "I-02",
            RuleRef::I03 => "I-03",
            RuleRef::I04 => "I-04",
            RuleRef::I05 => "I-05",
            RuleRef::I06 => "I-06",
            RuleRef::I07 => "I-07",
            RuleRef::I08 => "I-08",
            RuleRef::I09 => "I-09",
            RuleRef::I10 => "I-10",
            RuleRef::I11 => "I-11",
            RuleRef::I12 => "I-12",
            RuleRef::I13 => "I-13",
            RuleRef::I14 => "I-14",
            RuleRef::I15 => "I-15",
            RuleRef::I18 => "I-18",
            RuleRef::I23 => "I-23",
            RuleRef::I34 => "I-34",
            RuleRef::I35 => "I-35",
            RuleRef::I36 => "I-36",
            RuleRef::I50 => "I-50",
            RuleRef::I64 => "I-64",
            RuleRef::I65 => "I-65",
            RuleRef::I66 => "I-66",
            RuleRef::I67 => "I-67",
            RuleRef::I78 => "I-78",
            RuleRef::I84 => "I-84",
            RuleRef::I85 => "I-85",
            RuleRef::Sod01 => "SoD-01",
            RuleRef::Sod02 => "SoD-02",
            RuleRef::Sod03 => "SoD-03",
            RuleRef::Sod04 => "SoD-04",
            RuleRef::Sod05 => "SoD-05",
            RuleRef::Sod06 => "SoD-06",
            RuleRef::Sod07 => "SoD-07",
            RuleRef::Sod09 => "SoD-09",
            RuleRef::Sod10 => "SoD-10",
            RuleRef::Sod11 => "SoD-11",
            RuleRef::Sod12 => "SoD-12",
            RuleRef::Rpc01 => "R-PC-01",
            RuleRef::Rpc02 => "R-PC-02",
            RuleRef::Rpc03 => "R-PC-03",
            RuleRef::Rsb01 => "R-SB-01",
            RuleRef::Rsb02 => "R-SB-02",
            RuleRef::Rsb03 => "R-SB-03",
            RuleRef::Rsb05 => "R-SB-05",
            RuleRef::Rev01 => "R-EV-01",
            RuleRef::Rev02 => "R-EV-02",
            RuleRef::Rev03 => "R-EV-03",
            RuleRef::Rev05 => "R-EV-05",
            RuleRef::Rev06 => "R-EV-06",
            RuleRef::Rev07 => "R-EV-07",
            RuleRef::Rev08 => "R-EV-08",
            RuleRef::Rev09 => "R-EV-09",
            RuleRef::Rir01 => "R-IR-01",
            RuleRef::Rir02 => "R-IR-02",
            RuleRef::Rir04 => "R-IR-04",
            RuleRef::Rng02 => "R-NG-02",
            RuleRef::Rng03 => "R-NG-03",
            RuleRef::Rng05 => "R-NG-05",
            RuleRef::Rng06 => "R-NG-06",
            RuleRef::Rcf02 => "R-CF-02",
            RuleRef::Rcf04 => "R-CF-04",
            RuleRef::Rac01 => "R-AC-01",
            RuleRef::Ran01 => "R-AN-01",
            RuleRef::Rla03 => "R-LA-03",
            RuleRef::Rla05 => "R-LA-05",
            RuleRef::Rex04 => "R-EX-04",
            RuleRef::Rmc05 => "R-MC-05",
            RuleRef::Param(p) => p.spec_id(),
            RuleRef::Row
            | RuleRef::Actor
            | RuleRef::FactsIncomplete
            | RuleRef::StaleFacts
            | RuleRef::OracleDown
            | RuleRef::Ledger
            | RuleRef::Input
            | RuleRef::NotImplemented => return None,
        };
        Some(id)
    }
}

/// Why a rule refused. Closed and fieldless, so it carries no account and no text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalReason {
    /// The lane that implements this path has not landed yet.
    NotImplemented,
    /// The proposal or call is in a state from which the command does not apply.
    WrongState,
    /// The actor is not the kind of actor the command needs.
    WrongActor,
    /// The actor's binding is not active now: not started, ended, suspended or voided.
    BindingInactive,
    /// A guard of the rule does not hold.
    GuardFailed,
    /// The vault answered so that the rule refuses.
    VaultRefused,
    /// A vault answer the command needs is missing.
    AnswerMissing,
    /// A vault answer is at another epoch than the state.
    AnswerStale,
    /// The vault could not answer.
    OracleUnavailable,
    /// A shell-supplied id is already taken.
    IdReused,
    /// The command time is earlier than the latest recorded time.
    ClockBackwards,
    /// The command refers to an entity that does not exist.
    UnknownEntity,
    /// A value is inconsistent or unsafe for exact arithmetic.
    InvalidValue,
    /// The command cannot complete through MCP (I-85, P-77).
    NotThroughMcp,
}

/// A refusal of a command by `queries` or `decide`. Nothing is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Refusal {
    /// The rule that refused.
    pub rule: RuleRef,
    /// Why it refused.
    pub reason: RefusalReason,
}

impl Refusal {
    /// A refusal by `rule` for `reason`.
    pub const fn new(rule: RuleRef, reason: RefusalReason) -> Refusal {
        Refusal { rule, reason }
    }

    /// The refusal of a stub whose lane has not landed. No engine path
    /// returns it since step W5 integration. It stays for the codec and
    /// for test doubles.
    pub const fn not_implemented() -> Refusal {
        Refusal::new(RuleRef::NotImplemented, RefusalReason::NotImplemented)
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.rule.spec_id() {
            Some(id) => write!(f, "refused by {id}: {:?}", self.reason),
            None => write!(f, "refused ({:?}): {:?}", self.rule, self.reason),
        }
    }
}

impl std::error::Error for Refusal {}
