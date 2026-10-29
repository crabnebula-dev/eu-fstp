//! Generators, setups and the money world, with synthetic data only (design sections 4.5 and 6.1).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10).
//!
//! - [`MoneySetup`] builds a start state from genesis by production
//!   commands: one programme with the setup's P-04 and P-05, the Judging
//!   and Operations bindings, proposals with the setup's plans, and the
//!   proposals it names driven to NEGOTIATION through stage 1, stage 2
//!   with "no questions", one cut-off and the IRC review.
//! - The vault of a setup gives every account its own identity, except
//!   the pairs it names, where the second account takes the identity of
//!   the first (corpus variant "Sybil"). Every account is verified unless
//!   the setup names it as unverified.
//! - [`MoneyWorld`] is the model driver. It wraps the lifecycle world,
//!   which runs production `queries`, `decide` and `apply` without a store
//!   and keeps the L-SOD, L-REV and L-LIFE reference views, and adds the
//!   money view. [`MoneyWorld::step`] compares each command of this lane
//!   with [`money_verdict`] in both directions, checks the records an
//!   accepted one must hold, and folds every batch into the money view.
//!   Its [`Backend::Reference`] mode runs the same steps on the references
//!   alone, which checks the tests before production lands.
//! - [`MoneyStory`] drives a world along its rows for the example tests.
//! - [`MoneyMachine`] is the fstp-prop machine of
//!   `i13_i14_grant_sequences_respect_range_and_cap` and
//!   `i14_p05_edit_below_committed_is_refused`.
//! - The two commands the interface does not declare yet,
//!   `CloseMilestone { proposal, milestone, reason }` and
//!   `ClosePaymentRequest { request, reason }`, are built through the
//!   command codec. Until the codec knows them, building them fails, so a
//!   test that needs them is red for that reason alone.
//! - `AcceptGrant` and `ApproveGrant` name the amount determination they
//!   accept, by its decision id, in the member `determination` (Q-W7-7,
//!   decided 2026-10-28). Every `AcceptGrant` and `ApproveGrant` the kit
//!   builds carries that member. [`accept_grant_naming`] and
//!   [`approve_grant_naming`] build one that may name a superseded
//!   determination, and round-trip it through the command codec. The
//!   other grant fact steps name the determination they are given.

use std::collections::BTreeSet;

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, ContractEvent, DeclarationSubject, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::grant::IneligibleCost;
use fstp_domain::id::{
    AccountId, AmendmentId, AssignmentId, CommandId, ContentDigest, ContractId, DecisionId,
    DeliverableId, LineId, MilestoneId, OrganisationId, PlanVersionId, PolicyVersionId, ProposalId,
    RequestId, TextRef,
};
use fstp_domain::oracle::Answers;
use fstp_domain::payment::PaymentLine;
use fstp_domain::policy::{PolicyVersion, SpdxId};
use fstp_domain::proposal::{Milestone, PlanOrigin, Task};
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_json::{ToJson, Value};
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, PosAmount};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::policy::text;
use crate::r#gen::review::{COORDINATOR, IRC, R1, R2, R3, after, declare, plan_of, submit, tag};
use crate::r#gen::roster::{Backend, Flags, STAFF_PM, Step, add_staff, call, edit_policy};
use crate::mc::life_model::{
    IRC2, LifeSetup, LifeWorld, Start, admit, assign_declared, assignment_of, ballots, close,
    cut_off, cut_off_decision, irc_review, knock_out, life_judges, no_questions, score,
};
use crate::reference::money::{
    Ext, MoneyCx, MoneyVerdict, MoneyView, check_i13, check_i14, check_i15, check_i64,
    check_money_batch, ext_verdict, money_verdict, withdraw_release,
};
use crate::reference::payment::{check_i05, check_sod12};
use crate::vault::{GroundTruth, IdentityTag};

// ---------------------------------------------------------------------------
// Synthetic accounts and ids
// ---------------------------------------------------------------------------

/// Lead a: shares an identity with lead b (corpus variant "Sybil").
pub const LA: AccountId = AccountId::from_raw(401);
/// Lead b: the Sybil of lead a.
pub const LB: AccountId = AccountId::from_raw(402);
/// Lead c: a distinct identity.
pub const LC: AccountId = AccountId::from_raw(403);
/// The finance approver.
pub const FIN: AccountId = AccountId::from_raw(501);
/// A payment releaser who holds no other role.
pub const REL: AccountId = AccountId::from_raw(502);
/// A finance approver who is also a payment releaser.
pub const FINREL: AccountId = AccountId::from_raw(503);

/// The proposal of lead a.
pub const PA: ProposalId = ProposalId::from_raw(11);
/// The proposal of lead b.
pub const PB: ProposalId = ProposalId::from_raw(12);
/// The proposal of lead c.
pub const PC: ProposalId = ProposalId::from_raw(13);

/// The instant of every money command: one second after every call deadline.
pub use crate::mc::life_model::T_EVAL;

/// The command id every money world command uses. The pure functions never read it.
const MONEY_COMMAND: CommandId = CommandId::from_bytes(*b"model:money:step");

/// The `n`-th milestone of `proposal`.
pub fn milestone_n(proposal: ProposalId, n: u128) -> MilestoneId {
    MilestoneId::from_raw(
        600u128
            .saturating_add(proposal.raw())
            .saturating_add(n.saturating_mul(1_000)),
    )
}

/// The `n`-th amount decision of `proposal`.
pub fn amount_decision(proposal: ProposalId, n: u128) -> DecisionId {
    DecisionId::from_raw(
        20_000u128
            .saturating_add(proposal.raw().saturating_mul(100))
            .saturating_add(n),
    )
}

/// The acceptance decision of `proposal`.
pub fn accept_decision(proposal: ProposalId) -> DecisionId {
    DecisionId::from_raw(21_000u128.saturating_add(proposal.raw()))
}

/// The acceptance decision of `proposal` after its `n`-th amount
/// determination. For `n` at most 1 it is [`accept_decision`]. A later
/// one is fresh, since a new amount needs a new acceptance (NOTE 9,
/// decided 2026-10-28).
pub fn accept_decision_n(proposal: ProposalId, n: u128) -> DecisionId {
    if n <= 1 {
        return accept_decision(proposal);
    }
    DecisionId::from_raw(
        25_000u128
            .saturating_add(proposal.raw().saturating_mul(100))
            .saturating_add(n),
    )
}

/// The approval decision of `proposal`.
pub fn approve_decision(proposal: ProposalId) -> DecisionId {
    DecisionId::from_raw(22_000u128.saturating_add(proposal.raw()))
}

/// The approval decision of `proposal` after its `n`-th amount
/// determination. For `n` at most 1 it is [`approve_decision`]. A later
/// one is fresh, since a new amount needs a new approval (NOTE 9, decided
/// 2026-10-28).
pub fn approve_decision_n(proposal: ProposalId, n: u128) -> DecisionId {
    if n <= 1 {
        return approve_decision(proposal);
    }
    DecisionId::from_raw(
        26_000u128
            .saturating_add(proposal.raw().saturating_mul(100))
            .saturating_add(n),
    )
}

/// The termination decision of `proposal`.
pub fn terminate_decision(proposal: ProposalId) -> DecisionId {
    DecisionId::from_raw(23_000u128.saturating_add(proposal.raw()))
}

/// The contract of `proposal`.
pub fn contract_of(proposal: ProposalId) -> ContractId {
    ContractId::from_raw(24_000u128.saturating_add(proposal.raw()))
}

/// The contract of `proposal` for its `n`-th amount determination. For
/// `n` at most 1 it is [`contract_of`]. A new amount clears the contract
/// fact of the old one, so the contract port reports the contract of the
/// new amount (Q-W7-4, decided 2026-10-28).
pub fn contract_of_n(proposal: ProposalId, n: u128) -> ContractId {
    if n <= 1 {
        return contract_of(proposal);
    }
    ContractId::from_raw(
        27_000u128
            .saturating_add(proposal.raw().saturating_mul(100))
            .saturating_add(n),
    )
}

/// EUR `minor` cents, at least zero.
pub fn nonneg(minor: i64) -> Result<NonNegAmount, String> {
    Amount::from_minor(minor, Currency::Eur)
        .and_then(NonNegAmount::new)
        .map_err(|e| format!("amount: {e:?}"))
}

/// EUR `minor` cents, above zero.
pub fn pos(minor: i64) -> Result<PosAmount, String> {
    Amount::from_minor(minor, Currency::Eur)
        .and_then(PosAmount::new)
        .map_err(|e| format!("amount: {e:?}"))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

fn by(account: AccountId, cmd: Command) -> Step {
    Step::by(account, Flags::NONE, cmd)
}

fn system(cause: SystemCause, cmd: Command) -> Step {
    Step {
        actor: Actor::System(cause),
        flags: Flags::NONE,
        cmd,
    }
}

/// A `DetermineAmount` by `reviewer` on the effective plan `agreed`, with
/// one deduction per amount in `deductions`, each with a synthetic reason.
pub fn determine(
    reviewer: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    agreed: PlanVersionId,
    deductions: &[i64],
) -> Result<Step, String> {
    let mut out = Vec::new();
    for (i, d) in (0u128..).zip(deductions) {
        out.push(IneligibleCost {
            amount: pos(*d)?,
            reason: text(
                90_000u128
                    .saturating_add(proposal.raw().saturating_mul(10))
                    .saturating_add(i),
            ),
        });
    }
    Ok(by(
        reviewer,
        Command::DetermineAmount {
            decision,
            proposal,
            agreed,
            deductions: out,
        },
    ))
}

/// The JSON form of the decision id `d`, as a command member carries it.
fn decision_json(d: DecisionId) -> Result<Value, String> {
    let probe = Command::Terminate {
        decision: d,
        proposal: ProposalId::from_raw(0),
        reason: text(0),
    }
    .to_json();
    member(probe, "decision")
}

/// `cmd` with the member `determination` set to `determination`, built
/// through the command codec (Q-W7-7, decided 2026-10-28). It fails only if
/// the codec refuses the result.
pub fn with_determination(cmd: &Command, determination: DecisionId) -> Result<Command, String> {
    let Value::Object(mut o) = cmd.to_json() else {
        return Err("a command encodes as an object".to_owned());
    };
    let _ = o.insert("determination", decision_json(determination)?);
    fstp_domain::codec::command_from_json(&Value::Object(o)).map_err(|e| {
        format!(
            "the command codec does not know the determination member of {cmd:?} yet ({e:?}), \
             Q-W7-7"
        )
    })
}

/// The `AcceptGrant` of `decision` on `proposal`, naming `determination`
/// (Q-W7-7, decided 2026-10-28).
fn accept_cmd(decision: DecisionId, proposal: ProposalId, determination: DecisionId) -> Command {
    Command::AcceptGrant {
        decision,
        proposal,
        determination,
    }
}

/// The `ApproveGrant` of `decision` on `proposal`, naming `determination`
/// (Q-W7-7, decided 2026-10-28).
fn approve_cmd(decision: DecisionId, proposal: ProposalId, determination: DecisionId) -> Command {
    Command::ApproveGrant {
        decision,
        proposal,
        determination,
    }
}

/// The lead's `AcceptGrant`, naming the first determination
/// [`amount_decision`] `(proposal, 1)` (Q-W7-7).
pub fn accept_grant(lead: AccountId, proposal: ProposalId) -> Step {
    by(
        lead,
        accept_cmd(
            accept_decision(proposal),
            proposal,
            amount_decision(proposal, 1),
        ),
    )
}

/// The lead's `AcceptGrant` with the decision id `decision`, naming the
/// current determination `determination`, as given again after a new
/// amount (NOTE 9, Q-W7-7, decided 2026-10-28).
pub fn accept_grant_as(
    lead: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    determination: DecisionId,
) -> Step {
    by(lead, accept_cmd(decision, proposal, determination))
}

/// The programme manager's `ApproveGrant` with the decision id
/// `decision`, naming the current determination `determination`, as given
/// again after a new amount (NOTE 9, Q-W7-7, decided 2026-10-28).
pub fn approve_grant_as(
    pm: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    determination: DecisionId,
) -> Step {
    by(pm, approve_cmd(decision, proposal, determination))
}

/// The lead's `AcceptGrant` with the decision id `decision`, naming
/// `determination`, which may be superseded (Q-W7-7, decided 2026-10-28).
/// It is built through the command codec.
pub fn accept_grant_naming(
    lead: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    determination: DecisionId,
) -> Result<Step, String> {
    let base = accept_cmd(decision, proposal, determination);
    Ok(by(lead, with_determination(&base, determination)?))
}

/// The programme manager's `ApproveGrant` with the decision id
/// `decision`, naming `determination`, which may be superseded (Q-W7-7,
/// decided 2026-10-28). It is built through the command codec.
pub fn approve_grant_naming(
    pm: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    determination: DecisionId,
) -> Result<Step, String> {
    let base = approve_cmd(decision, proposal, determination);
    Ok(by(pm, with_determination(&base, determination)?))
}

/// The determination `cmd` names, read from its JSON form (Q-W7-7).
/// `None` for a command without the member.
pub fn named_determination(cmd: &Command) -> Option<DecisionId> {
    match member(cmd.to_json(), "determination") {
        Ok(Value::String(s)) => s.parse::<u128>().ok().map(DecisionId::from_raw),
        _ => None,
    }
}

/// The programme manager's `ApproveGrant`, naming the first determination
/// [`amount_decision`] `(proposal, 1)` (Q-W7-7).
pub fn approve_grant(pm: AccountId, proposal: ProposalId) -> Step {
    by(
        pm,
        approve_cmd(
            approve_decision(proposal),
            proposal,
            amount_decision(proposal, 1),
        ),
    )
}

/// The contract port's EFFECTIVE fact.
pub fn contract_effective(proposal: ProposalId) -> Step {
    contract_effective_as(proposal, contract_of(proposal))
}

/// The contract port's EFFECTIVE fact for the contract `contract`.
pub fn contract_effective_as(proposal: ProposalId, contract: ContractId) -> Step {
    system(
        SystemCause::ContractPort,
        Command::ContractFact {
            proposal,
            contract,
            event: ContractEvent::Effective,
        },
    )
}

/// `DeclineNegotiation` by `actor`.
pub fn decline_negotiation(actor: Actor, proposal: ProposalId) -> Step {
    Step {
        actor,
        flags: Flags::NONE,
        cmd: Command::DeclineNegotiation { proposal },
    }
}

/// The System's `StartExecution`.
pub fn start_execution(proposal: ProposalId) -> Step {
    system(SystemCause::Timeline, Command::StartExecution { proposal })
}

/// The System's `Complete`.
pub fn complete(proposal: ProposalId) -> Step {
    system(SystemCause::Timeline, Command::Complete { proposal })
}

/// A `Terminate` by `actor` with a synthetic reason.
pub fn terminate(actor: AccountId, proposal: ProposalId) -> Step {
    by(
        actor,
        Command::Terminate {
            decision: terminate_decision(proposal),
            proposal,
            reason: text(91_000u128.saturating_add(proposal.raw())),
        },
    )
}

fn member(v: Value, name: &str) -> Result<Value, String> {
    match v {
        Value::Object(o) => o
            .get(name)
            .cloned()
            .ok_or_else(|| format!("no member {name}")),
        _ => Err("not an object".to_owned()),
    }
}

/// Builds a command of the JSON object `members` through the command
/// codec. The codec decides whether the command exists.
fn decoded(type_name: &str, members: Vec<(&str, Value)>) -> Result<Command, String> {
    let mut o = fstp_json::Object::new();
    let _ = o.insert("type", Value::String(type_name.to_owned()));
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    fstp_domain::codec::command_from_json(&Value::Object(o)).map_err(|e| {
        format!("the command codec does not know {type_name} yet ({e:?}), lane scope W5")
    })
}

/// The synthetic reason of [`close_milestone`] for `milestone`.
pub fn milestone_close_reason(milestone: MilestoneId) -> TextRef {
    text(92_000u128.saturating_add(milestone.raw()))
}

/// The synthetic reason of [`close_request`] for `request`.
pub fn request_close_reason(request: RequestId) -> TextRef {
    text(93_000u128.saturating_add(request.raw()))
}

/// The programme manager's `CloseMilestone { proposal, milestone, reason }`
/// with a synthetic reason (NOTE 12, O-51), built through the command codec.
pub fn close_milestone(
    pm: AccountId,
    proposal: ProposalId,
    milestone: MilestoneId,
) -> Result<Step, String> {
    let reason = milestone_close_reason(milestone);
    let probe = Command::Terminate {
        decision: DecisionId::from_raw(0),
        proposal,
        reason,
    }
    .to_json();
    let deliverable = Command::RecordDeliverable {
        deliverable: DeliverableId::from_raw(0),
        grant: proposal,
        milestone,
        public_location: reason,
        release: reason,
        licence: SpdxId("MIT".to_owned()),
        snapshot: ContentDigest::from_bytes([0; 32]),
        accepted: true,
    }
    .to_json();
    let cmd = decoded(
        "CloseMilestone",
        vec![
            ("proposal", member(probe.clone(), "proposal")?),
            ("milestone", member(deliverable, "milestone")?),
            ("reason", member(probe, "reason")?),
        ],
    )?;
    Ok(by(pm, cmd))
}

/// The programme manager's `ClosePaymentRequest { request, reason }` with
/// a synthetic reason (O-51), built through the command codec.
pub fn close_request(pm: AccountId, request: RequestId) -> Result<Step, String> {
    let probe = Command::RequestPaymentChanges {
        request,
        reason: request_close_reason(request),
    }
    .to_json();
    let cmd = decoded(
        "ClosePaymentRequest",
        vec![
            ("request", member(probe.clone(), "request")?),
            ("reason", member(probe, "reason")?),
        ],
    )?;
    Ok(by(pm, cmd))
}

/// The lead's `RequestPayment` of `lines`: line id, milestone and cents.
pub fn request_payment(
    lead: AccountId,
    request: RequestId,
    grant: ProposalId,
    lines: &[(LineId, MilestoneId, i64)],
) -> Result<Step, String> {
    let mut out = Vec::new();
    for (line, milestone, amount) in lines {
        out.push(PaymentLine {
            line: *line,
            milestone: *milestone,
            amount: pos(*amount)?,
        });
    }
    Ok(by(
        lead,
        Command::RequestPayment {
            request,
            grant,
            lines: out,
        },
    ))
}

/// An `AcceptLine` by `reviewer` approving `approved` cents, with a reason when `reason`.
pub fn accept_line(
    reviewer: AccountId,
    request: RequestId,
    line: LineId,
    approved: i64,
    reason: bool,
) -> Result<Step, String> {
    Ok(by(
        reviewer,
        Command::AcceptLine {
            request,
            line,
            approved: nonneg(approved)?,
            reason: reason.then(|| text(94_000u128.saturating_add(line.raw()))),
        },
    ))
}

/// A `RequestPaymentChanges` by `reviewer`.
pub fn request_changes(reviewer: AccountId, request: RequestId) -> Step {
    by(
        reviewer,
        Command::RequestPaymentChanges {
            request,
            reason: text(95_000u128.saturating_add(request.raw())),
        },
    )
}

/// An `ApprovePayment` by `approver`.
pub fn approve_payment(approver: AccountId, request: RequestId) -> Step {
    by(approver, Command::ApprovePayment { request })
}

/// A `ReleasePayment` by `releaser`.
pub fn release_payment(releaser: AccountId, request: RequestId) -> Step {
    by(releaser, Command::ReleasePayment { request })
}

/// The payment port's `ConfirmPaid`.
pub fn confirm_paid(request: RequestId) -> Step {
    system(SystemCause::PaymentPort, Command::ConfirmPaid { request })
}

/// The lead's `WithdrawPaymentRequest`.
pub fn withdraw_request(lead: AccountId, request: RequestId) -> Step {
    by(lead, Command::WithdrawPaymentRequest { request })
}

/// The M5 checks' `RecordDeliverable` under `licence`.
pub fn record_deliverable(
    grant: ProposalId,
    deliverable: DeliverableId,
    milestone: MilestoneId,
    licence: &str,
    accepted: bool,
) -> Step {
    let mut d = [9u8; 32];
    let (head, _) = d.split_at_mut(16);
    head.copy_from_slice(&deliverable.raw().to_be_bytes());
    system(
        SystemCause::ContractPort,
        Command::RecordDeliverable {
            deliverable,
            grant,
            milestone,
            public_location: text(96_000u128.saturating_add(deliverable.raw())),
            release: text(97_000u128.saturating_add(deliverable.raw())),
            licence: SpdxId(licence.to_owned()),
            snapshot: ContentDigest::from_bytes(d),
            accepted,
        },
    )
}

/// One milestone of `cents` from `start` to a year after `T0`.
pub fn milestone_of_amount(
    id: MilestoneId,
    cents: i64,
    start: Timestamp,
) -> Result<Milestone, String> {
    Ok(Milestone {
        id,
        amount: pos(cents)?,
        start,
        due: after(crate::r#gen::roster::T0, 31_536_000_000_000),
        activity: None,
        deliverables: Vec::new(),
    })
}

/// A plan of one task per milestone: id, cents and start.
pub fn plan_tasks(milestones: &[(MilestoneId, i64, Timestamp)]) -> Result<Vec<Task>, String> {
    milestones
        .iter()
        .map(|(id, c, s)| {
            Ok(Task {
                milestones: vec![milestone_of_amount(*id, *c, *s)?],
            })
        })
        .collect()
}

/// The lead's plan `plan` of `origin` superseding `supersedes`.
pub fn money_plan(
    lead: AccountId,
    proposal: ProposalId,
    plan: PlanVersionId,
    origin: PlanOrigin,
    supersedes: Option<PlanVersionId>,
    milestones: &[(MilestoneId, i64, Timestamp)],
) -> Result<Step, String> {
    let mut digest = [5u8; 32];
    let (head, _) = digest.split_at_mut(16);
    head.copy_from_slice(&plan.raw().to_be_bytes());
    Ok(by(
        lead,
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin,
            supersedes,
            tasks: plan_tasks(milestones)?,
            content: ContentDigest::from_bytes(digest),
        },
    ))
}

/// A `ProposeAmendment` by `actor`.
pub fn propose_amendment(
    actor: AccountId,
    amendment: AmendmentId,
    grant: ProposalId,
    plan: PlanVersionId,
) -> Step {
    by(
        actor,
        Command::ProposeAmendment {
            amendment,
            grant,
            plan,
        },
    )
}

/// A `RouteAmendment` by `actor`.
pub fn route_amendment(actor: AccountId, amendment: AmendmentId, route: AmendmentRoute) -> Step {
    by(actor, Command::RouteAmendment { amendment, route })
}

/// The contract port's `ActivateAmendment`.
pub fn activate_amendment(amendment: AmendmentId, contract: ContractId) -> Step {
    system(
        SystemCause::ContractPort,
        Command::ActivateAmendment {
            amendment,
            contract,
        },
    )
}

/// The id of the IRC assignment of `member` to the amendment `amendment`.
/// It never meets an id of [`crate::mc::life_model::assignment_of`].
pub fn amendment_assignment(member: AccountId, amendment: AmendmentId) -> AssignmentId {
    AssignmentId::from_raw(
        90_000_000u128
            .saturating_add(amendment.raw().saturating_mul(1_000))
            .saturating_add(member.raw()),
    )
}

/// The coordinator's assignment of `member` to the IRC review of
/// `amendment` of `grant`, then the member's no-conflict declaration on it
/// (R-IR-04).
pub fn assign_amendment_declared(
    member: AccountId,
    grant: ProposalId,
    amendment: AmendmentId,
) -> Vec<Step> {
    let id = amendment_assignment(member, amendment);
    vec![
        crate::r#gen::review::assign(
            COORDINATOR,
            id,
            grant,
            member,
            AssignmentKind::Amendment(amendment),
            Some(crate::r#gen::review::handle(id.raw())),
        ),
        declare(member, DeclarationSubject::Assignment(id), false, false),
    ]
}

/// The staff programme manager's `EditPolicy` of `head` as version `id`, with P-05 at `cents`.
pub fn edit_p05(head: &PolicyVersion, id: PolicyVersionId, cents: i64) -> Result<Step, String> {
    let p05 = nonneg(cents)?;
    Ok(edit_policy(head, id, |v| v.live.p05 = p05))
}

// ---------------------------------------------------------------------------
// Setups from genesis
// ---------------------------------------------------------------------------

/// One proposal of a money setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneyDraft {
    /// The lead.
    pub lead: AccountId,
    /// The proposal.
    pub proposal: ProposalId,
    /// Whether the lead is flagged as a minor.
    pub minor: bool,
    /// The submitted plan: milestone, cents and start.
    pub milestones: Vec<(MilestoneId, i64, Timestamp)>,
    /// Whether the setup drives it to NEGOTIATION.
    pub negotiate: bool,
}

impl MoneyDraft {
    /// A proposal of `lead` with one milestone of `cents` starting at `T0`, driven to NEGOTIATION.
    pub fn one(lead: AccountId, proposal: ProposalId, cents: i64) -> MoneyDraft {
        MoneyDraft {
            lead,
            proposal,
            minor: false,
            milestones: vec![(milestone_n(proposal, 0), cents, crate::r#gen::roster::T0)],
            negotiate: true,
        }
    }
}

/// A start state from genesis: what [`MoneySetup::world`] runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneySetup {
    /// P-04 minimum and maximum, cents.
    pub p04: (i64, i64),
    /// P-05, cents.
    pub p05: i64,
    /// The proposals in call 1.
    pub drafts: Vec<MoneyDraft>,
    /// Bindings beside the life judges: account and role, granted from `T0`.
    pub staff: Vec<(AccountId, Role)>,
    /// Pairs whose second account takes the identity of the first.
    pub shared: Vec<(AccountId, AccountId)>,
    /// Accounts the vault does not verify.
    pub unverified: Vec<AccountId>,
    /// Proposals with a verified guardian consent.
    pub consents: Vec<ProposalId>,
    /// The reviewers assigned to every proposal: committee members of the life judges.
    pub reviewers: Vec<AccountId>,
    /// Identities set last, overriding the others: account and identity.
    pub identities: Vec<(AccountId, IdentityTag)>,
}

impl MoneySetup {
    /// The setup of M-MONEY (design 6.3): identities {a, b} and {c}, P-04
    /// = [2.00, 4.00], P-05 = 6.00, and the plans of `cents` for a, b and c.
    pub fn sybil(cents: [i64; 3]) -> MoneySetup {
        let [a, b, c] = cents;
        MoneySetup {
            p04: (200, 400),
            p05: 600,
            drafts: vec![
                MoneyDraft::one(LA, PA, a),
                MoneyDraft::one(LB, PB, b),
                MoneyDraft::one(LC, PC, c),
            ],
            staff: Vec::new(),
            shared: vec![(LA, LB)],
            unverified: Vec::new(),
            consents: Vec::new(),
            reviewers: vec![R1, R2],
            identities: Vec::new(),
        }
    }

    /// The Judging and Operations bindings: the life judges, then `staff`.
    pub fn judges(&self) -> Vec<(AccountId, Role, Option<OrganisationId>)> {
        let mut out = life_judges();
        out.extend(self.staff.iter().map(|(a, r)| (*a, *r, None)));
        out
    }

    /// The lifecycle setup underneath.
    pub fn life(&self) -> LifeSetup {
        LifeSetup {
            scale_max: 2,
            weights: vec![1, 1],
            p02_bp: 5_000,
            p03: 2,
            p07_days: 28,
            p15: 2,
            judges: self.judges(),
            proposals: self
                .drafts
                .iter()
                .map(|d| (d.lead, d.proposal, d.minor))
                .collect(),
            reviewers: Vec::new(),
            start_scores: Vec::new(),
            revision_scores: Vec::new(),
            start: Start::Draft,
        }
    }

    /// The vault of the setup. Every lead whose draft is not flagged as a
    /// minor's is attested 18 or older from
    /// [`crate::r#gen::roster::LEAD_ADULT_FROM`] on, so the flag the
    /// lifecycle derives from the vault matches the draft (R-ID-04).
    pub fn truth(&self) -> GroundTruth {
        let mut truth = GroundTruth::new();
        add_staff(&mut truth);
        let mut accounts: BTreeSet<AccountId> = self.judges().iter().map(|(a, _, _)| *a).collect();
        accounts.extend(self.drafts.iter().map(|d| d.lead));
        for a in accounts {
            let t = self
                .shared
                .iter()
                .find(|(_, second)| *second == a)
                .map_or(tag(a), |(first, _)| tag(*first));
            truth.set_identity(a, t);
            if !self.unverified.contains(&a) {
                truth.verify(a);
            }
        }
        for (a, t) in &self.identities {
            truth.set_identity(*a, *t);
        }
        for p in &self.consents {
            truth.consent(*p);
        }
        crate::r#gen::review::attest_adult_leads(
            &mut truth,
            self.drafts.iter().map(|d| (d.lead, d.minor)),
        );
        truth
    }

    /// The production commands from genesis to every proposal in DRAFT.
    pub fn draft_steps(&self) -> Result<Vec<Step>, String> {
        let mut steps = self.life().draft_steps()?;
        let p04 = AmountRange::new(nonneg(self.p04.0)?, nonneg(self.p04.1)?)
            .map_err(|e| format!("P-04: {e:?}"))?;
        let p05 = nonneg(self.p05)?;
        for s in &mut steps {
            match &mut s.cmd {
                Command::CreateProgramme { policy } => {
                    policy.frozen.p04 = p04;
                    policy.live.p05 = p05;
                }
                Command::RecordPlanVersion {
                    proposal, tasks, ..
                } => {
                    if let Some(d) = self.drafts.iter().find(|d| d.proposal == *proposal) {
                        *tasks = plan_tasks(&d.milestones)?;
                    }
                }
                _ => {}
            }
        }
        Ok(steps)
    }

    /// The world from genesis with every proposal the setup names in NEGOTIATION.
    pub fn world(&self, backend: Backend) -> Result<MoneyWorld, String> {
        self.world_with(backend, |_| {})
    }

    /// [`MoneySetup::world`] over the setup's vault after `change`. A test
    /// uses it to give a lead an over-18 attestation or a guardian consent
    /// apart from the draft's minor bit (R-ID-04, state-machine NOTE 14).
    pub fn world_with(
        &self,
        backend: Backend,
        change: impl FnOnce(&mut GroundTruth),
    ) -> Result<MoneyWorld, String> {
        let mut truth = self.truth();
        change(&mut truth);
        let mut w = MoneyWorld::new(backend, truth);
        for s in self.draft_steps()? {
            w = w.must(&s)?;
        }
        let going: Vec<&MoneyDraft> = self.drafts.iter().filter(|d| d.negotiate).collect();
        for d in &going {
            w = w.must(&submit(d.lead, d.proposal, plan_of(d.proposal), false))?;
        }
        w.set_now(T_EVAL);
        for d in &going {
            w = w.ranked(d.proposal, &self.reviewers)?;
        }
        if going.is_empty() {
            return Ok(w);
        }
        let order: Vec<ProposalId> = going.iter().map(|d| d.proposal).collect();
        let n = u32::try_from(order.len()).map_err(|_| "too many proposals")?;
        w = w.must(&cut_off(
            R1,
            cut_off_decision(1),
            call(1),
            order,
            n,
            false,
            ballots(&[R1, R2, R3], Vote::For),
        ))?;
        for d in &going {
            for i in [IRC, IRC2] {
                for st in assign_declared(i, d.proposal, call(1), AssignmentKind::Irc) {
                    w = w.must(&st)?;
                }
            }
            for i in [IRC, IRC2] {
                let a = assignment_of(i, d.proposal, call(1), AssignmentKind::Irc);
                w = w.must(&irc_review(i, a, true))?;
            }
            if w.state(d.proposal) != Some(StateTag::Negotiation) {
                return Err(format!(
                    "setup: {:?} did not reach NEGOTIATION (it is in {:?})",
                    d.proposal,
                    w.state(d.proposal)
                ));
            }
        }
        Ok(w)
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// A model world for money: the lifecycle world and the money view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyWorld {
    /// Production, the vault and the L-SOD, L-REV and L-LIFE reference views.
    pub life: LifeWorld,
    /// The money reference view of every record committed.
    pub money: MoneyView,
    /// The latest policy version of the programme, for P-05 edits.
    pub head: Option<Box<PolicyVersion>>,
}

impl MoneyWorld {
    /// A world at genesis over `truth`.
    pub fn new(backend: Backend, truth: GroundTruth) -> MoneyWorld {
        MoneyWorld {
            life: LifeWorld::new(backend, truth),
            money: MoneyView::new(),
            head: None,
        }
    }

    /// What decides the steps.
    pub fn backend(&self) -> Backend {
        self.life.backend()
    }

    /// The vault facts.
    pub fn truth(&self) -> &GroundTruth {
        &self.life.rev.sod.truth
    }

    /// The instant of every command.
    pub fn now(&self) -> Timestamp {
        self.life.now()
    }

    /// Moves `now` to `t`. Time never runs backwards.
    pub fn set_now(&mut self, t: Timestamp) {
        self.life.set_now(t);
    }

    /// The reference state of `proposal`.
    pub fn state(&self, proposal: ProposalId) -> Option<StateTag> {
        self.life.life.state_of(proposal)
    }

    /// The money verdict on `step` now.
    pub fn verdict(&self, step: &Step) -> MoneyVerdict {
        let cx = MoneyCx {
            sod: &self.life.rev.sod.view,
            rev: &self.life.rev.view,
            life: &self.life.life,
            money: &self.money,
            truth: self.truth(),
            now: self.now(),
        };
        money_verdict(&cx, step.actor, &step.cmd)
    }

    /// The records of a withdrawal that the money lane adds.
    fn withdraw_release(&self, proposal: ProposalId) -> Option<Record> {
        let cx = MoneyCx {
            sod: &self.life.rev.sod.view,
            rev: &self.life.rev.view,
            life: &self.life.life,
            money: &self.money,
            truth: self.truth(),
            now: self.now(),
        };
        withdraw_release(&cx, proposal)
    }

    fn fold(&mut self, records: &[Record]) -> Result<(), String> {
        let truth = self.life.rev.sod.truth.clone();
        self.money.fold_batch(records, &truth)?;
        for r in records {
            if let Record::PolicyVersionRecorded { version, .. } = r {
                self.head = Some(version.clone());
            }
        }
        Ok(())
    }

    /// Processes a newer vault epoch and folds its records.
    pub fn sync(&mut self) -> Result<Vec<Record>, String> {
        let records = self.life.sync()?;
        self.fold(&records)?;
        Ok(records)
    }

    /// Changes the vault facts with `change` and processes the change in the same step.
    pub fn vault(&mut self, change: impl FnOnce(&mut GroundTruth)) -> Result<Vec<Record>, String> {
        change(&mut self.life.rev.sod.truth);
        self.sync()
    }

    /// Production `queries` and `decide` on `step`, without committing.
    fn production(&self, step: &Step) -> Result<Vec<Record>, String> {
        let state = &self.life.rev.sod.state;
        let ctx = step.ctx(self.now(), MONEY_COMMAND);
        let mut answers = Answers::new();
        let qs = fstp_domain::queries(state, &step.cmd, &ctx).map_err(|r| r.to_string())?;
        for q in qs {
            let a = self.life.rev.answer(&q);
            answers.insert(q, a);
        }
        fstp_domain::decide(state, &step.cmd, &ctx, &answers).map_err(|r| r.to_string())
    }

    /// Runs `step` after any pending vault reaction and compares it with
    /// the references in both directions. `Ok(Some)` is the world after an
    /// accepted step with its records, `Ok(None)` a step both refuse, and
    /// `Err` a divergence or a harness failure.
    pub fn step(&self, step: &Step) -> Result<Option<(MoneyWorld, Vec<Record>)>, String> {
        let mut w = self.clone();
        w.sync()?;
        let context = format!("{:?} by {:?}", step.cmd, step.actor);
        let verdict = w.verdict(step);
        match verdict {
            MoneyVerdict::NotMine => w.delegate(step, &context),
            MoneyVerdict::Refuse(why) if matches!(step.cmd, Command::EditPolicy { .. }) => {
                if w.backend() == Backend::Reference {
                    return Ok(None);
                }
                match w.life.step(step)? {
                    None => Ok(None),
                    Some((_, records)) => Err(format!(
                        "{context}: over-permission, the reference refuses ({why}), production accepts with {records:?}"
                    )),
                }
            }
            v => w.mine(step, &context, v),
        }
    }

    fn delegate(
        mut self,
        step: &Step,
        context: &str,
    ) -> Result<Option<(MoneyWorld, Vec<Record>)>, String> {
        let release = match step.cmd {
            Command::Withdraw { proposal } => Some((proposal, self.withdraw_release(proposal))),
            _ => None,
        };
        let Some((lw, mut records)) = self.life.step(step)? else {
            if matches!(step.cmd, Command::EditPolicy { .. }) {
                return Err(format!(
                    "{context}: over-denial, a valid P-05 edit within every counted sum was refused"
                ));
            }
            return Ok(None);
        };
        self.life = lw;
        if let Some((proposal, expected)) = release {
            let got = records
                .iter()
                .any(|r| matches!(r, Record::CapReleased { proposal: p, .. } if *p == proposal));
            match (self.backend(), expected) {
                (Backend::Reference, Some(r)) => {
                    self.life = self.life.inject(core::slice::from_ref(&r))?;
                    records.push(r);
                }
                (Backend::Production, Some(_)) if !got => {
                    return Err(format!(
                        "{context}: the withdrawal does not release the open reservation (row 15, design 2.11)"
                    ));
                }
                (_, None) if got => {
                    return Err(format!(
                        "{context}: the withdrawal releases a reservation that is not open"
                    ));
                }
                _ => {}
            }
        }
        self.fold(&records)?;
        Ok(Some((self, records)))
    }

    fn mine(
        mut self,
        step: &Step,
        context: &str,
        verdict: MoneyVerdict,
    ) -> Result<Option<(MoneyWorld, Vec<Record>)>, String> {
        let outcome = match self.backend() {
            Backend::Production => self.production(step),
            Backend::Reference => match &verdict {
                MoneyVerdict::Accept(e) | MoneyVerdict::Either(e) => Ok(e.synth.clone()),
                MoneyVerdict::Refuse(why) => Err(why.clone()),
                MoneyVerdict::NotMine => Err("unreachable".to_owned()),
            },
        };
        let exp = match (verdict, outcome) {
            (MoneyVerdict::Refuse(_) | MoneyVerdict::Either(_), Err(_)) => return Ok(None),
            (MoneyVerdict::Accept(_), Err(r)) => {
                return Err(format!(
                    "{context}: over-denial, the reference accepts, production refuses with {r}"
                ));
            }
            (MoneyVerdict::Refuse(why), Ok(records)) => {
                return Err(format!(
                    "{context}: over-permission, the reference refuses ({why}), production accepts with {records:?}"
                ));
            }
            (MoneyVerdict::Accept(e) | MoneyVerdict::Either(e), Ok(records)) => (e, records),
            (MoneyVerdict::NotMine, _) => return Err("unreachable".to_owned()),
        };
        let (e, records) = exp;
        check_money_batch(context, &e, &records)?;
        self.life = self.life.inject(&records)?;
        self.fold(&records)?;
        if let Some(x) = e.ext {
            self.money.note_ext(x);
        }
        Ok(Some((self, records)))
    }

    /// Runs the extension command `ext` by `actor`, built through the
    /// command codec. On the references alone, a command the codec does
    /// not know yet is judged by [`ext_verdict`] and noted in the view, so
    /// the reference twins can run before the codec lands. Under
    /// production the codec must know it.
    pub fn ext(&self, actor: Actor, ext: Ext) -> Result<Option<(MoneyWorld, Vec<Record>)>, String> {
        let built = match ext {
            Ext::CloseMilestone {
                proposal,
                milestone,
            } => close_milestone(STAFF_PM, proposal, milestone),
            Ext::ClosePaymentRequest { request } => close_request(STAFF_PM, request),
        };
        match built {
            Ok(mut step) => {
                step.actor = actor;
                self.step(&step)
            }
            Err(e) if self.backend() == Backend::Production => Err(e),
            Err(_) => {
                let mut w = self.clone();
                w.sync()?;
                let cx = MoneyCx {
                    sod: &w.life.rev.sod.view,
                    rev: &w.life.rev.view,
                    life: &w.life.life,
                    money: &w.money,
                    truth: w.truth(),
                    now: w.now(),
                };
                match ext_verdict(&cx, actor, ext) {
                    MoneyVerdict::Accept(_) | MoneyVerdict::Either(_) => {
                        w.money.note_ext(ext);
                        Ok(Some((w, Vec::new())))
                    }
                    _ => Ok(None),
                }
            }
        }
    }

    /// The world after `step`, which must be accepted.
    pub fn must(&self, step: &Step) -> Result<MoneyWorld, String> {
        match self.step(step)? {
            Some((w, _)) => Ok(w),
            None => Err(format!(
                "{:?} by {:?} was refused by production and the references",
                step.cmd, step.actor
            )),
        }
    }

    /// Folds `records` that a broken engine would emit into production
    /// through the public structural `apply`, and into every view.
    pub fn inject(&self, records: &[Record]) -> Result<MoneyWorld, String> {
        let mut w = self.clone();
        w.life = w.life.inject(records)?;
        w.fold(records)?;
        Ok(w)
    }

    /// `proposal` through intake, stage 1 with `reviewers`, and stage 2
    /// with "no questions", to RANKED.
    pub fn ranked(
        &self,
        proposal: ProposalId,
        reviewers: &[AccountId],
    ) -> Result<MoneyWorld, String> {
        let mut w = self.clone();
        for r in reviewers.iter().copied() {
            for s in assign_declared(r, proposal, call(1), AssignmentKind::Reviewer) {
                w = w.must(&s)?;
            }
        }
        w = w.must(&declare(
            COORDINATOR,
            DeclarationSubject::Proposal(proposal),
            false,
            false,
        ))?;
        w = w.must(&knock_out(proposal, true))?;
        w = w.must(&admit(proposal))?;
        for r in reviewers.iter().copied() {
            let key = ScoreKey {
                assignment: assignment_of(r, proposal, call(1), AssignmentKind::Reviewer),
                stage: Stage::One,
                plan: plan_of(proposal),
            };
            w = w.must(&score(r, key, &[2, 2]))?;
        }
        w = w.must(&close(Actor::Account(COORDINATOR), proposal))?;
        for r in reviewers.iter().copied() {
            let a = assignment_of(r, proposal, call(1), AssignmentKind::Reviewer);
            w = w.must(&no_questions(r, proposal, a))?;
        }
        Ok(w)
    }

    /// Every invariant predicate of this lane on the world.
    pub fn invariants(&self) -> Result<(), String> {
        check_i13(&self.money)?;
        check_i14(&self.money, self.truth())?;
        check_i15(&self.money)?;
        check_i64(&self.money)?;
        check_i05(&self.money.pay, &self.money.breaches)?;
        check_sod12(&self.money.breaches)
    }
}

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

/// A world for an example test, with helpers that drive grants along their
/// rows. Every step is compared with the references in both directions.
#[derive(Clone, Debug)]
pub struct MoneyStory {
    /// The world.
    pub world: MoneyWorld,
}

impl MoneyStory {
    /// The story of `setup` from genesis, every proposal it names in NEGOTIATION.
    pub fn new(setup: &MoneySetup, backend: Backend) -> Result<MoneyStory, String> {
        Ok(MoneyStory {
            world: setup.world(backend)?,
        })
    }

    /// [`MoneyStory::new`] over the setup's vault after `change`, see
    /// [`MoneySetup::world_with`].
    pub fn with(
        setup: &MoneySetup,
        backend: Backend,
        change: impl FnOnce(&mut GroundTruth),
    ) -> Result<MoneyStory, String> {
        Ok(MoneyStory {
            world: setup.world_with(backend, change)?,
        })
    }

    /// Runs `step`, which production and the references must both accept.
    pub fn run(&mut self, step: &Step) -> Result<Vec<Record>, String> {
        match self.attempt(step)? {
            Some(r) => Ok(r),
            None => Err(format!(
                "{:?} by {:?} was refused by production and the references",
                step.cmd, step.actor
            )),
        }
    }

    /// Runs `step`. `Ok(None)` when production and the references both refuse it.
    pub fn attempt(&mut self, step: &Step) -> Result<Option<Vec<Record>>, String> {
        match self.world.step(step)? {
            Some((w, r)) => {
                self.world = w;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    /// Runs `step`, which production and the references must both refuse.
    pub fn refused(&mut self, step: &Step) -> Result<(), String> {
        match self.attempt(step)? {
            None => Ok(()),
            Some(r) => Err(format!(
                "{:?} by {:?} was accepted with {r:?}",
                step.cmd, step.actor
            )),
        }
    }

    /// The reference state of `proposal`.
    pub fn state(&self, proposal: ProposalId) -> Option<StateTag> {
        self.world.state(proposal)
    }

    /// Moves `now` to `t`.
    pub fn at(&mut self, t: Timestamp) {
        self.world.set_now(t);
    }

    /// The lead of `proposal`.
    pub fn lead(&self, proposal: ProposalId) -> Result<AccountId, String> {
        self.world
            .money
            .proposals
            .get(&proposal)
            .map(|p| p.lead)
            .ok_or_else(|| format!("unknown proposal {proposal:?}"))
    }

    /// R1 determines the amount of `proposal` on its submitted plan with `deductions`.
    pub fn determine(
        &mut self,
        proposal: ProposalId,
        n: u128,
        deductions: &[i64],
    ) -> Result<(), String> {
        let s = determine(
            R1,
            proposal,
            amount_decision(proposal, n),
            plan_of(proposal),
            deductions,
        )?;
        self.run(&s)?;
        Ok(())
    }

    /// The current amount determination of `proposal` in the reference
    /// view, by its decision id.
    pub fn determination(&self, proposal: ProposalId) -> Result<DecisionId, String> {
        self.world
            .money
            .proposals
            .get(&proposal)
            .and_then(|p| p.determined.as_ref())
            .map(|d| d.decision)
            .ok_or_else(|| format!("{proposal:?} has no amount determination"))
    }

    /// The acceptance, the approval and the contract fact of `proposal`, in
    /// that order. The acceptance and the approval name the current
    /// determination (Q-W7-7, decided 2026-10-28).
    pub fn grant_facts(&mut self, proposal: ProposalId) -> Result<(), String> {
        let lead = self.lead(proposal)?;
        let current = self.determination(proposal)?;
        self.run(&accept_grant_as(
            lead,
            proposal,
            accept_decision(proposal),
            current,
        ))?;
        self.run(&approve_grant_as(
            STAFF_PM,
            proposal,
            approve_decision(proposal),
            current,
        ))?;
        self.run(&contract_effective(proposal))?;
        Ok(())
    }

    /// [`MoneyStory::determine`] without deductions, then [`MoneyStory::grant_facts`].
    pub fn grant(&mut self, proposal: ProposalId) -> Result<(), String> {
        self.determine(proposal, 1, &[])?;
        self.grant_facts(proposal)?;
        if self.state(proposal) == Some(StateTag::Granted) {
            Ok(())
        } else {
            Err(format!(
                "{proposal:?} is in {:?} after its grant facts",
                self.state(proposal)
            ))
        }
    }

    /// [`MoneyStory::grant`] and the start of execution.
    pub fn execute(&mut self, proposal: ProposalId) -> Result<(), String> {
        self.grant(proposal)?;
        self.run(&start_execution(proposal))?;
        Ok(())
    }

    /// Runs the extension command `ext` by `actor`. `Ok(None)` when it is refused.
    pub fn ext(&mut self, actor: Actor, ext: Ext) -> Result<Option<Vec<Record>>, String> {
        match self.world.ext(actor, ext)? {
            Some((w, r)) => {
                self.world = w;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    /// The programme manager closes every milestone of the effective
    /// contract version of `proposal`.
    pub fn close_milestones(&mut self, proposal: ProposalId) -> Result<(), String> {
        let ms: Vec<MilestoneId> = self
            .world
            .money
            .contract_plan(proposal)
            .map(|p| p.milestones.keys().copied().collect())
            .unwrap_or_default();
        for m in ms {
            let x = Ext::CloseMilestone {
                proposal,
                milestone: m,
            };
            if self.ext(Actor::Account(STAFF_PM), x)?.is_none() {
                return Err(format!("CloseMilestone of {m:?} was refused"));
            }
        }
        Ok(())
    }

    /// Every invariant predicate of this lane.
    pub fn invariants(&self) -> Result<(), String> {
        self.world.invariants()
    }
}

// ---------------------------------------------------------------------------
// The fstp-prop machine
// ---------------------------------------------------------------------------

/// What a money machine draws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoneyFocus {
    /// Draw weights in the order determine, accept, approve, contract,
    /// decline, withdraw, P-05 edit, start, terminate.
    pub weights: [u32; 9],
    /// Commands per case.
    pub max_commands: usize,
}

impl MoneyFocus {
    /// `i13_i14_grant_sequences_respect_range_and_cap`: grant sequences.
    pub const GRANTS: MoneyFocus = MoneyFocus {
        weights: [6, 3, 3, 3, 2, 1, 1, 1, 1],
        max_commands: 24,
    };
    /// `i14_p05_edit_below_committed_is_refused`: P-05 edits among grants.
    pub const P05: MoneyFocus = MoneyFocus {
        weights: [5, 2, 2, 2, 1, 1, 6, 0, 1],
        max_commands: 24,
    };
}

/// One machine command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoneyCmd {
    /// A `DetermineAmount` by `by` with these deductions, cents.
    Determine {
        /// The reviewer, assigned or not.
        by: AccountId,
        /// The proposal.
        proposal: ProposalId,
        /// The deductions.
        deductions: Vec<i64>,
    },
    /// The lead's acceptance, naming a superseded determination when the
    /// flag is set (Q-W7-7).
    Accept(ProposalId, bool),
    /// The programme manager's approval, naming a superseded determination
    /// when the flag is set (Q-W7-7).
    Approve(ProposalId, bool),
    /// The contract port's EFFECTIVE fact.
    Contract(ProposalId),
    /// `DeclineNegotiation` by the programme manager.
    Decline(ProposalId),
    /// The lead's withdrawal.
    Withdraw(ProposalId),
    /// An `EditPolicy` setting P-05 to these cents.
    EditP05(i64),
    /// The System's `StartExecution`.
    Start(ProposalId),
    /// The programme manager's `Terminate`.
    Terminate(ProposalId),
}

/// The machine model: the world, with the divergence of the last step.
#[derive(Clone, Debug)]
pub struct MoneyModel {
    /// The world.
    pub world: MoneyWorld,
    /// The number of amount decisions drawn.
    pub decisions: u128,
    /// The number of policy versions drawn.
    pub versions: u128,
    /// Set when production and the references disagree.
    pub divergence: Option<String>,
}

/// The fstp-prop machine over grant sequences (I-13, I-14). Several
/// accounts share one identity. The postcondition is the two-way
/// comparison of [`MoneyWorld::step`]; the invariant checks I-13, I-14,
/// I-15 and I-64 on the money view after every step.
#[derive(Debug)]
pub struct MoneyMachine {
    /// What the machine draws.
    pub focus: MoneyFocus,
    /// The start state, built once from genesis.
    pub start: Result<MoneyWorld, String>,
}

/// The setup of the machine: four leads, three of them one identity, P-04
/// = [2.00, 4.00] and P-05 = 6.00, plans of 4.00, 3.00, 1.00 and 2.00. A
/// deduction is always refused, since the agreed plan must carry the
/// granted amount (design 2.11), so the plans span P-04 without one.
pub fn machine_setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 300, 100]);
    s.drafts.push(MoneyDraft::one(
        AccountId::from_raw(404),
        ProposalId::from_raw(14),
        200,
    ));
    s.shared.push((LA, AccountId::from_raw(404)));
    s
}

impl MoneyMachine {
    /// The machine of `focus` over `backend`.
    pub fn new(focus: MoneyFocus, backend: Backend) -> MoneyMachine {
        MoneyMachine {
            focus,
            start: machine_setup().world(backend),
        }
    }

    fn proposals() -> [ProposalId; 4] {
        [PA, PB, PC, ProposalId::from_raw(14)]
    }

    /// The step of `cmd` in `m`.
    /// `Ok(None)` for an acceptance or approval naming a superseded
    /// determination while the command codec does not know the member yet
    /// (Q-W7-7), so it is not drawn until then.
    pub fn step_of(m: &MoneyModel, cmd: &MoneyCmd) -> Result<Option<Step>, String> {
        let lead = |p: ProposalId| {
            m.world
                .money
                .proposals
                .get(&p)
                .map(|x| x.lead)
                .ok_or_else(|| format!("unknown {p:?}"))
        };
        Ok(Some(match cmd {
            MoneyCmd::Determine {
                by,
                proposal,
                deductions,
            } => determine(
                *by,
                *proposal,
                amount_decision(*proposal, m.decisions),
                plan_of(*proposal),
                deductions,
            )?,
            // A fresh decision id after every new determination, since a new
            // amount needs a new acceptance and approval (NOTE 9). Each names
            // the current determination, or a superseded one when drawn
            // stale, which both sides must refuse (Q-W7-7, decided 2026-10-28).
            MoneyCmd::Accept(p, stale) => {
                let d = accept_decision_n(*p, m.decisions);
                let named = naming(m, *p, *stale);
                if *stale {
                    match accept_grant_naming(lead(*p)?, *p, d, named) {
                        Ok(s) => s,
                        Err(_) => return Ok(None),
                    }
                } else {
                    accept_grant_as(lead(*p)?, *p, d, named)
                }
            }
            MoneyCmd::Approve(p, stale) => {
                let d = approve_decision_n(*p, m.decisions);
                let named = naming(m, *p, *stale);
                if *stale {
                    match approve_grant_naming(STAFF_PM, *p, d, named) {
                        Ok(s) => s,
                        Err(_) => return Ok(None),
                    }
                } else {
                    approve_grant_as(STAFF_PM, *p, d, named)
                }
            }
            // A new amount clears the contract fact of the old one, so the
            // port reports the contract of the new amount (Q-W7-4).
            MoneyCmd::Contract(p) => contract_effective_as(*p, contract_of_n(*p, m.decisions)),
            MoneyCmd::Decline(p) => decline_negotiation(Actor::Account(STAFF_PM), *p),
            MoneyCmd::Withdraw(p) => crate::r#gen::review::withdraw(lead(*p)?, *p),
            MoneyCmd::EditP05(c) => {
                let head = m.world.head.as_deref().ok_or("no policy head")?;
                edit_p05(
                    head,
                    PolicyVersionId::from_raw(700u128.saturating_add(m.versions)),
                    *c,
                )?
            }
            MoneyCmd::Start(p) => start_execution(*p),
            MoneyCmd::Terminate(p) => terminate(STAFF_PM, *p),
        }))
    }
}

/// The determination an acceptance or approval of `p` names in `m`: the
/// current one, or a superseded one when `stale` (Q-W7-7). Without a
/// superseded one a stale draw names [`amount_decision`] `(p, 0)`, which
/// no machine run records.
fn naming(m: &MoneyModel, p: ProposalId, stale: bool) -> DecisionId {
    if stale {
        return superseded_determination(&m.world.money, p).unwrap_or(amount_decision(p, 0));
    }
    let current = m
        .world
        .money
        .proposals
        .get(&p)
        .and_then(|q| q.determined.as_ref())
        .map(|d| d.decision);
    current.unwrap_or(amount_decision(p, 0))
}

/// The latest amount determination of `p` in `view` that a later one
/// superseded, read from the decision ids of [`amount_decision`].
pub fn superseded_determination(view: &MoneyView, p: ProposalId) -> Option<DecisionId> {
    let current = view
        .proposals
        .get(&p)
        .and_then(|q| q.determined.as_ref())
        .map(|d| d.decision)?;
    let base = amount_decision(p, 0).raw();
    view.decisions
        .iter()
        .filter(|d| d.raw() > base && d.raw() < base.saturating_add(100) && **d != current)
        .max()
        .copied()
}

impl StateMachine for MoneyMachine {
    type Model = MoneyModel;
    type Sut = ();
    type Command = MoneyCmd;
    type Output = ();

    fn init_model(&self) -> MoneyModel {
        match &self.start {
            Ok(w) => MoneyModel {
                world: w.clone(),
                decisions: 1,
                versions: 1,
                divergence: None,
            },
            Err(e) => MoneyModel {
                world: MoneyWorld::new(Backend::Reference, GroundTruth::new()),
                decisions: 1,
                versions: 1,
                divergence: Some(format!("the start from genesis failed: {e}")),
            },
        }
    }

    fn init_sut(&self) {}

    fn command(&self, g: &mut Gen, _model: &MoneyModel) -> MoneyCmd {
        let p = *g.pick(&Self::proposals());
        match g.weighted(&self.focus.weights) {
            0 => {
                let by = *g.pick(&[R1, R1, R2, R3]);
                let deductions = g.pick(&[vec![], vec![], vec![100], vec![50, 50]]).clone();
                MoneyCmd::Determine {
                    by,
                    proposal: p,
                    deductions,
                }
            }
            1 => MoneyCmd::Accept(p, *g.pick(&[false, false, true])),
            2 => MoneyCmd::Approve(p, *g.pick(&[false, false, true])),
            3 => MoneyCmd::Contract(p),
            4 => MoneyCmd::Decline(p),
            5 => MoneyCmd::Withdraw(p),
            6 => MoneyCmd::EditP05(*g.pick(&[400, 500, 600])),
            7 => MoneyCmd::Start(p),
            _ => MoneyCmd::Terminate(p),
        }
    }

    fn precondition(&self, model: &MoneyModel, cmd: &MoneyCmd) -> bool {
        // The amount is never locked (NOTE 9, decided 2026-10-28), so the
        // machine also draws a determination after acceptance or approval.
        let _ = cmd;
        model.divergence.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &MoneyCmd) {}

    fn next_state(&self, model: &mut MoneyModel, cmd: &MoneyCmd) {
        let step = match MoneyMachine::step_of(model, cmd) {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                model.divergence = Some(format!("harness: {e}"));
                return;
            }
        };
        match model.world.step(&step) {
            Ok(Some((w, records))) => {
                model.world = w;
                if records
                    .iter()
                    .any(|r| matches!(r, Record::AmountDetermined { .. }))
                {
                    model.decisions = model.decisions.saturating_add(1);
                }
                if records
                    .iter()
                    .any(|r| matches!(r, Record::PolicyVersionRecorded { .. }))
                {
                    model.versions = model.versions.saturating_add(1);
                }
            }
            Ok(None) => {}
            Err(e) => model.divergence = Some(e),
        }
    }

    fn invariant(&self, model: &MoneyModel, _sut: &()) -> Result<(), String> {
        if let Some(d) = &model.divergence {
            return Err(format!("two-way: {d}"));
        }
        model.world.invariants()
    }

    fn max_commands(&self) -> usize {
        self.focus.max_commands
    }
}

/// The identity of lead a, b and the fourth lead in the machine.
pub fn sybil_identity() -> IdentityTag {
    tag(LA)
}
