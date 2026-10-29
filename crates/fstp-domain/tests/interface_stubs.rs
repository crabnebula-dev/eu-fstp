//! The W1c engine stubs refuse without panicking, so later lanes start red (design section 10).
//! The shared checks of the dispatcher run before any lane.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{
    Actor, Command, CommandKind, ContractEvent, Ctx, DeclarationSubject, KnockOutResult,
    SystemCause, Via,
};
use fstp_domain::decision::{Ballot, IrcVerdict, Vote};
use fstp_domain::engine::{FoldError, apply, decide, due, queries, replay, stage1_ready};
use fstp_domain::grant::IneligibleCost;
use fstp_domain::id::{
    AccountId, AmendmentId, AssignmentId, BindingId, CallId, ClassId, CommandId, ContentDigest,
    ContractId, CriterionId, DecisionId, DeliverableId, KnockOutCriterionId, LineId, LlmConfigId,
    MilestoneId, PlanVersionId, PolicyVersionId, ProgrammeId, ProposalId, RequestId, TextId,
    TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, Query, QueryKind};
use fstp_domain::payment::PaymentLine;
use fstp_domain::policy::{
    EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef, InferenceBinding,
    IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, LiveValues, McpBindingActions,
    ModelRef, OpaqueValue, ParamId, PolicyVersion, ProximityLists, ReadAccess, ReviewerAnonymity,
    SpdxId, TieBreakRule, VotingRules,
};
use fstp_domain::proposal::{EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, Task};
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::scoring::{Criteria, CriteriaError, Criterion, ScoreKey, ScoreVector, Stage};
use fstp_domain::state::State;
use fstp_domain::time::{Days, Timestamp, ZoneName};
use fstp_ledger::{Entry, Seq};
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent, PosAmount};

use support::{read_spec, section, table};

fn ctx() -> Ctx {
    Ctx {
        now: Timestamp::from_micros(1),
        actor: Actor::Account(AccountId::from_raw(1)),
        command: CommandId::from_bytes([1; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn accept_grant() -> Command {
    Command::AcceptGrant {
        decision: DecisionId::from_raw(7),
        proposal: ProposalId::from_raw(7),
        determination: DecisionId::from_raw(8),
    }
}

fn grant_role() -> Command {
    Command::GrantRole {
        binding: BindingId::from_raw(1),
        account: AccountId::from_raw(2),
        programme: ProgrammeId::from_raw(1),
        role: Role::ProgrammeManager,
        start: Timestamp::from_micros(1),
        second_admin: None,
        confidentiality: None,
        organisation: None,
        end: None,
    }
}

fn wrong_actor() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)
}

/// Every engine entry point is total, and every lane has landed. No command
/// kind reaches a not-implemented refusal at genesis, from any actor kind
/// or channel: each is refused for a rule of its lane, or accepted. A fold
/// that cannot apply its record fails without changing the state, an
/// empty replay is genesis, and nothing is due or ready.
///
/// Step W5 integration rewrote this test. It asserted that `AcceptGrant`
/// was still refused as not implemented, an assumption of step W1c that
/// no longer holds. The full walk over legal states is
/// `interface_no_command_kind_reaches_not_implemented` in the testkit.
#[test]
fn interface_engine_stubs_refuse_without_panicking() {
    let state = State::genesis();
    for kind in CommandKind::ALL {
        let cmd = sample(kind);
        assert_eq!(cmd.kind(), kind, "the sample of {kind:?} has another kind");
        for c in contexts() {
            let answers = match queries(&state, &cmd, &c) {
                Ok(qs) => answered(qs),
                Err(r) => {
                    assert!(
                        !is_not_implemented(&r),
                        "{kind:?} reached a not-implemented refusal in queries with {c:?}"
                    );
                    Answers::new()
                }
            };
            if let Err(r) = decide(&state, &cmd, &c, &answers) {
                assert!(
                    !is_not_implemented(&r),
                    "{kind:?} reached a not-implemented refusal in decide with {c:?}"
                );
            }
        }
    }

    let record = Record::ProposalCreated {
        proposal: ProposalId::from_raw(7),
        call: CallId::from_raw(1),
        lead: AccountId::from_raw(1),
        minor: false,
    };
    let mut folded = State::genesis();
    assert!(
        apply(
            &mut folded,
            Seq::from_raw(1),
            Timestamp::from_micros(1),
            &record
        )
        .is_err(),
        "a draft in an unknown call folded"
    );
    assert_eq!(folded, State::genesis(), "a refused fold changed the state");

    let none: Vec<Entry<Record>> = Vec::new();
    assert_eq!(replay(&none), Ok(State::genesis()));
    let one = vec![entry(1, 1, [1; 16], record)];
    assert!(replay(&one).is_err(), "a draft in an unknown call replayed");

    assert!(due(&state, Timestamp::from_micros(i64::MAX)).is_empty());
    assert!(stage1_ready(&state, Timestamp::from_micros(i64::MAX)).is_empty());
}

/// The domain command kinds of each row of the high-risk table in
/// `SPEC/03-architecture/authentication.md`. `None` for an action this
/// mapping does not know, so a new or reworded row fails the test.
fn high_risk_kinds(action: &str) -> Option<&'static [CommandKind]> {
    let kinds: &'static [CommandKind] = match action {
        "Granting or changing a role in the Drafting, Judging or Operations groups, or tenant admin" => {
            &[
                CommandKind::GrantRole,
                CommandKind::EndRole,
                CommandKind::ReinstateBinding,
            ]
        }
        "Approving or releasing a payment" => {
            &[CommandKind::ApprovePayment, CommandKind::ReleasePayment]
        }
        // M2 has no separate activation step, so creating a programme activates it.
        "Activating a programme or publishing a call" => {
            &[CommandKind::CreateProgramme, CommandKind::PublishCall]
        }
        "Tenant export, vault export, and any download containing identity attributes"
        | "Adding a passkey, linking a device, or signing in the desktop client"
        | "Changing the account email address or login methods"
        | "Changing bank details"
        | "Publishing a template to other tenants"
        | "Approving break-glass access" => &[],
        // Approving a recovery is a cell-level authentication action
        // (`authentication.md` Account recovery, I-79). The domain has no
        // command for it, and `fstp_cell_core::gate::HIGH_RISK_TABLE`
        // carries its step-up (decided 2026-10-28, Q15).
        "Approving an account recovery" => &[],
        _ => return None,
    };
    Some(kinds)
}

/// I-78 and I-85: the high-risk command kinds are exactly the domain
/// commands of the high-risk table in `SPEC/03-architecture/authentication.md`,
/// which the test reads row by row.
#[test]
fn i78_high_risk_kinds_match_authentication_list() {
    let doc = match read_spec("03-architecture/authentication.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let lines = match section(&doc, "## High-risk actions and step-up (I-78)") {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let rows = match table(&lines, &["Action", "Why"]) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let mut spec = BTreeSet::new();
    for row in rows {
        let action = row.first().cloned().unwrap_or_default();
        match high_risk_kinds(&action) {
            Some(kinds) => spec.extend(kinds.iter().copied()),
            None => panic!("high-risk action {action:?} has no mapping to command kinds"),
        }
    }
    let ours: BTreeSet<CommandKind> = CommandKind::ALL
        .iter()
        .copied()
        .filter(|k| k.high_risk())
        .collect();
    assert_eq!(ours, spec, "high-risk kinds differ from authentication.md");
}

/// R-MC-05: the binding actions that `mcp-server.md` names as examples
/// (submitting a proposal, answering stage 2, a payment request, a score)
/// are binding, and System commands are not.
#[test]
fn r_mc_05_binding_actions_include_the_named_examples() {
    for k in [
        CommandKind::Submit,
        CommandKind::AnswerQuestions,
        CommandKind::RequestPayment,
        CommandKind::RecordScore,
        CommandKind::ConfirmPaid,
    ] {
        assert!(k.binding_action(), "{k:?} must be a binding action");
    }
    for (k, rule) in fstp_domain::rules::ACTOR_RULES {
        if *rule == fstp_domain::rules::ActorRule::System {
            assert!(!k.binding_action(), "System command {k:?} marked binding");
        }
    }
}

/// I-85: a high-risk command never completes through MCP. The dispatcher
/// refuses it before any lane runs.
#[test]
fn i85_high_risk_command_refused_through_mcp() {
    let cmd = Command::PublishCall {
        call: CallId::from_raw(1),
        config: LlmConfigId::from_raw(1),
        config_model: ModelRef("synthetic-model".to_owned()),
    };
    let mcp = Ctx {
        via: Via::Mcp,
        ..ctx()
    };
    assert_eq!(
        decide(&State::genesis(), &cmd, &mcp, &Answers::new()),
        Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp))
    );
}

/// I-84: a System actor cannot issue a command whose actor rule names a
/// person, here the lead's acceptance of the grant.
#[test]
fn i84_system_actor_refused_for_a_person_command() {
    let system = Ctx {
        actor: Actor::System(SystemCause::Timeline),
        ..ctx()
    };
    assert_eq!(
        decide(&State::genesis(), &accept_grant(), &system, &Answers::new()),
        Err(wrong_actor())
    );
}

/// I-84: an account cannot issue a System command, here `ExpireStage2`.
#[test]
fn i84_account_refused_for_a_system_command() {
    let cmd = Command::ExpireStage2 {
        proposal: ProposalId::from_raw(7),
    };
    assert_eq!(
        decide(&State::genesis(), &cmd, &ctx(), &Answers::new()),
        Err(wrong_actor())
    );
}

/// I-84 and R-LA-03: `CloseStage1` is recorded by a named FSTP coordinator,
/// so a System actor cannot issue it (Q2 A).
#[test]
fn r_la_03_system_actor_cannot_record_stage1_close() {
    let system = Ctx {
        actor: Actor::System(SystemCause::Timeline),
        ..ctx()
    };
    let cmd = Command::CloseStage1 {
        proposal: ProposalId::from_raw(7),
    };
    assert_eq!(
        decide(&State::genesis(), &cmd, &system, &Answers::new()),
        Err(wrong_actor())
    );
}

/// I-84 and O-47: `GrantRole` needs a tenant admin at tenant scope, which
/// the shell attests. Without the attestation it is refused. With it the
/// command passes the actor check and reaches the roles lane.
#[test]
fn i84_tenant_admin_rule_needs_the_shell_attestation() {
    let state = State::genesis();
    assert_eq!(
        decide(&state, &grant_role(), &ctx(), &Answers::new()),
        Err(wrong_actor())
    );
    let admin = Ctx {
        tenant_admin: true,
        ..ctx()
    };
    let reached = decide(&state, &grant_role(), &admin, &Answers::new());
    assert!(
        reached.is_err(),
        "a grant in an unknown programme was accepted"
    );
    assert_ne!(reached, Err(wrong_actor()));
}

/// `decide` refuses a command time before the latest recorded time.
#[test]
fn interface_decide_refuses_a_time_before_the_floor() {
    let early = Ctx {
        now: Timestamp::from_micros(-1),
        ..ctx()
    };
    assert_eq!(
        decide(&State::genesis(), &accept_grant(), &early, &Answers::new()),
        Err(Refusal::new(RuleRef::Ledger, RefusalReason::ClockBackwards))
    );
}

fn vault_outcome() -> Record {
    Record::VaultOutcome {
        kind: QueryKind::IsVerified,
        digest: ContentDigest::from_bytes([3; 32]),
        holds: true,
        epoch: VaultEpoch::GENESIS,
    }
}

/// The audit records leave the projection unchanged except for the time
/// floor, and the fold refuses an entry earlier than that floor.
#[test]
fn interface_apply_refuses_time_backwards() {
    let mut state = State::genesis();
    let record = vault_outcome();
    assert_eq!(
        apply(
            &mut state,
            Seq::from_raw(1),
            Timestamp::from_micros(5),
            &record
        ),
        Ok(())
    );
    assert_eq!(state.now_floor(), Timestamp::from_micros(5));
    let before = state.clone();
    assert_eq!(
        apply(
            &mut state,
            Seq::from_raw(2),
            Timestamp::from_micros(4),
            &record
        ),
        Err(FoldError::TimeBackwards)
    );
    assert_eq!(state, before, "a refused fold changed the state");
}

fn answer(holds: bool) -> Answer {
    Answer {
        holds,
        accounts: None,
        epoch: VaultEpoch::GENESIS,
        digest: ContentDigest::from_bytes([0; 32]),
    }
}

fn hash_of(a: &Answers) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    a.hash(&mut h);
    h.finish()
}

/// Two answer sets with the same entries are equal and hash equally,
/// whatever order the driver asked the queries in.
#[test]
fn interface_answers_equality_ignores_insertion_order() {
    let q1 = Query::IsVerified {
        account: AccountId::from_raw(1),
    };
    let q2 = Query::IsVerified {
        account: AccountId::from_raw(2),
    };
    let mut a = Answers::new();
    a.insert(q1.clone(), answer(true));
    a.insert(q2.clone(), answer(false));
    let mut b = Answers::new();
    b.insert(q2.clone(), answer(false));
    b.insert(q1.clone(), answer(true));
    assert_eq!(a, b);
    assert_eq!(hash_of(&a), hash_of(&b));

    let mut c = Answers::new();
    c.insert(q1, answer(true));
    c.insert(q2, answer(true));
    assert_ne!(a, c, "different answers compare equal");
}

fn criterion(id: u128, weight: u16) -> Criterion {
    Criterion {
        id: CriterionId::from_raw(id),
        weight: NonZeroU16::new(weight).unwrap_or(NonZeroU16::MIN),
    }
}

fn scale(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap_or(NonZeroU8::MIN)
}

/// `Criteria::new` accepts the design section 2.4 bounds and refuses
/// values outside them, so a policy can be built outside the crate.
#[test]
fn interface_criteria_new_checks_design_bounds() {
    let ok = Criteria::new(scale(4), vec![criterion(1, 30), criterion(2, 40)]);
    assert!(ok.is_ok(), "{ok:?}");
    let max: Vec<Criterion> = (1..=16).map(|i| criterion(i, 1000)).collect();
    assert!(Criteria::new(scale(100), max).is_ok());

    assert_eq!(
        Criteria::new(scale(4), Vec::new()),
        Err(CriteriaError::Empty)
    );
    let many: Vec<Criterion> = (1..=17).map(|i| criterion(i, 1)).collect();
    assert_eq!(Criteria::new(scale(4), many), Err(CriteriaError::TooMany));
    assert_eq!(
        Criteria::new(scale(4), vec![criterion(1, 1001)]),
        Err(CriteriaError::WeightTooLarge)
    );
    assert_eq!(
        Criteria::new(scale(101), vec![criterion(1, 1)]),
        Err(CriteriaError::ScaleTooLarge)
    );
    assert_eq!(
        Criteria::new(scale(4), vec![criterion(1, 1), criterion(1, 2)]),
        Err(CriteriaError::DuplicateCriterion)
    );
}

fn vault_entry(seq: u64, at: i64) -> Entry<Record> {
    entry(seq, at, [2; 16], vault_outcome())
}

/// An entry with these envelope fields. Only a store or the decoder builds
/// entries, so this decodes a template and then sets the public fields,
/// which lets replay tests use sequence numbers no store would write.
#[allow(clippy::expect_used, reason = "the template is a fixed valid entry")]
fn entry(seq: u64, at: i64, command: [u8; 16], record: Record) -> Entry<Record> {
    let text = br#"{"at":0,"command":"00000000000000000000000000000000","record":null,"schema":1,"seq":"1"}"#;
    let value = fstp_json::parse(text).expect("template entry parses");
    let mut e = fstp_json::FromJson::from_json(&value)
        .map(|e: Entry<fstp_json::Value>| e.map_record(|_| record))
        .expect("template entry decodes");
    e.seq = Seq::from_raw(seq);
    e.at = at;
    e.command = command;
    e
}

/// `replay` folds only a log numbered from 1 with no gaps. A repeated,
/// decreasing, skipped or zero sequence number fails with `OutOfOrder`,
/// even for records that leave the projection unchanged.
#[test]
fn interface_replay_refuses_entries_out_of_sequence() {
    let good = vec![vault_entry(1, 1), vault_entry(2, 2)];
    assert!(replay(&good).is_ok());
    for bad in [
        vec![vault_entry(1, 1), vault_entry(1, 2)],
        vec![vault_entry(2, 1), vault_entry(1, 2)],
        vec![vault_entry(1, 1), vault_entry(3, 2)],
        vec![vault_entry(0, 1)],
        vec![vault_entry(2, 1)],
    ] {
        assert_eq!(replay(&bad), Err(FoldError::OutOfOrder), "{bad:?}");
    }
}

/// Enforcement point 3: `VaultChanged` carries the accounts that the
/// driver's first `ChangedSince` answer listed, so its batch is decided in
/// one round. A System vault actor passes the actor check and reaches the
/// roles lane.
#[test]
fn interface_vault_changed_carries_the_changed_accounts() {
    let cmd = Command::VaultChanged {
        epoch: VaultEpoch::GENESIS,
        changed: BTreeSet::from([AccountId::from_raw(4), AccountId::from_raw(5)]),
    };
    assert_eq!(cmd.kind(), CommandKind::VaultChanged);
    let system = Ctx {
        actor: Actor::System(SystemCause::Vault),
        ..ctx()
    };
    let reached = decide(&State::genesis(), &cmd, &system, &Answers::new());
    assert!(
        reached.is_err(),
        "a change at the processed epoch was accepted"
    );
    assert_ne!(reached, Err(wrong_actor()));
}

/// R-MC-05: a binding action through MCP asks the owning lane for the
/// policy that governs it, and lane L-POL reads P-77 from that policy.
///
/// Step W5 integration rewrote this test, which assumed both lookups were
/// still stubs. It now uses a real binding action, `DraftCall`, and a real
/// governing policy: the head policy version of a programme created from
/// genesis (`PolicyScope::Programme`). Under P-77 "draft only" the call
/// draft through MCP is refused for P-77. Under P-77 "allowed" it passes
/// the MCP gate and gets the same verdict as through the web: the drafter
/// holds no CallDrafter binding, which is a rule of the programme lane.
#[test]
fn r_mc_05_mcp_binding_action_reaches_the_governing_policy_lookup() {
    let mut state = State::genesis();
    let admin = Ctx {
        tenant_admin: true,
        ..ctx()
    };
    for (programme, p77) in [
        (DRAFT_ONLY, McpBindingActions::DraftOnly),
        (ALLOWED, McpBindingActions::Allowed),
    ] {
        let policy = Box::new(policy_version(programme.raw(), programme, p77));
        let r = run(&mut state, &Command::CreateProgramme { policy }, &admin);
        assert_eq!(
            r,
            Ok(()),
            "the tenant admin creates programme {programme:?}"
        );
    }
    let mcp = Ctx {
        via: Via::Mcp,
        ..ctx()
    };
    let draft = |programme| draft_call(CallId::from_raw(programme_raw(programme)), programme);
    assert!(draft(DRAFT_ONLY).binding_action());
    assert_eq!(
        decide(&state, &draft(DRAFT_ONLY), &mcp, &Answers::new()),
        Err(Refusal::new(
            RuleRef::Param(ParamId::P77),
            RefusalReason::NotThroughMcp
        )),
        "R-MC-05: the head P-77 of programme 1 keeps binding actions off MCP"
    );
    let through_mcp = decide_answered(&state, &draft(ALLOWED), &mcp);
    let through_web = decide_answered(&state, &draft(ALLOWED), &ctx());
    assert!(
        through_mcp.is_err(),
        "an account without a CallDrafter binding drafted a call"
    );
    assert_ne!(
        through_mcp,
        Err(Refusal::new(
            RuleRef::Param(ParamId::P77),
            RefusalReason::NotThroughMcp
        )),
        "R-MC-05: P-77 \"allowed\" lets the binding action through MCP"
    );
    if let Err(r) = &through_mcp {
        assert!(!is_not_implemented(r), "the programme lane is implemented");
    }
    assert_eq!(
        through_mcp, through_web,
        "R-MC-05: past the P-77 gate, MCP and the web reach the same lane verdict"
    );
}

// ---------------------------------------------------------------------------
// Helpers of the step W5 integration rewrite
// ---------------------------------------------------------------------------

/// The programme whose head P-77 is "draft only".
const DRAFT_ONLY: ProgrammeId = ProgrammeId::from_raw(1);
/// The programme whose head P-77 is "allowed".
const ALLOWED: ProgrammeId = ProgrammeId::from_raw(2);

fn programme_raw(p: ProgrammeId) -> u128 {
    p.raw()
}

/// Whether `r` is a not-implemented refusal. It reads the debug names, so
/// it compiles whether or not the `NotImplemented` variants stay for wire
/// compatibility.
fn is_not_implemented(r: &Refusal) -> bool {
    format!("{:?}", r.rule) == "NotImplemented" || format!("{:?}", r.reason) == "NotImplemented"
}

/// Every actor kind and channel the sweep sends a command through.
fn contexts() -> Vec<Ctx> {
    let mut out = vec![
        ctx(),
        Ctx {
            tenant_admin: true,
            ..ctx()
        },
        Ctx {
            via: Via::Mcp,
            ..ctx()
        },
    ];
    for cause in [
        SystemCause::Timeline,
        SystemCause::Vault,
        SystemCause::ContractPort,
        SystemCause::PaymentPort,
    ] {
        out.push(Ctx {
            actor: Actor::System(cause),
            ..ctx()
        });
    }
    out
}

/// An answer to every query in `qs`: nothing holds, no account changed,
/// at the genesis epoch.
fn answered(qs: Vec<Query>) -> Answers {
    let mut a = Answers::new();
    for q in qs {
        let accounts = matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new);
        a.insert(
            q,
            Answer {
                holds: false,
                accounts,
                epoch: VaultEpoch::GENESIS,
                digest: ContentDigest::from_bytes([0; 32]),
            },
        );
    }
    a
}

/// `decide` with [`answered`] answers to the command's queries.
fn decide_answered(state: &State, cmd: &Command, c: &Ctx) -> Result<Vec<Record>, Refusal> {
    let answers = answered(queries(state, cmd, c)?);
    decide(state, cmd, c, &answers)
}

/// Decides `cmd` and folds its records into `state`.
fn run(state: &mut State, cmd: &Command, c: &Ctx) -> Result<(), String> {
    let records = decide_answered(state, cmd, c).map_err(|r| r.to_string())?;
    let mut seq = 1u64;
    for r in &records {
        apply(state, Seq::from_raw(seq), c.now, r).map_err(|e| e.to_string())?;
        seq = seq.saturating_add(1);
    }
    Ok(())
}

fn text_ref(n: u128) -> TextRef {
    let mut d = [0u8; 32];
    let (head, _) = d.split_at_mut(16);
    head.copy_from_slice(&n.to_be_bytes());
    TextRef::new(TextId::from_raw(n), ContentDigest::from_bytes(d))
}

#[allow(
    clippy::panic,
    reason = "a fixed synthetic fixture that cannot be built fails the test"
)]
fn eur(minor: i64) -> NonNegAmount {
    Amount::from_minor(minor, Currency::Eur)
        .and_then(NonNegAmount::new)
        .unwrap_or_else(|e| panic!("amount: {e:?}"))
}

#[allow(
    clippy::panic,
    reason = "a fixed synthetic fixture that cannot be built fails the test"
)]
fn pos(minor: i64) -> PosAmount {
    Amount::from_minor(minor, Currency::Eur)
        .and_then(PosAmount::new)
        .unwrap_or_else(|e| panic!("amount: {e:?}"))
}

#[allow(
    clippy::panic,
    reason = "a fixed synthetic fixture that cannot be built fails the test"
)]
fn opaque(s: &str) -> OpaqueValue {
    OpaqueValue::from_value(&fstp_json::Value::String(s.to_owned()))
        .unwrap_or_else(|e| panic!("opaque value: {e:?}"))
}

/// The frozen parameters without a typed field (as the testkit's
/// `gen::policy::FROZEN_OPAQUE`).
const FROZEN_OPAQUE: [ParamId; 18] = [
    ParamId::P08,
    ParamId::P23,
    ParamId::P25,
    ParamId::P28,
    ParamId::P29,
    ParamId::P30,
    ParamId::P34,
    ParamId::P44,
    ParamId::P55,
    ParamId::P59,
    ParamId::P60,
    ParamId::P61,
    ParamId::P62,
    ParamId::P63,
    ParamId::P64,
    ParamId::P65,
    ParamId::P66,
    ParamId::P75,
];

/// The live parameters without a typed field (as the testkit's
/// `gen::policy::LIVE_OPAQUE`).
const LIVE_OPAQUE: [ParamId; 27] = [
    ParamId::P06,
    ParamId::P18,
    ParamId::P19,
    ParamId::P22,
    ParamId::P27,
    ParamId::P31,
    ParamId::P32,
    ParamId::P33,
    ParamId::P35,
    ParamId::P36,
    ParamId::P37,
    ParamId::P40,
    ParamId::P41,
    ParamId::P42,
    ParamId::P43,
    ParamId::P45,
    ParamId::P46,
    ParamId::P47,
    ParamId::P48,
    ParamId::P49,
    ParamId::P50,
    ParamId::P51,
    ParamId::P52,
    ParamId::P54,
    ParamId::P57,
    ParamId::P67,
    ParamId::P76,
];

/// A complete, valid first policy version of `programme` with P-77 `p77`,
/// with synthetic values only.
#[allow(
    clippy::panic,
    reason = "a fixed synthetic fixture that cannot be built fails the test"
)]
fn policy_version(id: u128, programme: ProgrammeId, p77: McpBindingActions) -> PolicyVersion {
    let two = NonZeroU8::new(2).unwrap_or(NonZeroU8::MIN);
    let p01 = Criteria::new(
        scale(4),
        vec![criterion(1, 30), criterion(2, 40), criterion(3, 30)],
    )
    .unwrap_or_else(|e| panic!("P-01: {e}"));
    let p04 =
        AmountRange::new(eur(500_000), eur(10_000_000)).unwrap_or_else(|e| panic!("P-04: {e:?}"));
    PolicyVersion {
        id: PolicyVersionId::from_raw(id),
        programme,
        parent: None,
        currency: Currency::Eur,
        frozen: FrozenValues {
            p01,
            p02: Percent::from_bp(7_500).unwrap_or_else(|| panic!("P-02")),
            p03: two,
            p04,
            p07: Days::new(28),
            p09: KnockOutCriteria(
                (1u128..=3)
                    .map(|i| KnockOutCriterion {
                        id: KnockOutCriterionId::from_raw(i),
                        text: text_ref(1_000u128.saturating_add(i)),
                    })
                    .collect(),
            ),
            p10: ReadAccess::AssignedReviewersOnly,
            p11: ReviewerAnonymity::Anonymous,
            p14: IrcExemptions(opaque("synthetic P-14")),
            p15: two,
            p16: VotingRules(opaque("synthetic P-16")),
            p17: TieBreakRule(opaque("synthetic P-17")),
            p21: InferenceBinding {
                provider: opaque("synthetic provider"),
                primary: ModelRef("synthetic-model-a".to_owned()),
                fallbacks: vec![ModelRef("synthetic-model-b".to_owned())],
            },
            p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
            p26: LicenceSet(
                [SpdxId("Apache-2.0".to_owned()), SpdxId("MIT".to_owned())]
                    .into_iter()
                    .collect(),
            ),
            p39: two,
            p53: FunderProfileRef(opaque("synthetic funder profile")),
            p77,
            opaque: FROZEN_OPAQUE
                .iter()
                .map(|p| (*p, opaque(&format!("synthetic {}", p.spec_id()))))
                .collect(),
        },
        live: LiveValues {
            p05: eur(40_000_000),
            p12: CoolingOff(1),
            p13: ExclusionClasses([ClassId::from_raw(1)].into_iter().collect()),
            p38: ProximityLists(BTreeMap::new()),
            p56: Some(eur(200_000_000)),
            p58: Some(eur(50_000_000)),
            opaque: LIVE_OPAQUE
                .iter()
                .map(|p| (*p, opaque(&format!("synthetic {}", p.spec_id()))))
                .collect(),
        },
    }
}

/// A `DraftCall` of `call` in `programme`.
fn draft_call(call: CallId, programme: ProgrammeId) -> Command {
    Command::DraftCall {
        call,
        programme,
        opens: Timestamp::from_micros(10),
        deadline: Timestamp::from_micros(20),
        deadline_zone: zone(),
        budget: eur(100_000_000),
        text: text_ref(10_001),
    }
}

#[allow(
    clippy::panic,
    reason = "a fixed synthetic fixture that cannot be built fails the test"
)]
fn zone() -> ZoneName {
    ZoneName::new("Europe/Brussels").unwrap_or_else(|| panic!("zone"))
}

/// A well-formed command of `kind` with synthetic ids that no state holds
/// at genesis. The match is exhaustive, so a new kind needs a sample here.
#[allow(clippy::too_many_lines, reason = "one arm per command kind")]
fn sample(kind: CommandKind) -> Command {
    use CommandKind as K;
    let proposal = ProposalId::from_raw(7);
    let call = CallId::from_raw(1);
    let decision = DecisionId::from_raw(7);
    let assignment = AssignmentId::from_raw(7);
    let request = RequestId::from_raw(7);
    let amendment = AmendmentId::from_raw(7);
    let plan = PlanVersionId::from_raw(7);
    let milestone = MilestoneId::from_raw(7);
    let account = AccountId::from_raw(2);
    let binding = BindingId::from_raw(7);
    let key = ScoreKey {
        assignment,
        stage: Stage::One,
        plan,
    };
    let tasks = vec![Task {
        milestones: vec![Milestone {
            id: milestone,
            amount: pos(100),
            start: Timestamp::from_micros(1),
            due: Timestamp::from_micros(2),
            activity: None,
            deliverables: Vec::new(),
        }],
    }];
    match kind {
        K::CreateProgramme => Command::CreateProgramme {
            policy: Box::new(policy_version(
                9,
                ProgrammeId::from_raw(9),
                McpBindingActions::DraftOnly,
            )),
        },
        K::EditPolicy => Command::EditPolicy {
            base: PolicyVersionId::from_raw(9),
            version: Box::new(policy_version(
                10,
                ProgrammeId::from_raw(9),
                McpBindingActions::DraftOnly,
            )),
        },
        K::DraftCall => draft_call(call, ProgrammeId::from_raw(9)),
        K::EditCall => Command::EditCall {
            call,
            opens: Timestamp::from_micros(10),
            deadline: Timestamp::from_micros(20),
            deadline_zone: zone(),
            budget: eur(100_000_000),
            text: text_ref(10_002),
        },
        K::ApproveCallPublication => Command::ApproveCallPublication { call, decision },
        K::PublishCall => Command::PublishCall {
            call,
            config: LlmConfigId::from_raw(1),
            config_model: ModelRef("synthetic-model-a".to_owned()),
        },
        K::GrantRole => grant_role(),
        K::EndRole => Command::EndRole {
            binding,
            at: Timestamp::from_micros(1),
        },
        K::EndScheduledRole => Command::EndScheduledRole { binding },
        K::ReinstateBinding => Command::ReinstateBinding {
            binding,
            reason: text_ref(7),
        },
        K::VaultChanged => Command::VaultChanged {
            epoch: VaultEpoch::from_raw(1),
            changed: BTreeSet::new(),
        },
        K::CreateDraft => Command::CreateDraft {
            proposal,
            call,
            binding,
            minor: false,
        },
        K::AddTeamMember => Command::AddTeamMember {
            proposal,
            account,
            binding,
        },
        K::AddGuardian => Command::AddGuardian {
            proposal,
            account,
            binding,
        },
        K::RecordPlanVersion => Command::RecordPlanVersion {
            plan,
            proposal,
            origin: PlanOrigin::Negotiated,
            supersedes: None,
            tasks,
            content: ContentDigest::from_bytes([7; 32]),
        },
        K::Submit => Command::Submit {
            proposal,
            plan,
            ethics: EthicsDeclaration {
                issues_declared: false,
                text: text_ref(8),
            },
            notice: NoticeVersion(1),
        },
        K::DeclareConflict => Command::DeclareConflict {
            subject: DeclarationSubject::Assignment(assignment),
            conflicted: false,
            notifiable: false,
        },
        K::Assign => Command::Assign {
            assignment,
            proposal,
            reviewer: account,
            kind: AssignmentKind::Amendment(amendment),
            handle: None,
        },
        K::Unassign => Command::Unassign { assignment },
        K::ReadContent => Command::ReadContent { proposal },
        K::RecordKnockOut => Command::RecordKnockOut {
            decision,
            proposal,
            outcomes: vec![KnockOutResult {
                criterion: KnockOutCriterionId::from_raw(1),
                passed: true,
            }],
            reason: None,
        },
        K::AdmitToStage1 => Command::AdmitToStage1 { decision, proposal },
        K::RecordScore => Command::RecordScore {
            key,
            values: ScoreVector(vec![1, 1, 1]),
        },
        K::CorrectScore => Command::CorrectScore {
            key,
            values: ScoreVector(vec![1, 1, 1]),
            reason: text_ref(9),
        },
        K::RecordRankingSummary => Command::RecordRankingSummary {
            proposal,
            assignment,
            title: text_ref(10),
            neutral_summary: text_ref(11),
            rationale: text_ref(12),
        },
        K::CloseStage1 => Command::CloseStage1 { proposal },
        K::AskQuestion => Command::AskQuestion {
            proposal,
            assignment,
            text: text_ref(13),
        },
        K::RecordNoQuestions => Command::RecordNoQuestions {
            proposal,
            assignment,
        },
        K::AnswerQuestions => Command::AnswerQuestions {
            proposal,
            text: text_ref(14),
        },
        K::SubmitRevision => Command::SubmitRevision { proposal, plan },
        K::RankAfterStage2 => Command::RankAfterStage2 { proposal },
        K::ExpireStage2 => Command::ExpireStage2 { proposal },
        K::RecordCutOff => Command::RecordCutOff {
            decision,
            call,
            order: vec![proposal],
            nominated: 1,
            rationale: text_ref(15),
            tie_breaks: None,
            ballots: vec![Ballot {
                voter: account,
                vote: Vote::For,
                delegated_by: None,
            }],
        },
        K::RecordIrcReview => Command::RecordIrcReview {
            assignment,
            verdict: IrcVerdict::Validate,
        },
        K::DeclineAfterConcern => Command::DeclineAfterConcern { proposal },
        K::ReEnter => Command::ReEnter {
            proposal,
            call: CallId::from_raw(2),
        },
        K::DetermineAmount => Command::DetermineAmount {
            decision,
            proposal,
            agreed: plan,
            deductions: vec![IneligibleCost {
                amount: pos(100),
                reason: text_ref(16),
            }],
        },
        K::AcceptGrant => accept_grant(),
        K::ApproveGrant => Command::ApproveGrant {
            decision,
            proposal,
            determination: decision,
        },
        K::ContractFact => Command::ContractFact {
            proposal,
            contract: ContractId::from_raw(7),
            event: ContractEvent::Effective,
        },
        K::DeclineNegotiation => Command::DeclineNegotiation { proposal },
        K::Withdraw => Command::Withdraw { proposal },
        K::StartExecution => Command::StartExecution { proposal },
        K::Complete => Command::Complete { proposal },
        K::Terminate => Command::Terminate {
            decision,
            proposal,
            reason: text_ref(17),
        },
        K::RequestPayment => Command::RequestPayment {
            request,
            grant: proposal,
            lines: vec![PaymentLine {
                line: LineId::from_raw(7),
                milestone,
                amount: pos(100),
            }],
        },
        K::AcceptLine => Command::AcceptLine {
            request,
            line: LineId::from_raw(7),
            approved: eur(100),
            reason: None,
        },
        K::ApprovePayment => Command::ApprovePayment { request },
        K::ReleasePayment => Command::ReleasePayment { request },
        K::ConfirmPaid => Command::ConfirmPaid { request },
        K::WithdrawPaymentRequest => Command::WithdrawPaymentRequest { request },
        K::RequestPaymentChanges => Command::RequestPaymentChanges {
            request,
            reason: text_ref(18),
        },
        K::RecordDeliverable => Command::RecordDeliverable {
            deliverable: DeliverableId::from_raw(7),
            grant: proposal,
            milestone,
            public_location: text_ref(19),
            release: text_ref(20),
            licence: SpdxId("MIT".to_owned()),
            snapshot: ContentDigest::from_bytes([7; 32]),
            accepted: true,
        },
        K::ProposeAmendment => Command::ProposeAmendment {
            amendment,
            grant: proposal,
            plan,
        },
        K::RouteAmendment => Command::RouteAmendment {
            amendment,
            route: AmendmentRoute::Irc,
        },
        K::ActivateAmendment => Command::ActivateAmendment {
            amendment,
            contract: ContractId::from_raw(7),
        },
        K::CloseMilestone => Command::CloseMilestone {
            proposal,
            milestone,
            reason: text_ref(21),
        },
        K::ClosePaymentRequest => Command::ClosePaymentRequest {
            request,
            reason: text_ref(22),
        },
    }
}
