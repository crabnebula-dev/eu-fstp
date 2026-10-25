//! The W1c engine stubs refuse without panicking, so later lanes start red (design section 10).
//! The shared checks of the dispatcher run before any lane.

mod support;

use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::command::{Actor, Command, CommandKind, Ctx, SystemCause, Via};
use fstp_domain::engine::{FoldError, apply, decide, due, queries, replay, stage1_ready};
use fstp_domain::id::{
    AccountId, BindingId, CallId, CommandId, ContentDigest, CriterionId, DecisionId, LlmConfigId,
    ProgrammeId, ProposalId, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, Query, QueryKind};
use fstp_domain::policy::ModelRef;
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::scoring::{Criteria, CriteriaError, Criterion};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_ledger::{Entry, Seq};

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
    }
}

fn wrong_actor() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)
}

/// Every engine entry point is total. A command of a lane that has not
/// landed is refused with `NotImplemented`. A fold that cannot apply its
/// record fails without changing the state, an empty replay is genesis, and
/// nothing is due or ready.
#[test]
fn interface_engine_stubs_refuse_without_panicking() {
    let state = State::genesis();
    let cmd = accept_grant();
    assert_eq!(cmd.kind(), CommandKind::AcceptGrant);
    assert_eq!(
        queries(&state, &cmd, &ctx()),
        Err(Refusal::not_implemented())
    );
    assert_eq!(
        decide(&state, &cmd, &ctx(), &Answers::new()),
        Err(Refusal::not_implemented())
    );
    assert_eq!(Refusal::not_implemented().rule, RuleRef::NotImplemented);

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
/// policy that governs it before lane L-POL reads P-77. Both are stubs, so
/// the command is refused without panicking.
#[test]
fn r_mc_05_mcp_binding_action_reaches_the_governing_policy_lookup() {
    let mcp = Ctx {
        via: Via::Mcp,
        ..ctx()
    };
    assert!(accept_grant().binding_action());
    assert_eq!(
        decide(&State::genesis(), &accept_grant(), &mcp, &Answers::new()),
        Err(Refusal::not_implemented())
    );
}
