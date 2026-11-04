//! The I-85 world, built from genesis through production commands.
//!
//! - Programme P1 under the SuperSAFE P-77 "draft only", and programme P2
//!   with P-77 "allowed". [`OWNER`] is the programme manager of both and
//!   [`OTHER`] the call drafter of both. [`ADMIN`] and [`ADMIN_2`] are the
//!   tenant admins.
//! - Calls 1, 2 and 3 in P1 and call 4 in P2, each drafted by [`OTHER`]
//!   and approved by [`OWNER`]. Call 3 is published. So [`OWNER`] may
//!   publish calls 1 and 2 and edit calls 1, 2 and 4.
//! - [`LEAD`] has a draft proposal [`PX`] in call 3 with a recorded plan,
//!   not yet submitted.
//! - Every account has its own verified synthetic identity, and the lead
//!   is attested adult (R-ID-04).
//!
//! Every ledger entry is at `T0` of the roster. The cell clock starts one
//! hour later, at [`START`].

use std::collections::{BTreeMap, BTreeSet};

use fstp_api_core::port::AgentClientId;
use fstp_domain::id::{AccountId, CallId, CommandId, ProgrammeId, ProposalId};
use fstp_domain::policy::{McpBindingActions, ReadAccess};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{
    DraftSpec, ReviewSetup, attest_adult_leads, plan_of, review_truth,
};
use fstp_domain_testkit::r#gen::roster::{self, K1, SodSetup, Step, T0, call};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_engine::{Engine, Record};
use fstp_ledger::MemStore;

use super::FakeVault;

/// The programme manager of P1 and P2, who owns the agent.
pub const OWNER: AccountId = roster::STAFF_PM;
/// The call drafter of P1 and P2: a second staff account.
pub const OTHER: AccountId = roster::STAFF_DRAFTER;
/// The first tenant admin.
pub const ADMIN: AccountId = roster::ADMIN;
/// The second tenant admin.
pub const ADMIN_2: AccountId = roster::ADMIN_2;
/// The lead of the draft proposal.
pub const LEAD: AccountId = roster::C;
/// The draft proposal.
pub const PX: ProposalId = ProposalId::from_raw(11);
/// Programme P1, P-77 "draft only".
pub const P1: ProgrammeId = roster::P1;
/// Programme P2, P-77 "allowed".
pub const P2: ProgrammeId = roster::P2;
/// An approved call of P1 that the owner publishes.
pub const CALL_PUBLISH: CallId = call(1);
/// An approved call of P1 that the owner edits.
pub const CALL_EDIT: CallId = call(2);
/// The published call of P1, holding the draft proposal.
pub const CALL_OPEN: CallId = call(3);
/// An approved call of P2.
pub const CALL_ALLOWED: CallId = call(4);
/// The owner's agent client.
pub const AGENT: AgentClientId = AgentClientId::from_raw(0xa6e7);
/// Another agent client.
pub const AGENT_2: AgentClientId = AgentClientId::from_raw(0xa6e8);
/// When the cell clock starts: one hour after every ledger entry.
pub const START: Timestamp = Timestamp::from_micros(3_601_000_000);

/// The ledger and the vault facts of the world, with the cell clock's
/// start and the attested tenant admin set.
#[derive(Clone, Debug)]
pub struct World {
    /// The ledger.
    pub store: MemStore<Record>,
    /// The vault facts.
    pub truth: GroundTruth,
    /// When the cell clock starts.
    pub start: Timestamp,
    /// The attested tenant admin set.
    pub admins: BTreeSet<AccountId>,
}

/// The setup of the world.
pub fn setup() -> ReviewSetup {
    ReviewSetup {
        base: SodSetup {
            programmes: vec![P1, P2],
            p12: 0,
            p13: [K1].into_iter().collect(),
            calls: vec![
                (P1, CALL_PUBLISH),
                (P1, CALL_EDIT),
                (P1, CALL_OPEN),
                (P2, CALL_ALLOWED),
            ],
            published: vec![CALL_OPEN],
        },
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: Vec::new(),
        drafts: vec![DraftSpec {
            lead: LEAD,
            proposal: PX,
            call: CALL_OPEN,
            team: Vec::new(),
            minor: false,
            submit: false,
        }],
    }
}

/// The production commands of the world, in order. P2's first policy
/// version allows binding actions through MCP.
pub fn steps() -> Result<Vec<Step>, String> {
    let s = setup();
    let mut steps = s.steps()?;
    for step in &mut steps {
        if let fstp_domain::Command::CreateProgramme { policy } = &mut step.cmd
            && policy.programme == P2
        {
            policy.frozen.p77 = McpBindingActions::Allowed;
        }
    }
    Ok(steps)
}

/// The vault facts of the world.
pub fn truth() -> GroundTruth {
    let s = setup();
    let mut truth = review_truth(s.accounts());
    attest_adult_leads(&mut truth, s.drafts.iter().map(|d| (d.lead, d.minor)));
    truth
}

/// The command id of the `i`-th fixture step.
fn fixture_command(i: usize) -> CommandId {
    let mut b = *b"fixture:i85:\0\0\0\0";
    let n = u32::try_from(i).unwrap_or(u32::MAX).to_be_bytes();
    let (_, tail) = b.split_at_mut(12);
    tail.copy_from_slice(&n);
    CommandId::from_bytes(b)
}

/// Builds the world from genesis. Fails with the step that production
/// refused.
pub fn pending_world() -> Result<World, String> {
    let truth = truth();
    let vault = FakeVault::new(truth.clone());
    let mut engine = Engine::open(MemStore::new(), vault.oracle())
        .map_err(|e| format!("open the fixture engine: {e:?}"))?;
    for (i, step) in steps()?.into_iter().enumerate() {
        let ctx = step.ctx(T0, fixture_command(i));
        fstp_domain_testkit::activation::run_core(&mut engine, &step.cmd, ctx)
            .map_err(|e| format!("fixture step {i} {:?}: {e}", step.cmd.kind()))?;
    }
    let (store, _, _) = engine.into_parts();
    Ok(World {
        store,
        truth,
        start: START,
        admins: [ADMIN, ADMIN_2].into_iter().collect(),
    })
}

/// The plan version of [`PX`].
pub fn px_plan() -> fstp_domain::id::PlanVersionId {
    plan_of(PX)
}

/// A default edit of a call: the roster's dates, a new budget and text.
pub fn sample_edit() -> super::requests::CallEdit {
    super::requests::CallEdit {
        opens: roster::CALL_OPENS,
        deadline: roster::CALL_DEADLINE,
        deadline_zone: "Europe/Brussels".to_owned(),
        budget_cents: 90_000_000,
        text: "SYNTHETIC CALL TEXT, EDITED".to_owned(),
    }
}

/// The domain `EditCall` of `edit` on `call`, with `text` for its text.
pub fn edit_command(
    call: CallId,
    edit: &super::requests::CallEdit,
    text: fstp_domain::id::TextRef,
) -> Result<fstp_domain::Command, String> {
    let zone = fstp_domain::time::ZoneName::new(&edit.deadline_zone).ok_or("zone")?;
    Ok(fstp_domain::Command::EditCall {
        call,
        opens: edit.opens,
        deadline: edit.deadline,
        deadline_zone: zone,
        budget: fstp_domain_testkit::r#gen::policy::eur(edit.budget_cents)?,
        text,
    })
}

/// An account outside the world that the lead may add to the team. Its
/// addition asks the vault (I-04, SoD-03).
pub const NEW_MEMBER: AccountId = AccountId::from_raw(2_000);

/// The `n`-th account outside the world, from [`NEW_MEMBER`] on.
pub fn new_member(n: u32) -> AccountId {
    AccountId::from_raw(NEW_MEMBER.raw().saturating_add(u128::from(n)))
}

/// The domain `AddTeamMember` by the lead of `account` to [`PX`].
pub fn add_member_command(
    account: AccountId,
    binding: fstp_domain::id::BindingId,
) -> fstp_domain::Command {
    roster::add_member(LEAD, PX, account, binding, false).cmd
}

/// The domain `PublishCall` of `call`, as the roster's programme manager
/// publishes it, with the P-21 primary model.
pub fn publish_command(call: CallId) -> fstp_domain::Command {
    roster::publish(call).cmd
}

/// The context of a command by `account` through `via` at `now`, with the
/// tenant admin attestation of the world.
pub fn ctx(
    account: AccountId,
    via: fstp_domain::Via,
    now: Timestamp,
    command: u128,
) -> fstp_domain::Ctx {
    let mut b = *b"fixture:ctx:\0\0\0\0";
    let n = u32::try_from(command).unwrap_or(u32::MAX).to_be_bytes();
    let (_, tail) = b.split_at_mut(12);
    tail.copy_from_slice(&n);
    let admin = account == ADMIN || account == ADMIN_2;
    fstp_domain::Ctx {
        now,
        actor: fstp_domain::command::Actor::Account(account),
        command: CommandId::from_bytes(b),
        via,
        tenant_admin: admin,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::fake::FakeEngine;
    use fstp_api_core::port::AsyncEngine;
    use fstp_domain::Via;
    use fstp_domain::programme::CallStatus;
    use fstp_domain::refusal::RuleRef;
    use fstp_domain::rules::ParamId;
    use fstp_engine::Command;
    use fstp_rt::future::block_on;

    fn engine() -> FakeEngine {
        let world = pending_world().unwrap();
        FakeEngine::open(&world, FakeVault::new(world.truth.clone()).oracle()).unwrap()
    }

    fn status(e: &FakeEngine, c: CallId) -> Option<CallStatus> {
        e.state().core.calls().get(c).map(|v| v.status())
    }

    /// I-85 fixture: the world builds from genesis through production
    /// commands, with calls 1, 2 and 4 approved and call 3 published.
    #[test]
    fn i85_fixture_builds_from_genesis_through_production_commands() {
        let e = engine();
        assert_eq!(status(&e, CALL_PUBLISH), Some(CallStatus::Approved));
        assert_eq!(status(&e, CALL_EDIT), Some(CallStatus::Approved));
        assert_eq!(status(&e, CALL_OPEN), Some(CallStatus::Published));
        assert_eq!(status(&e, CALL_ALLOWED), Some(CallStatus::Approved));
        assert!(e.head().raw() > 0);
    }

    /// I-85 and P-77 fixture: through the web the owner may publish call 1
    /// and edit calls 2 and 4. Through MCP the domain refuses the
    /// publication with I-85 and the edit in P1 with P-77, and admits the
    /// edit in P2.
    #[test]
    fn i85_p77_fixture_owner_rights_by_channel() {
        let e = engine();
        let now = START;
        let text = fstp_domain_testkit::r#gen::policy::text(77_001);
        let edit = |c| edit_command(c, &sample_edit(), text).unwrap();
        let publish = Command::Core(publish_command(CALL_PUBLISH));
        let web = ctx(OWNER, Via::Web, now, 1);
        let mcp = ctx(OWNER, Via::Mcp, now, 2);
        assert_eq!(block_on(e.dry_run(&publish, web)), Ok(()));
        assert_eq!(
            block_on(e.dry_run(&Command::Core(edit(CALL_EDIT)), web)),
            Ok(())
        );
        assert_eq!(
            block_on(e.dry_run(&Command::Core(edit(CALL_ALLOWED)), web)),
            Ok(())
        );
        let r = block_on(e.dry_run(&publish, mcp)).unwrap_err();
        assert_eq!(r.rule, RuleRef::I85);
        let r = block_on(e.dry_run(&Command::Core(edit(CALL_EDIT)), mcp)).unwrap_err();
        assert_eq!(r.rule, RuleRef::Param(ParamId::P77));
        assert_eq!(
            block_on(e.dry_run(&Command::Core(edit(CALL_ALLOWED)), mcp)),
            Ok(())
        );
        assert_eq!(e.dry_runs().len(), 6);
        assert_eq!(e.executions().len(), 0, "a dry run executes nothing");
    }

    /// Overview NOTE 5 fixture: adding a team member asks the vault
    /// (I-04, SoD-03), and the dry run reports every answer it obtained.
    #[test]
    fn i85_fixture_team_member_dry_run_asks_the_vault() {
        let e = engine();
        let add = add_member_command(NEW_MEMBER, fstp_domain::id::BindingId::from_raw(5_000));
        let c = ctx(LEAD, Via::Web, START, 3);
        assert_eq!(block_on(e.dry_run(&Command::Core(add), c)), Ok(()));
        let runs = e.dry_runs();
        assert!(!runs[0].asks.is_empty(), "the submission asks the vault");
    }
}
