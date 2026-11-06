//! I-85, the bypass twin (M4 design sections 0.1 and 8.4).
//!
//! The twin calls the engine port `AsyncEngine::execute` with `Via::Mcp`
//! directly, around `dispatch`, as a compromised adapter would. So the
//! domain's own I-85 refusal is tested alone: every `high_risk()` kind of
//! `CommandKind::ALL`, routed or not, is refused with `RuleRef::I85`, and
//! nothing is appended. The web twin of each command that the world makes
//! legal is accepted by a web dry run, so the refusal is the channel's and
//! no other guard's.
//!
//! The engine port is the fake of `fstp_api_testkit::fake`, which runs the
//! production M2 driver and domain. These tests need no `ApiCore`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::ActionDigest;
use fstp_api_core::port::{AsyncEngine, ExecError, ExecMeta, OpName};
use fstp_api_testkit::fake::fixture::{
    ADMIN, ADMIN_2, AGENT, CALL_PUBLISH, OTHER, OWNER, P1, START, World, ctx, new_member,
    pending_world, publish_command,
};
use fstp_api_testkit::fake::{FakeEngine, FakeVault};
use fstp_domain::command::{CommandKind, Via};
use fstp_domain::id::{AccountId, BindingId, PolicyVersionId, ProgrammeId, RequestId};
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::policy::base_version;
use fstp_domain_testkit::r#gen::roster::{self, staff_bindings};
use fstp_engine::Command;
use fstp_rt::future::block_on;

/// One sample command of a high-risk kind: its actor, the command, and
/// whether the world makes its web twin legal.
struct Sample {
    actor: AccountId,
    cmd: fstp_domain::Command,
    legal_on_web: bool,
}

/// A sample of every high-risk kind, or `None` for a kind that is not
/// high-risk. A new high-risk kind gets `None` until a sample is added,
/// and the test then fails naming it.
fn sample(kind: CommandKind) -> Option<Sample> {
    let s = match kind {
        CommandKind::CreateProgramme => Sample {
            actor: ADMIN,
            cmd: fstp_domain::Command::CreateProgramme {
                policy: Box::new(
                    base_version(
                        PolicyVersionId::from_raw(99),
                        ProgrammeId::from_raw(99),
                        None,
                    )
                    .ok()?,
                ),
            },
            legal_on_web: true,
        },
        CommandKind::GrantRole => Sample {
            actor: ADMIN,
            cmd: roster::grant(
                BindingId::from_raw(9_001),
                new_member(50),
                P1,
                Role::FinanceApprover,
                START,
            )
            .cmd,
            legal_on_web: true,
        },
        CommandKind::EndRole => Sample {
            actor: ADMIN,
            cmd: roster::end(staff_bindings(P1)[1], START).cmd,
            legal_on_web: true,
        },
        CommandKind::ReinstateBinding => Sample {
            actor: ADMIN,
            cmd: roster::reinstate(staff_bindings(P1)[1]).cmd,
            legal_on_web: false,
        },
        CommandKind::ApprovePayment => Sample {
            actor: OTHER,
            cmd: fstp_domain::Command::ApprovePayment {
                request: RequestId::from_raw(1),
            },
            legal_on_web: false,
        },
        CommandKind::ReleasePayment => Sample {
            actor: OTHER,
            cmd: fstp_domain::Command::ReleasePayment {
                request: RequestId::from_raw(1),
                record_file: fstp_domain::id::ContentDigest::from_bytes([0; 32]),
            },
            legal_on_web: false,
        },
        CommandKind::PublishCall => Sample {
            actor: OWNER,
            cmd: publish_command(CALL_PUBLISH),
            legal_on_web: true,
        },
        // M4 change D2: the second tenant admin's activation. P1 is active
        // already, so its web twin is refused by another guard.
        CommandKind::ActivateProgramme => Sample {
            actor: ADMIN_2,
            cmd: fstp_domain_testkit::activation::activate_command(P1),
            legal_on_web: false,
        },
        _ => return None,
    };
    Some(s)
}

/// Every high-risk kind with its sample. Fails on a high-risk kind
/// without one.
fn samples() -> Vec<(CommandKind, Sample)> {
    let mut out = Vec::new();
    for kind in CommandKind::ALL {
        if !kind.high_risk() {
            continue;
        }
        let s = sample(kind)
            .unwrap_or_else(|| panic!("high-risk kind {kind:?} has no bypass-twin sample"));
        assert_eq!(
            s.cmd.kind(),
            kind,
            "the sample of {kind:?} is of another kind"
        );
        out.push((kind, s));
    }
    assert!(!out.is_empty(), "CommandKind::ALL has no high-risk kind");
    out
}

fn world() -> World {
    pending_world().unwrap_or_else(|e| panic!("the I-85 world: {e}"))
}

fn engine(w: &World) -> FakeEngine {
    FakeEngine::open(w, FakeVault::new(w.truth.clone()).oracle()).unwrap()
}

/// The metadata a compromised MCP adapter would send.
fn mcp_meta(kind: CommandKind) -> ExecMeta {
    ExecMeta {
        via: Via::Mcp,
        session: None,
        agent: Some(AGENT),
        op: OpName("bypass-twin"),
        request: ActionDigest([0x85; 32]),
        step_up: None,
        pending: None,
        second_tenant_admin: (kind == CommandKind::GrantRole).then_some(roster::ADMIN_2),
    }
}

/// I-85, R-MC-05: `AsyncEngine::execute` with `Via::Mcp` refuses every
/// `high_risk()` kind of `CommandKind::ALL` with `RuleRef::I85` and
/// `NotThroughMcp`, whether or not the actor is attested as a tenant
/// admin, and appends nothing.
#[test]
fn i85_domain_refuses_high_risk_via_mcp_when_dispatch_is_bypassed() {
    let w = world();
    let e = engine(&w);
    let head = e.head();
    let mut n = 0u128;
    for (kind, s) in samples() {
        for admin in [true, false] {
            n = n.saturating_add(1);
            let mut c = ctx(s.actor, Via::Mcp, START, n);
            c.tenant_admin = admin;
            let r = block_on(e.execute(Command::Core(s.cmd.clone()), c, mcp_meta(kind)));
            match r {
                Err(ExecError::Refused(x))
                    if x.rule == RuleRef::I85 && x.reason == RefusalReason::NotThroughMcp => {}
                other => panic!("{kind:?} through MCP (tenant admin {admin}) gave {other:?}"),
            }
            assert_eq!(e.head(), head, "{kind:?} through MCP appended");
        }
    }
    assert!(e.appended().is_empty());
}

/// I-85: the bypass twin is not vacuous. Each command of the twin that the
/// world makes legal passes a web dry run with the same actor, so its MCP
/// refusal comes from the channel alone.
#[test]
fn i85_bypass_twin_web_twins_pass_a_web_dry_run() {
    let w = world();
    let e = engine(&w);
    let mut legal = 0usize;
    let mut n = 1_000u128;
    for (kind, s) in samples() {
        if !s.legal_on_web {
            continue;
        }
        n = n.saturating_add(1);
        let mut c = ctx(s.actor, Via::Web, START, n);
        if kind == CommandKind::GrantRole {
            c.second_tenant_admin = None;
        }
        let r = block_on(e.dry_run(&Command::Core(s.cmd.clone()), c));
        assert_eq!(r, Ok(()), "the web twin of {kind:?} is refused");
        legal = legal.saturating_add(1);
    }
    assert!(legal >= 4, "only {legal} web twins are legal");
}
