//! The two admissions of ADR-026 (decided by Daniel on 2026-11-20): the
//! agent admission of an MCP command, and the API step-up admission of a
//! web command whose step-up is bound to the `ApiCore` request digest
//! (I-77, I-78, I-79, I-85, production design gaps G2b and G2c).
//!
//! Lane L1 wrote these before the two admissions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../../fstp-domain/tests/codec_support/mod.rs"]
#[allow(unused_macros, unused_imports)]
mod codec_support;

mod common;

use std::collections::BTreeSet;

use codec_support::{Draw, command};
use common::{
    MINUTE_US, NOW, P71_US, POLICY, admin_ended, cid, ledger, magic, passkey, plus, state_of,
    stepup, table_commands, with_admins, with_admins_granted,
};
use fstp_cell_core::gate::{
    self, Action, AgentGrant, Deny, HighRiskAction, Principal, ReadAction, STRICT_ADDITIONS,
};
use fstp_cell_core::{CellCommand, CellState};
use fstp_domain::Via;
use fstp_domain::command::CommandKind;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN, T0};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The command id of the action in these tests.
const ID: [u8; 16] = cid(0x31);

/// An `ApiCore` request digest: any 32 bytes the API core computed.
const REQUEST: [u8; 32] = [0x7A; 32];

/// The grant of ADMIN's agent, from a passkey consent one minute ago.
fn grant() -> AgentGrant {
    AgentGrant {
        account: ADMIN,
        family_started: plus(NOW, -MINUTE_US),
        phishing_resistant: true,
    }
}

fn cell() -> CellState {
    with_admins(&[ADMIN]).unwrap()
}

/// The high-risk M2 kinds: those `high_risk()` marks and the strict
/// additions.
fn high_risk_kinds() -> Vec<CommandKind> {
    let strict: BTreeSet<&str> = STRICT_ADDITIONS.iter().map(|s| s.command).collect();
    CommandKind::ALL
        .into_iter()
        .filter(|k| k.high_risk() || strict.contains(format!("{k:?}").as_str()))
        .collect()
}

/// I-85, I-78, ADR-026: the agent admission refuses every command of
/// every row of `HIGH_RISK_TABLE`, whether the row names a cell command
/// or an M2 kind, and whatever the agent offers. An agent never acts
/// high risk: only the user confirms such an action, with a step-up.
#[test]
fn i85_agent_admission_refuses_every_high_risk_action() {
    let s = cell();
    for (name, c) in table_commands().unwrap() {
        let got = gate::admit_agent_command(&s, &grant(), Action::Command(c), ID, NOW);
        assert_eq!(got.map(|_| ()), Err(Deny::NotPermitted), "{name}");
    }
    let kinds = high_risk_kinds();
    assert!(!kinds.is_empty());
    check(
        "i85_agent_admission_refuses_every_high_risk_action",
        |g: &mut Gen| {
            let kind = *g.pick(&kinds);
            let c = command(g, &mut Draw::plain(), kind)?;
            let action = Action::Command(CellCommand::Engine(fstp_engine::Command::Core(c)));
            prop_assert!(
                matches!(HighRiskAction::of(&action), Ok(Some(_)) | Err(_)),
                "{kind:?} is not high risk"
            );
            let got = gate::admit_agent_command(&s, &grant(), action, ID, NOW);
            prop_assert_eq!(got.map(|_| ()), Err(Deny::NotPermitted), "{kind:?}");
            Ok(())
        },
    );
}

/// I-85, ADR-026: an agent's low-risk command is admitted as its
/// account, through `Via::Mcp`, with no step-up and under its command
/// id. Every read is refused: the API core reads, never the agent
/// through the gate.
#[test]
fn i85_agent_admission_admits_low_risk_through_mcp_only() {
    let s = cell();
    let low: Vec<CommandKind> = CommandKind::ALL
        .into_iter()
        .filter(|k| !high_risk_kinds().contains(k))
        .collect();
    check(
        "i85_agent_admission_admits_low_risk_through_mcp_only",
        |g: &mut Gen| {
            let kind = *g.pick(&low);
            let c = command(g, &mut Draw::plain(), kind)?;
            let action = Action::Command(CellCommand::Engine(fstp_engine::Command::Core(c)));
            let a = gate::admit_agent_command(&s, &grant(), action, ID, NOW)
                .map_err(|d| format!("{kind:?}: {d:?}"))?;
            prop_assert_eq!(a.principal(), Principal::Account(ADMIN));
            prop_assert_eq!(a.stepup(), None);
            prop_assert_eq!(a.command_id(), Some(ID));
            prop_assert_eq!(a.inputs().via(), Via::Mcp);
            Ok(())
        },
    );
    for read in [
        ReadAction::ReadContent,
        ReadAction::ReadAudit,
        ReadAction::ReadErasureLog,
    ] {
        let got = gate::admit_agent_command(&s, &grant(), Action::Read(read), ID, NOW);
        assert_eq!(got.map(|_| ()), Err(Deny::NotPermitted), "{read:?}");
    }
}

/// I-77, ADR-026: a management holder's agent whose consent came from a
/// session that is not phishing resistant is refused, as the session
/// itself would be.
#[test]
fn i77_agent_admission_refuses_a_weak_consent_of_a_management_holder() {
    let s = cell();
    let weak = AgentGrant {
        phishing_resistant: false,
        ..grant()
    };
    check("i77_agent_weak_consent", |g: &mut Gen| {
        let c = low_risk_command(g)?;
        let got = gate::admit_agent_command(&s, &weak, Action::Command(c), ID, NOW);
        prop_assert_eq!(got.map(|_| ()), Err(Deny::WeakSessionForRole));
        Ok(())
    });
}

/// I-79, ADR-026: a binding of the account that ended after the token
/// family started ends the grant, as it ends a session. A family that
/// started after the end is admitted.
#[test]
fn i79_agent_admission_refuses_a_grant_older_than_a_binding_end() {
    let ended = plus(NOW, -2 * MINUTE_US);
    let entries = ledger(&[
        (T0, cid(0xA0), vec![common::admin_granted(ADMIN)]),
        (ended, cid(0xA1), vec![admin_ended(ADMIN)]),
    ])
    .unwrap();
    let s = state_of(&entries).unwrap();
    let old = AgentGrant {
        family_started: plus(ended, -MINUTE_US),
        ..grant()
    };
    let young = AgentGrant {
        family_started: plus(ended, MINUTE_US),
        ..grant()
    };
    check("i79_agent_binding_end", |g: &mut Gen| {
        let c = low_risk_command(g)?;
        let got = gate::admit_agent_command(&s, &old, Action::Command(c.clone()), ID, NOW);
        prop_assert_eq!(got.map(|_| ()), Err(Deny::SessionEnded));
        let got = gate::admit_agent_command(&s, &young, Action::Command(c), ID, NOW);
        prop_assert!(got.is_ok(), "{got:?}");
        Ok(())
    });
}

/// A low-risk M2 command drawn from `g`.
fn low_risk_command(g: &mut Gen) -> Result<CellCommand, String> {
    let low: Vec<CommandKind> = CommandKind::ALL
        .into_iter()
        .filter(|k| !high_risk_kinds().contains(k))
        .collect();
    let kind = *g.pick(&low);
    let c = command(g, &mut Draw::plain(), kind)?;
    Ok(CellCommand::Engine(fstp_engine::Command::Core(c)))
}

/// A high-risk table command that a tenant admin's session may run.
fn high_risk_command() -> CellCommand {
    table_commands()
        .unwrap()
        .into_iter()
        .find(|(n, _)| *n == "GrantTenantAdmin")
        .map(|(_, c)| c)
        .unwrap()
}

/// I-78, TH-56, ADR-026: the API step-up admission takes a step-up the
/// ledger granted for the `ApiCore` request digest, in this session,
/// strong, fresh and unused. A step-up for another digest, for the
/// command's own gate digest, of another session, weak, stale or
/// consumed is refused. A magic-link session is refused before any
/// step-up is read.
#[test]
fn i78_api_step_up_admission_binds_the_request_digest() {
    let c = high_risk_command();
    let session = passkey(ADMIN);
    let su = stepup(&session, REQUEST, NOW);
    let s = with_admins_granted(&[ADMIN], &su).unwrap();
    let admit = |s: &CellState, su: Option<&gate::StepUpView>, now: Timestamp| {
        gate::admit_api_command(
            s,
            &session,
            Action::Command(c.clone()),
            ID,
            REQUEST,
            su,
            now,
            &POLICY,
        )
    };
    let a = admit(&s, Some(&su), NOW).unwrap();
    let used = a.stepup().unwrap();
    assert_eq!(used.id, su.id);
    assert_eq!(used.action_digest, REQUEST);
    assert_eq!(a.inputs().via(), Via::Web);
    assert_eq!(a.command_id(), Some(ID));
    // Exactly at P-71 still admits, one microsecond later does not.
    assert!(admit(&s, Some(&su), plus(NOW, P71_US)).is_ok());
    assert_eq!(
        admit(&s, Some(&su), plus(NOW, P71_US + 1)).map(|_| ()),
        Err(Deny::StepUpStale)
    );
    assert_eq!(
        admit(&s, None, NOW).map(|_| ()),
        Err(Deny::StepUpRequired(HighRiskAction::ManagementRoleChange))
    );
    // A step-up the ledger granted for the gate digest of the command
    // does not authorise the API request.
    let gate_digest = fstp_cell_core::try_action_digest(&c, ID).unwrap();
    let other = stepup(&session, gate_digest, NOW);
    let s_other = with_admins_granted(&[ADMIN], &other).unwrap();
    assert_eq!(
        admit(&s_other, Some(&other), NOW).map(|_| ()),
        Err(Deny::StepUpMismatch)
    );
    let weak = gate::StepUpView {
        strong: false,
        ..su.clone()
    };
    let s_weak = with_admins_granted(&[ADMIN], &weak).unwrap();
    assert_eq!(
        admit(&s_weak, Some(&weak), NOW).map(|_| ()),
        Err(Deny::StepUpFromWeakMethod)
    );
    let consumed = gate::StepUpView {
        consumed: true,
        ..su.clone()
    };
    assert_eq!(
        admit(&s, Some(&consumed), NOW).map(|_| ()),
        Err(Deny::StepUpStale)
    );
    let m = magic(ADMIN);
    let got = gate::admit_api_command(
        &s,
        &m,
        Action::Command(c.clone()),
        ID,
        REQUEST,
        Some(&su),
        NOW,
        &POLICY,
    );
    assert_eq!(got.map(|_| ()), Err(Deny::WeakSessionForRole));
}

/// I-85, ADR-026: neither admission admits a system-only or route-only
/// command, whatever the session or the grant.
#[test]
fn i85_new_admissions_refuse_system_and_route_commands() {
    let s = cell();
    let session = passkey(ADMIN);
    let route_only = CellCommand::Auth(fstp_auth::AuthCommand::GrantStepUp {
        action_digest: REQUEST,
        session: session.id,
    });
    let system_only = CellCommand::Auth(fstp_auth::AuthCommand::MarkCredentialSuspect {
        account: ADMIN,
        credential: vec![1, 2, 3],
    });
    for c in [route_only, system_only] {
        let got = gate::admit_api_command(
            &s,
            &session,
            Action::Command(c.clone()),
            ID,
            REQUEST,
            None,
            NOW,
            &POLICY,
        );
        assert_eq!(got.map(|_| ()), Err(Deny::NotPermitted));
        let got = gate::admit_agent_command(&s, &grant(), Action::Command(c), ID, NOW);
        assert_eq!(got.map(|_| ()), Err(Deny::NotPermitted));
    }
}
