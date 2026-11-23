//! M10 finding F-039 (lane H-01, H01-1), I-78, TH-56, adapted from the
//! lane's proof of concept.
//!
//! `POST /api/v1/commands` classes a command through `HighRiskAction::of`
//! only. The operation registry marks every tenant setting, the signatory
//! grants, the admin invitation and the I-67 override as high-risk, and
//! the API core asks for their step-up from `OpSpec::high_risk`. The gate's
//! table names none of them. Daniel decided on 2026-11-23 (ADR-026 D8 as
//! amended) that the raw route of a production cell serves break-glass
//! approval only. So I-78 holds on that route when it serves no command
//! that the gate passes without a step-up.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::table_commands;
use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, HighRiskAction, raw_route_serves};
use fstp_engine::TenantRequest;
use fstp_tenant::TenantCommand;

fn of(c: &CellCommand) -> Option<HighRiskAction> {
    HighRiskAction::of(&Action::Command(c.clone())).expect("classified")
}

/// I-78, ADR-026 D8 as amended: the raw route serves break-glass approval
/// and nothing else of the gate's table, and every command it serves
/// needs a step-up at the gate.
#[test]
fn m10_f039_i78_raw_route_serves_only_step_up_commands() {
    let served: Vec<&str> = table_commands()
        .unwrap()
        .into_iter()
        .filter(|(_, c)| raw_route_serves(c))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(served, ["ApproveBreakGlass"]);
    for (name, c) in table_commands().unwrap() {
        if raw_route_serves(&c) {
            assert_eq!(
                of(&c),
                Some(HighRiskAction::ApproveBreakGlass),
                "I-78: the raw route serves {name} without a step-up"
            );
        }
    }
}

/// I-78: a high-risk tenant command in the `onboarding` envelope, such as
/// `tenant.set_guide_notice` through the API core, never passes the raw
/// route without a step-up: the gate classes it, or the route does not
/// serve it.
#[test]
fn m10_f039_i78_raw_route_classes_or_refuses_high_risk_tenant_commands() {
    let cmd = TenantCommand::SetGuideNotice { notice: None };
    assert!(cmd.high_risk(), "the tenant part calls it high-risk");
    let cell = CellCommand::Engine(fstp_engine::Command::Tenant(TenantRequest::new(cmd)));
    assert!(
        of(&cell).is_some() || !raw_route_serves(&cell),
        "I-78: the raw route runs a high-risk tenant command with no step-up"
    );
}

/// I-78, ADR-022: the I-67 override is high-risk in the creator and in
/// the registry (`creator.override_activation`). It never passes the raw
/// route without a step-up.
#[test]
fn m10_f039_i78_raw_route_classes_or_refuses_the_i67_override() {
    use fstp_creator::CreatorCommand;
    use fstp_domain::id::{ContentDigest, DecisionId, ProgrammeId, TextId, TextRef};
    let cmd = CreatorCommand::OverrideActivation {
        programme: ProgrammeId::from_raw(1),
        revision: fstp_creator::DraftRevision::new(1, fstp_ledger::Seq::from_raw(1)),
        decision: DecisionId::from_raw(1),
        reason: TextRef::new(TextId::from_raw(1), ContentDigest::from_bytes([0; 32])),
    };
    assert!(cmd.high_risk(), "the creator calls it high-risk");
    let cell = CellCommand::Engine(fstp_engine::Command::Creator(cmd));
    assert!(
        of(&cell).is_some() || !raw_route_serves(&cell),
        "I-78: the raw route runs the I-67 override with no step-up"
    );
}
