//! I-65, I-66, I-67, I-84, I-85 and R-MC-05: the rule references, command kinds and rules version of M4 (M4 design section 3.4, D2, D5 and D7).
//!
//! D7: `RuleRef` gains I-65, I-66 and I-67, so refusals name the rule.
//! `CommandKind::ALL` grows by four kinds: `ActivateProgramme` (D2) and the
//! three ballot commands of D5. `RulesVersion` is bumped, so decisions
//! recorded before keep their own version. The actor rules of the new
//! kinds are interim readings, pending Daniel (Q1 and Q4).

use fstp_domain::command::CommandKind;
use fstp_domain::record::RulesVersion;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{ACTOR_RULES, ActorRule, actor_rule};

/// The kinds that M4 adds to the 58 kinds of M2 and M3.
const M4_KINDS: [CommandKind; 4] = [
    CommandKind::ActivateProgramme,
    CommandKind::OpenCutOffRound,
    CommandKind::CastBallot,
    CommandKind::DelegateVote,
];

/// D7: I-65, I-66 and I-67 are fixed rule references that name their
/// invariants. `spec_rule_refs_exist` checks that `SPEC/` defines them.
#[test]
fn d7_rule_refs_name_i65_i66_i67() {
    for (r, id) in [
        (RuleRef::I65, "I-65"),
        (RuleRef::I66, "I-66"),
        (RuleRef::I67, "I-67"),
    ] {
        assert_eq!(r.spec_id(), Some(id));
        assert!(RuleRef::ALL_FIXED.contains(&r), "{r:?} is not in ALL_FIXED");
    }
}

/// D7, I-84: `CommandKind::ALL` holds each of its kinds once, the four M4
/// kinds among them, and `ACTOR_RULES` gives each an actor rule. M4 has
/// 62 kinds. M5 adds the System command `RecordChecks` (I-32), so 63.
#[test]
fn d7_command_kinds_grow_by_the_m4_kinds() {
    assert_eq!(CommandKind::ALL.len(), 63);
    assert!(CommandKind::ALL.contains(&CommandKind::RecordChecks));
    let distinct: std::collections::BTreeSet<CommandKind> = CommandKind::ALL.into_iter().collect();
    assert_eq!(
        distinct.len(),
        CommandKind::ALL.len(),
        "a kind appears twice"
    );
    for k in M4_KINDS {
        assert!(CommandKind::ALL.contains(&k), "{k:?} is not in ALL");
        assert!(actor_rule(k).is_some(), "{k:?} has no actor rule");
    }
    assert_eq!(ACTOR_RULES.len(), CommandKind::ALL.len());
}

/// D2, Q1 A, O-47: the activation is a tenant admin's, as `CreateProgramme`
/// and `GrantRole` are. D5, Q4 A: each ballot command is a committee
/// member's, as `RecordCutOff` is.
#[test]
fn d7_actor_rules_of_the_m4_kinds() {
    assert_eq!(
        actor_rule(CommandKind::ActivateProgramme),
        Some(ActorRule::TenantAdmin)
    );
    assert_eq!(
        actor_rule(CommandKind::CreateProgramme),
        Some(ActorRule::TenantAdmin),
        "D1: CreateProgramme keeps its actor rule"
    );
    for k in [
        CommandKind::OpenCutOffRound,
        CommandKind::CastBallot,
        CommandKind::DelegateVote,
        CommandKind::RecordCutOff,
    ] {
        assert_eq!(actor_rule(k), Some(ActorRule::Committee), "{k:?}");
    }
}

/// I-78, I-85, R-MC-05, D2, Q10: the activation and the creation are high
/// risk and binding. The ballot commands are binding actions that are not
/// high risk, so P-77 governs them through MCP.
#[test]
fn d7_high_risk_and_binding_flags_of_the_m4_kinds() {
    assert!(CommandKind::ActivateProgramme.high_risk());
    assert!(CommandKind::ActivateProgramme.binding_action());
    assert!(
        CommandKind::CreateProgramme.high_risk(),
        "Q10: creation stays high risk"
    );
    for k in [
        CommandKind::OpenCutOffRound,
        CommandKind::CastBallot,
        CommandKind::DelegateVote,
    ] {
        assert!(!k.high_risk(), "{k:?}");
        assert!(k.binding_action(), "{k:?}");
    }
}

/// D7, design section 5.1: the rules version of M4 is newer than every
/// earlier one, so decisions recorded under M2 and the minor-flag answers
/// keep their recorded versions.
#[test]
fn d7_rules_version_is_bumped() {
    assert!(RulesVersion::M4 > RulesVersion::MINOR_FLAG_2026_10_29);
    assert!(RulesVersion::MINOR_FLAG_2026_10_29 > RulesVersion::M2);
}
