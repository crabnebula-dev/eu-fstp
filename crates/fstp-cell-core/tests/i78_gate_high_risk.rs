//! `HighRiskAction::of`, the single high-risk table of the gate (I-78,
//! R-LG-03, M3 design sections 5.4 and 8.4, ADR-008).
//!
//! - Every command that the table names is classified with its row's
//!   action.
//! - Every M2 command kind is high risk exactly when
//!   `CommandKind::high_risk()` says so or `STRICT_ADDITIONS` names it.
//! - Reads and the other cell commands need no step-up.
//!
//! `i78_high_risk_table_matches_spec_and_domain` in `fstp-celltest`
//! checks the table data against the spec text. These tests check the
//! classifier against the table. Lane W2c's test author wrote them before
//! the classifier, which the W0 stub refuses with `Deny::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../../fstp-domain/tests/codec_support/mod.rs"]
#[allow(unused_macros, unused_imports)]
mod codec_support;

use std::collections::BTreeSet;

mod common;

use codec_support::{Draw, command};
use common::{high_risk_of, table_action, table_commands};
use fstp_auth::AuthCommand;
use fstp_cell_core::gate::{Action, HIGH_RISK_TABLE, HighRiskAction, ReadAction, STRICT_ADDITIONS};
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::release::ReleaseCommand;
use fstp_cell_core::text::TextCommand;
use fstp_cell_core::{CellCommand, KeyCommand};
use fstp_domain::command::CommandKind;
use fstp_domain::id::AccountId;
use fstp_prop::{Gen, check, prop_assert_eq};

fn cmd(c: CellCommand) -> Action {
    Action::Command(c)
}

const ADMIN_2: AccountId = AccountId::from_raw(2);

/// Table entries with no command or action in the stubs yet. Each names
/// where it arrives. The coverage test fails if an entry is neither built
/// nor listed here, so the list cannot hide a new entry.
const NO_STUB_ACTION: [(&str, &str); 9] = [
    ("TenantExport", "M9 export"),
    ("VaultExport", "M9 export"),
    (
        "IdentityDownload",
        "vault ticket with download scope, no scope field yet",
    ),
    ("LinkDevice", "no M3 route"),
    ("DesktopSignIn", "no M3 route"),
    ("ChangeEmail", "no M3 route"),
    ("ChangeBankDetails", "M5 payments"),
    ("PublishTemplate", "M4 templates"),
    (
        "ApproveRecovery",
        "fstp-auth recovery step, no AuthCommand variant yet",
    ),
];

/// I-78: every table entry is classified by `of` (through a cell command,
/// or through an M2 kind in the next test), or is listed as having no
/// stub action yet.
#[test]
fn i78_every_table_entry_is_classified_or_listed() {
    let built: BTreeSet<&str> = table_commands().unwrap().iter().map(|(n, _)| *n).collect();
    let m2: BTreeSet<String> = CommandKind::ALL.iter().map(|k| format!("{k:?}")).collect();
    let listed: BTreeSet<&str> = NO_STUB_ACTION.iter().map(|(n, _)| *n).collect();
    for e in HIGH_RISK_TABLE {
        assert!(
            built.contains(e.command) || m2.contains(e.command) || listed.contains(e.command),
            "{} has no classified command and is not listed",
            e.command
        );
        assert!(
            !(listed.contains(e.command) && (built.contains(e.command) || m2.contains(e.command))),
            "{} is listed but also built",
            e.command
        );
    }
    for (name, _) in NO_STUB_ACTION {
        assert!(table_action(name).is_some(), "{name} is not a table entry");
    }
    // Only now the classifier itself: each built command.
    for (name, c) in table_commands().unwrap() {
        assert_eq!(high_risk_of(&cmd(c)), Ok(table_action(name)), "{name}");
    }
}

/// I-78, Q38: every M2 command kind is high risk exactly when the domain's
/// `high_risk()` marks it or `STRICT_ADDITIONS` names it, and then with the
/// action of its table entry. Commands of every kind are drawn with the
/// generators of the M2 codec suites.
#[test]
fn i78_high_risk_of_marks_every_domain_kind_as_the_table_does() {
    let strict: BTreeSet<&str> = STRICT_ADDITIONS.iter().map(|s| s.command).collect();
    check(
        "i78_high_risk_of_marks_every_domain_kind_as_the_table_does",
        |g: &mut Gen| {
            let kind = *g.pick(&CommandKind::ALL);
            let name = format!("{kind:?}");
            let c = command(g, &mut Draw::plain(), kind)?;
            let want = if kind.high_risk() || strict.contains(name.as_str()) {
                Some(
                    table_action(&name)
                        .ok_or_else(|| format!("{name} is high risk but not in the table"))?,
                )
            } else {
                None
            };
            let got = high_risk_of(&cmd(CellCommand::Engine(fstp_engine::Command::Core(c))));
            prop_assert_eq!(got, Ok(want), "{name}");
            Ok(())
        },
    );
}

/// I-78: every M2 kind that the table names is a domain high-risk kind or
/// a strict addition, so no entry is silent (design section 8.4).
#[test]
fn i78_table_m2_entries_are_domain_high_risk_or_strict_additions() {
    let strict: BTreeSet<&str> = STRICT_ADDITIONS.iter().map(|s| s.command).collect();
    let mut unexplained = Vec::new();
    for k in CommandKind::ALL {
        let name = format!("{k:?}");
        if table_action(&name).is_some() && !k.high_risk() && !strict.contains(name.as_str()) {
            unexplained.push(name);
        }
    }
    assert!(unexplained.is_empty(), "{unexplained:?}");
    // The classifier agrees for a fixed command of each strict addition.
    let assign = fstp_domain::Command::Unassign {
        assignment: fstp_domain::id::AssignmentId::from_raw(1),
    };
    assert_eq!(
        high_risk_of(&cmd(CellCommand::Engine(fstp_engine::Command::Core(
            assign
        )))),
        Ok(Some(HighRiskAction::ManagementRoleChange))
    );
}

/// I-78, design section 5.4: reads need no step-up. Break-glass reads are
/// gated by scope and time instead (SoD-08).
#[test]
fn i78_reads_need_no_step_up() {
    for r in [
        ReadAction::ReadContent,
        ReadAction::ReadAudit,
        ReadAction::ReadErasureLog,
    ] {
        assert_eq!(high_risk_of(&Action::Read(r)), Ok(None), "{r:?}");
    }
}

/// I-78: the cell commands that no table row names need no step-up. The
/// table is the single list (design section 8.4).
///
/// `IssueReleaseTicket` is left out: its class depends on a download
/// scope the stub does not carry (section 8.7, `IdentityDownload`).
#[test]
fn i78_cell_commands_outside_the_table_need_no_step_up() {
    let low = [
        CellCommand::Text(TextCommand::PutText { id: [1; 16] }),
        CellCommand::Text(TextCommand::EraseTexts {
            ids: vec![[1; 16]],
            cause: 1,
        }),
        CellCommand::Key(KeyCommand::RecordKeyOp { op: b"{}".to_vec() }),
        CellCommand::Key(KeyCommand::RecordEpochDestroyed {
            epoch: 1,
            receipt: [0; 32],
        }),
        CellCommand::Release(ReleaseCommand::IssueWriteTicket { kind: 1 }),
        CellCommand::Release(ReleaseCommand::RecordRelationship {
            relationship: b"{}".to_vec(),
        }),
        CellCommand::Ops(OpsCommand::EndBreakGlass { grant: [1; 16] }),
        CellCommand::Ops(OpsCommand::ApplyOperatorTicket {
            ticket: b"{}".to_vec(),
        }),
        CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { account: ADMIN_2 }),
        CellCommand::Auth(AuthCommand::GrantStepUp {
            session: [1; 16],
            action_digest: [0; 32],
        }),
    ];
    for c in low {
        assert_eq!(high_risk_of(&cmd(c.clone())), Ok(None), "{c:?}");
    }
}
