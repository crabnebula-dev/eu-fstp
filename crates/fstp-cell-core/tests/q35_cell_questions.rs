//! Q35 A, `overview.md` NOTE 8, ADR-027: the cell asks the two creator
//! queries of a report over the draft's head policy, and a shell answer
//! stands in for the vault's.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::collections::BTreeSet;

use fstp_cell_core::creator::{q35_answer, q35_of, q35_queries};
use fstp_creator::CreatorCommand;
use fstp_domain::id::{ContentDigest, PolicyVersionId, ProgrammeId, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};

const P1: ProgrammeId = ProgrammeId::from_raw(7);

fn supersafe_policy() -> fstp_domain::policy::PolicyVersion {
    let fixture = fstp_programme::supersafe_fixture().expect("the SuperSAFE fixture");
    let profile = fstp_programme::FunderProfile::horizon_europe();
    fstp_programme::compile(
        &fixture.spec,
        &profile,
        fstp_programme::CompileIds::new(P1, PolicyVersionId::from_raw(1), None),
    )
    .expect("the SuperSAFE fixture compiles")
    .policy
}

fn answer(holds: bool) -> Answer {
    Answer {
        holds,
        accounts: None,
        epoch: VaultEpoch::GENESIS,
        digest: ContentDigest::from_bytes([1; 32]),
    }
}

/// Q35, NOTE 8: the questions name the draft's P-13 classes and the list
/// ids of its P-38, and no account.
#[test]
fn q35_questions_name_the_draft_classes_and_lists() {
    let policy = supersafe_policy();
    let [classes, lists] = q35_of(P1, &policy);
    assert_eq!(
        classes,
        Query::ClassesDefined {
            programme: P1,
            classes: policy.live.p13.clone(),
        }
    );
    let want: BTreeSet<_> = policy.live.p38.0.values().copied().collect();
    assert_eq!(
        lists,
        Query::ProximityListsDeclared {
            programme: P1,
            lists: want,
        }
    );
}

/// Q35: a command that reads no report asks nothing, and neither does a
/// report on a programme with no policy.
#[test]
fn q35_only_report_commands_on_a_policy_ask() {
    let state = fstp_engine::EngineState::genesis();
    let fields = CreatorCommand::SaveFields {
        programme: P1,
        base: fstp_creator::DraftRevision::new(1, fstp_ledger::Seq::from_raw(1)),
        fields: Vec::new(),
        clear: Vec::new(),
    };
    assert!(q35_queries(&state, &fields).is_none());
    let request = CreatorCommand::RequestActivation {
        programme: P1,
        revision: fstp_creator::DraftRevision::new(1, fstp_ledger::Seq::from_raw(1)),
    };
    assert!(
        q35_queries(&state, &request).is_none(),
        "no policy, no question"
    );
}

/// Q35, NOTE 2, ADR-027: with no shell answer the vault's answer counts,
/// a missing vault answer leaves the check failing closed, and a shell
/// answer stands in for the vault.
#[test]
fn q35_report_commands_ask_the_vault_without_shell_answers() {
    let policy = supersafe_policy();
    let [classes, _] = q35_of(P1, &policy);
    let mut answers = Answers::new();
    assert_eq!(q35_answer(None, Some(&classes), &answers), None);
    answers.insert(classes.clone(), answer(false));
    assert_eq!(q35_answer(None, Some(&classes), &answers), Some(false));
    answers.insert(classes.clone(), answer(true));
    assert_eq!(q35_answer(None, Some(&classes), &answers), Some(true));
    assert_eq!(
        q35_answer(Some(false), Some(&classes), &answers),
        Some(false)
    );
    assert_eq!(q35_answer(None, None, &answers), None);
}
