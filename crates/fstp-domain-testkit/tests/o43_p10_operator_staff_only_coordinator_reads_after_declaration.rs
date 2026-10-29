//! O-43 and P-10 NOTE 1: under "operator staff only" the FSTP coordinator reads in STAGE1 and STAGE2 after declaring no conflict (M4 design section 3.4, D4).
//!
//! `SPEC/02-domain/policy-parameters.md` NOTE 1, decided 2026-10-25: under
//! the P-10 option "operator staff only", the FSTP coordinator reads,
//! after declaring conflicts as for the knock-out read. M2 refused every
//! such read, since the reading role was open. Under the two other
//! options the coordinator does not read in stages 1 and 2 (D11).
//!
//! Every story runs production commands from genesis through [`Story`],
//! which compares each step with the references in both directions.
//! COORD2 is a second FSTP coordinator who never declares on PR1.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::AccountId;
use fstp_domain::policy::ReadAccess;
use fstp_domain::record::{ContentRead, Record};
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, PR1, R1, R2, read};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::mc::life_model::{LifeWorld, Story, life_judges, story_setup};

/// A second FSTP coordinator, who declares nothing on PR1.
const COORD2: AccountId = AccountId::from_raw(202);

/// The story of PR1 under P-10 `p10`, with COORD2 bound as a second
/// coordinator. PR1 is in DRAFT.
fn story(p10: ReadAccess) -> Story {
    let mut judges = life_judges();
    judges.push((COORD2, Role::FstpCoordinator, None));
    let setup = story_setup(vec![(L1, PR1, false)], judges);
    let mut steps = setup.draft_steps().unwrap_or_else(|e| panic!("{e}"));
    for s in &mut steps {
        if let Command::CreateProgramme { policy } = &mut s.cmd {
            policy.frozen.p10 = p10;
        }
    }
    Story {
        world: LifeWorld::from_steps(Backend::Production, setup.truth(), &steps)
            .unwrap_or_else(|e| panic!("story from genesis: {e}")),
    }
}

fn reads(records: &[Record], account: AccountId) -> bool {
    records.contains(&Record::ContentRead(ContentRead {
        account,
        proposal: PR1,
    }))
}

/// O-43, D4: in STAGE1 under "operator staff only", the coordinator who
/// declared no conflict on PR1 for the knock-out reads, and the read is
/// recorded (R-AU-01). The assigned reviewers and the undeclared second
/// coordinator do not read.
#[test]
fn o43_p10_operator_staff_only_coordinator_reads_in_stage1() {
    let mut s = story(ReadAccess::OperatorStaffOnly);
    s.to_stage1(L1, PR1, &[R1, R2])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage1));
    let records = s
        .run(&read(COORDINATOR, PR1))
        .unwrap_or_else(|e| panic!("O-43: the declared coordinator reads: {e}"));
    assert!(
        reads(&records, COORDINATOR),
        "R-AU-01: the read is recorded: {records:?}"
    );
    for (who, why) in [
        (R1, "an assigned reviewer reads under operator staff only"),
        (COORD2, "a coordinator who never declared reads (R-CF-02)"),
    ] {
        assert_eq!(
            s.attempt(&read(who, PR1)).unwrap_or_else(|e| panic!("{e}")),
            None,
            "O-43: {why}"
        );
    }
}

/// O-43, D4: the coordinator reads in STAGE2 too.
#[test]
fn o43_p10_operator_staff_only_coordinator_reads_in_stage2() {
    let mut s = story(ReadAccess::OperatorStaffOnly);
    s.closed(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage2));
    let records = s
        .run(&read(COORDINATOR, PR1))
        .unwrap_or_else(|e| panic!("O-43: the declared coordinator reads in STAGE2: {e}"));
    assert!(reads(&records, COORDINATOR));
    assert_eq!(
        s.attempt(&read(R2, PR1)).unwrap_or_else(|e| panic!("{e}")),
        None
    );
}

/// D11, P-10 NOTE 1: under "assigned reviewers only" and "all committee
/// members" the coordinator does not read in STAGE1, and the assigned
/// reviewer does.
#[test]
fn o43_coordinator_does_not_read_under_the_other_p10_options() {
    for p10 in [
        ReadAccess::AssignedReviewersOnly,
        ReadAccess::AllCommitteeMembers,
    ] {
        let mut s = story(p10);
        s.to_stage1(L1, PR1, &[R1, R2])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            s.attempt(&read(COORDINATOR, PR1))
                .unwrap_or_else(|e| panic!("{e}")),
            None,
            "D11: the coordinator reads in STAGE1 under {p10:?}"
        );
        let records = s
            .run(&read(R1, PR1))
            .unwrap_or_else(|e| panic!("the assigned reviewer reads under {p10:?}: {e}"));
        assert!(reads(&records, R1));
    }
}
