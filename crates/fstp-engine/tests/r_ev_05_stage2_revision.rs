//! R-EV-05, NOTE 1 (lane mapp): a stage 2 revision composes the plan of
//! origin "stage 2 revision" and its submission, which name the same plan
//! and proposal. No other plan composes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Command;
use fstp_domain::id::{ContentDigest, PlanVersionId, ProposalId};
use fstp_domain::proposal::PlanOrigin;
use fstp_engine::Stage2Revision;

fn plan(origin: PlanOrigin) -> Command {
    Command::RecordPlanVersion {
        plan: PlanVersionId::from_raw(7),
        proposal: ProposalId::from_raw(3),
        origin,
        supersedes: None,
        tasks: Vec::new(),
        content: ContentDigest::from_bytes([1; 32]),
    }
}

/// R-EV-05: the revision records the plan, then submits that plan of that
/// proposal.
#[test]
fn r_ev_05_revision_submits_the_plan_it_records() {
    let r = Stage2Revision::new(plan(PlanOrigin::Stage2Revision)).unwrap();
    let [first, second] = r.commands();
    assert_eq!(first, plan(PlanOrigin::Stage2Revision));
    assert_eq!(
        second,
        Command::SubmitRevision {
            proposal: ProposalId::from_raw(3),
            plan: PlanVersionId::from_raw(7),
        }
    );
}

/// R-EV-05, NOTE 1: only a plan of origin "stage 2 revision" composes. A
/// submission plan, a negotiated plan, an amendment or another command
/// builds no revision.
#[test]
fn r_ev_05_only_a_stage2_plan_composes() {
    for origin in [
        PlanOrigin::Submitted,
        PlanOrigin::Negotiated,
        PlanOrigin::Amendment,
    ] {
        assert!(Stage2Revision::new(plan(origin)).is_none(), "{origin:?}");
    }
    assert!(
        Stage2Revision::new(Command::SubmitRevision {
            proposal: ProposalId::from_raw(3),
            plan: PlanVersionId::from_raw(7),
        })
        .is_none()
    );
}
