//! ADR-011 "Two-operator approval", R-SW-02: the two-operator check of
//! destructive control-plane jobs, as properties of the pure approval
//! book (`fstp_control::approval`). Written before the book (lane
//! m3/erase-cell).
//!
//! A destructive job runs only with approvals of two distinct staff
//! members over its digest, each fresh, the requester one of them. One
//! person never satisfies both. Approvals are single use. Every approval,
//! refusal and run is logged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_control::ControlError;
use fstp_control::approval::{
    APPROVAL_LIFETIME_SECS, ApprovalBook, ApprovalEvent, DestructiveJob, job_digest,
};
use fstp_control::pgagent::{DbIdent, PgagentJob};
use fstp_control::placement::ClusterId;
use fstp_cp_proto::{CellId, StaffRef};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

const T0: i64 = 1_800_000_000;

/// The jobs the properties draw from: two cell erasures and one
/// destructive agent job.
fn jobs() -> Vec<DestructiveJob> {
    let db = DbIdent::parse("c_00112233445566778899aabbccddeeff").unwrap();
    vec![
        DestructiveJob::EraseCell {
            cell: CellId([1; 16]),
        },
        DestructiveJob::EraseCell {
            cell: CellId([2; 16]),
        },
        DestructiveJob::pgagent(ClusterId([3; 16]), PgagentJob::DropCellDatabase(db)).unwrap(),
    ]
}

fn staff(n: u8) -> StaffRef {
    StaffRef([n; 16])
}

/// One step of a run: an approval or a request to run.
#[derive(Clone, Debug)]
enum Step {
    Approve { staff: u8, job: usize, at: i64 },
    Take { staff: u8, job: usize, at: i64 },
}

fn steps(g: &mut Gen, people: u8) -> Vec<Step> {
    let mut at = T0;
    g.vec(1..=24, |g| {
        at += g.i64_in(0..=APPROVAL_LIFETIME_SECS + 60);
        let staff = g.u8_in(1..=people);
        let job = g.usize_in(0..=2);
        if g.bool() {
            Step::Approve { staff, job, at }
        } else {
            Step::Take { staff, job, at }
        }
    })
}

/// The reference: the approvals of each job that are still unused, as
/// (staff, at).
#[derive(Default)]
struct Model {
    open: Vec<Vec<(u8, i64)>>,
}

impl Model {
    fn new() -> Model {
        Model {
            open: vec![Vec::new(); 3],
        }
    }

    fn fresh(at: i64, now: i64) -> bool {
        now >= at && now - at <= APPROVAL_LIFETIME_SECS
    }

    /// Whether a request of `staff` for `job` at `now` runs, and consumes
    /// the job's approvals when it does.
    fn take(&mut self, staff: u8, job: usize, now: i64) -> bool {
        let who: BTreeSet<u8> = self.open[job]
            .iter()
            .filter(|(_, at)| Model::fresh(*at, now))
            .map(|(s, _)| *s)
            .collect();
        let runs = who.contains(&staff) && who.len() >= 2;
        if runs {
            self.open[job].clear();
        }
        runs
    }
}

/// ADR-011 "A destructive job runs only with approvals from two distinct
/// staff members. The requester counts as one of them", and "An approval
/// is single-use and expires after a fixed lifetime": over random runs of
/// three staff members and three jobs, the book runs a request exactly
/// when the reference does, and names two distinct approvers, the
/// requester among them.
#[test]
fn adr011_two_operator_runs_exactly_when_two_distinct_fresh_approvals_hold() {
    check(
        "adr011_two_operator_runs_exactly_when_two_distinct_fresh_approvals_hold",
        |g| {
            let jobs = jobs();
            let mut book = ApprovalBook::default();
            let mut model = Model::new();
            for step in steps(g, 3) {
                match step {
                    Step::Approve { staff: s, job, at } => {
                        book.approve(staff(s), &jobs[job], at).unwrap();
                        model.open[job].push((s, at));
                    }
                    Step::Take { staff: s, job, at } => {
                        let want = model.take(s, job, at);
                        let got = book.take(staff(s), &jobs[job], at);
                        g.note("step", &(s, job, at));
                        match got {
                            Ok(approved) => {
                                prop_assert!(want, "the book ran a job the reference refuses");
                                prop_assert_eq!(approved.job(), &jobs[job]);
                                prop_assert_eq!(approved.digest(), job_digest(&jobs[job]));
                                let [a, b] = approved.approvers();
                                prop_assert!(a != b, "one person stood for both approvers");
                                prop_assert_eq!(a, staff(s));
                            }
                            Err(e) => {
                                prop_assert!(!want, "the book refused a job the reference runs");
                                prop_assert_eq!(e, ControlError::ApprovalRequired);
                            }
                        }
                    }
                }
            }
            Ok(())
        },
    );
}

/// ADR-011, R-SW-02: one staff member alone never runs a destructive job,
/// however many times, at whatever times, they approve it.
#[test]
fn adr011_two_operator_one_person_never_satisfies_both() {
    check("adr011_two_operator_one_person_never_satisfies_both", |g| {
        let jobs = jobs();
        let mut book = ApprovalBook::default();
        for step in steps(g, 1) {
            match step {
                Step::Approve { staff: s, job, at } => {
                    book.approve(staff(s), &jobs[job], at).unwrap();
                }
                Step::Take { staff: s, job, at } => {
                    prop_assert_eq!(
                        book.take(staff(s), &jobs[job], at).map(|a| a.approvers()),
                        Err(ControlError::ApprovalRequired)
                    );
                }
            }
        }
        Ok(())
    });
}

/// ADR-011 "The digest covers the job kind, the cluster and every
/// argument": approvals of one job never count for another, so two
/// approvals of different jobs run neither.
#[test]
fn adr011_two_operator_approvals_bind_the_job_digest() {
    check("adr011_two_operator_approvals_bind_the_job_digest", |g| {
        let jobs = jobs();
        let i = g.usize_in(0..=2);
        let j = (i + g.usize_in(1..=2)) % 3;
        let mut book = ApprovalBook::default();
        book.approve(staff(1), &jobs[i], T0).unwrap();
        book.approve(staff(2), &jobs[j], T0).unwrap();
        for s in [1, 2] {
            for k in [i, j] {
                prop_assert!(book.take(staff(s), &jobs[k], T0 + 1).is_err());
            }
        }
        let digests: BTreeSet<[u8; 32]> = jobs.iter().map(|j| job_digest(j).0).collect();
        prop_assert_eq!(digests.len(), jobs.len());
        Ok(())
    });
}

/// ADR-011 "An approval is single-use": a job that ran needs two new
/// approvals before it runs again.
#[test]
fn adr011_two_operator_approvals_are_single_use() {
    let job = &jobs()[0];
    let mut book = ApprovalBook::default();
    book.approve(staff(1), job, T0).unwrap();
    book.approve(staff(2), job, T0 + 1).unwrap();
    assert!(book.take(staff(1), job, T0 + 2).is_ok());
    assert_eq!(
        book.take(staff(2), job, T0 + 3).map(|a| a.approvers()),
        Err(ControlError::ApprovalRequired)
    );
    book.approve(staff(2), job, T0 + 4).unwrap();
    assert!(book.take(staff(2), job, T0 + 5).is_err());
    book.approve(staff(1), job, T0 + 6).unwrap();
    assert_eq!(
        book.take(staff(2), job, T0 + 7).unwrap().approvers(),
        [staff(2), staff(1)]
    );
}

/// ADR-011 "expires after a fixed lifetime": an approval one second past
/// its lifetime no longer counts.
#[test]
fn adr011_two_operator_approvals_expire() {
    let job = &jobs()[1];
    let mut book = ApprovalBook::default();
    book.approve(staff(1), job, T0).unwrap();
    book.approve(staff(2), job, T0).unwrap();
    assert!(
        book.take(staff(1), job, T0 + APPROVAL_LIFETIME_SECS + 1)
            .is_err()
    );
    book.approve(staff(1), job, T0 + APPROVAL_LIFETIME_SECS)
        .unwrap();
    book.approve(staff(2), job, T0 + APPROVAL_LIFETIME_SECS)
        .unwrap();
    assert!(
        book.take(staff(1), job, T0 + 2 * APPROVAL_LIFETIME_SECS)
            .is_ok()
    );
}

/// ADR-011 "Each job is recorded ... with its approvals": every approval,
/// every refused request and every run is in the book's log, in order,
/// with the job digest and the staff members.
#[test]
fn adr011_two_operator_every_approval_and_run_is_logged() {
    check(
        "adr011_two_operator_every_approval_and_run_is_logged",
        |g| {
            let jobs = jobs();
            let mut book = ApprovalBook::default();
            let mut want = Vec::new();
            for step in steps(g, 3) {
                match step {
                    Step::Approve { staff: s, job, at } => {
                        book.approve(staff(s), &jobs[job], at).unwrap();
                        want.push(ApprovalEvent::Approved {
                            digest: job_digest(&jobs[job]),
                            staff: staff(s),
                            at,
                        });
                    }
                    Step::Take { staff: s, job, at } => {
                        let digest = job_digest(&jobs[job]);
                        want.push(match book.take(staff(s), &jobs[job], at) {
                            Ok(a) => ApprovalEvent::Ran {
                                digest,
                                approvers: a.approvers(),
                                at,
                            },
                            Err(_) => ApprovalEvent::Refused {
                                digest,
                                requester: staff(s),
                                at,
                            },
                        });
                    }
                }
            }
            prop_assert_eq!(book.log(), want.as_slice());
            Ok(())
        },
    );
}

/// ADR-011 job table: only a destructive agent job has a two-operator
/// form. A non-destructive one is refused, since one operator with a
/// step-up runs it.
#[test]
fn adr011_two_operator_admits_destructive_agent_jobs_only() {
    let db = DbIdent::parse("v_00112233445566778899aabbccddeeff").unwrap();
    assert!(DestructiveJob::pgagent(ClusterId([3; 16]), PgagentJob::DropRoles(db)).is_ok());
    assert!(
        DestructiveJob::pgagent(ClusterId([3; 16]), PgagentJob::CreateCellDatabase(db)).is_err()
    );
}
