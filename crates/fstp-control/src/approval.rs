//! The two-operator check of destructive control-plane jobs (ADR-011
//! "Two-operator approval", R-SW-02). Lane m3/erase-cell.
//!
//! A destructive job runs only with approvals of two distinct staff
//! members over its digest. The requester holds one of them. Each
//! approval lives [`APPROVAL_LIFETIME_SECS`], and a job that runs
//! consumes every approval of its digest.
//!
//! [`ApprovalBook`] is the pure state. It counts approvals by staff
//! member, never by session or credential, so one person never stands for
//! both. [`crate::operator::OperatorLogin`] feeds it: each approval is a
//! passkey assertion with user verification, over a challenge that binds
//! the job digest, from the session's own staff member. That assertion is
//! the approver's fresh step-up for the job.
//!
//! Every approval, refused request, custody call and run is logged in the
//! book, with the job digest and staff references only. Interim, pending
//! Daniel: the log stays in memory until `cp.job` rows are written
//! (ADR-011 record of lane m3/erase-cell).

use fstp_cp_proto::{CellId, StaffRef};

use crate::ControlError;
use crate::api::{CpApiRequest, encode_cp_api};
use crate::pgagent::{PgagentJob, encode_pgagent_job};
use crate::placement::ClusterId;

/// How long an approval counts, in seconds, from its assertion. Interim,
/// pending Daniel: ADR-011 proposes 5 minutes.
pub const APPROVAL_LIFETIME_SECS: i64 = 300;

/// The most approvals the book holds at once. Older ones go first.
pub const MAX_APPROVALS: usize = 1024;

/// The domain label of a job digest.
const DIGEST_LABEL: &[u8] = b"fstp-cp-job-v1";

/// The job kind octet of `erase-cell`.
const KIND_ERASE_CELL: u8 = 1;
/// The job kind octet of a `fstp-pgagent` job.
const KIND_PGAGENT: u8 = 2;

/// The SHA-256 digest of a destructive job (ADR-011: "The digest covers
/// the job kind, the cluster and every argument").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobDigest(pub [u8; 32]);

/// A destructive `fstp-pgagent` job on one cluster. Only
/// [`DestructiveJob::pgagent`] makes one, so it is always destructive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentJob {
    cluster: ClusterId,
    job: PgagentJob,
    frame: Vec<u8>,
}

impl AgentJob {
    /// The cluster.
    pub fn cluster(&self) -> ClusterId {
        self.cluster
    }

    /// The job.
    pub fn job(&self) -> &PgagentJob {
        &self.job
    }
}

/// A job that needs two operators (ADR-011 job table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestructiveJob {
    /// `erase-cell` (R-SW-02, design section 3.7).
    EraseCell {
        /// The cell.
        cell: CellId,
    },
    /// A destructive `fstp-pgagent` job.
    Pgagent(AgentJob),
}

impl DestructiveJob {
    /// The destructive agent job `job` on `cluster`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] for a job the ADR-011 table does not mark
    /// destructive, which one operator with a step-up runs.
    pub fn pgagent(cluster: ClusterId, job: PgagentJob) -> Result<DestructiveJob, ControlError> {
        if !job.is_destructive() {
            return Err(ControlError::Job("not destructive"));
        }
        let frame = encode_pgagent_job(&job)?;
        Ok(DestructiveJob::Pgagent(AgentJob {
            cluster,
            job,
            frame,
        }))
    }
}

/// The digest of `job`: SHA-256 over the label, a zero octet, the kind
/// octet and the job's canonical bytes. Each encoding has one spelling.
pub fn job_digest(job: &DestructiveJob) -> JobDigest {
    let mut m = DIGEST_LABEL.to_vec();
    m.push(0);
    match job {
        DestructiveJob::EraseCell { cell } => {
            m.push(KIND_ERASE_CELL);
            m.extend_from_slice(&encode_cp_api(&CpApiRequest::EraseCell { cell: *cell }));
        }
        DestructiveJob::Pgagent(a) => {
            m.push(KIND_PGAGENT);
            m.extend_from_slice(&a.cluster.0);
            m.extend_from_slice(&a.frame);
        }
    }
    JobDigest(fstp_crypto::sha256(&m))
}

/// One logged event of the book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalEvent {
    /// A staff member approved a job.
    Approved {
        /// The job.
        digest: JobDigest,
        /// The approver.
        staff: StaffRef,
        /// When, in seconds.
        at: i64,
    },
    /// A request to run a job was refused for want of approvals.
    Refused {
        /// The job.
        digest: JobDigest,
        /// The staff member who asked.
        requester: StaffRef,
        /// When, in seconds.
        at: i64,
    },
    /// A job was admitted to run.
    Ran {
        /// The job.
        digest: JobDigest,
        /// The requester, then the second approver.
        approvers: [StaffRef; 2],
        /// When, in seconds.
        at: i64,
    },
    /// The job made a custody call (ADR-004 "Reconciliation"). Logged
    /// before the call.
    CustodyCall {
        /// The job.
        digest: JobDigest,
        /// The request id of the call.
        request: [u8; 16],
        /// When, in seconds.
        at: i64,
    },
}

/// A job that two distinct staff members approved, admitted to run. Only
/// [`ApprovalBook::take`] makes one.
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovedJob {
    job: DestructiveJob,
    digest: JobDigest,
    approvers: [StaffRef; 2],
    at: i64,
}

impl ApprovedJob {
    /// The job.
    pub fn job(&self) -> &DestructiveJob {
        &self.job
    }

    /// The job digest.
    pub fn digest(&self) -> JobDigest {
        self.digest
    }

    /// The requester, then the second approver. Never equal.
    pub fn approvers(&self) -> [StaffRef; 2] {
        self.approvers
    }

    /// When the job was admitted, in seconds.
    pub fn at(&self) -> i64 {
        self.at
    }
}

#[derive(Clone, Copy, Debug)]
struct Approval {
    digest: JobDigest,
    staff: StaffRef,
    at: i64,
}

/// The approvals that wait for their job, and the log.
#[derive(Debug, Default)]
pub struct ApprovalBook {
    open: Vec<Approval>,
    log: Vec<ApprovalEvent>,
}

fn fresh(at: i64, now: i64) -> bool {
    now >= at && now.saturating_sub(at) <= APPROVAL_LIFETIME_SECS
}

impl ApprovalBook {
    /// Records that `staff` approved `job` at `at`. The caller has
    /// verified the approver's passkey assertion over the job digest.
    ///
    /// # Errors
    ///
    /// None yet. The result keeps room for a persisted book.
    pub fn approve(
        &mut self,
        staff: StaffRef,
        job: &DestructiveJob,
        at: i64,
    ) -> Result<(), ControlError> {
        let digest = job_digest(job);
        if self.open.len() >= MAX_APPROVALS {
            self.open.remove(0);
        }
        self.open.push(Approval { digest, staff, at });
        self.log.push(ApprovalEvent::Approved { digest, staff, at });
        Ok(())
    }

    /// Admits `job` for `requester` at `now`, and consumes every approval
    /// of its digest.
    ///
    /// # Errors
    ///
    /// [`ControlError::ApprovalRequired`] unless the requester and a
    /// second, distinct staff member each hold a fresh approval of the
    /// digest. A refusal consumes nothing.
    pub fn take(
        &mut self,
        requester: StaffRef,
        job: &DestructiveJob,
        now: i64,
    ) -> Result<ApprovedJob, ControlError> {
        let digest = job_digest(job);
        let counted = self
            .open
            .iter()
            .filter(|a| a.digest == digest && fresh(a.at, now));
        let mut own = false;
        let mut second = None;
        for a in counted {
            if a.staff == requester {
                own = true;
            } else if second.is_none() {
                second = Some(a.staff);
            }
        }
        match (own, second) {
            (true, Some(other)) => {
                self.open.retain(|a| a.digest != digest);
                let approvers = [requester, other];
                self.log.push(ApprovalEvent::Ran {
                    digest,
                    approvers,
                    at: now,
                });
                Ok(ApprovedJob {
                    job: job.clone(),
                    digest,
                    approvers,
                    at: now,
                })
            }
            _ => {
                self.log.push(ApprovalEvent::Refused {
                    digest,
                    requester,
                    at: now,
                });
                Err(ControlError::ApprovalRequired)
            }
        }
    }

    /// Logs a custody call of an admitted job, before the call.
    pub fn log_custody_call(&mut self, job: &ApprovedJob, request: [u8; 16], at: i64) {
        self.log.push(ApprovalEvent::CustodyCall {
            digest: job.digest,
            request,
            at,
        });
    }

    /// The log, oldest first.
    pub fn log(&self) -> &[ApprovalEvent] {
        &self.log
    }
}
