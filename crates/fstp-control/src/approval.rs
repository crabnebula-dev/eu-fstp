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
//! Every approval, refused request, custody call, erasure step and run is
//! logged in the book, with the job digest and staff references only.
//! Interim, pending Daniel: the log stays in memory until `cp.job` rows
//! are written (ADR-011 record of lane m3/erase-cell).
//!
//! # The agent's own check (ADR-011, lane m3/erase-cell-2)
//!
//! `fstp-pgagent` checks both approvals of a destructive job again
//! itself ([`AgentApprovals`]). The book keeps each approval's evidence:
//! the passkey assertion, the 32 random octets of its challenge and the
//! time the challenge was drawn ([`ApprovalEvidence`]). An approved agent
//! job carries both. The agent recomputes the job digest from its own
//! cluster id and the job, then the challenge from that digest
//! ([`approval_challenge`]), and verifies each assertion against the staff
//! passkeys pinned in its own configuration. So an approval count read
//! from the `cp` database never stands in for the approvals.

use std::collections::BTreeMap;

use fstp_cp_proto::{CellId, StaffRef};
use fstp_webauthn::{AssertionExpect, AssertionResponse, RelyingParty, StoredCredential};

use crate::ControlError;
use crate::api::{CpApiRequest, encode_cp_api};
use crate::erase::ErasureStep;
use crate::operator::{CHALLENGE_LIFETIME_SECS, StaffCredential};
use crate::pgagent::{PgagentJob, VerifiedJob, encode_pgagent_job};
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

/// The domain label of an approval challenge. Version 2 binds the time
/// the challenge was drawn, so `fstp-pgagent` can bound an approval's age
/// itself.
const APPROVAL_LABEL: &[u8] = b"fstp-cp-approval-v2";

/// The challenge of an approval: SHA-256 over the label, the job digest,
/// the time the challenge was drawn as a big-endian `i64`, and 32 random
/// octets. The assertion over it binds the job and that time.
pub fn approval_challenge(digest: JobDigest, issued_at: i64, nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = APPROVAL_LABEL.to_vec();
    m.extend_from_slice(&digest.0);
    m.extend_from_slice(&issued_at.to_be_bytes());
    m.extend_from_slice(nonce);
    fstp_crypto::sha256(&m)
}

/// What an approver signed: the time the challenge was drawn, its random
/// octets and the passkey assertion over [`approval_challenge`]. The
/// agent checks it again ([`AgentApprovals`]). It names no staff member:
/// the agent finds the member from the credential id among its own
/// pinned passkeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalEvidence {
    /// When the challenge was drawn, in seconds.
    pub issued_at: i64,
    /// The random octets of the challenge.
    pub nonce: [u8; 32],
    /// The passkey assertion with user verification.
    pub assertion: AssertionResponse,
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
    /// A step of an admitted cell erasure finished (design section 3.7).
    /// Logged after the step.
    Step {
        /// The `erase-cell` job.
        digest: JobDigest,
        /// The step.
        step: ErasureStep,
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
    evidence: Option<Box<[ApprovalEvidence; 2]>>,
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

    /// The evidence of both approvals, the requester's first, when both
    /// came through a passkey ceremony
    /// ([`ApprovalBook::approve_with_evidence`]). A destructive agent job
    /// is sent only with it, since the agent checks it again.
    pub fn evidence(&self) -> Option<&[ApprovalEvidence; 2]> {
        self.evidence.as_deref()
    }
}

#[derive(Clone, Debug)]
struct Approval {
    digest: JobDigest,
    staff: StaffRef,
    at: i64,
    evidence: Option<ApprovalEvidence>,
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
        self.record(staff, job, at, None)
    }

    /// As [`Self::approve`], and keeps the approval's evidence, so an
    /// approved agent job can carry it to `fstp-pgagent`.
    ///
    /// # Errors
    ///
    /// None yet. The result keeps room for a persisted book.
    pub fn approve_with_evidence(
        &mut self,
        staff: StaffRef,
        job: &DestructiveJob,
        at: i64,
        evidence: ApprovalEvidence,
    ) -> Result<(), ControlError> {
        self.record(staff, job, at, Some(evidence))
    }

    fn record(
        &mut self,
        staff: StaffRef,
        job: &DestructiveJob,
        at: i64,
        evidence: Option<ApprovalEvidence>,
    ) -> Result<(), ControlError> {
        let digest = job_digest(job);
        if self.open.len() >= MAX_APPROVALS {
            self.open.remove(0);
        }
        self.open.push(Approval {
            digest,
            staff,
            at,
            evidence,
        });
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
        let counted: Vec<&Approval> = self
            .open
            .iter()
            .filter(|a| a.digest == digest && fresh(a.at, now))
            .collect();
        let own = counted.iter().any(|a| a.staff == requester);
        let second = counted
            .iter()
            .find(|a| a.staff != requester)
            .map(|a| a.staff);
        match (own, second) {
            (true, Some(other)) => {
                // The newest fresh evidence of each approver.
                let evidence_of = |s: StaffRef| {
                    counted
                        .iter()
                        .rev()
                        .find_map(|a| a.evidence.as_ref().filter(|_| a.staff == s))
                        .cloned()
                };
                let evidence = match (evidence_of(requester), evidence_of(other)) {
                    (Some(a), Some(b)) => Some(Box::new([a, b])),
                    _ => None,
                };
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
                    evidence,
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

    /// Logs a finished step of an admitted cell erasure.
    pub fn log_step(&mut self, job: &ApprovedJob, step: ErasureStep, at: i64) {
        self.log.push(ApprovalEvent::Step {
            digest: job.digest,
            step,
            at,
        });
    }

    /// The log, oldest first.
    pub fn log(&self) -> &[ApprovalEvent] {
        &self.log
    }
}

// ---------------------------------------------------------------------------
// The agent's own check (ADR-011 "fstp-pgagent checks both approvals again
// itself, against a staff key set pinned at its installation").

/// How far ahead of the agent's clock a challenge's time may lie, in
/// seconds. Interim, pending Daniel.
pub const AGENT_CLOCK_SKEW_SECS: i64 = 60;

/// How old a challenge may be when the agent checks its approval, in
/// seconds: the challenge lifetime, in which the approver answers, and
/// then the approval lifetime. Interim, pending Daniel.
pub const AGENT_APPROVAL_WINDOW_SECS: i64 = CHALLENGE_LIFETIME_SECS + APPROVAL_LIFETIME_SECS;

/// The most spent challenges the agent remembers. A check that would
/// exceed it is refused, so the agent never forgets a spent challenge
/// inside its window.
pub const AGENT_MAX_SPENT: usize = 4096;

/// The approvers an agent trusts, pinned in its configuration at
/// installation (ADR-011). A change to them is itself a destructive job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedApprovers {
    /// The agent's own cluster, which every job digest it checks covers.
    pub cluster: ClusterId,
    /// The control-plane host, the relying party of staff passkeys.
    pub operator_host: String,
    /// The pinned staff passkeys.
    pub staff: Vec<StaffCredential>,
}

/// The agent's check of a destructive job's two approvals.
///
/// [`AgentApprovals::verify`] recomputes the digest from the agent's own
/// cluster and the job, the challenge from the digest and the evidence,
/// and verifies each assertion with user verification against the pinned
/// passkeys. Two distinct staff members must approve. A challenge counts
/// once: the agent remembers it while it can still be fresh.
///
/// Interim, pending Daniel: the agent keeps no sign counts, since one
/// staff member's approvals of several jobs may arrive in any order.
/// `fstp-control` keeps them. The spent challenges live in memory, so a
/// restarted agent could run a job again within the window. Every
/// destructive job is idempotent, so that repeats the approved effect
/// only.
#[derive(Debug)]
pub struct AgentApprovals {
    cluster: ClusterId,
    rp: RelyingParty,
    staff: Vec<StaffCredential>,
    spent: BTreeMap<[u8; 32], i64>,
}

impl AgentApprovals {
    /// The check for `pinned`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Config`] for an operator host that is no relying
    /// party host, for no pinned passkey, or for a credential id pinned
    /// twice.
    pub fn new(pinned: &PinnedApprovers) -> Result<AgentApprovals, ControlError> {
        let rp = RelyingParty::new(&pinned.operator_host)
            .map_err(|_| ControlError::Config("operator_host"))?;
        if pinned.staff.is_empty() {
            return Err(ControlError::Config("staff"));
        }
        for (i, s) in pinned.staff.iter().enumerate() {
            if pinned
                .staff
                .iter()
                .skip(i.saturating_add(1))
                .any(|t| t.credential_id == s.credential_id)
            {
                return Err(ControlError::Config("staff"));
            }
        }
        Ok(AgentApprovals {
            cluster: pinned.cluster,
            rp,
            staff: pinned.staff.clone(),
            spent: BTreeMap::new(),
        })
    }

    /// The staff member whose pinned passkey made `e` over `digest`.
    fn approver(&self, digest: JobDigest, e: &ApprovalEvidence) -> Option<StaffRef> {
        let cred = self
            .staff
            .iter()
            .find(|s| s.credential_id == e.assertion.credential_id)?;
        let stored = StoredCredential {
            id: cred.credential_id.clone(),
            key: cred.key.clone(),
            sign_count: 0,
        };
        let expect = AssertionExpect {
            rp: self.rp.clone(),
            challenge: approval_challenge(digest, e.issued_at, &e.nonce),
            user_verification: true,
        };
        fstp_webauthn::verify_assertion(&e.assertion, &stored, &expect)
            .ok()
            .map(|_| cred.staff)
    }

    /// Admits the destructive `job` at `now` (seconds) on two approvals,
    /// and spends both challenges.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] for a job that is not destructive.
    /// [`ControlError::ApprovalRequired`] unless both approvals verify
    /// over this agent's digest of `job`, each from a pinned passkey with
    /// user verification, each fresh and unspent, from two distinct staff
    /// members. A refusal spends nothing.
    pub fn verify(
        &mut self,
        job: &PgagentJob,
        approvals: &[ApprovalEvidence; 2],
        now: i64,
    ) -> Result<VerifiedJob, ControlError> {
        let digest = job_digest(&DestructiveJob::pgagent(self.cluster, job.clone())?);
        let window = |e: &ApprovalEvidence| {
            e.issued_at <= now.saturating_add(AGENT_CLOCK_SKEW_SECS)
                && now.saturating_sub(e.issued_at) <= AGENT_APPROVAL_WINDOW_SECS
        };
        let [a, b] = approvals;
        let challenges = [a, b].map(|e| approval_challenge(digest, e.issued_at, &e.nonce));
        let [ca, cb] = challenges;
        if !window(a) || !window(b) || ca == cb {
            return Err(ControlError::ApprovalRequired);
        }
        if challenges.iter().any(|c| self.spent.contains_key(c)) {
            return Err(ControlError::ApprovalRequired);
        }
        let (Some(sa), Some(sb)) = (self.approver(digest, a), self.approver(digest, b)) else {
            return Err(ControlError::ApprovalRequired);
        };
        if sa == sb {
            return Err(ControlError::ApprovalRequired);
        }
        self.spent
            .retain(|_, at| now.saturating_sub(*at) <= AGENT_APPROVAL_WINDOW_SECS);
        if self.spent.len().saturating_add(2) > AGENT_MAX_SPENT {
            return Err(ControlError::ApprovalRequired);
        }
        self.spent.insert(ca, a.issued_at);
        self.spent.insert(cb, b.issued_at);
        Ok(VerifiedJob::new(job.clone()))
    }
}
