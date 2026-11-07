//! Evidence snapshots (R-PR-03, I-32, TH-24).
//!
//! A snapshot records, per line, the evidence identifiers as the grantee
//! gave them, the licence the checks detected, and for each retrieval its
//! status, SHA-256 content hash and length, with the retrieval time of
//! the run. Retrieved bytes are never kept: an upstream change or deletion
//! after the run leaves the recorded snapshot and its digest unchanged.
//!
//! [`Snapshot::encode`] is a deterministic length-prefixed encoding under
//! a version label. [`Snapshot::digest`] is the SHA-256 of that encoding,
//! the value `RecordChecks` carries.

use fstp_domain::id::{ContentDigest, LineId, RequestId};
use fstp_domain::payment::CheckPhase;
use fstp_domain::time::Timestamp;

/// The version label that opens every encoding.
pub const LABEL: &[u8] = b"fstp-checks-snapshot-v1\0";

/// The outcome of one retrieval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retrieval {
    /// An answer: its status, the SHA-256 of its body and the body length.
    Got {
        /// The HTTP status.
        status: u16,
        /// The SHA-256 of the body.
        sha256: [u8; 32],
        /// The body length in bytes.
        len: u64,
    },
    /// The cell egress refused the host.
    Refused,
    /// The host could not be reached.
    Unreachable,
    /// The body exceeded the size cap.
    TooLarge,
    /// The retrieval exceeded the time cap.
    TimedOut,
}

/// The evidence of one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineSnapshot {
    /// The line.
    pub line: LineId,
    /// The public location as given.
    pub location: Option<String>,
    /// The release or commit identifier as given.
    pub release: Option<String>,
    /// The declared SPDX expression as given.
    pub declared: Option<String>,
    /// The detected SPDX expression, in canonical form.
    pub detected: Option<String>,
    /// The digest of the progress or delivery report.
    pub report: Option<ContentDigest>,
    /// The retrieval of the public location.
    pub location_page: Option<Retrieval>,
    /// The retrieval of the licence file at the release.
    pub licence_file: Option<Retrieval>,
}

/// The evidence snapshot of one run of the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The request.
    pub request: RequestId,
    /// The phase.
    pub phase: CheckPhase,
    /// When the run retrieved its evidence.
    pub retrieved_at: Timestamp,
    /// One entry per line, in request order.
    pub lines: Vec<LineSnapshot>,
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            put_len(out, s.len());
            out.extend_from_slice(s.as_bytes());
        }
    }
}

fn put_retrieval(out: &mut Vec<u8>, r: Option<Retrieval>) {
    match r {
        None => out.push(0),
        Some(Retrieval::Got {
            status,
            sha256,
            len,
        }) => {
            out.push(1);
            out.extend_from_slice(&status.to_be_bytes());
            out.extend_from_slice(&sha256);
            out.extend_from_slice(&len.to_be_bytes());
        }
        Some(Retrieval::Refused) => out.push(2),
        Some(Retrieval::Unreachable) => out.push(3),
        Some(Retrieval::TooLarge) => out.push(4),
        Some(Retrieval::TimedOut) => out.push(5),
    }
}

impl Snapshot {
    /// The deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = LABEL.to_vec();
        out.extend_from_slice(&self.request.raw().to_be_bytes());
        out.push(match self.phase {
            CheckPhase::Submission => 1,
            CheckPhase::Acceptance => 2,
        });
        out.extend_from_slice(&self.retrieved_at.micros().to_be_bytes());
        put_len(&mut out, self.lines.len());
        for l in &self.lines {
            out.extend_from_slice(&l.line.raw().to_be_bytes());
            put_str(&mut out, l.location.as_deref());
            put_str(&mut out, l.release.as_deref());
            put_str(&mut out, l.declared.as_deref());
            put_str(&mut out, l.detected.as_deref());
            match l.report {
                None => out.push(0),
                Some(d) => {
                    out.push(1);
                    out.extend_from_slice(&d.bytes());
                }
            }
            put_retrieval(&mut out, l.location_page);
            put_retrieval(&mut out, l.licence_file);
        }
        out
    }

    /// The SHA-256 of [`Snapshot::encode`].
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::from_bytes(fstp_crypto::sha256(&self.encode()))
    }
}
