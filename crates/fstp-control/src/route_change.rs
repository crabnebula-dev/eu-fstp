//! Route changes of the pilot `fstp-control` under an operator passkey
//! step-up, and their audit log (ADR-009 "Pilot route feed", rows
//! "Operator identity", "Proposal and approval", "Step-up per change"
//! and "Audit"; decided by Daniel on 2026-11-21, lane L15).
//!
//! `fstp-control route add` and `route remove` only propose a change
//! ([`RouteChanges::propose`]). The process checks it against the edge's
//! rules and keeps it for [`CHANGE_LIFETIME_SECS`]. A staff member logs in
//! with a pinned passkey ([`crate::operator::OperatorLogin`], I-77), draws
//! a step-up challenge bound to the change ([`RouteChanges::begin_approval`])
//! and answers it with a fresh assertion ([`RouteChanges::approve`]). One
//! step-up authorises exactly one change, once (I-78). Only then does the
//! publisher sign the new table. The audit record of the change is
//! appended before the table is stored.
//!
//! Interim, pending Daniel, the audit log `route-audit.log`:
//!
//! ```text
//! log    = record*
//! record = "FRL1" | body len u32 | body | chain 32
//! body   = at i64 | staff 16 | op u8 | cell 16 | version u64 | digest 32
//!          | session digest 32 | nonce 32
//!          | credential id | client data json | authenticator data | signature
//!          (each u16 length, then the bytes)
//! chain  = SHA-256(previous chain | body), the first over 32 zero bytes
//! ```
//!
//! The decoder checks the chain and is fuzzed (`route_feed_decode`). The
//! assertion in a record verifies again under the pinned staff key over
//! the challenge its digest, session digest and nonce give
//! ([`verify_evidence`]).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_cp_proto::{CellId, StaffRef};
use fstp_webauthn::{AssertionExpect, AssertionResponse, RelyingParty, StoredCredential};

use crate::ControlError;
use crate::operator::{
    OperatorLogin, OperatorRefusal, OperatorSession, StaffCredential, route_change_challenge,
    session_digest,
};
use crate::route_feed::{OperatorReply, OperatorRequest, OperatorStatus, encode_operator_request};
use crate::routes::RoutePublisher;

/// How long a proposed change waits for its step-up, in seconds.
/// Interim, pending Daniel.
pub const CHANGE_LIFETIME_SECS: i64 = 300;

/// The most changes that may wait at once.
pub const MAX_CHANGES: usize = 16;

/// The audit log in the state directory.
pub const AUDIT_FILE: &str = "route-audit.log";

/// The magic of one audit record.
pub const AUDIT_MAGIC: [u8; 4] = *b"FRL1";

/// The longest field of an assertion an audit record holds.
pub const MAX_EVIDENCE_FIELD: usize = 4096;

/// The longest audit log read at start.
pub const MAX_AUDIT_LOG: usize = 64 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The digest a change is approved under: the SHA-256 of its operator
/// request bytes, which name the operation, the cell, the host, both
/// endpoints and both pins.
///
/// # Errors
///
/// As [`encode_operator_request`].
pub fn change_digest(request: &OperatorRequest) -> Result<[u8; 32], ControlError> {
    Ok(fstp_crypto::sha256(&encode_operator_request(request)?))
}

/// A proposed change, as the operator page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingChange {
    /// The change id.
    pub id: [u8; 16],
    /// The request.
    pub request: OperatorRequest,
    /// Its digest.
    pub digest: [u8; 32],
}

struct Change {
    request: OperatorRequest,
    digest: [u8; 32],
    created: i64,
    waiter: Option<Sender<OperatorReply>>,
}

struct Bound {
    change: [u8; 16],
    session: [u8; 32],
    nonce: [u8; 32],
}

/// One audit record (module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// When the change was approved, in Unix seconds.
    pub at: i64,
    /// The approving staff member.
    pub staff: StaffRef,
    /// The operation: 1 add, 2 remove.
    pub op: u8,
    /// The cell.
    pub cell: [u8; 16],
    /// The version that serves the change.
    pub version: u64,
    /// The change digest.
    pub digest: [u8; 32],
    /// The SHA-256 of the session token.
    pub session_digest: [u8; 32],
    /// The nonce of the challenge.
    pub nonce: [u8; 32],
    /// The step-up assertion.
    pub assertion: AssertionResponse,
}

fn put_field(out: &mut Vec<u8>, b: &[u8]) -> Result<(), ControlError> {
    if b.len() > MAX_EVIDENCE_FIELD {
        return Err(ControlError::Request("evidence"));
    }
    let n = u16::try_from(b.len()).map_err(|_| ControlError::Request("evidence"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// The body of `r`.
///
/// # Errors
///
/// [`ControlError::Request`] for an assertion field above
/// [`MAX_EVIDENCE_FIELD`].
pub fn encode_audit_body(r: &AuditRecord) -> Result<Vec<u8>, ControlError> {
    let mut out = Vec::new();
    out.extend_from_slice(&r.at.to_be_bytes());
    out.extend_from_slice(&r.staff.0);
    out.push(r.op);
    out.extend_from_slice(&r.cell);
    out.extend_from_slice(&r.version.to_be_bytes());
    out.extend_from_slice(&r.digest);
    out.extend_from_slice(&r.session_digest);
    out.extend_from_slice(&r.nonce);
    put_field(&mut out, &r.assertion.credential_id)?;
    put_field(&mut out, &r.assertion.client_data_json)?;
    put_field(&mut out, &r.assertion.authenticator_data)?;
    put_field(&mut out, &r.assertion.signature)?;
    Ok(out)
}

fn chain(previous: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut m = previous.to_vec();
    m.extend_from_slice(body);
    fstp_crypto::sha256(&m)
}

/// The bytes of one record after the chain head `previous`, and the new
/// head.
///
/// # Errors
///
/// As [`encode_audit_body`].
pub fn encode_audit_record(
    previous: &[u8; 32],
    r: &AuditRecord,
) -> Result<(Vec<u8>, [u8; 32]), ControlError> {
    let body = encode_audit_body(r)?;
    let head = chain(previous, &body);
    let mut out = AUDIT_MAGIC.to_vec();
    let n = u32::try_from(body.len()).map_err(|_| ControlError::Request("evidence"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&head);
    Ok((out, head))
}

fn decode_body(body: &[u8]) -> Result<AuditRecord, ControlError> {
    let mut r = fstp_audit::codec::Reader::new(body);
    let e = |_| ControlError::Config("audit log");
    let at = i64::from_be_bytes(r.array::<8>().map_err(e)?);
    let staff = StaffRef(r.array::<16>().map_err(e)?);
    let op = r.array::<1>().map_err(e)?[0];
    if op != 1 && op != 2 {
        return Err(ControlError::Config("audit log"));
    }
    let cell = r.array::<16>().map_err(e)?;
    let version = r.be64().map_err(e)?;
    let digest = r.array::<32>().map_err(e)?;
    let session_digest = r.array::<32>().map_err(e)?;
    let nonce = r.array::<32>().map_err(e)?;
    let mut field = || -> Result<Vec<u8>, ControlError> {
        let n = usize::from(r.be16().map_err(e)?);
        if n > MAX_EVIDENCE_FIELD {
            return Err(ControlError::Config("audit log"));
        }
        Ok(r.take(n).map_err(e)?.to_vec())
    };
    let assertion = AssertionResponse {
        credential_id: field()?,
        client_data_json: field()?,
        authenticator_data: field()?,
        signature: field()?,
    };
    r.finish().map_err(e)?;
    Ok(AuditRecord {
        at,
        staff,
        op,
        cell,
        version,
        digest,
        session_digest,
        nonce,
        assertion,
    })
}

/// Decodes a whole audit log and checks its chain. Returns the records
/// and the chain head. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Config`] for a cut record, a wrong magic, a body that
/// does not decode, versions that do not rise, or a broken chain.
pub fn decode_audit_log(bytes: &[u8]) -> Result<(Vec<AuditRecord>, [u8; 32]), ControlError> {
    if bytes.len() > MAX_AUDIT_LOG {
        return Err(ControlError::Config("audit log"));
    }
    let mut r = fstp_audit::codec::Reader::new(bytes);
    let e = |_| ControlError::Config("audit log");
    let mut head = [0u8; 32];
    let mut out: Vec<AuditRecord> = Vec::new();
    while !r.is_empty() {
        if r.array::<4>().map_err(e)? != AUDIT_MAGIC {
            return Err(ControlError::Config("audit log"));
        }
        let n =
            usize::try_from(r.be32().map_err(e)?).map_err(|_| ControlError::Config("audit log"))?;
        let body = r.take(n).map_err(e)?;
        let stored = r.array::<32>().map_err(e)?;
        let next = chain(&head, body);
        if stored != next {
            return Err(ControlError::Config("audit chain"));
        }
        let record = decode_body(body)?;
        if out.last().is_some_and(|p| p.version >= record.version) {
            return Err(ControlError::Config("audit log"));
        }
        out.push(record);
        head = next;
    }
    Ok((out, head))
}

/// Whether the assertion of `r` verifies under the pinned credential of
/// its staff member, over the challenge its digest, session digest and
/// nonce give, with user verification.
#[must_use]
pub fn verify_evidence(r: &AuditRecord, staff: &[StaffCredential], rp: &RelyingParty) -> bool {
    let Some(cred) = staff
        .iter()
        .find(|c| c.staff == r.staff && c.credential_id == r.assertion.credential_id)
    else {
        return false;
    };
    let stored = StoredCredential {
        id: cred.credential_id.clone(),
        key: cred.key.clone(),
        sign_count: 0,
    };
    let expect = AssertionExpect {
        rp: rp.clone(),
        challenge: route_change_challenge(&r.session_digest, &r.digest, &r.nonce),
        user_verification: true,
    };
    fstp_webauthn::verify_assertion(&r.assertion, &stored, &expect).is_ok()
}

/// The append-only audit log of one process.
pub struct AuditLog {
    path: PathBuf,
    head: [u8; 32],
    last_version: u64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens the log at `path`, an empty one when the file is missing, and
    /// checks its whole chain.
    ///
    /// # Errors
    ///
    /// The errors of [`decode_audit_log`], and [`ControlError::Io`] for a
    /// file that cannot be read.
    pub fn open(path: &Path) -> Result<AuditLog, ControlError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(ControlError::Io(e.kind())),
        };
        let (records, head) = decode_audit_log(&bytes)?;
        Ok(AuditLog {
            path: path.to_path_buf(),
            head,
            last_version: records.last().map_or(0, |r| r.version),
        })
    }

    /// Appends `r` and syncs the file before it returns.
    ///
    /// # Errors
    ///
    /// [`ControlError::Io`] when the write or the sync fails, and the
    /// errors of [`encode_audit_record`].
    pub fn append(&mut self, r: &AuditRecord) -> Result<(), ControlError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        if r.version <= self.last_version {
            return Err(ControlError::Job("audit version"));
        }
        let (bytes, head) = encode_audit_record(&self.head, r)?;
        let io = |e: std::io::Error| ControlError::Io(e.kind());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(io)?;
        f.write_all(&bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
        self.head = head;
        self.last_version = r.version;
        Ok(())
    }
}

struct Inner {
    changes: BTreeMap<[u8; 16], Change>,
    bound: BTreeMap<[u8; 32], Bound>,
}

/// The route changes of the pilot `fstp-control` (module documentation).
pub struct RouteChanges {
    publisher: Arc<RoutePublisher>,
    login: Mutex<OperatorLogin>,
    inner: Mutex<Inner>,
    audit: Mutex<AuditLog>,
}

impl std::fmt::Debug for RouteChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteChanges").finish_non_exhaustive()
    }
}

fn fresh(at: i64, now: i64) -> bool {
    now >= at && now.saturating_sub(at) <= CHANGE_LIFETIME_SECS
}

fn refuse(r: OperatorRefusal) -> ControlError {
    ControlError::Operator(r)
}

impl RouteChanges {
    /// Changes of `publisher`, approved through `login`, audited in
    /// `audit`.
    pub fn new(
        publisher: Arc<RoutePublisher>,
        login: OperatorLogin,
        audit: AuditLog,
    ) -> RouteChanges {
        RouteChanges {
            publisher,
            login: Mutex::new(login),
            inner: Mutex::new(Inner {
                changes: BTreeMap::new(),
                bound: BTreeMap::new(),
            }),
            audit: Mutex::new(audit),
        }
    }

    /// The publisher.
    pub fn publisher(&self) -> &RoutePublisher {
        &self.publisher
    }

    /// The publisher, shared, for the feed listener.
    pub fn publisher_arc(&self) -> Arc<RoutePublisher> {
        Arc::clone(&self.publisher)
    }

    /// The operator login, for the login ceremony of the operator page.
    pub fn login(&self) -> MutexGuard<'_, OperatorLogin> {
        lock(&self.login)
    }

    fn prune(inner: &mut Inner, now: i64, version: u64) {
        let expired: Vec<[u8; 16]> = inner
            .changes
            .iter()
            .filter(|(_, c)| !fresh(c.created, now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(c) = inner.changes.remove(&id)
                && let Some(w) = c.waiter
            {
                let _ = w.send(OperatorReply {
                    status: OperatorStatus::Expired,
                    version,
                });
            }
        }
        inner
            .bound
            .retain(|_, b| inner.changes.contains_key(&b.change));
    }

    /// Proposes `request` at `now`. A change an edge would refuse is
    /// refused here, and nothing waits. The receiver gets the outcome:
    /// stored with its version once approved, or expired.
    ///
    /// # Errors
    ///
    /// [`ControlError::Request`] for a change an edge would refuse,
    /// [`ControlError::Operator`] with [`OperatorRefusal::Capacity`] when
    /// [`MAX_CHANGES`] wait, and [`OperatorRefusal::Random`].
    pub fn propose(
        &self,
        request: OperatorRequest,
        now: i64,
    ) -> Result<([u8; 16], Receiver<OperatorReply>), ControlError> {
        if let OperatorRequest::Add(route) = &request {
            self.publisher.check_publish(route)?;
        }
        let digest = change_digest(&request)?;
        let mut inner = lock(&self.inner);
        Self::prune(&mut inner, now, self.publisher.version());
        if inner.changes.len() >= MAX_CHANGES {
            return Err(refuse(OperatorRefusal::Capacity));
        }
        let id: [u8; 16] =
            fstp_crypto::random_array().map_err(|_| refuse(OperatorRefusal::Random))?;
        let (tx, rx) = channel();
        inner.changes.insert(
            id,
            Change {
                request,
                digest,
                created: now,
                waiter: Some(tx),
            },
        );
        Ok((id, rx))
    }

    /// The changes waiting at `now`, oldest id order.
    pub fn pending(&self, now: i64) -> Vec<PendingChange> {
        let mut inner = lock(&self.inner);
        Self::prune(&mut inner, now, self.publisher.version());
        inner
            .changes
            .iter()
            .map(|(id, c)| PendingChange {
                id: *id,
                request: c.request.clone(),
                digest: c.digest,
            })
            .collect()
    }

    /// Draws the step-up challenge of change `id` in `session`, bound to
    /// its digest.
    ///
    /// # Errors
    ///
    /// [`OperatorRefusal::Challenge`] for a change that does not wait,
    /// and the refusals of [`OperatorLogin::begin_route_step_up`].
    pub fn begin_approval(
        &self,
        session: OperatorSession,
        id: [u8; 16],
        now: i64,
    ) -> Result<[u8; 32], ControlError> {
        let mut inner = lock(&self.inner);
        Self::prune(&mut inner, now, self.publisher.version());
        let digest = inner
            .changes
            .get(&id)
            .map(|c| c.digest)
            .ok_or(refuse(OperatorRefusal::Challenge))?;
        let (challenge, nonce) = self.login().begin_route_step_up(session, &digest, now)?;
        inner.bound.insert(
            challenge,
            Bound {
                change: id,
                session: session.0,
                nonce,
            },
        );
        Ok(challenge)
    }

    /// Approves change `id` in `session` with `assertion` over
    /// `challenge`: verifies the step-up, consumes it, appends the audit
    /// record and stores and serves the new table. Returns its version.
    ///
    /// # Errors
    ///
    /// [`OperatorRefusal::Challenge`] for a challenge that was not drawn
    /// for this change and session or was used, the refusals of the
    /// step-up and of [`OperatorLogin::authorise_route_change`], and the
    /// errors of the publisher and the audit log. A refused approval
    /// leaves the change waiting.
    pub fn approve(
        &self,
        session: OperatorSession,
        id: [u8; 16],
        challenge: [u8; 32],
        assertion: &AssertionResponse,
        now: i64,
    ) -> Result<u64, ControlError> {
        let mut inner = lock(&self.inner);
        Self::prune(&mut inner, now, self.publisher.version());
        let bound = inner
            .bound
            .remove(&challenge)
            .filter(|b| b.change == id && b.session == session.0)
            .ok_or(refuse(OperatorRefusal::Challenge))?;
        let (request, digest) = inner
            .changes
            .get(&id)
            .map(|c| (c.request.clone(), c.digest))
            .ok_or(refuse(OperatorRefusal::Challenge))?;
        let staff = {
            let mut login = self.login();
            login.finish_step_up(session, challenge, assertion, now)?;
            login.authorise_route_change(session, now)?
        };
        let (op, cell) = match &request {
            OperatorRequest::Add(route) => (1, route.route.app.cell),
            OperatorRequest::Remove(cell) => (2, *cell),
            OperatorRequest::List => return Err(ControlError::Request("operation")),
        };
        let mut record = AuditRecord {
            at: now,
            staff,
            op,
            cell,
            version: 0,
            digest,
            session_digest: session_digest(session),
            nonce: bound.nonce,
            assertion: assertion.clone(),
        };
        let mut audit = lock(&self.audit);
        let mut hook = |version: u64| {
            record.version = version;
            audit.append(&record)
        };
        let version = match &request {
            OperatorRequest::Add(route) => {
                self.publisher.publish_with((**route).clone(), &mut hook)?
            }
            OperatorRequest::Remove(cell) => {
                self.publisher.remove_cell_with(CellId(*cell), &mut hook)?.1
            }
            OperatorRequest::List => return Err(ControlError::Request("operation")),
        };
        drop(audit);
        if let Some(c) = inner.changes.remove(&id)
            && let Some(w) = c.waiter
        {
            let _ = w.send(OperatorReply {
                status: OperatorStatus::Stored,
                version,
            });
        }
        Ok(version)
    }
}
