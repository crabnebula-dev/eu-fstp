//! Route changes of the pilot `fstp-control` and their audit log (ADR-009
//! "Pilot route feed", rows "Route changes on the host" and "Audit", lane
//! L15).
//!
//! Decided by Daniel on 2026-11-21: route changes are plain commands on
//! the host, and each one is logged. Root access to the host is the
//! guard. `fstp-control route add` and `route remove` apply at once
//! ([`RouteChanges::apply`]): the publisher checks the change against
//! the edge's rules, appends the audit record, and stores and serves the
//! new signed table.
//!
//! Interim, pending Daniel, the audit log `route-audit.log`:
//!
//! ```text
//! log    = record*
//! record = "FRL2" | body len u32 | body | chain 32
//! body   = at i64 (Unix seconds) | op u8 (1 add, 2 remove) | cell 16
//!          | version u64 | digest 32 | user len u8 | user
//! chain  = SHA-256(previous chain | body), the first over 32 zero bytes
//! ```
//!
//! `digest` is the SHA-256 of the operator request bytes. `user` is the OS
//! user who ran the command when it is known (`SUDO_USER`, else `USER`),
//! in the grammar of [`is_user_name`], and empty otherwise. The decoder
//! checks the chain and is fuzzed (`route_feed_decode`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_cp_proto::CellId;

use crate::ControlError;
use crate::route_feed::{OperatorRequest, encode_operator_request};
use crate::routes::RoutePublisher;

/// The audit log in the state directory.
pub const AUDIT_FILE: &str = "route-audit.log";

/// The magic of one audit record.
pub const AUDIT_MAGIC: [u8; 4] = *b"FRL2";

/// The longest user name a record holds.
pub const MAX_USER_LEN: usize = 32;

/// The longest audit log read at start.
pub const MAX_AUDIT_LOG: usize = 64 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether `name` is a POSIX-style user name: 1 to 32 bytes, a lowercase
/// letter or `_` first, then lowercase letters, digits, `_` and `-`.
#[must_use]
pub fn is_user_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_USER_LEN
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || *c == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// The digest of a change: the SHA-256 of its operator request bytes.
///
/// # Errors
///
/// As [`encode_operator_request`].
pub fn change_digest(request: &OperatorRequest) -> Result<[u8; 32], ControlError> {
    Ok(fstp_crypto::sha256(&encode_operator_request(request)?))
}

/// One audit record (module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// When the change was applied, in Unix seconds.
    pub at: i64,
    /// The operation: 1 add, 2 remove.
    pub op: u8,
    /// The cell of the route.
    pub cell: [u8; 16],
    /// The version that serves the change.
    pub version: u64,
    /// The change digest.
    pub digest: [u8; 32],
    /// The OS user who ran the command, empty when not known.
    pub user: String,
}

/// The body of `r`.
///
/// # Errors
///
/// [`ControlError::Request`] for a user name outside [`is_user_name`].
pub fn encode_audit_body(r: &AuditRecord) -> Result<Vec<u8>, ControlError> {
    if !r.user.is_empty() && !is_user_name(&r.user) {
        return Err(ControlError::Request("user"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&r.at.to_be_bytes());
    out.push(r.op);
    out.extend_from_slice(&r.cell);
    out.extend_from_slice(&r.version.to_be_bytes());
    out.extend_from_slice(&r.digest);
    out.push(u8::try_from(r.user.len()).map_err(|_| ControlError::Request("user"))?);
    out.extend_from_slice(r.user.as_bytes());
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
    let n = u32::try_from(body.len()).map_err(|_| ControlError::Request("user"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&head);
    Ok((out, head))
}

fn decode_body(body: &[u8]) -> Result<AuditRecord, ControlError> {
    let mut r = fstp_audit::codec::Reader::new(body);
    let e = |_| ControlError::Config("audit log");
    let at = i64::from_be_bytes(r.array::<8>().map_err(e)?);
    let [op] = r.array::<1>().map_err(e)?;
    if op != 1 && op != 2 {
        return Err(ControlError::Config("audit log"));
    }
    let cell = r.array::<16>().map_err(e)?;
    let version = r.be64().map_err(e)?;
    let digest = r.array::<32>().map_err(e)?;
    let [n] = r.array::<1>().map_err(e)?;
    let user = std::str::from_utf8(r.take(usize::from(n)).map_err(e)?)
        .map_err(|_| ControlError::Config("audit log"))?
        .to_owned();
    if !user.is_empty() && !is_user_name(&user) {
        return Err(ControlError::Config("audit log"));
    }
    r.finish().map_err(e)?;
    Ok(AuditRecord {
        at,
        op,
        cell,
        version,
        digest,
        user,
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

/// The route changes of the pilot `fstp-control` (module documentation).
pub struct RouteChanges {
    publisher: Arc<RoutePublisher>,
    audit: Mutex<AuditLog>,
}

impl std::fmt::Debug for RouteChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteChanges").finish_non_exhaustive()
    }
}

impl RouteChanges {
    /// Changes of `publisher`, logged in `audit`.
    pub fn new(publisher: Arc<RoutePublisher>, audit: AuditLog) -> RouteChanges {
        RouteChanges {
            publisher,
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

    /// Applies `request` at `now`, as `user` asked (empty when not
    /// known): checks it against the edge's rules, appends its audit
    /// record, and stores and serves the new table. Returns the version
    /// that serves it. A removal of a cell without routes changes nothing,
    /// logs nothing, and returns the current version.
    ///
    /// # Errors
    ///
    /// [`ControlError::Request`] for a change an edge would refuse, and
    /// the errors of the publisher and the audit log. Nothing changes then.
    pub fn apply(
        &self,
        request: &OperatorRequest,
        user: &str,
        now: i64,
    ) -> Result<u64, ControlError> {
        let user = if is_user_name(user) { user } else { "" };
        let digest = change_digest(request)?;
        let (op, cell) = match request {
            OperatorRequest::Add(route) => (1, route.route.app.cell),
            OperatorRequest::Remove(cell) => (2, *cell),
            OperatorRequest::List => return Err(ControlError::Request("operation")),
        };
        let mut record = AuditRecord {
            at: now,
            op,
            cell,
            version: 0,
            digest,
            user: user.to_owned(),
        };
        let mut audit = lock(&self.audit);
        let mut hook = |version: u64| {
            record.version = version;
            audit.append(&record)
        };
        match request {
            OperatorRequest::Add(route) => {
                self.publisher.publish_with((**route).clone(), &mut hook)
            }
            OperatorRequest::Remove(cell) => self
                .publisher
                .remove_cell_with(CellId(*cell), &mut hook)
                .map(|(_, v)| v),
            OperatorRequest::List => Err(ControlError::Request("operation")),
        }
    }
}
