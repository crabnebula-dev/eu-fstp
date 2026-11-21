//! The pilot `fstp-control`: the signed route feed and nothing else
//! (ADR-009 "Pilot route feed", lane L15 `prod/route-feed`).
//!
//! Daniel decided on 2026-11-21 that the pilot edge changes routes
//! without a restart, and not by SIGHUP or file watching. A minimal
//! `fstp-control` serves the signed route feed, and the edge polls it.
//! This module holds what that process needs:
//!
//! - the configuration ([`crate::config::decode_feed_config`]);
//! - the sealed feed signing key [`KEY_FILE`], whose seal key `fstp-keyd`
//!   wraps under a ControlPlane root ([`create_feed_key`],
//!   [`open_feed_key`]);
//! - the table state [`STATE_FILE`], the current signed table, which
//!   [`crate::routes::RoutePublisher::resume`] verifies at start;
//! - the operator socket and its bytes ([`OperatorRequest`],
//!   [`OperatorReply`]), through which `fstp-control route add` and
//!   `fstp-control route remove` reach the running process;
//! - the commands [`init`], [`run`], [`route_add`] and [`route_remove`].
//!
//! Interim, pending Daniel, the key file:
//!
//! ```text
//! file   = magic (22) || be64(epoch) || be16(len) || custody handle
//!          || be16(len) || wrapped S(e) || nonce (12) || sealed (80)
//! magic  = "fstp-route-feed-key-v1"
//! wrap   = custody wrap of S(e) under the ControlPlane root of `epoch`,
//!          AAD = magic || "controlplane" || be64(epoch)
//! sealed = AES-256-GCM under S(e) of the 64-byte composite private key,
//!          with the same AAD
//! ```
//!
//! Interim, pending Daniel, the operator bytes, one request per
//! connection:
//!
//! ```text
//! request = "FRO1" | op u8 | body
//!           op 1 (add):    body = one route of the feed (fstp_edge::decode_route)
//!           op 2 (remove): body = cell id (16)
//! reply   = "FRA1" | status u8 (0 stored, 1 refused route, 2 failed) | version u64
//! ```
//!
//! Every decoder here is fuzzed (`route_feed_decode`). No error carries
//! input bytes (R-NF-02).

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fstp_crypto::composite::CompositeSigningKey;
use fstp_custody::{
    Aad, BackendId, Chain, Custody, CustodyHandle, Epoch, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_edge::PinnedRoute;
use fstp_obs::{LogEvent, Method};
use fstp_rt::signal::Signals as _;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime as _, Shutdown};

use crate::ControlError;
use crate::config::{FeedConfig, decode_feed_config, read_credential};
use crate::routes::{RoutePublisher, serve_route_feed, sign_table, write_atomic};

/// The magic that opens a feed key file and labels its AAD.
pub const KEY_MAGIC: &[u8; 22] = b"fstp-route-feed-key-v1";

/// The sealed feed signing key in the credentials directory.
pub const KEY_FILE: &str = "route-feed.key";

/// The public key `init` writes to its output directory, one hex line.
/// The edge reads the same name from its credentials directory.
pub const PUBLIC_KEY_FILE: &str = "route-feed.pub";

/// The current signed table in the state directory.
pub const STATE_FILE: &str = "route-table.signed";

/// The epoch of the ControlPlane root that wraps the seal key.
pub const ROOT_EPOCH: u64 = 1;

/// The chain of that root.
pub const ROOT_CHAIN: Chain = Chain::ControlPlane;

/// The longest custody handle or wrapped seal key a key file holds.
pub const MAX_KEY_FIELD_LEN: usize = 4096;

/// The length of the sealed composite private key and its tag.
pub const SEALED_KEY_LEN: usize =
    fstp_crypto::composite::PRIVATE_KEY_LEN + fstp_crypto::aead::TAG_LEN;

/// The magic of an operator request.
pub const REQUEST_MAGIC: [u8; 4] = *b"FRO1";

/// The magic of an operator reply.
pub const REPLY_MAGIC: [u8; 4] = *b"FRA1";

/// The length of an operator reply.
pub const REPLY_LEN: usize = 13;

/// The longest operator request.
pub const MAX_REQUEST_LEN: usize = 2048;

/// How long one operator exchange may take.
pub const OPERATOR_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a drain may take after SIGTERM.
pub const DRAIN: Duration = Duration::from_secs(30);

/// The route template the operator socket logs under.
const OPERATOR_ROUTE: &str = "/cp/routes";

fn bad(rule: &'static str) -> ControlError {
    ControlError::Config(rule)
}

// ---------------------------------------------------------------- key file

/// A decoded feed key file: references and sealed bytes only (I-80).
#[derive(Clone, PartialEq, Eq)]
pub struct FeedKeyFile {
    /// The epoch of the ControlPlane root.
    pub epoch: u64,
    /// The custody handle of that root.
    pub handle: Vec<u8>,
    /// `S(e)`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The AES-256-GCM nonce of the sealed key.
    pub nonce: [u8; fstp_crypto::aead::NONCE_LEN],
    /// The sealed composite private key.
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for FeedKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedKeyFile")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// The AAD of both the custody wrap and the seal.
#[must_use]
pub fn key_aad(epoch: u64) -> Vec<u8> {
    [
        &KEY_MAGIC[..],
        ROOT_CHAIN.name().as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), ControlError> {
    if field.is_empty() || field.len() > MAX_KEY_FIELD_LEN {
        return Err(bad("key file field"));
    }
    let len = u16::try_from(field.len()).map_err(|_| bad("key file field"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Encodes a feed key file.
///
/// # Errors
///
/// [`ControlError::Config`] for an empty or overlong field, or a sealed
/// key of another length.
pub fn encode_feed_key_file(f: &FeedKeyFile) -> Result<Vec<u8>, ControlError> {
    if f.sealed.len() != SEALED_KEY_LEN {
        return Err(bad("sealed key length"));
    }
    let mut out = KEY_MAGIC.to_vec();
    out.extend_from_slice(&f.epoch.to_be_bytes());
    put16(&mut out, &f.handle)?;
    put16(&mut out, &f.wrapped)?;
    out.extend_from_slice(&f.nonce);
    out.extend_from_slice(&f.sealed);
    Ok(out)
}

/// Decodes a feed key file. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Config`] for a wrong magic, a cut or overlong field,
/// or trailing bytes.
pub fn decode_feed_key_file(bytes: &[u8]) -> Result<FeedKeyFile, ControlError> {
    let mut r = fstp_audit::codec::Reader::new(bytes);
    let e = |_| bad("key file");
    if r.take(KEY_MAGIC.len()).map_err(e)? != KEY_MAGIC {
        return Err(bad("key file magic"));
    }
    let epoch = r.be64().map_err(e)?;
    let field = |r: &mut fstp_audit::codec::Reader<'_>| -> Result<Vec<u8>, ControlError> {
        let len = usize::from(r.be16().map_err(e)?);
        if len == 0 || len > MAX_KEY_FIELD_LEN {
            return Err(bad("key file field"));
        }
        Ok(r.take(len).map_err(e)?.to_vec())
    };
    let handle = field(&mut r)?;
    let wrapped = field(&mut r)?;
    let nonce = r.array::<{ fstp_crypto::aead::NONCE_LEN }>().map_err(e)?;
    let sealed = r.take(SEALED_KEY_LEN).map_err(e)?.to_vec();
    r.finish().map_err(e)?;
    Ok(FeedKeyFile {
        epoch,
        handle,
        wrapped,
        nonce,
        sealed,
    })
}

/// The custody root of `f`: a ControlPlane root of no cell.
#[must_use]
pub fn root_of(f: &FeedKeyFile) -> RootRef {
    RootRef {
        backend: BackendId::Keyd,
        cell: None,
        chain: ROOT_CHAIN,
        epoch: Epoch(f.epoch),
        handle: CustodyHandle(f.handle.clone()),
    }
}

/// Seals `key` under a fresh `S(e)`, has `custody` create the
/// ControlPlane root and wrap `S(e)` under it, and returns the key file
/// (ADR-009 "Pilot route feed", row "Feed signing key").
///
/// # Errors
///
/// [`ControlError::Custody`] when custody refuses, and
/// [`ControlError::Job`] when the seal fails.
pub async fn create_feed_key<C: Custody>(
    custody: &C,
    key: &CompositeSigningKey,
) -> Result<Vec<u8>, ControlError> {
    let root = custody
        .create_root(RootLabel {
            cell: None,
            chain: ROOT_CHAIN,
            epoch: Epoch(ROOT_EPOCH),
        })
        .await
        .map_err(ControlError::Custody)?;
    let seal = SealKey::generate().map_err(ControlError::Custody)?;
    let wrapped = custody
        .wrap(&root, &seal, &Aad(key_aad(ROOT_EPOCH)))
        .await
        .map_err(ControlError::Custody)?;
    let aead = fstp_crypto::aead::Key::from_bytes(seal.expose())
        .map_err(|_| ControlError::Job("seal key"))?;
    let secret = key.to_bytes().map_err(|_| ControlError::Job("feed key"))?;
    let sealed = fstp_crypto::aead::seal(&aead, &key_aad(ROOT_EPOCH), &secret[..])
        .map_err(|_| ControlError::Job("seal"))?;
    encode_feed_key_file(&FeedKeyFile {
        epoch: ROOT_EPOCH,
        handle: root.handle.0,
        wrapped: wrapped.0,
        nonce: sealed.nonce,
        sealed: sealed.body,
    })
}

/// Opens the feed signing key of the key file `bytes` through `custody`.
///
/// # Errors
///
/// [`ControlError::Config`] for a file that does not decode or open, and
/// [`ControlError::Custody`] when custody does not unwrap `S(e)`.
pub async fn open_feed_key<C: Custody>(
    custody: &C,
    bytes: &[u8],
) -> Result<CompositeSigningKey, ControlError> {
    let f = decode_feed_key_file(bytes)?;
    let seal = custody
        .unwrap(
            &root_of(&f),
            &WrappedSealKey(f.wrapped.clone()),
            &Aad(key_aad(f.epoch)),
        )
        .await
        .map_err(ControlError::Custody)?;
    let aead = fstp_crypto::aead::Key::from_bytes(seal.expose()).map_err(|_| bad("key file"))?;
    let secret = fstp_crypto::aead::open(&aead, &f.nonce, &key_aad(f.epoch), &f.sealed)
        .map_err(|_| bad("key file"))?;
    CompositeSigningKey::from_bytes(&secret).map_err(|_| bad("key file"))
}

// --------------------------------------------------------- operator bytes

/// One operator request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorRequest {
    /// Publish this route for its cell, replacing an older one.
    Add(Box<PinnedRoute>),
    /// Remove every route of this cell.
    Remove([u8; 16]),
}

/// Encodes an operator request.
///
/// # Errors
///
/// [`ControlError::Request`] for a route that does not encode.
pub fn encode_operator_request(r: &OperatorRequest) -> Result<Vec<u8>, ControlError> {
    let mut out = REQUEST_MAGIC.to_vec();
    match r {
        OperatorRequest::Add(route) => {
            out.push(1);
            fstp_edge::encode_route(&mut out, route).map_err(|_| ControlError::Request("I-19"))?;
        }
        OperatorRequest::Remove(cell) => {
            out.push(2);
            out.extend_from_slice(cell);
        }
    }
    Ok(out)
}

/// Decodes an operator request. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] naming the rule broken.
pub fn decode_operator_request(bytes: &[u8]) -> Result<OperatorRequest, ControlError> {
    if bytes.len() > MAX_REQUEST_LEN {
        return Err(ControlError::Request("length"));
    }
    let (magic, rest) = bytes
        .split_at_checked(4)
        .ok_or(ControlError::Request("length"))?;
    if magic != REQUEST_MAGIC {
        return Err(ControlError::Request("magic"));
    }
    match rest.split_first() {
        Some((1, body)) => fstp_edge::decode_route(body)
            .map(|r| OperatorRequest::Add(Box::new(r)))
            .map_err(|_| ControlError::Request("route")),
        Some((2, body)) => <[u8; 16]>::try_from(body)
            .map(OperatorRequest::Remove)
            .map_err(|_| ControlError::Request("cell")),
        _ => Err(ControlError::Request("operation")),
    }
}

/// What the running process did with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorStatus {
    /// The new table is stored and served.
    Stored,
    /// The route was refused: an edge would refuse the table (I-19).
    Refused,
    /// Anything else failed. Nothing changed.
    Failed,
}

/// The reply to one operator request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorReply {
    /// The outcome.
    pub status: OperatorStatus,
    /// The version served after the request.
    pub version: u64,
}

/// Encodes an operator reply.
#[must_use]
pub fn encode_operator_reply(r: &OperatorReply) -> [u8; REPLY_LEN] {
    let mut out = [0u8; REPLY_LEN];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&REPLY_MAGIC);
    let (status, version) = rest.split_at_mut(1);
    status.copy_from_slice(&[match r.status {
        OperatorStatus::Stored => 0,
        OperatorStatus::Refused => 1,
        OperatorStatus::Failed => 2,
    }]);
    version.copy_from_slice(&r.version.to_be_bytes());
    out
}

/// Decodes an operator reply. Fuzzed (`route_feed_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] for anything but [`REPLY_LEN`] bytes with the
/// magic and a known status.
pub fn decode_operator_reply(bytes: &[u8]) -> Result<OperatorReply, ControlError> {
    let bytes: &[u8; REPLY_LEN] = bytes
        .try_into()
        .map_err(|_| ControlError::Request("reply length"))?;
    let (magic, rest) = bytes.split_at(4);
    if magic != REPLY_MAGIC {
        return Err(ControlError::Request("reply magic"));
    }
    let (status, version) = rest.split_at(1);
    let status = match status {
        [0] => OperatorStatus::Stored,
        [1] => OperatorStatus::Refused,
        [2] => OperatorStatus::Failed,
        _ => return Err(ControlError::Request("reply status")),
    };
    let version: [u8; 8] = version
        .try_into()
        .map_err(|_| ControlError::Request("reply length"))?;
    Ok(OperatorReply {
        status,
        version: u64::from_be_bytes(version),
    })
}

/// Answers one operator request on `publisher`, and logs it as a typed
/// event with no host and no cell (R-NF-02).
pub fn answer_operator(publisher: &RoutePublisher, request: &[u8]) -> OperatorReply {
    let started = Instant::now();
    let outcome = decode_operator_request(request).and_then(|r| match r {
        OperatorRequest::Add(route) => publisher.publish(*route),
        OperatorRequest::Remove(cell) => publisher
            .remove_cell(fstp_cp_proto::CellId(cell))
            .map(|(_, v)| v),
    });
    let (status, rule) = match outcome {
        Ok(_) => (OperatorStatus::Stored, None),
        Err(ControlError::Request(rule)) => (OperatorStatus::Refused, Some(rule)),
        Err(_) => (OperatorStatus::Failed, Some("R-SW-02")),
    };
    let event = match rule {
        None => LogEvent::Request {
            method: Method::Other,
            route: OPERATOR_ROUTE,
            status: 200,
            elapsed: started.elapsed(),
        },
        Some(rule) => LogEvent::Refused {
            method: Method::Other,
            route: OPERATOR_ROUTE,
            // A decoder rule such as "magic" is no SPEC rule: log it as
            // I-19, which every route refusal serves.
            rule: if rule.contains('-') { rule } else { "I-19" },
            status: if status == OperatorStatus::Refused {
                422
            } else {
                500
            },
        },
    };
    let _ = fstp_obs::log_to_stderr(&event);
    OperatorReply {
        status,
        version: publisher.version(),
    }
}

/// Binds the operator socket at `path` with mode 0600 before any client
/// can reach it: it binds inside a fresh private directory beside the
/// path, restricts the socket there, and renames it into place. A stale
/// socket at the path is replaced.
///
/// # Errors
///
/// [`ControlError::Io`] when a step fails.
pub fn bind_operator_socket(path: &Path) -> Result<UnixListener, ControlError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let io = |e: std::io::Error| ControlError::Io(e.kind());
    let parent = path
        .parent()
        .ok_or(ControlError::Io(std::io::ErrorKind::InvalidInput))?;
    let dir = parent.join(format!(".fstp-control-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(io)?;
    let tmp = dir.join("s");
    let bound = (|| {
        let listener = UnixListener::bind(&tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)?;
        Ok::<_, std::io::Error>(listener)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    bound.map_err(io)
}

fn exchange(stream: &mut UnixStream, publisher: &RoutePublisher) -> std::io::Result<()> {
    let started = Instant::now();
    stream.set_read_timeout(Some(OPERATOR_TIMEOUT))?;
    stream.set_write_timeout(Some(OPERATOR_TIMEOUT))?;
    let mut request = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        if started.elapsed() > OPERATOR_TIMEOUT {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(buf.get(..n).unwrap_or_default());
        if request.len() > MAX_REQUEST_LEN {
            break;
        }
    }
    let reply = answer_operator(publisher, &request);
    stream.write_all(&encode_operator_reply(&reply))?;
    stream.flush()
}

/// Serves operator requests on `listener`, one per connection, one at a
/// time, until the listener fails. A connection that breaks the
/// protocol gets a refusal, and a slow one is dropped.
pub fn serve_operator(listener: &UnixListener, publisher: &RoutePublisher) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let _ = exchange(&mut stream, publisher);
    }
}

/// Sends `request` to the operator socket at `socket` and returns the
/// reply.
///
/// # Errors
///
/// [`ControlError::Io`] when the exchange fails, and the errors of
/// [`encode_operator_request`] and [`decode_operator_reply`].
pub fn operator_request(
    socket: &Path,
    request: &OperatorRequest,
) -> Result<OperatorReply, ControlError> {
    let io = |e: std::io::Error| ControlError::Io(e.kind());
    let bytes = encode_operator_request(request)?;
    let mut stream = UnixStream::connect(socket).map_err(io)?;
    stream
        .set_read_timeout(Some(OPERATOR_TIMEOUT))
        .map_err(io)?;
    stream
        .set_write_timeout(Some(OPERATOR_TIMEOUT))
        .map_err(io)?;
    stream.write_all(&bytes).map_err(io)?;
    stream.shutdown(std::net::Shutdown::Write).map_err(io)?;
    let mut reply = Vec::new();
    stream
        .take(
            u64::try_from(REPLY_LEN)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut reply)
        .map_err(io)?;
    decode_operator_reply(&reply)
}

// ---------------------------------------------------------------- commands

/// The environment variable that names the route feed configuration.
pub const CONFIG_ENV: &str = crate::service::CONFIG_ENV;

/// Reads and decodes the configuration that [`CONFIG_ENV`] names.
///
/// # Errors
///
/// As [`decode_feed_config`] and [`crate::config::read_config_file`].
pub fn load_config() -> Result<FeedConfig, ControlError> {
    decode_feed_config(&crate::config::read_config_file(CONFIG_ENV)?)
}

fn runtime() -> Result<TokioRuntime, ControlError> {
    TokioRuntime::new_multi_thread(2).map_err(|e| ControlError::Io(e.kind()))
}

fn hex_line(b: &[u8]) -> String {
    let mut s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    s.push('\n');
    s
}

/// `fstp-control init-route-feed <out dir>` (ADR-009 "Pilot route feed",
/// rows "Feed signing key" and "Table state"). When the key file is
/// missing it generates the feed signing key and writes the key file
/// through `fstp-keyd`. When the state file is missing it writes the
/// first, empty table at a version from [`crate::routes::next_version`].
/// It writes the public key to `<out>/route-feed.pub` in both cases.
///
/// # Errors
///
/// [`ControlError::Config`] when both files exist already, and the
/// errors of each step.
pub fn init(out: &Path) -> Result<(), ControlError> {
    let cfg = load_config()?;
    let key_path = Path::new(&cfg.credentials_dir).join(KEY_FILE);
    let state_path = Path::new(&cfg.state_dir).join(STATE_FILE);
    let have_key = std::fs::symlink_metadata(&key_path).is_ok();
    let have_state = std::fs::symlink_metadata(&state_path).is_ok();
    if have_key && have_state {
        return Err(bad("the route feed is initialised"));
    }
    let custody = fstp_custody::KeydCustody::new(Path::new(&cfg.keyd_socket))
        .map_err(|_| bad("keyd_socket"))?;
    let rt = runtime()?;
    let key = rt.block_on(async {
        if have_key {
            let bytes = read_credential(&cfg.credentials_dir, KEY_FILE)?;
            open_feed_key(&custody, &bytes).await
        } else {
            let key =
                fstp_crypto::composite::generate().map_err(|_| ControlError::Job("feed key"))?;
            let file = create_feed_key(&custody, &key).await?;
            write_atomic(&key_path, &file)?;
            Ok(key)
        }
    })?;
    if !have_state {
        let version = crate::routes::next_version(0)?;
        write_atomic(&state_path, &sign_table(&key, version, &[])?)?;
    }
    write_atomic(
        &out.join(PUBLIC_KEY_FILE),
        hex_line(&key.public_key().to_bytes()).as_bytes(),
    )
}

/// What [`run`] loads at start.
struct Started {
    publisher: Arc<RoutePublisher>,
    tls: fstp_tls::ServerConfig,
    feed_listen: SocketAddr,
    operator: PathBuf,
}

fn start(cfg: &FeedConfig, rt: &TokioRuntime) -> Result<Started, ControlError> {
    let dir = &cfg.credentials_dir;
    let ca = read_credential(dir, "control-ca.pem")?;
    let cert = read_credential(dir, "control.pem")?;
    let key_pem = read_credential(dir, "control-key.pem")?;
    let tls = fstp_tls::ServerConfig::mutual(&cert, &key_pem, &ca)
        .map_err(|_| ControlError::Tls("route feed listener"))?;
    let key_file = read_credential(dir, KEY_FILE)?;
    let state_path = Path::new(&cfg.state_dir).join(STATE_FILE);
    let state = std::fs::read(&state_path).map_err(|_| bad("route table state"))?;
    let custody = fstp_custody::KeydCustody::new(Path::new(&cfg.keyd_socket))
        .map_err(|_| bad("keyd_socket"))?;
    let signer = rt.block_on(open_feed_key(&custody, &key_file))?;
    let publisher = RoutePublisher::resume(signer, &cfg.edges, &state, state_path)?;
    Ok(Started {
        publisher: Arc::new(publisher),
        tls,
        feed_listen: cfg.feed_listen,
        operator: PathBuf::from(&cfg.operator_socket),
    })
}

/// `fstp-control route-feed`: runs the pilot route feed named by
/// [`CONFIG_ENV`] until SIGTERM or SIGINT (ADR-009 "Pilot route feed").
/// It opens its signing key through `fstp-keyd`, resumes its table from
/// the state file, serves the feed to the configured edges over mutual
/// TLS, and takes operator requests on its socket. Nothing else of
/// `fstp-control` runs.
///
/// # Errors
///
/// [`ControlError::Config`] for a refused configuration, key file or
/// state, [`ControlError::Custody`] when custody does not unwrap,
/// [`ControlError::Tls`] for TLS files that do not build, and
/// [`ControlError::Io`] or [`ControlError::Signal`] when a listener or
/// the signal handler does not start.
pub fn run() -> Result<(), ControlError> {
    let cfg = load_config()?;
    let rt = runtime()?;
    let mut term = rt.listen_termination().map_err(|_| ControlError::Signal)?;
    let started = start(&cfg, &rt)?;
    let operator = bind_operator_socket(&started.operator)?;
    let op_publisher = Arc::clone(&started.publisher);
    drop(std::thread::spawn(move || {
        serve_operator(&operator, &op_publisher);
    }));
    let task_rt = rt.clone();
    let result = rt.block_on(async move {
        let listener = task_rt
            .bind_tcp(started.feed_listen)
            .await
            .map_err(|e| ControlError::Io(e.kind()))?;
        let shutdown = Shutdown::new();
        drop(task_rt.spawn(serve_route_feed(
            task_rt.clone(),
            listener,
            started.tls,
            shutdown.signal(),
            Arc::clone(&started.publisher),
        )));
        let _ = fstp_obs::log_to_stderr(&LogEvent::Started);
        crate::service::await_termination_and_drain(&task_rt, &shutdown, &mut term, DRAIN).await;
        Ok(())
    });
    let _ = std::fs::remove_file(&started.operator);
    result
}

/// `fstp-control route add <route file>`: publishes the one route of the
/// route file (the grammar of `fstp_edge::config::decode_routes`) through
/// the running process. Returns the version that serves it.
///
/// # Errors
///
/// [`ControlError::Config`] for a refused configuration or route file,
/// [`ControlError::Request`] when the running process refuses the route,
/// and [`ControlError::Io`] when it cannot be reached or fails.
pub fn route_add(file: &Path) -> Result<u64, ControlError> {
    let cfg = load_config()?;
    let bytes = read_route_file(file)?;
    let routes = fstp_edge::config::decode_routes(&bytes).map_err(|_| bad("route file"))?;
    let [route] =
        <[PinnedRoute; 1]>::try_from(routes.entries()).map_err(|_| bad("route file: one route"))?;
    send(&cfg, &OperatorRequest::Add(Box::new(route)))
}

/// `fstp-control route remove <cell id>`: removes every route of the cell
/// (32 lowercase hex digits) through the running process. Returns the
/// version without it.
///
/// # Errors
///
/// As [`route_add`].
pub fn route_remove(cell: &str) -> Result<u64, ControlError> {
    let cfg = load_config()?;
    let id = crate::config::lower_hex(cell, 16)
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or(bad("cell id"))?;
    send(&cfg, &OperatorRequest::Remove(id))
}

fn send(cfg: &FeedConfig, request: &OperatorRequest) -> Result<u64, ControlError> {
    let reply = operator_request(Path::new(&cfg.operator_socket), request)?;
    match reply.status {
        OperatorStatus::Stored => Ok(reply.version),
        OperatorStatus::Refused => Err(ControlError::Request("I-19")),
        OperatorStatus::Failed => Err(ControlError::Io(std::io::ErrorKind::Other)),
    }
}

fn read_route_file(path: &Path) -> Result<Vec<u8>, ControlError> {
    let limit = fstp_edge::config::MAX_ROUTE_FILE_LEN;
    let file = std::fs::File::open(path).map_err(|_| bad("route file"))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| bad("route file"))?;
    if bytes.len() > limit {
        return Err(bad("route file"));
    }
    Ok(bytes)
}
