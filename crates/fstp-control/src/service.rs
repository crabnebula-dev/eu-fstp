//! The `fstp-control` process: the `CellToCp` listener and the run loop
//! (design sections 1.3, 2.3 and 9.1, ADR-009, R-NF-09).
//!
//! Cells connect over mutual TLS. The handshake accepts only a client
//! certificate that chains to the control-plane CA. The listener then
//! reads the cell from the certificate's one subject CN, `cell_<32 hex
//! digits>` ([`CELL_CN_PREFIX`]). Interim, pending Daniel: design section
//! 1.3 names the issuer of `CellToCp` certificates but not their subject.
//! A message that names a cell must name the certificate's cell, so no
//! cell can speak for another (I-19, I-20).
//!
//! The framing is one exchange per connection ([`crate::exchange`]), as
//! the cell side in `fstp_cell::control` writes it. The cell sends a
//! heartbeat every 60 seconds there. Interim, pending Daniel: design
//! section 9.1 names no interval.
//!
//! What the listener answers:
//!
//! - `Heartbeat` and `Metering` of the certificate's cell: recorded in
//!   memory in the [`CellRegistry`], answered with `Ack`;
//! - the same naming another cell: closed without a reply;
//! - `RoleCredential` and `CertRenewal`: closed without a reply. They need
//!   the `cp` registry, the cluster CAs in control-plane custody and the
//!   agent link, which this build does not compose yet.
//!
//! The operator login of [`crate::operator`] is built and checked at
//! start, but no listener serves it yet.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fstp_cp_proto::{CellId, CellToCp, CounterKind, CpToCell, Health, ProductVersion};
use fstp_obs::{LogEvent, Method, Signal};
use fstp_rt::signal::{Signals, Termination, TerminationListener};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime, Shutdown, ShutdownSignal};

use crate::config::{CONTROL_FILES, decode_control_config, read_credential};
use crate::operator::OperatorLogin;
use crate::{ControlConfig, ControlError};

/// The environment variable that names the control plane's configuration
/// file.
pub const CONFIG_ENV: &str = "FSTP_CONTROL_CONFIG";

/// The prefix of the subject CN of a `CellToCp` client certificate. The
/// 32 lowercase hex digits of the cell follow. Interim, pending Daniel.
pub const CELL_CN_PREFIX: &str = "cell_";

/// The longest request the listener reads: one `CellToCp` frame.
pub const MAX_REQUEST_LEN: usize = fstp_cp_proto::codec::MAX_FRAME_LEN;

/// How long a drain may take after SIGTERM.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The route template the listener logs under.
const ROUTE: &str = "/cp/cell-to-cp";

/// The cell a `CellToCp` client certificate names: its one subject CN must
/// be [`CELL_CN_PREFIX`] and 32 lowercase hex digits.
pub fn cell_of_peer(cert_der: &[u8]) -> Option<CellId> {
    let cns = crate::exchange::peer_common_names(cert_der)?;
    let [cn] = cns.as_slice() else {
        return None;
    };
    let hex = cn.strip_prefix(CELL_CN_PREFIX)?;
    if hex.len() != 32 {
        return None;
    }
    let bytes = crate::config::lower_hex(hex, 16)?;
    Some(CellId(bytes.try_into().ok()?))
}

/// The last heartbeat of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatSeen {
    /// The product version it reported.
    pub version: ProductVersion,
    /// The health it reported.
    pub health: Health,
    /// When it arrived, in seconds since the Unix epoch.
    pub at: u64,
}

/// The metering counters of one cell and day.
pub type Counters = Vec<(CounterKind, u64)>;

/// What the listener learned from cells, in memory. Interim: the `cp`
/// database is not composed yet, so a restart forgets it.
#[derive(Debug, Default)]
pub struct CellRegistry {
    heartbeats: Mutex<BTreeMap<CellId, HeartbeatSeen>>,
    metering: Mutex<BTreeMap<(CellId, i64), Counters>>,
}

impl CellRegistry {
    /// The last heartbeat of `cell`.
    pub fn heartbeat(&self, cell: CellId) -> Option<HeartbeatSeen> {
        self.heartbeats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cell)
            .copied()
    }

    /// The metering counters of `cell` for `period`.
    pub fn metering(&self, cell: CellId, period: i64) -> Option<Counters> {
        self.metering
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(cell, period))
            .cloned()
    }

    /// The cells that sent a heartbeat.
    pub fn cells(&self) -> Vec<CellId> {
        self.heartbeats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn refused(rule: &'static str, status: u16) {
    let _ = fstp_obs::log_to_stderr(&LogEvent::Refused {
        method: Method::Other,
        route: ROUTE,
        rule,
        status,
    });
}

/// Answers one `CellToCp` exchange from the peer certificate `peer`
/// (module documentation). `None` closes without a reply.
pub fn answer_cell(registry: &CellRegistry, peer: &[u8], request: &[u8]) -> Option<Vec<u8>> {
    let started = Instant::now();
    let Some(cell) = cell_of_peer(peer) else {
        refused("R-NF-09", 403);
        return None;
    };
    let Ok(message) = fstp_cp_proto::decode_cell_to_cp(request) else {
        refused("TH-26", 400);
        return None;
    };
    match message {
        CellToCp::Heartbeat {
            cell: named,
            version,
            health,
        } if named == cell => {
            registry
                .heartbeats
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    cell,
                    HeartbeatSeen {
                        version,
                        health,
                        at: now_secs(),
                    },
                );
        }
        CellToCp::Metering {
            cell: named,
            period,
            counters,
        } if named == cell => {
            registry
                .metering
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((cell, period), counters);
        }
        CellToCp::Heartbeat { .. } | CellToCp::Metering { .. } => {
            refused("I-20", 403);
            return None;
        }
        CellToCp::RoleCredential { .. } | CellToCp::CertRenewal { .. } => {
            refused("ADR-011", 501);
            return None;
        }
    }
    let reply = fstp_cp_proto::encode_cp_to_cell(&CpToCell::Ack).ok()?;
    let _ = fstp_obs::log_to_stderr(&LogEvent::Request {
        method: Method::Other,
        route: ROUTE,
        status: 200,
        elapsed: started.elapsed(),
    });
    Some(reply)
}

/// The TLS files of the `CellToCp` listener.
#[derive(Clone)]
pub struct ControlParts {
    /// The listener address.
    pub cell_listen: SocketAddr,
    /// The control-plane CA (PEM), the only root for cell certificates.
    pub control_ca_pem: Vec<u8>,
    /// The listener certificate chain (PEM).
    pub cert_pem: Vec<u8>,
    /// The listener key (PEM).
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for ControlParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlParts")
            .field("cell_listen", &self.cell_listen)
            .finish_non_exhaustive()
    }
}

impl ControlParts {
    /// Reads the files of [`CONTROL_FILES`] for `cfg`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Io`] or [`ControlError::Config`] for a file that
    /// cannot be read.
    pub fn load(cfg: &ControlConfig) -> Result<ControlParts, ControlError> {
        let [ca, cert, key] = CONTROL_FILES;
        let dir = &cfg.credentials_dir;
        Ok(ControlParts {
            cell_listen: cfg.cell_listen,
            control_ca_pem: read_credential(dir, ca)?,
            cert_pem: read_credential(dir, cert)?,
            key_pem: read_credential(dir, key)?,
        })
    }

    /// The listener's TLS configuration: the control-plane CA as the only
    /// client root (R-NF-09).
    ///
    /// # Errors
    ///
    /// [`ControlError::Tls`] for PEM that does not build.
    pub fn server_tls(&self) -> Result<fstp_tls::ServerConfig, ControlError> {
        fstp_tls::ServerConfig::mutual(&self.cert_pem, &self.key_pem, &self.control_ca_pem)
            .map_err(|_| ControlError::Tls("cell listener"))
    }
}

/// Serves `CellToCp` exchanges on `listener` until `signal` is triggered.
pub async fn serve_cells<R: Runtime>(
    rt: R,
    tls: fstp_tls::ServerConfig,
    listener: R::TcpListener,
    registry: Arc<CellRegistry>,
    signal: ShutdownSignal,
) {
    crate::exchange::serve(
        rt,
        listener,
        tls,
        MAX_REQUEST_LEN,
        signal,
        move |peer, request| {
            let reply = answer_cell(&registry, &peer, &request);
            std::future::ready(reply)
        },
    )
    .await;
}

/// Waits for a termination signal, then triggers `shutdown` and waits up
/// to `deadline` for its participants. Logs `SignalReceived`,
/// `ShuttingDown`, then `Drained` or `DrainTimedOut` (ADR-002).
pub async fn await_termination_and_drain<R: Runtime, T: TerminationListener>(
    rt: &R,
    shutdown: &Shutdown,
    term: &mut T,
    deadline: Duration,
) {
    let signal = match term.recv().await {
        Termination::Terminate => Signal::Terminate,
        Termination::Interrupt => Signal::Interrupt,
    };
    let _ = fstp_obs::log_to_stderr(&LogEvent::SignalReceived { signal });
    let _ = fstp_obs::log_to_stderr(&LogEvent::ShuttingDown);
    let started = Instant::now();
    let event = match shutdown.shutdown(rt, deadline).await {
        Ok(()) => LogEvent::Drained {
            elapsed: started.elapsed(),
        },
        Err(t) => LogEvent::DrainTimedOut {
            remaining: u64::try_from(t.remaining).unwrap_or(u64::MAX),
        },
    };
    let _ = fstp_obs::log_to_stderr(&event);
}

/// Serves cells on a bound listener until a termination signal, then
/// drains. Logs `Started` once it serves.
///
/// # Errors
///
/// [`ControlError::Tls`] for a listener configuration that does not
/// build.
pub async fn serve_listener_until_terminated<R: Runtime, T: TerminationListener>(
    rt: R,
    parts: &ControlParts,
    listener: R::TcpListener,
    registry: Arc<CellRegistry>,
    term: &mut T,
) -> Result<(), ControlError> {
    let tls = parts.server_tls()?;
    let shutdown = Shutdown::new();
    let served = rt.spawn(serve_cells(
        rt.clone(),
        tls,
        listener,
        registry,
        shutdown.signal(),
    ));
    let _ = fstp_obs::log_to_stderr(&LogEvent::Started);
    await_termination_and_drain(&rt, &shutdown, term, DRAIN_TIMEOUT).await;
    served
        .await
        .map_err(|_| ControlError::Io(std::io::ErrorKind::Other))
}

/// Runs the control plane named by [`CONFIG_ENV`] until SIGTERM. The
/// binary's one runtime is tokio behind `fstp_rt` (ADR-002).
///
/// # Errors
///
/// [`ControlError::Config`] for a missing or refused configuration,
/// [`ControlError::Operator`] for a refused operator host,
/// [`ControlError::Io`] for an unreadable file or a listener that does not
/// bind, [`ControlError::Signal`] when SIGTERM cannot be caught, and
/// [`ControlError::Tls`] for TLS files that do not build.
pub fn run() -> Result<(), ControlError> {
    let bytes = crate::config::read_config_file(CONFIG_ENV)?;
    let cfg = decode_control_config(&bytes)?;
    let parts = ControlParts::load(&cfg)?;
    // Built at start so a refused host or key set stops the process. No
    // listener serves the ceremony yet (module documentation).
    let _login = OperatorLogin::new(&cfg.operator_host, &cfg.staff)?;
    let rt = TokioRuntime::new_multi_thread(2).map_err(|e| ControlError::Io(e.kind()))?;
    let mut term = rt.listen_termination().map_err(|_| ControlError::Signal)?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let listener = rt2
            .bind_tcp(parts.cell_listen)
            .await
            .map_err(|e| ControlError::Io(e.kind()))?;
        let registry = Arc::new(CellRegistry::default());
        serve_listener_until_terminated(rt2, &parts, listener, registry, &mut term).await
    })
}
