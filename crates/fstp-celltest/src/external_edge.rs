//! The pilot route feed run by its binaries (lane L15 `prod/route-feed`,
//! ADR-009 "Pilot route feed", decided by Daniel on 2026-11-21).
//!
//! [`PilotFeed::start`] writes the files an operator writes and starts
//! `fstp-control route-feed` and `fstp-edge` in front of a world's cells:
//!
//! 1. the control plane's credentials directory, from the world's
//!    control-plane CA, which stands in for the operator's tunnel CA;
//! 2. `fstp-control init-route-feed`, which creates the feed signing key
//!    through a custody process and the first, empty table;
//! 3. `fstp-control route-feed`;
//! 4. the edge's credentials directory with `route-feed.pub`, and its
//!    configuration with the pin of the control plane's certificate;
//! 5. `fstp-edge`, which starts with no route.
//!
//! Routes then come and go through `fstp-control route add` and
//! `fstp-control route remove` ([`PilotFeed::add`], [`PilotFeed::remove`])
//! while both processes run. The binaries must be built first: `cargo
//! build -p fstp-control --bin fstp-control -p fstp-edge --bin fstp-edge`.
//! Test only. Every value is synthetic.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use fstp_edge::{CellEndpoint, PinnedRoute, RouteEntry};
use fstp_rt::Runtime as _;
use fstp_rt::tokio::TokioRuntime;

use crate::world::{FEED_SERVER_NAME, World, WorldError};
use crate::world_host::bin_path;

/// How long a process may take to come up.
const READY: Duration = Duration::from_secs(60);

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("{what}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn free_port() -> Result<SocketAddr, WorldError> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| fail("a free port", &e))?;
    l.local_addr().map_err(|e| fail("a free port", &e))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WorldError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| fail("a private file", &e))?;
    f.write_all(bytes).map_err(|e| fail("a private file", &e))
}

fn mkdir(path: &Path) -> Result<(), WorldError> {
    std::fs::create_dir_all(path).map_err(|e| fail("a directory", &e))
}

/// One child process. Dropping it sends SIGTERM and waits for the drain.
#[derive(Debug)]
struct Proc {
    child: Option<Child>,
}

impl Proc {
    fn spawn(mut cmd: Command) -> Result<Proc, WorldError> {
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| fail("a process", &e))?;
        Ok(Proc { child: Some(child) })
    }

    /// Whether the process exited already.
    fn exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|c| matches!(c.try_wait(), Ok(Some(_))))
    }

    /// Sends SIGTERM and returns whether the process exited with status 0.
    fn stop(&mut self) -> bool {
        let Some(mut child) = self.child.take() else {
            return true;
        };
        let sent = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .is_ok_and(|s| s.success());
        let begun = Instant::now();
        while sent && begun.elapsed() < READY {
            if let Ok(Some(status)) = child.try_wait() {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        false
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// A pilot `fstp-control route-feed` and an `fstp-edge` polling it, run
/// by their binaries (module documentation).
#[derive(Debug)]
pub struct PilotFeed {
    dir: PathBuf,
    control_bin: PathBuf,
    edge_bin: PathBuf,
    control_config: PathBuf,
    operator_socket: PathBuf,
    feed_addr: SocketAddr,
    edge_addr: SocketAddr,
    tunnel_tls: fstp_tls::ClientConfig,
    routes: Vec<RouteEntry>,
    control: Option<Proc>,
    edge: Option<Proc>,
}

impl PilotFeed {
    /// Starts both processes in `dir` in front of `world`'s cells, with
    /// the custody process at `keyd_socket` for the feed key and the edge
    /// polling every `poll_seconds` (module documentation).
    ///
    /// # Errors
    ///
    /// Fails when a binary is not built, a file is not written, the
    /// init command fails or a process does not come up.
    pub fn start(
        world: &World,
        dir: &Path,
        keyd_socket: &Path,
        poll_seconds: u8,
    ) -> Result<PilotFeed, WorldError> {
        let control_bin = bin_path("fstp-control")?;
        let edge_bin = bin_path("fstp-edge")?;
        let parts = world.edge_feed_parts()?;
        let tunnel_tls = fstp_tls::ClientConfig::mutual(
            &parts.tunnel.ca_pem,
            &parts.tunnel.client_cert_pem,
            &parts.tunnel.client_key_pem,
        )
        .map_err(|e| fail("the tunnel client", &e))?;

        // The control plane's files.
        let control = dir.join("control");
        let (creds, state, out) = (
            control.join("credentials"),
            control.join("state"),
            control.join("out"),
        );
        for d in [&creds, &state, &out] {
            mkdir(d)?;
        }
        write_private(&creds.join("control-ca.pem"), &parts.tunnel.ca_pem)?;
        write_private(&creds.join("control.pem"), &parts.feed_cert_pem)?;
        write_private(&creds.join("control-key.pem"), &parts.feed_key_pem)?;
        let feed_addr = free_port()?;
        let operator_socket = control.join("routes.sock");
        let control_config = control.join("control.json");
        write_private(
            &control_config,
            format!(
                r#"{{"credentials_dir":"{}","edges":["{}"],"feed_listen":"{feed_addr}","keyd_socket":"{}","operator_socket":"{}","state_dir":"{}"}}"#,
                creds.display(),
                hex(&parts.edge_id),
                keyd_socket.display(),
                operator_socket.display(),
                state.display(),
            )
            .as_bytes(),
        )?;
        let mut feed = PilotFeed {
            dir: dir.to_path_buf(),
            control_bin,
            edge_bin,
            control_config,
            operator_socket,
            feed_addr,
            edge_addr: free_port()?,
            tunnel_tls,
            routes: parts.tunnel.routes.clone(),
            control: None,
            edge: None,
        };
        let init = feed
            .control_command()
            .arg("init-route-feed")
            .arg(&out)
            .status()
            .map_err(|e| fail("fstp-control init-route-feed", &e))?;
        if !init.success() {
            return Err(fail("fstp-control init-route-feed", &init));
        }
        feed.start_control()?;

        // The edge's files, with the pin of the control plane's
        // certificate as the operator reads it.
        let feed_pin = feed.pin_of(feed_addr, FEED_SERVER_NAME)?;
        let edge = dir.join("edge");
        let edge_creds = edge.join("credentials");
        mkdir(&edge_creds)?;
        write_private(&edge_creds.join("tunnel-ca.pem"), &parts.tunnel.ca_pem)?;
        write_private(
            &edge_creds.join("tunnel.pem"),
            &parts.tunnel.client_cert_pem,
        )?;
        write_private(&edge_creds.join("tunnel.key"), &parts.tunnel.client_key_pem)?;
        let public =
            std::fs::read(out.join("route-feed.pub")).map_err(|e| fail("route-feed.pub", &e))?;
        write_private(&edge_creds.join("route-feed.pub"), &public)?;
        let edge_config = edge.join("edge.json");
        write_private(
            &edge_config,
            format!(
                r#"{{"credentials_dir":"{}","feed":{{"address":"{feed_addr}","cert_sha256":"{}","poll_seconds":{poll_seconds},"server_name":"{FEED_SERVER_NAME}"}},"limits":{{"hello_seconds":10,"open_seconds":10}},"listen":{{"public":"{}"}}}}"#,
                edge_creds.display(),
                hex(&feed_pin),
                feed.edge_addr,
            )
            .as_bytes(),
        )?;
        let mut cmd = Command::new(&feed.edge_bin);
        cmd.env("FSTP_EDGE_CONFIG", &edge_config);
        let mut proc = Proc::spawn(cmd)?;
        let begun = Instant::now();
        while std::net::TcpStream::connect(feed.edge_addr).is_err() {
            if proc.exited() || begun.elapsed() > READY {
                return Err(fail("fstp-edge", &"it did not come up"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        feed.edge = Some(proc);
        Ok(feed)
    }

    fn control_command(&self) -> Command {
        let mut cmd = Command::new(&self.control_bin);
        cmd.env("FSTP_CONTROL_CONFIG", &self.control_config)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        cmd
    }

    /// Starts `fstp-control route-feed` and waits until it serves.
    ///
    /// # Errors
    ///
    /// Fails when it does not come up.
    pub fn start_control(&mut self) -> Result<(), WorldError> {
        let mut cmd = self.control_command();
        cmd.arg("route-feed");
        let _ = std::fs::remove_file(&self.operator_socket);
        let mut proc = Proc::spawn(cmd)?;
        let begun = Instant::now();
        while !(self.operator_socket.exists()
            && std::net::TcpStream::connect(self.feed_addr).is_ok())
        {
            if proc.exited() || begun.elapsed() > READY {
                return Err(fail("fstp-control route-feed", &"it did not come up"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.control = Some(proc);
        Ok(())
    }

    /// Sends SIGTERM to `fstp-control` and returns whether it drained to
    /// status 0.
    pub fn stop_control(&mut self) -> bool {
        self.control.take().is_none_or(|mut p| p.stop())
    }

    /// Sends SIGTERM to `fstp-edge` and returns whether it drained to
    /// status 0.
    pub fn stop_edge(&mut self) -> bool {
        self.edge.take().is_none_or(|mut p| p.stop())
    }

    /// The process id of the edge, to show it never restarted.
    #[must_use]
    pub fn edge_pid(&self) -> Option<u32> {
        self.edge.as_ref().and_then(Proc::pid)
    }

    /// Where the edge listens.
    #[must_use]
    pub fn edge_addr(&self) -> SocketAddr {
        self.edge_addr
    }

    /// The configuration file of `fstp-control`.
    #[must_use]
    pub fn control_config(&self) -> &Path {
        &self.control_config
    }

    /// The SHA-256 of the end-entity certificate that the server at
    /// `addr` presents for `name`, as an operator reads it.
    fn pin_of(&self, addr: SocketAddr, name: &str) -> Result<[u8; 32], WorldError> {
        let rt = TokioRuntime::new_multi_thread(1).map_err(|e| fail("a runtime", &e))?;
        rt.block_on(async {
            let tcp = rt
                .connect_tcp(addr)
                .await
                .map_err(|e| fail("a tunnel server", &e))?;
            let tls = fstp_tls::connect(&self.tunnel_tls, name, tcp)
                .await
                .map_err(|e| fail("a tunnel handshake", &e))?;
            let leaf = tls
                .peer_end_entity_der()
                .ok_or_else(|| fail("a tunnel server", &"no certificate"))?;
            Ok(fstp_crypto::sha256(leaf))
        })
    }

    /// The routes of the world's cells with the pins their tunnel servers
    /// present.
    ///
    /// # Errors
    ///
    /// Fails when a tunnel server does not answer.
    pub fn pinned_routes(&self) -> Result<Vec<PinnedRoute>, WorldError> {
        self.routes
            .iter()
            .map(|r| {
                Ok(PinnedRoute {
                    route: r.clone(),
                    app_pin: self.pin_of(r.app.address, &r.app.tls_name)?,
                    vault_pin: self.pin_of(r.vault.address, &r.vault.tls_name)?,
                })
            })
            .collect()
    }

    /// Writes `route` as an operator's route file and returns its path.
    ///
    /// # Errors
    ///
    /// Fails when the file is not written.
    pub fn route_file(&self, route: &PinnedRoute, name: &str) -> Result<PathBuf, WorldError> {
        let ep = |e: &CellEndpoint, pin: &[u8; 32]| {
            format!(
                r#"{{"address":"{}","cert_sha256":"{}","server_name":"{}"}}"#,
                e.address,
                hex(pin),
                e.tls_name
            )
        };
        let path = self.dir.join(format!("{name}.json"));
        write_private(
            &path,
            format!(
                r#"{{"routes":[{{"app":{},"cell":"{}","host":"{}","vault":{}}}]}}"#,
                ep(&route.route.app, &route.app_pin),
                hex(&route.route.app.cell),
                route.route.host.as_str(),
                ep(&route.route.vault, &route.vault_pin),
            )
            .as_bytes(),
        )?;
        Ok(path)
    }

    /// Runs `fstp-control route add <file>`.
    ///
    /// # Errors
    ///
    /// Fails when the command does not run.
    pub fn add(&self, file: &Path) -> Result<ExitStatus, WorldError> {
        self.control_command()
            .args(["route", "add"])
            .arg(file)
            .status()
            .map_err(|e| fail("fstp-control route add", &e))
    }

    /// Runs `fstp-control route remove <cell>`.
    ///
    /// # Errors
    ///
    /// Fails when the command does not run.
    pub fn remove(&self, cell: &[u8; 16]) -> Result<ExitStatus, WorldError> {
        self.control_command()
            .args(["route", "remove", &hex(cell)])
            .status()
            .map_err(|e| fail("fstp-control route remove", &e))
    }
}
