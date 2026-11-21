//! The pilot route feed run by its binaries (lane L15 `prod/route-feed`,
//! ADR-009 "Pilot route feed", decided by Daniel on 2026-11-21).
//!
//! [`PilotFeed::start`] writes the files an operator writes and starts
//! `fstp-control route-feed` and `fstp-edge` in front of a world's cells:
//!
//! 1. the control plane's credentials directory, from the world's
//!    control-plane CA, which stands in for the operator's tunnel CA and
//!    for the CA the operator's browser trusts;
//! 2. `fstp-control init-route-feed`, which creates the feed signing key
//!    through a custody process and the first, empty table;
//! 3. `fstp-control route-feed` with no staff, the enrolment of a staff
//!    passkey on its operator page, and a restart with that passkey pinned;
//! 4. the edge's credentials directory with `route-feed.pub`, and its
//!    configuration with the pin of the control plane's certificate and
//!    its cache directory;
//! 5. `fstp-edge`, which starts with no route.
//!
//! Routes then come and go through `fstp-control route add` and `route
//! remove` while both processes run ([`PilotFeed::add`],
//! [`PilotFeed::remove`]). Each command only proposes. The helper then
//! approves the change on the operator page as a staff member would: a
//! passkey login and a step-up bound to the change, with the software
//! authenticator of [`crate::soft_authn`]. The binaries must be built
//! first: `cargo build -p fstp-control --bin fstp-control -p fstp-edge
//! --bin fstp-edge`. Test only. Every value is synthetic.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use fstp_edge::{CellEndpoint, PinnedRoute, RouteEntry};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Runtime as _};

use crate::soft_authn::{Alg, SoftAuthenticator};
use crate::world::{FEED_SERVER_NAME, OPERATOR_HOST, World, WorldError};
use crate::world_host::bin_path;

/// How long a process may take to come up, or a change to be proposed.
const READY: Duration = Duration::from_secs(60);

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("{what}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i.saturating_add(2))?, 16).ok())
        .collect()
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

/// One reply of the operator page: the status, the `Set-Cookie` value
/// and the parsed JSON body.
struct PageReply {
    status: u16,
    cookie: Option<String>,
    body: Option<fstp_json::Value>,
}

/// A pilot `fstp-control route-feed` and an `fstp-edge` polling it, run
/// by their binaries (module documentation).
#[derive(Debug)]
pub struct PilotFeed {
    dir: PathBuf,
    control_bin: PathBuf,
    edge_bin: PathBuf,
    control_config: PathBuf,
    edge_config: PathBuf,
    operator_socket: PathBuf,
    feed_addr: SocketAddr,
    operator_addr: SocketAddr,
    edge_addr: SocketAddr,
    tunnel_tls: fstp_tls::ClientConfig,
    routes: Vec<RouteEntry>,
    staff: SoftAuthenticator,
    session: Option<String>,
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
    /// init command fails, the enrolment fails or a process does not come
    /// up.
    pub fn start(
        world: &World,
        dir: &Path,
        keyd_socket: &Path,
        poll_seconds: u8,
    ) -> Result<PilotFeed, WorldError> {
        PilotFeed::start_with_assets(world, dir, keyd_socket, poll_seconds, None)
    }

    /// As [`PilotFeed::start`], with the compiled operator page in `assets`
    /// (`auth/` and `routefeed/` of `web/dist`), for a browser.
    ///
    /// # Errors
    ///
    /// As [`PilotFeed::start`].
    pub fn start_with_assets(
        world: &World,
        dir: &Path,
        keyd_socket: &Path,
        poll_seconds: u8,
        page_assets: Option<&Path>,
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
        let assets = page_assets.map_or_else(|| control.join("assets"), Path::to_path_buf);
        for d in [&creds, &state, &out, &assets] {
            mkdir(d)?;
        }
        write_private(&creds.join("control-ca.pem"), &parts.tunnel.ca_pem)?;
        write_private(&creds.join("control.pem"), &parts.feed_cert_pem)?;
        write_private(&creds.join("control-key.pem"), &parts.feed_key_pem)?;
        write_private(&creds.join("operator.pem"), &parts.operator_cert_pem)?;
        write_private(&creds.join("operator-key.pem"), &parts.operator_key_pem)?;
        let feed_addr = free_port()?;
        let operator_addr = free_port()?;
        let operator_socket = control.join("routes.sock");
        let control_config = control.join("control.json");
        let edge_dir = dir.join("edge");
        let mut feed = PilotFeed {
            dir: dir.to_path_buf(),
            control_bin,
            edge_bin,
            control_config,
            edge_config: edge_dir.join("edge.json"),
            operator_socket,
            feed_addr,
            operator_addr,
            edge_addr: free_port()?,
            tunnel_tls,
            routes: parts.tunnel.routes.clone(),
            staff: SoftAuthenticator::for_rp(OPERATOR_HOST),
            session: None,
            control: None,
            edge: None,
        };
        let socket_path = feed.operator_socket.clone();
        let config = |staff: &str| {
            format!(
                r#"{{"assets_dir":"{}","credentials_dir":"{}","edges":["{}"],"feed_listen":"{feed_addr}","keyd_socket":"{}","operator_host":"{OPERATOR_HOST}","operator_listen":"{operator_addr}","operator_socket":"{}","staff":[{staff}],"state_dir":"{}"}}"#,
                assets.display(),
                creds.display(),
                hex(&parts.edge_id),
                keyd_socket.display(),
                socket_path.display(),
                state.display(),
            )
        };
        write_private(&feed.control_config, config("").as_bytes())?;
        let init = feed
            .control_command()
            .arg("init-route-feed")
            .arg(&out)
            .status()
            .map_err(|e| fail("fstp-control init-route-feed", &e))?;
        if !init.success() {
            return Err(fail("fstp-control init-route-feed", &init));
        }
        // With no staff pinned, enrol one passkey on the page, pin it, and
        // restart, as an operator does once.
        feed.start_control()?;
        let entry = feed.enrol()?;
        write_private(&feed.control_config, config(&entry).as_bytes())?;
        if !feed.stop_control() {
            return Err(fail("fstp-control", &"it did not drain"));
        }
        feed.start_control()?;

        // The edge's files, with the pin of the control plane's
        // certificate as the operator reads it.
        let feed_pin = feed.pin_of(feed_addr, FEED_SERVER_NAME)?;
        let edge_creds = edge_dir.join("credentials");
        let edge_state = edge_dir.join("state");
        mkdir(&edge_creds)?;
        mkdir(&edge_state)?;
        write_private(&edge_creds.join("tunnel-ca.pem"), &parts.tunnel.ca_pem)?;
        write_private(
            &edge_creds.join("tunnel.pem"),
            &parts.tunnel.client_cert_pem,
        )?;
        write_private(&edge_creds.join("tunnel.key"), &parts.tunnel.client_key_pem)?;
        let public =
            std::fs::read(out.join("route-feed.pub")).map_err(|e| fail("route-feed.pub", &e))?;
        write_private(&edge_creds.join("route-feed.pub"), &public)?;
        write_private(
            &feed.edge_config,
            format!(
                r#"{{"credentials_dir":"{}","feed":{{"address":"{feed_addr}","cert_sha256":["{}"],"poll_seconds":{poll_seconds},"server_name":"{FEED_SERVER_NAME}"}},"limits":{{"hello_seconds":10,"open_seconds":10}},"listen":{{"public":"{}"}},"state_dir":"{}"}}"#,
                edge_creds.display(),
                hex(&feed_pin),
                feed.edge_addr,
                edge_state.display(),
            )
            .as_bytes(),
        )?;
        feed.start_edge()?;
        Ok(feed)
    }

    fn control_command(&self) -> Command {
        let mut cmd = Command::new(&self.control_bin);
        cmd.env("FSTP_CONTROL_CONFIG", &self.control_config)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        cmd
    }

    /// Starts `fstp-edge` and waits until it listens.
    ///
    /// # Errors
    ///
    /// Fails when it does not come up.
    pub fn start_edge(&mut self) -> Result<(), WorldError> {
        let mut cmd = Command::new(&self.edge_bin);
        cmd.env("FSTP_EDGE_CONFIG", &self.edge_config);
        let mut proc = Proc::spawn(cmd)?;
        let begun = Instant::now();
        while std::net::TcpStream::connect(self.edge_addr).is_err() {
            if proc.exited() || begun.elapsed() > READY {
                return Err(fail("fstp-edge", &"it did not come up"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.edge = Some(proc);
        Ok(())
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
            && std::net::TcpStream::connect(self.feed_addr).is_ok()
            && std::net::TcpStream::connect(self.operator_addr).is_ok())
        {
            if proc.exited() || begun.elapsed() > READY {
                return Err(fail("fstp-control route-feed", &"it did not come up"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.control = Some(proc);
        self.session = None;
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

    /// Where the operator page listens. A browser reaches it as
    /// `https://<OPERATOR_HOST>`, through a forward to this address.
    #[must_use]
    pub fn operator_addr(&self) -> SocketAddr {
        self.operator_addr
    }

    /// The audit log of `fstp-control`.
    #[must_use]
    pub fn audit_log(&self) -> PathBuf {
        self.dir
            .join("control")
            .join("state")
            .join("route-audit.log")
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

    /// One request to the operator page, as the page's own script sends
    /// it: same origin, the CSRF header, the session cookie.
    fn page(&self, method: &str, path: &str, body: &str) -> Result<PageReply, WorldError> {
        let rt = TokioRuntime::new_multi_thread(1).map_err(|e| fail("a runtime", &e))?;
        let cookie = self
            .session
            .as_ref()
            .map(|c| format!("Cookie: {c}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {OPERATOR_HOST}\r\nOrigin: https://{OPERATOR_HOST}\r\nX-FSTP-Request: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{cookie}Connection: close\r\n\r\n{body}",
            body.len()
        );
        let answer = rt.block_on(async {
            let tcp = rt
                .connect_tcp(self.operator_addr)
                .await
                .map_err(|e| fail("the operator page", &e))?;
            let mut tls = fstp_tls::connect(&self.tunnel_tls, OPERATOR_HOST, tcp)
                .await
                .map_err(|e| fail("the operator page", &e))?;
            tls.write_all(head.as_bytes())
                .await
                .map_err(|e| fail("the operator page", &e))?;
            tls.flush()
                .await
                .map_err(|e| fail("the operator page", &e))?;
            let mut answer = Vec::new();
            let _ = tls.read_to_end(&mut answer, 1 << 20).await;
            Ok::<_, WorldError>(answer)
        })?;
        let m =
            fstp_http::Method::from_bytes(method.as_bytes()).map_err(|e| fail("a method", &e))?;
        match fstp_http::parse_response(&answer, &m, &fstp_http::Limits::default(), true) {
            Ok(fstp_http::Parsed::Complete { message, .. }) => Ok(PageReply {
                status: message.status.as_u16(),
                cookie: message
                    .headers
                    .get("set-cookie")
                    .and_then(|v| v.to_str())
                    .and_then(|v| v.split(';').next())
                    .map(str::to_owned),
                body: fstp_json::parse(&message.body).ok(),
            }),
            _ => Err(fail("the operator page", &"no complete answer")),
        }
    }

    fn challenge_of(r: &PageReply) -> Result<[u8; 32], WorldError> {
        r.body
            .as_ref()
            .and_then(|b| b.get("challenge_id"))
            .and_then(|v| v.as_str())
            .and_then(unhex)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| fail("the operator page", &"no challenge"))
    }

    fn assertion_body(challenge: &[u8; 32], a: &fstp_webauthn::AssertionResponse) -> String {
        format!(
            r#"{{"authenticator_data":"{}","challenge_id":"{}","client_data_json":"{}","credential_id":"{}","signature":"{}"}}"#,
            hex(&a.authenticator_data),
            hex(challenge),
            hex(&a.client_data_json),
            hex(&a.credential_id),
            hex(&a.signature)
        )
    }

    /// Enrols a new staff passkey on the page, and returns the staff entry
    /// the page answered, as JSON.
    fn enrol(&mut self) -> Result<String, WorldError> {
        let opts = self.page("POST", "/api/register/options", "{}")?;
        let c = Self::challenge_of(&opts)?;
        let reg = self
            .staff
            .register(Alg::Es256, c, &[])
            .map_err(|e| fail("a passkey", &format!("{e:?}")))?;
        let body = format!(
            r#"{{"attestation_object":"{}","challenge_id":"{}","client_data_json":"{}","credential_id":"{}"}}"#,
            hex(&reg.response.attestation_object),
            hex(&c),
            hex(&reg.response.client_data_json),
            hex(&reg.credential_id)
        );
        let done = self.page("POST", "/api/register", &body)?;
        let b = done
            .body
            .filter(|_| done.status == 200)
            .ok_or_else(|| fail("the enrolment", &done.status))?;
        let field = |n: &str| {
            b.get(n)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| fail("the enrolment", &n))
        };
        Ok(format!(
            r#"{{"cose_key":"{}","credential_id":"{}","staff":"{}"}}"#,
            field("cose_key")?,
            field("credential_id")?,
            field("staff")?
        ))
    }

    fn assert(
        &mut self,
        challenge: [u8; 32],
    ) -> Result<fstp_webauthn::AssertionResponse, WorldError> {
        let id = self
            .staff
            .credential_ids()
            .first()
            .cloned()
            .ok_or_else(|| fail("a passkey", &"none enrolled"))?;
        self.staff
            .assert(&id, challenge, &[])
            .map_err(|e| fail("a passkey", &format!("{e:?}")))
    }

    /// Logs in on the page with the enrolled passkey, once per control
    /// process.
    fn login(&mut self) -> Result<(), WorldError> {
        if self.session.is_some() {
            return Ok(());
        }
        let opts = self.page("POST", "/api/login/options", "{}")?;
        let c = Self::challenge_of(&opts)?;
        let a = self.assert(c)?;
        let done = self.page("POST", "/api/login", &Self::assertion_body(&c, &a))?;
        self.session = done
            .cookie
            .filter(|_| done.status == 200)
            .map(Some)
            .ok_or_else(|| fail("the login", &done.status))?;
        Ok(())
    }

    /// The ids of the changes waiting on the page.
    fn pending(&mut self) -> Result<Vec<String>, WorldError> {
        self.login()?;
        let state = self.page("GET", "/api/state", "")?;
        Ok(state
            .body
            .as_ref()
            .and_then(|b| b.get("pending"))
            .and_then(|p| p.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Approves the change `id` with a step-up bound to it. Returns the
    /// page's status.
    fn approve(&mut self, id: &str) -> Result<u16, WorldError> {
        self.login()?;
        let opts = self.page("POST", &format!("/api/changes/{id}/options"), "{}")?;
        let c = Self::challenge_of(&opts)?;
        let a = self.assert(c)?;
        Ok(self
            .page(
                "POST",
                &format!("/api/changes/{id}/approve"),
                &Self::assertion_body(&c, &a),
            )?
            .status)
    }

    /// Runs `cmd`, a proposal, and approves it on the page once it waits,
    /// as a staff member would. Returns the command's exit status. A
    /// proposal refused at once never waits.
    fn propose_and_approve(&mut self, mut cmd: Command) -> Result<ExitStatus, WorldError> {
        let before = self.pending()?;
        let mut child = cmd.spawn().map_err(|e| fail("fstp-control route", &e))?;
        let begun = Instant::now();
        let id = loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Ok(status);
            }
            if let Some(id) = self.pending()?.into_iter().find(|i| !before.contains(i)) {
                break id;
            }
            if begun.elapsed() > READY {
                let _ = child.kill();
                return Err(fail("fstp-control route", &"no proposal arrived"));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let status = self.approve(&id)?;
        if status != 200 {
            let _ = child.kill();
            return Err(fail("the approval", &status));
        }
        child.wait().map_err(|e| fail("fstp-control route", &e))
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

    /// Runs `fstp-control route add <file>` and approves the proposal
    /// with a step-up on the operator page.
    ///
    /// # Errors
    ///
    /// Fails when the command does not run or the approval fails.
    pub fn add(&mut self, file: &Path) -> Result<ExitStatus, WorldError> {
        let mut cmd = self.control_command();
        cmd.args(["route", "add"]).arg(file);
        self.propose_and_approve(cmd)
    }

    /// Runs `fstp-control route remove <cell>` and approves the proposal
    /// with a step-up on the operator page.
    ///
    /// # Errors
    ///
    /// Fails when the command does not run or the approval fails.
    pub fn remove(&mut self, cell: &[u8; 16]) -> Result<ExitStatus, WorldError> {
        let mut cmd = self.control_command();
        cmd.args(["route", "remove", &hex(cell)]);
        self.propose_and_approve(cmd)
    }

    /// Runs `fstp-control route list <out>`.
    ///
    /// # Errors
    ///
    /// Fails when the command does not run.
    pub fn list(&self, out: &Path) -> Result<ExitStatus, WorldError> {
        self.control_command()
            .args(["route", "list"])
            .arg(out)
            .status()
            .map_err(|e| fail("fstp-control route list", &e))
    }
}
