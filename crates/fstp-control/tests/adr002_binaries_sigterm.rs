//! ADR-002, design section 2.3, ADR-011: the `fstp-pgagent` and
//! `fstp-control` binaries start from their configuration file, serve
//! until SIGTERM, drain through `fstp_rt::Shutdown` and exit with status
//! 0. A configuration with an unknown member is refused with the usage
//! status 2 before anything starts.
//!
//! Each test runs the built binary as a child process with a synthetic
//! configuration and test certificates in a fresh directory, and sends it
//! a real signal with the system `kill` command. The child's events reach
//! standard error as `fstp_obs` lines.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use fstp_obs::{LogEvent, Signal, encode_log};
use fstp_pgtest::certs::ClusterCa;

const STEP: Duration = Duration::from_secs(60);

/// A fresh directory for one test.
fn fresh_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "fstp-control-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Writes the agent's credential files and configuration into `dir` and
/// returns the configuration path. `extra` is spliced into the JSON
/// object, so a test can add an unknown member.
fn agent_config(dir: &std::path::Path, extra: &str) -> PathBuf {
    let ca = ClusterCa::generate("fstp test control plane CA").unwrap();
    let me = ca.issue_server("control").unwrap();
    let su = ca.issue_role("fstp_super").unwrap();
    for (name, bytes) in [
        ("control-ca.pem", ca.cert_pem().to_vec()),
        ("pgagent.pem", me.cert_pem.clone()),
        ("pgagent-key.pem", me.key_pem.clone()),
        ("cluster-ca.pem", ca.cert_pem().to_vec()),
        ("fstp_super.pem", su.cert_pem.clone()),
        ("fstp_super-key.pem", su.key_pem.clone()),
        ("fstp_super.password", b"synthetic-test-password\n".to_vec()),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    let cfg = format!(
        "{{\"cell_subnet\":\"127.0.0.1/32\",\"cluster_kind\":\"application\",\
         \"credentials_dir\":\"{}\",\"hba_file\":\"{}/pg_hba.conf\",\
         \"listen\":\"127.0.0.1:{}\",\"postgres_port\":5432{extra}}}",
        dir.display(),
        dir.display(),
        free_port()
    );
    let path = dir.join("pgagent.json");
    std::fs::write(&path, cfg).unwrap();
    path
}

/// Writes the control plane's credential files and configuration into
/// `dir` and returns the configuration path.
fn control_config(dir: &std::path::Path, extra: &str) -> PathBuf {
    let ca = ClusterCa::generate("fstp test control plane CA").unwrap();
    let me = ca.issue_server("control").unwrap();
    for (name, bytes) in [
        ("control-ca.pem", ca.cert_pem().to_vec()),
        ("control.pem", me.cert_pem.clone()),
        ("control-key.pem", me.key_pem.clone()),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    let cfg = format!(
        "{{\"cell_listen\":\"127.0.0.1:{}\",\"clusters\":[],\"credentials_dir\":\"{}\",\
         \"operator_host\":\"control.example.test\",\"staff\":[]{extra}}}",
        free_port(),
        dir.display()
    );
    let path = dir.join("control.json");
    std::fs::write(&path, cfg).unwrap();
    path
}

struct Spawned {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

fn spawn(exe: &str, env: &str, config: &std::path::Path) -> Spawned {
    let mut child = Command::new(exe)
        .env_clear()
        .env(env, config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, lines) = channel();
    let stderr = child.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    Spawned {
        child,
        lines,
        seen: Vec::new(),
    }
}

fn log_line(event: &LogEvent) -> String {
    encode_log(event).unwrap().trim_end().to_owned()
}

impl Spawned {
    fn expect(&mut self, want: &str) {
        let deadline = Instant::now() + STEP;
        loop {
            match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => {
                    let done = line == want;
                    self.seen.push(line);
                    if done {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    let _ = self.child.kill();
                    panic!("child stalled before {want}: {:?}", self.seen);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.wait();
                    panic!("child ended before {want}: {:?}, {status:?}", self.seen);
                }
            }
        }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + STEP;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                return self.child.wait().unwrap();
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(mut self) -> (ExitStatus, Vec<String>) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        let status = self.wait();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(line);
        }
        (status, self.seen)
    }
}

/// Whether `lines` hold the signal report, the shutdown start and a
/// completed drain, in that order, and no drain timeout.
fn drained(lines: &[String]) -> bool {
    let want = [
        log_line(&LogEvent::SignalReceived {
            signal: Signal::Terminate,
        }),
        log_line(&LogEvent::ShuttingDown),
    ];
    let mut from = 0;
    for w in &want {
        match lines[from..].iter().position(|l| l == w) {
            Some(i) => from += i + 1,
            None => return false,
        }
    }
    lines[from..]
        .iter()
        .any(|l| l.starts_with("{\"event\":\"drained\""))
        && !lines
            .iter()
            .any(|l| l.starts_with("{\"event\":\"drain_timed_out\""))
}

fn run_until_sigterm(exe: &str, env: &str, config: &std::path::Path) {
    let mut child = spawn(exe, env, config);
    child.expect(&log_line(&LogEvent::Started));
    let (status, lines) = child.terminate();
    assert!(
        status.success() && drained(&lines),
        "status {status:?}, lines {lines:?}"
    );
}

fn refused_with_usage(exe: &str, env: &str, config: &std::path::Path) {
    let mut child = spawn(exe, env, config);
    let status = child.wait();
    while let Ok(line) = child.lines.recv_timeout(Duration::from_secs(5)) {
        child.seen.push(line);
    }
    assert_eq!(status.code(), Some(2), "{:?}", child.seen);
    assert!(
        !child.seen.contains(&log_line(&LogEvent::Started)),
        "{:?}",
        child.seen
    );
}

/// ADR-002, ADR-011, design section 2.3: SIGTERM drains a running
/// `fstp-pgagent`, which then exits with status 0.
#[test]
fn adr002_pgagent_starts_and_stops_on_sigterm() {
    let dir = fresh_dir("pgagent");
    let cfg = agent_config(&dir, "");
    run_until_sigterm(
        env!("CARGO_BIN_EXE_fstp-pgagent"),
        "FSTP_PGAGENT_CONFIG",
        &cfg,
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// ADR-011, R-NF-05: an agent configuration with an unknown member, here
/// a password, is refused with the usage status and nothing starts.
#[test]
fn adr011_pgagent_refuses_a_configuration_with_an_unknown_member() {
    let dir = fresh_dir("pgagent-bad");
    let cfg = agent_config(&dir, ",\"password\":\"x\"");
    refused_with_usage(
        env!("CARGO_BIN_EXE_fstp-pgagent"),
        "FSTP_PGAGENT_CONFIG",
        &cfg,
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// ADR-002, design section 2.3: SIGTERM drains a running `fstp-control`,
/// which then exits with status 0.
#[test]
fn adr002_control_starts_and_stops_on_sigterm() {
    let dir = fresh_dir("control");
    let cfg = control_config(&dir, "");
    run_until_sigterm(
        env!("CARGO_BIN_EXE_fstp-control"),
        "FSTP_CONTROL_CONFIG",
        &cfg,
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// I-19, I-20, design section 9.1: a control plane configuration with an
/// unknown member is refused with the usage status and nothing starts.
#[test]
fn i20_control_refuses_a_configuration_with_an_unknown_member() {
    let dir = fresh_dir("control-bad");
    let cfg = control_config(&dir, ",\"tenant\":\"Acme\"");
    refused_with_usage(
        env!("CARGO_BIN_EXE_fstp-control"),
        "FSTP_CONTROL_CONFIG",
        &cfg,
    );
    let _ = std::fs::remove_dir_all(dir);
}
