//! Running commands and services (ADR-028 "Services").
//!
//! In `systemd` mode each service is a unit under `/etc/systemd/system`.
//! In `direct` mode `fstp-admin` starts the same process itself, writes
//! its process id under `<state>/admin/pids` and its standard streams to
//! `<state>/admin/logs`. Both modes start the same binaries with the same
//! files.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::Services;
use crate::layout::Layout;
use crate::state::write_atomic;

/// How a service shows that it is ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ready {
    /// A Unix socket exists at the path.
    Socket(PathBuf),
    /// A TCP listener accepts.
    Tcp(SocketAddr),
    /// `GET /healthz` answers 200.
    Health(SocketAddr),
    /// Nothing to wait for.
    Started,
}

/// One long-running service.
#[derive(Clone, Debug)]
pub struct Service {
    /// The unit name, without `.service`, for example `fstp-cell`.
    pub name: String,
    /// What it is, in a few words, for `status`.
    pub what: &'static str,
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Its environment.
    pub env: Vec<(String, OsString)>,
    /// The OS user in systemd mode.
    pub user: Option<String>,
    /// Extra lines of the `[Service]` section in systemd mode.
    pub unit_lines: Vec<String>,
    /// In direct mode: the directory that stands in for
    /// `$CREDENTIALS_DIRECTORY`.
    pub direct_credentials: Option<PathBuf>,
    /// In direct mode: keep standard input open for the life of the
    /// process, through a FIFO the process holds both ends of. The custody
    /// simulator serves until its standard input closes.
    pub hold_stdin: bool,
    /// The readiness check.
    pub ready: Ready,
    /// Units this one starts after.
    pub after: Vec<String>,
}

/// Why running something failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunFail {
    /// The program could not start.
    Spawn(PathBuf),
    /// It exited with this status (or none, for a signal).
    Exit(PathBuf, Option<i32>),
    /// The service did not get ready in time.
    NotReady(String),
    /// A file did not read or write.
    Io,
}

impl From<std::io::Error> for RunFail {
    fn from(_: std::io::Error) -> RunFail {
        RunFail::Io
    }
}

/// The children this process started in direct mode.
fn children() -> &'static std::sync::Mutex<Vec<(String, std::process::Child)>> {
    static C: std::sync::OnceLock<std::sync::Mutex<Vec<(String, std::process::Child)>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// How long a service may take to get ready.
pub const READY_TIMEOUT: Duration = Duration::from_secs(180);

/// Runs `cmd` to completion with its standard streams on the admin's log
/// file `log`, and returns its exit code.
///
/// # Errors
///
/// [`RunFail::Spawn`] when it cannot start.
pub fn run_logged(cmd: &mut Command, log: &Path) -> Result<Option<i32>, RunFail> {
    let program = PathBuf::from(cmd.get_program());
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    let err = out.try_clone()?;
    let status = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .status()
        .map_err(|_| RunFail::Spawn(program))?;
    Ok(status.code())
}

/// Runs `cmd` and requires exit status 0.
///
/// # Errors
///
/// [`RunFail::Exit`] for any other status.
pub fn run_ok(cmd: &mut Command, log: &Path) -> Result<(), RunFail> {
    let program = PathBuf::from(cmd.get_program());
    match run_logged(cmd, log)? {
        Some(0) => Ok(()),
        code => Err(RunFail::Exit(program, code)),
    }
}

/// Whether `GET /healthz` on `addr` answers 200.
#[must_use]
pub fn healthz(addr: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut head = [0u8; 12];
    s.read_exact(&mut head).is_ok() && head.get(9..12) == Some(b"200".as_slice())
}

/// Whether `ready` holds now.
#[must_use]
pub fn is_ready(ready: &Ready) -> bool {
    match ready {
        Ready::Socket(p) => {
            use std::os::unix::fs::FileTypeExt as _;
            std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
        }
        Ready::Tcp(a) => TcpStream::connect_timeout(a, Duration::from_secs(2)).is_ok(),
        Ready::Health(a) => healthz(*a),
        Ready::Started => true,
    }
}

/// The service manager of a host.
#[derive(Clone, Debug)]
pub struct Manager {
    mode: Services,
    admin: PathBuf,
    unit_dir: PathBuf,
}

impl Manager {
    /// The manager of `layout`.
    #[must_use]
    pub fn new(layout: &Layout) -> Manager {
        Manager {
            mode: layout.cfg.services,
            admin: layout.admin_dir(),
            unit_dir: layout.unit_dir().to_owned(),
        }
    }

    /// The admin's log file.
    #[must_use]
    pub fn log(&self) -> PathBuf {
        self.admin.join("logs").join("fstp-admin.log")
    }

    /// The log file of a service in direct mode.
    #[must_use]
    pub fn service_log(&self, name: &str) -> PathBuf {
        self.admin.join("logs").join(format!("{name}.log"))
    }

    fn pid_file(&self, name: &str) -> PathBuf {
        self.admin.join("pids").join(name)
    }

    fn pid(&self, name: &str) -> Option<u32> {
        std::fs::read_to_string(self.pid_file(name))
            .ok()
            .and_then(|t| t.trim().parse().ok())
    }

    fn alive(pid: u32) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn systemctl(&self, args: &[&str]) -> Result<Option<i32>, RunFail> {
        let mut c = Command::new("systemctl");
        c.args(args);
        run_logged(&mut c, &self.log())
    }

    /// Renders the systemd unit of `s`.
    #[must_use]
    pub fn unit_text(s: &Service) -> String {
        let mut t =
            String::from("# Written by fstp-admin. Edit /etc/fstp/fstp.json instead.\n[Unit]\n");
        t.push_str(&format!("Description=fstp {}\n", s.what));
        let after: Vec<String> = s.after.iter().map(|a| format!("{a}.service")).collect();
        if !after.is_empty() {
            t.push_str(&format!(
                "After={}\nRequires={}\n",
                after.join(" "),
                after.join(" ")
            ));
        }
        t.push_str("\n[Service]\nType=simple\n");
        if let Some(u) = &s.user {
            t.push_str(&format!("User={u}\n"));
        }
        for (k, v) in &s.env {
            t.push_str(&format!("Environment={k}={}\n", v.to_string_lossy()));
        }
        let mut exec = vec![s.program.display().to_string()];
        exec.extend(s.args.iter().map(|a| a.to_string_lossy().into_owned()));
        t.push_str(&format!("ExecStart={}\n", exec.join(" ")));
        for l in &s.unit_lines {
            t.push_str(l);
            t.push('\n');
        }
        t.push_str("Restart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nNoNewPrivileges=yes\nPrivateTmp=yes\n\n[Install]\nWantedBy=multi-user.target\n");
        t
    }

    /// Writes the unit of `s` (systemd mode) and starts it, then waits
    /// until it is ready. A running, ready service is left alone.
    ///
    /// # Errors
    ///
    /// [`RunFail`] when it does not start or get ready.
    pub fn ensure(&self, s: &Service) -> Result<bool, RunFail> {
        match self.mode {
            Services::Systemd => {
                let path = self.unit_dir.join(format!("{}.service", s.name));
                let text = Self::unit_text(s);
                let same = std::fs::read_to_string(&path).is_ok_and(|t| t == text);
                if !same {
                    write_atomic(&path, text.as_bytes(), 0o644)?;
                    self.systemctl(&["daemon-reload"])?;
                }
                if same && self.running(s) && is_ready(&s.ready) {
                    return Ok(false);
                }
                self.systemctl(&["enable", &format!("{}.service", s.name)])?;
                let verb = if same { "start" } else { "restart" };
                match self.systemctl(&[verb, &format!("{}.service", s.name)])? {
                    Some(0) => {}
                    code => return Err(RunFail::Exit(PathBuf::from("systemctl"), code)),
                }
            }
            Services::Direct => {
                if self.running(s) && is_ready(&s.ready) {
                    return Ok(false);
                }
                self.stop(s)?;
                if let Ready::Socket(p) = &s.ready {
                    let _ = std::fs::remove_file(p);
                }
                let log = self.service_log(&s.name);
                if let Some(dir) = log.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let out = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)?;
                let err = out.try_clone()?;
                let mut c = Command::new(&s.program);
                let stdin = if s.hold_stdin {
                    let fifo = self.pid_file(&format!("{}.stdin", s.name));
                    let _ = std::fs::remove_file(&fifo);
                    if let Some(dir) = fifo.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    run_ok(
                        Command::new("mkfifo").arg("-m").arg("600").arg(&fifo),
                        &self.log(),
                    )?;
                    // Both ends in the child: its reads block and never end.
                    Stdio::from(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&fifo)?,
                    )
                } else {
                    Stdio::null()
                };
                c.args(&s.args)
                    .stdin(stdin)
                    .stdout(Stdio::from(out))
                    .stderr(Stdio::from(err));
                for (k, v) in &s.env {
                    c.env(k, v);
                }
                if let Some(d) = &s.direct_credentials {
                    c.env("CREDENTIALS_DIRECTORY", d);
                }
                let child = c.spawn().map_err(|_| RunFail::Spawn(s.program.clone()))?;
                write_atomic(
                    &self.pid_file(&s.name),
                    child.id().to_string().as_bytes(),
                    0o600,
                )?;
                // The child outlives this process. While this process runs,
                // it keeps the handle, so an exited child counts as stopped.
                children()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((s.name.clone(), child));
            }
        }
        self.wait_ready(s)?;
        Ok(true)
    }

    /// Waits until `s` is ready, or [`READY_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`RunFail::NotReady`] when it stopped or did not get ready.
    pub fn wait_ready(&self, s: &Service) -> Result<(), RunFail> {
        let begun = Instant::now();
        loop {
            if is_ready(&s.ready) {
                return Ok(());
            }
            if !self.running(s) || begun.elapsed() > READY_TIMEOUT {
                return Err(RunFail::NotReady(s.name.clone()));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether `s` runs.
    #[must_use]
    pub fn running(&self, s: &Service) -> bool {
        match self.mode {
            Services::Systemd => self
                .systemctl(&["is-active", "--quiet", &format!("{}.service", s.name)])
                .is_ok_and(|c| c == Some(0)),
            Services::Direct => {
                let mut kids = children()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some((_, c)) = kids.iter_mut().rev().find(|(n, _)| *n == s.name) {
                    return matches!(c.try_wait(), Ok(None));
                }
                drop(kids);
                self.pid(&s.name).is_some_and(Self::alive)
            }
        }
    }

    /// Stops `s` and waits until it is gone.
    ///
    /// # Errors
    ///
    /// [`RunFail`] when it does not stop.
    pub fn stop(&self, s: &Service) -> Result<(), RunFail> {
        match self.mode {
            Services::Systemd => {
                self.systemctl(&["stop", &format!("{}.service", s.name)])?;
                Ok(())
            }
            Services::Direct => {
                let Some(pid) = self.pid(&s.name) else {
                    return Ok(());
                };
                if Self::alive(pid) {
                    // The kill signal of the unit, as systemd would send it:
                    // PostgreSQL stops fast on SIGINT, while SIGTERM waits
                    // for every client (lane m10/backup-health).
                    let signal = if s.unit_lines.iter().any(|l| l == "KillSignal=SIGINT") {
                        "-INT"
                    } else {
                        "-TERM"
                    };
                    let _ = Command::new("kill")
                        .arg(signal)
                        .arg(pid.to_string())
                        .status();
                    let begun = Instant::now();
                    while Self::alive(pid) {
                        if begun.elapsed() > Duration::from_secs(40) {
                            let _ = Command::new("kill")
                                .arg("-KILL")
                                .arg(pid.to_string())
                                .status();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                let _ = std::fs::remove_file(self.pid_file(&s.name));
                Ok(())
            }
        }
    }

    /// Writes a systemd timer that runs `fstp-admin <args>` on `calendar`.
    /// Direct mode has no timers.
    ///
    /// # Errors
    ///
    /// [`RunFail`] when a unit does not write or start.
    pub fn timer(
        &self,
        name: &str,
        admin: &Path,
        args: &str,
        calendar: &str,
    ) -> Result<(), RunFail> {
        if self.mode != Services::Systemd {
            return Ok(());
        }
        let service = format!(
            "# Written by fstp-admin.\n[Unit]\nDescription=fstp-admin {args}\n\n[Service]\nType=oneshot\nExecStart={} {args}\n",
            admin.display()
        );
        let timer = format!(
            "# Written by fstp-admin.\n[Unit]\nDescription=fstp-admin {args}\n\n[Timer]\nOnCalendar={calendar}\nPersistent=true\nRandomizedDelaySec=300\n\n[Install]\nWantedBy=timers.target\n"
        );
        write_atomic(
            &self.unit_dir.join(format!("{name}.service")),
            service.as_bytes(),
            0o644,
        )?;
        write_atomic(
            &self.unit_dir.join(format!("{name}.timer")),
            timer.as_bytes(),
            0o644,
        )?;
        self.systemctl(&["daemon-reload"])?;
        self.systemctl(&["enable", "--now", &format!("{name}.timer")])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-028 "Services": a unit names its user, environment, program and
    /// order, and restarts on failure.
    #[test]
    fn adr028_unit_text_names_user_env_and_order() {
        let s = Service {
            name: "fstp-cell".into(),
            what: "cell",
            program: "/usr/local/bin/fstp-cell".into(),
            args: vec![],
            env: vec![("FSTP_CELL_CONFIG".into(), "/etc/fstp/cell.json".into())],
            user: Some("fstp-cell".into()),
            unit_lines: vec![],
            direct_credentials: None,
            hold_stdin: false,
            ready: Ready::Started,
            after: vec!["fstp-vault".into()],
        };
        let t = Manager::unit_text(&s);
        assert!(t.contains("User=fstp-cell\n"));
        assert!(t.contains("Environment=FSTP_CELL_CONFIG=/etc/fstp/cell.json\n"));
        assert!(t.contains("ExecStart=/usr/local/bin/fstp-cell\n"));
        assert!(t.contains("After=fstp-vault.service\n"));
        assert!(t.contains("Restart=on-failure\n"));
    }
}
