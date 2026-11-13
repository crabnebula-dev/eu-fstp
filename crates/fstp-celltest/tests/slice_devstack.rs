//! Smoke test of the `fstp-devstack` binary (design section 0.1 "A
//! runnable stack early", section 2.3 and step W3b of section 19).
//!
//! The binary starts one SaaS-mode world on localhost: the clusters, a
//! cell, its vault and the witness. On standard output it prints one line
//! `<name> <url>` for each of `cell`, `vault`, `witness`, `health` and
//! `enrol`, then the line `ready`. It stops cleanly on SIGTERM. Other
//! lines are allowed and ignored.
//!
//! The test runs `fstp-devstack --resolver-rules`, so it needs no port
//! 443 (M3 exit audit section 7, item 7, Daniel 2026-11-13). The stack
//! then prints the exact origins with no port and a line `resolver
//! <rules>` in the form of Chromium's `--host-resolver-rules`. The test
//! applies those rules as a browser started with them would.
//!
//! Lane W3b wrote this test before the production code. It is red while
//! the binary refuses to start.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the stack may take to print `ready`. It starts four
/// PostgreSQL clusters first.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

/// How long the stack may take to stop after SIGTERM: the cell's drain
/// deadline (`fstp_cell::engine::serve::DRAIN_DEADLINE`) and a margin.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// The URL lines the stack prints before `ready`.
const NAMES: [&str; 5] = ["cell", "vault", "witness", "health", "enrol"];

/// A running stack. Dropping it kills the process, so a failed test leaves
/// no stack behind.
struct Stack {
    child: std::process::Child,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
}

impl Drop for Stack {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Stack {
    fn start() -> Stack {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fstp-devstack"))
            .arg("--resolver-rules")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("fstp-devstack did not spawn: {e}"));
        let stdout = child.stdout.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf));
        });
        Stack {
            child,
            lines,
            stderr,
        }
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The URL lines printed before `ready`, and the `resolver` line.
    fn ready(&mut self) -> BTreeMap<String, String> {
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut urls = BTreeMap::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line == "ready" => return urls,
                Ok(line) => {
                    if let Some((name, url)) = line.split_once(' ')
                        && (NAMES.contains(&name) || name == "resolver")
                    {
                        urls.insert(name.to_owned(), url.to_owned());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("fstp-devstack printed no ready line in {READY_TIMEOUT:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.wait(STOP_TIMEOUT);
                    // Let the stderr reader drain.
                    std::thread::sleep(Duration::from_millis(200));
                    panic!(
                        "fstp-devstack stopped before ready ({status:?}): {}",
                        self.stderr()
                    );
                }
            }
        }
    }

    /// Waits up to `limit` for the process to exit.
    fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Sends SIGTERM through `kill`, which every supported host has.
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap_or_else(|e| panic!("kill did not run: {e}"));
        assert!(status.success(), "kill -TERM failed: {status:?}");
    }
}

/// The socket address of an `http://<ip>:<port>/...` URL.
fn http_addr(url: &str) -> SocketAddr {
    let rest = url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("{url} is not an http URL"));
    let authority = rest.split('/').next().unwrap_or_default();
    authority
        .parse()
        .unwrap_or_else(|_| panic!("{url} does not name an IP address and port"))
}

/// The host of an `https://<host>[:port]/...` URL.
fn https_host(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .unwrap_or_else(|| panic!("{url} is not an https URL"));
    let authority = rest.split('/').next().unwrap_or_default();
    authority
        .rsplit_once(':')
        .map_or(authority, |(h, _)| h)
        .to_owned()
}

/// The host and port of an `http://` or `https://` URL. A missing port is
/// the scheme's default. An IPv6 host loses its brackets.
fn host_port(url: &str) -> (String, u16) {
    let (rest, default) = if let Some(rest) = url.strip_prefix("https://") {
        (rest, 443)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (rest, 80)
    } else {
        panic!("{url} is not an http or https URL")
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6
            .split_once(']')
            .unwrap_or_else(|| panic!("{url} has an unclosed IPv6 host"));
        let port = after.strip_prefix(':').map_or(default, |p| {
            p.parse().unwrap_or_else(|_| panic!("{url}: bad port"))
        });
        return (host.to_owned(), port);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse().unwrap_or_else(|_| panic!("{url}: bad port")),
        ),
        None => (authority.to_owned(), default),
    }
}

/// The resolver rules of a `resolver` line: `MAP <host> <ip>:<port>`
/// entries separated by commas, as Chromium's `--host-resolver-rules`
/// takes them. Every entry must have that form.
fn resolver_rules(line: &str) -> BTreeMap<String, SocketAddr> {
    line.split(',')
        .map(|rule| {
            let mut words = rule.split_whitespace();
            match (words.next(), words.next(), words.next(), words.next()) {
                (Some("MAP"), Some(host), Some(to), None) => (
                    host.to_ascii_lowercase(),
                    to.parse()
                        .unwrap_or_else(|_| panic!("resolver rule {rule:?}: bad address")),
                ),
                _ => panic!("resolver rule {rule:?} is not MAP <host> <address>"),
            }
        })
        .collect()
}

/// The addresses a browser on this host, started with `rules`, reaches
/// `host:port` at. A host that a rule maps is reached at its address
/// only. An IP literal is itself. `localhost` and every name under
/// `.localhost` are loopback by RFC 6761 section 6.3, which browsers
/// apply without asking the resolver. Any other name goes to the system
/// resolver.
fn reached_at(host: &str, port: u16, rules: &BTreeMap<String, SocketAddr>) -> Vec<SocketAddr> {
    if let Some(to) = rules.get(&host.to_ascii_lowercase()) {
        return vec![*to];
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ];
    }
    (host, port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default()
}

/// The host's own non-loopback interface addresses, one per family that
/// has a route: the source address of a UDP socket connected towards a
/// documentation address (RFC 5737, RFC 3849). Connecting a UDP socket
/// sends nothing.
fn interface_addresses() -> Vec<IpAddr> {
    let probes: [(SocketAddr, SocketAddr); 2] = [
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9),
        ),
        (
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9,
            ),
        ),
    ];
    let mut out = Vec::new();
    for (bind, towards) in probes {
        let Ok(socket) = UdpSocket::bind(bind) else {
            continue;
        };
        if socket.connect(towards).is_err() {
            continue;
        }
        if let Ok(local) = socket.local_addr()
            && !local.ip().is_loopback()
            && !local.ip().is_unspecified()
        {
            out.push(local.ip());
        }
    }
    out
}

/// The longest run of lowercase hexadecimal digits in `s`.
fn longest_hex_run(s: &str) -> usize {
    let (mut best, mut run) = (0, 0);
    for b in s.bytes() {
        if matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// One `GET <path>` over plain HTTP/1.1: the status and the body. A
/// chunked body is decoded.
fn http_get(addr: SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("no connection to {addr}: {e}"));
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end in {:?}", String::from_utf8_lossy(&raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut body = raw[split + 4..].to_vec();
    let status: u16 = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    let field = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_owned())
        })
    };
    if field("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut out = Vec::new();
        let mut rest = body.as_slice();
        loop {
            let end = rest.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&rest[..end])
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim(),
                16,
            )
            .unwrap();
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        body = out;
    } else if let Some(len) = field("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.truncate(len);
    }
    (status, body)
}

/// Design sections 2.3 and 9.5, R-NF-05, ADR-002 and ADR-009: the dev
/// stack prints the cell, vault origin, witness and health URLs and an
/// enrolment link, then `ready`. The vault origin is `id.<cell host>`.
/// The enrolment link is on the cell origin and carries a random token
/// of at least 256 bits, so the stack has no default credential. Its
/// path is a `GET` of the cell's page table
/// (`fstp_cell::routes::page_table`), so the link opens a page. The page
/// table stays apart from the design section 8.7 table, as I-78 and
/// Daniel's decision of 2026-11-13 (M3 exit audit section 7, item 7)
/// keep it. The cell and vault hosts are reached through the printed
/// resolver rules. Every printed URL is reached on loopback only (design
/// section 2.3 table, "Loopback"): its host is loopback, a listener
/// accepts there, and no listener accepts on the port at the host's
/// own interface addresses. The loopback health listener answers
/// `GET /healthz` with the cell's fixed body. On SIGTERM the stack
/// drains and exits with success, and the health listener is gone.
#[test]
fn slice_devstack_serves_healthz_and_stops_on_sigterm() {
    let mut stack = Stack::start();
    let urls = stack.ready();
    for name in NAMES {
        assert!(
            urls.contains_key(name),
            "fstp-devstack printed no {name} URL: {urls:?}"
        );
    }

    let cell_host = https_host(&urls["cell"]);
    assert_eq!(
        https_host(&urls["vault"]),
        format!("id.{cell_host}"),
        "the vault origin is not id.<cell host>: {urls:?}"
    );
    assert!(
        urls["enrol"].starts_with(urls["cell"].trim_end_matches('/')),
        "the enrolment link is not on the cell origin: {urls:?}"
    );
    assert!(
        longest_hex_run(&urls["enrol"]) >= 64,
        "R-NF-05: the enrolment link carries no random token of 256 bits: {}",
        urls["enrol"]
    );
    let enrol_path = urls["enrol"]
        .strip_prefix(urls["cell"].trim_end_matches('/'))
        .and_then(|rest| rest.split(['#', '?']).next())
        .unwrap_or_default()
        .to_owned();
    assert!(
        fstp_cell::routes::page_table()
            .iter()
            .any(|r| matches!(r.parts(), ("GET", p, _) if p == enrol_path)),
        "the enrolment link opens {enrol_path:?}, a page the cell's page table does not serve"
    );

    let rules = urls
        .get("resolver")
        .map(|line| resolver_rules(line))
        .unwrap_or_default();
    for name in ["cell", "vault"] {
        let host = https_host(&urls[name]);
        assert!(
            rules.contains_key(&host),
            "the resolver rules {rules:?} do not map the {name} host {host}"
        );
    }

    let interfaces = interface_addresses();
    for name in ["cell", "vault", "witness", "health"] {
        let (host, port) = host_port(&urls[name]);
        let addrs = reached_at(&host, port, &rules);
        assert!(
            !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()),
            "design section 2.3: the {name} URL {} is not reached on loopback only: {addrs:?}",
            urls[name]
        );
        assert!(
            addrs
                .iter()
                .any(|a| TcpStream::connect_timeout(a, Duration::from_secs(5)).is_ok()),
            "no listener accepts at the {name} URL {} ({addrs:?})",
            urls[name]
        );
        for (ip, at_port) in interfaces
            .iter()
            .flat_map(|ip| addrs.iter().map(move |a| (ip, a.port())))
        {
            let at = SocketAddr::new(*ip, at_port);
            assert!(
                TcpStream::connect_timeout(&at, Duration::from_secs(2)).is_err(),
                "design section 2.3: a listener on the {name} port accepts at the interface address {at}"
            );
        }
    }

    let health = http_addr(&urls["health"]);
    assert!(
        health.ip().is_loopback(),
        "ADR-009: the health listener is not on loopback: {health}"
    );
    let (status, body) = http_get(health, "/healthz");
    assert_eq!(
        (status, body.as_slice()),
        (200, fstp_cell::http::front::HEALTH_BODY),
        "GET /healthz on the health listener"
    );

    stack.terminate();
    let status = stack
        .wait(STOP_TIMEOUT)
        .unwrap_or_else(|| panic!("fstp-devstack did not stop within {STOP_TIMEOUT:?} of SIGTERM"));
    assert!(
        status.success(),
        "fstp-devstack did not stop cleanly on SIGTERM ({status:?}): {}",
        stack.stderr()
    );
    assert!(
        TcpStream::connect_timeout(&health, Duration::from_secs(2)).is_err(),
        "the health listener still accepts connections after the stack stopped"
    );
}
