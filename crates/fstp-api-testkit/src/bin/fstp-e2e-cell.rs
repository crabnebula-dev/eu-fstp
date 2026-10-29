//! `fstp-e2e-cell`, the M4 end-to-end test cell (design section 1.2). Test
//! only. Lane W5 (L-E2E) owns this file. In the demo path, lane W3b writes
//! it, and its test author wrote the smoke test and the declarations below.
//!
//! The cell is the `fstp-cell` library with a controllable clock, the
//! synthetic vault, recording-fake probes and the synthetic legal-wording
//! profile, serving the `fstp-web` routes on one loopback listener.
//! Playwright (`e2e/`) drives it, and moves deadlines through its clock
//! route.
//!
//! Status: [`start`] refuses here, so the binary exits with status 2.
//! Lane W3b wrote the full cell and ran it on an integration overlay of
//! this branch with `m4/app`. It waits for three changes the lead owns:
//!
//! - `fstp-http` as a dependency of `fstp-api-testkit`, for the server;
//! - the `fstp_web::router` of lane W4e, with its `call_core` wired to
//!   `fstp_api_core::decode::decode_route` and `ApiCore::dispatch`;
//! - the dispatch seams of `port.rs`, which the fake ports need.
//!
//! The full cell serves the `fstp-web` routes over the fake ports, with
//! control routes under `/__e2e/` for login, the clock, step-ups and the
//! synthetic world. The W3b report names the patch that holds it.

use std::net::SocketAddr;
use std::process::ExitCode;

use fstp_api_testkit::NotImplemented;

/// What the e2e cell listens on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Config {
    /// The loopback address of the one listener. Port 0 picks a free port.
    listen: SocketAddr,
}

impl Config {
    /// A loopback listener on a free port.
    fn loopback() -> Config {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }

    /// The configuration from the arguments: `--listen <address>`, or the
    /// loopback default. Any other argument is refused.
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
        let mut cfg = Config::loopback();
        let mut args = args.into_iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "--listen" => {
                    let v = args.next().ok_or("--listen needs an address")?;
                    let addr: SocketAddr = v.parse().map_err(|_| format!("bad address {v}"))?;
                    if !addr.ip().is_loopback() {
                        return Err(format!("{addr} is not a loopback address"));
                    }
                    cfg.listen = addr;
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(cfg)
    }
}

/// A running e2e cell. It serves until dropped.
#[derive(Debug)]
struct Running {
    /// The address it listens on.
    addr: SocketAddr,
}

/// Starts the e2e cell on `cfg.listen`, serving the `fstp-web` routes over
/// the I-85 world of `fstp_api_testkit::fake::fixture` on the fake ports.
/// It returns once the listener accepts connections.
///
/// It refuses until the lead applies the seams of the module
/// documentation. It never starts a cell without them.
fn start(cfg: &Config) -> Result<Running, NotImplemented> {
    let _ = cfg.listen;
    Err(NotImplemented::new("fstp-e2e-cell::start"))
}

fn main() -> ExitCode {
    let Ok(cfg) = Config::from_args(std::env::args().skip(1)) else {
        return ExitCode::from(64);
    };
    match start(&cfg) {
        Ok(running) => {
            let _ = running.addr;
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::from(2),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// R-PB-01, design sections 1.2 and 8.7: the e2e cell starts on a
    /// loopback port and answers one read. `GET /api/v1/calls` lists the
    /// open calls, public data that needs no session, as JSON.
    #[test]
    fn r_pb_01_e2e_cell_starts_and_answers_one_read() {
        let running = start(&Config::loopback()).unwrap_or_else(|e| panic!("{e}"));
        assert!(running.addr.ip().is_loopback());
        let mut s = TcpStream::connect(running.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(
            b"GET /api/v1/calls HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        let text = String::from_utf8_lossy(&reply);
        assert!(text.starts_with("HTTP/1.1 200"), "the reply: {text}");
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "the reply head: {head}"
        );
        assert!(
            fstp_json::parse_str(body.trim()).is_ok()
                || head.to_ascii_lowercase().contains("chunked"),
            "the body is not JSON: {body}"
        );
    }

    /// The arguments: only a loopback `--listen` address is taken.
    #[test]
    fn e2e_cell_takes_only_a_loopback_listen_address() {
        let ok = Config::from_args(["--listen".to_owned(), "127.0.0.1:8443".to_owned()]).unwrap();
        assert_eq!(ok.listen.port(), 8443);
        assert!(Config::from_args(["--listen".to_owned(), "0.0.0.0:1".to_owned()]).is_err());
        assert!(Config::from_args(["--other".to_owned()]).is_err());
        assert_eq!(Config::from_args(Vec::new()).unwrap(), Config::loopback());
    }
}
