//! Real handshakes between an `fstp-tls` client and an `fstp-tls` server
//! over an in-memory pipe (M3 design section 15, `client_hello_sni`).
//!
//! The client's transport is tapped, so a capture holds every byte the
//! client sent, starting with its ClientHello. The server reports the SNI
//! it saw. That report is the oracle of the `client_hello_sni`
//! differential. The server half lives only in tests and fuzz targets,
//! which the rule 5 scan does not read: the shipped edge holds no TLS
//! server (design section 2.4 rule 5).
//!
//! The fuzz project includes this file too.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join};
use fstp_rt::{AsyncRead, AsyncWrite};
use fstp_tls::{ClientConfig, ServerConfig, accept, connect};

const CA: &[u8] = include_bytes!("../../../fstp-tls/testdata/ca.pem");
const SERVER: &[u8] = include_bytes!("../../../fstp-tls/testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../../fstp-tls/testdata/server-key.pem");

/// Names the test server certificate covers. Its SAN holds `localhost`,
/// `127.0.0.1` and `::1` (see `crates/fstp-tls/testdata/gen.sh`). DNS
/// names compare without case, so each spelling below completes a
/// handshake.
pub(crate) const DNS_NAMES: [&str; 4] = ["localhost", "LOCALHOST", "LocalHost", "lOcAlHoSt"];
/// Address names. A TLS client sends no SNI for them (RFC 6066 section 3).
pub(crate) const IP_NAMES: [&str; 2] = ["127.0.0.1", "::1"];

/// One completed handshake.
#[derive(Clone, Debug)]
pub(crate) struct Capture {
    /// The name the client connected to.
    pub(crate) name: String,
    /// Every byte the client wrote, in order.
    pub(crate) client_bytes: Vec<u8>,
    /// The SNI the `fstp-tls` server reported.
    pub(crate) server_sni: Option<String>,
}

impl Capture {
    /// The client's first record, which holds its ClientHello.
    pub(crate) fn first_record(&self) -> &[u8] {
        let n = crate::hello::first_record_len(&self.client_bytes)
            .expect("the capture holds a record header");
        self.client_bytes
            .get(..n)
            .expect("the capture holds the first record")
    }
}

/// A transport that records every byte written through it.
struct Tap {
    inner: DuplexStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            let written = buf.get(..*n).expect("a write reports at most its input");
            this.log.lock().unwrap().extend_from_slice(written);
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Runs one full handshake to `name` and returns what the client sent and
/// what the server reported.
pub(crate) fn handshake(name: &str) -> Capture {
    let client_cfg = ClientConfig::new(CA).expect("test CA loads");
    let server_cfg = ServerConfig::new(SERVER, SERVER_KEY).expect("test server loads");
    let (c, s) = duplex(64 * 1024);
    let log = Arc::new(Mutex::new(Vec::new()));
    let tap = Tap {
        inner: c,
        log: Arc::clone(&log),
    };
    let (client, server) = block_on(join(
        connect(&client_cfg, name, tap),
        accept(&server_cfg, s),
    ));
    let client = client.unwrap_or_else(|e| panic!("client handshake to {name}: {e}"));
    let server = server.unwrap_or_else(|e| panic!("server handshake for {name}: {e}"));
    let server_sni = server.sni().map(str::to_owned);
    drop(client);
    let client_bytes = log.lock().unwrap().clone();
    Capture {
        name: name.to_owned(),
        client_bytes,
        server_sni,
    }
}
