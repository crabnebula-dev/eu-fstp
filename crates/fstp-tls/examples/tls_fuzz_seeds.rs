//! Regenerates the seed inputs of the fstp-tls fuzz targets.
//!
//! Seed groups, each selected by its name on the command line (default:
//! all of them):
//!
//! - `handshakes`: runs real handshakes over the in-memory duplex, records
//!   the bytes each side receives, and writes them with a few IO timing
//!   variants. The hostile-peer targets start from these to reach deep
//!   handshake states sooner. The bytes differ on every run.
//! - `fragmented`: one handshake message split into small records, larger
//!   than rustls's 64 KiB handshake buffer. These seeds also raise
//!   libFuzzer's default input length limit above that buffer size.
//! - `round-trip`: control inputs for `tls_round_trip` that cover clean
//!   sessions, backpressure, aborts, corruption, cuts, a stalled handshake
//!   and resumed sessions. They are the same on every run.
//!
//! Usage: `cargo run -p fstp-tls --example tls_fuzz_seeds -- [GROUP]...`

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join};
use fstp_rt::{AsyncRead, AsyncWrite, IoExt};
use fstp_tls::{ClientConfig, ServerConfig, accept, connect};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Records every byte read through it.
struct Recorder {
    inner: DuplexStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Recorder {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            log.extend(buf.iter().take(*n));
        }
        res
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn testdata(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(std::fs::read(Path::new(DIR).join("testdata").join(name))?)
}

/// Runs one session and returns (bytes the client read, bytes the server read).
fn record(client: &ClientConfig, server: &ServerConfig) -> (Vec<u8>, Vec<u8>) {
    let (c, s) = duplex(1 << 16);
    let client_log = Arc::new(Mutex::new(Vec::new()));
    let server_log = Arc::new(Mutex::new(Vec::new()));
    let c = Recorder {
        inner: c,
        log: client_log.clone(),
    };
    let s = Recorder {
        inner: s,
        log: server_log.clone(),
    };
    block_on(async {
        let (cr, sr) = join(connect(client, "localhost", c), accept(server, s)).await;
        if let (Ok(mut c), Ok(mut s)) = (cr, sr) {
            let client_side = async {
                let _ = c.write_all(b"seed request").await;
                let _ = c.shutdown().await;
                let mut out = Vec::new();
                let _ = c.read_to_end(&mut out, 1024).await;
            };
            let server_side = async {
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out, 1024).await;
                let _ = s.write_all(b"seed response").await;
                let _ = s.shutdown().await;
            };
            join(client_side, server_side).await;
        }
    });
    let take =
        |log: &Arc<Mutex<Vec<u8>>>| log.lock().unwrap_or_else(PoisonError::into_inner).clone();
    (take(&client_log), take(&server_log))
}

/// Writes `body` with several control prefixes (see
/// `fstp_rt::scripted::ScriptedStream::from_fuzz_input`).
fn write_variants(dir: &Path, name: &str, body: &[u8]) -> Result<(), Box<dyn Error>> {
    let variants: [(&str, [u8; 3]); 3] = [
        ("whole", [0xFF, 0x00, 0xFF]),
        ("bytewise", [0x00, 0x00, 0x00]),
        ("pending", [0x0F, 0xA5, 0x03]),
    ];
    for (tag, ctrl) in variants {
        let mut seed = ctrl.to_vec();
        seed.extend_from_slice(body);
        std::fs::write(dir.join(format!("{name}-{tag}")), seed)?;
    }
    Ok(())
}

/// A handshake message of type `msg_type` with a zero body of `len` bytes,
/// split into handshake records of at most `frag` payload bytes each.
fn fragmented_handshake(msg_type: u8, len: u32, frag: usize) -> Vec<u8> {
    let mut msg = vec![msg_type];
    msg.extend_from_slice(len.to_be_bytes().get(1..).unwrap_or_default());
    msg.resize(
        msg.len().saturating_add(usize::try_from(len).unwrap_or(0)),
        0,
    );
    let mut out = Vec::new();
    for chunk in msg.chunks(frag.max(1)) {
        out.extend_from_slice(&[22, 3, 3]);
        let n = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

fn write_fragmented(client_dir: &Path, server_dir: &Path) -> Result<(), Box<dyn Error>> {
    // Records of 255 bytes, then of 1 byte. Both overflow the buffer.
    for (tag, ctrl, len, frag) in [
        ("whole", [0xFF, 0x00, 0xFF], 65_000u32, 255usize),
        ("pending", [0x0F, 0xA5, 0x03], 11_000, 1),
    ] {
        for (dir, msg_type) in [(server_dir, 1u8), (client_dir, 2u8)] {
            let mut seed = ctrl.to_vec();
            seed.extend(fragmented_handshake(msg_type, len, frag));
            std::fs::write(dir.join(format!("fragmented-hello-{tag}")), seed)?;
        }
    }
    Ok(())
}

/// One `tls_round_trip` header (see `tests/support/round_trip.rs`).
struct RoundTrip {
    capacity: u8,
    client: [u8; 4],
    client_len: u16,
    server: [u8; 4],
    server_len: u16,
    faults: u8,
    tamper_at: u32,
    tamper_bit: u8,
    cut_at: u32,
}

impl RoundTrip {
    fn plain(client_len: u16, server_len: u16) -> Self {
        Self {
            capacity: 0x80,
            client: [0xFF, 0xFF, 0, 0],
            client_len,
            server: [0xFF, 0xFF, 0, 0],
            server_len,
            faults: 0,
            tamper_at: 0,
            tamper_bit: 0,
            cut_at: 0,
        }
    }

    fn encode(&self, tape: &[u8]) -> Vec<u8> {
        let mut out = vec![self.capacity];
        out.extend_from_slice(&self.client);
        out.extend_from_slice(&self.client_len.to_be_bytes());
        out.extend_from_slice(&self.server);
        out.extend_from_slice(&self.server_len.to_be_bytes());
        out.push(self.faults);
        out.extend_from_slice(self.tamper_at.to_be_bytes().get(1..).unwrap_or_default());
        out.push(self.tamper_bit);
        out.extend_from_slice(self.cut_at.to_be_bytes().get(1..).unwrap_or_default());
        out.extend_from_slice(tape);
        out
    }
}

fn write_round_trip(dir: &Path) -> Result<(), Box<dyn Error>> {
    // A tape with spurious polls, small and large IO sizes and flushes.
    let mixed: Vec<u8> = (0u8..=255).map(|i| i.wrapping_mul(37) ^ 0x5A).collect();
    let mut seeds: Vec<(&str, RoundTrip, Vec<u8>)> = Vec::new();
    seeds.push(("complete-plain", RoundTrip::plain(1000, 2000), Vec::new()));
    seeds.push((
        "complete-mixed-tape",
        RoundTrip::plain(3000, 3000),
        mixed.clone(),
    ));
    // Both payloads exceed rustls's 64 KiB send buffer plus the pipe.
    let mut rt = RoundTrip::plain(0xFFFF, 0xC000);
    rt.capacity = 63;
    rt.client[3] = 0x08;
    rt.server[3] = 0x08;
    seeds.push(("complete-backpressure", rt, Vec::new()));
    let mut rt = RoundTrip::plain(300, 300);
    rt.capacity = 0;
    rt.client = [0, 0, 0xA5, 0];
    rt.server = [0, 0, 0x5A, 0];
    seeds.push(("complete-bytewise-pending", rt, mixed.clone()));
    let mut rt = RoundTrip::plain(5000, 7000);
    rt.server[3] = 0x04;
    seeds.push(("complete-read-first-server", rt, Vec::new()));
    let mut rt = RoundTrip::plain(6000, 4000);
    rt.client[3] = 0x02;
    seeds.push(("truncated-client-aborts-flushed", rt, Vec::new()));
    let mut rt = RoundTrip::plain(3000, 20_000);
    rt.capacity = 63;
    rt.server[3] = 0x03;
    seeds.push(("truncated-server-aborts-unflushed", rt, Vec::new()));
    let mut rt = RoundTrip::plain(4000, 4000);
    rt.faults = 0x04;
    rt.cut_at = 5000;
    seeds.push(("truncated-cut-client-to-server", rt, Vec::new()));
    let mut rt = RoundTrip::plain(4000, 4000);
    rt.faults = 0x08;
    rt.cut_at = 5000;
    seeds.push(("truncated-cut-server-to-client", rt, Vec::new()));
    let mut rt = RoundTrip::plain(20_000, 2000);
    rt.faults = 0x01;
    rt.tamper_at = 15_000;
    seeds.push(("failure-tamper-client-to-server", rt, Vec::new()));
    let mut rt = RoundTrip::plain(2000, 20_000);
    rt.faults = 0x02;
    rt.tamper_at = 15_000;
    rt.tamper_bit = 5;
    seeds.push(("failure-tamper-server-to-client", rt, mixed.clone()));
    // Corrupts the length of the first record, the ClientHello, so that
    // both sides wait for each other.
    let mut rt = RoundTrip::plain(100, 100);
    rt.faults = 0x01;
    rt.tamper_at = 3;
    rt.tamper_bit = 3;
    seeds.push(("stalled-handshake", rt, Vec::new()));
    // Faults bit 4 runs a clean session first, so these resume (P2).
    let mut rt = RoundTrip::plain(1000, 2000);
    rt.faults = 0x10;
    seeds.push(("complete-resumed", rt, Vec::new()));
    let mut rt = RoundTrip::plain(300, 300);
    rt.capacity = 0;
    rt.client = [0, 0, 0xA5, 0];
    rt.server = [0, 0, 0x5A, 0];
    rt.faults = 0x10;
    seeds.push(("complete-resumed-bytewise-pending", rt, mixed.clone()));
    let mut rt = RoundTrip::plain(20_000, 2000);
    rt.faults = 0x11;
    rt.tamper_at = 15_000;
    seeds.push(("failure-resumed-tamper-client-to-server", rt, Vec::new()));
    let mut rt = RoundTrip::plain(4000, 4000);
    rt.faults = 0x18;
    rt.cut_at = 5000;
    seeds.push(("truncated-resumed-cut-server-to-client", rt, mixed));
    for (name, rt, tape) in seeds {
        std::fs::write(dir.join(name), rt.encode(&tape))?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let groups: Vec<String> = std::env::args().skip(1).collect();
    let wanted = |g: &str| groups.is_empty() || groups.iter().any(|a| a == g);
    let client_dir: PathBuf = Path::new(DIR).join("fuzz/seeds/tls_client_hostile_server");
    let server_dir: PathBuf = Path::new(DIR).join("fuzz/seeds/tls_server_hostile_client");
    let round_trip_dir: PathBuf = Path::new(DIR).join("fuzz/seeds/tls_round_trip");
    std::fs::create_dir_all(&client_dir)?;
    std::fs::create_dir_all(&server_dir)?;
    std::fs::create_dir_all(&round_trip_dir)?;
    if wanted("handshakes") {
        write_handshakes(&client_dir, &server_dir)?;
    }
    if wanted("fragmented") {
        write_fragmented(&client_dir, &server_dir)?;
    }
    if wanted("round-trip") {
        write_round_trip(&round_trip_dir)?;
    }
    println!(
        "wrote seeds under {}",
        Path::new(DIR).join("fuzz/seeds").display()
    );
    Ok(())
}

fn write_handshakes(client_dir: &Path, server_dir: &Path) -> Result<(), Box<dyn Error>> {
    let ca = testdata("ca.pem")?;
    let client_pem = testdata("client.pem")?;
    let client_key = testdata("client-key.pem")?;
    let server_pem = testdata("server.pem")?;
    let server_key = testdata("server-key.pem")?;
    let untrusted_client = testdata("untrusted-client.pem")?;
    let untrusted_client_key = testdata("untrusted-client-key.pem")?;

    let mutual_client = ClientConfig::mutual(&ca, &client_pem, &client_key)?;
    let mutual_server = ServerConfig::mutual(&server_pem, &server_key, &ca)?;
    let anonymous_client = ClientConfig::new(&ca)?;
    let untrusted = ClientConfig::mutual(&ca, &untrusted_client, &untrusted_client_key)?;
    let alpn_client = ClientConfig::builder(&ca)
        .client_auth_pem(&client_pem, &client_key)
        .alpn_protocols(&[b"h2"])
        .build()?;
    let alpn_server = ServerConfig::builder(&server_pem, &server_key)
        .require_client_auth(&ca)
        .alpn_protocols(&[b"pgsql"])
        .build()?;

    let (to_client, to_server) = record(&mutual_client, &mutual_server);
    write_variants(client_dir, "mutual-session", &to_client)?;
    write_variants(server_dir, "mutual-session", &to_server)?;
    // The first record alone, then a truncated record.
    write_variants(
        client_dir,
        "first-record",
        to_client.get(..5).unwrap_or_default(),
    )?;
    write_variants(
        server_dir,
        "truncated-hello",
        to_server.get(..100).unwrap_or_default(),
    )?;

    let (_, to_server) = record(&anonymous_client, &mutual_server);
    write_variants(server_dir, "no-client-cert", &to_server)?;

    let (to_client, to_server) = record(&untrusted, &mutual_server);
    write_variants(client_dir, "server-rejects-client", &to_client)?;
    write_variants(server_dir, "untrusted-client-cert", &to_server)?;

    let (to_client, to_server) = record(&alpn_client, &alpn_server);
    write_variants(client_dir, "alpn-alert", &to_client)?;
    write_variants(server_dir, "alpn-mismatch", &to_server)?;
    Ok(())
}
