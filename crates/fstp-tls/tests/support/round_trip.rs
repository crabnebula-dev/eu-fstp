//! A real TLS session between this crate's client and server, with the
//! transport, the scheduling and the faults chosen by fuzzer bytes (TH-26).
//!
//! The `tls_round_trip` fuzz target and `tests/round_trip.rs` share this
//! file. [`run`] documents the input layout and the properties it checks.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{block_on, join};
use fstp_rt::{AsyncRead, AsyncWrite, IoExt};
use fstp_tls::{ClientConfig, ServerConfig, TlsError, TlsStream, accept, connect};

/// Number of header bytes before the schedule tape. See [`run`].
pub(crate) const HEADER_LEN: usize = 21;

/// Largest buffer passed to one `poll_read` or `poll_write` call.
const MAX_IO_LEN: usize = 1 << 16;

/// How a run ended, for coverage checks in the test suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ending {
    /// Both sides sent and received everything, and closed with
    /// `close_notify`.
    Complete,
    /// No TLS error occurred, but at least one read detected a truncation.
    Truncated,
    /// At least one side failed with a typed TLS error.
    TlsFailure,
    /// Corrupted bytes left both sides waiting for each other, as a
    /// corrupted record length can. A deployment ends such a session with
    /// a timeout.
    Stalled,
}

/// Reads fuzzer bytes. Missing bytes read as zero.
struct Bytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    fn u24(&mut self) -> u32 {
        u32::from_be_bytes([0, self.u8(), self.u8(), self.u8()])
    }
}

/// A transport chunk limit: 1 to 64 bytes for the first quarter of the
/// range, 128 bytes to 16 KiB for the next half, and none for the rest.
fn chunk_limit(b: u8) -> usize {
    match b {
        0..=63 => usize::from(b).saturating_add(1),
        64..=191 => usize::from(b - 63).saturating_mul(128),
        192..=255 => usize::MAX,
    }
}

/// Bytes buffered per direction in the in-memory pipe: 1 to 64 bytes for
/// the first quarter of the range, 256 bytes to 16 KiB for the second, and
/// a table of sizes up to 1 MiB for the rest.
fn capacity(b: u8) -> usize {
    const LARGE: [usize; 6] = [256, 1024, 4096, 16_384, 65_536, 1 << 20];
    match b {
        0..=63 => usize::from(b).saturating_add(1),
        64..=127 => usize::from(b - 63).saturating_mul(256),
        128..=255 => LARGE
            .get(usize::from(b) % LARGE.len())
            .copied()
            .unwrap_or(4096),
    }
}

/// Length of one application read or write. Zero, which an exhausted tape
/// yields, means as much as possible.
fn io_len(b: u8) -> usize {
    match b {
        0 | 128..=255 => MAX_IO_LEN,
        1..=63 => usize::from(b),
        64..=127 => usize::from(b - 63).saturating_mul(512),
    }
}

/// How a side ends its sending direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Close {
    /// `poll_shutdown` on the TLS stream: `close_notify`, then a transport
    /// shutdown.
    Graceful,
    /// Flush the TLS stream, then shut the transport down without
    /// `close_notify`.
    AbortFlushed,
    /// Shut the transport down at once, without flushing or `close_notify`.
    AbortUnflushed,
}

#[derive(Debug, Clone, Copy)]
struct SideConfig {
    read_chunk: usize,
    write_chunk: usize,
    pending: u8,
    close: Close,
    read_first: bool,
    /// Send `close_notify` only after the read side has finished. See
    /// [`run`] for why the receiver of corrupted bytes needs this.
    close_after_read: bool,
    payload_len: usize,
}

impl SideConfig {
    fn decode(b: &mut Bytes<'_>) -> Self {
        let read_chunk = chunk_limit(b.u8());
        let write_chunk = chunk_limit(b.u8());
        let pending = b.u8();
        let mode = b.u8();
        let close = match mode & 3 {
            2 => Close::AbortFlushed,
            3 => Close::AbortUnflushed,
            _ => Close::Graceful,
        };
        let extra = if mode & 8 == 0 { 0 } else { 1 << 14 };
        // Bits 4 to 6 shift the length down, so short payloads are common.
        let shift = (mode >> 4) & 7;
        let payload_len = (usize::from(b.u16()) >> shift).saturating_add(extra);
        Self {
            read_chunk,
            write_chunk,
            pending,
            close,
            read_first: mode & 4 != 0,
            close_after_read: false,
            payload_len,
        }
    }
}

/// Deterministic payload bytes without short repeats, so that lost,
/// duplicated or reordered data shows up as a mismatch.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Counters shared by both transport ends of a run.
#[derive(Default)]
struct Counters {
    moved: Arc<AtomicU64>,
    injected: Arc<AtomicU64>,
}

/// Transport operation kinds, for `Pending` injection.
#[derive(Debug, Clone, Copy)]
enum Op {
    Read = 0,
    Write = 1,
    Flush = 2,
    Shutdown = 3,
}

/// One direction's transport: an fstp-rt duplex end with chunking,
/// injected `Pending`, and optional tampering or a silent cut.
struct Wire {
    inner: DuplexStream,
    read_chunk: usize,
    write_chunk: usize,
    pending: u8,
    /// Per operation kind: operations so far, and whether the last one
    /// returned an injected `Pending`.
    ops: [(u32, bool); 4],
    /// Bytes the duplex accepted from this end.
    written: u64,
    /// Offset and bit mask of one byte to corrupt on the way out.
    tamper: Option<(u64, u8)>,
    /// Offset at which the link dies: the peer sees end of stream there.
    cut_at: Option<u64>,
    cut: bool,
    /// Counts bytes moved and shutdowns, shared by both ends of a run.
    moved: Arc<AtomicU64>,
    /// Counts injected `Pending` results, shared by both ends of a run.
    injected: Arc<AtomicU64>,
}

impl Wire {
    fn new(inner: DuplexStream, cfg: &SideConfig, counters: &Counters) -> Self {
        Self {
            inner,
            read_chunk: cfg.read_chunk,
            write_chunk: cfg.write_chunk,
            pending: cfg.pending,
            ops: [(0, false); 4],
            written: 0,
            tamper: None,
            cut_at: None,
            cut: false,
            moved: counters.moved.clone(),
            injected: counters.injected.clone(),
        }
    }

    fn note<T>(&self, res: &Poll<io::Result<T>>, amount: usize) {
        if let Poll::Ready(Ok(_)) = res {
            let amount = u64::try_from(amount).unwrap_or(u64::MAX);
            self.moved.fetch_add(amount, Ordering::SeqCst);
        }
    }

    /// Bit `n % 8` of the pattern makes the `n`-th operation of one kind
    /// (read, write, flush or shutdown) return `Pending` once, after waking
    /// the task. The next operation of that kind never does, so every kind
    /// makes progress.
    fn maybe_pending(&mut self, cx: &mut Context<'_>, kind: Op) -> bool {
        let Some((n, last)) = self.ops.get_mut(kind as usize) else {
            return false;
        };
        let bit = *n % 8;
        *n = n.wrapping_add(1);
        if *last {
            *last = false;
            return false;
        }
        if (self.pending >> bit) & 1 == 1 {
            *last = true;
            self.injected.fetch_add(1, Ordering::SeqCst);
            cx.waker().wake_by_ref();
            return true;
        }
        false
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.maybe_pending(cx, Op::Read) {
            return Poll::Pending;
        }
        let n = buf.len().min(this.read_chunk);
        let buf = buf.get_mut(..n).unwrap_or_default();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        let got = match &res {
            Poll::Ready(Ok(n)) => *n,
            _ => 0,
        };
        this.note(&res, got);
        res
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut n = buf.len().min(this.write_chunk);
        if this.cut {
            // The link is dead. Bytes vanish without an error, so only the
            // receiver can notice.
            let res = Poll::Ready(Ok(n));
            this.note(&res, n);
            return res;
        }
        if this.maybe_pending(cx, Op::Write) {
            return Poll::Pending;
        }
        if let Some(at) = this.cut_at {
            let room = at.saturating_sub(this.written);
            if room == 0 {
                this.cut = true;
                // The receiver reads exactly `at` bytes, then end of stream.
                // A duplex shutdown is always ready.
                let _ = Pin::new(&mut this.inner).poll_shutdown(cx);
                let res = Poll::Ready(Ok(n));
                this.note(&res, n);
                return res;
            }
            n = n.min(usize::try_from(room).unwrap_or(usize::MAX));
        }
        let chunk = buf.get(..n).unwrap_or_default();
        let res = match this.tamper {
            Some((at, mask))
                if at >= this.written
                    && at.saturating_sub(this.written) < u64::try_from(n).unwrap_or(u64::MAX) =>
            {
                let mut copy = chunk.to_vec();
                let i = usize::try_from(at.saturating_sub(this.written)).unwrap_or(usize::MAX);
                if let Some(b) = copy.get_mut(i) {
                    *b ^= mask;
                }
                Pin::new(&mut this.inner).poll_write(cx, &copy)
            }
            _ => Pin::new(&mut this.inner).poll_write(cx, chunk),
        };
        if let Poll::Ready(Ok(m)) = &res {
            this.written = this
                .written
                .saturating_add(u64::try_from(*m).unwrap_or(u64::MAX));
            this.note(&res, *m);
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.maybe_pending(cx, Op::Flush) {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cut {
            return Poll::Ready(Ok(()));
        }
        if this.maybe_pending(cx, Op::Shutdown) {
            return Poll::Pending;
        }
        let res = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.note(&res, 1);
        res
    }
}

type Handshake<'a> = Pin<Box<dyn Future<Output = io::Result<TlsStream<Wire>>> + 'a>>;

/// What one side observed.
#[derive(Default)]
struct Outcome {
    /// `Some(Ok)` once the handshake completed.
    handshake: Option<io::Result<()>>,
    /// Whether the completed handshake resumed a session.
    resumed: Option<bool>,
    /// `Some(Ok)` once a read returned `Ok(0)`.
    read: Option<io::Result<()>>,
    /// `Some(Ok)` once all plaintext was accepted and the side closed.
    write: Option<io::Result<()>>,
    received: Vec<u8>,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("handshake", &self.handshake)
            .field("resumed", &self.resumed)
            .field("read", &self.read)
            .field("write", &self.write)
            .field("received_len", &self.received.len())
            .finish()
    }
}

/// One endpoint: a handshake, then full-duplex application IO.
struct Side<'a> {
    name: &'static str,
    cfg: SideConfig,
    handshake: Option<Handshake<'a>>,
    stream: Option<TlsStream<Wire>>,
    out: &'a [u8],
    expect: &'a [u8],
    sent: usize,
    flushed: bool,
    buf: Vec<u8>,
    outcome: Outcome,
    done: bool,
}

impl<'a> Side<'a> {
    fn new(
        name: &'static str,
        cfg: SideConfig,
        handshake: Handshake<'a>,
        out: &'a [u8],
        expect: &'a [u8],
    ) -> Self {
        Self {
            name,
            cfg,
            handshake: Some(handshake),
            stream: None,
            out,
            expect,
            sent: 0,
            flushed: false,
            buf: vec![0; MAX_IO_LEN],
            outcome: Outcome::default(),
            done: false,
        }
    }

    /// Everything a poll can change, to detect progress in a probe poll.
    fn state(&self) -> (bool, bool, usize, usize, bool, bool, bool, bool) {
        (
            self.handshake.is_some(),
            self.stream.is_some(),
            self.sent,
            self.outcome.received.len(),
            self.outcome.read.is_some(),
            self.outcome.write.is_some(),
            self.flushed,
            self.done,
        )
    }

    fn failed(&self) -> bool {
        matches!(self.outcome.read, Some(Err(_))) || matches!(self.outcome.write, Some(Err(_)))
    }

    /// Polls the side once. After real progress it wakes itself and
    /// returns, so that the scheduler can interleave the two sides.
    /// Returns whether it woke itself.
    fn poll(&mut self, cx: &mut Context<'_>, tape: &mut Bytes<'_>) -> Result<bool, String> {
        if let Some(hs) = self.handshake.as_mut() {
            match hs.as_mut().poll(cx) {
                Poll::Pending => return Ok(false),
                Poll::Ready(Ok(stream)) => {
                    self.handshake = None;
                    self.outcome.resumed = Some(stream.is_resumed());
                    self.stream = Some(stream);
                    self.outcome.handshake = Some(Ok(()));
                }
                Poll::Ready(Err(e)) => {
                    self.handshake = None;
                    self.outcome.handshake = Some(Err(e));
                    self.done = true;
                    return Ok(false);
                }
            }
        }
        if self.stream.is_none() {
            self.done = true;
            return Ok(false);
        }
        let read_first = tape.u8() & 1 == 1;
        let mut progress = false;
        for step in 0..2 {
            if self.failed() {
                break;
            }
            if (step == 0) == read_first {
                progress |= self.step_read(cx, tape)?;
            } else {
                progress |= self.step_write(cx, tape)?;
            }
        }
        let read_done = self.outcome.read.is_some();
        let write_done = self.outcome.write.is_some();
        if self.failed() || (read_done && write_done) {
            // Dropping the stream closes the transport, which wakes the
            // peer as a real connection close would.
            self.stream = None;
            self.done = true;
        } else if progress {
            cx.waker().wake_by_ref();
            return Ok(true);
        }
        Ok(false)
    }

    /// One read attempt. Returns whether it made progress.
    fn step_read(&mut self, cx: &mut Context<'_>, tape: &mut Bytes<'_>) -> Result<bool, String> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(false);
        };
        let outcome = &mut self.outcome;
        let (name, expect) = (self.name, self.expect);
        if outcome.read.is_some() {
            return Ok(false);
        }
        let len = io_len(tape.u8()).min(self.buf.len());
        let buf = self.buf.get_mut(..len).unwrap_or_default();
        match Pin::new(stream).poll_read(cx, buf) {
            Poll::Pending => Ok(false),
            Poll::Ready(Ok(0)) => {
                outcome.read = Some(Ok(()));
                Ok(true)
            }
            Poll::Ready(Ok(n)) => {
                let start = outcome.received.len();
                let end = start.saturating_add(n);
                let got = buf.get(..n);
                if got.is_none() || expect.get(start..end) != got {
                    return Err(format!(
                        "{name}: bytes {start}..{end} differ from what the peer sent"
                    ));
                }
                outcome.received.extend_from_slice(got.unwrap_or_default());
                Ok(true)
            }
            Poll::Ready(Err(e)) => {
                outcome.read = Some(Err(e));
                Ok(true)
            }
        }
    }

    /// One write attempt, or one step of closing once all plaintext was
    /// accepted. Returns whether it made progress.
    fn step_write(&mut self, cx: &mut Context<'_>, tape: &mut Bytes<'_>) -> Result<bool, String> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(false);
        };
        if self.outcome.write.is_some() || (self.cfg.read_first && self.outcome.read.is_none()) {
            return Ok(false);
        }
        if self.sent < self.out.len() {
            let ctl = tape.u8();
            if ctl == 0xFF {
                match Pin::new(&mut *stream).poll_flush(cx) {
                    Poll::Ready(Err(e)) => {
                        self.outcome.write = Some(Err(e));
                        return Ok(true);
                    }
                    Poll::Ready(Ok(())) | Poll::Pending => {}
                }
            }
            let end = self.sent.saturating_add(io_len(ctl)).min(self.out.len());
            let chunk = self.out.get(self.sent..end).unwrap_or_default();
            return match Pin::new(&mut *stream).poll_write(cx, chunk) {
                Poll::Pending => Ok(false),
                Poll::Ready(Ok(n)) if n == 0 || n > chunk.len() => Err(format!(
                    "{}: poll_write returned {n} for {} bytes",
                    self.name,
                    chunk.len()
                )),
                Poll::Ready(Ok(n)) => {
                    self.sent = self.sent.saturating_add(n);
                    Ok(true)
                }
                Poll::Ready(Err(e)) => {
                    self.outcome.write = Some(Err(e));
                    Ok(true)
                }
            };
        }
        if self.cfg.close == Close::Graceful
            && self.cfg.close_after_read
            && self.outcome.read.is_none()
        {
            return Ok(false);
        }
        let mut progress = false;
        let res = match self.cfg.close {
            Close::Graceful => Pin::new(&mut *stream).poll_shutdown(cx),
            Close::AbortFlushed if !self.flushed => match Pin::new(&mut *stream).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.flushed = true;
                    progress = true;
                    Pin::new(stream.get_mut()).poll_shutdown(cx)
                }
                other => other,
            },
            // Shuts the transport down under the TLS layer.
            Close::AbortFlushed | Close::AbortUnflushed => {
                Pin::new(stream.get_mut()).poll_shutdown(cx)
            }
        };
        match res {
            Poll::Pending => Ok(progress),
            Poll::Ready(r) => {
                self.outcome.write = Some(r);
                Ok(true)
            }
        }
    }
}

/// Sets a flag when woken, so the scheduler polls only woken sides.
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// An error that a run may produce once a fault was injected: a typed TLS
/// error, a detected truncation, or a write to a peer that already gave up.
fn acceptable(e: &io::Error) -> bool {
    TlsError::from_io(e).is_some()
        || matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
        )
}

const CA: &[u8] = include_bytes!("../../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../testdata/client-key.pem");
const SERVER: &[u8] = include_bytes!("../../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../testdata/server-key.pem");

/// A mutual TLS client and server configuration with empty session caches.
fn configs() -> Result<(ClientConfig, ServerConfig), String> {
    let client = ClientConfig::mutual(CA, CLIENT, CLIENT_KEY)
        .map_err(|e| format!("test client configuration: {e}"))?;
    let server = ServerConfig::mutual(SERVER, SERVER_KEY, CA)
        .map_err(|e| format!("test server configuration: {e}"))?;
    Ok((client, server))
}

/// Runs one clean session with a full handshake, so that the client holds
/// a ticket for the next session. The client reads to the end, which makes
/// it process the ticket that the server sends after the handshake.
fn prime(client: &ClientConfig, server: &ServerConfig) -> Result<(), String> {
    let (c, s) = duplex(1 << 16);
    let (c, s) = block_on(join(connect(client, "localhost", c), accept(server, s)));
    let (mut c, mut s) = match (c, s) {
        (Ok(c), Ok(s)) => (c, s),
        (c, s) => {
            return Err(format!(
                "priming handshake failed: client {:?}, server {:?}",
                c.err(),
                s.err()
            ));
        }
    };
    if c.is_resumed() || s.is_resumed() {
        return Err(String::from("the priming session resumed"));
    }
    let (from_server, from_client) = block_on(join(
        async {
            c.shutdown().await?;
            let mut out = Vec::new();
            c.read_to_end(&mut out, 16).await.map(|_| out)
        },
        async {
            let mut out = Vec::new();
            s.read_to_end(&mut out, 16).await?;
            s.shutdown().await.map(|()| out)
        },
    ));
    match (from_server, from_client) {
        (Ok(a), Ok(b)) if a.is_empty() && b.is_empty() => Ok(()),
        other => Err(format!("priming session failed: {other:?}")),
    }
}

fn is_eof(r: &Option<io::Result<()>>) -> bool {
    matches!(r, Some(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof && TlsError::from_io(e).is_none())
}

/// Runs one session described by `data` and checks its properties.
///
/// Input layout (missing bytes read as zero):
///
/// - byte 0: pipe capacity per direction, from 1 byte to 1 MiB.
/// - chunk limits: 1 to 64 bytes, 128 bytes to 16 KiB, or none.
/// - bytes 1 to 6, client: transport read chunk, write chunk, `Pending`
///   pattern, mode, and payload length (two bytes).
/// - bytes 7 to 12: the same for the server.
/// - byte 13: faults and resumption. Bits 0 and 1 choose a direction for
///   one corrupted byte, bits 2 and 3 a direction for a silent cut. Bit 4
///   first runs a clean session that leaves the client a ticket, so the
///   fuzzed session resumes (policy P2).
/// - bytes 14 to 17: corruption offset (three bytes) and bit index.
/// - bytes 18 to 20: cut offset.
/// - the rest is a schedule tape. It picks which woken side runs next,
///   spurious polls, the order of reads and writes, and their sizes.
///
/// Mode bits: 0 and 1 choose the close (`close_notify`, flush and abort,
/// or plain abort). Bit 2 makes the server read everything before it
/// writes. Bit 3 adds 16 KiB to the payload, and bits 4 to 6 shift the
/// two length bytes right. A payload is at most 2048 times the smallest
/// pipe capacity or chunk limit on its path.
///
/// Properties:
///
/// - Termination: the two sides finish within a poll budget linear in the
///   data size, and a side is polled only when woken (spurious polls aside).
///   A lost wake-up or a busy loop fails the run. A poll that wakes its own
///   task without progress counts as a busy loop.
/// - Corrupted bytes can leave both sides waiting for each other. The run
///   then probes each side once. Progress in a probe is a lost wake-up.
///   Otherwise the run ends as a timeout would end it.
/// - Integrity: what a side reads is always a prefix of what its peer sent.
/// - Truncation detection: a read returns `Ok(0)` only after the complete
///   payload, and only if the peer sent `close_notify`. A transport end of
///   stream without it fails with `UnexpectedEof`.
/// - Without faults, everything arrives and both sides close cleanly.
/// - Without corruption, both sides resume exactly when bit 4 is set. Two
///   sides that both complete the handshake agree on whether it resumed.
/// - With aborts only, the peer of an aborting side detects the
///   truncation, after the complete payload if the side flushed first.
/// - Every error is a typed `TlsError`, a detected truncation, or a write
///   to a peer that already closed. Errors happen only after a fault.
///
/// Each run builds its own mutual TLS configurations, so their session
/// caches start empty and a run depends on its input alone.
pub(crate) fn run(data: &[u8]) -> Result<Ending, String> {
    let (client_cfg, server_cfg) = configs()?;
    let (client_cfg, server_cfg) = (&client_cfg, &server_cfg);
    let mut b = Bytes { data, pos: 0 };
    let cap = capacity(b.u8());
    let mut ccfg = SideConfig::decode(&mut b);
    let mut scfg = SideConfig::decode(&mut b);
    // Only the server may wait for the whole request. Two such sides would
    // deadlock by design, like two TCP peers that never read.
    ccfg.read_first = false;
    let faults = b.u8();
    let resume = faults & 0x10 != 0;
    if resume {
        prime(client_cfg, server_cfg)?;
    }
    // rustls 0.23.46 has a debug assertion that fails when it sends a fatal
    // alert after this side's close_notify. Corrupted input after a
    // graceful shutdown triggers it in debug builds, including fuzz builds.
    // So the receiver of corrupted bytes reads everything before it closes.
    // Release builds return a typed error instead.
    match faults & 3 {
        1 => scfg.close_after_read = true,
        2 => {
            ccfg.close_after_read = true;
            // A server that waits for the client's close would deadlock
            // with a client that waits for the server's close.
            scfg.read_first = false;
        }
        _ => {}
    }
    let tamper_off = b.u24();
    let tamper_mask = 1u8 << (b.u8() & 7);
    let cut_off = b.u24();
    // With a transport that moves a few bytes per operation, every byte
    // costs several polls. rustls also does work linear in its queued
    // records on each write attempt. So a payload is capped by the smallest
    // chunk on its path, which keeps one run well under a second.
    let cap_payload = |from: &mut SideConfig, to: &SideConfig| {
        let unit = cap.min(from.write_chunk).min(to.read_chunk);
        from.payload_len = from.payload_len.min(unit.saturating_mul(2048));
    };
    cap_payload(&mut ccfg, &scfg);
    cap_payload(&mut scfg, &ccfg);
    let tape_len = data.len().saturating_sub(HEADER_LEN);
    let mut tape = Bytes {
        data: data.get(HEADER_LEN..).unwrap_or_default(),
        pos: 0,
    };

    let to_server = payload(ccfg.payload_len, 0xC11E_17C1);
    let to_client = payload(scfg.payload_len, 0x5E4F_E45E);

    // An offset within the handshake, the payload or a little beyond.
    let place = |raw: u32, len: usize| -> u64 {
        let span = u64::try_from(len).unwrap_or(u64::MAX).saturating_add(8192);
        u64::from(raw) % span
    };
    let (c_io, s_io) = duplex(cap);
    let counters = Counters::default();
    let mut c_wire = Wire::new(c_io, &ccfg, &counters);
    let mut s_wire = Wire::new(s_io, &scfg, &counters);
    let moved = counters.moved.clone();
    match faults & 3 {
        1 => c_wire.tamper = Some((place(tamper_off, ccfg.payload_len), tamper_mask)),
        2 => s_wire.tamper = Some((place(tamper_off, scfg.payload_len), tamper_mask)),
        _ => {}
    }
    match (faults >> 2) & 3 {
        1 => c_wire.cut_at = Some(place(cut_off, ccfg.payload_len)),
        2 => s_wire.cut_at = Some(place(cut_off, scfg.payload_len)),
        _ => {}
    }
    let corrupted = c_wire.tamper.is_some()
        || s_wire.tamper.is_some()
        || c_wire.cut_at.is_some()
        || s_wire.cut_at.is_some();

    let mut sides = [
        Side::new(
            "client",
            ccfg,
            Box::pin(connect(client_cfg, "localhost", c_wire)),
            &to_server,
            &to_client,
        ),
        Side::new(
            "server",
            scfg,
            Box::pin(accept(server_cfg, s_wire)),
            &to_client,
            &to_server,
        ),
    ];

    let flags = [
        Arc::new(Flag(AtomicBool::new(true))),
        Arc::new(Flag(AtomicBool::new(true))),
    ];
    let wakers = [Waker::from(flags[0].clone()), Waker::from(flags[1].clone())];
    let wire_estimate = ccfg
        .payload_len
        .saturating_add(scfg.payload_len)
        .saturating_add(tape_len.saturating_mul(64))
        .saturating_add(1 << 16);
    let budget = wire_estimate.saturating_mul(32).saturating_add(200_000);
    let mut polls = 0usize;
    let mut round = 0usize;
    let mut stalled = false;
    loop {
        let live = [!sides[0].done, !sides[1].done];
        if !live[0] && !live[1] {
            break;
        }
        let woken = [
            live[0] && flags[0].0.load(Ordering::SeqCst),
            live[1] && flags[1].0.load(Ordering::SeqCst),
        ];
        if !woken[0] && !woken[1] {
            if !corrupted {
                return Err(format!(
                    "lost wake-up: no side was woken (client {:?}, server {:?})",
                    sides[0].outcome, sides[1].outcome
                ));
            }
            // Corrupted bytes can leave both peers waiting for each other.
            // Probe each side once: if a probe moves bytes or changes any
            // state, a wake-up was lost. Otherwise the session is stuck as
            // a real one would be until a timeout ends it.
            let before = (
                moved.load(Ordering::SeqCst),
                sides[0].state(),
                sides[1].state(),
            );
            for (side, waker) in sides.iter_mut().zip(wakers.iter()) {
                if !side.done {
                    side.poll(&mut Context::from_waker(waker), &mut tape)?;
                }
            }
            let after = (
                moved.load(Ordering::SeqCst),
                sides[0].state(),
                sides[1].state(),
            );
            if before != after {
                return Err(format!(
                    "lost wake-up: a probe poll made progress (client {:?}, server {:?})",
                    sides[0].outcome, sides[1].outcome
                ));
            }
            stalled = true;
            break;
        }
        let pick = tape.u8();
        round = round.wrapping_add(1);
        // The tape picks the order, relative to plain alternation. Once
        // the tape is used up, the sides alternate, so neither starves.
        let first = if woken[0] && woken[1] {
            usize::from(pick & 1) ^ (round & 1)
        } else if woken[0] {
            0
        } else {
            1
        };
        let mut order = vec![first];
        // A spurious poll of the other side. Futures must tolerate it.
        if pick & 2 != 0 && live[1 - first] {
            order.push(1 - first);
        }
        for i in order {
            let (Some(side), Some(flag), Some(waker)) =
                (sides.get_mut(i), flags.get(i), wakers.get(i))
            else {
                continue;
            };
            if side.done {
                continue;
            }
            flag.0.store(false, Ordering::SeqCst);
            let injected = counters.injected.load(Ordering::SeqCst);
            let woke_itself = side.poll(&mut Context::from_waker(waker), &mut tape)?;
            polls = polls.saturating_add(1);
            // Only the harness, after progress, and an injected `Pending`
            // wake a side during its own poll. The duplex wakes only the
            // peer. Any other self-wake is a poll that will spin.
            if flag.0.load(Ordering::SeqCst)
                && !woke_itself
                && !side.done
                && injected == counters.injected.load(Ordering::SeqCst)
            {
                return Err(format!(
                    "{}: woke itself without progress, a busy loop ({:?})",
                    side.name, side.outcome
                ));
            }
        }
        if polls > budget {
            return Err(format!(
                "no completion within {budget} polls (client {:?}, server {:?})",
                sides[0].outcome, sides[1].outcome
            ));
        }
    }
    let [client, server] = sides;
    let ending = check(&client, &server, corrupted, resume)?;
    Ok(if stalled { Ending::Stalled } else { ending })
}

/// Checks the outcome of a finished or stalled run. See [`run`].
fn check(
    client: &Side<'_>,
    server: &Side<'_>,
    corrupted: bool,
    resume: bool,
) -> Result<Ending, String> {
    if let (Some(c), Some(s)) = (client.outcome.resumed, server.outcome.resumed)
        && c != s
    {
        return Err(format!("client resumed: {c}, server resumed: {s}"));
    }
    let aborted = client.cfg.close != Close::Graceful || server.cfg.close != Close::Graceful;
    let mut tls_failure = false;
    let mut truncated = false;
    for (me, peer) in [(client, server), (server, client)] {
        let o = &me.outcome;
        for e in [&o.handshake, &o.read, &o.write]
            .into_iter()
            .filter_map(|r| r.as_ref().and_then(|r| r.as_ref().err()))
        {
            if !corrupted && !aborted {
                return Err(format!("{}: error without any fault: {e:?}", me.name));
            }
            if !acceptable(e) {
                return Err(format!("{}: untyped error {e:?}", me.name));
            }
            tls_failure |= TlsError::from_io(e).is_some();
        }
        truncated |= is_eof(&o.read);
        if !me.expect.starts_with(&o.received) {
            return Err(format!("{}: received data is not a prefix", me.name));
        }
        if matches!(o.read, Some(Ok(()))) {
            if o.received.len() != me.expect.len() {
                return Err(format!(
                    "{}: truncation not detected, Ok(0) after {} of {} bytes",
                    me.name,
                    o.received.len(),
                    me.expect.len()
                ));
            }
            if peer.cfg.close != Close::Graceful {
                return Err(format!(
                    "{}: Ok(0) although the peer sent no close_notify",
                    me.name
                ));
            }
        }
        if corrupted {
            continue;
        }
        // No corruption: the handshake completes, writes never fail, and
        // each read ends as the peer's close mode dictates.
        if !matches!(o.handshake, Some(Ok(()))) {
            return Err(format!("{}: handshake did not complete: {o:?}", me.name));
        }
        if o.resumed != Some(resume) {
            return Err(format!(
                "{}: resumed {:?}, but the input asked for {resume}",
                me.name, o.resumed
            ));
        }
        if matches!(o.write, Some(Err(_))) {
            return Err(format!(
                "{}: write failed without corruption: {o:?}",
                me.name
            ));
        }
        let full = o.received.len() == me.expect.len();
        let ok = match (&peer.outcome.write, peer.cfg.close) {
            (Some(Ok(())), Close::Graceful) => matches!(o.read, Some(Ok(()))),
            (Some(Ok(())), Close::AbortFlushed) => is_eof(&o.read) && full,
            // The peer failed after its close_notify went out, while its
            // transport shutdown was still pending.
            (_, Close::Graceful) => is_eof(&o.read) || matches!(o.read, Some(Ok(()))),
            _ => is_eof(&o.read),
        };
        if !ok {
            return Err(format!(
                "{}: read ended wrongly for peer close {:?}: {o:?}, peer {:?}",
                me.name, peer.cfg.close, peer.outcome
            ));
        }
    }
    Ok(if tls_failure {
        Ending::TlsFailure
    } else if truncated {
        Ending::Truncated
    } else {
        Ending::Complete
    })
}
