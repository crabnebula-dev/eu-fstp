//! The splice: one client connection, one tunnel (ADR-009 "Edge and
//! tunnel", I-19, B5, design section 2.4 rule 5).
//!
//! [`read_hello`] reads at most [`MAX_HELLO_BUF`] bytes, until the parser
//! decides. [`serve`] then opens a tunnel to the routed endpoint, writes
//! the tunnel header, writes every byte read so far unchanged, and copies
//! both directions until both ends close. The edge never terminates the
//! client's TLS: it reads the ClientHello and nothing else.
//!
//! The caller sets deadlines. It wraps [`read_hello`] in a short timeout
//! against slow clients and [`serve`] in its connection lifetime.

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use fstp_rt::{AsyncRead, AsyncWrite, Connection, IoExt, Runtime};
use fstp_tls::{ClientConfig, TlsStream};

use crate::header::{TunnelHeader, encode_tunnel_header};
use crate::host::HostName;
use crate::route::{CellEndpoint, CloseReason, Decision, RouteKind, RouteTable, decide};
use crate::sni::{HelloScan, MAX_HELLO_BUF, SniError};

/// The buffer size of each copy direction.
const COPY_BUF: usize = 16 * 1024;

/// The most reads one poll of a copy direction makes before it yields.
const YIELD_READS: usize = 4;

/// Why the edge closed a connection.
#[derive(Debug)]
pub enum EdgeError {
    /// The client closed before its ClientHello was complete.
    ClosedEarly,
    /// The routing decision closed the connection.
    Closed(CloseReason),
    /// The tunnel to the cell did not open.
    TunnelOpen(io::Error),
    /// Reading from or writing to either end failed.
    Io(io::Error),
    /// The edge binary has no route feed or listener configuration yet.
    /// It names the missing part.
    NotImplemented(&'static str),
}

impl From<io::Error> for EdgeError {
    fn from(e: io::Error) -> Self {
        EdgeError::Io(e)
    }
}

/// A client connection whose ClientHello the edge has routed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routed {
    /// The host the ClientHello named.
    pub host: HostName,
    /// The route's endpoint.
    pub endpoint: CellEndpoint,
    /// What the route serves.
    pub kind: RouteKind,
    /// Every byte read from the client so far, in order: the ClientHello
    /// and whatever followed it in the same reads.
    pub buffered: Vec<u8>,
}

/// Byte counts of one finished splice, for the edge's typed metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spliced {
    /// What the route served.
    pub kind: RouteKind,
    /// Client bytes forwarded to the cell, the buffered ones included.
    pub to_cell: u64,
    /// Cell bytes forwarded to the client.
    pub to_client: u64,
}

/// Opens the tunnel to a cell process.
pub trait TunnelOpener {
    /// The tunnel connection.
    type Tunnel: Connection;

    /// Opens a tunnel to `endpoint`.
    fn open(&self, endpoint: &CellEndpoint) -> impl Future<Output = io::Result<Self::Tunnel>>;
}

/// The production opener: TCP to the endpoint, then an `fstp-tls` client
/// handshake with the edge's tunnel certificate (mutual TLS).
#[derive(Clone)]
pub struct TlsTunnelOpener<R: Runtime> {
    rt: R,
    config: ClientConfig,
}

impl<R: Runtime> TlsTunnelOpener<R> {
    /// An opener over `rt` that authenticates with `config`. The config
    /// carries the edge tunnel certificate and the roots for the cell's
    /// tunnel port.
    pub fn new(rt: R, config: ClientConfig) -> Self {
        TlsTunnelOpener { rt, config }
    }
}

impl<R: Runtime> TunnelOpener for TlsTunnelOpener<R> {
    type Tunnel = TlsStream<R::Tcp>;

    async fn open(&self, endpoint: &CellEndpoint) -> io::Result<Self::Tunnel> {
        let tcp = self.rt.connect_tcp(endpoint.address).await?;
        fstp_tls::connect(&self.config, &endpoint.tls_name, tcp).await
    }
}

/// Reads from `client` until the ClientHello routes or closes, at most
/// [`MAX_HELLO_BUF`] bytes.
///
/// The parser runs only when the record scan says it can decide, when the
/// buffer is full or when the client stops. So a hello sent one byte per
/// segment costs one parse, not one per read.
///
/// # Errors
///
/// Returns [`EdgeError::Closed`] when the decision closes the connection,
/// [`EdgeError::ClosedEarly`] when the client stops first, and
/// [`EdgeError::Io`] on a read error.
pub async fn read_hello<C>(client: &mut C, table: &RouteTable) -> Result<Routed, EdgeError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; MAX_HELLO_BUF];
    let mut filled = 0usize;
    let mut scan = HelloScan::default();
    loop {
        let read = buf.get(..filled).unwrap_or_default();
        if (filled >= MAX_HELLO_BUF || scan.ready(read))
            && let Some(verdict) = settle(table, read)
        {
            return verdict;
        }
        // The parser never asks for more once the buffer is full, so this
        // only guards the bound.
        let Some(space) = buf.get_mut(filled..).filter(|s| !s.is_empty()) else {
            return Err(EdgeError::Closed(CloseReason::Refused(
                SniError::HelloTooLong,
            )));
        };
        let n = client.read(space).await?;
        if n == 0 {
            let read = buf.get(..filled).unwrap_or_default();
            return settle(table, read).unwrap_or(Err(EdgeError::ClosedEarly));
        }
        filled = filled
            .checked_add(n)
            .filter(|f| *f <= MAX_HELLO_BUF)
            .ok_or(EdgeError::Io(io::Error::from(io::ErrorKind::InvalidData)))?;
    }
}

/// The routing decision on the bytes read so far, or `None` when the
/// parser needs more.
fn settle(table: &RouteTable, read: &[u8]) -> Option<Result<Routed, EdgeError>> {
    match decide(table, read) {
        Decision::NeedMore => None,
        Decision::Close(reason) => Some(Err(EdgeError::Closed(reason))),
        Decision::Forward {
            host,
            endpoint,
            kind,
        } => Some(Ok(Routed {
            host,
            endpoint: endpoint.clone(),
            kind,
            buffered: read.to_vec(),
        })),
    }
}

/// Serves one client connection: routes it by SNI, opens the tunnel,
/// writes the tunnel header, forwards every client byte unchanged and
/// copies both directions until both ends close.
///
/// # Errors
///
/// Returns an [`EdgeError`] when the connection closes before or during
/// the splice.
pub async fn serve<C, O>(
    mut client: C,
    peer: SocketAddr,
    table: &RouteTable,
    opener: &O,
) -> Result<Spliced, EdgeError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: TunnelOpener,
{
    let routed = read_hello(&mut client, table).await?;
    let mut tunnel = opener
        .open(&routed.endpoint)
        .await
        .map_err(EdgeError::TunnelOpen)?;
    let header = encode_tunnel_header(&TunnelHeader::new(routed.host, peer));
    tunnel.write_all(&header).await?;
    tunnel.write_all(&routed.buffered).await?;
    tunnel.flush().await?;
    let (up, down) = copy_both(&mut client, &mut tunnel).await?;
    let buffered = u64::try_from(routed.buffered.len()).unwrap_or(u64::MAX);
    Ok(Spliced {
        kind: routed.kind,
        to_cell: up.saturating_add(buffered),
        to_client: down,
    })
}

/// One copy direction with a bounded buffer.
struct Pump {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    read_done: bool,
    need_flush: bool,
    done: bool,
    total: u64,
}

impl Pump {
    fn new() -> Self {
        Pump {
            buf: vec![0u8; COPY_BUF],
            start: 0,
            end: 0,
            read_done: false,
            need_flush: false,
            done: false,
            total: 0,
        }
    }

    /// Moves bytes from `r` to `w` until `r` ends, then shuts `w` down.
    ///
    /// One call reads at most [`YIELD_READS`] times. Then it wakes its
    /// task and returns `Pending`, so two ends that stay ready never hold
    /// the executor thread or starve the other direction.
    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        r: &mut R,
        w: &mut W,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reads = 0usize;
        loop {
            if self.done {
                return Poll::Ready(Ok(()));
            }
            if self.start == self.end && !self.read_done {
                if reads >= YIELD_READS {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                reads = reads.saturating_add(1);
                match Pin::new(&mut *r).poll_read(cx, &mut self.buf) {
                    Poll::Ready(Ok(0)) => self.read_done = true,
                    Poll::Ready(Ok(n)) => {
                        self.start = 0;
                        self.end = n.min(self.buf.len());
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if self.need_flush {
                            ready!(Pin::new(&mut *w).poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        return Poll::Pending;
                    }
                }
            }
            while self.start < self.end {
                let pending = self.buf.get(self.start..self.end).unwrap_or_default();
                let n = ready!(Pin::new(&mut *w).poll_write(cx, pending))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                self.start = self.start.saturating_add(n).min(self.end);
                self.total = self
                    .total
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                self.need_flush = true;
            }
            if self.read_done {
                ready!(Pin::new(&mut *w).poll_flush(cx))?;
                ready!(Pin::new(&mut *w).poll_shutdown(cx))?;
                self.done = true;
            }
        }
    }
}

/// Copies `a` to `b` and `b` to `a` until both directions end. Returns the
/// byte counts in each direction.
async fn copy_both<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = Pump::new();
    let mut down = Pump::new();
    poll_fn(|cx| {
        let up_ready = up.poll_copy(cx, a, b)?.is_ready();
        let down_ready = down.poll_copy(cx, b, a)?.is_ready();
        if up_ready && down_ready {
            Poll::Ready(Ok((up.total, down.total)))
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Wake, Waker};

    use fstp_rt::duplex::{DuplexStream, duplex};
    use fstp_rt::future::{block_on, join};

    use super::*;
    use crate::sni::{SniOutcome, parse_client_hello_sni};

    /// A ClientHello record naming `host`, built by hand.
    fn hello(host: &[u8]) -> Vec<u8> {
        let n = |len: usize| u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&n(host.len().saturating_add(3)));
        sni.push(0);
        sni.extend_from_slice(&n(host.len()));
        sni.extend_from_slice(host);
        let mut exts = vec![0, 0];
        exts.extend_from_slice(&n(sni.len()));
        exts.extend_from_slice(&sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&n(exts.len()));
        body.extend_from_slice(&exts);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&n(body.len()));
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&n(hs.len()));
        rec.extend_from_slice(&hs);
        rec
    }

    /// The handshake bytes of a one-record hello, cut into records of
    /// `size` bytes each.
    fn split_records(record: &[u8], size: usize) -> Vec<u8> {
        let hs = record.get(5..).unwrap_or_default();
        let mut out = Vec::new();
        for chunk in hs.chunks(size) {
            out.extend_from_slice(&[0x16, 3, 1]);
            let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    fn endpoint(cell: u8, port: u16) -> CellEndpoint {
        CellEndpoint {
            cell: [cell; 16],
            address: SocketAddr::from(([10, 0, 0, cell], port)),
            tls_name: "tunnel.cell.internal".to_owned(),
        }
    }

    /// Hands out one prepared tunnel end.
    struct OneTunnel(Mutex<Option<DuplexStream>>);

    impl TunnelOpener for OneTunnel {
        type Tunnel = DuplexStream;

        async fn open(&self, _endpoint: &CellEndpoint) -> io::Result<DuplexStream> {
            let taken = self.0.lock().map(|mut slot| slot.take());
            taken
                .ok()
                .flatten()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
        }
    }

    fn table() -> Result<RouteTable, crate::host::HostError> {
        let mut t = RouteTable::new();
        let host = HostName::parse(b"cell.example")?;
        let added = t.add_cell(host, endpoint(1, 8443), endpoint(1, 9443));
        assert_eq!(added, Ok(()));
        Ok(t)
    }

    /// I-19 (design section 9.4): an unknown host closes before any tunnel
    /// opens, and no byte reaches a cell.
    #[test]
    fn i19_splice_unknown_host_opens_no_tunnel() -> Result<(), crate::host::HostError> {
        let table = table()?;
        let (mut client, edge_side) = duplex(64 * 1024);
        let (tunnel_edge, _cell) = duplex(64 * 1024);
        let opener = OneTunnel(Mutex::new(Some(tunnel_edge)));
        let peer = SocketAddr::from(([192, 0, 2, 9], 50_000));
        let sent = hello(b"other.example");
        let (served, wrote) = block_on(join(
            serve(edge_side, peer, &table, &opener),
            client.write_all(&sent),
        ));
        assert!(wrote.is_ok());
        assert!(matches!(
            served,
            Err(EdgeError::Closed(CloseReason::UnknownHost))
        ));
        let unopened = opener.0.lock().map(|slot| slot.is_some());
        assert_eq!(unopened.ok(), Some(true));
        Ok(())
    }

    /// The prefixes of `bytes` on which the scan says "parse now", fed one
    /// byte at a time as a slow client sends them.
    fn scan_points(bytes: &[u8]) -> Vec<usize> {
        let mut scan = HelloScan::default();
        (1..=bytes.len())
            .filter(|end| scan.ready(bytes.get(..*end).unwrap_or_default()))
            .collect()
    }

    /// I-19, B5 (design section 9.4, review W5): a hello sent one byte per
    /// segment is parsed once, at its last byte, and not after every read.
    /// The parser names the host there. This holds for one record and for
    /// records of 1, 3 and 64 bytes.
    #[test]
    fn i19_byte_by_byte_hello_is_parsed_once() {
        let one = hello(b"cell.example");
        for bytes in [
            one.clone(),
            split_records(&one, 1),
            split_records(&one, 3),
            split_records(&one, 64),
        ] {
            assert_eq!(scan_points(&bytes), vec![bytes.len()]);
            let verdict = parse_client_hello_sni(&bytes);
            assert!(
                matches!(&verdict, Ok(SniOutcome::Host(h)) if h.as_str() == "cell.example"),
                "{verdict:?}"
            );
        }
    }

    /// I-19, B5 (found by `client_hello_sni`): once the hello is complete,
    /// the scan says "parse now" on every longer buffer, even when the next
    /// bytes start a record of their own.
    #[test]
    fn i19_scan_stays_ready_after_the_hello() {
        let mut bytes = split_records(&hello(b"cell.example"), 5);
        let end = bytes.len();
        bytes.extend_from_slice(&[0x16, 3, 1, 0, 9, 1]);
        assert_eq!(scan_points(&bytes), (end..=bytes.len()).collect::<Vec<_>>());
    }

    /// I-19 (design section 9.4): bytes that are not TLS are parsed at
    /// once, so the edge closes on the first byte.
    #[test]
    fn i19_scan_parses_non_tls_at_once() {
        assert_eq!(
            scan_points(b"GET / HTTP/1.1\r\n"),
            (1..=16).collect::<Vec<_>>()
        );
    }

    /// I-19, B5: `read_hello` routes a hello that arrives one byte per
    /// read and keeps every byte it read, in order.
    #[test]
    fn i19_read_hello_routes_a_byte_by_byte_hello() -> Result<(), crate::host::HostError> {
        let table = table()?;
        let (mut client, mut edge_side) = duplex(1);
        let sent = split_records(&hello(b"cell.example"), 7);
        let writer = async {
            for b in &sent {
                client.write_all(std::slice::from_ref(b)).await?;
                fstp_rt::future::yield_now().await;
            }
            io::Result::Ok(())
        };
        let (routed, wrote) = block_on(join(read_hello(&mut edge_side, &table), writer));
        assert!(wrote.is_ok());
        let routed = routed.map_err(|e| format!("{e:?}"));
        assert_eq!(
            routed.map(|r| (r.kind, r.host.as_str().to_owned(), r.buffered)),
            Ok((RouteKind::Cell, "cell.example".to_owned(), sent.clone()))
        );
        Ok(())
    }

    /// A reader that always has bytes.
    struct Endless;

    impl AsyncRead for Endless {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            buf.fill(0x42);
            Poll::Ready(Ok(buf.len()))
        }
    }

    /// A writer that always accepts everything.
    struct Sink;

    impl AsyncWrite for Sink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Counts its wakes.
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Review W5 (design section 9.4): when both ends stay ready, one poll
    /// of a copy direction moves a bounded number of bytes, wakes its task
    /// and yields.
    #[test]
    fn splice_pump_yields_when_both_ends_stay_ready() {
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let mut pump = Pump::new();
        let polled = pump.poll_copy(&mut cx, &mut Endless, &mut Sink);
        assert!(polled.is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        let bound = u64::try_from(YIELD_READS.saturating_mul(COPY_BUF)).unwrap_or(u64::MAX);
        assert_eq!(pump.total, bound);
    }
}
