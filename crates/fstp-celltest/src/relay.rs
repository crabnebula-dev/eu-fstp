//! Recording relays: the egress recorder on the live links of a world
//! cell (design section 14.3, R-NF-09, lane F-ISO).
//!
//! A world cell reaches its vault, its witness and the control plane
//! through a relay of the world, never directly. A relay is a loopback
//! listener that terminates the cell's TLS with a certificate from the CA
//! the cell already trusts for that peer. It requires a client
//! certificate under the cell CA, as the vault's internal listener and the
//! witness do. It then opens its own TLS connection to the real peer with
//! the cell's own client certificate and passes the plaintext through.
//!
//! What it records in the world's [`EgressLog`]:
//!
//! - every plaintext chunk in each direction, from the cell's side: a
//!   chunk the cell sent is [`Direction::Outbound`], a chunk the cell
//!   received is [`Direction::Inbound`]. The recorder thus sits above TLS,
//!   as design section 14.3 asks, and the scans see what the cell meant
//!   to send;
//! - one [`Handshake`] per connection, with whether the cell presented a
//!   client certificate that the relay verified. A handshake that failed
//!   is recorded with `false`.
//!
//! Claims, so a reader knows what the relay proves. The relay's server
//! configuration is built by the world from the same CA and the same
//! client roots as the real peer's listener. The handshake record is the
//! relay's, not the peer's. The upstream handshake presents the same cell
//! certificate, and a peer that refuses it fails the cell's exchange.
//!
//! A [`Upstream::ControlPlane`] relay has no upstream process: no world
//! part runs the control plane yet (lane F-CP). It reads one message per
//! connection up to the cell's close (`fstp_cell::control`), records it
//! whole as one capture, and answers `CpToCell::Ack` to a message that
//! decodes as `CellToCp`. A message that does not decode gets no reply.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use fstp_rt::{AbortHandle, AsyncRead, AsyncWrite, IoExt, Listener, Runtime};

use crate::egress::{Direction, EgressLog, Handshake, Route};

/// How long a relay waits for one handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// The longest message the control plane relay reads.
const MAX_CP_MESSAGE: usize = 64 * 1024;

/// The size of each pump buffer.
const PUMP_BUFFER: usize = 16 * 1024;

/// Where a relay forwards.
#[derive(Clone)]
pub enum Upstream {
    /// The real peer over TLS.
    Tls {
        /// Its address.
        addr: SocketAddr,
        /// The name its server certificate carries.
        server_name: String,
        /// The client configuration with the cell's client certificate.
        tls: fstp_tls::ClientConfig,
    },
    /// The world's stand-in for the control plane (module documentation).
    ControlPlane,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Tls { addr, .. } => f.debug_struct("Tls").field("addr", addr).finish(),
            Upstream::ControlPlane => f.write_str("ControlPlane"),
        }
    }
}

/// A running relay. Dropping it stops the listener and every connection.
pub struct Relay {
    addr: SocketAddr,
    tasks: Arc<Mutex<Vec<AbortHandle>>>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// Where the relay listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        for t in self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            t.abort();
        }
    }
}

/// Starts a relay on a free loopback port for `route`. It terminates TLS
/// with `server` and forwards to `upstream`, recording in `log`.
///
/// # Errors
///
/// Fails when the listener cannot bind.
pub async fn start<R: Runtime>(
    rt: R,
    log: EgressLog,
    route: Route,
    server: fstp_tls::ServerConfig,
    upstream: Upstream,
) -> io::Result<Relay> {
    let mut listener = rt
        .bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await?;
    let addr = listener.local_addr()?;
    let tasks: Arc<Mutex<Vec<AbortHandle>>> = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(server);
    let held = Arc::clone(&tasks);
    let inner_rt = rt.clone();
    let accept = rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let conn = serve(
                inner_rt.clone(),
                log.clone(),
                route,
                Arc::clone(&server),
                upstream.clone(),
                tcp,
            );
            let handle = inner_rt.spawn(conn).abort_handle();
            let mut list = held.lock().unwrap_or_else(PoisonError::into_inner);
            list.retain(|t| !t.is_finished());
            list.push(handle);
        }
    });
    tasks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(accept.abort_handle());
    Ok(Relay { addr, tasks })
}

/// One relayed connection.
async fn serve<R: Runtime>(
    rt: R,
    log: EgressLog,
    route: Route,
    server: Arc<fstp_tls::ServerConfig>,
    upstream: Upstream,
    tcp: R::Tcp,
) {
    let connection = log.open_connection();
    let accepted = fstp_rt::timeout(&rt, HANDSHAKE_TIMEOUT, fstp_tls::accept(&server, tcp)).await;
    let mut cell = match accepted {
        Ok(Ok(s)) => s,
        _ => {
            log.record_handshake(Handshake {
                route,
                connection,
                client_certificate_verified: false,
            });
            return;
        }
    };
    log.record_handshake(Handshake {
        route,
        connection,
        client_certificate_verified: cell.peer_end_entity_der().is_some(),
    });
    match upstream {
        Upstream::ControlPlane => {
            let _ = control_plane(&log, route, connection, &mut cell).await;
        }
        Upstream::Tls {
            addr,
            server_name,
            tls,
        } => {
            let open = async {
                let tcp = rt.connect_tcp(addr).await?;
                fstp_tls::connect(&tls, &server_name, tcp).await
            };
            let Ok(Ok(peer)) = fstp_rt::timeout(&rt, HANDSHAKE_TIMEOUT, open).await else {
                let _ = cell.shutdown().await;
                return;
            };
            let _ = Pump::new(cell, peer, log, route, connection).await;
        }
    }
}

/// The control plane stand-in of one connection (module documentation).
async fn control_plane<S: fstp_rt::Connection>(
    log: &EgressLog,
    route: Route,
    connection: u64,
    cell: &mut S,
) -> io::Result<()> {
    let mut message = Vec::new();
    cell.read_to_end(&mut message, MAX_CP_MESSAGE).await?;
    log.record(route, Direction::Outbound, connection, &message);
    if fstp_cp_proto::decode_cell_to_cp(&message).is_err() {
        return cell.shutdown().await;
    }
    let reply = fstp_cp_proto::encode_cp_to_cell(&fstp_cp_proto::CpToCell::Ack)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    cell.write_all(&reply).await?;
    log.record(route, Direction::Inbound, connection, &reply);
    cell.flush().await?;
    cell.shutdown().await
}

/// One direction of a [`Pump`].
struct Half {
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
    unflushed: bool,
    done: bool,
}

impl Half {
    fn new() -> Half {
        Half {
            buf: vec![0u8; PUMP_BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            unflushed: false,
            done: false,
        }
    }

    /// Moves bytes from `from` to `to`, handing each chunk read to
    /// `seen`. Ready once `from` ended and `to` was shut down.
    fn poll<A, B>(
        &mut self,
        cx: &mut Context<'_>,
        from: &mut A,
        to: &mut B,
        mut seen: impl FnMut(&[u8]),
    ) -> Poll<io::Result<()>>
    where
        A: AsyncRead + Unpin,
        B: AsyncWrite + Unpin,
    {
        if self.done {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.start < self.end {
                let chunk = self.buf.get(self.start..self.end).unwrap_or_default();
                let n = ready!(Pin::new(&mut *to).poll_write(cx, chunk))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.start = self.start.saturating_add(n);
                self.unflushed = true;
                continue;
            }
            if self.unflushed {
                ready!(Pin::new(&mut *to).poll_flush(cx))?;
                self.unflushed = false;
            }
            if self.eof {
                ready!(Pin::new(&mut *to).poll_shutdown(cx))?;
                self.done = true;
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut *from).poll_read(cx, &mut self.buf))?;
            if n == 0 {
                self.eof = true;
            } else {
                seen(self.buf.get(..n).unwrap_or_default());
                self.start = 0;
                self.end = n;
            }
        }
    }
}

/// Both directions between the cell and its peer, recorded from the
/// cell's side.
struct Pump<A, B> {
    cell: A,
    peer: B,
    out: Half,
    back: Half,
    log: EgressLog,
    route: Route,
    connection: u64,
}

impl<A, B> Pump<A, B> {
    fn new(cell: A, peer: B, log: EgressLog, route: Route, connection: u64) -> Pump<A, B> {
        Pump {
            cell,
            peer,
            out: Half::new(),
            back: Half::new(),
            log,
            route,
            connection,
        }
    }
}

impl<A, B> Future for Pump<A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let (log, route, connection) = (&this.log, this.route, this.connection);
        let out = this.out.poll(cx, &mut this.cell, &mut this.peer, |b| {
            log.record(route, Direction::Outbound, connection, b);
        })?;
        let back = this.back.poll(cx, &mut this.peer, &mut this.cell, |b| {
            log.record(route, Direction::Inbound, connection, b);
        })?;
        match (out, back) {
            (Poll::Ready(()), Poll::Ready(())) => Poll::Ready(Ok(())),
            _ => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{Endpoint, Peer};
    use fstp_rt::duplex::duplex;

    /// Design section 14.3: the pump passes every byte both ways and
    /// records each direction from the cell's side.
    #[test]
    fn harness_pump_records_both_directions() {
        let log = EgressLog::new();
        let route = Route::new(Endpoint::cell(0), Peer::Vault, Some(0));
        let (cell_end, relay_cell) = duplex(64);
        let (relay_peer, peer_end) = duplex(64);
        let pump = Pump::new(relay_cell, relay_peer, log.clone(), route, 1);
        let run = async move {
            let (mut c, mut p) = (cell_end, peer_end);
            let echo = async {
                let mut got = Vec::new();
                p.read_to_end(&mut got, 1024).await?;
                p.write_all(b"pong").await?;
                p.shutdown().await?;
                Ok::<Vec<u8>, io::Error>(got)
            };
            let talk = async {
                c.write_all(b"ping").await?;
                c.shutdown().await?;
                let mut got = Vec::new();
                c.read_to_end(&mut got, 1024).await?;
                Ok::<Vec<u8>, io::Error>(got)
            };
            let (pumped, (echoed, answered)) =
                fstp_rt::future::join(pump, fstp_rt::future::join(echo, talk)).await;
            (pumped.is_ok(), echoed.ok(), answered.ok())
        };
        let (pumped, echoed, answered) = fstp_rt::future::block_on(run);
        assert!(pumped);
        assert_eq!(echoed.as_deref(), Some(&b"ping"[..]));
        assert_eq!(answered.as_deref(), Some(&b"pong"[..]));
        let dirs: Vec<(Direction, Vec<u8>)> = log
            .captures()
            .into_iter()
            .map(|c| (c.direction, c.bytes))
            .collect();
        assert_eq!(
            dirs,
            vec![
                (Direction::Outbound, b"ping".to_vec()),
                (Direction::Inbound, b"pong".to_vec())
            ]
        );
    }
}
