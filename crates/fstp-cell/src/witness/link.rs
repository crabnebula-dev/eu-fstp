//! The witness link over mutual TLS (design section 1.3, ADR-010
//! "Witnesses", R-NF-09). Lane int5.
//!
//! [`TlsWitnessLink`] opens one TCP connection to the witness and runs a
//! TLS 1.3 handshake with the cell's `cell-witness` client certificate.
//! Its client configuration trusts exactly one root, the witness CA, so a
//! handshake that completes proves that the pinned CA issued the peer's
//! certificate. [`WitnessLink::peer_issuer`] then reports the SHA-256
//! digest of that CA's SubjectPublicKeyInfo, which the caller computed
//! when it pinned the CA.
//!
//! The link frames each message with `fstp_witness::wire`. It holds its
//! connection under an async lock, so one exchange runs at a time. A
//! failed exchange drops the connection: the next `peer_issuer` call
//! opens and checks a new one, and the failed call reports
//! [`WitnessFault::Unreachable`].

use std::net::SocketAddr;
use std::time::Duration;

use fstp_audit::anchorer::WitnessFault;
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId, Link};
use fstp_rt::Runtime;
use fstp_witness::lock::AsyncMutex;
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};

use super::{WitnessLink, WitnessMessage, WitnessReply};

/// How long one connection, handshake included, may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one exchange may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where and how a cell reaches its witness.
#[derive(Clone, Debug)]
pub struct WitnessEndpoint {
    /// The witness address.
    pub addr: SocketAddr,
    /// The name its server certificate carries.
    pub server_name: String,
    /// The client configuration: the witness CA as the only root, and the
    /// cell's `cell-witness` certificate and key.
    pub tls: fstp_tls::ClientConfig,
    /// The SHA-256 digest of the witness CA's SubjectPublicKeyInfo.
    pub ca_digest: [u8; 32],
}

/// The connection state of a link.
struct Conn<R: Runtime> {
    stream: Option<fstp_tls::TlsStream<R::Tcp>>,
}

impl<R: Runtime> Default for Conn<R> {
    fn default() -> Self {
        Conn { stream: None }
    }
}

/// A witness link over mutual TLS (module documentation).
pub struct TlsWitnessLink<R: Runtime> {
    rt: R,
    endpoint: WitnessEndpoint,
    cell: CellId,
    chain: ChainId,
    conn: AsyncMutex<Conn<R>>,
}

impl<R: Runtime> std::fmt::Debug for TlsWitnessLink<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsWitnessLink")
            .field("addr", &self.endpoint.addr)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> TlsWitnessLink<R> {
    /// A link of `cell`'s `chain` to `endpoint` on `rt`. It connects on
    /// first use. A link carries the messages of its one chain only.
    pub fn new(
        rt: R,
        endpoint: WitnessEndpoint,
        cell: CellId,
        chain: ChainId,
    ) -> TlsWitnessLink<R> {
        TlsWitnessLink {
            rt,
            endpoint,
            cell,
            chain,
            conn: AsyncMutex::new(Conn::default()),
        }
    }

    async fn connect(&self) -> Result<fstp_tls::TlsStream<R::Tcp>, WitnessFault> {
        let open = async {
            let tcp = self.rt.connect_tcp(self.endpoint.addr).await?;
            fstp_tls::connect(&self.endpoint.tls, &self.endpoint.server_name, tcp).await
        };
        match fstp_rt::timeout(&self.rt, CONNECT_TIMEOUT, open).await {
            Ok(Ok(stream)) => Ok(stream),
            _ => Err(WitnessFault::Unreachable),
        }
    }

    /// One exchange over the current connection. A failure drops it.
    async fn exchange(&self, req: &WireRequest) -> Result<WireReply, WitnessFault> {
        let bytes = encode_request(req).map_err(|_| WitnessFault::Refused)?;
        let mut conn = self.conn.lock().await;
        if conn.stream.is_none() {
            conn.stream = Some(self.connect().await?);
        }
        let Some(stream) = conn.stream.as_mut() else {
            return Err(WitnessFault::Unreachable);
        };
        let run = async {
            write_frame(stream, &bytes).await?;
            read_frame(stream).await
        };
        let reply = match fstp_rt::timeout(&self.rt, EXCHANGE_TIMEOUT, run).await {
            Ok(Ok(Some(frame))) => decode_reply(&frame).map_err(|_| ()),
            _ => Err(()),
        };
        match reply {
            Ok(r) => Ok(r),
            Err(()) => {
                // The answer is lost or garbled: the connection goes, and
                // the caller treats the message as unanswered.
                conn.stream = None;
                Err(WitnessFault::Unreachable)
            }
        }
    }
}

impl<R: Runtime> WitnessLink for TlsWitnessLink<R> {
    async fn peer_issuer(&self) -> Result<[u8; 32], WitnessFault> {
        let mut conn = self.conn.lock().await;
        if conn.stream.is_none() {
            conn.stream = Some(self.connect().await?);
        }
        // The configuration trusts the witness CA alone, so a completed
        // handshake was verified under it.
        Ok(self.endpoint.ca_digest)
    }

    async fn send(&self, message: WitnessMessage) -> Result<WitnessReply, WitnessFault> {
        let (cell, chain) = (self.cell, self.chain);
        let m = match message {
            WitnessMessage::Prepare(p) => {
                if p.anchor.cell != cell || p.anchor.chain != chain {
                    return Ok(WitnessReply::Refused);
                }
                fstp_witness::WitnessMessage::Prepare(p)
            }
            WitnessMessage::Abort { n, link } => fstp_witness::WitnessMessage::Abort {
                cell,
                chain,
                n,
                link,
            },
            WitnessMessage::InDoubtAbsent { n, link } => {
                fstp_witness::WitnessMessage::InDoubtAbsent {
                    cell,
                    chain,
                    n,
                    link,
                }
            }
        };
        match self.exchange(&WireRequest::Message(m)).await? {
            WireReply::Receipt(r) => Ok(WitnessReply::Receipt(r)),
            WireReply::Recorded => Ok(WitnessReply::Recorded),
            WireReply::Refused => Ok(WitnessReply::Refused),
            WireReply::UnknownPrepare => Ok(WitnessReply::UnknownPrepare),
            // An answer that fits no message leaves the witness's state
            // unknown, so it reads as a lost answer.
            WireReply::Outstanding(_) | WireReply::Log(_) => Err(WitnessFault::Unreachable),
        }
    }

    async fn outstanding(
        &self,
        cell: CellId,
        chain: ChainId,
    ) -> Result<Option<(u64, Link)>, WitnessFault> {
        if (cell, chain) != (self.cell, self.chain) {
            return Err(WitnessFault::Refused);
        }
        match self
            .exchange(&WireRequest::Outstanding { cell, chain })
            .await?
        {
            WireReply::Outstanding(o) => Ok(o),
            WireReply::Refused => Err(WitnessFault::Refused),
            _ => Err(WitnessFault::Unreachable),
        }
    }

    async fn log(&self, cell: CellId, chain: ChainId) -> Result<Vec<WitnessRecord>, WitnessFault> {
        if (cell, chain) != (self.cell, self.chain) {
            return Err(WitnessFault::Refused);
        }
        // The log comes in pages of at most `MAX_LOG_RECORDS` records. Each
        // next page follows the records held so far. The log only grows at
        // its end, so the pages join into the log as the last page saw it.
        let mut records: Vec<WitnessRecord> = Vec::new();
        loop {
            let req = match u64::try_from(records.len()) {
                Ok(0) => WireRequest::Log { cell, chain },
                Ok(after) => WireRequest::LogAfter { cell, chain, after },
                Err(_) => return Err(WitnessFault::Unreachable),
            };
            match self.exchange(&req).await? {
                WireReply::Log(page) => {
                    // An empty page that says more follow never decodes, so
                    // every round adds records or ends.
                    let more = page.more && !page.records.is_empty();
                    records.extend(page.records);
                    if !more {
                        return Ok(records);
                    }
                }
                WireReply::Refused => return Err(WitnessFault::Refused),
                _ => return Err(WitnessFault::Unreachable),
            }
        }
    }
}
