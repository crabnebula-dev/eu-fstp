//! The closed set of outbound destinations of a cell and the connector
//! policy (B4, I-16, I-38, ADR-009 "Outbound destinations").
//!
//! The cell's connector opens connections only to a [`Destination`], and
//! the host firewall holds the same list. No variant reaches a payment
//! service or names a platform account (I-16).
//! `i16_cell_egress_has_no_payment_destination` enumerates the enum. A new
//! variant needs an amendment of ADR-009.
//!
//! # Policy (I-38)
//!
//! - Only [`Destination::CrabNebula`] may reach a CrabNebula host, and
//!   only the host its `CnCall` names. [`check_host`] refuses a CrabNebula
//!   host for every other destination.
//! - Only a self-hosted cell builds a CrabNebula call. A SaaS cell is
//!   refused before any byte is written (B12).
//! - The request bytes are exactly `fstp_release::egress::encode` of the
//!   call. No other code builds them.
//!
//! [`CnClient`] applies this policy over a [`CnTransport`].
//! [`TlsCnTransport`] is the TLS transport to the two service hosts. It
//! verifies each server certificate against the public root store and the
//! host name ([`service_tls`], ADR-001 amendment of 2026-11-06). Q34 is
//! still open (design section 10.1), so no cell process builds it yet.
//!
//! # Mail submission (ADR-018, proposed)
//!
//! [`Destination::MailSubmission`] reaches the tenant's submission relay,
//! on port 465 only, with implicit TLS verified against the public roots
//! plus the tenant's optional pinned CA ([`mail_tls`]). A CrabNebula host
//! is never a relay (I-38). [`MailEgress`] is the only way the cell opens
//! it, and `fstp_smtp` speaks SMTP over the stream it opens.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use fstp_checks::runner::{Fetch, FetchFault, Fetched};
use fstp_checks::url::{DeliverableUrl, Scheme};
use fstp_release::egress::{
    CnCall, EgressResponse, LICENCE_HOST, MAX_BODY_LEN, MAX_HEAD_LEN, UPDATE_HOST, decode_response,
};
use fstp_rt::{Connection, IoExt, Runtime, timeout};
use fstp_smtp::client::{Credentials, Envelope, SUBMISSION_PORT, SmtpClient, SmtpError, Staged};

use crate::config::Mode;

/// Where a cell may open a connection. Closed and exhaustive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `c_<cell>` on its application cluster, one pool per role.
    AppDatabase,
    /// Its own vault, over internal mTLS.
    Vault,
    /// Its own App and CellBackup custody entries.
    Custody,
    /// SaaS only: the control plane, through `CellToCp`. A self-hosted
    /// cell never builds it.
    ControlPlane,
    /// The witness, for the App chain's prepares, aborts and receipts.
    Witness,
    /// Self-hosted only: a CrabNebula host. The request is built only by
    /// `fstp_release::egress` (I-38). A SaaS cell never builds it.
    CrabNebula(CnCall),
    /// The `<cell>/keystore/` object storage prefix only. Proposed by
    /// ADR-012 and pending Daniel, so no connector builds it yet.
    KeystoreSnapshots,
    /// The tenant's mail submission relay, port 465 only, with implicit
    /// TLS (ADR-018, proposed). The host comes from the tenant's mail
    /// settings and is never a CrabNebula host (I-38).
    MailSubmission {
        /// The relay host.
        host: MailHost,
    },
}

/// Why the connector refused a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressRefusal {
    /// A CrabNebula host for a destination other than
    /// [`Destination::CrabNebula`], or a CrabNebula call to a host other
    /// than the one it names (I-38).
    CrabNebulaHost,
    /// A SaaS cell never reaches a CrabNebula host (B12, I-38).
    SaasNeverReachesCrabNebula,
    /// A self-hosted cell has no control plane.
    NoControlPlaneWhenSelfHosted,
    /// The destination is pending a decision, so no connector builds it
    /// (ADR-012 "Keystore snapshot path").
    PendingDecision,
    /// A deliverable host that is not on the cell's forge allowlist
    /// (M5 design section 11).
    ForgeNotAllowlisted,
    /// A deliverable fetch over http outside the e2e test cell.
    ForgeScheme,
    /// A deliverable host at a private, loopback, link-local or other
    /// non-public address.
    ForgeAddress,
    /// A mail submission on a port other than 465 (ADR-018).
    MailPort,
    /// A mail relay host that is not a DNS host name, or a connection to
    /// a host other than the configured relay (ADR-018).
    MailHost,
    /// A mail relay that resolves to a private, loopback, link-local or
    /// other non-public address (ADR-018).
    MailAddress,
}

/// A mail relay host: a DNS host name in lowercase, without a trailing
/// dot, and never a CrabNebula host (ADR-018, I-38).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailHost(String);

impl MailHost {
    /// The longest host name in bytes.
    pub const MAX_LEN: usize = 253;

    /// The relay host `host`.
    ///
    /// # Errors
    ///
    /// [`EgressRefusal::CrabNebulaHost`] for a CrabNebula host, and
    /// [`EgressRefusal::MailHost`] for anything but a host name of letters,
    /// digits and hyphens in dot-separated labels of 1 to 63 bytes. An
    /// address literal, a port or a path is refused, and so is a name whose
    /// last label is all digits.
    pub fn parse(host: &str) -> Result<MailHost, EgressRefusal> {
        let h = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        let ok = (1..=MailHost::MAX_LEN).contains(&h.len())
            && h.split('.').all(label_ok)
            && h.rsplit('.')
                .next()
                .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            return Err(EgressRefusal::MailHost);
        }
        if is_crabnebula_host(&h) {
            return Err(EgressRefusal::CrabNebulaHost);
        }
        Ok(MailHost(h))
    }

    /// The host name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `host` is a CrabNebula service host, compared without case
/// and without a trailing dot.
pub fn is_crabnebula_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    [LICENCE_HOST, UPDATE_HOST]
        .iter()
        .any(|c| h.eq_ignore_ascii_case(c))
        || h.to_ascii_lowercase().ends_with(".crabnebula.dev")
        || h.eq_ignore_ascii_case("crabnebula.dev")
}

/// Checks that the connector may open `to` at `host` (I-38).
///
/// # Errors
///
/// [`EgressRefusal::CrabNebulaHost`] for a CrabNebula host and any
/// destination but `CrabNebula`, and for a CrabNebula call to another
/// host. [`EgressRefusal::PendingDecision`] for
/// [`Destination::KeystoreSnapshots`].
pub fn check_host(to: &Destination, host: &str) -> Result<(), EgressRefusal> {
    match to {
        Destination::CrabNebula(call) => {
            if host.trim_end_matches('.').eq_ignore_ascii_case(call.host()) {
                Ok(())
            } else {
                Err(EgressRefusal::CrabNebulaHost)
            }
        }
        Destination::KeystoreSnapshots => Err(EgressRefusal::PendingDecision),
        Destination::MailSubmission { host: relay } => {
            if is_crabnebula_host(host) {
                Err(EgressRefusal::CrabNebulaHost)
            } else if host
                .strip_suffix('.')
                .unwrap_or(host)
                .eq_ignore_ascii_case(relay.as_str())
            {
                Ok(())
            } else {
                Err(EgressRefusal::MailHost)
            }
        }
        Destination::AppDatabase
        | Destination::Vault
        | Destination::Custody
        | Destination::ControlPlane
        | Destination::Witness => {
            if is_crabnebula_host(host) {
                Err(EgressRefusal::CrabNebulaHost)
            } else {
                Ok(())
            }
        }
    }
}

/// Checks that the connector may open `to` on `port`. Mail submission
/// uses port 465 only, implicit TLS (ADR-018, RFC 8314). The other
/// destinations take their ports from their own configuration.
///
/// # Errors
///
/// [`EgressRefusal::MailPort`] for a mail submission on any other port.
pub fn check_port(to: &Destination, port: u16) -> Result<(), EgressRefusal> {
    match to {
        Destination::MailSubmission { .. } if port != SUBMISSION_PORT => {
            Err(EgressRefusal::MailPort)
        }
        _ => Ok(()),
    }
}

/// Checks that a cell in `mode` may build `to` at all.
///
/// # Errors
///
/// [`EgressRefusal::SaasNeverReachesCrabNebula`],
/// [`EgressRefusal::NoControlPlaneWhenSelfHosted`] or
/// [`EgressRefusal::PendingDecision`].
pub fn check_mode(mode: Mode, to: &Destination) -> Result<(), EgressRefusal> {
    match (mode, to) {
        (Mode::Saas, Destination::CrabNebula(_)) => Err(EgressRefusal::SaasNeverReachesCrabNebula),
        (Mode::SelfHosted, Destination::ControlPlane) => {
            Err(EgressRefusal::NoControlPlaneWhenSelfHosted)
        }
        (_, Destination::KeystoreSnapshots) => Err(EgressRefusal::PendingDecision),
        _ => Ok(()),
    }
}

/// Checks that `to` is a destination a connector builds, at the host its
/// own definition fixes: a CrabNebula call only at the host it names. The
/// full check of a configured host is [`connect_to`].
///
/// # Errors
///
/// [`EgressRefusal::PendingDecision`] for
/// [`Destination::KeystoreSnapshots`].
pub fn connect(to: &Destination) -> Result<(), crate::CellError> {
    match to {
        Destination::CrabNebula(call) => check_host(to, call.host()),
        Destination::MailSubmission { host } => check_host(to, host.as_str()),
        Destination::KeystoreSnapshots => Err(EgressRefusal::PendingDecision),
        Destination::AppDatabase
        | Destination::Vault
        | Destination::Custody
        | Destination::ControlPlane
        | Destination::Witness => Ok(()),
    }
    .map_err(crate::CellError::Egress)
}

/// Checks `to` at `host` for a cell in `mode`: [`check_mode`], then
/// [`check_host`].
///
/// # Errors
///
/// The first refusal of the two checks.
pub fn connect_to(mode: Mode, to: &Destination, host: &str) -> Result<(), crate::CellError> {
    check_mode(mode, to)
        .and_then(|()| check_host(to, host))
        .map_err(crate::CellError::Egress)
}

/// Why a CrabNebula call gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnFault {
    /// The connector refused the call before any byte was written.
    Refused(EgressRefusal),
    /// The connection failed.
    Unreachable,
    /// The service answered with an error status.
    Status(u16),
    /// The answer did not decode.
    Malformed,
}

/// The byte link to a CrabNebula host, above TLS. The transport presents
/// the host as SNI and no client certificate (design section 10.1).
pub trait CnTransport: Send + Sync + 'static {
    /// Sends `request` to `host` and gives the whole response.
    fn exchange(
        &self,
        host: &'static str,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send;
}

/// The client of the CrabNebula services. It is the only caller of a
/// [`CnTransport`], and it builds request bytes only through
/// `fstp_release::egress::encode` (I-38).
#[derive(Debug)]
pub struct CnClient<T> {
    mode: Mode,
    transport: T,
}

impl<T: CnTransport> CnClient<T> {
    /// A client for a cell in `mode`.
    pub fn new(mode: Mode, transport: T) -> CnClient<T> {
        CnClient { mode, transport }
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Sends `call` to the host it names and decodes the answer.
    ///
    /// # Errors
    ///
    /// [`CnFault::Refused`] for a SaaS cell, before any byte is written;
    /// otherwise the transport's fault, a non-2xx status, or a malformed
    /// answer.
    pub async fn call(&self, call: CnCall) -> Result<EgressResponse, CnFault> {
        let to = Destination::CrabNebula(call);
        let host = call.host();
        check_mode(self.mode, &to)
            .and_then(|()| check_host(&to, host))
            .map_err(CnFault::Refused)?;
        let bytes = fstp_release::egress::encode(&call).map_err(|_| CnFault::Malformed)?;
        let answer = self.transport.exchange(host, bytes).await?;
        let response =
            fstp_release::egress::decode_response(&answer).map_err(|_| CnFault::Malformed)?;
        if (200..300).contains(&response.status) {
            Ok(response)
        } else {
            Err(CnFault::Status(response.status))
        }
    }
}

/// The port of both CrabNebula service hosts (HTTPS).
pub const SERVICE_PORT: u16 = 443;

/// How long one exchange with a service host may take, from the name
/// lookup to the last response byte.
pub const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest answer read from a service host: the most that
/// `fstp_release::egress::decode_response` accepts.
const MAX_ANSWER: usize = MAX_HEAD_LEN + 4 + MAX_BODY_LEN;

/// The TLS client configuration for the CrabNebula service hosts: the
/// public root store with the host name check (ADR-001 amendment of
/// 2026-11-06), and no client certificate (design section 10.1).
/// Verification is never disabled.
///
/// # Errors
///
/// The configuration error of `fstp-tls`, which a fixed root set makes
/// unexpected.
pub fn service_tls() -> Result<fstp_tls::ClientConfig, fstp_tls::TlsError> {
    fstp_tls::ClientConfig::public_roots()
}

/// The TLS transport to the CrabNebula service hosts over a runtime. It
/// resolves the host, opens TCP to [`SERVICE_PORT`], verifies the server
/// against its TLS configuration with the host as SNI and name, and
/// presents no client certificate.
#[derive(Clone, Debug)]
pub struct TlsCnTransport<R> {
    rt: R,
    tls: fstp_tls::ClientConfig,
}

impl<R: Runtime> TlsCnTransport<R> {
    /// A transport that trusts the public roots ([`service_tls`]).
    ///
    /// # Errors
    ///
    /// The configuration error of [`service_tls`].
    pub fn new(rt: R) -> Result<TlsCnTransport<R>, fstp_tls::TlsError> {
        Ok(TlsCnTransport {
            rt,
            tls: service_tls()?,
        })
    }

    /// A transport with its own TLS configuration, such as the public
    /// roots plus a pinned CA.
    pub fn with_tls(rt: R, tls: fstp_tls::ClientConfig) -> TlsCnTransport<R> {
        TlsCnTransport { rt, tls }
    }
}

impl<R: Runtime> CnTransport for TlsCnTransport<R> {
    fn exchange(
        &self,
        host: &'static str,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send {
        let rt = self.rt.clone();
        let tls = self.tls.clone();
        async move {
            let run = async {
                let addrs = rt
                    .resolve(host, SERVICE_PORT)
                    .await
                    .map_err(|_| CnFault::Unreachable)?;
                let addr = addrs.first().copied().ok_or(CnFault::Unreachable)?;
                let tcp = rt
                    .connect_tcp(addr)
                    .await
                    .map_err(|_| CnFault::Unreachable)?;
                exchange_over(&tls, host, tcp, &request).await
            };
            timeout(&rt, SERVICE_TIMEOUT, run)
                .await
                .map_err(|_| CnFault::Unreachable)?
        }
    }
}

/// One request and its answer over `io`: the TLS handshake with `host`
/// as SNI and verified name, the request, then reads until the bytes form
/// one complete response or the peer closes.
///
/// A refused server certificate, an unknown CA or a host name mismatch
/// among them, gives [`CnFault::Unreachable`] before any request byte is
/// written. Completeness is judged by `decode_response` itself, so no
/// second response parser exists.
///
/// # Errors
///
/// [`CnFault::Unreachable`] when the handshake or the transport fails,
/// and [`CnFault::Malformed`] past the answer size limit.
pub async fn exchange_over<S: Connection>(
    tls: &fstp_tls::ClientConfig,
    host: &str,
    io: S,
    request: &[u8],
) -> Result<Vec<u8>, CnFault> {
    let mut stream = fstp_tls::connect(tls, host, io)
        .await
        .map_err(|_| CnFault::Unreachable)?;
    stream
        .write_all(request)
        .await
        .map_err(|_| CnFault::Unreachable)?;
    stream.flush().await.map_err(|_| CnFault::Unreachable)?;
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // A peer that closes without close_notify after a complete
            // answer has still answered.
            Err(_) if decode_response(&answer).is_ok() => break,
            Err(_) => return Err(CnFault::Unreachable),
        };
        if n == 0 {
            break;
        }
        answer.extend_from_slice(chunk.get(..n).ok_or(CnFault::Malformed)?);
        if answer.len() > MAX_ANSWER {
            return Err(CnFault::Malformed);
        }
        if decode_response(&answer).is_ok() {
            break;
        }
    }
    Ok(answer)
}

// ---------------------------------------------------------------------------
// Mail submission (ADR-018, proposed; M6 design section 5.4).

/// How long opening the TCP link to the relay may take, from the name
/// lookup to the connected socket. The SMTP client's own deadlines start
/// with the TLS handshake.
pub const MAIL_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a mail submission gave no staged message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailFault {
    /// The connector refused the relay, the port or an address before
    /// any byte was written.
    Refused(EgressRefusal),
    /// The pinned CA is not valid PEM, so no TLS configuration exists.
    /// Verification is never turned off instead.
    Config,
    /// The name lookup or the TCP connection failed or timed out.
    Unreachable,
    /// The TLS handshake or the SMTP session failed. An unknown CA or a
    /// host name mismatch is `SmtpError::Tls`.
    Smtp(SmtpError),
}

/// The TLS client configuration for a mail relay: the public root store
/// with the host name check (ADR-001 amendment of 2026-11-06), plus the
/// tenant's pinned CA when it names one. Verification is never disabled.
///
/// # Errors
///
/// The configuration error of `fstp-tls`, for a pinned CA that is not
/// valid PEM.
pub fn mail_tls(ca_pem: Option<&[u8]>) -> Result<fstp_tls::ClientConfig, fstp_tls::TlsError> {
    match ca_pem {
        None => fstp_tls::ClientConfig::public_roots(),
        Some(pem) => fstp_tls::ClientConfig::public_roots_builder()
            .also_trust_pem(pem)
            .build(),
    }
}

/// The byte link to a mail relay, below TLS.
pub trait MailTransport: Send + Sync + 'static {
    /// The connection it opens.
    type Conn: Connection;

    /// Opens a connection to `host` on `port`.
    fn open(
        &self,
        host: &MailHost,
        port: u16,
    ) -> impl Future<Output = Result<Self::Conn, MailFault>> + Send;
}

/// The TCP transport to a mail relay over a runtime. It opens port 465
/// only, resolves the host, and refuses the relay when any resolved
/// address is not a public unicast address.
#[derive(Clone, Debug)]
pub struct TcpMailTransport<R> {
    rt: R,
}

impl<R: Runtime> TcpMailTransport<R> {
    /// A transport on `rt`.
    pub fn new(rt: R) -> TcpMailTransport<R> {
        TcpMailTransport { rt }
    }
}

impl<R: Runtime> MailTransport for TcpMailTransport<R> {
    type Conn = R::Tcp;

    fn open(
        &self,
        host: &MailHost,
        port: u16,
    ) -> impl Future<Output = Result<R::Tcp, MailFault>> + Send {
        let rt = self.rt.clone();
        let host = host.clone();
        async move {
            if port != SUBMISSION_PORT {
                return Err(MailFault::Refused(EgressRefusal::MailPort));
            }
            let run = async {
                let addrs = rt
                    .resolve(host.as_str(), port)
                    .await
                    .map_err(|_| MailFault::Unreachable)?;
                if addrs.iter().any(|a| !public_ip(a.ip())) {
                    return Err(MailFault::Refused(EgressRefusal::MailAddress));
                }
                let addr = addrs.first().copied().ok_or(MailFault::Unreachable)?;
                rt.connect_tcp(addr)
                    .await
                    .map_err(|_| MailFault::Unreachable)
            };
            timeout(&rt, MAIL_CONNECT_TIMEOUT, run)
                .await
                .map_err(|_| MailFault::Unreachable)?
        }
    }
}

/// The cell's only way to its mail relay: the connector policy of
/// [`Destination::MailSubmission`] over a [`MailTransport`], and the
/// `fstp_smtp` client over the stream it opens.
#[derive(Debug)]
pub struct MailEgress<R, T> {
    rt: R,
    transport: T,
    to: Destination,
    host: MailHost,
    client: SmtpClient,
}

impl<R: Runtime, T: MailTransport> MailEgress<R, T> {
    /// The egress of a cell in `mode` to the relay `host`, trusting the
    /// public roots plus `ca_pem` when given, introducing itself as `helo`
    /// and authenticating with `credentials`.
    ///
    /// # Errors
    ///
    /// [`MailFault::Refused`] for a host that is not a host name or is a
    /// CrabNebula host, and [`MailFault::Config`] for an invalid pinned CA.
    pub fn new(
        mode: Mode,
        rt: R,
        transport: T,
        host: &str,
        ca_pem: Option<&[u8]>,
        helo: &str,
        credentials: Credentials,
    ) -> Result<MailEgress<R, T>, MailFault> {
        let host = MailHost::parse(host).map_err(MailFault::Refused)?;
        let to = Destination::MailSubmission { host: host.clone() };
        check_mode(mode, &to)
            .and_then(|()| check_host(&to, host.as_str()))
            .map_err(MailFault::Refused)?;
        let tls = mail_tls(ca_pem).map_err(|_| MailFault::Config)?;
        let client = SmtpClient::new(tls, host.as_str(), helo, credentials);
        Ok(MailEgress {
            rt,
            transport,
            to,
            host,
            client,
        })
    }

    /// The same egress with other SMTP deadlines.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: fstp_smtp::client::Timeouts) -> Self {
        self.client = self.client.with_timeouts(timeouts);
        self
    }

    /// The relay host.
    pub fn host(&self) -> &MailHost {
        &self.host
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Opens the relay on port 465 and stages `body` for `envelope`: the
    /// whole session except the final dot (`fstp_smtp`, I-26). The TLS
    /// handshake verifies the relay against [`mail_tls`] and its host
    /// name, so an unknown CA ends the session before any SMTP byte.
    ///
    /// # Errors
    ///
    /// [`MailFault`] for a refusal, an unreachable relay, or a failed
    /// handshake or session. None of them is in doubt.
    pub async fn stage(
        &self,
        envelope: &Envelope,
        body: &[u8],
    ) -> Result<Staged<R, T::Conn>, MailFault> {
        check_port(&self.to, SUBMISSION_PORT).map_err(MailFault::Refused)?;
        let io = self.transport.open(&self.host, SUBMISSION_PORT).await?;
        self.client
            .stage(&self.rt, io, envelope, body)
            .await
            .map_err(MailFault::Smtp)
    }
}

// ---------------------------------------------------------------------------
// Deliverable fetches of the payment checks (M5 design section 11).
//
// The checks runner fetches deliverable locations and licence files that
// grantees supply. It reaches them only through a [`ForgeClient`]:
//
// - the host is on the cell's forge allowlist, compared without case, and
//   is never a CrabNebula host (I-38);
// - the scheme is https, and every resolved address is public: private,
//   loopback, link-local, shared, documentation, multicast and reserved
//   ranges are refused, IPv4-mapped IPv6 included. A host with any refused
//   address is refused as a whole;
// - one fetch takes at most [`FORGE_MAX_TIME`] and [`FORGE_MAX_BYTES`];
// - no arbitrary URL is fetched, since the URL is the strict subset of
//   `fstp_checks::url`, and the transport follows no redirect.
//
// The e2e test cell's local forge alone may use http on loopback, through
// [`ForgePolicy::test_cell`]. No shipped configuration builds it.
//
// The deliverable connector is not a `Destination` variant yet: ADR-009
// says a new variant needs its amendment, which waits for Daniel. The
// policy here is the one that amendment would name.

/// The most bytes one deliverable fetch reads.
pub const FORGE_MAX_BYTES: usize = 2 * 1024 * 1024;
/// The longest one deliverable fetch may take, resolution included.
pub const FORGE_MAX_TIME: Duration = Duration::from_secs(10);

/// Which forges the checks may reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgePolicy {
    hosts: BTreeSet<String>,
    local: bool,
}

fn normal_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `ip` is a public unicast IPv4 address.
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

/// Whether `ip` is a public unicast address. An IPv4-mapped IPv6 address
/// is judged as its IPv4 address.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let s = v6.segments();
            let first = s.first().copied().unwrap_or(0);
            // 2000::/3 is the global unicast range. Inside it, the
            // documentation prefix 2001:db8::/32 is refused.
            (first & 0xe000) == 0x2000 && !(first == 0x2001 && s.get(1) == Some(&0x0db8))
        }
    }
}

impl ForgePolicy {
    /// The policy of a cell: https to public addresses of `hosts` only.
    pub fn new<S: AsRef<str>>(hosts: impl IntoIterator<Item = S>) -> ForgePolicy {
        ForgePolicy {
            hosts: hosts.into_iter().map(|h| normal_host(h.as_ref())).collect(),
            local: false,
        }
    }

    /// The policy of the e2e test cell: as [`ForgePolicy::new`], and http
    /// and loopback addresses are allowed for its local forge.
    pub fn test_cell<S: AsRef<str>>(hosts: impl IntoIterator<Item = S>) -> ForgePolicy {
        ForgePolicy {
            local: true,
            ..ForgePolicy::new(hosts)
        }
    }

    /// Checks that the checks may fetch `url`.
    ///
    /// # Errors
    ///
    /// [`EgressRefusal::CrabNebulaHost`] for a CrabNebula host,
    /// [`EgressRefusal::ForgeNotAllowlisted`] for a host off the
    /// allowlist, [`EgressRefusal::ForgeScheme`] for http outside the test
    /// cell, and [`EgressRefusal::ForgeAddress`] for an IP literal host
    /// whose address is refused.
    pub fn check_url(&self, url: &DeliverableUrl) -> Result<(), EgressRefusal> {
        let host = normal_host(url.host());
        if is_crabnebula_host(&host) {
            return Err(EgressRefusal::CrabNebulaHost);
        }
        if !self.hosts.contains(&host) {
            return Err(EgressRefusal::ForgeNotAllowlisted);
        }
        if url.scheme() == Scheme::Http && !self.local {
            return Err(EgressRefusal::ForgeScheme);
        }
        match url.ip_literal() {
            Some(ip) => self.check_addr(IpAddr::V4(ip)),
            None => Ok(()),
        }
    }

    /// Checks that the checks may connect to `ip`.
    ///
    /// # Errors
    ///
    /// [`EgressRefusal::ForgeAddress`] for an address outside the public
    /// unicast ranges, except loopback in the test cell.
    pub fn check_addr(&self, ip: IpAddr) -> Result<(), EgressRefusal> {
        if public_ip(ip) || (self.local && ip.is_loopback()) {
            Ok(())
        } else {
            Err(EgressRefusal::ForgeAddress)
        }
    }
}

/// The byte link to a forge. It sends an unauthenticated GET with no
/// cookie, follows no redirect, and reads at most `max_bytes` plus one of
/// the body, so a longer body is reported as `TooLarge`.
pub trait ForgeTransport: Send + Sync + 'static {
    /// Resolves `host` to its addresses.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<IpAddr>, FetchFault>> + Send;

    /// Sends a GET of `url` to `addr`.
    fn get(
        &self,
        addr: SocketAddr,
        url: &DeliverableUrl,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Fetched, FetchFault>> + Send;
}

/// The checks' only way out of the cell: [`ForgePolicy`] over a
/// [`ForgeTransport`], within the size and time caps.
#[derive(Debug)]
pub struct ForgeClient<R, T> {
    policy: ForgePolicy,
    rt: R,
    transport: T,
}

impl<R: Runtime, T: ForgeTransport> ForgeClient<R, T> {
    /// A client applying `policy` over `transport`, timed on `rt`.
    pub fn new(policy: ForgePolicy, rt: R, transport: T) -> ForgeClient<R, T> {
        ForgeClient {
            policy,
            rt,
            transport,
        }
    }

    async fn fetch_within(&self, url: &DeliverableUrl) -> Result<Fetched, FetchFault> {
        self.policy
            .check_url(url)
            .map_err(|_| FetchFault::Refused)?;
        let addrs = self.transport.resolve(url.host(), url.port()).await?;
        if addrs.iter().any(|a| self.policy.check_addr(*a).is_err()) {
            return Err(FetchFault::Refused);
        }
        let first = addrs.first().copied().ok_or(FetchFault::Unreachable)?;
        let got = self
            .transport
            .get(SocketAddr::new(first, url.port()), url, FORGE_MAX_BYTES)
            .await?;
        if got.body.len() > FORGE_MAX_BYTES {
            return Err(FetchFault::TooLarge);
        }
        Ok(got)
    }
}

impl<R: Runtime, T: ForgeTransport> Fetch for ForgeClient<R, T> {
    async fn fetch(&self, url: &DeliverableUrl) -> Result<Fetched, FetchFault> {
        fstp_rt::timeout(&self.rt, FORGE_MAX_TIME, self.fetch_within(url))
            .await
            .unwrap_or(Err(FetchFault::TimedOut))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_release::egress::{Channel, ProductVersion, UpdateCheck};

    /// I-38: every destination but `CrabNebula` is refused at both
    /// CrabNebula hosts, and a call is refused at the other host.
    #[test]
    fn i38_connector_refuses_crabnebula_hosts_for_other_destinations() {
        let others = [
            Destination::AppDatabase,
            Destination::Vault,
            Destination::Custody,
            Destination::ControlPlane,
            Destination::Witness,
        ];
        for d in others {
            for h in [LICENCE_HOST, UPDATE_HOST, "LICENCES.fstp.crabnebula.dev."] {
                assert_eq!(check_host(&d, h), Err(EgressRefusal::CrabNebulaHost));
            }
            assert_eq!(check_host(&d, "db.cell.internal"), Ok(()));
        }
        let call = CnCall::Update(UpdateCheck {
            version: ProductVersion(0, 3, 0),
            channel: Channel::Stable,
        });
        let to = Destination::CrabNebula(call);
        assert_eq!(check_host(&to, UPDATE_HOST), Ok(()));
        assert_eq!(
            check_host(&to, LICENCE_HOST),
            Err(EgressRefusal::CrabNebulaHost)
        );
        assert_eq!(
            check_mode(Mode::Saas, &to),
            Err(EgressRefusal::SaasNeverReachesCrabNebula)
        );
    }

    macro_rules! tls_testdata {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fstp-tls/testdata/",
                $name
            ))
            .as_slice()
        };
    }

    const TEST_CA: &[u8] = tls_testdata!("ca.pem");
    const TEST_SERVER: &[u8] = tls_testdata!("server.pem");
    const TEST_SERVER_KEY: &[u8] = tls_testdata!("server-key.pem");

    /// A test server under the test CA, valid for `localhost`. It reads
    /// one request head, answers `answer` and keeps the connection open,
    /// so the client must stop at a complete response. It gives what it
    /// read, or `None` when the handshake failed.
    async fn serve_once(io: fstp_rt::duplex::DuplexStream, answer: &[u8]) -> Option<Vec<u8>> {
        let cfg = fstp_tls::ServerConfig::new(TEST_SERVER, TEST_SERVER_KEY).ok()?;
        let mut tls = fstp_tls::accept(&cfg, io).await.ok()?;
        let mut got = Vec::new();
        let mut chunk = [0u8; 512];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        tls.write_all(answer).await.ok()?;
        tls.flush().await.ok()?;
        Some(got)
    }

    fn run(
        tls: &fstp_tls::ClientConfig,
        host: &str,
        answer: &[u8],
    ) -> (Result<Vec<u8>, CnFault>, Option<Vec<u8>>) {
        let (c, s) = fstp_rt::duplex::duplex(4096);
        let request = b"GET /probe HTTP/1.1\r\nHost: x\r\n\r\n";
        fstp_rt::future::block_on(fstp_rt::future::join(
            exchange_over(tls, host, c, request),
            serve_once(s, answer),
        ))
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    /// R-NF-09, I-38: the service host configuration trusts the public
    /// roots only. A server under an unknown CA is refused in the
    /// handshake, before any request byte reaches it.
    #[test]
    fn r_nf_09_service_tls_refuses_unknown_ca() {
        let tls = service_tls().unwrap();
        assert!(format!("{tls:?}").contains("public_roots: true"));
        let (client, server) = run(&tls, "localhost", OK);
        assert_eq!(client, Err(CnFault::Unreachable));
        assert_eq!(server, None);
    }

    /// R-NF-09, I-38: a trusted chain for another name is refused too. The
    /// test CA is pinned on top of the public roots, and the certificate
    /// names `localhost`, not the update host.
    #[test]
    fn r_nf_09_service_tls_refuses_host_name_mismatch() {
        let tls = fstp_tls::ClientConfig::public_roots_builder()
            .also_trust_pem(TEST_CA)
            .build()
            .unwrap();
        for host in [UPDATE_HOST, LICENCE_HOST] {
            let (client, server) = run(&tls, host, OK);
            assert_eq!(client, Err(CnFault::Unreachable), "{host}");
            assert_eq!(server, None, "{host}");
        }
    }

    /// I-38: over a verified link the request bytes arrive unchanged, and
    /// the transport stops at the first complete response without waiting
    /// for the server to close.
    #[test]
    fn i38_tls_exchange_delivers_request_and_complete_answer() {
        let tls = fstp_tls::ClientConfig::public_roots_builder()
            .also_trust_pem(TEST_CA)
            .build()
            .unwrap();
        let (client, server) = run(&tls, "localhost", OK);
        let answer = client.unwrap();
        assert_eq!(answer, OK);
        let decoded = decode_response(&answer).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(server.unwrap(), b"GET /probe HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    fn relay() -> Destination {
        Destination::MailSubmission {
            host: MailHost::parse("smtp.relay.example").unwrap(),
        }
    }

    /// ADR-018, B4: the mail submission destination opens port 465 only.
    /// Every other port, the other submission and relay ports among them,
    /// is refused before any connection.
    #[test]
    fn adr018_mail_submission_refuses_every_port_but_465() {
        let to = relay();
        assert_eq!(check_port(&to, 465), Ok(()));
        for port in [0, 25, 443, 464, 466, 587, 2525, u16::MAX] {
            assert_eq!(
                check_port(&to, port),
                Err(EgressRefusal::MailPort),
                "{port}"
            );
        }
    }

    /// ADR-018, I-38: no mail relay is a CrabNebula host. The host is
    /// refused when parsed, and the connector refuses a CrabNebula host or
    /// any host other than the configured one, in both modes.
    #[test]
    fn i38_mail_submission_refuses_crabnebula_hosts() {
        for h in [
            LICENCE_HOST,
            UPDATE_HOST,
            "smtp.crabnebula.dev",
            "CrabNebula.dev.",
            "mx.fstp.CRABNEBULA.dev",
        ] {
            assert_eq!(
                MailHost::parse(h),
                Err(EgressRefusal::CrabNebulaHost),
                "{h}"
            );
        }
        let to = relay();
        for mode in [Mode::Saas, Mode::SelfHosted] {
            assert_eq!(check_mode(mode, &to), Ok(()));
        }
        assert_eq!(check_host(&to, "smtp.relay.example"), Ok(()));
        assert_eq!(check_host(&to, "SMTP.relay.example."), Ok(()));
        assert_eq!(
            check_host(&to, UPDATE_HOST),
            Err(EgressRefusal::CrabNebulaHost)
        );
        assert_eq!(
            check_host(&to, "other.relay.example"),
            Err(EgressRefusal::MailHost)
        );
        assert_eq!(connect(&to), Ok(()));
    }

    /// ADR-018: a relay is a DNS host name. An address literal, a port,
    /// a path, an empty label or an over-long name is refused.
    #[test]
    fn adr018_mail_host_is_a_host_name() {
        assert_eq!(
            MailHost::parse("Smtp.Relay.Example.").map(|h| h.as_str().to_owned()),
            Ok("smtp.relay.example".to_owned())
        );
        assert!(MailHost::parse("localhost").is_ok());
        let long = format!("{}.example", "a".repeat(250));
        for bad in [
            "",
            ".",
            "10.0.0.1",
            "[::1]",
            "::1",
            "smtp.relay.example:587",
            "smtp.relay.example/x",
            "smtp..relay.example",
            "-smtp.relay.example",
            "smtp-.relay.example",
            "smtp relay.example",
            "smtp_relay.example",
            long.as_str(),
        ] {
            assert_eq!(MailHost::parse(bad), Err(EgressRefusal::MailHost), "{bad}");
        }
    }

    /// ADR-018, R-NF-09: the mail TLS configuration trusts the public
    /// roots, with a pinned CA on top when the tenant names one. Invalid
    /// PEM is a configuration fault, never a fallback to no verification.
    #[test]
    fn adr018_mail_tls_is_public_roots_plus_optional_pin() {
        let plain = mail_tls(None).unwrap();
        assert!(format!("{plain:?}").contains("public_roots: true"));
        let pinned = mail_tls(Some(TEST_CA)).unwrap();
        assert!(format!("{pinned:?}").contains("public_roots: true"));
        assert!(mail_tls(Some(b"-----BEGIN CERTIFICATE-----\nnope\n")).is_err());
    }

    /// I-16, ADR-018: the transport opens port 465 only and refuses a
    /// relay that resolves to a non-public address, before any byte.
    #[test]
    fn adr018_tcp_mail_transport_refuses_other_ports_and_private_addresses() {
        let rt = TokioRuntime::new_current_thread().unwrap();
        let t = TcpMailTransport::new(rt.clone());
        let host = MailHost::parse("localhost").unwrap();
        let r = rt.block_on(t.open(&host, 587));
        assert_eq!(r.err(), Some(MailFault::Refused(EgressRefusal::MailPort)));
        let r = rt.block_on(t.open(&host, SUBMISSION_PORT));
        assert_eq!(
            r.err(),
            Some(MailFault::Refused(EgressRefusal::MailAddress))
        );
    }

    use std::sync::Mutex;

    use fstp_rt::tokio::TokioRuntime;

    /// A transport that resolves every host to `addr` and answers
    /// `body`, recording each GET.
    struct FakeForge {
        addr: IpAddr,
        body: Vec<u8>,
        gets: Mutex<Vec<String>>,
    }

    impl ForgeTransport for FakeForge {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> impl Future<Output = Result<Vec<IpAddr>, FetchFault>> + Send {
            std::future::ready(Ok(vec![self.addr]))
        }

        fn get(
            &self,
            _addr: SocketAddr,
            url: &DeliverableUrl,
            _max_bytes: usize,
        ) -> impl Future<Output = Result<Fetched, FetchFault>> + Send {
            if let Ok(mut g) = self.gets.lock() {
                g.push(url.to_string());
            }
            std::future::ready(Ok(Fetched {
                status: 200,
                body: self.body.clone(),
            }))
        }
    }

    fn url(s: &str) -> DeliverableUrl {
        DeliverableUrl::parse(s).unwrap()
    }

    /// R-PR-02, M5 design section 11, I-38: the forge egress refuses any
    /// host off the allowlist, a CrabNebula host even when listed, and
    /// http outside the test cell.
    #[test]
    fn r_pr_02_forge_egress_refuses_hosts_off_the_allowlist() {
        let p = ForgePolicy::new(["Forge.Example.", UPDATE_HOST]);
        assert_eq!(p.check_url(&url("https://forge.example/a")), Ok(()));
        assert_eq!(p.check_url(&url("https://FORGE.example./a")), Ok(()));
        for off in [
            "https://evil.example/a",
            "https://sub.forge.example/a",
            "https://forge.example.evil.example/a",
            "https://10.0.0.1/a",
        ] {
            assert_eq!(
                p.check_url(&url(off)),
                Err(EgressRefusal::ForgeNotAllowlisted),
                "{off}"
            );
        }
        assert_eq!(
            p.check_url(&url(&format!("https://{UPDATE_HOST}/a"))),
            Err(EgressRefusal::CrabNebulaHost)
        );
        assert_eq!(
            p.check_url(&url("http://forge.example/a")),
            Err(EgressRefusal::ForgeScheme)
        );
        let local = ForgePolicy::new(["127.0.0.1"]);
        assert_eq!(
            local.check_url(&url("https://127.0.0.1/a")),
            Err(EgressRefusal::ForgeAddress)
        );
        let test = ForgePolicy::test_cell(["127.0.0.1"]);
        assert_eq!(
            test.check_url(&url("http://127.0.0.1:8080/demo/forge/a")),
            Ok(())
        );
    }

    /// M5 design section 11: private, loopback, link-local and other
    /// non-public addresses are refused, IPv4-mapped ones included.
    #[test]
    fn r_pr_02_forge_egress_refuses_non_public_addresses() {
        let p = ForgePolicy::new(["forge.example"]);
        for bad in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
            "ff02::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert_eq!(p.check_addr(ip), Err(EgressRefusal::ForgeAddress), "{bad}");
        }
        for good in ["93.184.216.34", "2a01:4f8::1", "::ffff:93.184.216.34"] {
            let ip: IpAddr = good.parse().unwrap();
            assert_eq!(p.check_addr(ip), Ok(()), "{good}");
        }
        let test = ForgePolicy::test_cell(["localhost"]);
        assert_eq!(test.check_addr("127.0.0.1".parse().unwrap()), Ok(()));
        assert_eq!(
            test.check_addr("10.0.0.1".parse().unwrap()),
            Err(EgressRefusal::ForgeAddress)
        );
    }

    /// M5 design section 11: the client sends nothing for a refused host
    /// or a host that resolves to a private address, and caps the body.
    #[test]
    fn r_pr_02_forge_client_fetches_only_allowed_public_hosts() {
        let rt = TokioRuntime::new_current_thread().unwrap();
        let policy = ForgePolicy::new(["forge.example"]);
        let public = ForgeClient::new(
            policy.clone(),
            rt.clone(),
            FakeForge {
                addr: "93.184.216.34".parse().unwrap(),
                body: b"synthetic".to_vec(),
                gets: Mutex::new(Vec::new()),
            },
        );
        let ok = rt.block_on(public.fetch(&url("https://forge.example/a")));
        assert_eq!(ok.map(|f| f.body), Ok(b"synthetic".to_vec()));
        let off = rt.block_on(public.fetch(&url("https://evil.example/a")));
        assert_eq!(off, Err(FetchFault::Refused));
        assert_eq!(public.transport.gets.lock().unwrap().len(), 1);

        let rebinding = ForgeClient::new(
            policy.clone(),
            rt.clone(),
            FakeForge {
                addr: "10.0.0.7".parse().unwrap(),
                body: Vec::new(),
                gets: Mutex::new(Vec::new()),
            },
        );
        let r = rt.block_on(rebinding.fetch(&url("https://forge.example/a")));
        assert_eq!(r, Err(FetchFault::Refused));
        assert!(rebinding.transport.gets.lock().unwrap().is_empty());

        let big = ForgeClient::new(
            policy,
            rt.clone(),
            FakeForge {
                addr: "93.184.216.34".parse().unwrap(),
                body: vec![0; FORGE_MAX_BYTES + 1],
                gets: Mutex::new(Vec::new()),
            },
        );
        let r = rt.block_on(big.fetch(&url("https://forge.example/a")));
        assert_eq!(r, Err(FetchFault::TooLarge));
    }
}
