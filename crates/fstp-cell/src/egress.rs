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

use std::future::Future;
use std::time::Duration;

use fstp_release::egress::{
    CnCall, EgressResponse, LICENCE_HOST, MAX_BODY_LEN, MAX_HEAD_LEN, UPDATE_HOST, decode_response,
};
use fstp_rt::{Connection, IoExt, Runtime, timeout};

use crate::config::Mode;

/// Where a cell may open a connection. Closed and exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        let request = b"GET /v1/updates/stable/0.3.0 HTTP/1.1\r\nHost: x\r\n\r\n";
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
        assert_eq!(
            server.unwrap(),
            b"GET /v1/updates/stable/0.3.0 HTTP/1.1\r\nHost: x\r\n\r\n"
        );
    }
}
