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
//! [`CnClient`] applies this policy over a [`CnTransport`]. The TLS
//! transport to the two service hosts needs a root store for their public
//! certificates, which no allowlisted crate provides yet, and Q34 is open
//! (design section 10.1). It is the seam a transport fills.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use fstp_checks::runner::{Fetch, FetchFault, Fetched};
use fstp_checks::url::{DeliverableUrl, Scheme};
use fstp_release::egress::{CnCall, EgressResponse, LICENCE_HOST, UPDATE_HOST};
use fstp_rt::Runtime;

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
    /// A deliverable host that is not on the cell's forge allowlist
    /// (M5 design section 11).
    ForgeNotAllowlisted,
    /// A deliverable fetch over http outside the e2e test cell.
    ForgeScheme,
    /// A deliverable host at a private, loopback, link-local or other
    /// non-public address.
    ForgeAddress,
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
