//! The prober of the creator shell (M4 design section 3.2, `Prober`;
//! ADR-027).
//!
//! - `Channel`: P-32 enables email only. The probe opens the configured
//!   submission relay through [`crate::egress::TcpMailTransport`], which
//!   keeps the policy of `Destination::MailSubmission`, completes the TLS
//!   handshake, reads a `220` greeting and sends `QUIT`.
//! - `SendingDomain`: SPF, DKIM and DMARC of the configured sending
//!   domain ([`super::mailauth`]), read through a [`TxtResolver`].
//! - `Inference`: absent. ADR-009 gives the cell no inference destination
//!   (assessor amendment of 2026-11-07), so `InferenceUnreachable` stays a
//!   warning to acknowledge.
//!
//! A probe whose setting is missing is absent. The creator reads an
//! absent channel or sending domain probe as a failure (Q5).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fstp_creator::{ProbeKind, ProbeOutcome};
use fstp_rt::{IoExt, Runtime, timeout};

use super::dns::TxtResolver;
use crate::egress::{MailHost, MailTransport, TcpMailTransport, mail_tls};

/// One boxed probe run.
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;

/// What runs the probes of the creator shell. Tests use a fake one.
pub trait Prober: Send + Sync + 'static {
    /// Runs `probe` now.
    fn run(&self, probe: ProbeKind) -> ProbeFuture<'_>;
}

/// How long the channel probe may take, from the lookup to the greeting.
pub const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

/// The settings the probes read (ADR-027). A missing one makes its probe
/// absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeSettings {
    /// The submission relay host of the email channel.
    pub mail_relay: Option<String>,
    /// A CA the relay's certificate may chain to, as PEM, beside the
    /// public roots (ADR-018).
    pub mail_ca_pem: Option<Vec<u8>>,
    /// The sending domain, such as `calls.example.org`.
    pub sending_domain: Option<String>,
    /// The DKIM selector of the sending domain.
    pub dkim_selector: Option<String>,
    /// The pinned socket address of the relay (`mail.address`, ADR-026
    /// "Relay address"), so the channel probe checks the relay the cell
    /// submits to.
    pub mail_address: Option<std::net::SocketAddr>,
}

/// The prober of a serving cell (module documentation).
pub struct CellProber<R> {
    rt: R,
    settings: ProbeSettings,
    resolver: Option<Arc<dyn TxtResolver>>,
}

impl<R: Runtime> CellProber<R> {
    /// A prober on `rt` with `settings`, reading TXT records through
    /// `resolver`, if any.
    pub fn new(
        rt: R,
        settings: ProbeSettings,
        resolver: Option<Arc<dyn TxtResolver>>,
    ) -> CellProber<R> {
        CellProber {
            rt,
            settings,
            resolver,
        }
    }

    async fn channel(&self) -> ProbeOutcome {
        let Some(relay) = self.settings.mail_relay.as_deref() else {
            return ProbeOutcome::Absent;
        };
        let Ok(host) = MailHost::parse(relay) else {
            return ProbeOutcome::Fail;
        };
        let Ok(tls) = mail_tls(self.settings.mail_ca_pem.as_deref()) else {
            return ProbeOutcome::Fail;
        };
        let transport = match self.settings.mail_address {
            Some(addr) => crate::mail::RelayTransport::Pinned {
                rt: self.rt.clone(),
                addr,
            },
            None => crate::mail::RelayTransport::Dns(TcpMailTransport::new(self.rt.clone())),
        };
        let run = async {
            let io = transport
                .open(&host, fstp_smtp::client::SUBMISSION_PORT)
                .await
                .ok()?;
            let mut stream = fstp_tls::connect(&tls, host.as_str(), io).await.ok()?;
            let greeting = read_reply(&mut stream).await?;
            let _ = stream.write_all(b"QUIT\r\n").await;
            let _ = stream.flush().await;
            Some(greeting == 220)
        };
        match timeout(&self.rt, CHANNEL_TIMEOUT, run).await {
            Ok(Some(true)) => ProbeOutcome::Pass,
            _ => ProbeOutcome::Fail,
        }
    }

    /// The sending domain probe of `domain`, the domain a tenant admin
    /// saved in the Domains and email step, with the configured DKIM
    /// selector (ADR-026 record of lane L18). Absent without a resolver
    /// or a selector.
    pub async fn domain_of(&self, domain: &str) -> ProbeOutcome {
        let (Some(resolver), Some(selector)) = (
            self.resolver.as_ref(),
            self.settings.dkim_selector.as_deref(),
        ) else {
            return ProbeOutcome::Absent;
        };
        sending_domain(resolver.as_ref(), domain, selector).await
    }

    async fn sending_domain(&self) -> ProbeOutcome {
        let (Some(resolver), Some(domain), Some(selector)) = (
            self.resolver.as_ref(),
            self.settings.sending_domain.as_deref(),
            self.settings.dkim_selector.as_deref(),
        ) else {
            return ProbeOutcome::Absent;
        };
        sending_domain(resolver.as_ref(), domain, selector).await
    }
}

/// The sending domain probe of `domain` with DKIM selector `selector`
/// over `resolver` (module documentation).
pub async fn sending_domain(
    resolver: &dyn TxtResolver,
    domain: &str,
    selector: &str,
) -> ProbeOutcome {
    let dmarc = format!("_dmarc.{domain}");
    let dkim = format!("{selector}._domainkey.{domain}");
    let (Ok(spf), Ok(dmarc), Ok(dkim)) = (
        resolver.txt(domain).await,
        resolver.txt(&dmarc).await,
        resolver.txt(&dkim).await,
    ) else {
        return ProbeOutcome::Fail;
    };
    if super::mailauth::spf_ok(&spf)
        && super::mailauth::dmarc_ok(&dmarc)
        && super::mailauth::dkim_ok(&dkim)
    {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Fail
    }
}

/// The code of the first complete SMTP reply on `stream`, or `None`.
async fn read_reply<S: IoExt + Unpin>(stream: &mut S) -> Option<u16> {
    let limits = fstp_smtp::reply::ReplyLimits::default();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if let Ok(Some((reply, _))) = fstp_smtp::reply::parse_reply(&buf, &limits) {
            return Some(reply.code());
        }
        if buf.len() > limits.max_line.saturating_mul(limits.max_lines) {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n)?);
    }
}

impl<R: Runtime> Prober for CellProber<R> {
    fn run(&self, probe: ProbeKind) -> ProbeFuture<'_> {
        Box::pin(async move {
            match probe {
                ProbeKind::Channel => self.channel().await,
                ProbeKind::SendingDomain => self.sending_domain().await,
                ProbeKind::Inference => ProbeOutcome::Absent,
            }
        })
    }
}

/// The onboarding probes of the API core's `Prober` port (ADR-026 record
/// of lane L18): the email channel and the sending domain a tenant admin
/// saved. Tests use a fake one.
pub trait TenantProbe: Send + Sync + 'static {
    /// The email channel: the platform relay's TLS greeting.
    fn channel(&self) -> ProbeFuture<'_>;
    /// SPF, DKIM and DMARC of `domain`.
    fn domain<'a>(&'a self, domain: &'a str) -> ProbeFuture<'a>;
}

impl<R: Runtime> TenantProbe for CellProber<R> {
    fn channel(&self) -> ProbeFuture<'_> {
        Box::pin(CellProber::channel(self))
    }

    fn domain<'a>(&'a self, domain: &'a str) -> ProbeFuture<'a> {
        Box::pin(self.domain_of(domain))
    }
}
