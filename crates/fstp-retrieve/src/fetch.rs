//! The GET-only retrieval client (TH-12).
//!
//! - Every URL, the first and each redirect target, passes the
//!   [`DestinationPolicy`] before any connection.
//! - No name resolution happens. The proxy connects only to the pinned
//!   upstream address and sends the policy-checked host in the Host field.
//!   In M7 the upstream is the fixture web server. Without one, every
//!   retrieval is refused as [`Refusal::RetrievalUnavailable`] (design Q2).
//! - Only GET is sent, with no cookies, credentials or request body.
//! - Redirects are followed by hand up to a limit, each checked again.
//! - The body size, the text size and the whole retrieval time are bounded.
//! - The text is returned as [`UntrustedText`], never as an instruction.

use std::net::SocketAddr;
use std::time::Duration;

use fstp_findings::UntrustedText;
use fstp_http::{Client, ClientConfig, ClientError, Limits, ParseErrorKind, Request};
use fstp_rt::{Runtime, timeout};

use crate::body::decode_body;
use crate::classing::{ApplicantSources, SourceClass};
use crate::policy::DestinationPolicy;
use crate::refusal::Refusal;
use crate::url::SourceUrl;

const ACCEPT: &str = "text/html, application/xhtml+xml, text/plain;q=0.9, text/markdown;q=0.9";

/// Settings of a [`Retriever`].
#[derive(Debug, Clone)]
pub struct RetrieveConfig {
    /// Which hosts may be reached.
    pub policy: DestinationPolicy,
    /// The pinned address every request goes to. `None` refuses every
    /// retrieval.
    pub upstream: Option<SocketAddr>,
    /// Largest response body, in bytes.
    pub max_body_bytes: u64,
    /// Largest text returned, in bytes.
    pub max_text_bytes: usize,
    /// Deadline for the whole retrieval, redirects included.
    pub deadline: Duration,
    /// Most redirects followed.
    pub max_redirects: usize,
}

impl RetrieveConfig {
    /// The M7 fixture settings: the fixture policy and the fixture server
    /// at `upstream`, 2 MiB bodies, 64 KiB of text, 10 seconds and three
    /// redirects.
    #[must_use]
    pub fn fixture(upstream: SocketAddr) -> RetrieveConfig {
        RetrieveConfig {
            policy: DestinationPolicy::fixture(),
            upstream: Some(upstream),
            max_body_bytes: 2 * 1024 * 1024,
            max_text_bytes: 64 * 1024,
            deadline: Duration::from_secs(10),
            max_redirects: 3,
        }
    }
}

/// A retrieved source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retrieved {
    /// The requested URL followed by each redirect target. Never empty.
    pub chain: Vec<SourceUrl>,
    /// The text, as data.
    pub text: UntrustedText,
    /// The text limit cut the text short.
    pub truncated: bool,
}

impl Retrieved {
    /// The URL the text came from.
    #[must_use]
    pub fn final_url(&self) -> Option<&SourceUrl> {
        self.chain.last()
    }

    /// Applicant-controlled when any URL of the chain is, since either end
    /// of a redirect chooses what the reader sees.
    #[must_use]
    pub fn class(&self, applicant: &ApplicantSources) -> SourceClass {
        if self
            .chain
            .iter()
            .any(|u| applicant.classify(u) == SourceClass::ApplicantControlled)
        {
            SourceClass::ApplicantControlled
        } else {
            SourceClass::Independent
        }
    }
}

/// The GET-only retrieval client.
#[derive(Clone)]
pub struct Retriever<R: Runtime> {
    rt: R,
    client: Client<R>,
    config: RetrieveConfig,
}

impl<R: Runtime> Retriever<R> {
    /// A retriever on `rt`.
    pub fn new(rt: R, config: RetrieveConfig) -> Retriever<R> {
        let client = Client::new(
            rt.clone(),
            ClientConfig {
                limits: Limits {
                    max_body_bytes: config.max_body_bytes,
                    max_chunk_size: config.max_body_bytes,
                    ..Limits::default()
                },
                tls: None,
                connect_timeout: config.deadline,
                request_timeout: config.deadline,
                response_timeout: config.deadline,
                max_idle_total: 0,
                ..ClientConfig::default()
            },
        );
        Retriever { rt, client, config }
    }

    /// The settings.
    #[must_use]
    pub fn config(&self) -> &RetrieveConfig {
        &self.config
    }

    /// Retrieves `url` as text.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] from the policy, the transport, the status, the media
    /// type or a limit.
    pub async fn get(&self, url: &SourceUrl) -> Result<Retrieved, Refusal> {
        timeout(&self.rt, self.config.deadline, self.walk(url))
            .await
            .unwrap_or(Err(Refusal::Timeout))
    }

    async fn walk(&self, url: &SourceUrl) -> Result<Retrieved, Refusal> {
        let mut chain: Vec<SourceUrl> = Vec::new();
        let mut current = url.clone();
        loop {
            self.config.policy.check(&current)?;
            chain.push(current.clone());
            let upstream = self.config.upstream.ok_or(Refusal::RetrievalUnavailable)?;
            let target = format!("http://{upstream}{}", current.path_and_query());
            let req = Request::get(&target)
                .and_then(|r| r.try_with_header("host", current.authority()))
                .and_then(|r| r.try_with_header("accept", ACCEPT))
                .and_then(|r| r.try_with_header("connection", "close"))
                .map_err(|_| Refusal::MalformedUrl)?;
            let resp = self.client.send(req).await.map_err(transport)?;
            let code = resp.status.as_u16();
            if matches!(code, 301 | 302 | 303 | 307 | 308) {
                if chain.len() > self.config.max_redirects {
                    return Err(Refusal::TooManyRedirects);
                }
                if resp.headers.count("location") != 1 {
                    return Err(Refusal::BadRedirect);
                }
                let loc = resp
                    .headers
                    .get("location")
                    .and_then(|v| v.to_str())
                    .ok_or(Refusal::BadRedirect)?;
                current = current.join(loc)?;
                continue;
            }
            if code != 200 {
                return Err(Refusal::HttpStatus(code));
            }
            if resp.headers.count("content-type") > 1
                || resp
                    .headers
                    .get("content-encoding")
                    .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
            {
                return Err(Refusal::UnsupportedMediaType);
            }
            let ct = resp.headers.get("content-type").map(|v| v.as_bytes());
            let text = decode_body(ct, &resp.body, self.config.max_text_bytes)?;
            return Ok(Retrieved {
                chain,
                text: UntrustedText::new(text.text),
                truncated: text.truncated,
            });
        }
    }
}

fn transport(e: ClientError) -> Refusal {
    match e {
        ClientError::Timeout(_) => Refusal::Timeout,
        ClientError::Protocol(p)
            if matches!(
                p.kind(),
                ParseErrorKind::BodyTooLarge | ParseErrorKind::ChunkTooLarge
            ) =>
        {
            Refusal::BodyTooLarge
        }
        _ => Refusal::Transport,
    }
}
