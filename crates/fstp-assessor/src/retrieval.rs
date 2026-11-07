//! The retrieval client: `GET /v1/retrieve?url=` on the retrieval proxy
//! of `fstp-retrieve`, through the [`AssessorDestination::Retrieval`]
//! fence (M7 design section 3.2, TH-12).
//!
//! The proxy applies the destination policy, the limits and the
//! HTML-to-text step. The assessor reads only its closed answer
//! ([`Outcome::from_json`]). Any failure becomes a refusal, so a missing
//! proxy never blocks an assessment.

use std::future::Future;
use std::time::Duration;

use fstp_http::{Client, ClientConfig, Limits};
use fstp_json::ParseLimits;
use fstp_retrieve::{Outcome, RETRIEVE_PATH, Refusal, SourceUrl, query_for};
use fstp_rt::Runtime;

use crate::egress::{AssessorDestination, EgressError, Fence, authority};

/// The largest proxy answer, in bytes.
const MAX_ANSWER_BYTES: u64 = 1 << 20;

/// Retrieves one source for stage 6.
pub trait Retrieval: Send + Sync {
    /// Retrieves `url`. Failures come back as [`Outcome::Refused`].
    fn retrieve(&self, url: &SourceUrl) -> impl Future<Output = Outcome> + Send;
}

/// No retrieval proxy is configured: every source is refused as
/// [`Refusal::RetrievalUnavailable`] (design Q2).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRetrieval;

impl Retrieval for NoRetrieval {
    async fn retrieve(&self, _url: &SourceUrl) -> Outcome {
        Outcome::Refused(Refusal::RetrievalUnavailable)
    }
}

impl<Q: Retrieval> Retrieval for Option<Q> {
    async fn retrieve(&self, url: &SourceUrl) -> Outcome {
        match self {
            Some(q) => q.retrieve(url).await,
            None => Outcome::Refused(Refusal::RetrievalUnavailable),
        }
    }
}

/// The client of the retrieval proxy.
#[derive(Debug)]
pub struct ProxyClient<R: Runtime> {
    client: Client<Fence<R>>,
    endpoint: String,
}

impl<R: Runtime> ProxyClient<R> {
    /// A client of the proxy at `base`, such as `http://10.0.0.5:8080`.
    /// The proxy runs inside the cell, so plain HTTP is the only scheme.
    ///
    /// # Errors
    ///
    /// [`EgressError::Url`] when `base` is not an absolute `http` URL.
    pub fn new(rt: R, base: &str) -> Result<ProxyClient<R>, EgressError> {
        let (scheme, _, _) = authority(base)?;
        if scheme != fstp_http::Scheme::Http {
            return Err(EgressError::Url);
        }
        let fence = Fence::new(rt, AssessorDestination::Retrieval, base)?;
        let deadline = Duration::from_secs(15);
        let client = Client::new(
            fence,
            ClientConfig {
                limits: Limits {
                    max_body_bytes: MAX_ANSWER_BYTES,
                    max_chunk_size: MAX_ANSWER_BYTES,
                    ..Limits::default()
                },
                tls: None,
                connect_timeout: deadline,
                request_timeout: deadline,
                response_timeout: deadline,
                ..ClientConfig::default()
            },
        );
        Ok(ProxyClient {
            client,
            endpoint: format!("{}{RETRIEVE_PATH}", base.trim_end_matches('/')),
        })
    }
}

impl<R: Runtime> Retrieval for ProxyClient<R> {
    async fn retrieve(&self, url: &SourceUrl) -> Outcome {
        let target = format!("{}?{}", self.endpoint, query_for(url));
        let Ok(resp) = self.client.get(&target).await else {
            return Outcome::Refused(Refusal::Transport);
        };
        if resp.status.as_u16() != 200 {
            return Outcome::Refused(Refusal::Transport);
        }
        let limits = ParseLimits::default()
            .with_max_input_bytes(usize::try_from(MAX_ANSWER_BYTES).unwrap_or(usize::MAX))
            .with_max_depth(4);
        fstp_json::parse_with(&resp.body, &limits)
            .ok()
            .and_then(|v| Outcome::from_json(&v).ok())
            .unwrap_or(Outcome::Refused(Refusal::Transport))
    }
}
