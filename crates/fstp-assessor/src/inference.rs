//! The inference transport of the process (ADR-019, R-LA-04).
//!
//! The process takes one mode at start: `synthetic` (the demo default,
//! in memory), `replay:<dir>` (recordings only), `anthropic:<url>` or
//! `chat:<url>` (an HTTP endpoint through the
//! [`AssessorDestination::Inference`] fence). The TLS client of an
//! `https` endpoint trusts only the PEM anchors the inference record pins
//! (ADR-009 amendment). No public root store is used here.

use std::path::PathBuf;
use std::time::Duration;

use fstp_http::{Client, ClientConfig};
use fstp_infer::{
    ApiKey, EncodedRequest, HttpTransport, Protocol, Replay, SyntheticModel, Transport,
    TransportError,
};
use fstp_rt::Runtime;

use crate::egress::{AssessorDestination, EgressError, Fence};

/// How the process reaches a model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InferenceMode {
    /// The synthetic model, in memory. Never reported as an LLM result.
    Synthetic,
    /// Saved responses only. A miss leaves the job pending.
    Replay(PathBuf),
    /// The Anthropic Messages API at this URL.
    Anthropic(String),
    /// A chat-completions endpoint at this URL.
    ChatCompletions(String),
}

impl InferenceMode {
    /// Reads a mode argument.
    pub fn parse(s: &str) -> Option<InferenceMode> {
        if s == "synthetic" {
            return Some(InferenceMode::Synthetic);
        }
        let (kind, rest) = s.split_once(':')?;
        if rest.is_empty() {
            return None;
        }
        match kind {
            "replay" => Some(InferenceMode::Replay(PathBuf::from(rest))),
            "anthropic" => Some(InferenceMode::Anthropic(rest.to_owned())),
            "chat" => Some(InferenceMode::ChatCompletions(rest.to_owned())),
            _ => None,
        }
    }

    /// The protocol an HTTP endpoint speaks. Jobs of another protocol
    /// are refused. `None` for the in-memory modes, which follow the job.
    pub fn protocol(&self) -> Option<Protocol> {
        match self {
            InferenceMode::Synthetic | InferenceMode::Replay(_) => None,
            InferenceMode::Anthropic(_) => Some(Protocol::Anthropic),
            InferenceMode::ChatCompletions(_) => Some(Protocol::ChatCompletions),
        }
    }
}

/// The transport of the process.
#[derive(Debug)]
pub enum Inference<R: Runtime> {
    /// [`InferenceMode::Synthetic`].
    Synthetic(SyntheticModel),
    /// [`InferenceMode::Replay`].
    Replay(Replay),
    /// An HTTP endpoint behind the inference fence.
    Http(HttpTransport<Fence<R>>),
}

impl<R: Runtime> Inference<R> {
    /// The transport of `mode` on `rt`. `key` is the credential of an
    /// HTTP endpoint and `anchors` the PEM trust anchors of an `https`
    /// one.
    ///
    /// # Errors
    ///
    /// [`EgressError::Url`] for an endpoint URL that is not absolute, and
    /// [`EgressError::Tls`] for anchors that do not load.
    pub fn new(
        rt: R,
        mode: &InferenceMode,
        key: Option<Vec<u8>>,
        anchors: Option<&[u8]>,
    ) -> Result<Inference<R>, EgressError> {
        let url = match mode {
            InferenceMode::Synthetic => return Ok(Inference::Synthetic(SyntheticModel)),
            InferenceMode::Replay(dir) => return Ok(Inference::Replay(Replay::new(dir.clone()))),
            InferenceMode::Anthropic(u) | InferenceMode::ChatCompletions(u) => u,
        };
        let fence = Fence::new(rt, AssessorDestination::Inference, url)?;
        let tls = match anchors {
            Some(pem) => Some(fstp_tls::ClientConfig::new(pem).map_err(|_| EgressError::Tls)?),
            None => None,
        };
        let client = Client::new(
            fence,
            ClientConfig {
                tls,
                connect_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(30),
                response_timeout: Duration::from_secs(300),
                ..ClientConfig::default()
            },
        );
        Ok(Inference::Http(match mode {
            InferenceMode::Anthropic(_) => {
                HttpTransport::anthropic(client, url.clone(), ApiKey::new(key.unwrap_or_default()))
            }
            _ => HttpTransport::new(client, url.clone(), key),
        }))
    }
}

impl<R: Runtime> Transport for Inference<R> {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        match self {
            Inference::Synthetic(t) => t.exchange(req).await,
            Inference::Replay(t) => t.exchange(req).await,
            Inference::Http(t) => t.exchange(req).await,
        }
    }
}
