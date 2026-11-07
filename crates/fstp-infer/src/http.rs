//! The HTTP transport over `fstp-http` (ADR-019, R-LA-04).

use core::fmt;

use fstp_rt::Runtime;

use crate::encode::{ANTHROPIC_VERSION, EncodedRequest};
use crate::transport::{Transport, TransportError};

/// An inference API key. It has no `Display`, its `Debug` shows only its
/// length, and it leaves the process only in one request header
/// (R-NF-02).
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey(Vec<u8>);

impl ApiKey {
    /// Wraps the key bytes.
    pub fn new(key: Vec<u8>) -> ApiKey {
        ApiKey(key)
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey(<redacted, {} bytes>)", self.0.len())
    }
}

/// How a request authenticates, which follows its protocol.
#[derive(Clone, Debug)]
enum Auth {
    /// No credential, for a local endpoint.
    None,
    /// `Authorization: Bearer`, the chat-completions convention.
    Bearer(ApiKey),
    /// `x-api-key` and `anthropic-version`, as the Anthropic reference
    /// shows (<https://platform.claude.com/docs/en/api/messages/create>).
    Anthropic(ApiKey),
}

/// Posts each request to one endpoint URL.
pub struct HttpTransport<R: Runtime> {
    client: fstp_http::Client<R>,
    url: String,
    auth: Auth,
}

impl<R: Runtime> fmt::Debug for HttpTransport<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = match self.auth {
            Auth::None => "none",
            Auth::Bearer(_) => "bearer",
            Auth::Anthropic(_) => "x-api-key",
        };
        f.debug_struct("HttpTransport")
            .field("url", &self.url)
            .field("auth", &auth)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> HttpTransport<R> {
    /// A chat-completions transport that posts to `url` through `client`,
    /// with an optional bearer credential sent in the `Authorization`
    /// header only.
    pub fn new(client: fstp_http::Client<R>, url: String, bearer: Option<Vec<u8>>) -> Self {
        HttpTransport {
            client,
            url,
            auth: bearer.map_or(Auth::None, |b| Auth::Bearer(ApiKey::new(b))),
        }
    }

    /// An Anthropic Messages transport that posts to `url`, normally
    /// `https://api.anthropic.com/v1/messages`, with `key` in the
    /// `x-api-key` header and `anthropic-version: 2026-10-21`.
    pub fn anthropic(client: fstp_http::Client<R>, url: String, key: ApiKey) -> Self {
        HttpTransport {
            client,
            url,
            auth: Auth::Anthropic(key),
        }
    }
}

impl<R: Runtime> Transport for HttpTransport<R> {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        let mut request = fstp_http::Request::post(&self.url, req.body().to_vec())
            .map_err(|_| TransportError::Unavailable)?;
        let mut headers = vec![
            ("content-type", b"application/json".to_vec()),
            ("accept", b"application/json".to_vec()),
        ];
        match &self.auth {
            Auth::None => {}
            Auth::Bearer(token) => {
                let mut v = b"Bearer ".to_vec();
                v.extend_from_slice(token.bytes());
                headers.push(("authorization", v));
            }
            Auth::Anthropic(key) => {
                headers.push(("x-api-key", key.bytes().to_vec()));
                headers.push(("anthropic-version", ANTHROPIC_VERSION.as_bytes().to_vec()));
            }
        }
        for (name, value) in headers {
            request
                .headers
                .try_insert(name, value)
                .map_err(|_| TransportError::Unavailable)?;
        }
        let response = self
            .client
            .send(request)
            .await
            .map_err(|_| TransportError::Unavailable)?;
        // A non-200 answer keeps only its status. The error body is never
        // read or logged (R-NF-02).
        let status = response.status.as_u16();
        if status != 200 {
            return Err(TransportError::Status(status));
        }
        Ok(response.body)
    }
}
