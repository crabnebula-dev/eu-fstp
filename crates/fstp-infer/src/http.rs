//! The HTTP transport over `fstp-http` (ADR-019, R-LA-04).

use core::fmt;

use fstp_rt::Runtime;

use crate::encode::EncodedRequest;
use crate::transport::{Transport, TransportError};

/// Posts each request to one endpoint URL.
pub struct HttpTransport<R: Runtime> {
    client: fstp_http::Client<R>,
    url: String,
    bearer: Option<Vec<u8>>,
}

impl<R: Runtime> fmt::Debug for HttpTransport<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpTransport")
            .field("url", &self.url)
            .field("bearer", &self.bearer.is_some())
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> HttpTransport<R> {
    /// A transport that posts to `url` through `client`, with an optional
    /// bearer credential sent in the `Authorization` header only.
    pub fn new(client: fstp_http::Client<R>, url: String, bearer: Option<Vec<u8>>) -> Self {
        HttpTransport {
            client,
            url,
            bearer,
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
        if let Some(token) = &self.bearer {
            let mut v = b"Bearer ".to_vec();
            v.extend_from_slice(token);
            headers.push(("authorization", v));
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
        let status = response.status.as_u16();
        if status != 200 {
            return Err(TransportError::Status(status));
        }
        Ok(response.body)
    }
}
