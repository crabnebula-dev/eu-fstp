//! The in-house S3 client of the subset (ADR-012 "S3 subset", record of
//! lane L10): `PutObject`, `GetObject`, `HeadObject` and the four
//! multipart calls. No delete call and no listing call exist.
//!
//! It runs over `fstp-http` and `fstp-tls`. Each request is signed with
//! SigV4 ([`crate::sigv4`]) and carries the SHA-256 of its body. URLs are
//! path-style, `https://<endpoint>:<port>/<bucket>/<key>`. Response
//! bodies of the XML shapes go through [`crate::xml`]. An error names a
//! status or a known error code and never quotes the server's text.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_http::{Client, ClientConfig, HeaderName, HeaderValue, Method, Request, RequestTarget};
use fstp_rt::Runtime;

use crate::BackupError;
use crate::sigv4::{self, Credentials, Signed};
use crate::xml::{self, S3Code};

/// The largest body a `GetObject` reads: a container of one base backup
/// part (record of lane L10).
pub const MAX_OBJECT_LEN: usize = crate::agent::MAX_CONTAINER_LEN;

/// Where the objects live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The endpoint host name, which TLS verifies.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The region of the signing scope.
    pub region: String,
    /// The bucket.
    pub bucket: String,
}

impl Endpoint {
    /// The `host` header value: the host, with the port unless it is 443.
    #[must_use]
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Whether `key` is an object key this client sends: 1 to 1024 bytes of
/// ASCII letters, digits, `/`, `.`, `_` and `-`, with no empty, `.` or
/// `..` segment.
#[must_use]
pub fn key_ok(key: &str) -> bool {
    (1..=1024).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        && key
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// An S3 client of one endpoint and bucket.
pub struct S3Client<R: Runtime> {
    http: Client<R>,
    endpoint: Endpoint,
    credentials: Credentials,
}

impl<R: Runtime> std::fmt::Debug for S3Client<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Client")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

fn transport(e: &fstp_http::ClientError) -> BackupError {
    use fstp_http::ClientError as E;
    BackupError::Transport(match e {
        E::Timeout(_) => "timeout",
        E::TlsNotConfigured => "TLS",
        E::ConnectionClosed => "connection closed",
        _ => "request",
    })
}

fn header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), BackupError> {
    Ok((
        HeaderName::new(name).map_err(|_| BackupError::Transport("header"))?,
        HeaderValue::new(value.as_bytes().to_vec())
            .map_err(|_| BackupError::Transport("header"))?,
    ))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The refusal of a response that is not the expected success.
fn refusal(status: u16, body: &[u8]) -> BackupError {
    match xml::error_code(body) {
        S3Code::Other => BackupError::S3Status(status),
        code => BackupError::S3Refused(code),
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl<R: Runtime> S3Client<R> {
    /// A client that verifies the endpoint against the public roots,
    /// plus `extra_ca_pem` when given (`s3-ca.pem`).
    ///
    /// # Errors
    ///
    /// [`BackupError::Config`] when the CA does not load.
    pub fn new(
        rt: R,
        endpoint: Endpoint,
        credentials: Credentials,
        extra_ca_pem: Option<&[u8]>,
    ) -> Result<S3Client<R>, BackupError> {
        let builder = fstp_tls::ClientConfig::public_roots_builder();
        let tls = match extra_ca_pem {
            Some(pem) => builder.also_trust_pem(pem).build(),
            None => builder.build(),
        }
        .map_err(|_| BackupError::Config("s3-ca.pem"))?;
        Ok(S3Client::with_tls(rt, endpoint, credentials, tls))
    }

    /// A client over the TLS configuration `tls`.
    #[must_use]
    pub fn with_tls(
        rt: R,
        endpoint: Endpoint,
        credentials: Credentials,
        tls: fstp_tls::ClientConfig,
    ) -> S3Client<R> {
        let mut cfg = ClientConfig {
            tls: Some(tls),
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(600),
            response_timeout: Duration::from_secs(600),
            ..ClientConfig::default()
        };
        let max = u64::try_from(MAX_OBJECT_LEN).unwrap_or(u64::MAX);
        cfg.limits.max_body_bytes = max;
        cfg.limits.max_chunk_size = max;
        S3Client {
            http: Client::new(rt, cfg),
            endpoint,
            credentials,
        }
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Sends one signed request and gives the status, the `etag` header
    /// and the body.
    async fn send(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(u16, Option<String>, Vec<u8>), BackupError> {
        if !key_ok(key) {
            return Err(BackupError::Malformed("object key"));
        }
        let path = format!(
            "/{}/{}",
            sigv4::uri_encode(&self.endpoint.bucket, false),
            sigv4::uri_encode(key, true)
        );
        let query_text = sigv4::canonical_query(query);
        let host = self.endpoint.host_header();
        let payload = sigv4::hex(&fstp_crypto::sha256(&body));
        let date = sigv4::amz_date(now_unix());
        let signed = Signed {
            method: method.as_str(),
            path: &path,
            query,
            host: &host,
            payload_sha256: &payload,
            amz_date: &date,
            region: &self.endpoint.region,
        };
        let auth = sigv4::authorization(&self.credentials, &signed);
        let mut url = format!(
            "https://{}:{}{path}",
            self.endpoint.host, self.endpoint.port
        );
        if !query_text.is_empty() {
            url.push('?');
            url.push_str(&query_text);
        }
        let target = RequestTarget::absolute(&url).map_err(|_| BackupError::Transport("URL"))?;
        let mut req = Request::new(method, target);
        let mut headers = vec![
            header("host", &host)?,
            header("x-amz-date", &date)?,
            header("x-amz-content-sha256", &payload)?,
            header("authorization", &auth)?,
        ];
        if let Some(ct) = content_type {
            headers.push(header("content-type", ct)?);
        }
        for (n, v) in headers {
            req.headers.append(n, v);
        }
        req.body = body;
        let resp = self.http.send(req).await.map_err(|e| transport(&e))?;
        let etag = resp
            .headers
            .get("etag")
            .and_then(HeaderValue::to_str)
            .map(str::to_owned);
        Ok((resp.status.as_u16(), etag, resp.body))
    }

    /// `PutObject`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Transport`], [`BackupError::S3Refused`] or
    /// [`BackupError::S3Status`].
    pub async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<(), BackupError> {
        let (status, _, resp) = self.send(Method::PUT, key, &[], body, None).await?;
        if status == 200 {
            Ok(())
        } else {
            Err(refusal(status, &resp))
        }
    }

    /// `GetObject`: the bytes, or `None` when the object does not exist.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::put_object`].
    pub async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, BackupError> {
        let (status, _, body) = self.send(Method::GET, key, &[], Vec::new(), None).await?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            _ => Err(refusal(status, &body)),
        }
    }

    /// `HeadObject`: whether the object exists.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::put_object`].
    pub async fn head_object(&self, key: &str) -> Result<bool, BackupError> {
        let (status, _, _) = self.send(Method::HEAD, key, &[], Vec::new(), None).await?;
        match status {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(BackupError::S3Status(status)),
        }
    }

    /// `CreateMultipartUpload`: the upload id.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::put_object`], and [`BackupError::Xml`] for a body
    /// of another shape.
    pub async fn create_multipart(&self, key: &str) -> Result<String, BackupError> {
        let (status, _, body) = self
            .send(Method::POST, key, &[("uploads", "")], Vec::new(), None)
            .await?;
        if status != 200 {
            return Err(refusal(status, &body));
        }
        xml::create_upload_id(&body)
    }

    /// `UploadPart`: the part's ETag.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::put_object`], and [`BackupError::Malformed`] for
    /// a missing or unusable ETag.
    pub async fn upload_part(
        &self,
        key: &str,
        upload: &str,
        number: u32,
        body: Vec<u8>,
    ) -> Result<String, BackupError> {
        let n = number.to_string();
        let (status, etag, resp) = self
            .send(
                Method::PUT,
                key,
                &[("partNumber", &n), ("uploadId", upload)],
                body,
                None,
            )
            .await?;
        if status != 200 {
            return Err(refusal(status, &resp));
        }
        let etag = etag.ok_or(BackupError::Malformed("part ETag"))?;
        if etag.is_empty() || etag.len() > 256 || !etag.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(BackupError::Malformed("part ETag"));
        }
        Ok(etag)
    }

    /// `CompleteMultipartUpload` over `parts`, each a part number and its
    /// ETag, in order.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::create_multipart`]. An error document with
    /// status 200 is a refusal.
    pub async fn complete_multipart(
        &self,
        key: &str,
        upload: &str,
        parts: &[(u32, String)],
    ) -> Result<(), BackupError> {
        let mut doc = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            doc.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                escape(etag)
            ));
        }
        doc.push_str("</CompleteMultipartUpload>");
        let (status, _, body) = self
            .send(
                Method::POST,
                key,
                &[("uploadId", upload)],
                doc.into_bytes(),
                Some("application/xml"),
            )
            .await?;
        if status != 200 {
            return Err(refusal(status, &body));
        }
        xml::complete_result(&body)
    }

    /// `AbortMultipartUpload`.
    ///
    /// # Errors
    ///
    /// As for [`S3Client::put_object`].
    pub async fn abort_multipart(&self, key: &str, upload: &str) -> Result<(), BackupError> {
        let (status, _, body) = self
            .send(
                Method::DELETE,
                key,
                &[("uploadId", upload)],
                Vec::new(),
                None,
            )
            .await?;
        if status == 204 || status == 200 {
            Ok(())
        } else {
            Err(refusal(status, &body))
        }
    }

    /// Stores `body` as `key`: one `PutObject` up to `single_max` bytes,
    /// otherwise a multipart upload in parts of `part_len` bytes. A failed
    /// multipart upload is aborted.
    ///
    /// # Errors
    ///
    /// The first call that fails.
    pub async fn store(
        &self,
        key: &str,
        body: Vec<u8>,
        single_max: usize,
        part_len: usize,
    ) -> Result<(), BackupError> {
        if body.len() <= single_max {
            return self.put_object(key, body).await;
        }
        let upload = self.create_multipart(key).await?;
        let result = async {
            let mut parts = Vec::new();
            for (i, chunk) in body.chunks(part_len.max(1)).enumerate() {
                let n = u32::try_from(i)
                    .ok()
                    .and_then(|i| i.checked_add(1))
                    .filter(|n| *n <= 10_000)
                    .ok_or(BackupError::Malformed("part count"))?;
                let etag = self.upload_part(key, &upload, n, chunk.to_vec()).await?;
                parts.push((n, etag));
            }
            self.complete_multipart(key, &upload, &parts).await
        }
        .await;
        if result.is_err() {
            let _ = self.abort_multipart(key, &upload).await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-012 "Object names": the keys the agent writes pass, and a key
    /// that could climb out of its prefix does not.
    #[test]
    fn adr012_object_keys_are_checked() {
        for ok in [
            "0123abcd/base/00ff/0",
            "0123abcd/wal/000000010000000000000001",
            "0123abcd/wal/00000002.history",
        ] {
            assert!(key_ok(ok), "{ok}");
        }
        for bad in [
            "", "/a", "a/", "a//b", "a/../b", "./a", "a b", "a?b", "a%2Fb", "a#b",
        ] {
            assert!(!key_ok(bad), "{bad}");
        }
    }
}
