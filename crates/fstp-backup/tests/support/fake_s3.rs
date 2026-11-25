//! An in-process fake of the S3 subset for tests (ADR-012 record of lane
//! L10). Shared by `crates/fstp-backup/tests` and, through `#[path]`, by
//! `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs`.
//!
//! It serves HTTPS with the `fstp-tls` test server certificate, which
//! names `localhost` and `127.0.0.1`. Every request must carry a SigV4
//! signature that this file checks on its own: it rebuilds the canonical
//! request from the bytes it received, with its own percent-decoding,
//! encoding, header list and key derivation, so a fault in the client's
//! `sigv4` module does not cancel out. Only the HMAC and SHA-256 calls of
//! `fstp-crypto` are shared. The payload hash must equal the SHA-256 of
//! the received body.
//!
//! It keeps objects and multipart uploads in memory, and it records every
//! request and every body it received, so a test can scan what left the
//! client. An object `DELETE` removes the object and is recorded in
//! `deletes`, since pruning deletes (ADR-012 record of lane
//! m10/backup-format). A key in `locked` stands for an object lock: its
//! `DELETE` is refused with `AccessDenied` and the object stays.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_http::{
    Handler, Limits, Method, Request, Response, Server, ServerConfig, ServerHandle, StatusCode,
};
use fstp_rt::tokio::TokioRuntime;

const SERVER_PEM: &[u8] = include_bytes!("../../../fstp-tls/testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../../fstp-tls/testdata/server-key.pem");
/// The CA a client trusts for this server.
pub const CA_PEM: &[u8] = include_bytes!("../../../fstp-tls/testdata/ca.pem");

/// The open multipart uploads: id to key and parts.
type Uploads = BTreeMap<String, (String, BTreeMap<u32, Vec<u8>>)>;

/// The fake's accounts and its records.
#[derive(Default)]
pub struct State {
    /// The access key id and its secret.
    pub access_key: String,
    secret: String,
    /// The region and the bucket it serves.
    pub region: String,
    pub bucket: String,
    /// The stored objects, by key.
    pub objects: Mutex<BTreeMap<String, Vec<u8>>>,
    uploads: Mutex<Uploads>,
    next_upload: Mutex<u64>,
    /// Every request: method, path and query.
    pub requests: Mutex<Vec<(String, String)>>,
    /// Every request body received.
    pub bodies: Mutex<Vec<Vec<u8>>>,
    /// Requests refused for a bad signature or payload hash.
    pub bad_signatures: Mutex<u32>,
    /// Calls outside the subset.
    pub violations: Mutex<Vec<String>>,
    /// Every object `DELETE`, by key, in order.
    pub deletes: Mutex<Vec<String>>,
    /// Keys under an object lock: a `DELETE` of one is refused.
    pub locked: Mutex<std::collections::BTreeSet<String>>,
    /// When set, the next `CompleteMultipartUpload` answers 200 with an
    /// error document.
    pub fail_next_complete: Mutex<bool>,
}

/// A running fake.
pub struct FakeS3 {
    /// Its state.
    pub state: Arc<State>,
    handle: ServerHandle<TokioRuntime>,
}

impl FakeS3 {
    /// Starts a fake on a loopback port of `rt`.
    pub fn start(
        rt: &TokioRuntime,
        access_key: &str,
        secret: &str,
        region: &str,
        bucket: &str,
    ) -> FakeS3 {
        let state = Arc::new(State {
            access_key: access_key.to_owned(),
            secret: secret.to_owned(),
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            ..State::default()
        });
        let cfg = ServerConfig {
            tls: Some(fstp_tls::ServerConfig::new(SERVER_PEM, SERVER_KEY).unwrap()),
            limits: Limits {
                max_body_bytes: 256 * 1024 * 1024,
                ..Limits::default()
            },
            body_read_timeout: Duration::from_secs(120),
            ..ServerConfig::default()
        };
        let handler = Fake(Arc::clone(&state));
        let handle = rt
            .block_on(
                Server::new(rt.clone(), cfg, handler)
                    .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            )
            .unwrap();
        FakeS3 { state, handle }
    }

    /// The port it listens on.
    pub fn port(&self) -> u16 {
        self.handle.local_addr().port()
    }

    /// Stops it.
    pub fn stop(&self, rt: &TokioRuntime) {
        let _ = rt.block_on(self.handle.shutdown(Duration::from_secs(5)));
    }
}

struct Fake(Arc<State>);

impl Handler for Fake {
    async fn handle(&self, req: Request) -> Response {
        self.0.serve(req)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// This file's own percent-decoding of a query component.
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// This file's own SigV4 encoding: RFC 3986 unreserved characters stay.
fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for c in s.bytes() {
        let unreserved = c.is_ascii_uppercase()
            || c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == b'-'
            || c == b'.'
            || c == b'_'
            || c == b'~';
        if unreserved {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn error(status: u16, code: &str) -> Response {
    Response::with_body(
        StatusCode::from_u16(status).unwrap(),
        "application/xml",
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
             <Message>fake</Message><RequestId>1</RequestId></Error>"
        )
        .into_bytes(),
    )
}

impl State {
    /// Checks the request's SigV4 signature on its own (module
    /// documentation).
    fn verify(&self, req: &Request) -> Result<(), &'static str> {
        let h = |n: &str| {
            req.headers
                .get(n)
                .and_then(|v| v.to_str())
                .map(str::to_owned)
        };
        let auth = h("authorization").ok_or("no authorization")?;
        let date = h("x-amz-date").ok_or("no date")?;
        let hash = h("x-amz-content-sha256").ok_or("no payload hash")?;
        if hash != hex(&fstp_crypto::sha256(&req.body)) {
            return Err("payload hash");
        }
        let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ").ok_or("algorithm")?;
        let mut cred = None;
        let mut signed = None;
        let mut sig = None;
        for part in rest.split(", ") {
            if let Some(v) = part.strip_prefix("Credential=") {
                cred = Some(v);
            } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
                signed = Some(v);
            } else if let Some(v) = part.strip_prefix("Signature=") {
                sig = Some(v);
            }
        }
        let (cred, signed, sig) = (
            cred.ok_or("cred")?,
            signed.ok_or("signed")?,
            sig.ok_or("sig")?,
        );
        let c: Vec<&str> = cred.split('/').collect();
        if c.len() != 5
            || c[0] != self.access_key
            || c[2] != self.region
            || c[3] != "s3"
            || c[4] != "aws4_request"
        {
            return Err("credential scope");
        }
        if date.len() != 16 || !date.starts_with(c[1]) {
            return Err("date");
        }
        // The date must be within 15 minutes of now.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let then = parse_date(&date).ok_or("date")?;
        if now.abs_diff(then) > 900 {
            return Err("skew");
        }
        let names: Vec<&str> = signed.split(';').collect();
        for must in ["host", "x-amz-content-sha256", "x-amz-date"] {
            if !names.contains(&must) {
                return Err("signed headers");
            }
        }
        let mut canon_headers = String::new();
        for n in &names {
            let v = h(n).ok_or("signed header missing")?;
            canon_headers.push_str(&format!("{n}:{}\n", v.trim()));
        }
        let mut q: Vec<(String, String)> = Vec::new();
        if let Some(query) = req.query() {
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                q.push((
                    pct_encode(&pct_decode(k).ok_or("query")?),
                    pct_encode(&pct_decode(v).ok_or("query")?),
                ));
            }
        }
        q.sort();
        let query = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let canonical = format!(
            "{}\n{}\n{query}\n{canon_headers}\n{signed}\n{hash}",
            req.method.as_str(),
            req.path()
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{date}\n{}/{}/s3/aws4_request\n{}",
            c[1],
            self.region,
            hex(&fstp_crypto::sha256(canonical.as_bytes()))
        );
        let mut k =
            fstp_crypto::hmac_sha256(format!("AWS4{}", self.secret).as_bytes(), c[1].as_bytes());
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            k = fstp_crypto::hmac_sha256(&k, part.as_bytes());
        }
        let want = hex(&fstp_crypto::hmac_sha256(&k, to_sign.as_bytes()));
        if !fstp_crypto::constant_time_eq(want.as_bytes(), sig.as_bytes()) {
            return Err("signature");
        }
        Ok(())
    }

    fn serve(&self, req: Request) -> Response {
        self.requests.lock().unwrap().push((
            req.method.as_str().to_owned(),
            format!("{}?{}", req.path(), req.query().unwrap_or("")),
        ));
        self.bodies.lock().unwrap().push(req.body.clone());
        if self.verify(&req).is_err() {
            *self.bad_signatures.lock().unwrap() += 1;
            return error(403, "SignatureDoesNotMatch");
        }
        let prefix = format!("/{}/", self.bucket);
        let Some(key) = req.path().strip_prefix(&prefix).map(str::to_owned) else {
            return error(404, "NoSuchBucket");
        };
        let query: BTreeMap<String, String> = req
            .query()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (pct_decode(k).unwrap(), pct_decode(v).unwrap())
            })
            .collect();
        let m = req.method.clone();
        if m == Method::PUT && query.is_empty() {
            self.objects.lock().unwrap().insert(key, req.body);
            return Response::new(StatusCode::OK);
        }
        if m == Method::PUT {
            let (Some(n), Some(id)) = (query.get("partNumber"), query.get("uploadId")) else {
                return error(400, "InvalidRequest");
            };
            let mut ups = self.uploads.lock().unwrap();
            let Some((k, parts)) = ups.get_mut(id) else {
                return error(404, "NoSuchUpload");
            };
            if *k != key {
                return error(404, "NoSuchUpload");
            }
            let n: u32 = n.parse().unwrap();
            let etag = format!("\"{}\"", &hex(&fstp_crypto::sha256(&req.body))[..32]);
            parts.insert(n, req.body);
            let mut r = Response::new(StatusCode::OK);
            r.headers.try_insert("etag", etag.as_str()).unwrap();
            return r;
        }
        if m == Method::GET || m == Method::HEAD {
            return match self.objects.lock().unwrap().get(&key) {
                Some(b) if m == Method::GET => {
                    Response::with_body(StatusCode::OK, "application/octet-stream", b.clone())
                }
                Some(_) => Response::new(StatusCode::OK),
                None if m == Method::HEAD => Response::new(StatusCode::NOT_FOUND),
                None => error(404, "NoSuchKey"),
            };
        }
        if m == Method::POST && query.contains_key("uploads") {
            let mut n = self.next_upload.lock().unwrap();
            *n += 1;
            let id = format!("up~{n}.x_y-z");
            self.uploads
                .lock()
                .unwrap()
                .insert(id.clone(), (key.clone(), BTreeMap::new()));
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult \
                 xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{key}</Key>\
                 <UploadId>{id}</UploadId></InitiateMultipartUploadResult>",
                self.bucket
            );
            return Response::with_body(StatusCode::OK, "application/xml", body.into_bytes());
        }
        if m == Method::POST {
            let Some(id) = query.get("uploadId") else {
                return error(400, "InvalidRequest");
            };
            if std::mem::take(&mut *self.fail_next_complete.lock().unwrap()) {
                return error(200, "InternalError");
            }
            let Some((k, parts)) = self.uploads.lock().unwrap().remove(id) else {
                return error(404, "NoSuchUpload");
            };
            if k != key {
                return error(404, "NoSuchUpload");
            }
            let doc = String::from_utf8(req.body.clone()).unwrap();
            let mut joined = Vec::new();
            let mut want = 1u32;
            for chunk in doc.split("<Part>").skip(1) {
                let n: u32 = between(chunk, "<PartNumber>", "</PartNumber>")
                    .parse()
                    .unwrap();
                let etag = between(chunk, "<ETag>", "</ETag>");
                let Some(body) = parts.get(&n) else {
                    return error(400, "InvalidPart");
                };
                let have = format!("\"{}\"", &hex(&fstp_crypto::sha256(body))[..32]);
                if n != want || have != etag {
                    return error(400, "InvalidPart");
                }
                want += 1;
                joined.extend_from_slice(body);
            }
            self.objects.lock().unwrap().insert(key.clone(), joined);
            let body = format!(
                "<CompleteMultipartUploadResult><Location>l</Location><Bucket>b</Bucket>\
                 <Key>{key}</Key><ETag>&quot;x-{}&quot;</ETag></CompleteMultipartUploadResult>",
                want - 1
            );
            return Response::with_body(StatusCode::OK, "application/xml", body.into_bytes());
        }
        if m == Method::DELETE {
            if let Some(id) = query.get("uploadId") {
                self.uploads.lock().unwrap().remove(id);
                return Response::new(StatusCode::NO_CONTENT);
            }
            self.deletes.lock().unwrap().push(key.clone());
            if self.locked.lock().unwrap().contains(&key) {
                return error(403, "AccessDenied");
            }
            self.objects.lock().unwrap().remove(&key);
            return Response::new(StatusCode::NO_CONTENT);
        }
        self.violations
            .lock()
            .unwrap()
            .push(format!("{} {key}", m.as_str()));
        error(405, "MethodNotAllowed")
    }

    /// Whether a multipart upload is still open.
    pub fn open_uploads(&self) -> usize {
        self.uploads.lock().unwrap().len()
    }
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let start = s.find(a).unwrap() + a.len();
    let end = s[start..].find(b).unwrap() + start;
    &s[start..end]
}

/// `yyyymmddThhmmssZ` as Unix seconds, by day counting of this file's own.
fn parse_date(d: &str) -> Option<u64> {
    let n = |r: std::ops::Range<usize>| d.get(r)?.parse::<u64>().ok();
    let (y, m, day) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (hh, mm, ss) = (n(9..11)?, n(11..13)?, n(13..15)?);
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mut days = 0u64;
    for yy in 1970..y {
        days += if leap(yy) { 366 } else { 365 };
    }
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    days += months.iter().take(m as usize - 1).sum::<u64>();
    days += day - 1;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}
