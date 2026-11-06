//! `fstp-fixture-web`: the fixture site server for retrieval (M7 design
//! section 5, `SPEC/07-test-plan/synthetic-corpus.md` "Fixtures"). Lane
//! L-CORPUS owns this file.
//!
//! It serves the fixture repositories and pages of `corpus/v1/web` over
//! plain HTTP on a loopback port, inside tests only. A request names its
//! site in the Host field, and only hosts under the reserved `.test` name
//! exist, so no test reaches the public internet. Any other host answers
//! 403, any method other than GET or HEAD answers 405, and an unknown page
//! answers 404. The server records every request it receives, so a test
//! can check what retrieval fetched (T-LLM-RETRIEVAL, TH-12).

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fstp_http::{
    HeaderName, HeaderValue, Method, Request, Response, Server, ServerConfig, ServerHandle,
    StatusCode,
};
use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;

/// The only top-level name a fixture host may use (RFC 2606).
pub const FIXTURE_SUFFIX: &str = ".test";

/// The pages of the fixture sites: host, then path, then body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixtureSites {
    pages: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

/// A host outside the reserved `.test` name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotAFixtureHost(pub String);

impl std::fmt::Display for NotAFixtureHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not under {FIXTURE_SUFFIX}", self.0)
    }
}

impl std::error::Error for NotAFixtureHost {}

impl FixtureSites {
    /// No site at all.
    pub fn new() -> FixtureSites {
        FixtureSites::default()
    }

    /// The fixture sites of `corpus/v1/web` in this repository.
    ///
    /// # Errors
    ///
    /// An I/O error, or a directory that is not a `.test` host.
    pub fn corpus_v1() -> io::Result<FixtureSites> {
        FixtureSites::load(&PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/v1/web"
        )))
    }

    /// Loads `dir/<host>/<path>`: each directory under `dir` is one host.
    ///
    /// # Errors
    ///
    /// An I/O error, or a directory that is not a `.test` host.
    pub fn load(dir: &Path) -> io::Result<FixtureSites> {
        let mut sites = FixtureSites::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let host = entry.file_name().to_string_lossy().into_owned();
            let mut files = Vec::new();
            collect(&entry.path(), "", &mut files)?;
            for (path, body) in files {
                sites
                    .insert(&host, &path, body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
        }
        Ok(sites)
    }

    /// Adds or replaces one page. `path` starts with `/`.
    ///
    /// # Errors
    ///
    /// A host outside `.test`.
    pub fn insert(&mut self, host: &str, path: &str, body: Vec<u8>) -> Result<(), NotAFixtureHost> {
        let host = host.to_ascii_lowercase();
        if !host.ends_with(FIXTURE_SUFFIX) || host.len() <= FIXTURE_SUFFIX.len() {
            return Err(NotAFixtureHost(host));
        }
        self.pages
            .entry(host)
            .or_default()
            .insert(path.to_owned(), body);
        Ok(())
    }

    /// The page at `host` and `path`. A path ending in `/` names its
    /// `index.html`.
    pub fn get(&self, host: &str, path: &str) -> Option<&[u8]> {
        let site = self.pages.get(&host.to_ascii_lowercase())?;
        let found = if path.ends_with('/') {
            site.get(&format!("{path}index.html"))
        } else {
            site.get(path)
        };
        found.map(Vec::as_slice)
    }

    /// Every host, in order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.pages.keys().map(String::as_str)
    }
}

/// The files under `dir` as `/relative/path` and bytes.
fn collect(dir: &Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        if entry.file_type()?.is_dir() {
            collect(&entry.path(), &name, out)?;
        } else {
            out.push((name, std::fs::read(entry.path())?));
        }
    }
    Ok(())
}

/// One request the server received: method, host and path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureHit {
    /// The method.
    pub method: String,
    /// The Host field without its port, in lower case.
    pub host: String,
    /// The path.
    pub path: String,
    /// The status of the answer.
    pub status: u16,
}

struct Site {
    sites: FixtureSites,
    hits: Mutex<Vec<FixtureHit>>,
}

impl Site {
    fn answer(&self, req: &Request) -> Response {
        let host = req
            .headers
            .get("host")
            .and_then(HeaderValue::to_str)
            .map(strip_port)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = req.path().to_owned();
        let is_head = req.method == Method::HEAD;
        let res = if req.method != Method::GET && !is_head {
            Response::text(
                StatusCode::METHOD_NOT_ALLOWED,
                "fixture pages are read only\n",
            )
        } else if !host.ends_with(FIXTURE_SUFFIX) {
            Response::text(StatusCode::FORBIDDEN, "not a fixture host\n")
        } else {
            match self.sites.get(&host, &path) {
                Some(body) => {
                    let mut r =
                        Response::with_body(StatusCode::OK, content_type(&path), body.to_vec());
                    if is_head {
                        r.body.clear();
                    }
                    r
                }
                None => Response::text(StatusCode::NOT_FOUND, "no such fixture page\n"),
            }
        };
        if let Ok(mut hits) = self.hits.lock() {
            hits.push(FixtureHit {
                method: req.method.as_str().to_owned(),
                host,
                path,
                status: res.status.as_u16(),
            });
        }
        res
    }
}

/// `host` without a trailing `:port`.
fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

fn content_type(path: &str) -> &'static str {
    if path.ends_with('/') || path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    }
}

/// A running fixture server on a loopback port. Dropping it stops it.
pub struct FixtureWeb {
    site: Arc<Site>,
    handle: ServerHandle<TokioRuntime>,
    _rt: TokioRuntime,
}

impl std::fmt::Debug for FixtureWeb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixtureWeb")
            .field("addr", &self.handle.local_addr())
            .finish_non_exhaustive()
    }
}

struct SiteHandler(Arc<Site>);

impl fstp_http::Handler for SiteHandler {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        std::future::ready(self.0.answer(&req))
    }
}

impl FixtureWeb {
    /// Starts a server for `sites` on `127.0.0.1` and a free port.
    ///
    /// # Errors
    ///
    /// The runtime or the listener could not start.
    pub fn start(sites: FixtureSites) -> io::Result<FixtureWeb> {
        let rt = TokioRuntime::new_multi_thread(1)?;
        let listener = rt.block_on(rt.bind_tcp(SocketAddr::from(([127, 0, 0, 1], 0))))?;
        let site = Arc::new(Site {
            sites,
            hits: Mutex::new(Vec::new()),
        });
        let handle = Server::new(
            rt.clone(),
            ServerConfig::default(),
            SiteHandler(Arc::clone(&site)),
        )
        .serve(listener)?;
        Ok(FixtureWeb {
            site,
            handle,
            _rt: rt,
        })
    }

    /// Starts a server for the fixture sites of `corpus/v1`.
    ///
    /// # Errors
    ///
    /// As [`FixtureSites::corpus_v1`] and [`FixtureWeb::start`].
    pub fn corpus_v1() -> io::Result<FixtureWeb> {
        FixtureWeb::start(FixtureSites::corpus_v1()?)
    }

    /// The loopback address to connect to. A client sends the fixture host
    /// in the Host field.
    pub fn addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }

    /// The pages it serves.
    pub fn sites(&self) -> &FixtureSites {
        &self.site.sites
    }

    /// Every request received so far, in order.
    pub fn hits(&self) -> Vec<FixtureHit> {
        self.site.hits.lock().map(|h| h.clone()).unwrap_or_default()
    }
}

/// The Host field for `host`, for clients that build requests by hand.
///
/// # Errors
///
/// A host that is not a valid field value.
pub fn host_header(host: &str) -> Result<(HeaderName, HeaderValue), fstp_http::InvalidInput> {
    Ok((HeaderName::new("host")?, HeaderValue::new(host)?))
}
