//! `fstp-fixture-web` (M7 design section 5, lane L-CORPUS): the fixture
//! server serves the corpus pages to retrieval inside tests, and only
//! under `.test` hosts, so no test reaches the public internet
//! (`synthetic-corpus.md` "Fixtures", T-LLM-RETRIEVAL, TH-12).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpStream;

use fstp_api_testkit::fixture_web::{FixtureSites, FixtureWeb};
use fstp_http::{Limits, Method, Parsed, Response, parse_response};

fn fetch(web: &FixtureWeb, method: &str, host: &str, path: &str) -> Response {
    let mut s = TcpStream::connect(web.addr()).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let m = Method::from_bytes(method.as_bytes()).unwrap();
    match parse_response(&buf, &m, &Limits::default(), true).unwrap() {
        Parsed::Complete { message, .. } => message,
        _ => panic!("incomplete response"),
    }
}

/// T-LLM-RETRIEVAL: every page of `corpus/v1/web` is served byte for byte
/// under its `.test` host, on loopback only, and every request is logged.
#[test]
fn t_llm_retrieval_fixture_web_serves_corpus_pages() {
    let web = FixtureWeb::corpus_v1().unwrap();
    assert!(web.addr().ip().is_loopback());
    let hosts: Vec<String> = web.sites().hosts().map(str::to_owned).collect();
    assert!(hosts.iter().any(|h| h == "forge.test"));
    assert!(hosts.iter().all(|h| h.ends_with(".test")));
    let site = hosts.iter().find(|h| h.starts_with("www.")).unwrap();
    let r = fetch(&web, "GET", &format!("{site}:80"), "/");
    assert_eq!(r.status.as_u16(), 200);
    assert_eq!(Some(r.body.as_slice()), web.sites().get(site, "/"));
    assert!(String::from_utf8(r.body).unwrap().contains("<h1>"));

    let manifest = fstp_json::parse(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/v1/manifest.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let item = manifest.get("items").unwrap().get_index(0).unwrap();
    let repo = item.get("repository").unwrap().as_str().unwrap();
    let path = format!(
        "{}/README.md",
        repo.strip_prefix("http://forge.test").unwrap()
    );
    let r = fetch(&web, "GET", "forge.test", &path);
    assert_eq!(r.status.as_u16(), 200);
    assert_eq!(
        Some(r.body.as_slice()),
        web.sites().get("forge.test", &path)
    );
    let hits = web.hits();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[1].host, "forge.test");
    assert_eq!(hits[1].path, path);
}

/// Fixture pages are read only and exist only under `.test`: another
/// host answers 403, another method 405, an unknown page 404, and no
/// site outside `.test` can be added.
#[test]
fn t_llm_retrieval_fixture_web_refuses_real_hosts_and_writes() {
    let mut sites = FixtureSites::new();
    sites
        .insert("pages.test", "/a.txt", b"alpha".to_vec())
        .unwrap();
    assert!(
        sites
            .insert("example.com", "/a.txt", b"x".to_vec())
            .is_err()
    );
    assert!(sites.insert(".test", "/a.txt", b"x".to_vec()).is_err());
    let web = FixtureWeb::start(sites).unwrap();
    assert_eq!(fetch(&web, "GET", "pages.test", "/a.txt").body, b"alpha");
    assert_eq!(
        fetch(&web, "GET", "example.com", "/a.txt").status.as_u16(),
        403
    );
    assert_eq!(
        fetch(&web, "POST", "pages.test", "/a.txt").status.as_u16(),
        405
    );
    assert_eq!(
        fetch(&web, "GET", "pages.test", "/missing").status.as_u16(),
        404
    );
    assert_eq!(
        fetch(&web, "GET", "other.test", "/a.txt").status.as_u16(),
        404
    );
    assert_eq!(web.hits().len(), 5);
}
