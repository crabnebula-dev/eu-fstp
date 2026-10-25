//! Integration tests of the server and client drivers over loopback TCP on
//! the real tokio runtime.
//!
//! Tests named `r_nf_09_*` verify R-NF-09 (encrypted and mutually
//! authenticated traffic). Tests named `r_nf_02_*` verify R-NF-02 (no
//! content in logs or events). Tests named `th26_*` verify parser and
//! protocol robustness under hostile clients (TH-26).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fstp_http::{
    Client, ClientConfig, ClientError, ClientPhase, EventHook, Limits, Method, ParseErrorKind,
    Request, Response, ResponseDecoder, ResponseEvent, Router, Server, ServerConfig, ServerEvent,
    ServerHandle, StatusCode, TimeoutPhase, handler_fn,
};
use fstp_rt::tokio::{TcpStream, TokioRuntime};
use fstp_rt::{Connection, IoExt, Runtime, timeout};
use fstp_tls::{TlsError, TlsErrorKind};

macro_rules! testdata {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fstp-tls/testdata/",
            $name
        ))
        .as_slice()
    };
}

const CA: &[u8] = testdata!("ca.pem");
const SERVER_CERT: &[u8] = testdata!("server.pem");
const SERVER_KEY: &[u8] = testdata!("server-key.pem");
const CLIENT_CERT: &[u8] = testdata!("client.pem");
const CLIENT_KEY: &[u8] = testdata!("client-key.pem");
const UNTRUSTED_SERVER: &[u8] = testdata!("untrusted-server.pem");
const UNTRUSTED_SERVER_KEY: &[u8] = testdata!("untrusted-server-key.pem");
const UNTRUSTED_CLIENT: &[u8] = testdata!("untrusted-client.pem");
const UNTRUSTED_CLIENT_KEY: &[u8] = testdata!("untrusted-client-key.pem");

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(2).unwrap()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Shared state that test handlers record into.
#[derive(Default)]
struct Probe {
    calls: AtomicUsize,
    slow_started: AtomicBool,
}

fn app(rt: &TokioRuntime, probe: &Arc<Probe>) -> Router {
    let p = probe.clone();
    let hello = handler_fn(move |_req: Request| {
        p.calls.fetch_add(1, Ordering::SeqCst);
        async { Response::text(StatusCode::OK, "hello") }
    });
    let echo = handler_fn(|req: Request| async move {
        Response::with_body(StatusCode::OK, "application/octet-stream", req.body)
    });
    let item = handler_fn(|req: Request| async move {
        Response::text(
            StatusCode::OK,
            format!("item {}", req.param("id").unwrap_or("?")),
        )
    });
    let cert = handler_fn(|req: Request| async move {
        match req.client_certificate_der() {
            Some(der) => Response::with_body(StatusCode::OK, "application/pkix-cert", der.to_vec()),
            None => Response::new(StatusCode::NO_CONTENT),
        }
    });
    let (rt2, p2) = (rt.clone(), probe.clone());
    let slow = handler_fn(move |req: Request| {
        let rt = rt2.clone();
        let p = p2.clone();
        async move {
            p.slow_started.store(true, Ordering::SeqCst);
            let ms = req.query().and_then(|q| q.parse().ok()).unwrap_or(400);
            rt.sleep(Duration::from_millis(ms)).await;
            Response::text(StatusCode::OK, "done")
        }
    });
    let panics = handler_fn(|_req: Request| async move {
        if std::hint::black_box(true) {
            panic!("handler failure");
        }
        Response::new(StatusCode::OK)
    });
    let redirect = handler_fn(|_req: Request| async move {
        Response::new(StatusCode::FOUND)
            .try_with_header("location", "/hello")
            .unwrap()
    });
    let big = handler_fn(|_req: Request| async move {
        Response::with_body(
            StatusCode::OK,
            "application/octet-stream",
            vec![b'z'; 100_000],
        )
    });
    let any = handler_fn(|_req: Request| async move { Response::text(StatusCode::OK, "any") });
    Router::new()
        .get("/hello", hello)
        .unwrap()
        .post("/echo", echo)
        .unwrap()
        .get("/items/{id}", item)
        .unwrap()
        .get("/cert", cert)
        .unwrap()
        .get("/slow", slow)
        .unwrap()
        .get("/panic", panics)
        .unwrap()
        .get("/redirect", redirect)
        .unwrap()
        .get("/big", big)
        .unwrap()
        .route(Method::from_bytes(b"CANARYMETHOD").unwrap(), "/any", any)
        .unwrap()
}

type Events = Arc<Mutex<Vec<ServerEvent>>>;

fn test_config() -> (ServerConfig, Events) {
    let events: Events = Arc::default();
    let sink = events.clone();
    let cfg = ServerConfig {
        limits: Limits {
            max_body_bytes: 64 * 1024,
            ..Limits::default()
        },
        header_read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        linger_timeout: Duration::from_millis(500),
        on_event: Some(EventHook::new(move |e| {
            sink.lock().unwrap().push(e.clone())
        })),
        ..ServerConfig::default()
    };
    (cfg, events)
}

async fn start(
    rt: &TokioRuntime,
    cfg: ServerConfig,
    probe: &Arc<Probe>,
) -> ServerHandle<TokioRuntime> {
    Server::new(rt.clone(), cfg, app(rt, probe))
        .bind(loopback())
        .await
        .unwrap()
}

fn url(handle: &ServerHandle<TokioRuntime>, scheme: &str, host: &str, path: &str) -> String {
    format!("{scheme}://{host}:{}{path}", handle.local_addr().port())
}

async fn connect(rt: &TokioRuntime, handle: &ServerHandle<TokioRuntime>) -> TcpStream {
    rt.connect_tcp(handle.local_addr()).await.unwrap()
}

/// Reads until end of stream or `limit` passes.
async fn read_to_eof<C: Connection>(rt: &TokioRuntime, conn: &mut C, limit: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(rt, left, conn.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_) => panic!("no end of stream within {limit:?}; got {out:?}"),
        }
    }
}

/// Reads and decodes one response per method in `methods`.
async fn read_responses<C: Connection>(
    rt: &TokioRuntime,
    conn: &mut C,
    methods: &[Method],
) -> Vec<Response> {
    let mut d = ResponseDecoder::new(Limits::default());
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut head = None;
    let mut body = Vec::new();
    while out.len() < methods.len() {
        d.expect_response_to(methods[out.len()].clone());
        match d.next_event().unwrap() {
            Some(ResponseEvent::Head(h)) => head = Some(h),
            Some(ResponseEvent::Data(b)) => body.extend_from_slice(&b),
            Some(ResponseEvent::End(t)) => {
                let h = head.take().unwrap();
                if !h.status.is_informational() {
                    out.push(Response::from_parts(*h, std::mem::take(&mut body), t));
                }
            }
            None => {
                let n = timeout(rt, Duration::from_secs(5), conn.read(&mut buf))
                    .await
                    .expect("response within 5 s")
                    .unwrap();
                if n == 0 {
                    d.feed_eof();
                } else {
                    d.feed(&buf[..n]);
                }
            }
        }
    }
    out
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers.get(name).and_then(|v| v.to_str())
}

fn plain_client(rt: &TokioRuntime) -> Client<TokioRuntime> {
    Client::new(rt.clone(), ClientConfig::default())
}

fn tls_client(rt: &TokioRuntime, tls: fstp_tls::ClientConfig) -> Client<TokioRuntime> {
    Client::new(
        rt.clone(),
        ClientConfig {
            tls: Some(tls),
            ..ClientConfig::default()
        },
    )
}

#[test]
fn plain_requests_through_the_router() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/hello"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, b"hello");
        assert!(header(&r, "date").unwrap().ends_with(" GMT"));
        let r = c
            .send(Request::post(&url(&h, "http", "127.0.0.1", "/echo"), b"ping".to_vec()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.body, b"ping");
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/items/a%20b"))
            .await
            .unwrap();
        assert_eq!(r.body, b"item a b");
        let r = c.get(&url(&h, "http", "127.0.0.1", "/nope")).await.unwrap();
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/items/%2e%2e"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        let del = Request::new(
            Method::DELETE,
            fstp_http::RequestTarget::absolute(&url(&h, "http", "127.0.0.1", "/hello")).unwrap(),
        );
        let r = c.send(del).await.unwrap();
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(header(&r, "allow"), Some("GET, HEAD"));
        let head = Request::new(
            Method::HEAD,
            fstp_http::RequestTarget::absolute(&url(&h, "http", "localhost", "/hello")).unwrap(),
        );
        let r = c.send(head).await.unwrap();
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(header(&r, "content-length"), Some("5"));
        assert!(r.body.is_empty());
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// R-NF-09: TLS 1.3 between client and server, by IP and by name.
#[test]
fn r_nf_09_tls_requests() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.tls = Some(fstp_tls::ServerConfig::new(SERVER_CERT, SERVER_KEY).unwrap());
        let h = start(&rt, cfg, &probe).await;
        let c = tls_client(&rt, fstp_tls::ClientConfig::new(CA).unwrap());
        for host in ["localhost", "127.0.0.1"] {
            let r = c.get(&url(&h, "https", host, "/hello")).await.unwrap();
            assert_eq!(r.body, b"hello");
        }
        // Without mutual TLS the handler sees no client certificate.
        let r = c
            .get(&url(&h, "https", "localhost", "/cert"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        // Plain HTTP to a TLS port fails cleanly.
        let r = plain_client(&rt)
            .get(&url(&h, "http", "127.0.0.1", "/hello"))
            .await;
        assert!(r.is_err());
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// R-NF-09: under mutual TLS the handler sees the client's certificate.
#[test]
fn r_nf_09_mutual_tls_exposes_client_certificate() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.tls = Some(fstp_tls::ServerConfig::mutual(SERVER_CERT, SERVER_KEY, CA).unwrap());
        let h = start(&rt, cfg, &probe).await;
        let c = tls_client(
            &rt,
            fstp_tls::ClientConfig::mutual(CA, CLIENT_CERT, CLIENT_KEY).unwrap(),
        );
        let r = c
            .get(&url(&h, "https", "localhost", "/cert"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, common::first_der(CLIENT_CERT));
        let r = c
            .get(&url(&h, "https", "localhost", "/hello"))
            .await
            .unwrap();
        assert_eq!(r.body, b"hello");
        assert_eq!(c.connections_opened(), 1, "keep-alive over mutual TLS");
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// R-NF-09: a client without a certificate, or with one from an untrusted
/// CA, is rejected before any handler runs.
#[test]
fn r_nf_09_mutual_tls_rejects_missing_or_untrusted_client_certificate() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, events) = test_config();
        cfg.tls = Some(fstp_tls::ServerConfig::mutual(SERVER_CERT, SERVER_KEY, CA).unwrap());
        let h = start(&rt, cfg, &probe).await;
        let no_cert = tls_client(&rt, fstp_tls::ClientConfig::new(CA).unwrap());
        let r = no_cert.get(&url(&h, "https", "localhost", "/hello")).await;
        assert!(r.is_err(), "missing client certificate accepted: {r:?}");
        let untrusted = tls_client(
            &rt,
            fstp_tls::ClientConfig::mutual(CA, UNTRUSTED_CLIENT, UNTRUSTED_CLIENT_KEY).unwrap(),
        );
        let r = untrusted
            .get(&url(&h, "https", "localhost", "/hello"))
            .await;
        assert!(r.is_err(), "untrusted client certificate accepted: {r:?}");
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        // Give the server tasks a moment to report.
        rt.sleep(Duration::from_millis(100)).await;
        let kinds: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ServerEvent::TlsHandshakeFailed { kind } => Some(*kind),
                _ => None,
            })
            .collect();
        assert_eq!(kinds.len(), 2, "{kinds:?}");
        assert!(
            kinds.contains(&Some(TlsErrorKind::CertificateRequired)),
            "{kinds:?}"
        );
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// R-NF-09: the client verifies the server's chain (verify-full).
#[test]
fn r_nf_09_client_rejects_untrusted_server() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.tls =
            Some(fstp_tls::ServerConfig::new(UNTRUSTED_SERVER, UNTRUSTED_SERVER_KEY).unwrap());
        let h = start(&rt, cfg, &probe).await;
        let c = tls_client(&rt, fstp_tls::ClientConfig::new(CA).unwrap());
        match c.get(&url(&h, "https", "localhost", "/hello")).await {
            Err(ClientError::Tls(e)) => {
                assert_eq!(
                    TlsError::from_io(&e).map(TlsError::kind),
                    Some(TlsErrorKind::UntrustedCertificate)
                );
            }
            other => panic!("expected a TLS error, got {other:?}"),
        }
        assert!(matches!(
            plain_client(&rt)
                .get(&url(&h, "https", "localhost", "/hello"))
                .await,
            Err(ClientError::TlsNotConfigured)
        ));
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn keep_alive_reuses_one_connection() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, events) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        for _ in 0..5 {
            let r = c
                .get(&url(&h, "http", "127.0.0.1", "/hello"))
                .await
                .unwrap();
            assert_eq!(r.body, b"hello");
        }
        assert_eq!(c.connections_opened(), 1);
        assert_eq!(c.idle_connections(), 1);
        let opened = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == ServerEvent::ConnectionOpened)
            .count();
        assert_eq!(opened, 1);
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn client_reconnects_after_the_server_closed_an_idle_connection() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.idle_timeout = Duration::from_millis(100);
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        c.get(&url(&h, "http", "127.0.0.1", "/hello"))
            .await
            .unwrap();
        rt.sleep(Duration::from_millis(400)).await;
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/hello"))
            .await
            .unwrap();
        assert_eq!(r.body, b"hello");
        assert_eq!(c.connections_opened(), 2);
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let mut conn = connect(&rt, &h).await;
        conn.write_all(
            b"GET /items/1 HTTP/1.1\r\nHost: a\r\n\r\n\
              POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc\
              HEAD /hello HTTP/1.1\r\nHost: a\r\n\r\n\
              GET /items/3 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        let rs = read_responses(
            &rt,
            &mut conn,
            &[Method::GET, Method::POST, Method::HEAD, Method::GET],
        )
        .await;
        let bodies: Vec<&[u8]> = rs.iter().map(|r| r.body.as_slice()).collect();
        assert_eq!(bodies, [&b"item 1"[..], b"abc", b"", b"item 3"]);
        assert_eq!(header(&rs[2], "content-length"), Some("5"));
        // The connection stays usable.
        conn.write_all(b"GET /hello HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let rs = read_responses(&rt, &mut conn, &[Method::GET]).await;
        assert_eq!(rs[0].body, b"hello");
        assert_eq!(header(&rs[0], "connection"), Some("close"));
        assert!(
            read_to_eof(&rt, &mut conn, Duration::from_secs(2))
                .await
                .is_empty()
        );
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// TH-26: a client that sends its head slowly is cut off when the head
/// deadline passes (slowloris), with 408 and a closed connection.
#[test]
fn th26_slowloris_head_is_cut_off() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, events) = test_config();
        cfg.header_read_timeout = Duration::from_millis(400);
        let h = start(&rt, cfg, &probe).await;
        let mut conn = connect(&rt, &h).await;
        let started = Instant::now();
        conn.write_all(b"GET /hello HTTP/1.1\r\nHost: a\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            assert!(started.elapsed() < Duration::from_secs(5), "never cut off");
            let _ = conn.write_all(b"X").await;
            match timeout(&rt, Duration::from_millis(50), conn.read(&mut buf)).await {
                Err(_) => continue,
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            }
        }
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(350), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert!(
            got.starts_with(b"HTTP/1.1 408 "),
            "{:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(events.lock().unwrap().contains(&ServerEvent::Timeout {
            phase: TimeoutPhase::Header
        }));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// TH-26: a connection that sends nothing is closed without a response.
#[test]
fn th26_silent_connection_is_closed() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.header_read_timeout = Duration::from_millis(200);
        let h = start(&rt, cfg, &probe).await;
        let mut conn = connect(&rt, &h).await;
        let started = Instant::now();
        let got = read_to_eof(&rt, &mut conn, Duration::from_secs(3)).await;
        assert!(got.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// Sends `bytes` on a new connection and returns everything until EOF.
async fn raw(rt: &TokioRuntime, h: &ServerHandle<TokioRuntime>, bytes: &[u8]) -> Vec<u8> {
    let mut conn = connect(rt, h).await;
    conn.write_all(bytes).await.unwrap();
    read_to_eof(rt, &mut conn, Duration::from_secs(5)).await
}

fn status_of(wire: &[u8]) -> u16 {
    std::str::from_utf8(&wire[9..12]).unwrap().parse().unwrap()
}

/// TH-26: limit violations get 431, 413 and 414 and close the connection.
#[test]
fn th26_limits_map_to_status_codes() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, events) = test_config();
        let h = start(&rt, cfg, &probe).await;

        let big_header = format!(
            "GET /hello HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n",
            "v".repeat(20_000)
        );
        let got = raw(&rt, &h, big_header.as_bytes()).await;
        assert_eq!(status_of(&got), 431);
        assert!(String::from_utf8_lossy(&got).contains("connection: close"));

        let many = format!(
            "GET /hello HTTP/1.1\r\nHost: a\r\n{}\r\n",
            (0..101)
                .map(|i| format!("X-{i}: v\r\n"))
                .collect::<String>()
        );
        assert_eq!(status_of(&raw(&rt, &h, many.as_bytes()).await), 431);

        let too_big = b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n";
        assert_eq!(status_of(&raw(&rt, &h, too_big).await), 413);

        let mut chunked =
            b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..25 {
            chunked.extend_from_slice(b"1000\r\n");
            chunked.extend_from_slice(&[b'x'; 4096]);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(status_of(&raw(&rt, &h, &chunked).await), 413);

        let long_line = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(9000));
        assert_eq!(status_of(&raw(&rt, &h, long_line.as_bytes()).await), 414);

        let h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(status_of(&raw(&rt, &h, h2).await), 505);

        let expect = b"GET /hello HTTP/1.1\r\nHost: a\r\nExpect: magic\r\n\r\n";
        assert_eq!(status_of(&raw(&rt, &h, expect).await), 417);

        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        let rejected = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, ServerEvent::RequestRejected { .. }))
            .count();
        assert_eq!(rejected, 7);
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// TH-26: a smuggling attempt gets 400 and the connection closes, so the
/// smuggled request behind it is never processed.
#[test]
fn th26_smuggling_attempt_closes_the_connection() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, events) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let attack = b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /hello HTTP/1.1\r\nHost: a\r\n\r\n";
        let got = raw(&rt, &h, attack).await;
        assert_eq!(status_of(&got), 400);
        assert_eq!(
            got.windows(9).filter(|w| *w == b"HTTP/1.1 ").count(),
            1,
            "{:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        assert!(events.lock().unwrap().contains(&ServerEvent::RequestRejected {
            kind: ParseErrorKind::ContentLengthWithTransferEncoding,
            status: StatusCode::BAD_REQUEST,
        }));
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn expect_continue_gets_an_interim_response() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let mut conn = connect(&rt, &h).await;
        conn.write_all(
            b"POST /echo HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
        )
        .await
        .unwrap();
        let mut interim = [0u8; 25];
        timeout(&rt, Duration::from_secs(5), conn.read_exact(&mut interim))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&interim, fstp_http::CONTINUE_RESPONSE);
        conn.write_all(b"hello").await.unwrap();
        let rs = read_responses(&rt, &mut conn, &[Method::POST]).await;
        assert_eq!(rs[0].body, b"hello");
        // An oversized body is refused before the client sends it.
        let mut conn = connect(&rt, &h).await;
        conn.write_all(
            b"POST /echo HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 999999\r\n\r\n",
        )
        .await
        .unwrap();
        let got = read_to_eof(&rt, &mut conn, Duration::from_secs(5)).await;
        assert_eq!(status_of(&got), 413);
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn http10_connections_close_unless_kept_alive() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let got = raw(&rt, &h, b"GET /hello HTTP/1.0\r\n\r\n").await;
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("connection: close"), "{text}");
        assert!(text.ends_with("hello"), "{text}");

        let mut conn = connect(&rt, &h).await;
        conn.write_all(b"GET /hello HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        let rs = read_responses(&rt, &mut conn, &[Method::GET]).await;
        assert_eq!(header(&rs[0], "connection"), Some("keep-alive"));
        conn.write_all(b"GET /items/2 HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let rs = read_responses(&rt, &mut conn, &[Method::GET]).await;
        assert_eq!(rs[0].body, b"item 2");
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn handler_panic_gives_500() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, events) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/panic"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/hello"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            events
                .lock()
                .unwrap()
                .contains(&ServerEvent::HandlerPanicked)
        );
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

/// Graceful shutdown lets an in-flight request finish, closes the
/// connection after it, and stops accepting.
#[test]
fn graceful_shutdown_completes_in_flight_requests() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let addr = h.local_addr();
        let mut conn = connect(&rt, &h).await;
        conn.write_all(b"GET /slow?500 HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        let rt2 = rt.clone();
        let reader = rt.spawn(async move {
            let got = read_to_eof(&rt2, &mut conn, Duration::from_secs(5)).await;
            String::from_utf8(got).unwrap()
        });
        while !probe.slow_started.load(Ordering::SeqCst) {
            rt.sleep(Duration::from_millis(5)).await;
        }
        // An idle keep-alive connection is closed by the shutdown.
        let mut idle = connect(&rt, &h).await;
        idle.write_all(b"GET /hello HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        read_responses(&rt, &mut idle, &[Method::GET]).await;
        let started = Instant::now();
        h.shutdown(Duration::from_secs(5)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        let text = reader.await.unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("connection: close"), "{text}");
        assert!(text.ends_with("done"), "{text}");
        assert!(
            read_to_eof(&rt, &mut idle, Duration::from_secs(2))
                .await
                .is_empty()
        );
        assert!(
            rt.connect_tcp(addr).await.is_err(),
            "still accepting after shutdown"
        );
    });
}

/// Connections still busy at the drain deadline are aborted.
#[test]
fn shutdown_deadline_aborts_stuck_connections() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let mut conn = connect(&rt, &h).await;
        conn.write_all(b"GET /slow?20000 HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        while !probe.slow_started.load(Ordering::SeqCst) {
            rt.sleep(Duration::from_millis(5)).await;
        }
        let started = Instant::now();
        let err = h.shutdown(Duration::from_millis(300)).await.unwrap_err();
        assert_eq!(err.remaining, 1);
        assert!(started.elapsed() < Duration::from_secs(2));
        let got = read_to_eof(&rt, &mut conn, Duration::from_secs(3)).await;
        assert!(got.is_empty());
    });
}

/// The connection cap makes extra connections wait for a free slot.
#[test]
fn max_connections_caps_concurrency() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (mut cfg, _) = test_config();
        cfg.max_connections = 1;
        let h = start(&rt, cfg, &probe).await;
        let mut a = connect(&rt, &h).await;
        a.write_all(b"GET /hello HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        read_responses(&rt, &mut a, &[Method::GET]).await;
        let mut b = connect(&rt, &h).await;
        b.write_all(b"GET /items/b HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            timeout(&rt, Duration::from_millis(300), b.read(&mut buf))
                .await
                .is_err(),
            "second connection served while the first holds the only slot"
        );
        drop(a);
        let rs = read_responses(&rt, &mut b, &[Method::GET]).await;
        assert_eq!(rs[0].body, b"item b");
        h.shutdown(Duration::from_secs(5)).await.unwrap();
    });
}

#[test]
fn client_limits_and_redirects() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, _) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        let r = c
            .get(&url(&h, "http", "127.0.0.1", "/redirect"))
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::FOUND);
        assert_eq!(header(&r, "location"), Some("/hello"));
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "redirect was followed"
        );

        let small = Client::new(
            rt.clone(),
            ClientConfig {
                limits: Limits {
                    max_body_bytes: 1000,
                    ..Limits::default()
                },
                ..ClientConfig::default()
            },
        );
        match small.get(&url(&h, "http", "127.0.0.1", "/big")).await {
            Err(ClientError::Protocol(e)) => assert_eq!(e.kind(), ParseErrorKind::BodyTooLarge),
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
        let r = c.get(&url(&h, "http", "127.0.0.1", "/big")).await.unwrap();
        assert_eq!(r.body.len(), 100_000);

        let impatient = Client::new(
            rt.clone(),
            ClientConfig {
                response_timeout: Duration::from_millis(100),
                ..ClientConfig::default()
            },
        );
        assert!(matches!(
            impatient
                .get(&url(&h, "http", "127.0.0.1", "/slow?1000"))
                .await,
            Err(ClientError::Timeout(ClientPhase::Response))
        ));
        h.shutdown(Duration::from_secs(5)).await.unwrap();

        let closed = rt.bind_tcp(loopback()).await.unwrap();
        let port = fstp_rt::Listener::local_addr(&closed).unwrap().port();
        drop(closed);
        assert!(matches!(
            c.get(&format!("http://127.0.0.1:{port}/")).await,
            Err(ClientError::Connect(_))
        ));
        assert!(matches!(
            c.send(Request::new(
                Method::GET,
                fstp_http::RequestTarget::origin("/").unwrap()
            ))
            .await,
            Err(ClientError::InvalidRequest(_))
        ));
    });
}

/// R-NF-02: server events carry no header values, bodies, targets or
/// extension method names, even for rejected requests.
#[test]
fn r_nf_02_server_events_carry_no_content() {
    let rt = rt();
    rt.block_on(async {
        let probe = Arc::new(Probe::default());
        let (cfg, events) = test_config();
        let h = start(&rt, cfg, &probe).await;
        let c = plain_client(&rt);
        let req = Request::post(
            &url(&h, "http", "127.0.0.1", "/echo?canary-query"),
            b"canary-body".to_vec(),
        )
        .unwrap()
        .try_with_header("x-canary", "canary-header")
        .unwrap();
        c.send(req).await.unwrap();
        c.get(&url(&h, "http", "127.0.0.1", "/items/canary-path"))
            .await
            .unwrap();
        raw(
            &rt,
            &h,
            b"CANARYMETHOD /any HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await;
        raw(
            &rt,
            &h,
            b"GET /canary HTTP/1.1\r\nHost: a\r\nX-Canary: canary\x00value\r\n\r\n",
        )
        .await;
        h.shutdown(Duration::from_secs(5)).await.unwrap();
        let shown = format!("{:?}", events.lock().unwrap());
        assert!(!shown.to_ascii_lowercase().contains("canary"), "{shown}");
        assert!(shown.contains("OTHER"), "{shown}");
        assert!(shown.contains("RequestRejected"), "{shown}");
    });
}

/// A body of `"1\r\nX\r\n"` chunks, repeated: valid chunked framing that
/// keeps a reader busy without reaching any size limit soon.
fn one_byte_chunks(count: usize) -> Vec<u8> {
    b"1\r\nX\r\n".repeat(count)
}

/// Writes `batch` to `w` again and again on a thread until `stop` is set,
/// a write fails or `max` passes. Returns the thread and a byte counter.
fn stream_from_thread(
    mut w: std::net::TcpStream,
    batch: Vec<u8>,
    stop: Arc<AtomicBool>,
    max: Duration,
) -> (std::thread::JoinHandle<()>, Arc<AtomicUsize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = sent.clone();
    let thread = std::thread::spawn(move || {
        use std::io::Write;
        let t0 = Instant::now();
        while !stop.load(Ordering::SeqCst) && t0.elapsed() < max {
            if w.write_all(&batch).is_err() {
                break;
            }
            counter.fetch_add(batch.len(), Ordering::SeqCst);
        }
    });
    (thread, sent)
}

/// TH-26, review finding phase-deadline-bypass-streaming. The body
/// deadline fires even while a client keeps the socket readable with
/// valid chunks. Each read used to get its own timer, which a read that
/// was already ready always won.
#[test]
fn review_phase_deadline_bypass_streaming() {
    use std::io::{Read, Write};
    let rt = rt();
    let (mut cfg, events) = test_config();
    cfg.body_read_timeout = Duration::from_millis(300);
    cfg.limits.max_body_bytes = 1 << 30;
    let h = rt.block_on(start(&rt, cfg, &Arc::default()));
    let mut s = std::net::TcpStream::connect(h.local_addr()).unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (writer, sent) = stream_from_thread(
        s.try_clone().unwrap(),
        one_byte_chunks(8 * 1024),
        stop.clone(),
        Duration::from_secs(6),
    );
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let t0 = Instant::now();
    let mut first = [0u8; 64];
    let n = s.read(&mut first).unwrap_or(0);
    let waited = t0.elapsed();
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let head = String::from_utf8_lossy(&first[..n]).into_owned();
    assert!(
        waited < Duration::from_secs(2),
        "a 300 ms body deadline held the request open for {waited:?} \
         while the client sent {} bytes",
        sent.load(Ordering::SeqCst)
    );
    assert!(head.starts_with("HTTP/1.1 408 "), "{head:?}");
    assert!(events.lock().unwrap().contains(&ServerEvent::Timeout {
        phase: TimeoutPhase::Body
    }));
}

/// TH-26, review finding phase-deadline-bypass-streaming (wire cost). The
/// stream from the review, 1023 leading zeros per one-byte chunk, is
/// refused at its first chunk-size line instead of being parsed for
/// seconds.
#[test]
fn review_phase_deadline_bypass_streaming_leading_zeros() {
    use std::io::{Read, Write};
    let rt = rt();
    let (mut cfg, _events) = test_config();
    cfg.body_read_timeout = Duration::from_millis(300);
    cfg.limits = Limits::default();
    let h = rt.block_on(start(&rt, cfg, &Arc::default()));
    let mut s = std::net::TcpStream::connect(h.local_addr()).unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    let mut chunk = vec![b'0'; 1023];
    chunk.extend_from_slice(b"1\r\nX\r\n");
    let stop = Arc::new(AtomicBool::new(false));
    let (writer, _sent) = stream_from_thread(
        s.try_clone().unwrap(),
        chunk.repeat(64),
        stop.clone(),
        Duration::from_secs(6),
    );
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let t0 = Instant::now();
    let mut first = [0u8; 64];
    let n = s.read(&mut first).unwrap_or(0);
    let waited = t0.elapsed();
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let head = String::from_utf8_lossy(&first[..n]).into_owned();
    assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    assert!(head.starts_with("HTTP/1.1 400 "), "{head:?}");
}

/// TH-26, review finding phase-deadline-bypass-streaming (client side). A
/// hostile server that streams a chunked body without pause cannot hold
/// the client past `response_timeout`.
#[test]
fn review_phase_deadline_bypass_streaming_client() {
    use std::io::Read;
    let rt = rt();
    let listener = std::net::TcpListener::bind(loopback()).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let server = std::thread::spawn(move || {
        use std::io::Write;
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap();
        let (writer, _sent) =
            stream_from_thread(s, one_byte_chunks(8 * 1024), stop2, Duration::from_secs(6));
        writer.join().unwrap();
    });
    let client = Client::new(
        rt.clone(),
        ClientConfig {
            response_timeout: Duration::from_millis(300),
            limits: Limits {
                max_body_bytes: 1 << 30,
                ..Limits::default()
            },
            ..ClientConfig::default()
        },
    );
    let t0 = Instant::now();
    let res = rt.block_on(client.get(&format!("http://127.0.0.1:{port}/")));
    let waited = t0.elapsed();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    assert!(
        matches!(res, Err(ClientError::Timeout(ClientPhase::Response))),
        "{res:?}"
    );
}

/// A server whose events land in a counter of closed connections.
async fn counting_server(
    rt: &TokioRuntime,
    closed: &Arc<AtomicUsize>,
) -> ServerHandle<TokioRuntime> {
    let closed = closed.clone();
    let cfg = ServerConfig {
        on_event: Some(EventHook::new(move |e| {
            if matches!(e, ServerEvent::ConnectionClosed { .. }) {
                closed.fetch_add(1, Ordering::SeqCst);
            }
        })),
        ..ServerConfig::default()
    };
    let router = Router::new()
        .get(
            "/",
            handler_fn(|_r: Request| async { Response::text(StatusCode::OK, "x") }),
        )
        .unwrap();
    Server::new(rt.clone(), cfg, router)
        .bind(loopback())
        .await
        .unwrap()
}

/// Review finding client-pool-never-pruned. Idle connections to an
/// authority that is not used again are closed once `idle_timeout`
/// passes, at the next pool operation on any authority. The total number
/// of idle connections is capped too.
#[test]
fn review_client_pool_never_pruned() {
    let rt = rt();
    rt.block_on(async {
        let closed = Arc::new(AtomicUsize::new(0));
        let mut servers = Vec::new();
        for _ in 0..6 {
            servers.push(counting_server(&rt, &closed).await);
        }
        let client = Client::new(
            rt.clone(),
            ClientConfig {
                idle_timeout: Duration::from_millis(500),
                ..ClientConfig::default()
            },
        );
        for h in &servers[..5] {
            let url = format!("http://127.0.0.1:{}/", h.local_addr().port());
            assert_eq!(client.get(&url).await.unwrap().status, StatusCode::OK);
        }
        assert_eq!(client.idle_connections(), 5);
        rt.sleep(Duration::from_millis(800)).await;
        // A request to a sixth authority sweeps the whole pool.
        let url = format!("http://127.0.0.1:{}/", servers[5].local_addr().port());
        assert_eq!(client.get(&url).await.unwrap().status, StatusCode::OK);
        assert_eq!(client.idle_connections(), 1);
        // The five expired sockets are really closed: their servers see it.
        let t0 = Instant::now();
        while closed.load(Ordering::SeqCst) < 5 && t0.elapsed() < Duration::from_secs(5) {
            rt.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(closed.load(Ordering::SeqCst), 5);
        // The scenario from the review: no later request at all.
        rt.sleep(Duration::from_millis(800)).await;
        assert_eq!(client.idle_connections(), 0);

        // The pool holds at most max_idle_total connections overall.
        let capped = Client::new(
            rt.clone(),
            ClientConfig {
                max_idle_total: 2,
                ..ClientConfig::default()
            },
        );
        for h in &servers {
            let url = format!("http://127.0.0.1:{}/", h.local_addr().port());
            assert_eq!(capped.get(&url).await.unwrap().status, StatusCode::OK);
        }
        assert_eq!(capped.idle_connections(), 2);
        for h in &servers {
            h.shutdown(Duration::from_secs(2)).await.unwrap();
        }
    });
}

/// Review finding client-early-error-response-lost. A server that answers
/// 413 at the head and closes before the body is written gets its 413
/// through to the caller, not a transport error.
#[test]
fn review_client_early_error_response_lost() {
    let rt = rt();
    rt.block_on(async {
        let h = Server::new(
            rt.clone(),
            ServerConfig::default(),
            app(&rt, &Arc::default()),
        )
        .bind(loopback())
        .await
        .unwrap();
        let client = plain_client(&rt);
        let req =
            Request::post(&url(&h, "http", "127.0.0.1", "/echo"), vec![b'a'; 32 << 20]).unwrap();
        let resp = client.send(req).await;
        match resp {
            Ok(r) => assert_eq!(r.status, StatusCode::CONTENT_TOO_LARGE),
            Err(e) => panic!("client got error: {e}"),
        }
        // The connection is not reused after an early response.
        assert_eq!(client.idle_connections(), 0);
        h.shutdown(Duration::from_secs(2)).await.unwrap();
    });
}
