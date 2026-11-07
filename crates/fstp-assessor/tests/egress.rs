//! I-16 and B4: the assessor reaches only its two destinations (ADR-009
//! amendment "assessor egress", M7 design section 3.1).
//!
//! Every connection of the assessor goes through a [`Fence`]: a runtime
//! that resolves only its one endpoint and connects only to the
//! addresses that endpoint resolved to. It never listens.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fstp_assessor::{AssessorDestination, Fence};
use fstp_http::{Request, Response, Server, ServerConfig, StatusCode, handler_fn};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;

/// What a destination reaches.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// The tenant's P-21 endpoint from its inference record.
    InferenceEndpoint,
    /// The retrieval proxy.
    RetrievalProxy,
}

fn reach(d: AssessorDestination) -> Reach {
    match d {
        AssessorDestination::Inference => Reach::InferenceEndpoint,
        AssessorDestination::Retrieval => Reach::RetrievalProxy,
    }
}

/// I-16: the closed set of assessor destinations holds no payment
/// service, no CrabNebula host, no vault and no database.
#[test]
fn i16_assessor_egress_has_no_payment_destination() {
    let reached: Vec<Reach> = AssessorDestination::ALL.into_iter().map(reach).collect();
    assert_eq!(
        reached,
        vec![Reach::InferenceEndpoint, Reach::RetrievalProxy]
    );
}

/// B4: a fence refuses every name and port but its endpoint's, every
/// address its endpoint did not resolve to, and every listener.
#[test]
fn b4_assessor_connector_refuses_every_address_outside_its_destination() {
    let rt = TokioRuntime::new_current_thread().unwrap();
    let endpoint = "http://127.0.0.1:4100/v1/messages";
    check(
        "b4_assessor_connector_refuses_every_address_outside_its_destination",
        |g| {
            let to = *g.pick(&AssessorDestination::ALL);
            let fence = Fence::new(rt.clone(), to, endpoint).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(fence.destination(), to);
            let host = match g.usize_in(0..=4) {
                0 => "127.0.0.1".to_owned(),
                1 => "localhost".to_owned(),
                2 => "api.payments.test".to_owned(),
                3 => format!("10.{}.{}.{}", g.u8(), g.u8(), g.u8()),
                _ => g.string(1..=12),
            };
            let port = g.u16();
            let allowed = host == "127.0.0.1" && port == 4100;
            let resolved = rt.block_on(fence.resolve(&host, port));
            if allowed {
                prop_assert!(resolved.is_ok(), "own endpoint refused");
            } else {
                let refused = resolved
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.kind() == ErrorKind::PermissionDenied);
                prop_assert!(refused, "resolved {host}:{port}");
            }
            let addr = SocketAddr::from((
                Ipv4Addr::new(g.u8(), g.u8(), g.u8(), g.u8()),
                g.u16_in(1..=65535),
            ));
            if addr != SocketAddr::from((Ipv4Addr::LOCALHOST, 4100)) {
                let r = rt.block_on(fence.connect_tcp(addr));
                prop_assert!(
                    r.as_ref()
                        .err()
                        .is_some_and(|e| e.kind() == ErrorKind::PermissionDenied),
                    "connected to {addr}"
                );
            }
            let bound = rt.block_on(fence.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))));
            prop_assert!(bound.is_err(), "a fence never listens");
            Ok(())
        },
    );
}

/// B4: an HTTP client over the retrieval fence reaches the proxy and
/// never another local server, even one on the same host.
#[test]
fn b4_assessor_client_never_reaches_another_local_server() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let hits = Arc::new(AtomicU64::new(0));
        let h1 = hits.clone();
        let proxy = Server::new(
            rt2.clone(),
            ServerConfig::default(),
            handler_fn(move |_req: Request| {
                h1.fetch_add(1, Ordering::SeqCst);
                async move { Response::text(StatusCode::OK, "proxy") }
            }),
        )
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
        let other_hits = Arc::new(AtomicU64::new(0));
        let oh = other_hits.clone();
        let other = Server::new(
            rt2.clone(),
            ServerConfig::default(),
            handler_fn(move |_req: Request| {
                oh.fetch_add(1, Ordering::SeqCst);
                async move { Response::text(StatusCode::OK, "other") }
            }),
        )
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
        let base = format!("http://127.0.0.1:{}", proxy.local_addr().port());
        let fence = Fence::new(rt2.clone(), AssessorDestination::Retrieval, &base).unwrap();
        let client = fstp_http::Client::new(fence, fstp_http::ClientConfig::default());
        let ok = client.get(&format!("{base}/v1/retrieve")).await.unwrap();
        assert_eq!(ok.status.as_u16(), 200);
        for url in [
            format!("http://127.0.0.1:{}/", other.local_addr().port()),
            format!("http://localhost:{}/", proxy.local_addr().port()),
            "http://api.payments.test/".to_owned(),
        ] {
            assert!(client.get(&url).await.is_err(), "reached {url}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(other_hits.load(Ordering::SeqCst), 0);
        let _ = proxy.shutdown(Duration::from_secs(1)).await;
        let _ = other.shutdown(Duration::from_secs(1)).await;
    });
}
