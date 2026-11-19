//! Issue 6 (review of 2026-11-12): M8 (H-21, TH-21) rate limits and the
//! challenge purge and cap of the public auth routes, M9 (H-01) the
//! `PutText` rate, L12 uniform magic-link work, L17 response headers.
//! ADR-024 and ADR-009 (the peer address is never logged or stored).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use fstp_cell::routes::CHALLENGE_US;
use fstp_cell::routes::backend::MAX_CHALLENGES;
use fstp_cell::routes::memory::{DEFAULT_NOW_US, LocalCell};
use fstp_cell_core::CellCommand;
use fstp_cell_core::text::TextCommand;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xA1; 16];
const HOST: &str = "tenant-a.fstp.test";

fn cell() -> LocalCell {
    LocalCell::start(CELL, HOST).unwrap()
}

fn peer(a: u8, b: u8) -> SocketAddr {
    SocketAddr::from(([203, 0, a, b], 4000))
}

fn post(path: &str, cookie: Option<&[u8]>, body: &[u8], from: SocketAddr) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap()
        .with_peer_addr(from);
    if let Some(c) = cookie {
        req = req.try_with_header("cookie", c.to_vec()).unwrap();
    }
    req.body = body.to_vec();
    req
}

fn code(r: &Response) -> u16 {
    r.status.as_u16()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn magic(c: &LocalCell, email: &str, from: SocketAddr) -> Response {
    let body = format!("{{\"email\":\"{email}\"}}");
    c.serve(post("/auth/magic/request", None, body.as_bytes(), from))
}

fn recovery(c: &LocalCell, email: &str, from: SocketAddr) -> Response {
    let body = format!("{{\"email\":\"{email}\"}}");
    c.serve(post("/auth/recovery", None, body.as_bytes(), from))
}

/// M8, H-21, TH-21, ADR-024: login start is limited per peer. The 31st
/// call of a peer in a minute is refused, and another peer is unaffected.
#[test]
fn issue6_m8_login_start_is_limited_per_peer() {
    let c = cell();
    for i in 0..30 {
        let r = c.serve(post("/auth/passkey/login/options", None, b"{}", peer(1, 1)));
        assert_eq!(code(&r), 200, "call {i}");
    }
    let r = c.serve(post("/auth/passkey/login/options", None, b"{}", peer(1, 1)));
    assert_eq!(code(&r), 429);
    let r = c.serve(post("/auth/passkey/login/options", None, b"{}", peer(1, 2)));
    assert_eq!(code(&r), 200);
    // The finish route shares the peer budget.
    let r = c.serve(post("/auth/passkey/login", None, b"{}", peer(1, 1)));
    assert_eq!(code(&r), 429);
}

/// M8, H-21, ADR-024: magic-link requests are limited per peer (10 a
/// minute) and per target address (5 an hour). The per-target refusal is
/// the same reply as an accepted request, so it names no account.
#[test]
fn issue6_m8_magic_request_is_limited_per_peer_and_per_target() {
    let c = cell();
    for i in 0..10 {
        let r = magic(&c, &format!("nobody{i}@example.test"), peer(2, 1));
        assert_eq!(code(&r), 202, "call {i}");
    }
    assert_eq!(code(&magic(&c, "nobody@example.test", peer(2, 1))), 429);

    let known = c.applicant_email().to_owned();
    let before = c.backend().outbox().len();
    let mut replies = Vec::new();
    for i in 0..6 {
        let from = peer(3, i);
        replies.push(magic(&c, &known, from));
    }
    let unknown: Vec<Response> = (0..6)
        .map(|i| magic(&c, "ghost@example.test", peer(4, i)))
        .collect();
    for (k, u) in replies.iter().zip(&unknown) {
        assert_eq!(code(k), 202);
        assert_eq!(code(u), 202);
        assert_eq!(k.body, u.body, "a limited reply must match an accepted one");
    }
    // Five links went out for the known address, the sixth did not.
    assert_eq!(c.backend().outbox().len() - before, 5);
}

/// M8, H-21, ADR-024: expired challenges are purged when the next is
/// stored, and the table has a cap that fails closed.
#[test]
fn issue6_m8_expired_challenges_are_purged_and_the_table_is_capped() {
    let c = cell();
    let mut n = 0usize;
    let mut last = 0u16;
    'fill: for a in 0u8..=255 {
        for b in 0u8..=255 {
            for _ in 0..30 {
                let r = c.serve(post("/auth/passkey/login/options", None, b"{}", peer(a, b)));
                last = code(&r);
                if last != 200 {
                    break 'fill;
                }
                n += 1;
            }
        }
    }
    assert_eq!(n, MAX_CHALLENGES, "the cap admits exactly the bound");
    assert_eq!(last, 503, "at the cap, a new challenge fails closed");
    assert_eq!(c.backend().challenge_count(), MAX_CHALLENGES);
    // After their lifetime, the next call purges them all.
    c.backend()
        .set_now(Timestamp::from_micros(DEFAULT_NOW_US + CHALLENGE_US + 1));
    let r = c.serve(post(
        "/auth/passkey/login/options",
        None,
        b"{}",
        peer(250, 250),
    ));
    assert_eq!(code(&r), 200);
    assert_eq!(c.backend().challenge_count(), 1);
}

/// L12, issue 6: a known and an unknown address take the same steps in the
/// same order before the reply. The decoy of a storing step stands in the
/// same place as the step.
#[test]
fn issue6_l12_known_and_unknown_magic_requests_take_the_same_steps() {
    let c = cell();
    let known = c.applicant_email().to_owned();
    let _ = c.backend().take_magic_trail();
    let r1 = magic(&c, &known, peer(5, 1));
    let known_trail = c.backend().take_magic_trail();
    let r2 = magic(&c, "ghost@example.test", peer(5, 2));
    let unknown_trail = c.backend().take_magic_trail();
    assert_eq!(code(&r1), 202);
    assert_eq!(r1.body, r2.body);
    let shape = |t: &[&'static str]| -> Vec<&'static str> {
        t.iter()
            .map(|s| s.strip_prefix("decoy_").unwrap_or(s))
            .collect()
    };
    assert_eq!(shape(&known_trail), shape(&unknown_trail));
    assert_eq!(known_trail, ["state", "put_token", "send_magic_link"]);
    assert_eq!(
        unknown_trail,
        ["state", "decoy_put_token", "decoy_send_magic_link"]
    );
}

/// L17, ADR-014: the cell origin sends HSTS, COOP and CORP, as `fstp-web`
/// does.
#[test]
fn issue6_l17_cell_origin_sends_hsts_coop_and_corp() {
    let c = cell();
    let r = c.serve(post("/auth/passkey/login/options", None, b"{}", peer(6, 1)));
    let get = |n: &str| {
        r.headers
            .get(n)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    assert_eq!(
        get("strict-transport-security").as_deref(),
        Some("max-age=31536000")
    );
    assert_eq!(
        get("cross-origin-opener-policy").as_deref(),
        Some("same-origin")
    );
    assert_eq!(
        get("cross-origin-resource-policy").as_deref(),
        Some("same-origin")
    );
}

/// M9, H-01, ADR-024: an account puts at most 120 texts a minute. The
/// command has no owning object and no size, so the cell enforces the rate.
#[test]
fn issue6_m9_put_text_is_rate_limited_per_account() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let put = |i: u32| {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        id[15] = 0x77;
        let cmd = CellCommand::Text(TextCommand::PutText { id });
        let command = String::from_utf8(fstp_cell_core::encode_cell_command(&cmd)).unwrap();
        let mut cid = [0u8; 16];
        cid[..4].copy_from_slice(&i.to_be_bytes());
        cid[15] = 0x78;
        let body = format!("{{\"command\":{command},\"command_id\":\"{}\"}}", hex(&cid));
        c.serve(post(
            "/api/v1/commands",
            Some(&cookie),
            body.as_bytes(),
            peer(7, 1),
        ))
    };
    for i in 0..120 {
        assert_eq!(code(&put(i)), 200, "put {i}");
    }
    assert_eq!(code(&put(120)), 429);
}

/// L12, issue 6: `POST /auth/recovery` takes the same steps in the same
/// order for a known and an unknown address before the reply: read the
/// state, open the case, store the token row, send the proof. The decoy of
/// each storing step stands in the same place as the step. Only the known
/// address opens a case.
#[test]
fn issue6_l12_known_and_unknown_recovery_requests_take_the_same_steps() {
    let c = cell();
    c.backend()
        .set_deployment(Some(fstp_auth::recovery::Deployment::Saas));
    let known = c.applicant_email().to_owned();
    let before = c.backend().records().len();
    let _ = c.backend().take_magic_trail();
    let r1 = recovery(&c, &known, peer(6, 1));
    let known_trail = c.backend().take_magic_trail();
    let opened = c.backend().records().len();
    let r2 = recovery(&c, "ghost@example.test", peer(6, 2));
    let unknown_trail = c.backend().take_magic_trail();
    assert_eq!(code(&r1), 202);
    assert_eq!(code(&r2), 202);
    assert_eq!(r1.body, r2.body);
    let shape = |t: &[&'static str]| -> Vec<&'static str> {
        t.iter()
            .map(|s| s.strip_prefix("decoy_").unwrap_or(s))
            .collect()
    };
    assert_eq!(shape(&known_trail), shape(&unknown_trail));
    assert_eq!(
        known_trail,
        ["state", "execute", "put_token", "send_recovery_proof"]
    );
    assert_eq!(
        unknown_trail,
        [
            "state",
            "decoy_execute",
            "decoy_put_token",
            "decoy_send_recovery_proof"
        ]
    );
    assert!(opened > before, "the known address opened a case");
    assert_eq!(c.backend().records().len(), opened);
}
