//! The demo's email links and the demo inbox (ADR-008 record of lane L37).
//! Tests only.
//!
//! Each test starts the two cells on free loopback ports, with or without
//! `--demo-signin`, and talks HTTP to them as the auth pages and a person
//! on the front door do. Every address is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use fstp_json::Value;

use super::*;

const APPLICANT: &str = "inbox-applicant@e2e.invalid";

fn running(demo: bool) -> Running {
    let mut cfg = Config::loopback();
    cfg.demo_signin = demo;
    start(&cfg).unwrap_or_else(|e| panic!("{e}"))
}

/// One HTTP/1.1 exchange with `addr`: the status and the whole reply.
fn exchange(addr: &str, request: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).unwrap();
    let text = String::from_utf8_lossy(&reply).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, text)
}

fn cell_addr(site: &Site) -> String {
    let port = site.info.origin.rsplit(':').next().unwrap();
    format!("127.0.0.1:{port}")
}

fn control_addr(site: &Site) -> String {
    site.info.control.trim_start_matches("http://").to_owned()
}

/// A state-changing request to the cell, as the auth pages send it.
fn post(site: &Site, path: &str, body: &str, cookie: Option<&str>) -> (u16, String) {
    let cookie = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    exchange(
        &cell_addr(site),
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nX-FSTP-Request: 1\r\nContent-Type: application/json\r\n{cookie}Content-Length: {n}\r\nConnection: close\r\n\r\n{body}",
            host = site.info.host,
            origin = site.info.origin,
            n = body.len(),
        ),
    )
}

/// A page of the front door, as a person's browser asks for it.
fn front(site: &Site, path: &str) -> (u16, String) {
    exchange(
        &control_addr(site),
        &format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n"
        ),
    )
}

fn json_of(reply: &str) -> Value {
    let body = reply.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    fstp_json::parse_str(body.trim()).unwrap_or(Value::Null)
}

/// The session cookie a reply sets, as `name=value`.
fn cookie_of(reply: &str) -> String {
    let line = reply
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap_or_else(|| panic!("no cookie: {reply}"));
    let v = line.split_once(':').unwrap().1.trim();
    v.split(';').next().unwrap().to_owned()
}

/// The first link of `kind` on the demo inbox, unescaped.
fn link_on(page: &str, kind: &str) -> String {
    let item = page
        .split(&format!("data-demo-mail=\"{kind}\""))
        .nth(1)
        .unwrap_or_else(|| panic!("no {kind} on the inbox: {page}"));
    let href = item.split("href=\"").nth(1).unwrap();
    href.split('"').next().unwrap().replace("&amp;", "&")
}

/// The fragment of `link`.
fn fragment(link: &str) -> &str {
    link.split_once('#').unwrap().1
}

/// ADR-008 (lane L37), layering rule A9: without `--demo-signin`, as the
/// e2e suite runs the cell, the inbox and every email link route answer
/// 404, and the front door names no inbox.
#[test]
fn adr008_l37_demo_links_absent_without_the_flag() {
    let r = running(false);
    let site = &r.sites[0];
    assert_eq!(front(site, "/demo/inbox").0, 404);
    let (_, door) = front(site, "/demo");
    assert!(
        !door.contains("/demo/inbox"),
        "the front door links the inbox"
    );
    for path in [
        "/auth/magic/request",
        "/auth/magic/consume",
        "/auth/passkey-link",
        "/auth/recovery/00112233445566778899aabbccddeeff/email",
        "/auth/recovery/00112233445566778899aabbccddeeff/complete",
    ] {
        assert_eq!(post(site, path, "{}", None).0, 404, "{path}");
    }
}

/// ADR-008 "Registration code", "Later passkey" (lane L37): with the
/// demo flag, a sign-up email lands on the demo inbox with its link and
/// its 6-digit code, which answers the same proof. After an email-only
/// sign-up, "Send me a link" on the passkey offer lands a passkey link
/// there, whose proof answers `EmailThenPasskey` once and whose enrolment
/// token gives the creation options of a new passkey.
#[test]
fn adr008_l37_demo_inbox_holds_the_signup_code_and_the_passkey_link() {
    let r = running(true);
    let site = &r.sites[0];
    let (status, door) = front(site, "/demo");
    assert_eq!(status, 200);
    assert!(
        door.contains("href=\"/demo/inbox\""),
        "the front door links the inbox"
    );
    let (status, empty) = front(site, "/demo/inbox");
    assert_eq!(status, 200, "{empty}");
    assert!(empty.contains("demo-inbox-empty"));
    let body = format!(r#"{{"email":"{APPLICANT}"}}"#);
    assert_eq!(post(site, "/auth/signup/options", &body, None).0, 202);
    let (_, page) = front(site, "/demo/inbox");
    assert!(page.contains(APPLICANT), "{page}");
    let link = link_on(&page, "signup");
    assert!(
        link.starts_with(&format!("{}/auth/signup#", site.info.origin)),
        "{link}"
    );
    let token = fragment(&link).to_owned();
    assert_eq!(token.len(), 64, "a 32-byte proof token, as the cell's own");
    let raw: [u8; 32] = wire::unhex(&token).unwrap().try_into().unwrap();
    let code = String::from_utf8(fstp_auth::ceremony::signup_code(&raw).to_vec()).unwrap();
    assert!(
        page.contains(&format!("data-demo-code>{code}<")),
        "the code is on the inbox: {page}"
    );
    let (status, reply) = post(
        site,
        "/auth/signup/code",
        &format!(r#"{{"code":"{code}","email":"{APPLICANT}"}}"#),
        None,
    );
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        json_of(&reply).get("token").and_then(Value::as_str),
        Some(token.as_str())
    );
    let (status, reply) = post(
        site,
        "/auth/signup",
        &format!(r#"{{"token":"{token}"}}"#),
        None,
    );
    assert_eq!(status, 200, "the email-only sign-up: {reply}");
    let session = cookie_of(&reply);
    // "Send me a link" on the passkey offer.
    let (status, reply) = post(site, "/auth/passkey-link", "{}", Some(&session));
    assert_eq!(status, 202, "{reply}");
    assert_eq!(post(site, "/auth/passkey-link", "{}", None).0, 401);
    let (_, page) = front(site, "/demo/inbox");
    let link = link_on(&page, "passkey_link");
    assert!(
        link.starts_with(&format!("{}/auth/recovery#e.", site.info.origin)),
        "{link}"
    );
    let mut parts = fragment(&link).split('.').skip(1);
    let (case, proof) = (parts.next().unwrap(), parts.next().unwrap());
    let email = format!("/auth/recovery/{case}/email");
    let (status, reply) = post(site, &email, &format!(r#"{{"token":"{proof}"}}"#), None);
    assert_eq!(status, 200, "{reply}");
    let v = json_of(&reply);
    assert_eq!(
        v.get("path").and_then(Value::as_str),
        Some("EmailThenPasskey")
    );
    let enrolment = v
        .get("enrolment")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    assert_eq!(
        post(site, &email, &format!(r#"{{"token":"{proof}"}}"#), None).0,
        401,
        "the proof is single use"
    );
    let complete = format!("/auth/recovery/{case}/complete");
    let (status, reply) = post(
        site,
        &complete,
        &format!(r#"{{"token":"{enrolment}"}}"#),
        None,
    );
    assert_eq!(status, 200, "{reply}");
    let v = json_of(&reply);
    assert!(v.get("challenge_id").and_then(Value::as_str).is_some());
    assert!(v.get("public_key").is_some());
    assert_eq!(
        post(site, &complete, &format!(r#"{{"token":"{proof}"}}"#), None).0,
        401,
        "the proof is no enrolment token"
    );
}

/// I-77, ADR-008 (lane L37): with the demo flag, "Send me a link" on the
/// sign-in page lands a sign-in link on the demo inbox for a
/// Receiving-only account, which opens a session once. The tenant admin
/// and an unknown address get the same reply and no link.
#[test]
fn i77_l37_demo_sign_in_link_never_reaches_a_management_account() {
    let r = running(true);
    let site = &r.sites[0];
    let body = format!(r#"{{"email":"{APPLICANT}"}}"#);
    assert_eq!(post(site, "/auth/signup/options", &body, None).0, 202);
    let (_, page) = front(site, "/demo/inbox");
    let token = fragment(&link_on(&page, "signup")).to_owned();
    assert_eq!(
        post(
            site,
            "/auth/signup",
            &format!(r#"{{"token":"{token}"}}"#),
            None
        )
        .0,
        200
    );
    // The first tenant admin of the fresh cell.
    let (status, reset) = exchange(
        &control_addr(site),
        "POST /test/reset HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200, "{reset}");
    let admin = json_of(&reset)
        .get("first_admin")
        .and_then(|a| a.get("email"))
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    // The reset dropped the applicant: sign up again.
    assert_eq!(post(site, "/auth/signup/options", &body, None).0, 202);
    let (_, page) = front(site, "/demo/inbox");
    let token = fragment(&link_on(&page, "signup")).to_owned();
    assert_eq!(
        post(
            site,
            "/auth/signup",
            &format!(r#"{{"token":"{token}"}}"#),
            None
        )
        .0,
        200
    );
    for email in [admin.as_str(), "nobody@e2e.invalid", APPLICANT] {
        let (status, reply) = post(
            site,
            "/auth/magic/request",
            &format!(r#"{{"email":"{email}"}}"#),
            None,
        );
        assert_eq!(status, 202, "{email}: {reply}");
    }
    let (_, page) = front(site, "/demo/inbox");
    assert_eq!(
        page.matches("data-demo-mail=\"magic\"").count(),
        1,
        "one sign-in link, for the applicant only: {page}"
    );
    let link = link_on(&page, "magic");
    assert!(
        link.starts_with(&format!("{}/auth/magic#", site.info.origin)),
        "{link}"
    );
    let consume = format!(r#"{{"token":"{}"}}"#, fragment(&link));
    let (status, reply) = post(site, "/auth/magic/consume", &consume, None);
    assert_eq!(status, 200, "{reply}");
    assert!(cookie_of(&reply).starts_with("__Host-fstp="));
    assert_eq!(
        post(site, "/auth/magic/consume", &consume, None).0,
        401,
        "the link is single use"
    );
}
