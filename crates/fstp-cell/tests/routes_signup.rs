//! The self-registration routes (design section 8.3 ceremony 2, ADR-008
//! "Ceremonies and the first passkey", lane F-CYCLE3). Each test drives
//! the production front over the in-memory backend
//! (`fstp_cell::routes::memory::LocalCell`), which keeps each email proof
//! it sends (`MemoryBackend::signup_proofs`). Every address is synthetic.
//!
//! The registrations are real WebAuthn bytes: a `none` attestation over an
//! Ed25519 key from `fstp_crypto::sig`, built as `routes_invitation.rs`
//! builds them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::routes::ChallengePurpose;
use fstp_cell::routes::memory::LocalCell;
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC5; 16];
const HOST: &str = "tenant-s.fstp.test";
const EMAIL: &str = "applicant.synthetic@example.test";

fn cell() -> LocalCell {
    LocalCell::start(CELL, HOST).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn post(path: &str, body: &[u8]) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    req.body = body.to_vec();
    req
}

fn status(r: &Response) -> u16 {
    r.status.as_u16()
}

fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn member(r: &Response, key: &str) -> String {
    let t = text(r);
    let (_, rest) = t
        .split_once(&format!("\"{key}\":\""))
        .unwrap_or_else(|| panic!("no {key} in {t}"));
    rest.split_once('"').unwrap().0.to_owned()
}

fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
        for k in 0..=chunk.len() {
            s.push(char::from(
                A[usize::try_from((n >> (18 - 6 * k)) & 63).unwrap()],
            ));
        }
    }
    s
}

fn unbase64url(s: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url: {s}"),
        }
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        acc = (acc << 6) | value(c);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
        }
    }
    out
}

fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | u8::try_from(n).unwrap()),
        24..=255 => out.extend([m | 24, u8::try_from(n).unwrap()]),
        _ => {
            out.push(m | 25);
            out.extend(u16::try_from(n).unwrap().to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, t: &str) {
    cbor_head(out, 3, t.len());
    out.extend_from_slice(t.as_bytes());
}

/// `(attestation_object, client_data_json)` of a new Ed25519 credential
/// over `challenge` for the cell origin, with UP and without UV, as an
/// applicant's authenticator may answer.
fn registration(challenge: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let key = Ed25519SigningKey::generate().unwrap();
    let client = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
        b64(&challenge)
    )
    .into_bytes();
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    cbor_bytes(&mut cose, &key.public_key());
    let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
    auth.push(0x01 | 0x40);
    auth.extend(0u32.to_be_bytes());
    auth.extend([0u8; 16]);
    auth.extend(16u16.to_be_bytes());
    auth.extend(fstp_crypto::random_array::<16>().unwrap());
    auth.extend(cose);
    let mut att = Vec::new();
    cbor_head(&mut att, 5, 3);
    cbor_text(&mut att, "fmt");
    cbor_text(&mut att, "none");
    cbor_text(&mut att, "attStmt");
    cbor_head(&mut att, 5, 0);
    cbor_text(&mut att, "authData");
    cbor_bytes(&mut att, &auth);
    (att, client)
}

/// Sends the email proof and returns its token from the proof mail.
fn proof(c: &LocalCell) -> String {
    let r = c.serve(post(
        "/auth/signup/options",
        format!("{{\"email\":\"{EMAIL}\"}}").as_bytes(),
    ));
    assert_eq!(status(&r), 202, "{}", text(&r));
    let (to, token) = c.backend().signup_proofs().last().cloned().unwrap();
    assert_eq!(to, EMAIL);
    hex(&token)
}

/// Asks for the creation options of `token`: `(challenge_id, challenge)`.
fn options(c: &LocalCell, token: &str) -> (String, [u8; 32]) {
    let r = c.serve(post(
        "/auth/signup/options",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let challenge: [u8; 32] = unbase64url(&member(&r, "challenge")).try_into().unwrap();
    (member(&r, "challenge_id"), challenge)
}

fn signup_body(challenge_id: &str, att: &[u8], client: &[u8], token: &str) -> Vec<u8> {
    format!(
        "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{challenge_id}\",\"client_data_json\":\"{}\",\"token\":\"{token}\"}}",
        hex(att),
        hex(client)
    )
    .into_bytes()
}

/// The accounts of every `CredentialRegistered` record. The local cell
/// seeds an admin and an applicant with passkeys at start.
fn registered(c: &LocalCell) -> Vec<fstp_domain::id::AccountId> {
    let mut out = Vec::new();
    for e in c.backend().records() {
        if let fstp_cell_core::CellRecord::Auth(fstp_auth::AuthRecord::CredentialRegistered {
            account,
            ..
        }) = e
        {
            out.push(account);
        }
    }
    out
}

/// Design section 8.3 ceremony 2, ADR-008: the email proof, then a
/// passkey in the same ceremony, creates one new account with its first
/// passkey and opens its session. An applicant passkey needs no UV, and
/// the options request it without requiring it.
#[test]
fn adr008_signup_creates_a_receiving_account_with_its_first_passkey() {
    let c = cell();
    let before = registered(&c).len();
    let token = proof(&c);
    let r = c.serve(post(
        "/auth/signup/options",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert!(
        text(&r).contains("\"userVerification\":\"preferred\""),
        "{}",
        text(&r)
    );
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration(challenge);
    let r = c.serve(post(
        "/auth/signup",
        &signup_body(&id, &att, &client, &token),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    assert!(r.headers.get("set-cookie").is_some(), "no session cookie");
    assert_eq!(registered(&c).len(), before + 1, "one new account");
}

/// ADR-008, design section 8.3: the email proof is single-use. A second
/// signup with the same token is refused and creates nothing.
#[test]
fn adr008_signup_proof_is_single_use() {
    let c = cell();
    let before = registered(&c).len();
    let token = proof(&c);
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration(challenge);
    let r = c.serve(post(
        "/auth/signup",
        &signup_body(&id, &att, &client, &token),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration(challenge);
    let r = c.serve(post(
        "/auth/signup",
        &signup_body(&id, &att, &client, &token),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert_eq!(
        registered(&c).len(),
        before + 1,
        "the replay created an account"
    );
}

/// ADR-008: a token the cell never sent proves nothing. The challenge is
/// bound to the token's digest, so it is a signup challenge, and the
/// signup is refused with nothing recorded.
#[test]
fn adr008_signup_without_a_sent_proof_is_refused() {
    let c = cell();
    let before = registered(&c).len();
    let token = hex(&[0x5a; 32]);
    let (id, challenge) = options(&c, &token);
    let row = c
        .backend()
        .peek_challenge(fstp_cell::http::body::hex_array::<16>(&id).unwrap())
        .unwrap();
    assert_eq!(row.purpose, ChallengePurpose::Signup);
    let (att, client) = registration(challenge);
    let r = c.serve(post(
        "/auth/signup",
        &signup_body(&id, &att, &client, &token),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert_eq!(registered(&c).len(), before);
}

/// The accounts of every `AccountSelfRegistered` record (ADR-032).
fn email_only(c: &LocalCell) -> Vec<fstp_domain::id::AccountId> {
    let mut out = Vec::new();
    for e in c.backend().records() {
        if let fstp_cell_core::CellRecord::Auth(fstp_auth::AuthRecord::AccountSelfRegistered {
            account,
        }) = e
        {
            out.push(account);
        }
    }
    out
}

/// R-LG-01, ADR-032, ADR-008 (Daniel, 2026-11-22: "Email only, passkey
/// optional"): with magic links on, the email proof alone creates the
/// account and opens a magic-link session. No passkey is registered. The
/// proof is single use, and the proven address then gets magic links.
#[test]
fn r_lg_01_adr032_signup_with_email_only_opens_a_magic_link_session() {
    let c = cell();
    let before = registered(&c).len();
    let token = proof(&c);
    let body = format!("{{\"token\":\"{token}\"}}");
    let r = c.serve(post("/auth/signup", body.as_bytes()));
    assert_eq!(status(&r), 200, "{}", text(&r));
    assert!(r.headers.get("set-cookie").is_some(), "no session cookie");
    assert_eq!(registered(&c).len(), before, "no passkey was registered");
    assert_eq!(email_only(&c).len(), 1, "one new email-only account");
    let again = c.serve(post("/auth/signup", body.as_bytes()));
    assert_eq!(status(&again), 401, "{}", text(&again));
    assert_eq!(email_only(&c).len(), 1, "the replay created an account");
    let m = c.serve(post(
        "/auth/magic/request",
        format!("{{\"email\":\"{EMAIL}\"}}").as_bytes(),
    ));
    assert_eq!(status(&m), 202, "{}", text(&m));
    assert!(
        c.backend()
            .outbox()
            .iter()
            .any(|(a, _)| *a == email_only(&c)[0]),
        "the proven address gets a magic link"
    );
}

/// ADR-008 "Magic links" by analogy: the proof request answers the same
/// whatever the address, and a body with an unknown member is refused.
#[test]
fn adr008_signup_options_answer_uniformly_and_check_their_body() {
    let c = cell();
    for email in ["a.synthetic@example.test", "b.synthetic@example.test"] {
        let r = c.serve(post(
            "/auth/signup/options",
            format!("{{\"email\":\"{email}\"}}").as_bytes(),
        ));
        assert_eq!(status(&r), 202);
        assert_eq!(text(&r), "{\"status\":\"accepted\"}");
    }
    let r = c.serve(post(
        "/auth/signup/options",
        b"{\"email\":\"a.synthetic@example.test\",\"x\":1}",
    ));
    assert_eq!(status(&r), 400, "{}", text(&r));
}

// ---------------------------------------------------------------------------
// The typed registration code and the later passkey (Daniel, 2026-11-22,
// ADR-008 "Registration code" and "Later passkey").
// ---------------------------------------------------------------------------

/// The code the registration email carries for the newest proof.
fn code_of_newest(c: &LocalCell) -> String {
    let (_, token) = c.backend().signup_proofs().last().cloned().unwrap();
    String::from_utf8(fstp_auth::ceremony::signup_code(&token).to_vec()).unwrap()
}

fn code_body(code: &str, email: &str) -> Vec<u8> {
    format!("{{\"code\":\"{code}\",\"email\":\"{email}\"}}").into_bytes()
}

/// The `name=value` of the session cookie a reply set.
fn cookie_of(r: &Response) -> String {
    let v = r.headers.get("set-cookie").expect("a session cookie");
    let s = String::from_utf8_lossy(v.as_bytes()).into_owned();
    s.split(';').next().unwrap().to_owned()
}

fn with_cookie(req: Request, cookie: &str) -> Request {
    req.try_with_header("cookie", cookie.to_owned()).unwrap()
}

/// ADR-008 "Registration code": the code of the email answers the proof
/// token once, and the token then finishes the registration as the link
/// does. The code works once.
#[test]
fn adr008_registration_code_completes_registration() {
    let c = cell();
    let _ = proof(&c);
    let code = code_of_newest(&c);
    let r = c.serve(post("/auth/signup/code", &code_body(&code, EMAIL)));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let token = member(&r, "token");
    let (_, sent) = c.backend().signup_proofs().last().cloned().unwrap();
    assert_eq!(token, hex(&sent), "the code names the email's proof");
    let done = c.serve(post(
        "/auth/signup",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert_eq!(status(&done), 200, "{}", text(&done));
    let again = c.serve(post("/auth/signup/code", &code_body(&code, EMAIL)));
    assert_eq!(status(&again), 401, "single use");
}

/// ADR-008 "Registration code": a wrong code, an unknown address and a
/// used code get the same 401 reply, so the answer tells nothing about
/// the address.
#[test]
fn adr008_wrong_code_and_unknown_address_answer_alike() {
    let c = cell();
    let _ = proof(&c);
    let code = code_of_newest(&c);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let a = c.serve(post("/auth/signup/code", &code_body(wrong, EMAIL)));
    let b = c.serve(post(
        "/auth/signup/code",
        &code_body(&code, "nobody.synthetic@example.test"),
    ));
    assert_eq!(status(&a), 401);
    assert_eq!((status(&b), text(&b)), (401, text(&a)));
}

/// ADR-008 "Registration code": five wrong attempts kill the code, so
/// the right code is refused after them. The link still works.
#[test]
fn adr008_registration_code_dies_after_five_wrong_attempts() {
    let c = cell();
    let token = proof(&c);
    let code = code_of_newest(&c);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for _ in 0..5 {
        let r = c.serve(post("/auth/signup/code", &code_body(wrong, EMAIL)));
        assert_eq!(status(&r), 401);
    }
    let r = c.serve(post("/auth/signup/code", &code_body(&code, EMAIL)));
    assert_eq!(status(&r), 401, "the code is dead");
    let link = c.serve(post(
        "/auth/signup",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert_eq!(status(&link), 200, "the link still works: {}", text(&link));
}

/// ADR-008 "Later passkey": an email-only account asks for a fresh
/// "email link, then create passkey" link in its session. The cell opens
/// a recovery case for that account and sends its email proof. An account
/// that holds a passkey is refused, since a completed recovery revokes its
/// credentials. Without a session the route answers 401.
#[test]
fn adr008_email_only_account_gets_a_passkey_link() {
    let c = cell();
    c.backend()
        .set_deployment(Some(fstp_auth::recovery::Deployment::Saas));
    let token = proof(&c);
    let r = c.serve(post(
        "/auth/signup",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let cookie = cookie_of(&r);
    let _ = c.backend().take_magic_trail();
    let link = c.serve(with_cookie(post("/auth/passkey-link", b"{}"), &cookie));
    assert_eq!(status(&link), 202, "{}", text(&link));
    assert!(
        c.backend()
            .take_magic_trail()
            .contains(&"send_recovery_proof"),
        "a fresh link was sent"
    );
    let none = c.serve(post("/auth/passkey-link", b"{}"));
    assert_eq!(status(&none), 401);
    // An account with a passkey.
    let c2 = cell();
    let token = proof(&c2);
    let (id, challenge) = options(&c2, &token);
    let (att, client) = registration(challenge);
    let r = c2.serve(post(
        "/auth/signup",
        &signup_body(&id, &att, &client, &token),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let refused = c2.serve(with_cookie(
        post("/auth/passkey-link", b"{}"),
        &cookie_of(&r),
    ));
    assert_eq!(status(&refused), 409, "{}", text(&refused));
}
