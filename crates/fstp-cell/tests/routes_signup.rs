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

/// ADR-008 open point "Self-registration without a passkey", interim: the
/// form without passkey members fails closed with 501 and records nothing.
#[test]
fn adr008_signup_without_a_passkey_fails_closed() {
    let c = cell();
    let before = registered(&c).len();
    let token = proof(&c);
    let r = c.serve(post(
        "/auth/signup",
        format!("{{\"token\":\"{token}\"}}").as_bytes(),
    ));
    assert_eq!(status(&r), 501, "{}", text(&r));
    assert_eq!(registered(&c).len(), before);
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
