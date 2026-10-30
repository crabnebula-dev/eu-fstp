//! The invitation ceremony routes (design section 8.3, G10, Q35, I-20,
//! ADR-008). Lane int4. Each test drives the production front over the
//! in-memory backend (`fstp_cell::routes::memory::LocalCell`).
//!
//! The registrations here are real WebAuthn bytes: a `none` attestation
//! over an Ed25519 key from `fstp_crypto::sig`, written by the small
//! builder below. `fstp-celltest` holds the full software authenticator,
//! but it depends on this crate, so these tests cannot use it.
//!
//! The enrolment itself cannot commit yet
//! (`fstp_cell::routes::INVITATION_SEAM`), so every verified registration
//! answers 501 and records nothing. The tests pin each check before that
//! point.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::routes::memory::LocalCell;
use fstp_cell::routes::{Backend, ChallengePurpose, ChallengeRow};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC4; 16];
const HOST: &str = "tenant-i.fstp.test";

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

/// The string member `key` of a compact JSON reply, at its first place.
fn member(r: &Response, key: &str) -> String {
    let t = text(r);
    let (_, rest) = t
        .split_once(&format!("\"{key}\":\""))
        .unwrap_or_else(|| panic!("no {key} in {t}"));
    rest.split_once('"').unwrap().0.to_owned()
}

/// Unpadded base64url, decoded.
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

/// The split first-admin token path parameter: both halves, first first.
fn split_token() -> String {
    format!("{}{}", hex(&[0x01; 32]), hex(&[0x02; 32]))
}

fn options_path(token: &str) -> String {
    format!("/auth/invitations/{token}/register/options")
}

fn register_path(token: &str) -> String {
    format!("/auth/invitations/{token}/register")
}

/// Asks for registration options and returns `(challenge_id, challenge)`.
fn options(c: &LocalCell, token: &str) -> (String, [u8; 32]) {
    let r = c.serve(post(&options_path(token), b"{}"));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let challenge: [u8; 32] = unbase64url(&member(&r, "challenge")).try_into().unwrap();
    (member(&r, "challenge_id"), challenge)
}

// ---------------------------------------------------------------------------
// A minimal `none` registration (WebAuthn Level 2 sections 5.8.1, 6.1, 6.5).

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
/// over `challenge`, for `origin`, with UP and UV.
fn registration(challenge: [u8; 32], origin: &str) -> (Vec<u8>, Vec<u8>) {
    registration_uv(challenge, origin, true)
}

/// [`registration`] with UV set only when `uv` holds. UP is always set.
fn registration_uv(challenge: [u8; 32], origin: &str, uv: bool) -> (Vec<u8>, Vec<u8>) {
    let key = Ed25519SigningKey::generate().unwrap();
    let b64 = |b: &[u8]| {
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
    };
    let client = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}",
        b64(&challenge)
    )
    .into_bytes();
    // COSE_Key: {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}.
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    cbor_bytes(&mut cose, &key.public_key());
    let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
    auth.push(if uv { 0x01 | 0x04 | 0x40 } else { 0x01 | 0x40 });
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

fn register_body(challenge_id: &str, att: &[u8], client: &[u8]) -> Vec<u8> {
    format!(
        "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{challenge_id}\",\"client_data_json\":\"{}\"}}",
        hex(att),
        hex(client)
    )
    .into_bytes()
}

fn challenge_row(c: &LocalCell, id: &str) -> Option<ChallengeRow> {
    c.backend()
        .peek_challenge(fstp_cell::http::body::hex_array::<16>(id).unwrap())
}

fn head(c: &LocalCell) -> impl PartialEq + std::fmt::Debug {
    fstp_rt::future::block_on(c.backend().state())
        .unwrap()
        .head()
}

// ---------------------------------------------------------------------------
// The options call.

/// I-20, design section 8.3, ADR-008: the registration options name the
/// exact cell host as the relying party, a 32-byte challenge, the `none`
/// attestation, a discoverable credential, and user verification
/// required for the split first-admin token.
#[test]
fn i20_invitation_options_name_the_exact_cell_host() {
    let c = cell();
    let r = c.serve(post(&options_path(&split_token()), b"{}"));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let t = text(&r);
    assert!(t.contains(&format!("\"rp\":{{\"id\":\"{HOST}\"")), "{t}");
    assert!(t.contains("\"attestation\":\"none\""), "{t}");
    assert!(t.contains("\"residentKey\":\"required\""), "{t}");
    assert!(t.contains("\"userVerification\":\"required\""), "{t}");
    assert_eq!(unbase64url(&member(&r, "challenge")).len(), 32);
    let row = challenge_row(&c, &member(&r, "challenge_id")).unwrap();
    assert_eq!(row.purpose, ChallengePurpose::Registration);
    assert!(row.session.is_none());
}

/// ADR-008 "User verification", review finding of lane int4: a single
/// invitation token also requires user verification in its options. The
/// options call cannot tell a self-hosted first admin's or a holder's
/// token from another, and an authenticator that skipped UV would be
/// refused only at enrolment, with its challenge spent.
#[test]
fn adr008_single_token_invitation_options_require_user_verification() {
    let c = cell();
    let r = c.serve(post(&options_path(&hex(&[0x03; 32])), b"{}"));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let t = text(&r);
    assert!(t.contains("\"userVerification\":\"required\""), "{t}");
    assert!(!t.contains("\"preferred\""), "{t}");
}

/// Design section 8.3, TH-26: the token parameter is 64 or 128 lowercase
/// hexadecimal digits, and the options body is `{}`. Anything else is
/// refused with 400 and stores no challenge.
#[test]
fn adr008_invitation_token_and_body_forms_are_checked() {
    let c = cell();
    let bad_tokens = [
        hex(&[0x01; 31]),
        format!("{}0", hex(&[0x01; 32])),
        hex(&[0x01; 33]),
        hex(&[0xab; 32]).to_ascii_uppercase(),
        "z".repeat(64),
    ];
    for token in &bad_tokens {
        let r = c.serve(post(&options_path(token), b"{}"));
        assert_eq!(status(&r), 400, "{token}: {}", text(&r));
    }
    let r = c.serve(post(&options_path(&split_token()), b"{\"x\":1}"));
    assert_eq!(status(&r), 400, "{}", text(&r));
}

// ---------------------------------------------------------------------------
// The register call.

/// G10, design section 8.3: a verified registration over the invitation's
/// own challenge reaches the enrolment step, which fails closed with 501
/// (`INVITATION_SEAM`). The challenge is spent, the ledger is unchanged,
/// and a second use of it is refused with 401.
#[test]
fn g10_invitation_register_fails_closed_and_spends_its_challenge() {
    let c = cell();
    let token = split_token();
    let (id, challenge) = options(&c, &token);
    let before = head(&c);
    let (att, client) = registration(challenge, &format!("https://{HOST}"));
    let body = register_body(&id, &att, &client);
    let r = c.serve(post(&register_path(&token), &body));
    assert_eq!(status(&r), 501, "{}", text(&r));
    assert_eq!(head(&c), before, "the refused enrolment recorded an entry");
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    let again = c.serve(post(&register_path(&token), &body));
    assert_eq!(status(&again), 401, "{}", text(&again));
}

/// ADR-008 "User verification", Q35, review finding of lane int4: a
/// split token is the first admin's, so its registration needs UV. One
/// without UV is refused with 401 before the enrolment step, and records
/// nothing.
#[test]
fn adr008_split_token_registration_without_uv_is_refused() {
    let c = cell();
    let token = split_token();
    let (id, challenge) = options(&c, &token);
    let before = head(&c);
    let (att, client) = registration_uv(challenge, &format!("https://{HOST}"), false);
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&id, &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert_eq!(head(&c), before);
}

/// ADR-008 "User verification": a single token's registration is checked
/// without the UV rule at this step, since the rule depends on its
/// invitation. One without UV reaches the enrolment step, which fails
/// closed with 501 (`INVITATION_SEAM`).
#[test]
fn adr008_single_token_registration_defers_the_uv_rule() {
    let c = cell();
    let token = hex(&[0x05; 32]);
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration_uv(challenge, &format!("https://{HOST}"), false);
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&id, &att, &client),
    ));
    assert_eq!(status(&r), 501, "{}", text(&r));
}

/// I-20, ADR-008: a registration for another origin is refused with 401
/// and records nothing.
#[test]
fn i20_invitation_register_refuses_another_origin() {
    let c = cell();
    let token = split_token();
    let (id, challenge) = options(&c, &token);
    let before = head(&c);
    let (att, client) = registration(challenge, "https://other.fstp.test");
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&id, &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert_eq!(head(&c), before);
}

/// ADR-008 "Challenges": the register call takes only a registration
/// challenge issued for its own proof. A challenge of another token, a
/// login challenge and an unknown id are refused with 401, and none of
/// them is burnt.
#[test]
fn adr008_invitation_register_takes_only_its_own_challenge() {
    let c = cell();
    let token = split_token();
    let (other_id, other) = options(&c, &hex(&[0x07; 32]));
    let (att, client) = registration(other, &format!("https://{HOST}"));
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&other_id, &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert!(
        challenge_row(&c, &other_id).is_some(),
        "another token's challenge was burnt"
    );

    let login = c.serve(post("/auth/passkey/login/options", b"{}"));
    assert_eq!(status(&login), 200);
    let login_id = member(&login, "challenge_id");
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&login_id, &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert!(
        challenge_row(&c, &login_id).is_some(),
        "a login challenge was burnt"
    );

    let r = c.serve(post(
        &register_path(&token),
        &register_body(&hex(&[0x09; 16]), &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
}

/// ADR-008 "Challenges": a registration challenge older than its lifetime
/// is refused with 401.
#[test]
fn adr008_invitation_register_refuses_a_stale_challenge() {
    let c = cell();
    let token = split_token();
    c.backend()
        .set_now(Timestamp::from_micros(1_000_000_000_000));
    let (id, challenge) = options(&c, &token);
    c.backend().set_now(Timestamp::from_micros(
        1_000_000_000_000 + fstp_cell::routes::CHALLENGE_US + 1,
    ));
    let (att, client) = registration(challenge, &format!("https://{HOST}"));
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&id, &att, &client),
    ));
    assert_eq!(status(&r), 401, "{}", text(&r));
}

/// Design section 8.3, TH-26: the register body is
/// `{attestation_object, challenge_id, client_data_json}` with an optional
/// `credential_id`, each in lowercase hexadecimal. Another member, a
/// missing member or a malformed value is refused with 400 before any
/// challenge is read.
#[test]
fn adr008_invitation_register_body_form_is_checked() {
    let c = cell();
    let token = split_token();
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration(challenge, &format!("https://{HOST}"));
    let good = String::from_utf8(register_body(&id, &att, &client)).unwrap();
    let bodies = [
        good.replace("\"challenge_id\"", "\"challenge\""),
        good.replacen(&hex(&att), "zz", 1),
        good.replacen('}', ",\"extra\":\"00\"}", 1),
        good.replacen('}', ",\"credential_id\":\"0\"}", 1),
    ];
    for b in &bodies {
        let r = c.serve(post(&register_path(&token), b.as_bytes()));
        assert_eq!(status(&r), 400, "{b}: {}", text(&r));
    }
    assert!(
        challenge_row(&c, &id).is_some(),
        "a refused body burnt the challenge"
    );
    let with_id = good.replacen('}', ",\"credential_id\":\"00ff\"}", 1);
    let r = c.serve(post(&register_path(&token), with_id.as_bytes()));
    assert_eq!(status(&r), 501, "{}", text(&r));
}
