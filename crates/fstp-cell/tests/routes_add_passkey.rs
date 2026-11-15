//! Adding a passkey through the cell routes (high risk `AddPasskey`,
//! R-LG-04, I-78, design sections 8.3 and 8.7, ADR-008 interim reading of
//! lane m3/cell-routes). Each test drives the production front over the
//! in-memory backend (`fstp_cell::routes::memory::LocalCell`).
//!
//! The flow, as the account page sends it: the step-up names the route
//! action `{type: "AddPasskey"}` and the addition's command id. Then
//! `POST /auth/passkeys/options {command_id, stepup}` draws a
//! registration challenge bound to the session and to that step-up, and
//! `POST /auth/passkeys` sends the registration with `challenge_id`,
//! `command_id` and `stepup`. The registrations are real WebAuthn bytes,
//! written by the small builder below, as in `routes_invitation.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::routes::memory::{LOCAL_ADMIN, LocalCell};
use fstp_cell::routes::{Backend, ChallengePurpose};
use fstp_cell_core::CellRecord;
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC7; 16];
const HOST: &str = "tenant-p.fstp.test";

fn cell() -> LocalCell {
    LocalCell::start(CELL, HOST).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn post(path: &str, cookie: &[u8], body: &[u8]) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap()
        .try_with_header("cookie", cookie.to_vec())
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

fn challenge_id_of(r: &Response) -> [u8; 16] {
    let t = text(r);
    let (_, rest) = t.split_once("\"challenge_id\":\"").unwrap();
    let (h, _) = rest.split_once('"').unwrap();
    fstp_cell::http::body::hex_array::<16>(h).unwrap()
}

/// The step-up options body of adding a passkey under `command_id`.
fn stepup_body(command_id: [u8; 16]) -> Vec<u8> {
    format!(
        "{{\"command\":{{\"type\":\"AddPasskey\"}},\"command_id\":\"{}\"}}",
        hex(&command_id)
    )
    .into_bytes()
}

/// A step-up granted in the admin's session for adding a passkey under
/// `command_id`: its id.
fn stepup(c: &LocalCell, cookie: &[u8], command_id: [u8; 16]) -> [u8; 16] {
    let o = c.serve(post(
        "/auth/stepup/options",
        cookie,
        &stepup_body(command_id),
    ));
    assert_eq!(status(&o), 200, "{}", text(&o));
    let id = challenge_id_of(&o);
    let g = c.serve(c.admin_stepup_request(cookie, id).unwrap());
    assert_eq!(status(&g), 200, "{}", text(&g));
    id
}

fn ids_body(command_id: [u8; 16], stepup: [u8; 16]) -> Vec<u8> {
    format!(
        "{{\"command_id\":\"{}\",\"stepup\":\"{}\"}}",
        hex(&command_id),
        hex(&stepup)
    )
    .into_bytes()
}

/// `POST /auth/passkeys/options {command_id, stepup}`.
fn options_reply(c: &LocalCell, cookie: &[u8], command_id: [u8; 16], su: [u8; 16]) -> Response {
    c.serve(post(
        "/auth/passkeys/options",
        cookie,
        &ids_body(command_id, su),
    ))
}

/// The options of a granted step-up: the challenge id and its nonce.
fn options(
    c: &LocalCell,
    cookie: &[u8],
    command_id: [u8; 16],
    su: [u8; 16],
) -> ([u8; 16], [u8; 32]) {
    let r = options_reply(c, cookie, command_id, su);
    assert_eq!(status(&r), 200, "{}", text(&r));
    let id = challenge_id_of(&r);
    let row = c.backend().peek_challenge(id).unwrap();
    (id, row.nonce)
}

fn add_body(
    challenge: [u8; 16],
    reg: &(Vec<u8>, Vec<u8>),
    command_id: [u8; 16],
    stepup: [u8; 16],
) -> Vec<u8> {
    format!(
        "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{}\",\"client_data_json\":\"{}\",\"command_id\":\"{}\",\"stepup\":\"{}\"}}",
        hex(&reg.0),
        hex(&challenge),
        hex(&reg.1),
        hex(&command_id),
        hex(&stepup)
    )
    .into_bytes()
}

/// The credentials registered to the seeded admin.
fn admin_credentials(c: &LocalCell) -> Vec<Vec<u8>> {
    fstp_rt::future::block_on(c.backend().state())
        .unwrap()
        .auth()
        .live_credentials(LOCAL_ADMIN)
}

fn head(c: &LocalCell) -> fstp_ledger::Seq {
    fstp_rt::future::block_on(c.backend().state())
        .unwrap()
        .head()
}

/// R-LG-04, I-78, design section 8.3: a tenant admin in a passkey session
/// adds a passkey. The step-up names the addition, the options bind a
/// registration challenge to the session and to that step-up, and the
/// registration records the key the gate verified and consumes the
/// step-up. The challenge is taken once.
#[test]
fn r_lg_04_i78_add_passkey_registers_through_the_cell_routes() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let command_id = [0x41; 16];
    let su = stepup(&c, &cookie, command_id);
    let (challenge, nonce) = options(&c, &cookie, command_id, su);
    let row = c.backend().peek_challenge(challenge).unwrap();
    assert_eq!(row.purpose, ChallengePurpose::AddPasskey);
    assert!(row.session.is_some());
    assert_eq!(
        row.action_digest,
        Some(fstp_cell_core::add_passkey_digest(command_id))
    );
    assert_eq!(admin_credentials(&c).len(), 1);
    let reg = registration_uv(nonce, true);
    let body = add_body(challenge, &reg, command_id, su);
    let r = c.serve(post("/auth/passkeys", &cookie, &body));
    assert_eq!(status(&r), 200, "{}", text(&r));
    let after = admin_credentials(&c);
    assert_eq!(after.len(), 2, "{after:?}");
    assert!(
        c.backend().records().iter().any(|r| matches!(
            r,
            CellRecord::Auth(fstp_auth::AuthRecord::StepUpConsumed { id }) if *id == su
        )),
        "the step-up was not consumed"
    );
    assert!(c.backend().peek_challenge(challenge).is_none());
    // A replay finds no challenge and records nothing.
    let at = head(&c);
    let again = c.serve(post("/auth/passkeys", &cookie, &body));
    assert_eq!(status(&again), 403, "{}", text(&again));
    assert_eq!(head(&c), at);
    // The consumed step-up draws no further challenge.
    let more = options_reply(&c, &cookie, command_id, su);
    assert_eq!(status(&more), 403, "{}", text(&more));
}

/// I-78, design sections 8.4 and 8.7: the options draw no registration
/// challenge without the granted step-up of the addition. No step-up
/// member is a body refusal, and an unknown step-up, one for another
/// command id and a stale one are refused under I-78.
#[test]
fn i78_add_passkey_options_need_the_step_up_of_the_addition() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let none = c.serve(post(
        "/auth/passkeys/options",
        &cookie,
        format!("{{\"command_id\":\"{}\"}}", hex(&[0x42; 16])).as_bytes(),
    ));
    assert_eq!(status(&none), 400, "{}", text(&none));
    let unknown = options_reply(&c, &cookie, [0x42; 16], [0x99; 16]);
    assert_eq!(status(&unknown), 403, "{}", text(&unknown));
    let su = stepup(&c, &cookie, [0x42; 16]);
    let other = options_reply(&c, &cookie, [0x43; 16], su);
    assert_eq!(status(&other), 403, "{}", text(&other));
    // P-71 plus 1 µs after the grant.
    let now = c.backend().now();
    c.backend().set_now(Timestamp::from_micros(
        now.micros() + fstp_cell_core::tenant::P71_DEFAULT_US + 1,
    ));
    let stale = options_reply(&c, &cookie, [0x42; 16], su);
    assert_eq!(status(&stale), 403, "{}", text(&stale));
}

/// I-78, ADR-008 interim reading of lane m3/cell-routes: a registration
/// over a challenge drawn under one addition is refused under another,
/// and nothing is recorded.
#[test]
fn i78_add_passkey_needs_the_challenge_of_its_own_step_up() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let first_id = [0x44; 16];
    let second_id = [0x45; 16];
    let first = stepup(&c, &cookie, first_id);
    let second = stepup(&c, &cookie, second_id);
    let (challenge, nonce) = options(&c, &cookie, first_id, first);
    let at = head(&c);
    let reg = registration_uv(nonce, true);
    let r = c.serve(post(
        "/auth/passkeys",
        &cookie,
        &add_body(challenge, &reg, second_id, second),
    ));
    assert_eq!(status(&r), 403, "{}", text(&r));
    assert_eq!(head(&c), at);
    assert_eq!(admin_credentials(&c).len(), 1);
}

/// I-78: the step-up options of `AddPasskey` take the route action, and
/// a step-up over the `RegisterCredential` command itself is no longer
/// offered, since it would admit nothing.
#[test]
fn i78_add_passkey_stepup_options_take_the_route_action_only() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let command = String::from_utf8(fstp_cell_core::encode_cell_command(
        &fstp_cell_core::CellCommand::Auth(fstp_auth::AuthCommand::RegisterCredential {
            account: LOCAL_ADMIN,
            credential: vec![0xA1, 2],
        }),
    ))
    .unwrap();
    let body = format!(
        "{{\"command\":{command},\"command_id\":\"{}\"}}",
        hex(&[0x46; 16])
    );
    let r = c.serve(post("/auth/stepup/options", &cookie, body.as_bytes()));
    assert_eq!(status(&r), 400, "{}", text(&r));
    let r = c.serve(post(
        "/auth/stepup/options",
        &cookie,
        b"{\"command\":{\"type\":\"AddPasskey\",\"x\":1},\"command_id\":\"00000000000000000000000000000000\"}",
    ));
    assert_eq!(status(&r), 400, "{}", text(&r));
    let r = c.serve(post(
        "/auth/stepup/options",
        &cookie,
        &stepup_body([0x46; 16]),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
}

/// I-78, design section 8.3: a magic-link session never adds a passkey,
/// and never steps up for one.
#[test]
fn i78_add_passkey_refuses_a_magic_link_session() {
    let c = cell();
    let cookie = c.applicant_session().unwrap();
    let r = c.serve(post(
        "/auth/stepup/options",
        &cookie,
        &stepup_body([0x47; 16]),
    ));
    assert_eq!(status(&r), 403, "{}", text(&r));
    let r = options_reply(&c, &cookie, [0x47; 16], [0x47; 16]);
    assert_eq!(status(&r), 403, "{}", text(&r));
}

/// I-78, ADR-008 "User verification": a tenant admin's new passkey
/// without UV is refused, and the spent challenge admits no retry.
#[test]
fn i78_add_passkey_refuses_a_holder_passkey_without_uv() {
    let c = cell();
    let cookie = c.admin_session().unwrap();
    let command_id = [0x48; 16];
    let su = stepup(&c, &cookie, command_id);
    let (challenge, nonce) = options(&c, &cookie, command_id, su);
    let at = head(&c);
    let reg = registration_uv(nonce, false);
    let r = c.serve(post(
        "/auth/passkeys",
        &cookie,
        &add_body(challenge, &reg, command_id, su),
    ));
    assert_eq!(status(&r), 403, "{}", text(&r));
    assert_eq!(head(&c), at);
    let reg = registration_uv(nonce, true);
    let r = c.serve(post(
        "/auth/passkeys",
        &cookie,
        &add_body(challenge, &reg, command_id, su),
    ));
    assert_eq!(status(&r), 403, "{}", text(&r));
    assert_eq!(admin_credentials(&c).len(), 1);
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
/// over `challenge` for the cell origin, with UP, and UV when `uv` holds.
fn registration_uv(challenge: [u8; 32], uv: bool) -> (Vec<u8>, Vec<u8>) {
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
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
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
