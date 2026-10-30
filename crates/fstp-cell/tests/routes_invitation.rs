//! The invitation ceremony routes (design section 8.3, G10, Q35, I-20,
//! ADR-008). Lane int4. Each test drives the production front over the
//! in-memory backend (`fstp_cell::routes::memory::LocalCell`).
//!
//! The registrations here are real WebAuthn bytes: a `none` attestation
//! over an Ed25519 key from `fstp_crypto::sig`, written by the small
//! builder below. `fstp-celltest` holds the full software authenticator,
//! but it depends on this crate, so these tests cannot use it.
//!
//! The in-memory cell holds no invitation until a test seeds one. A
//! verified registration then reaches the enrolment step, which finds no
//! invitation for its proof and refuses with 401 under ADR-008, the same
//! reply as every other cause. Tests that need a live invitation seed its
//! `InvitationIssued` record ([`seed_invitation`]).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::routes::memory::LocalCell;
use fstp_cell::routes::{Backend, ChallengePurpose, ChallengeRow};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::id::AccountId;
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
    format!("{}{}", hex(&FIRST), hex(&SECOND))
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

fn state(c: &LocalCell) -> std::sync::Arc<fstp_cell_core::CellState> {
    fstp_rt::future::block_on(c.backend().state()).unwrap()
}

/// The route template the front logs for the register call.
const REGISTER_ROUTE: &str = "/auth/invitations/{token}/register";

/// Whether the last log line is a refusal of the register call with
/// `status` under `rule`.
fn last_refusal_is(c: &LocalCell, status: u16, rule: &str) -> bool {
    matches!(
        c.logs().last(),
        Some(fstp_obs::LogEvent::Refused { route, rule: r, status: s, .. })
            if *route == REGISTER_ROUTE && *r == rule && *s == status
    )
}

/// The first half, second half and single tokens of these tests.
const FIRST: [u8; 32] = [0x01; 32];
const SECOND: [u8; 32] = [0x02; 32];

/// Seeds the `InvitationIssued` record of invitation `id` for `account`,
/// at the cell's current instant. A split invitation is the first admin's
/// and is proved by [`FIRST`] and [`SECOND`]. A single one is proved by
/// `token` and is not the first admin's.
fn seed_invitation(c: &LocalCell, id: [u8; 16], account: AccountId, split: bool, token: [u8; 32]) {
    use fstp_auth::ceremony::{split_token_digest, token_digest};
    use fstp_auth::codec::Token;
    let digest = if split {
        split_token_digest(&Token(FIRST), &Token(SECOND))
    } else {
        token_digest(&Token(token))
    };
    c.backend()
        .seed(
            c.backend().now(),
            vec![fstp_cell_core::CellRecord::Auth(
                fstp_auth::AuthRecord::InvitationIssued {
                    invitation: id,
                    account,
                    token_digest: digest,
                    first_admin: split,
                    split,
                },
            )],
        )
        .unwrap();
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

/// G10, design section 8.3, ADR-008 "Challenges": a verified registration
/// over the challenge of a split proof that no invitation holds reaches
/// the enrolment step. That step finds no invitation and fails closed
/// with 401 under ADR-008, the reply of every other cause. The challenge
/// is spent and the ledger is unchanged. A second use of the challenge is
/// refused with 401 and records nothing.
///
/// The same proof enrols once an invitation holds it, over a fresh
/// challenge. So the refusal above comes from the invitation lookup, not
/// from an earlier check of the route.
#[test]
fn g10_invitation_register_fails_closed_and_spends_its_challenge() {
    let c = cell();
    let token = split_token();
    let (id, challenge) = options(&c, &token);
    let before = head(&c);
    let (att, client) = registration(challenge, &format!("https://{HOST}"));
    let body = register_body(&id, &att, &client);
    let r = c.serve(post(&register_path(&token), &body));
    assert_eq!(
        (status(&r), text(&r).as_str()),
        (401, "{\"error\":\"login\"}")
    );
    assert!(last_refusal_is(&c, 401, "ADR-008"), "{:?}", c.logs().last());
    assert_eq!(head(&c), before, "the refused enrolment recorded an entry");
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    let again = c.serve(post(&register_path(&token), &body));
    assert_eq!(status(&again), 401, "{}", text(&again));
    assert!(last_refusal_is(&c, 401, "ADR-008"), "{:?}", c.logs().last());
    assert_eq!(head(&c), before, "the second use recorded an entry");

    let invitee = AccountId::from_raw(0x1a01);
    let invitation = [0x1a; 16];
    seed_invitation(&c, invitation, invitee, true, [0; 32]);
    let seeded = head(&c);
    let (id, challenge) = options(&c, &token);
    let (att, client) = registration(challenge, &format!("https://{HOST}"));
    let r = c.serve(post(
        &register_path(&token),
        &register_body(&id, &att, &client),
    ));
    assert_eq!(status(&r), 200, "{}", text(&r));
    assert!(text(&r).contains("\"duplicate\":false"), "{}", text(&r));
    assert_ne!(head(&c), seeded, "the enrolment recorded nothing");
    let s = state(&c);
    assert!(
        s.auth().invitation(invitation).is_some_and(|i| i.consumed),
        "the invitation is not consumed"
    );
    assert!(s.auth().has_any_credential(invitee), "no passkey enrolled");
    assert!(
        s.auth().first_admin_enrolled(invitee),
        "no FirstAdminEnrolled"
    );
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
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
/// without the UV rule at the route step, since the rule depends on its
/// invitation. The enrolment step applies the rule of the invitation. A
/// registration without UV enrols an invitee who holds no management
/// role. For an invitee who holds one, here tenant admin, the same kind
/// of registration is refused with 401 under ADR-008. So is one for a
/// token that no invitation holds. Each refusal spends its challenge and
/// records nothing. The same manager's invitation then enrols a
/// registration with UV, so the refusal came from the UV rule alone.
#[test]
fn adr008_single_token_registration_defers_the_uv_rule() {
    let c = cell();
    let origin = format!("https://{HOST}");
    let register_uv = |token: &str, uv: bool| {
        let (id, challenge) = options(&c, token);
        let (att, client) = registration_uv(challenge, &origin, uv);
        let r = c.serve(post(
            &register_path(token),
            &register_body(&id, &att, &client),
        ));
        (r, id)
    };
    let register = |token: &str| register_uv(token, false);

    let unknown = hex(&[0x06; 32]);
    let before = head(&c);
    let (r, id) = register(&unknown);
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert!(last_refusal_is(&c, 401, "ADR-008"), "{:?}", c.logs().last());
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    assert_eq!(head(&c), before, "an unknown token recorded an entry");

    let manager = AccountId::from_raw(0x1b01);
    c.backend()
        .seed(
            c.backend().now(),
            vec![fstp_cell_core::CellRecord::Tenant(
                fstp_cell_core::tenant::TenantRecord::TenantAdminGranted { account: manager },
            )],
        )
        .unwrap();
    seed_invitation(&c, [0x1b; 16], manager, false, [0x07; 32]);
    let before = head(&c);
    let (r, id) = register(&hex(&[0x07; 32]));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert!(last_refusal_is(&c, 401, "ADR-008"), "{:?}", c.logs().last());
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    assert_eq!(head(&c), before, "a manager's passkey without UV enrolled");
    assert!(!state(&c).auth().has_any_credential(manager));
    assert!(
        state(&c)
            .auth()
            .invitation([0x1b; 16])
            .is_some_and(|i| !i.consumed),
        "a refused registration consumed the manager's invitation"
    );

    // The contrast: the same invitation, with UV, enrols the manager.
    let before = head(&c);
    let (r, id) = register_uv(&hex(&[0x07; 32]), true);
    assert_eq!(status(&r), 200, "{}", text(&r));
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    assert_ne!(head(&c), before, "the manager's enrolment recorded nothing");
    let s = state(&c);
    assert!(
        s.auth().has_any_credential(manager),
        "the manager's passkey with UV is not enrolled"
    );
    assert!(
        s.auth().invitation([0x1b; 16]).is_some_and(|i| i.consumed),
        "the manager's invitation is not consumed"
    );
    assert!(!s.auth().first_admin_enrolled(manager));

    let applicant = AccountId::from_raw(0x1c01);
    seed_invitation(&c, [0x1c; 16], applicant, false, [0x05; 32]);
    let before = head(&c);
    let (r, id) = register(&hex(&[0x05; 32]));
    assert_eq!(status(&r), 200, "{}", text(&r));
    assert!(challenge_row(&c, &id).is_none(), "the challenge is unspent");
    assert_ne!(head(&c), before, "the enrolment recorded nothing");
    let s = state(&c);
    assert!(
        s.auth().has_any_credential(applicant),
        "no passkey enrolled"
    );
    assert!(
        s.auth().invitation([0x1c; 16]).is_some_and(|i| i.consumed),
        "the invitation is not consumed"
    );
    assert!(!s.auth().first_admin_enrolled(applicant));
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
/// challenge is read. A well-formed body with a `credential_id` passes the
/// form check: the route takes its challenge and reaches the enrolment
/// step, which finds no invitation for the token and refuses with 401
/// under ADR-008. Nothing is recorded.
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
    let before = head(&c);
    let with_id = good.replacen('}', ",\"credential_id\":\"00ff\"}", 1);
    let r = c.serve(post(&register_path(&token), with_id.as_bytes()));
    assert_eq!(status(&r), 401, "{}", text(&r));
    assert!(last_refusal_is(&c, 401, "ADR-008"), "{:?}", c.logs().last());
    assert!(
        challenge_row(&c, &id).is_none(),
        "the well-formed body did not reach the challenge"
    );
    assert_eq!(head(&c), before, "the refused enrolment recorded an entry");
}
