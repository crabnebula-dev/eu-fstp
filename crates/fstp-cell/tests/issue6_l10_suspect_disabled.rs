//! Issue 6 L10 follow-up, ADR-008 "Decided by Daniel, 2026-11-19": a
//! passkey flagged `CredentialSuspect` is disabled for good. It is refused
//! at login and at step-up, the refusal tells a client nothing about the
//! flag, the refusal writes nothing, and the account's other passkeys,
//! adding a passkey and account recovery keep working. The holder notice
//! (mailbox message and email) is not covered here: it is open in the ADR.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::AuthRecord;
use fstp_cell::routes::Backend as _;
use fstp_cell::routes::memory::{LOCAL_ADMIN, LocalCell};
use fstp_cell_core::CellRecord;
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_webauthn::CoseKey;

const CELL: [u8; 16] = [0xC4; 16];
const HOST: &str = "tenant-d.fstp.test";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

fn request(method: Method, path: &str, cookie: Option<&[u8]>, body: &[u8]) -> Request {
    let mut req = Request::new(method, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    if let Some(c) = cookie {
        req = req.try_with_header("cookie", c.to_vec()).unwrap();
    }
    req.body = body.to_vec();
    req
}

fn post(path: &str, cookie: Option<&[u8]>, body: &[u8]) -> Request {
    request(Method::POST, path, cookie, body)
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

fn cookie_of(r: &Response) -> Vec<u8> {
    assert_eq!(r.status.as_u16(), 200, "{}", text(r));
    let set = r.headers.get("set-cookie").unwrap();
    set.as_bytes()
        .split(|b| *b == b';')
        .next()
        .unwrap()
        .to_vec()
}

/// A software passkey the test holds. `registered` says whether the ledger
/// knows it.
struct Pk {
    key: Ed25519SigningKey,
    credential: Vec<u8>,
    count: u32,
}

impl Pk {
    fn new() -> Pk {
        Pk {
            key: Ed25519SigningKey::generate().unwrap(),
            credential: fstp_crypto::random_array::<16>().unwrap().to_vec(),
            count: 0,
        }
    }

    /// Registers this passkey to the seeded admin, as a second passkey.
    fn register(&self, c: &LocalCell) {
        c.backend()
            .seed(
                c.backend().now(),
                vec![CellRecord::Auth(AuthRecord::CredentialRegistered {
                    account: LOCAL_ADMIN,
                    credential: self.credential.clone(),
                    key: CoseKey::Ed25519 {
                        x: self.key.public_key(),
                    },
                    user_verified: true,
                })],
            )
            .unwrap();
    }

    /// The assertion body over `challenge` for challenge row `id`, with
    /// the next sign count.
    fn assertion(&mut self, id: [u8; 16], challenge: &[u8]) -> Vec<u8> {
        self.count += 1;
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
            b64(challenge)
        );
        let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        auth.push(0x01 | 0x04);
        auth.extend_from_slice(&self.count.to_be_bytes());
        let mut msg = auth.clone();
        msg.extend_from_slice(&fstp_crypto::sha256(client.as_bytes()));
        let sig = self.key.sign(&msg).unwrap();
        format!(
            "{{\"authenticator_data\":\"{}\",\"challenge_id\":\"{}\",\"client_data_json\":\"{}\",\"credential_id\":\"{}\",\"signature\":\"{}\"}}",
            hex(&auth),
            hex(&id),
            hex(client.as_bytes()),
            hex(&self.credential),
            hex(&sig)
        )
        .into_bytes()
    }

    fn login(&mut self, c: &LocalCell) -> Response {
        let o = c.serve(post("/auth/passkey/login/options", None, b"{}"));
        let id = challenge_id_of(&o);
        let nonce = c.backend().peek_challenge(id).unwrap().nonce;
        let body = self.assertion(id, &nonce);
        c.serve(post("/auth/passkey/login", None, &body))
    }

    /// Steps up in `cookie`'s session for adding a passkey under
    /// `command_id`. Answers the step-up id (the
    /// challenge id) and the step-up reply.
    fn stepup(
        &mut self,
        c: &LocalCell,
        cookie: &[u8],
        command_id: [u8; 16],
    ) -> ([u8; 16], Response) {
        let body = format!(
            "{{\"command\":{{\"type\":\"AddPasskey\"}},\"command_id\":\"{}\"}}",
            hex(&command_id)
        );
        let o = c.serve(post("/auth/stepup/options", Some(cookie), body.as_bytes()));
        assert_eq!(o.status.as_u16(), 200, "{}", text(&o));
        let id = challenge_id_of(&o);
        let row = c.backend().peek_challenge(id).unwrap();
        let ch = fstp_auth::stepup::challenge(
            CELL,
            row.session.unwrap(),
            row.action_digest.unwrap(),
            row.nonce,
        );
        let body = self.assertion(id, &ch);
        let r = c.serve(post("/auth/stepup", Some(cookie), &body));
        (id, r)
    }
}

fn admin_credential(c: &LocalCell) -> Vec<u8> {
    c.backend()
        .records()
        .into_iter()
        .find_map(|r| match r {
            CellRecord::Auth(AuthRecord::CredentialRegistered {
                account,
                credential,
                ..
            }) if account == LOCAL_ADMIN => Some(credential),
            _ => None,
        })
        .unwrap()
}

fn state(c: &LocalCell) -> std::sync::Arc<fstp_cell_core::CellState> {
    fstp_rt::future::block_on(c.backend().state()).unwrap()
}

/// Flags the seeded admin passkey: a signed regression at login. Then the
/// stored count is reset below the next count the admin passkey signs, so a
/// later assertion is correct and higher.
fn flag_admin_passkey(c: &LocalCell, cred: &[u8]) -> Response {
    drop(c.backend().set_sign_count(cred.to_vec(), 1000));
    let first = c.serve(c.admin_login_request().unwrap());
    assert_eq!(first.status.as_u16(), 401);
    assert!(state(c).auth().credential(cred).unwrap().suspect);
    drop(c.backend().set_sign_count(cred.to_vec(), 0));
    first
}

/// Issue 6 L10, ADR-008 (2026-11-19): a suspect passkey is refused at login
/// even with a correct, higher sign count. The refusal is the same status
/// and body as the refusal of a credential the cell does not know, and as
/// the refusal of the regression itself. It writes no record, so a replayed
/// cloned passkey grows the ledger by nothing.
#[test]
fn issue6_l10_adr008_suspect_passkey_is_refused_at_login_and_writes_nothing() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let first = flag_admin_passkey(&c, &cred);
    let before = c.backend().records().len();
    let unknown = Pk::new().login(&c);
    assert_eq!(unknown.status.as_u16(), 401);
    assert_eq!(
        unknown.body, first.body,
        "an unknown credential answers alike"
    );
    for _ in 0..3 {
        let r = c.serve(c.admin_login_request().unwrap());
        assert_eq!(r.status.as_u16(), 401, "correct and higher, still refused");
        assert_eq!(r.body, first.body, "no oracle for the flag");
    }
    assert_eq!(c.backend().records().len(), before, "nothing was written");
    assert!(state(&c).auth().stored_credential(&cred, 0).is_none());
}

/// Issue 6 L10, ADR-008 (2026-11-19): another passkey of the same account
/// still signs in after the first is flagged.
#[test]
fn issue6_l10_adr008_another_passkey_of_the_account_still_signs_in() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let mut second = Pk::new();
    second.register(&c);
    let _ = flag_admin_passkey(&c, &cred);
    let r = second.login(&c);
    assert_eq!(r.status.as_u16(), 200, "{}", text(&r));
    let _ = cookie_of(&r);
}

/// Issue 6 L10, ADR-008 (2026-11-19): a step-up by a suspect passkey is
/// refused as any failed step-up is, and a step-up by the other passkey of
/// the account is granted.
#[test]
fn issue6_l10_adr008_suspect_passkey_is_refused_at_stepup() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let mut second = Pk::new();
    second.register(&c);
    let cookie = cookie_of(&second.login(&c));
    let _ = flag_admin_passkey(&c, &cred);
    let body = format!(
        "{{\"command\":{{\"type\":\"AddPasskey\"}},\"command_id\":\"{}\"}}",
        hex(&[0x61; 16])
    );
    let o = c.serve(post("/auth/stepup/options", Some(&cookie), body.as_bytes()));
    let id = challenge_id_of(&o);
    let before = c.backend().records().len();
    // The suspect passkey signs a correct, higher assertion.
    let req = c.admin_stepup_request(&cookie, id).unwrap();
    let r = c.serve(req);
    assert_eq!(r.status.as_u16(), 403, "{}", text(&r));
    // An unknown credential answers alike.
    let row = c.backend().peek_challenge(id).unwrap();
    let ch = fstp_auth::stepup::challenge(
        CELL,
        row.session.unwrap(),
        row.action_digest.unwrap(),
        row.nonce,
    );
    let mut stranger = Pk::new();
    let u = c.serve(post(
        "/auth/stepup",
        Some(&cookie),
        &stranger.assertion(id, &ch),
    ));
    assert_eq!(u.status.as_u16(), 403);
    assert_eq!(u.body, r.body, "no oracle for the flag");
    assert_eq!(c.backend().records().len(), before, "nothing was written");
    // The other passkey steps up.
    let (_, ok) = second.stepup(&c, &cookie, [0x62; 16]);
    assert_eq!(ok.status.as_u16(), 200, "{}", text(&ok));
}

/// Issue 6 L10, ADR-008 (2026-11-19): after one passkey is flagged, the
/// holder can still register a new passkey from a session of another
/// passkey, and account recovery still revokes the suspect passkey with
/// the others (it stays in the account's live credentials).
#[test]
fn issue6_l10_adr008_new_passkey_registers_and_recovery_still_revokes_it() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let mut second = Pk::new();
    second.register(&c);
    let cookie = cookie_of(&second.login(&c));
    let _ = flag_admin_passkey(&c, &cred);
    let command_id = [0x63; 16];
    let (sid, su) = second.stepup(&c, &cookie, command_id);
    assert_eq!(su.status.as_u16(), 200, "{}", text(&su));
    let body = format!(
        "{{\"command_id\":\"{}\",\"stepup\":\"{}\"}}",
        hex(&command_id),
        hex(&sid)
    );
    let o = c.serve(post(
        "/auth/passkeys/options",
        Some(&cookie),
        body.as_bytes(),
    ));
    assert_eq!(o.status.as_u16(), 200, "{}", text(&o));
    let ch = challenge_id_of(&o);
    let nonce = c.backend().peek_challenge(ch).unwrap().nonce;
    let (att, client) = registration(nonce);
    let add = format!(
        "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{}\",\"client_data_json\":\"{}\",\"command_id\":\"{}\",\"stepup\":\"{}\"}}",
        hex(&att),
        hex(&ch),
        hex(&client),
        hex(&command_id),
        hex(&sid)
    );
    let r = c.serve(post("/auth/passkeys", Some(&cookie), add.as_bytes()));
    assert_eq!(r.status.as_u16(), 200, "{}", text(&r));
    let live = state(&c).auth().live_credentials(LOCAL_ADMIN);
    assert_eq!(
        live.len(),
        3,
        "the suspect passkey stays listed for recovery"
    );
    assert!(live.contains(&cred));
}

/// Issue 6 L10, ADR-008 (2026-11-19): `GET /auth/devices` shows a suspect
/// passkey as disabled and the others as not.
#[test]
fn issue6_l10_adr008_devices_show_a_suspect_passkey_as_disabled() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let mut second = Pk::new();
    second.register(&c);
    let cookie = cookie_of(&second.login(&c));
    let _ = flag_admin_passkey(&c, &cred);
    let r = c.serve(request(Method::GET, "/auth/devices", Some(&cookie), b""));
    assert_eq!(r.status.as_u16(), 200, "{}", text(&r));
    let v = fstp_json::parse(&r.body).unwrap();
    let list = v
        .get("devices")
        .and_then(fstp_json::Value::as_array)
        .unwrap();
    assert_eq!(list.len(), 2);
    for d in list.iter() {
        let id = d.get("id").and_then(fstp_json::Value::as_str).unwrap();
        let suspect = d.get("suspect").and_then(fstp_json::Value::as_bool);
        assert_eq!(suspect, Some(id == hex(&cred)), "{id}");
    }
}

// A minimal `none` registration with UV (WebAuthn Level 2 section 6.5).

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
    auth.push(0x01 | 0x04 | 0x40);
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
