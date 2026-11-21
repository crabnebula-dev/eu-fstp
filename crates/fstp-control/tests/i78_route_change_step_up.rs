//! I-77, I-78, ADR-008 "Step-up", ADR-009 "Pilot route feed" (lane L15,
//! decided by Daniel on 2026-11-21): a route change of the pilot
//! `fstp-control` is signed only after a staff member, logged in with a
//! pinned passkey, approves exactly that change with a fresh, single-use
//! step-up. Each approved change leaves an audit record whose assertion
//! verifies again under the pinned key.
//!
//! A software authenticator in this file signs with Ed25519 keys from
//! `fstp-crypto`. Times are passed in seconds. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fstp_control::ControlError;
use fstp_control::operator::{
    OperatorLogin, OperatorRefusal, OperatorSession, Purpose, StaffCredential,
};
use fstp_control::route_change::{
    AUDIT_FILE, AuditLog, CHANGE_LIFETIME_SECS, RouteChanges, decode_audit_log, verify_evidence,
};
use fstp_control::route_feed::{OperatorRequest, OperatorStatus};
use fstp_control::routes::{EdgeId, RoutePublisher, next_version, sign_table};
use fstp_cp_proto::StaffRef;
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_edge::{CellEndpoint, HostName, PinnedRoute, RouteEntry, verify_route_table};
use fstp_webauthn::{AssertionResponse, CoseKey, RelyingParty};

const HOST: &str = "control.example.test";
const T0: i64 = 1_800_000_000;

/// A software passkey of one staff member.
struct Passkey {
    staff: StaffRef,
    id: Vec<u8>,
    key: Ed25519SigningKey,
    count: u32,
}

impl Passkey {
    fn new(staff: u8) -> Passkey {
        Passkey {
            staff: StaffRef([staff; 16]),
            id: vec![staff; 16],
            key: Ed25519SigningKey::generate().unwrap(),
            count: 0,
        }
    }

    fn pinned(&self) -> StaffCredential {
        StaffCredential {
            staff: self.staff,
            credential_id: self.id.clone(),
            key: CoseKey::Ed25519 {
                x: self.key.public_key(),
            },
        }
    }

    /// An assertion over `challenge` with user verification when `uv`.
    fn assert_uv(&mut self, challenge: &[u8; 32], uv: bool) -> AssertionResponse {
        self.count += 1;
        let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        auth.push(if uv { 0x05 } else { 0x01 });
        auth.extend_from_slice(&self.count.to_be_bytes());
        let b64 = fstp_pgwire::base64::encode(challenge)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{b64}\",\"origin\":\"https://{HOST}\"}}"
        )
        .into_bytes();
        let mut message = auth.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client));
        AssertionResponse {
            credential_id: self.id.clone(),
            client_data_json: client,
            authenticator_data: auth,
            signature: self.key.sign(&message).unwrap().to_vec(),
        }
    }

    fn assert(&mut self, challenge: &[u8; 32]) -> AssertionResponse {
        self.assert_uv(challenge, true)
    }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn route(cell: u8, host: &str) -> PinnedRoute {
    let ep = |port| CellEndpoint {
        cell: [cell; 16],
        address: SocketAddr::from(([10, 0, 7, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    };
    PinnedRoute {
        route: RouteEntry {
            host: HostName::parse(host.as_bytes()).unwrap(),
            app: ep(8443),
            vault: ep(9443),
        },
        app_pin: [cell; 32],
        vault_pin: [cell ^ 0x80; 32],
    }
}

/// A pilot with a persisted table, an audit log and the staff of `keys`.
struct Pilot {
    dir: Scratch,
    changes: RouteChanges,
    feed_key: Vec<u8>,
}

fn pilot(keys: &[&Passkey]) -> Pilot {
    let tag: String = fstp_crypto::random_array::<4>()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let dir = Scratch(std::env::temp_dir().join(format!("fstp-l15-i78-{tag}")));
    std::fs::create_dir_all(&dir.0).unwrap();
    let state = dir.0.join("route-table.signed");
    let key = fstp_crypto::composite::generate().unwrap();
    let feed_key = key.public_key().to_bytes().to_vec();
    std::fs::write(
        &state,
        sign_table(&key, next_version(0).unwrap(), &[]).unwrap(),
    )
    .unwrap();
    let publisher = RoutePublisher::resume(
        key,
        &[EdgeId([1; 16])],
        &std::fs::read(&state).unwrap(),
        state,
    )
    .unwrap();
    let staff: Vec<StaffCredential> = keys.iter().map(|k| k.pinned()).collect();
    let login = OperatorLogin::new(HOST, &staff).unwrap();
    let audit = AuditLog::open(&dir.0.join(AUDIT_FILE)).unwrap();
    Pilot {
        changes: RouteChanges::new(Arc::new(publisher), login, audit),
        dir,
        feed_key,
    }
}

fn login(p: &Pilot, k: &mut Passkey, now: i64) -> OperatorSession {
    let c = p.changes.login().begin(Purpose::Login, now).unwrap();
    let a = k.assert(&c);
    p.changes.login().finish_login(c, &a, now).unwrap().0
}

fn refusal(r: Result<u64, ControlError>) -> OperatorRefusal {
    match r {
        Err(ControlError::Operator(o)) => o,
        other => panic!("not an operator refusal: {other:?}"),
    }
}

/// I-78 (ADR-009 "Pilot route feed", rows "Proposal and approval" and
/// "Step-up per change"): a proposed change is not signed. An approval
/// with no step-up challenge, with an assertion over a login challenge or
/// a challenge never drawn, without user verification, or after the
/// session's own step-up was consumed elsewhere, is refused. The version
/// and the served table stay as they were, and the change still waits.
#[test]
fn i78_route_change_without_step_up_is_refused() {
    let mut k = Passkey::new(1);
    let p = pilot(&[&k]);
    let session = login(&p, &mut k, T0);
    let before = p.changes.publisher().version();
    let signed = p.changes.publisher().signed_table();
    let (id, rx) = p
        .changes
        .propose(OperatorRequest::Add(Box::new(route(1, "a.example"))), T0)
        .unwrap();
    assert_eq!(
        p.changes.publisher().version(),
        before,
        "a proposal was signed"
    );
    // An assertion over a login challenge, not one bound to the change.
    let c = p.changes.login().begin(Purpose::Login, T0).unwrap();
    let a = k.assert(&c);
    assert_eq!(
        refusal(p.changes.approve(session, id, c, &a, T0)),
        OperatorRefusal::Challenge
    );
    // A challenge never drawn.
    let a = k.assert(&[9; 32]);
    assert_eq!(
        refusal(p.changes.approve(session, id, [9; 32], &a, T0)),
        OperatorRefusal::Challenge
    );
    // The bound challenge without user verification.
    let c = p.changes.begin_approval(session, id, T0).unwrap();
    let a = k.assert_uv(&c, false);
    assert_eq!(
        refusal(p.changes.approve(session, id, c, &a, T0)),
        OperatorRefusal::Assertion
    );
    // No step-up at all: the login alone authorises no change.
    assert_eq!(
        p.changes.login().authorise_route_change(session, T0).err(),
        Some(ControlError::Operator(OperatorRefusal::StepUpRequired))
    );
    assert_eq!(p.changes.publisher().version(), before);
    assert_eq!(p.changes.publisher().signed_table(), signed);
    assert_eq!(p.changes.pending(T0).len(), 1, "the change stopped waiting");
    assert!(rx.try_recv().is_err(), "the proposer got an answer");
    // A proposal no staff member approves expires.
    assert!(p.changes.pending(T0 + CHANGE_LIFETIME_SECS + 1).is_empty());
    assert_eq!(rx.recv().unwrap().status, OperatorStatus::Expired);
    let (records, _) =
        decode_audit_log(&std::fs::read(p.dir.0.join(AUDIT_FILE)).unwrap_or_default()).unwrap();
    assert!(records.is_empty(), "a refused change was audited");
}

/// I-78 (ADR-008 "Step-up": one step-up authorises exactly one command):
/// a step-up that approved one change is refused for a second change,
/// replayed as it was, or replayed for the same change again.
#[test]
fn i78_reused_step_up_is_refused() {
    let mut k = Passkey::new(1);
    let p = pilot(&[&k]);
    let session = login(&p, &mut k, T0);
    let (first, _rx1) = p
        .changes
        .propose(OperatorRequest::Add(Box::new(route(1, "a.example"))), T0)
        .unwrap();
    let (second, _rx2) = p
        .changes
        .propose(OperatorRequest::Add(Box::new(route(2, "b.example"))), T0)
        .unwrap();
    let c = p.changes.begin_approval(session, first, T0).unwrap();
    let a = k.assert(&c);
    let v = p.changes.approve(session, first, c, &a, T0 + 1).unwrap();
    for id in [second, first] {
        assert_eq!(
            refusal(p.changes.approve(session, id, c, &a, T0 + 2)),
            OperatorRefusal::Challenge,
            "a used step-up approved again"
        );
    }
    assert_eq!(p.changes.publisher().version(), v);
    assert_eq!(p.changes.publisher().routes(), vec![route(1, "a.example")]);
    assert_eq!(p.changes.pending(T0 + 2).len(), 1);
}

/// I-78, ADR-009 "Pilot route feed", row "Step-up per change": a
/// challenge is bound to one change and one session. It cannot approve
/// another change, it cannot be answered in another staff member's
/// session, and another staff member's passkey cannot answer it.
#[test]
fn i78_step_up_of_another_change_is_refused() {
    let mut k = Passkey::new(1);
    let mut other = Passkey::new(2);
    let p = pilot(&[&k, &other]);
    let mine = login(&p, &mut k, T0);
    let theirs = login(&p, &mut other, T0);
    let (a_id, _ra) = p
        .changes
        .propose(OperatorRequest::Add(Box::new(route(1, "a.example"))), T0)
        .unwrap();
    let (b_id, _rb) = p
        .changes
        .propose(OperatorRequest::Remove([7; 16]), T0)
        .unwrap();
    let c = p.changes.begin_approval(mine, a_id, T0).unwrap();
    let a = k.assert(&c);
    assert_eq!(
        refusal(p.changes.approve(mine, b_id, c, &a, T0)),
        OperatorRefusal::Challenge
    );
    let c = p.changes.begin_approval(mine, a_id, T0).unwrap();
    let a = k.assert(&c);
    assert_eq!(
        refusal(p.changes.approve(theirs, a_id, c, &a, T0)),
        OperatorRefusal::Challenge
    );
    let c = p.changes.begin_approval(mine, a_id, T0).unwrap();
    let a = other.assert(&c);
    assert_eq!(
        refusal(p.changes.approve(mine, a_id, c, &a, T0)),
        OperatorRefusal::OtherStaff
    );
    assert!(p.changes.publisher().routes().is_empty());
}

/// I-78, R-SW-02 (ADR-009 "Pilot route feed", rows "Proposal and
/// approval" and "Audit"): a valid step-up of the logged-in staff member
/// signs a new table with the change. It is stored, it verifies under
/// the feed key, and the proposer gets the version. A removal approved
/// the same way takes the route away again.
#[test]
fn i78_valid_step_up_signs_a_new_table() {
    let mut k = Passkey::new(1);
    let p = pilot(&[&k]);
    let session = login(&p, &mut k, T0);
    let before = p.changes.publisher().version();
    let (id, rx) = p
        .changes
        .propose(OperatorRequest::Add(Box::new(route(1, "a.example"))), T0)
        .unwrap();
    let c = p.changes.begin_approval(session, id, T0).unwrap();
    let a = k.assert(&c);
    let v = p.changes.approve(session, id, c, &a, T0 + 5).unwrap();
    assert!(v > before);
    let reply = rx.recv().unwrap();
    assert_eq!(reply.status, OperatorStatus::Stored);
    assert_eq!(reply.version, v);
    let stored = std::fs::read(p.dir.0.join("route-table.signed")).unwrap();
    let served = verify_route_table(std::slice::from_ref(&p.feed_key), &stored).unwrap();
    assert_eq!(served.version, v);
    assert_eq!(served.routes, vec![route(1, "a.example")]);
    let (rid, rrx) = p
        .changes
        .propose(OperatorRequest::Remove([1; 16]), T0 + 6)
        .unwrap();
    let c = p.changes.begin_approval(session, rid, T0 + 6).unwrap();
    let a = k.assert(&c);
    let v2 = p.changes.approve(session, rid, c, &a, T0 + 7).unwrap();
    assert!(v2 > v);
    assert_eq!(rrx.recv().unwrap().version, v2);
    assert!(p.changes.publisher().routes().is_empty());
    // A proposal an edge would refuse never waits for a step-up.
    let mut clash = route(2, "b.example");
    clash.route.vault.address = clash.route.app.address;
    assert!(matches!(
        p.changes
            .propose(OperatorRequest::Add(Box::new(clash)), T0 + 8),
        Err(ControlError::Request(_))
    ));
}

/// I-77, ADR-008 "Control plane": the operator login takes only a pinned
/// passkey with user verification for the operator host. A credential
/// that is not pinned, an assertion without user verification, and an
/// assertion for another origin open no session, and with no session no
/// step-up can be drawn.
#[test]
fn i77_login_needs_a_pinned_passkey_with_user_verification() {
    let mut k = Passkey::new(1);
    let mut stranger = Passkey::new(9);
    let p = pilot(&[&k]);
    let (id, _rx) = p
        .changes
        .propose(OperatorRequest::Remove([3; 16]), T0)
        .unwrap();
    for case in 0..3 {
        let c = p.changes.login().begin(Purpose::Login, T0).unwrap();
        let a = match case {
            0 => stranger.assert(&c),
            1 => k.assert_uv(&c, false),
            _ => {
                let mut a = k.assert(&c);
                a.client_data_json = String::from_utf8(a.client_data_json)
                    .unwrap()
                    .replace(HOST, "evil.example.test")
                    .into_bytes();
                a
            }
        };
        assert!(
            p.changes.login().finish_login(c, &a, T0).is_err(),
            "case {case} opened a session"
        );
    }
    assert!(
        p.changes
            .begin_approval(OperatorSession([0; 32]), id, T0)
            .is_err()
    );
}

/// ADR-009 "Pilot route feed", row "Audit": each approved change appends
/// one record before its table is stored, in a hash chain. Each record
/// names the staff member, the operation, the cell and the version, and
/// its assertion verifies again under the pinned key over the challenge
/// its digest gives. A changed byte breaks the chain, and a log with a
/// broken chain does not open.
#[test]
fn adr009_l15_audit_chain_carries_verifiable_evidence() {
    let mut k = Passkey::new(1);
    let p = pilot(&[&k]);
    let session = login(&p, &mut k, T0);
    let mut versions = Vec::new();
    for (i, req) in [
        OperatorRequest::Add(Box::new(route(1, "a.example"))),
        OperatorRequest::Add(Box::new(route(2, "b.example"))),
        OperatorRequest::Remove([1; 16]),
    ]
    .into_iter()
    .enumerate()
    {
        let now = T0 + i64::try_from(i).unwrap();
        let (id, _rx) = p.changes.propose(req, now).unwrap();
        let c = p.changes.begin_approval(session, id, now).unwrap();
        let a = k.assert(&c);
        versions.push(p.changes.approve(session, id, c, &a, now).unwrap());
    }
    let path = p.dir.0.join(AUDIT_FILE);
    let bytes = std::fs::read(&path).unwrap();
    let (records, _) = decode_audit_log(&bytes).unwrap();
    assert_eq!(records.len(), 3);
    let rp = RelyingParty::new(HOST).unwrap();
    let staff = [k.pinned()];
    for (r, (v, (op, cell))) in
        records.iter().zip(
            versions
                .iter()
                .zip([(1, [1; 16]), (1, [2; 16]), (2, [1; 16])]),
        )
    {
        assert_eq!(r.version, *v);
        assert_eq!((r.op, r.cell), (op, cell));
        assert_eq!(r.staff, k.staff);
        assert!(verify_evidence(r, &staff, &rp), "evidence does not verify");
        let mut forged = r.clone();
        forged.cell = [0xee; 16];
        forged.digest[0] ^= 1;
        assert!(!verify_evidence(&forged, &staff, &rp));
    }
    let mut changed = bytes.clone();
    changed[20] ^= 1;
    assert!(decode_audit_log(&changed).is_err());
    std::fs::write(&path, &changed).unwrap();
    assert!(AuditLog::open(&path).is_err());
    for cut in [1, 10, bytes.len() - 1] {
        assert!(decode_audit_log(&bytes[..cut]).is_err(), "cut {cut}");
    }
}

// ---- the operator page over HTTP (ADR-009 "Pilot route feed", row "Operator page")

use fstp_control::route_page::{
    COOKIE, OperatorPage, cose_key_bytes, decode_assertion_body, session_from_cookie,
};
use fstp_http::{Request, Response};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn post(path: &str, body: &str, cookie: Option<&str>) -> Request {
    let mut r = Request::post(&format!("https://{HOST}{path}"), body.as_bytes().to_vec())
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("x-fstp-request", "1")
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    if let Some(c) = cookie {
        r = r.try_with_header("cookie", c).unwrap();
    }
    r
}

fn body(r: &Response) -> fstp_json::Value {
    fstp_json::parse(&r.body).unwrap()
}

fn challenge_of(r: &Response) -> [u8; 32] {
    let v = body(r);
    unhex(v.get("challenge_id").unwrap().as_str().unwrap())
        .try_into()
        .unwrap()
}

fn assertion_json(c: &[u8; 32], a: &AssertionResponse) -> String {
    format!(
        r#"{{"authenticator_data":"{}","challenge_id":"{}","client_data_json":"{}","credential_id":"{}","signature":"{}"}}"#,
        hex(&a.authenticator_data),
        hex(c),
        hex(&a.client_data_json),
        hex(&a.credential_id),
        hex(&a.signature)
    )
}

/// I-77, I-78, ADR-009 "Pilot route feed", row "Operator page": over the
/// page's HTTP routes, a POST without the CSRF header or with another
/// origin is refused. The state needs a session. A passkey login sets a
/// `__Host-` cookie that is `Secure`, `HttpOnly` and `SameSite=Strict`.
/// A change is approved only with a step-up drawn for it, once, and the
/// approval signs the new table. The page itself runs no inline script.
#[test]
fn i78_operator_page_approves_a_change_only_with_its_step_up() {
    let mut k = Passkey::new(1);
    let p = pilot(&[&k]);
    let changes = Arc::new(p.changes);
    let page = OperatorPage::new(Arc::clone(&changes), HOST, p.dir.0.clone());
    let html = page.answer(&Request::get(&format!("https://{HOST}/")).unwrap(), T0);
    assert_eq!(html.status.as_u16(), 200);
    let csp = html
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe"));
    // CSRF: the header and the origin are both required.
    let mut no_header = post("/api/login/options", "{}", None);
    no_header.headers.remove("x-fstp-request");
    let mut other_origin = post("/api/login/options", "{}", None);
    other_origin.headers.remove("origin");
    other_origin = other_origin
        .try_with_header("origin", "https://evil.example.test")
        .unwrap();
    for r in [no_header, other_origin] {
        assert_eq!(page.answer(&r, T0).status.as_u16(), 403);
    }
    // No session, no state.
    let state = Request::get(&format!("https://{HOST}/api/state")).unwrap();
    assert_eq!(page.answer(&state, T0).status.as_u16(), 401);
    // Login.
    let opts = page.answer(&post("/api/login/options", "{}", None), T0);
    assert_eq!(opts.status.as_u16(), 200);
    let c = challenge_of(&opts);
    let a = k.assert(&c);
    let logged = page.answer(&post("/api/login", &assertion_json(&c, &a), None), T0);
    assert_eq!(logged.status.as_u16(), 200);
    let set = logged
        .headers
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    for attr in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(set.contains(attr), "{attr}");
    }
    let cookie = set.split(';').next().unwrap().to_owned();
    assert!(cookie.starts_with(&format!("{COOKIE}=")));
    // A proposal shows as waiting.
    let (id, rx) = changes
        .propose(OperatorRequest::Add(Box::new(route(1, "a.example"))), T0)
        .unwrap();
    let state = state.try_with_header("cookie", cookie.clone()).unwrap();
    let shown = body(&page.answer(&state, T0));
    let pending = shown.get("pending").unwrap().as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending
            .iter()
            .next()
            .and_then(|c| c.get("id"))
            .and_then(|v| v.as_str()),
        Some(hex(&id).as_str())
    );
    // An approval with the login challenge's assertion is refused.
    let approve = format!("/api/changes/{}/approve", hex(&id));
    let replay = page.answer(&post(&approve, &assertion_json(&c, &a), Some(&cookie)), T0);
    assert_eq!(replay.status.as_u16(), 403);
    // The step-up drawn for the change approves it, once.
    let opts = page.answer(
        &post(
            &format!("/api/changes/{}/options", hex(&id)),
            "{}",
            Some(&cookie),
        ),
        T0,
    );
    let c = challenge_of(&opts);
    let a = k.assert(&c);
    let done = page.answer(&post(&approve, &assertion_json(&c, &a), Some(&cookie)), T0);
    assert_eq!(done.status.as_u16(), 200);
    let v = body(&done).get("version").unwrap().as_u64().unwrap();
    assert_eq!(rx.recv().unwrap().version, v);
    let again = page.answer(&post(&approve, &assertion_json(&c, &a), Some(&cookie)), T0);
    assert_eq!(again.status.as_u16(), 403);
    assert_eq!(changes.publisher().routes(), vec![route(1, "a.example")]);
    // Assets: only compiled scripts of two directories.
    for path in [
        "/assets/routefeed/main.js",
        "/assets/../state",
        "/assets/auth/x.css",
    ] {
        let r = page.answer(&Request::get(&format!("https://{HOST}{path}")).unwrap(), T0);
        assert_eq!(r.status.as_u16(), 404, "{path}");
    }
}

/// TH-26, R-NF-02 (ADR-009 "Pilot route feed", row "Operator page"): the
/// body and cookie decoders take one form only, and the staff entry the
/// enrolment answers is a COSE key that `fstp-webauthn` reads back.
#[test]
fn th_26_operator_page_decoders_take_one_form() {
    let mut k = Passkey::new(1);
    let a = k.assert(&[3; 32]);
    let good = assertion_json(&[3; 32], &a);
    assert_eq!(decode_assertion_body(good.as_bytes()).unwrap().assertion, a);
    for bad in [
        good.replace("\"signature\"", "\"sig\""),
        good.replace(&hex(&[3; 32]), &hex(&[3; 31])),
        good.replacen(":\"", ":\"A", 1),
        format!("{},\"x\":1}}", &good[..good.len() - 1]),
        "[]".to_owned(),
        String::new(),
    ] {
        assert!(decode_assertion_body(bad.as_bytes()).is_err(), "{bad}");
    }
    let token = hex(&[0xab; 32]);
    assert_eq!(
        session_from_cookie(format!("a=b; {COOKIE}={token}").as_bytes()).map(|s| s.0),
        Some([0xab; 32])
    );
    for bad in [
        format!("{COOKIE}={token}; {COOKIE}={token}"),
        format!("{COOKIE}={}", token.to_uppercase()),
        format!("{COOKIE}={}", &token[2..]),
        format!("x{COOKIE}={token}"),
    ] {
        assert!(session_from_cookie(bad.as_bytes()).is_none(), "{bad}");
    }
    let ed = CoseKey::Ed25519 {
        x: k.key.public_key(),
    };
    let spki = fstp_crypto::sig::EcdsaP256KeyPair::generate()
        .unwrap()
        .spki_der()
        .unwrap();
    let point = &spki[spki.len() - 64..];
    let es = CoseKey::Es256 {
        x: point[..32].try_into().unwrap(),
        y: point[32..].try_into().unwrap(),
    };
    for key in [ed, es] {
        let bytes = cose_key_bytes(&key).unwrap();
        assert_eq!(fstp_webauthn::parse_cose_key(&bytes), Ok(key));
    }
}
