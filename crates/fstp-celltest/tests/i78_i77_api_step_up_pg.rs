//! I-78 and I-77 on the production cell's `ApiCore` over PostgreSQL
//! (ADR-026, production design section 3.3, lane L7; TH-55, TH-56).
//!
//! Every request goes through the cell's own HTTP listener, as a browser
//! sends it. The step-up of a web call is the cell's own ceremony: the
//! API core asks with a challenge bound to the request digest, and the
//! software authenticator proves it at `POST /auth/stepup`. The commit
//! checks run on the cell's engine over PostgreSQL. Every account and text
//! is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::engine::EngineError;
use fstp_cell_core::driver::ExecError;
use fstp_cell_core::gate::{self, Action, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellRefusal};
use fstp_celltest::cycle::Cycle;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::id::AccountId;
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_json::Value;

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "l7-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

/// The model accounts of the applicant and the reviewer (I-77).
const APPLICANT: AccountId = AccountId::from_raw(71_001);
const REVIEWER: AccountId = AccountId::from_raw(71_002);
const SECOND: AccountId = AccountId::from_raw(71_003);

fn world() -> World {
    World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

fn json(r: &HttpReply) -> Value {
    fstp_json::parse(&r.body).unwrap_or(Value::Null)
}

fn text(r: &HttpReply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn code(r: &HttpReply) -> Option<String> {
    json(r)
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A web API call in the session `cookie`, as `web/src/core/api.ts`
/// sends it.
fn web(cell: &CellHandle, method: &str, path: &str, cookie: &Cookie, body: &str) -> HttpReply {
    let mut r = HttpRequest::new(method, path)
        .header("cookie", cookie.0.clone())
        .header("accept", "application/json");
    if method != "GET" {
        r = r
            .header("origin", format!("https://{}", cell.host()))
            .header("x-fstp-request", "1")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec());
    }
    send(cell, r)
}

/// The challenge of a `step_up_required` reply: its id (lowercase hex)
/// and bytes.
fn challenge_of(r: &HttpReply) -> Option<(String, [u8; 32])> {
    let v = json(r);
    if v.get("code").and_then(Value::as_str) != Some("step_up_required") {
        return None;
    }
    let ch = v.get("challenge")?;
    let id = ch.get("challenge_id").and_then(Value::as_str)?.to_owned();
    let bytes = ch
        .get("public_key")
        .and_then(|p| p.get("challenge"))
        .and_then(Value::as_str)?;
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .ok()?
        .as_bytes()
        .try_into()
        .ok()?;
    Some((id, challenge))
}

fn unhex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Registers the agent client of the consents.
fn register(cell: &CellHandle) -> String {
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/register")
            .header("content-type", "application/json")
            .body(
                format!(r#"{{"client_name":"Synthetic agent","redirect_uris":["{REDIRECT}"]}}"#)
                    .into_bytes(),
            ),
    );
    assert_eq!(r.status, 201, "registration: {}", text(&r));
    json(&r)
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// One authorize request of `client`: the handle of its consent.
fn authorize(cell: &CellHandle, client: &str) -> String {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let resource = format!("https://{}/mcp", cell.host());
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read"),
        ("state", "synthetic-state"),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("GET", &format!("/oauth/authorize?{q}")),
    );
    assert_eq!(r.status, 303, "authorize: {}", text(&r));
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    to.strip_prefix("/app/connect#").unwrap().to_owned()
}

fn consent_body(handle: &str) -> String {
    format!(r#"{{"consent":"{handle}"}}"#)
}

/// A world with the programme P of the cycle and two enrolled accounts
/// with seeded verifications: the client, the first admin's session and
/// the two accounts' cell ids.
fn programme_world(world: &World) -> (AuthClient<'_>, Cookie, [AccountId; 2]) {
    let cell = world.cell(0).unwrap();
    let mut cycle = Cycle::new(cell);
    for step in ["login", "create-programme"] {
        cycle
            .step(step)
            .unwrap_or_else(|e| panic!("the cycle step {step}: {e}"));
    }
    let client = cycle.into_client();
    let mut ids = [AccountId::from_raw(0); 2];
    for (i, m) in [APPLICANT, REVIEWER].into_iter().enumerate() {
        assert!(client.enrol(m).unwrap(), "the enrolment of {}", m.raw());
        let id = client.cell_account(m).unwrap();
        cell.seed_verification(id, format!("l7-stepup-person-{}", m.raw()).as_bytes())
            .unwrap_or_else(|e| panic!("the verification: {e}"));
        ids[i] = id;
    }
    let admin = client
        .login(FIRST_ADMIN, RefMethod::Passkey)
        .unwrap()
        .expect("the admin session");
    (client, admin, ids)
}

/// The body of `roles.grant` of the Auditor role to `account`.
fn grant_body(cell: &CellHandle, account: AccountId) -> String {
    format!(
        r#"{{"account":"{}","role":"Auditor","start":"{}"}}"#,
        account.raw(),
        cell.clock().now()
    )
}

/// The active bindings of `account` on P.
fn bindings(cell: &CellHandle, account: AccountId) -> usize {
    cell.cell_engine()
        .unwrap()
        .state()
        .engine()
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == account)
        .count()
}

/// I-78, TH-56, ADR-026, production design section 3.3: a step-up of the
/// API core is bound to the digest of the request it was asked for, and
/// it serves that request once.
///
/// The first admin grants the Auditor role of P to one account
/// (`roles.grant`, a management role change). The request asks a step-up,
/// which the admin proves. The same proof does not serve the grant to a
/// second account: that request asks a step-up of its own, and nothing
/// consumed the first one. The first request is then served, its batch
/// records the step-up as consumed, and the account holds one binding.
/// The same request again is never served a second time: it appends no
/// binding.
#[test]
fn i78_api_step_up_is_digest_bound_and_single_use_on_pg() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let (client, admin, [a, b]) = programme_world(&world);
    let path = format!(
        "/api/v1/programmes/{}/roles",
        fstp_domain_testkit::r#gen::roster::P1.raw()
    );
    let (body_a, body_b) = (grant_body(cell, a), grant_body(cell, b));
    // The step-up asked for the grant to a, proved.
    let asked = web(cell, "POST", &path, &admin, &body_a);
    let (id, ch) =
        challenge_of(&asked).unwrap_or_else(|| panic!("I-78: no step-up asked: {}", text(&asked)));
    assert!(
        client.prove_api_step_up(&admin, &id, ch).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    let stepup = unhex16(&id);
    let state = || cell.cell_engine().unwrap().state();
    assert!(
        state().auth().stepup_grant(stepup).is_some(),
        "I-78: the ledger holds no grant of the proved step-up"
    );
    // Digest bound: the proof of the grant to a does not serve b's.
    let other = web(cell, "POST", &path, &admin, &body_b);
    assert_eq!(
        code(&other).as_deref(),
        Some("step_up_required"),
        "I-78: a step-up served another request: {} {}",
        other.status,
        text(&other)
    );
    assert_eq!(
        bindings(cell, b),
        0,
        "I-78: b was granted without a step-up"
    );
    assert!(
        !state().auth().consumed(stepup),
        "I-78: another request consumed the step-up"
    );
    // Its own request is served, once.
    let done = web(cell, "POST", &path, &admin, &body_a);
    assert_eq!(done.status, 200, "I-78: the grant: {}", text(&done));
    assert_eq!(bindings(cell, a), 1, "I-78: the grant to a");
    assert!(
        state().auth().consumed(stepup),
        "I-78: the served request did not consume its step-up"
    );
    let again = web(cell, "POST", &path, &admin, &body_a);
    assert_ne!(again.status, 200, "I-78: {}", text(&again));
    assert_eq!(
        bindings(cell, a),
        1,
        "I-78: a consumed step-up served its request again"
    );
}

/// I-78, ADR-013 "Consent page", ADR-026 record of lane L12: the passkey
/// step-up of `agents.consent` is single use, as every other step-up
/// action is (decided by Daniel on 2026-11-21, production design section
/// 2.4, decision 5).
///
/// The first admin approves an agent's consent on the production cell
/// over PostgreSQL. The approval asks a step-up, which the software
/// authenticator proves at the cell's `POST /auth/stepup`. Before the
/// approval is served, the ledger holds the grant and no use of it. The
/// served approval records the step-up as used in the ledger, and the
/// redirect carries a code. The same request again is not served by the
/// spent step-up: the API core asks for a new one.
#[test]
fn i78_consent_step_up_is_single_use_on_pg() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap());
    let admin = client.admin_session().expect("the admin session");
    let agent = register(cell);
    let handle = authorize(cell, &agent);
    let body = consent_body(&handle);
    let asked = web(cell, "POST", "/api/v1/oauth/consent", &admin, &body);
    let (id, ch) =
        challenge_of(&asked).unwrap_or_else(|| panic!("I-78: no step-up asked: {}", text(&asked)));
    assert!(
        client.prove_api_step_up(&admin, &id, ch).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    let stepup = unhex16(&id);
    let state = || cell.cell_engine().unwrap().state();
    assert!(state().auth().stepup_grant(stepup).is_some());
    assert!(
        !state().auth().consumed(stepup),
        "I-78: the step-up was used before the approval"
    );
    let done = web(cell, "POST", "/api/v1/oauth/consent", &admin, &body);
    assert_eq!(done.status, 200, "I-78: the consent: {}", text(&done));
    assert!(
        text(&done).contains("code="),
        "the consent redirect carries no code: {}",
        text(&done)
    );
    assert!(
        state().auth().consumed(stepup),
        "I-78: the served consent did not record its step-up as used"
    );
    let again = web(cell, "POST", "/api/v1/oauth/consent", &admin, &body);
    assert_eq!(
        code(&again).as_deref(),
        Some("step_up_required"),
        "I-78: a spent consent step-up served a request again: {} {}",
        again.status,
        text(&again)
    );
}

/// The step-up view the gate reads of the ledger's grant `id`, as the
/// production cell's engine port builds it (`fstp_cell::api::engine`).
fn view_of(cell: &CellHandle, id: [u8; 16]) -> StepUpView {
    let s = cell.cell_engine().unwrap().state();
    let grant = s.auth().stepup_grant(id).expect("the step-up grant");
    StepUpView {
        id,
        session: grant.session,
        action_digest: grant.action_digest,
        asserted_at: grant.granted_at,
        strong: true,
        consumed: s.auth().consumed(id),
    }
}

/// I-78, TH-56, ADR-026: the production cell's engine checks a step-up
/// again when the batch commits, over PostgreSQL. A command the API
/// step-up admission admitted with a fresh step-up is refused under I-78
/// once P-71 has passed by the commit instant, and appends nothing. One
/// step-up admits two commands while it is unused, but only the first
/// commits: the second is refused as a replay, and appends nothing.
///
/// The step-up is a real one: the API core asked it for a request of the
/// first admin, and the software authenticator proved it at the cell's
/// `POST /auth/stepup`. The admissions are the gate's own
/// (`gate::admit_api_command`), with that request's digest.
#[test]
fn i78_stale_api_step_up_refused_at_commit() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    assert!(client.enrol(FIRST_ADMIN).unwrap());
    for m in [APPLICANT, REVIEWER, SECOND] {
        assert!(client.enrol(m).unwrap());
    }
    let admin = client.admin_session().expect("the admin session");
    // A request that asks a step-up: the approval of an agent's consent.
    let agent = register(cell);
    let handle = authorize(cell, &agent);
    let body = consent_body(&handle);
    let asked = web(cell, "POST", "/api/v1/oauth/consent", &admin, &body);
    let (id, ch) = challenge_of(&asked).expect("I-78: no step-up asked");
    assert!(client.prove_api_step_up(&admin, &id, ch).unwrap());
    let id = unhex16(&id);
    let su = view_of(cell, id);
    let engine = cell.cell_engine().unwrap();
    let admin_id = client.cell_account(FIRST_ADMIN).unwrap();
    let session = fstp_auth::SessionView {
        id: su.session,
        account: admin_id,
        method: fstp_auth::Method::Passkey,
        started: su.asserted_at,
        last_used: su.asserted_at,
    };
    let policy = LoginPolicy {
        stepup_freshness_us: fstp_cell_core::tenant::P71_DEFAULT_US,
    };
    let admit = |m: AccountId, su: &StepUpView| {
        let now = Timestamp::from_micros(cell.clock().now());
        let command = CellCommand::Tenant(TenantCommand::GrantTenantAdmin {
            account: client.cell_account(m).unwrap(),
        });
        let command_id: [u8; 16] = fstp_crypto::random_array().unwrap();
        gate::admit_api_command(
            &engine.state(),
            &session,
            Action::Command(command),
            command_id,
            su.action_digest,
            Some(su),
            now,
            &policy,
        )
        .unwrap_or_else(|d| panic!("I-78: the fresh step-up was not admitted: {d:?}"))
    };
    let refused_i78 = |r: Result<_, EngineError>| match r {
        Err(EngineError::Exec(ExecError::Refused(CellRefusal::Domain(d)))) => {
            assert_eq!(d.rule, RuleRef::I78, "{d:?}");
        }
        other => panic!("I-78: expected a refusal at commit, got {other:?}"),
    };
    let admins = || engine.state().tenant().admins().len();
    // Stale at commit: admitted fresh, committed one microsecond past P-71.
    let stale = admit(APPLICANT, &su);
    let before = (admins(), engine.state().head());
    let p71 = fstp_cell_core::tenant::P71_DEFAULT_US;
    cell.clock().set(su.asserted_at.micros() + p71 + 1);
    refused_i78(cell.block_on(engine.execute(stale)).unwrap());
    assert_eq!(
        (admins(), engine.state().head()),
        before,
        "I-78: a stale step-up appended"
    );
    // Single use at commit: two admissions of one unused step-up, at P-71.
    cell.clock().set(su.asserted_at.micros() + p71);
    let (first, second) = (admit(REVIEWER, &su), admit(SECOND, &su));
    let before = admins();
    cell.block_on(engine.execute(first))
        .unwrap()
        .unwrap_or_else(|e| panic!("I-78: the step-up at exactly P-71 was refused: {e:?}"));
    assert_eq!(admins(), before + 1, "I-78: the first command");
    assert!(engine.state().auth().consumed(id), "I-78: not consumed");
    let head = engine.state().head();
    // The batch of the second consumes the step-up again: the cell's fold
    // refuses it (M3 design section 5.1, "replay checks single use by
    // structure"), or the store's step-up rule does.
    match cell.block_on(engine.execute(second)).unwrap() {
        Err(EngineError::Exec(ExecError::Unfoldable(_))) => {}
        r => refused_i78(r),
    }
    assert_eq!(
        (admins(), engine.state().head()),
        (before + 1, head),
        "I-78: a consumed step-up appended a second command"
    );
}

/// A web call of the first admin, with the step-up it asks proved.
fn stepped(client: &AuthClient<'_>, admin: &Cookie, path: &str, body: &str) -> HttpReply {
    let cell = client.cell();
    let r = web(cell, "POST", path, admin, body);
    let Some((id, ch)) = challenge_of(&r) else {
        return r;
    };
    assert!(client.prove_api_step_up(admin, &id, ch).unwrap());
    web(cell, "POST", path, admin, body)
}

/// I-77, TH-55, ADR-008, production design section 3.3: a magic-link
/// session is refused for management operations on the production cell.
///
/// The world's tenant enables magic links (P-70), as the auth machines'
/// universe does, since a production cell offers none by default.
///
/// - An applicant with no management role logs in by magic link. That
///   session is refused a management operation (`roles.grant`, a
///   management role change) before any step-up: it is not
///   phishing-resistant, and no challenge is issued to it.
/// - An account in that position is then granted the Auditor role, an
///   Operations role. The grant ends its magic-link session, so the
///   session is refused afterwards, and a new magic-link login of the
///   account is refused.
/// - A management account, the second tenant admin, never gets a
///   magic-link session, though its invitation named a login email.
#[test]
fn i77_magic_link_session_refused_for_management_ops_on_pg() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let (client, admin, [applicant, reviewer]) = programme_world(&world);
    let path = format!(
        "/api/v1/programmes/{}/roles",
        fstp_domain_testkit::r#gen::roster::P1.raw()
    );
    // A magic-link session of the applicant.
    let weak = client
        .login(APPLICANT, RefMethod::MagicLink)
        .unwrap()
        .expect("I-77: the applicant's magic-link login");
    let mine = web(cell, "GET", "/api/v1/me/roles", &weak, "");
    assert_eq!(
        mine.status,
        200,
        "the applicant's own read: {}",
        text(&mine)
    );
    // A management operation in it is refused, with no challenge.
    let before = bindings(cell, reviewer);
    let r = web(cell, "POST", &path, &weak, &grant_body(cell, reviewer));
    assert!(
        matches!(
            code(&r).as_deref(),
            Some("strong_method_required" | "login_strength")
        ) || json(&r).get("rule").and_then(Value::as_str) == Some("I-77"),
        "I-77: a magic-link session reached a management operation: {} {}",
        r.status,
        text(&r)
    );
    assert!(
        challenge_of(&r).is_none(),
        "I-77: a weak session got a step-up challenge"
    );
    assert_eq!(bindings(cell, reviewer), before, "I-77: the grant appended");
    // The reviewer logs in by magic link, then becomes an Auditor.
    let reviewer_weak = client
        .login(REVIEWER, RefMethod::MagicLink)
        .unwrap()
        .expect("the reviewer's magic-link login before any role");
    let ok = web(cell, "GET", "/api/v1/me/roles", &reviewer_weak, "");
    assert_eq!(ok.status, 200, "{}", text(&ok));
    let granted = stepped(&client, &admin, &path, &grant_body(cell, reviewer));
    assert_eq!(granted.status, 200, "the Auditor grant: {}", text(&granted));
    assert_eq!(bindings(cell, reviewer), before + 1);
    let after = web(cell, "GET", "/api/v1/me/roles", &reviewer_weak, "");
    assert_eq!(
        after.status,
        401,
        "I-77: the magic-link session outlived the management grant: {}",
        text(&after)
    );
    assert!(
        client
            .login(REVIEWER, RefMethod::MagicLink)
            .unwrap()
            .is_none(),
        "I-77: an Auditor logged in by magic link"
    );
    assert!(
        client
            .login(
                fstp_domain_testkit::r#gen::roster::ADMIN_2,
                RefMethod::MagicLink
            )
            .unwrap()
            .is_none(),
        "I-77: a tenant admin logged in by magic link"
    );
    // The applicant's passkey session is unaffected.
    assert!(bindings(cell, applicant) == 0);
    assert!(
        client
            .login(APPLICANT, RefMethod::Passkey)
            .unwrap()
            .is_some()
    );
}
