//! Lane m4/ops-roles-agents (Daniel, 2026-11-15): the operations the
//! authorisation matrices found unbuilt or unreachable, each through
//! `ApiCore::dispatch` on a matrix world.
//!
//! - `agents.list` reads the caller's live agent clients from the token
//!   port, and `agents.activity` the caller's calls through one of them
//!   (R-MC-03, `mcp-server.md`, ADR-013).
//! - `roles.list` lists a programme's staff bindings for a tenant admin,
//!   and `roles.reinstate` lifts a suspension that is over (J1, I-06).
//! - `pending.confirm` and `pending.discard` of an id that names no
//!   action of the caller refuse under `Input` (I-85).
//!
//! Every account and text is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

fn world(state: StateProfile) -> Built {
    let w = build(WorldKey {
        state,
        policy: Policy::SUPERSAFE,
        variant: Variant::Main,
    })
    .unwrap_or_else(|e| panic!("world {state:?}: {e}"));
    w.ports.clock.set(Timestamp::from_micros(w.now));
    w
}

fn active() -> Built {
    world(StateProfile::ProgrammeActive)
}

fn once(
    w: &Built,
    login: &WebLogin,
    method: ApiMethod,
    path: &str,
    body: &Value,
) -> Result<OpResult, ApiError> {
    let bytes = match body {
        Value::Null => Vec::new(),
        v => v.to_compact().into_bytes(),
    };
    let op = decode_web(method, path, &bytes)?;
    block_on(w.core.dispatch(
        Credential::SessionCookie(login.cookie.clone()),
        &RequestHead::new(),
        op,
    ))
}

fn stepped(
    w: &Built,
    login: &WebLogin,
    method: ApiMethod,
    path: &str,
    body: &Value,
) -> Result<OpResult, ApiError> {
    let r = once(w, login, method, path, body);
    let Ok(OpResult::StepUpRequired(ch)) = &r else {
        return r;
    };
    w.ports.step_up.approve(login.session, ch.action).unwrap();
    once(w, login, method, path, body)
}

fn observed(r: &Result<OpResult, ApiError>) -> Observed {
    observed_of_result(r).unwrap_or_else(|e| panic!("{e:?}"))
}

fn body_json(r: Result<OpResult, ApiError>) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("not done: {other:?}"),
    }
}

fn rows(v: &Value) -> Vec<Value> {
    v.as_array()
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default()
}

/// One MCP tool call with `token`.
fn tool(w: &Built, token: &[u8], name: &str, args: &Value) -> Result<OpResult, ApiError> {
    let op = decode_tool(name, args.to_compact().as_bytes())?;
    block_on(
        w.core
            .dispatch(Credential::Bearer(token.to_vec()), &RequestHead::new(), op),
    )
}

// ---------------------------------------------------------------------------
// agents.list and agents.activity
// ---------------------------------------------------------------------------

/// R-MC-03, `mcp-server.md`: a user sees their own connected agents with
/// the scopes each holds and how the consenting session logged in. Another
/// account's client is not listed, and a revoked client leaves the list.
#[test]
fn r_mc_03_agents_list_shows_own_live_clients_with_scopes() {
    let w = active();
    let mine = AgentClientId::from_raw(0x5a_0001);
    let theirs = AgentClientId::from_raw(0x5a_0002);
    let _ = w.ports.tokens.issue(
        PM,
        mine,
        [Scope::CallsRead, Scope::CallsDraft],
        LoginMethod::Passkey,
    );
    let _ = w
        .ports
        .tokens
        .issue(LEAD, theirs, [Scope::ProposalsRead], LoginMethod::Passkey);
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let list = rows(&body_json(once(
        &w,
        &login,
        GET,
        "/me/agents",
        &Value::Null,
    )));
    let ours: Vec<&Value> = list
        .iter()
        .filter(|r| str_member(r, "client").as_deref() == Some("5898241"))
        .collect();
    assert_eq!(ours.len(), 1, "{list:?}");
    let scopes: Vec<String> = ours[0]
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(scopes, ["calls:read", "calls:draft"]);
    assert_eq!(str_member(ours[0], "method").as_deref(), Some("passkey"));
    assert!(
        !list
            .iter()
            .any(|r| str_member(r, "client").as_deref() == Some("5898242")),
        "another account's client is never listed: {list:?}"
    );
    let r = once(
        &w,
        &login,
        POST,
        &format!("/me/agents/{}/revocation", mine.raw()),
        &obj(vec![]),
    );
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    let after = rows(&body_json(once(
        &w,
        &login,
        GET,
        "/me/agents",
        &Value::Null,
    )));
    assert!(
        !after
            .iter()
            .any(|r| str_member(r, "client").as_deref() == Some("5898241")),
        "a revoked client leaves the list: {after:?}"
    );
}

/// R-MC-03, ADR-013: a client connected through the authorisation
/// server's consent flow is listed with its name, its scope and the
/// period of its grant, and a revocation through the API reaches it.
#[test]
fn r_mc_03_adr013_agents_list_shows_a_consented_client() {
    let w = active();
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let at = Timestamp::from_micros(w.now);
    let start = w.ports.tokens.begin_consent(at).unwrap();
    let body = obj(vec![("consent", s(&start.handle))]);
    let reply = body_json(stepped(&w, &login, POST, "/oauth/consent", &body));
    let redirect = str_member(&reply, "redirect").unwrap();
    let grant = w.ports.tokens.redeem(&start, &redirect, at).unwrap();
    let client = grant.client.raw().to_string();
    let list = rows(&body_json(once(
        &w,
        &login,
        GET,
        "/me/agents",
        &Value::Null,
    )));
    let row = list
        .iter()
        .find(|r| str_member(r, "client").as_deref() == Some(client.as_str()))
        .unwrap_or_else(|| panic!("the consented client is not listed: {list:?}"));
    assert_eq!(str_member(row, "name").as_deref(), Some("Synthetic agent"));
    assert!(str_member(row, "since").is_some() && str_member(row, "until").is_some());
    let r = once(
        &w,
        &login,
        POST,
        &format!("/me/agents/{client}/revocation"),
        &obj(vec![]),
    );
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    let after = rows(&body_json(once(
        &w,
        &login,
        GET,
        "/me/agents",
        &Value::Null,
    )));
    assert!(
        !after
            .iter()
            .any(|r| str_member(r, "client").as_deref() == Some(client.as_str())),
        "{after:?}"
    );
}

/// R-MC-03, design section 3.6 (`ListMyAgentActivity`): the caller's own
/// calls through one agent client, newest first, with the operation, the
/// outcome and its rule, and the time. Another account reading the same
/// client id sees none of them.
#[test]
fn r_mc_03_agents_activity_lists_own_calls_through_one_client() {
    let w = active();
    let client = AgentClientId::from_raw(0x5a_0003);
    let token = w
        .ports
        .tokens
        .issue(PM, client, [Scope::CallsRead], LoginMethod::Passkey);
    let r = tool(&w, &token, "fstp_list_open_calls", &obj(vec![]));
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    // A tool whose scope the token lacks is refused, and recorded so.
    let p = w.targets.programme.unwrap().raw().to_string();
    let args = obj(vec![
        ("programme", s(&p)),
        ("opens", dec(u128::try_from(OPENS).unwrap())),
        ("deadline", dec(u128::try_from(DEADLINE).unwrap())),
        ("deadline_zone", s("Europe/Brussels")),
        ("currency", s("EUR")),
        ("budget", s("400000.00")),
        ("text", s("SYNTHETIC AGENT CALL TEXT")),
    ]);
    let r = tool(&w, &token, "fstp_draft_call", &args);
    assert!(r.is_err(), "{r:?}");
    let login = w.ports.sessions.login(PM, LoginMethod::Passkey);
    let path = format!("/me/agents/{}/activity", client.raw());
    let list = rows(&body_json(once(&w, &login, GET, &path, &Value::Null)));
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(str_member(&list[0], "op").as_deref(), Some("call.draft"));
    assert_eq!(str_member(&list[0], "outcome").as_deref(), Some("refused"));
    assert!(str_member(&list[0], "rule").is_some(), "{list:?}");
    assert_eq!(
        str_member(&list[1], "op").as_deref(),
        Some("calls.list_open")
    );
    assert_eq!(str_member(&list[1], "outcome").as_deref(), Some("accepted"));
    assert_eq!(
        str_member(&list[1], "at"),
        Some(w.now.to_string()),
        "the time of the call"
    );
    let other = w.ports.sessions.login(LEAD, LoginMethod::Passkey);
    let theirs = rows(&body_json(once(&w, &other, GET, &path, &Value::Null)));
    assert!(theirs.is_empty(), "I-17: {theirs:?}");
}

// ---------------------------------------------------------------------------
// roles.list and roles.reinstate
// ---------------------------------------------------------------------------

/// J1, SoD-09, I-17: a tenant admin lists the programme's staff bindings
/// by account id, role and state. The suspended IRC binding shows its
/// rule, and no Receiving binding of an applicant is listed.
#[test]
fn j1_roles_list_shows_the_programmes_staff_bindings() {
    let w = world(StateProfile::Proposal(StateTag::Submitted));
    let p = w.targets.programme.unwrap().raw();
    let login = w.ports.sessions.login(ADMIN_PLAIN, LoginMethod::Passkey);
    let list = rows(&body_json(once(
        &w,
        &login,
        GET,
        &format!("/programmes/{p}/roles"),
        &Value::Null,
    )));
    let of = |a: AccountId| {
        list.iter()
            .find(|r| str_member(r, "account") == Some(a.raw().to_string()))
            .cloned()
    };
    let drafter = of(DRAFTER).unwrap_or_else(|| panic!("{list:?}"));
    assert_eq!(
        str_member(&drafter, "role").as_deref(),
        Some("call_drafter")
    );
    assert_eq!(str_member(&drafter, "state").as_deref(), Some("active"));
    let suspended = of(IRC_REINSTATABLE).unwrap_or_else(|| panic!("{list:?}"));
    assert_eq!(
        str_member(&suspended, "state").as_deref(),
        Some("suspended")
    );
    assert_eq!(str_member(&suspended, "rule").as_deref(), Some("I-06"));
    assert!(of(LEAD).is_none(), "no Receiving binding: {list:?}");
    let pm = w.ports.sessions.login(PM, LoginMethod::Passkey);
    assert!(
        !matches!(
            observed(&once(
                &w,
                &pm,
                GET,
                &format!("/programmes/{p}/roles"),
                &Value::Null
            )),
            Observed::Completed
        ),
        "only a tenant admin lists the bindings"
    );
}

/// J1, I-06 (Identity discovery, decided 2026-10-25): once the identity
/// clash is over, a tenant admin reinstates the suspended binding with a
/// fresh step-up, and the list shows it active.
#[test]
fn i06_roles_reinstate_lifts_a_suspension_that_is_over() {
    let w = active();
    let p = w.targets.programme.unwrap().raw();
    let b = w.targets.binding_suspended.unwrap().raw();
    let login = w.ports.sessions.login(ADMIN_PLAIN, LoginMethod::Passkey);
    let body = obj(vec![("reason", s("SYNTHETIC REINSTATEMENT REASON"))]);
    let path = format!("/programmes/{p}/roles/{b}/reinstatement");
    assert_eq!(
        observed(&once(&w, &login, POST, &path, &body)),
        Observed::StepUpRequired
    );
    let r = stepped(&w, &login, POST, &path, &body);
    assert_eq!(observed(&r), Observed::Completed, "{r:?}");
    let list = rows(&body_json(once(
        &w,
        &login,
        GET,
        &format!("/programmes/{p}/roles"),
        &Value::Null,
    )));
    let row = list
        .iter()
        .find(|r| str_member(r, "binding") == Some(b.to_string()))
        .unwrap_or_else(|| panic!("{list:?}"));
    assert_eq!(str_member(row, "state").as_deref(), Some("active"));
}

// ---------------------------------------------------------------------------
// pending.confirm and pending.discard
// ---------------------------------------------------------------------------

/// I-85: a pending action is found only by its own account. An id that
/// names no open action of the caller is refused as an input, alike for
/// an unknown id and another account's action, so the refusal tells
/// nothing of other accounts.
#[test]
fn i85_pending_id_of_no_own_action_is_refused_as_input() {
    let w = active();
    let login = w.ports.sessions.login(UNBOUND, LoginMethod::Passkey);
    let shown = obj(vec![("shown", s(&"0".repeat(64)))]);
    for (path, body) in [
        ("/pending-actions/4242/confirmation", &shown),
        ("/pending-actions/4242/discard", &obj(vec![])),
    ] {
        assert_eq!(
            observed(&once(&w, &login, POST, path, body)),
            Observed::NotFound("Input".to_owned()),
            "{path}"
        );
    }
}
