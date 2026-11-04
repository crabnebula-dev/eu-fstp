//! I-86: `me.roles`, the read behind the interim home page (M4 design
//! section 15.0, 2026-10-31), names the caller's own active bindings and
//! nothing about any other account.
//!
//! Each test drives `ApiCore::dispatch` on the fake cell over the I-85
//! world: the staff programme manager holds programme bindings on P1 and
//! P2, the lead holds the Receiving binding of PX in the published call
//! `CALL_OPEN`, and the two tenant admins hold no binding. Every account
//! and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Credential, ErrorCode, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{ADMIN, CALL_OPEN, LEAD, OTHER, OWNER, PX};
use fstp_domain::id::AccountId;
use fstp_domain::roles::BindingScope;
use fstp_json::{ToJson, Value};

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn me_roles() -> Result<fstp_api_core::Op, ApiError> {
    decode_route(Method::Get, "/me/roles", b"")
}

/// The `me.roles` reply of `account`, signed in with a passkey, as JSON.
fn roles_of(c: &FakeCell, account: AccountId) -> Value {
    let login = c.login(account, LoginMethod::Passkey);
    match c.web(&login, me_roles()) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("me.roles of {account:?}: {other:?}"),
    }
}

fn members<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    match v.get(key) {
        Some(Value::Array(a)) => a.iter().collect(),
        other => panic!("{key} is not an array: {other:?}"),
    }
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// The (role, programme, proposal) of each active binding of `account`
/// in the cell's state, as the wire spells them.
fn bindings_of(c: &FakeCell, account: AccountId) -> BTreeSet<(String, String, Option<String>)> {
    let state = c.ports.engine.state();
    let now = c.ports.clock.read();
    state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| *b)
        .filter(|b| b.account == account && b.active_at(now))
        .map(|b| {
            let proposal = match b.scope {
                BindingScope::Proposal { proposal, .. } => Some(proposal.raw().to_string()),
                BindingScope::Programme => None,
            };
            (
                fstp_access::role_wire_name(b.role).to_owned(),
                b.programme.raw().to_string(),
                proposal,
            )
        })
        .collect()
}

/// The (role, programme, proposal) of each binding in a reply.
fn listed(v: &Value) -> BTreeSet<(String, String, Option<String>)> {
    members(v, "roles")
        .into_iter()
        .map(|r| {
            (
                text(r, "role").unwrap().to_owned(),
                text(r, "programme").unwrap().to_owned(),
                text(r, "proposal").map(str::to_owned),
            )
        })
        .collect()
}

/// I-86: each caller's reply lists exactly that caller's own active
/// bindings, and those of the other accounts never appear in it.
#[test]
fn i86_me_roles_lists_exactly_the_callers_own_bindings() {
    let c = cell();
    let people = [OWNER, OTHER, LEAD, ADMIN];
    for who in people {
        let got = listed(&roles_of(&c, who));
        let mine = bindings_of(&c, who);
        assert_eq!(got, mine, "{who:?}");
        for other in people.iter().filter(|o| **o != who) {
            let theirs = bindings_of(&c, *other);
            for b in theirs.difference(&mine) {
                assert!(!got.contains(b), "{who:?} sees {b:?} of {other:?}");
            }
        }
    }
    assert!(
        !bindings_of(&c, OWNER).is_empty(),
        "the programme manager holds bindings, so the check has teeth"
    );
}

/// I-86: the reply carries no email and no name. It holds the five
/// members of its shape: ids of programmes, proposals, calls and rounds,
/// role names, the published call titles, the caller's drafted
/// programmes and the tenant admin flag.
#[test]
fn i86_me_roles_names_no_account_and_no_email() {
    let c = cell();
    for who in [OWNER, LEAD, ADMIN] {
        let v = roles_of(&c, who);
        let s = v.to_compact();
        assert!(!s.contains('@'), "an email in {s}");
        let keys: BTreeSet<&str> = match &v {
            Value::Object(o) => o.iter().map(|(k, _)| k).collect(),
            _ => panic!("not an object: {s}"),
        };
        assert_eq!(
            keys,
            ["calls", "drafts", "roles", "rounds", "tenant_admin"]
                .into_iter()
                .collect(),
            "{s}"
        );
    }
}

/// I-86: the lead's reply names the proposal and its published call, and
/// the call's title comes with it. A programme binding reaches every
/// published call of its programme.
#[test]
fn i86_me_roles_names_the_calls_each_binding_reaches() {
    let c = cell();
    let lead = roles_of(&c, LEAD);
    let receiving: Vec<&Value> = members(&lead, "roles")
        .into_iter()
        .filter(|r| text(r, "proposal") == Some(PX.raw().to_string().as_str()))
        .collect();
    assert_eq!(receiving.len(), 1, "{}", lead.to_compact());
    let calls: Vec<&str> = members(receiving[0], "calls")
        .into_iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(calls, vec![CALL_OPEN.raw().to_string().as_str()]);
    let named: Vec<&str> = members(&lead, "calls")
        .into_iter()
        .filter_map(|x| text(x, "call"))
        .collect();
    assert_eq!(named, vec![CALL_OPEN.raw().to_string().as_str()]);

    let pm = roles_of(&c, OWNER);
    for r in members(&pm, "roles") {
        assert!(text(r, "proposal").is_none(), "{}", pm.to_compact());
        for call in members(r, "calls").into_iter().filter_map(Value::as_str) {
            let id = fstp_domain::id::CallId::from_raw(call.parse().unwrap());
            let view = c
                .ports
                .engine
                .state()
                .core
                .calls()
                .get(id)
                .cloned()
                .unwrap();
            assert_eq!(
                view.status(),
                fstp_domain::programme::CallStatus::Published,
                "{call}"
            );
            assert_eq!(
                view.programme().raw().to_string(),
                text(r, "programme").unwrap()
            );
        }
    }
}

/// I-86, Q31: the tenant admin flag is the caller's own membership of the
/// attested admin set.
#[test]
fn i86_me_roles_tenant_admin_is_the_callers_own_membership() {
    let c = cell();
    assert_eq!(
        roles_of(&c, ADMIN).get("tenant_admin"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        roles_of(&c, LEAD).get("tenant_admin"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        roles_of(&c, OWNER).get("tenant_admin"),
        Some(&Value::Bool(false))
    );
}

/// I-86: a caller with no session gets no reply, and the read has no MCP
/// tool, so it is web only.
#[test]
fn i86_me_roles_needs_a_session_and_has_no_tool() {
    let c = cell();
    let r = c.call(Credential::None, me_roles());
    assert!(
        matches!(
            r,
            Err(ApiError::Refused {
                code: ErrorCode::Unauthenticated,
                ..
            })
        ),
        "{r:?}"
    );
    let spec = fstp_access::OPS
        .iter()
        .find(|s| s.name == "me.roles")
        .expect("me.roles is in the registry");
    assert!(spec.tool.is_none(), "me.roles has an MCP tool");
}

/// I-86 (review finding U1 of lane m4home): `drafts` names only
/// programmes where the caller holds a programme manager binding, and
/// only those that hold a creator draft in the cell's state.
#[test]
fn i86_me_roles_drafts_are_the_callers_own_drafted_programmes() {
    let c = cell();
    for who in [OWNER, LEAD, ADMIN, OTHER] {
        let v = roles_of(&c, who);
        let managed: BTreeSet<String> = bindings_of(&c, who)
            .into_iter()
            .filter(|(role, _, proposal)| role == "programme_manager" && proposal.is_none())
            .map(|(_, programme, _)| programme)
            .collect();
        let state = c.ports.engine.state();
        for d in members(&v, "drafts") {
            let p = d
                .as_str()
                .unwrap_or_else(|| panic!("a draft id is a string: {d:?}"));
            assert!(
                managed.contains(p),
                "{who:?} lists {p}, which it does not manage"
            );
            let raw: u128 = p.parse().unwrap();
            assert!(
                state
                    .creator
                    .draft(fstp_domain::id::ProgrammeId::from_raw(raw))
                    .is_some(),
                "{p} holds no creator draft"
            );
        }
    }
}
