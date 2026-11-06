//! TH-63 and I-84: the MCP tool table (M4 design section 3.8, ADR-013
//! "Tools").
//!
//! - `tools/list` serves `fstp_api_core::meta::tools()` and nothing else:
//!   each listed tool's name, description and input schema is the
//!   registry's `const` data, in registry order.
//! - The list is filtered by the caller (lane scope item 2, interim,
//!   pending Daniel): `/mcp/public` lists exactly the public tools. On
//!   `/mcp`, a tool is listed when it is public, or when the token holds
//!   its scope and the caller acts under one of the operation's roles.
//!   The roles are those of `fstp_access::Principal`: every active
//!   binding, tenant admin from the attested set, and "applicant with no
//!   binding" for an account with neither.
//! - The list is deterministic: equal calls give equal bytes.
//! - A `tools/call` of a name outside the registry is a JSON-RPC error
//!   and reaches no operation: the ledger, the audit log and the pending
//!   list are unchanged.
//! - `fstp-mcp` holds no tool of its own: a scan of its source finds no
//!   `ToolDef` value and no `fstp_` tool name literal
//!   (`i84_one_tool_table`).
//!
//! The JSON form of a tool (interim, pending Daniel): `{"name",
//! "description", "inputSchema"}`, where `inputSchema` is an object
//! schema whose `properties` hold one string property per path parameter
//! of the registry's `Schema`, every one of them `required`.
//!
//! Status: red until `fstp_mcp::McpServer` exists, except the source scan
//! and the registry checks, which are green.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use std::collections::BTreeSet;

use fstp_access::{OPS, OpKind, RoleOrApplicant};
use fstp_api_core::Credential;
use fstp_api_core::meta::{Scope, tools};
use fstp_api_testkit::fake::fixture::{ADMIN, ADMIN_2, AGENT, LEAD, OTHER, OWNER};
use fstp_domain::id::AccountId;
use fstp_json::Value;
use fstp_mcp::Surface;
use fstp_prop::{check, prop_assert, prop_assert_eq};
use mcp_support::{McpCell, list, listed_names, obj};

/// Every scope M4 issues (design section 3.8).
const EVERY_SCOPE: [Scope; 12] = [
    Scope::CallsRead,
    Scope::ProposalsRead,
    Scope::ProposalsDraft,
    Scope::ProposalsBinding,
    Scope::Stage2Draft,
    Scope::ReviewRead,
    Scope::ReviewDraft,
    Scope::RankingRead,
    Scope::FindingsRead,
    Scope::CreatorDraft,
    Scope::CallsDraft,
    Scope::AuditRead,
];

/// The roles `account` acts under in the cell now, as
/// `fstp_access::Principal` computes them from the bindings and the
/// attested admin set. The listing rule itself is this file's reference.
fn roles_of(c: &McpCell, account: AccountId) -> BTreeSet<RoleOrApplicant> {
    let grant = fstp_access::GrantFacts {
        account,
        agent: fstp_access::AgentClientId::from_raw(AGENT.raw()),
        scopes: EVERY_SCOPE.into_iter().collect(),
        consent_method: fstp_access::LoginMethod::Passkey,
    };
    let admins: BTreeSet<AccountId> = [ADMIN, ADMIN_2].into_iter().collect();
    let p = fstp_access::Principal::mcp(
        &grant,
        &admins,
        &c.ports.engine.state(),
        c.ports.clock.read(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    p.roles().iter().collect()
}

/// The reference list: the registry's tools in registry order, filtered
/// as the module documentation says.
fn reference_list(
    surface: Surface,
    roles: &BTreeSet<RoleOrApplicant>,
    scopes: &BTreeSet<Scope>,
) -> Vec<&'static str> {
    OPS.iter()
        .filter_map(|op| op.tool.map(|t| (op, t)))
        .filter(|(op, t)| {
            let public = matches!(op.kind, OpKind::Public(_));
            match surface {
                Surface::Public => public,
                Surface::Mcp => {
                    public
                        || (scopes.contains(&t.scope)
                            && op.acting.iter().any(|r| roles.contains(r)))
                }
            }
        })
        .map(|(_, t)| t.name)
        .collect()
}

/// The JSON form of a registry tool (module documentation).
fn tool_json(t: &fstp_access::ToolDef) -> Value {
    let props: Vec<(&str, Value)> = t
        .input
        .params
        .iter()
        .map(|p| (*p, obj(vec![("type", Value::from("string"))])))
        .collect();
    obj(vec![
        ("name", Value::from(t.name)),
        ("description", Value::from(t.description)),
        (
            "inputSchema",
            obj(vec![
                ("type", Value::from("object")),
                ("properties", obj(props)),
                (
                    "required",
                    Value::from(
                        t.input
                            .params
                            .iter()
                            .map(|p| Value::from(*p))
                            .collect::<Vec<Value>>(),
                    ),
                ),
            ]),
        ),
    ])
}

/// TH-63, I-84: `/mcp/public` lists exactly the public tools of the
/// registry, in registry order, each with its fixed name and description
/// and the schema of its registry `Schema`, with no credential.
#[test]
fn th63_public_tools_list_is_the_registry_public_rows() {
    let c = McpCell::new();
    let s = c.server();
    let got = list(&s, Surface::Public, Credential::None).unwrap_or_else(|e| panic!("{e:?}"));
    let want: Vec<Value> = OPS
        .iter()
        .filter(|op| matches!(op.kind, OpKind::Public(_)))
        .filter_map(|op| op.tool.as_ref())
        .map(tool_json)
        .collect();
    assert!(!want.is_empty(), "the registry has public tools");
    let listed = got
        .as_object()
        .and_then(|o| o.get("tools"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no tools array: {}", got.to_compact()));
    assert_eq!(listed.len(), want.len(), "{}", got.to_compact());
    for (g, w) in listed.iter().zip(want.iter()) {
        let go = g.as_object().unwrap();
        let wo = w.as_object().unwrap();
        assert_eq!(go.get("name"), wo.get("name"));
        assert_eq!(go.get("description"), wo.get("description"));
        let gs = go.get("inputSchema").and_then(Value::as_object).unwrap();
        let ws = wo.get("inputSchema").and_then(Value::as_object).unwrap();
        assert_eq!(gs.get("type"), ws.get("type"));
        assert_eq!(gs.get("required"), ws.get("required"));
        let gp: BTreeSet<&str> = gs
            .get("properties")
            .and_then(Value::as_object)
            .map(|p| p.keys().collect())
            .unwrap_or_default();
        let wp: BTreeSet<&str> = ws
            .get("properties")
            .and_then(Value::as_object)
            .map(|p| p.keys().collect())
            .unwrap_or_default();
        assert!(
            wp.is_subset(&gp),
            "{:?}: the schema lacks a path parameter",
            go.get("name")
        );
    }
}

/// TH-63, I-84: on `/mcp`, `tools/list` equals the registry's tools
/// filtered by the caller's roles and the token's scopes, in registry
/// order, for every world account and any subset of the M4 scopes. Every
/// listed tool's description is the registry's fixed text.
#[test]
fn th63_tools_list_equals_registry_filtered_by_roles_and_scopes() {
    let c = McpCell::new();
    let s = c.server();
    check(
        "th63_tools_list_equals_registry_filtered_by_roles_and_scopes",
        |g| {
            let accounts = [OWNER, OTHER, ADMIN, LEAD];
            let account = accounts[usize::from(g.u8_in(0..=3))];
            let scopes: BTreeSet<Scope> = EVERY_SCOPE.into_iter().filter(|_| g.bool()).collect();
            g.note("account", &account);
            g.note("scopes", &scopes);
            let token = c.token(account, AGENT, scopes.iter().copied());
            let got =
                list(&s, Surface::Mcp, Credential::Bearer(token)).map_err(|e| format!("{e:?}"))?;
            let want = reference_list(Surface::Mcp, &roles_of(&c, account), &scopes);
            prop_assert_eq!(listed_names(&got), want);
            for t in got
                .as_object()
                .and_then(|o| o.get("tools"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let o = t.as_object().ok_or("a tool that is no object")?;
                let name = o.get("name").and_then(Value::as_str).unwrap_or("");
                let reg = tools().find(|r| r.name == name).ok_or("unknown tool")?;
                prop_assert_eq!(
                    o.get("description").and_then(Value::as_str),
                    Some(reg.description)
                );
                prop_assert!(
                    o.get("title").is_none() && o.get("annotations").is_none(),
                    "{name}: a member outside the registry's const data"
                );
            }
            Ok(())
        },
    );
}

/// TH-63 (ADR-013 "Tools", MCP 2026-07-28 minor change 3): `tools/list`
/// is deterministic. Two lists for the same caller give equal bytes, and
/// a list after an unrelated call gives the same bytes again.
#[test]
fn th63_tools_list_is_deterministic() {
    let c = McpCell::new();
    let s = c.server();
    let token = c.token(OWNER, AGENT, EVERY_SCOPE);
    let a = list(&s, Surface::Mcp, Credential::Bearer(token.clone()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let p = list(&s, Surface::Public, Credential::None).unwrap_or_else(|e| panic!("{e:?}"));
    let b = list(&s, Surface::Mcp, Credential::Bearer(token)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(a.to_compact(), b.to_compact());
    let q = list(&s, Surface::Public, Credential::None).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p.to_compact(), q.to_compact());
}

/// TH-63, I-84: a `tools/call` of a name outside the registry, on either
/// surface, is a JSON-RPC error. It reaches no operation: the ledger
/// head, the audit log and the owner's pending list are unchanged. A
/// private tool on `/mcp/public` is refused the same way.
#[test]
fn th63_no_tool_outside_the_registry() {
    let c = McpCell::new();
    let s = c.server();
    let token = c.token(OWNER, AGENT, EVERY_SCOPE);
    let owner = c.login(OWNER);
    let head = c.ports.engine.appended().len();
    let pending = c.web(&owner, fstp_api_testkit::fake::requests::pending_list());
    let audit = c.ports.audit.entries().len();
    let names = [
        "fstp_publish_call",
        "fstp_activate_programme",
        "fstp_approve_recovery",
        "call.publish",
        "FSTP_LIST_OPEN_CALLS",
        "fstp_list_open_calls ",
        "",
    ];
    for name in names {
        for (surface, cred) in [
            (Surface::Mcp, Credential::Bearer(token.clone())),
            (Surface::Public, Credential::None),
        ] {
            let r = mcp_support::call(&s, surface, cred, name, &obj(vec![]));
            assert!(r.is_err(), "{name:?} on {surface:?} gave a result: {r:?}");
        }
    }
    let r = mcp_support::call(
        &s,
        Surface::Public,
        Credential::None,
        "fstp_list_my_proposals",
        &obj(vec![]),
    );
    let refused = match &r {
        Err(_) => true,
        Ok(v) => mcp_support::is_error(v),
    };
    assert!(refused, "a private tool on /mcp/public: {r:?}");
    assert_eq!(c.ports.engine.appended().len(), head);
    // The refused private tool on `/mcp/public` may record its refusal.
    // An unknown name reaches no operation, so it records nothing.
    assert!(c.ports.audit.entries().len() <= audit.saturating_add(1));
    assert_eq!(
        c.web(&owner, fstp_api_testkit::fake::requests::pending_list()),
        pending
    );
}

/// Every string literal of `src` that is a whole tool-shaped name:
/// `"fstp_` and lower-case letters, digits and underscores, then `"`.
/// Module paths such as `"fstp_mcp::McpServer::new"` are not names.
fn name_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("\"fstp_") {
        let after = &rest[i + 1..];
        let n = after
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            .count();
        if after.as_bytes().get(n) == Some(&b'"') {
            out.push(after[..n].to_owned());
        }
        rest = after;
    }
    out
}

/// I-84 `i84_one_tool_table`, TH-63: `fstp-mcp` defines no tool. No
/// source file of the crate builds a `ToolDef` or holds a string literal
/// that names a tool of the registry or any `fstp_` name. Green on the
/// stub, and it must stay green.
#[test]
fn i84_one_tool_table() {
    assert_eq!(
        name_literals(r#"a "fstp_list_open_calls" b "fstp_mcp::McpServer::new" c"#),
        ["fstp_list_open_calls"]
    );
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fstp-mcp/src");
    let mut files = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    assert!(!files.is_empty(), "no source under {dir}");
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        assert!(
            !src.contains("ToolDef {"),
            "{} builds a ToolDef",
            f.display()
        );
        assert!(
            name_literals(&src).is_empty(),
            "{} holds the tool name literals {:?}",
            f.display(),
            name_literals(&src)
        );
        for t in tools() {
            assert!(
                !src.contains(t.description),
                "{} copies the description of {}",
                f.display(),
                t.name
            );
        }
    }
}

/// TH-63: every tool description is fixed `const` text that names no
/// tenant, carries no markup and stays one line, and every tool name is
/// unique and matches `^fstp_[a-z0-9_]+$`. Green now.
#[test]
fn th63_tool_descriptions_are_fixed_plain_text() {
    let mut seen = BTreeSet::new();
    for t in tools() {
        assert!(seen.insert(t.name), "{} twice", t.name);
        assert!(
            t.name.starts_with("fstp_")
                && t.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{}",
            t.name
        );
        assert!(!t.description.is_empty(), "{}", t.name);
        assert!(
            !t.description.contains(['<', '>', '{', '}', '\n', '`']),
            "{}: {:?}",
            t.name,
            t.description
        );
    }
}
