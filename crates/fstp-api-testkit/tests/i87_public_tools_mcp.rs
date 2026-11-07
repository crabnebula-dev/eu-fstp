//! I-87 through the MCP server (M4 design sections 3.8, 3.10 and 8.4):
//! the public tools return exactly the data of the public pages and feed,
//! under the same filters.
//!
//! The public pages, the feed and the public tools of `ApiCore::dispatch`
//! all come from one `fstp_public::PublicView` per request, and the tool
//! answer is `fstp_public::tools::select` over it (lane W2c, pinned by
//! `i87_filters_m_public.rs` and the `fstp-public` tests). So the MCP
//! server must add, drop and change nothing: for every public tool, every
//! argument and every generated state, `structuredContent.data` of
//! `/mcp/public` with no credential equals the JSON of that dispatch, and
//! a refusal of dispatch is a refusal of the same code and rule.
//!
//! The states vary which approved calls are published besides call 3,
//! and the instant: before, inside and after the open window of the
//! roster's calls. The arguments vary the slug (programme ids, an unknown
//! one, a malformed one) and the call (each world call, an unknown one).
//!
//! Status: red until `fstp_mcp::McpServer` exists.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod mcp_support;

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use fstp_access::{OPS, OpKind};
use fstp_api_core::meta::Scope;
use fstp_api_core::{ApiError, Credential, OpResult, RequestHead};
use fstp_api_testkit::fake::fixture::{
    self, AGENT, CALL_ALLOWED, CALL_EDIT, CALL_OPEN, CALL_PUBLISH, LEAD, OWNER,
};
use fstp_json::{ToJson, Value};
use fstp_mcp::{Classification, Surface};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_rt::future::block_on;
use mcp_support::{McpCell, call, dec, is_error, obj, structured, text, untrusted};

/// The public tools of the registry.
fn public_tools() -> Vec<&'static str> {
    OPS.iter()
        .filter(|o| matches!(o.kind, OpKind::Public(_)))
        .filter_map(|o| o.tool.map(|t| t.name))
        .collect()
}

/// The cell of each published subset, built once (a world from genesis
/// costs a full ledger replay).
fn cell_for(extra: u8) -> &'static McpCell {
    static CELLS: OnceLock<Mutex<BTreeMap<u8, &'static McpCell>>> = OnceLock::new();
    let m = CELLS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut m = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = m.get(&extra) {
        return c;
    }
    {
        let mut s = fixture::setup();
        let others = [CALL_PUBLISH, CALL_EDIT, CALL_ALLOWED];
        for (i, c) in others.iter().enumerate() {
            if extra & (1 << i) != 0 {
                s.base.published.push(*c);
            }
        }
        let c: &'static McpCell = Box::leak(Box::new(McpCell::over(&world_of(s))));
        let _ = m.insert(extra, c);
        c
    }
}

/// The world of setup `s`, as `mcp_support::world` builds the I-85 one.
fn world_of(s: fstp_domain_testkit::r#gen::review::ReviewSetup) -> fixture::World {
    use fstp_domain_testkit::r#gen::review::{attest_adult_leads, review_truth};
    let steps = s.steps().unwrap_or_else(|e| panic!("{e}"));
    let mut truth = review_truth(s.accounts());
    attest_adult_leads(&mut truth, s.drafts.iter().map(|d| (d.lead, d.minor)));
    let vault = fstp_api_testkit::fake::FakeVault::new(truth.clone());
    let mut engine = fstp_engine::Engine::open(fstp_ledger::MemStore::new(), vault.oracle())
        .unwrap_or_else(|e| panic!("{e:?}"));
    for (i, step) in steps.into_iter().enumerate() {
        let mut b = *b"mcp:w3c:i87:\0\0\0\0";
        b[12..16].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        let ctx = step.ctx(
            fstp_domain_testkit::r#gen::roster::T0,
            fstp_domain::id::CommandId::from_bytes(b),
        );
        fstp_domain_testkit::activation::run_core(&mut engine, &step.cmd, ctx)
            .unwrap_or_else(|e| panic!("step {i}: {e}"));
    }
    let (store, _, _) = engine.into_parts();
    fixture::World {
        store,
        truth,
        start: fixture::START,
        admins: [fixture::ADMIN, fixture::ADMIN_2].into_iter().collect(),
    }
}

/// Generated arguments of public tool `name`.
fn args(g: &mut Gen, name: &str) -> Value {
    let op = mcp_support::op_of_tool(name).unwrap();
    let mut members = Vec::new();
    for p in op.tool.unwrap().input.params {
        let v = match *p {
            "slug" => Value::from(*g.pick(&["1", "2", "99", "no-such-programme", "P%201"])),
            "call" => dec(*g.pick(&[
                CALL_PUBLISH.raw(),
                CALL_EDIT.raw(),
                CALL_OPEN.raw(),
                CALL_ALLOWED.raw(),
                999,
            ])),
            _ => Value::from("1"),
        };
        members.push((*p, v));
    }
    obj(members)
}

/// The JSON dispatch gives for public tool `name` with `args` and no
/// credential, or its refusal's code and rule.
fn dispatched(c: &McpCell, name: &str, args: &Value) -> Result<Value, (String, String)> {
    let op = fstp_api_core::decode::decode_tool(name, args.to_compact().as_bytes());
    let r = match op {
        Ok(op) => block_on(c.core.dispatch(Credential::None, &RequestHead::new(), op)),
        Err(e) => Err(e),
    };
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        Ok(other) => Err(("unexpected".to_owned(), format!("{other:?}"))),
        Err(ApiError::Refused { code, rule, .. }) => {
            Err((code.as_str().to_owned(), rule.to_owned()))
        }
        Err(ApiError::NotImplemented(s)) => Err(("not_implemented".to_owned(), s.to_owned())),
    }
}

/// One generated case: a state, a public tool and its arguments, through
/// `surface` with `cred`, against dispatch.
fn agrees(g: &mut Gen, surface: Surface, authenticated: bool) -> Result<(), String> {
    let extra = g.u8_in(0..=7);
    let c = cell_for(extra);
    let shift = *g.pick(&[-86_400_000_000i64, 0, 2_000_000_000_000, 40_000_000_000_000]);
    c.ports.clock.set(fstp_domain::time::Timestamp::from_micros(
        fixture::START.micros().saturating_add(shift),
    ));
    let name = *g.pick(&public_tools());
    let a = args(g, name);
    g.note("case", &(extra, shift, name, a.to_compact()));
    let cred = if authenticated {
        let who = *g.pick(&[OWNER, LEAD]);
        Credential::Bearer(c.token(who, AGENT, [Scope::CallsRead]))
    } else {
        Credential::None
    };
    let want = dispatched(c, name, &a);
    let got = call(&c.server(), surface, cred, name, &a).map_err(|e| format!("{e:?}"))?;
    let sc =
        structured(&got).ok_or_else(|| format!("no structuredContent: {}", got.to_compact()))?;
    match want {
        Ok(data) => {
            prop_assert!(
                !is_error(&got),
                "MCP refused what dispatch answers: {}",
                got.to_compact()
            );
            prop_assert_eq!(
                text(sc, "classification"),
                Some(Classification::Public.as_str())
            );
            prop_assert_eq!(sc.get("data"), Some(&data), "I-87: the data differ");
            let _ = untrusted(sc);
        }
        Err((code, rule)) => {
            prop_assert!(
                is_error(&got),
                "MCP answered what dispatch refuses ({code} {rule})"
            );
            prop_assert_eq!(text(sc, "code"), Some(code.as_str()));
            prop_assert_eq!(text(sc, "rule"), Some(rule.as_str()));
        }
    }
    Ok(())
}

/// I-87, R-PB-01: every public tool on `/mcp/public` with no credential
/// returns exactly the data dispatch builds from the one `PublicView`,
/// classified public, as a property over generated states, tools and
/// arguments. A refusal keeps its code and rule.
#[test]
fn i87_public_tools_on_mcp_public_equal_public_view() {
    check("i87_public_tools_on_mcp_public_equal_public_view", |g| {
        agrees(g, Surface::Public, false)
    });
}

/// I-87 `i87_authenticated_public_tools_equal_public_endpoint`: the same
/// public tools through `/mcp` with a token give the same data as
/// `/mcp/public` with none, so an account sees no more and no less of the
/// public data.
#[test]
fn i87_authenticated_public_tools_equal_public_endpoint() {
    check(
        "i87_authenticated_public_tools_equal_public_endpoint",
        |g| agrees(g, Surface::Mcp, true),
    );
}
