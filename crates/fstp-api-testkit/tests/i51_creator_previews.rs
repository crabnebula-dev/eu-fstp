//! The creator's previews of a draft (R-PG-01, R-GA-01, I-51, R-PB-04;
//! M4 design sections 2.2 J1, 3.2 and 3.10).
//!
//! `creator.preview` answers the Guide preview from `fstp-guide` and the
//! public page preview from `fstp-public`, over the draft's values. The
//! world is the fake cell of the I-85 world. A1 opens a draft through
//! dispatch with its step-up, M1 becomes its programme manager, applies
//! the SuperSAFE template start and accepts every template narrative, as
//! the creator wire tests do.
//!
//! The contract placeholder preview may stay a documented seam until a
//! contract renderer exists, so no test here reads it.
//!
//! Status: red. `creator.preview` answers `NotImplemented` in
//! `fstp-api-core/src/dispatch/creator_ops.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::creator_requests as rq;
use fstp_api_testkit::fake::fixture::{ADMIN, OWNER};
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::{BindingId, CommandId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::Command;
use fstp_json::{ToJson, Value};

fn login(c: &FakeCell, a: fstp_domain::id::AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

/// `op` through the web, with the step-up ceremony once when asked.
fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: impl Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, String> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports
                .step_up
                .approve(l.session, ch.action)
                .map_err(|e| format!("the step-up ceremony: {e:?}"))?;
            c.web(l, op()).map_err(|e| format!("{e:?}"))
        }
        other => other.map_err(|e| format!("{e:?}")),
    }
}

/// The JSON body of a completed call.
fn body(r: Result<OpResult, String>, what: &str) -> Result<Value, String> {
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        other => Err(format!("{what} gave {other:?}")),
    }
}

/// The string member `k` of `v`.
fn str_of(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("no string member {k:?} in {}", v.to_compact()))
}

/// The command id of the `n`-th change of the world in these tests.
fn world_command(n: u8) -> CommandId {
    let mut b = *b"public-preview:\0";
    b[15] = n;
    CommandId::from_bytes(b)
}

/// A SuperSAFE draft with every narrative accepted, and M1's login.
fn built(c: &FakeCell) -> Result<(ProgrammeId, WebLogin), String> {
    let admin = login(c, ADMIN);
    let opened = body(stepped(c, &admin, rq::open_draft), "creator.open_draft")?;
    let raw: u128 = str_of(&opened, "programme")?
        .parse()
        .map_err(|_| "the programme member is not a decimal id".to_owned())?;
    let p = ProgrammeId::from_raw(raw);
    let now = c.ports.clock.read();
    let step = roster::grant(
        BindingId::from_raw(91_001),
        OWNER,
        p,
        Role::ProgrammeManager,
        now,
    );
    c.ports
        .engine
        .environment(
            Command::Core(step.cmd.clone()),
            step.ctx(now, world_command(1)),
        )
        .map_err(|e| format!("the programme manager grant: {e:?}"))?;
    let owner = login(c, OWNER);
    let draft = body(
        c.web(&owner, rq::get_draft(p))
            .map_err(|e| format!("{e:?}")),
        "get_draft",
    )?;
    let base = str_of(&draft, "revision")?;
    body(
        c.web(&owner, rq::apply_start(p, &base, rq::supersafe_start()))
            .map_err(|e| format!("{e:?}")),
        "creator.apply_start",
    )?;
    loop {
        let draft = body(
            c.web(&owner, rq::get_draft(p))
                .map_err(|e| format!("{e:?}")),
            "get_draft",
        )?;
        let pending: Vec<String> = draft
            .get("pending_narratives")
            .and_then(Value::as_object)
            .map(|o| o.keys().map(str::to_owned).collect())
            .unwrap_or_default();
        let Some(key) = pending.into_iter().next() else {
            return Ok((p, owner));
        };
        let base = str_of(&draft, "revision")?;
        body(
            c.web(&owner, rq::accept_narrative(p, &key, &base))
                .map_err(|e| format!("{e:?}")),
            "creator.accept_narrative",
        )?;
    }
}

/// Every string of `v`, joined by new lines.
fn text_of(v: &Value) -> String {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.iter().for_each(|(_, x)| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out.join("\n")
}

/// The `kind` preview of `p` as M1 reads it.
fn preview(c: &FakeCell, l: &WebLogin, p: ProgrammeId, kind: &str) -> String {
    let v = body(
        c.web(l, rq::preview(p, kind)).map_err(|e| format!("{e:?}")),
        "creator.preview",
    )
    .unwrap_or_else(|e| panic!("the {kind} preview: {e}"));
    text_of(&v)
}

/// R-PG-01, R-GA-01, I-51: the Guide preview of a draft is bound from the
/// draft: it names the programme and shows its P-04 range and P-05 cap.
#[test]
fn i51_guide_preview_of_a_draft_is_bound_from_the_draft() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("{e}"));
    let (p, owner) = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let text = preview(&c, &owner, p, "guide");
    for want in ["SuperSAFE", "5000.00", "100000.00", "400000.00"] {
        assert!(
            text.contains(want),
            "the Guide preview lacks {want:?}: {text}"
        );
    }
    assert!(
        text.contains("How to apply"),
        "the Guide preview has no How to apply section: {text}"
    );
}

/// R-PG-01, R-PB-04: the public page preview of a draft names the
/// programme and holds no script.
#[test]
fn r_pb_04_public_preview_of_a_draft_names_the_programme_without_script() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("{e}"));
    let (p, owner) = built(&c).unwrap_or_else(|e| panic!("{e}"));
    let text = preview(&c, &owner, p, "public");
    assert!(text.contains("SuperSAFE"), "{text}");
    assert!(!text.to_ascii_lowercase().contains("<script"), "{text}");
}
