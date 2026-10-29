//! I-85: pending actions, digest-bound step-up and the stored request
//! (M4 design sections 3.7, 8.4 and 8.5).
//!
//! Every test drives `ApiCore::dispatch` on a cell of fake ports
//! ([`FakeCell`]), through the adapter-facing decoders. The engine port
//! runs the production M2 domain, so every executed command is decided by
//! the real guards. Each test reads what the ports saw: the engine's
//! executions, the step-up proofs taken and the pending list.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::meta::Scope;
use fstp_api_core::port::{BreakGlassId, LoginMethod, RecoveryId};
use fstp_api_core::{ActionDigest, ApiError, ErrorCode, Op, OpResult, PendingStatus, PendingView};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{
    ADMIN, AGENT, AGENT_2, CALL_ALLOWED, CALL_EDIT, CALL_PUBLISH, LEAD, OTHER, OWNER, P1, PX,
    px_plan, sample_edit,
};
use fstp_api_testkit::fake::requests::{self, CallEdit};
use fstp_api_testkit::fake::step_up::P71_MICROS;
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_api_testkit::mc::prep_model::PrepMachine;
use fstp_domain::Via;
use fstp_domain::command::{Actor, CommandKind};
use fstp_domain::id::{TextId, TextRef};
use fstp_engine::Command;
use fstp_json::Value;
use fstp_prop::{check, check_machine, prop_assert, prop_assert_eq};

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

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

fn owner_token(c: &FakeCell) -> Vec<u8> {
    c.token(
        OWNER,
        AGENT,
        [Scope::CallsDraft, Scope::CallsRead],
        LoginMethod::Passkey,
    )
}

/// The one pending action of `login` whose op the agent just prepared.
fn only_pending(c: &FakeCell, login: &WebLogin) -> PendingView {
    let list = c.pending(login).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(list.len(), 1, "pending.list: {list:?}");
    list.into_iter().next().unwrap()
}

/// Whether the engine appended a command of `kind`.
fn appended_kind(c: &FakeCell, kind: CommandKind) -> usize {
    c.ports
        .engine
        .appended()
        .iter()
        .filter(|e| matches!(&e.cmd, Command::Core(x) if x.kind() == kind))
        .count()
}

/// A high-risk operation of the reference list: its name, whether it has
/// a prepare-only tool, and how an agent sends it.
struct HighRisk {
    name: &'static str,
    prepare_only_tool: bool,
    op: fn() -> Result<Op, ApiError>,
}

/// The routed high-risk operations of M4 that an agent can name, from the
/// `authentication.md` high-risk list and design sections 2.2 and 3.8. The
/// publication has the prepare-only tool `fstp_prepare_call_publication`
/// (Q32). The others have no tool, so a bearer request for them is sent
/// on their web route.
fn high_risk_ops() -> Vec<HighRisk> {
    vec![
        HighRisk {
            name: "call.publish",
            prepare_only_tool: true,
            op: || requests::publish_mcp(CALL_PUBLISH),
        },
        HighRisk {
            name: "creator.approve_activation",
            prepare_only_tool: false,
            op: || requests::approve_activation(P1),
        },
        HighRisk {
            name: "admin.approve_recovery",
            prepare_only_tool: false,
            op: || requests::approve_recovery(RecoveryId::from_raw(1)),
        },
        HighRisk {
            name: "admin.approve_break_glass",
            prepare_only_tool: false,
            op: || requests::approve_break_glass(BreakGlassId::from_raw(1), true),
        },
    ]
}

/// I-85, I-84: every routed high-risk operation, for every MCP token
/// principal, never completes through MCP. An operation with a
/// prepare-only tool gives `Pending` or a refusal, and `Pending` for the
/// owner whose roles allow it. An operation without a tool gives
/// `Deny(NotExposed)` to every valid phishing-resistant token. No step-up
/// is begun through MCP, and nothing is executed.
#[test]
fn i85_every_high_risk_op_prepares_through_mcp() {
    let c = cell();
    let revoked = c.token(OWNER, AGENT_2, EVERY_SCOPE, LoginMethod::Passkey);
    c.ports.tokens.revoke(OWNER, AGENT_2).unwrap();
    // The owner with the scope comes first, so the one publication it may
    // prepare is prepared before any other token tries.
    let principals: Vec<(&str, Vec<u8>, bool, bool)> = vec![
        ("owner with calls:draft", owner_token(&c), true, true),
        (
            "owner without calls:draft",
            c.token(OWNER, AGENT, [Scope::CallsRead], LoginMethod::Passkey),
            true,
            false,
        ),
        (
            "call drafter with calls:draft",
            c.token(OTHER, AGENT, [Scope::CallsDraft], LoginMethod::Passkey),
            true,
            false,
        ),
        (
            "tenant admin with every scope",
            c.token(ADMIN, AGENT, EVERY_SCOPE, LoginMethod::Passkey),
            true,
            false,
        ),
        (
            "applicant with every scope",
            c.token(LEAD, AGENT, EVERY_SCOPE, LoginMethod::Passkey),
            true,
            false,
        ),
        (
            "owner through a magic-link consent",
            c.token(OWNER, AGENT, [Scope::CallsDraft], LoginMethod::MagicLink),
            false,
            false,
        ),
        ("revoked token", revoked, false, false),
    ];
    for op in high_risk_ops() {
        for (who, token, strong, may_prepare) in &principals {
            let r = c.mcp(token, (op.op)());
            let got = class(&r);
            if op.prepare_only_tool {
                if *may_prepare {
                    assert_eq!(got, Class::Pending, "{} by {who}: {r:?}", op.name);
                } else if *strong {
                    assert!(got.refused(), "{} by {who}: {r:?}", op.name);
                } else {
                    assert!(
                        got.refused() || got == Class::Pending,
                        "{} by {who}: {r:?}",
                        op.name
                    );
                }
            } else if *strong {
                assert_eq!(
                    got,
                    Class::Refused(ErrorCode::NotExposed),
                    "{} by {who}: {r:?}",
                    op.name
                );
            } else {
                assert!(got.refused(), "{} by {who}: {r:?}", op.name);
            }
        }
    }
    assert!(
        c.ports.engine.appended().is_empty(),
        "a high-risk call through MCP executed: {:?}",
        c.ports.engine.appended()
    );
    assert!(
        c.ports
            .engine
            .executions()
            .iter()
            .all(|e| e.ctx.via != Via::Mcp),
        "dispatch sent a call through MCP to execute"
    );
    assert!(
        c.ports.step_up.begun().is_empty(),
        "a step-up was begun through MCP: {:?}",
        c.ports.step_up.begun()
    );
}

/// I-85, R-MC-05, P-77: a binding operation through MCP under P-77 "draft
/// only" becomes a pending action and executes nothing. Under "allowed" it
/// completes through MCP, attributed to the user with the agent recorded.
/// A high-risk operation prepares under both values. The web channel is
/// unaffected by P-77.
#[test]
fn i85_p77_draft_only_binding_ops_prepare() {
    let c = cell();
    let owner = c.login(OWNER, LoginMethod::Passkey);
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let token = owner_token(&c);
    let lead_token = c.token(
        LEAD,
        AGENT_2,
        [
            Scope::ProposalsRead,
            Scope::ProposalsDraft,
            Scope::ProposalsBinding,
        ],
        LoginMethod::Passkey,
    );
    let edit = sample_edit();

    let r = c.mcp(&token, requests::edit_mcp(CALL_EDIT, &edit));
    assert_eq!(class(&r), Class::Pending, "edit in P1 (draft only): {r:?}");
    let r = c.mcp(
        &lead_token,
        requests::submit_mcp(PX, px_plan(), false, "SYNTHETIC ETHICS TEXT"),
    );
    assert_eq!(
        class(&r),
        Class::Pending,
        "submission in P1 (draft only): {r:?}"
    );
    assert!(
        c.ports.engine.appended().is_empty(),
        "a draft-only binding call executed"
    );

    // Both publications prepare before the P2 edit below. The edit resets
    // CALL_ALLOWED's approval, so a later dry run would refuse it with
    // R-PC-03 before any pending action is stored (design 3.7 step 5).
    for call in [CALL_PUBLISH, CALL_ALLOWED] {
        let r = c.mcp(&token, requests::publish_mcp(call));
        assert_eq!(class(&r), Class::Pending, "publication of {call:?}: {r:?}");
    }

    let r = c.mcp(&token, requests::edit_mcp(CALL_ALLOWED, &edit));
    assert_eq!(class(&r), Class::Done, "edit in P2 (allowed): {r:?}");
    let appended = c.ports.engine.appended();
    assert_eq!(appended.len(), 1, "{appended:?}");
    let e = &appended[0];
    assert!(
        matches!(&e.cmd, Command::Core(fstp_domain::Command::EditCall { call, .. }) if *call == CALL_ALLOWED)
    );
    assert_eq!(e.ctx.via, Via::Mcp);
    assert_eq!(e.meta.via, Via::Mcp);
    assert_eq!(
        e.meta.agent,
        Some(AGENT),
        "R-MC-05: the agent client is recorded"
    );
    assert_eq!(e.ctx.actor, Actor::Account(OWNER), "the user is the actor");

    assert_eq!(appended_kind(&c, CommandKind::PublishCall), 0);
    assert_eq!(appended_kind(&c, CommandKind::Submit), 0);

    let r = c.web(&owner, requests::edit_web(CALL_EDIT, &edit));
    assert_eq!(class(&r), Class::Done, "P-77 governs MCP only: {r:?}");
    assert_eq!(appended_kind(&c, CommandKind::EditCall), 2);

    let mine = c.pending(&owner).unwrap();
    assert_eq!(mine.len(), 3, "the owner's pending actions: {mine:?}");
    assert!(
        mine.iter()
            .all(|v| v.status == PendingStatus::Open && v.agent == AGENT)
    );
    let theirs = c.pending(&lead).unwrap();
    assert_eq!(theirs.len(), 1, "the lead's pending actions: {theirs:?}");
    assert_eq!(theirs[0].agent, AGENT_2);
}

/// I-85, I-24, design section 3.7 steps 6 and 9: a preparation whose
/// audit entry cannot be written is refused and leaves no pending action
/// to confirm. Once the sink works again the same call prepares.
#[test]
fn i85_preparation_without_its_audit_entry_leaves_no_action() {
    let c = cell();
    let owner = c.login(OWNER, LoginMethod::Passkey);
    let token = owner_token(&c);
    c.ports.audit.set_failing(true);
    let r = c.mcp(&token, requests::publish_mcp(CALL_PUBLISH));
    c.ports.audit.set_failing(false);
    assert_eq!(
        class(&r),
        Class::Refused(ErrorCode::Unavailable),
        "the preparation with no audit entry: {r:?}"
    );
    let mine = c.pending(&owner).unwrap();
    assert!(mine.is_empty(), "an unaudited action is held: {mine:?}");
    let r = c.mcp(&token, requests::publish_mcp(CALL_PUBLISH));
    assert_eq!(class(&r), Class::Pending, "{r:?}");
    assert_eq!(c.pending(&owner).unwrap().len(), 1);
}

/// I-85, I-78: a publication an agent prepared through
/// `fstp_prepare_call_publication` is published only by a confirmation
/// through the web by the same account, with the stored digest and a
/// fresh step-up proof for it. Random sequences of prepares, step-ups,
/// confirmations, discards, clock moves and binding ends, against the
/// M-PREP reference.
#[test]
fn i85_prepared_publication_completes_only_after_web_confirmation() {
    check_machine(
        "i85_prepared_publication_completes_only_after_web_confirmation",
        &PrepMachine::new(),
    );
}

/// A defect of the step-up behind a confirmation.
#[derive(Clone, Copy, Debug)]
enum Defect {
    /// No proof at all.
    NoProof,
    /// A proof older than P-71 by `extra` microseconds or more.
    Stale { extra: i64 },
    /// A proof for another digest.
    OtherDigest { flip: u8 },
    /// A proof from another session of the same account.
    OtherSession,
    /// A proof of another account, which also confirms.
    OtherAccount,
}

/// I-85, I-78: a confirmation of a high-risk pending action needs a fresh
/// proof for exactly its digest and session. These are refused: no proof,
/// a proof older than P-71, a proof for another digest, a proof from
/// another session, and a proof of another account. Each refusal asks for a
/// step-up bound to the stored digest and executes nothing. A fresh proof
/// then completes it, and the proof is consumed by that one confirmation.
#[test]
fn i85_confirmation_needs_fresh_digest_bound_step_up() {
    check("i85_confirmation_needs_fresh_digest_bound_step_up", |g| {
        let defect = match g.u8_in(0..=4) {
            0 => Defect::NoProof,
            1 => Defect::Stale {
                extra: g.i64_in(0..=3_000_000_000),
            },
            2 => Defect::OtherDigest {
                flip: g.u8_in(1..=255),
            },
            3 => Defect::OtherSession,
            _ => Defect::OtherAccount,
        };
        g.note("defect", &defect);
        let c = FakeCell::new().map_err(|e| e.to_string())?;
        let main = c.login(OWNER, LoginMethod::Passkey);
        let second = c.login(OWNER, LoginMethod::Passkey);
        let other = c.login(OTHER, LoginMethod::Passkey);
        let r = c.mcp(&owner_token(&c), requests::publish_mcp(CALL_PUBLISH));
        prop_assert_eq!(class(&r), Class::Pending, "{:?}", r);
        let view = only_pending(&c, &main);
        let d = view.digest;
        match defect {
            Defect::NoProof => {}
            Defect::Stale { extra } => {
                c.ports
                    .step_up
                    .approve(main.session, d)
                    .map_err(|e| format!("{e:?}"))?;
                c.ports.clock.advance(P71_MICROS.saturating_add(extra));
            }
            Defect::OtherDigest { flip } => {
                let mut b = d.0;
                b[31] ^= flip;
                c.ports
                    .step_up
                    .approve(main.session, ActionDigest(b))
                    .map_err(|e| format!("{e:?}"))?;
            }
            Defect::OtherSession => {
                c.ports
                    .step_up
                    .approve(second.session, d)
                    .map_err(|e| format!("{e:?}"))?;
            }
            Defect::OtherAccount => {
                c.ports
                    .step_up
                    .approve(other.session, d)
                    .map_err(|e| format!("{e:?}"))?;
                let r = c.web(&other, requests::pending_confirm(view.id, &d));
                prop_assert!(class(&r).refused(), "the other account confirmed: {:?}", r);
            }
        }
        let r = c.web(&main, requests::pending_confirm(view.id, &d));
        match &r {
            Ok(OpResult::StepUpRequired(ch)) => {
                prop_assert_eq!(ch.action, d, "the challenge is bound to another digest");
            }
            other => return Err(format!("{defect:?}: the confirmation gave {other:?}")),
        }
        prop_assert_eq!(appended_kind(&c, CommandKind::PublishCall), 0);

        c.ports
            .step_up
            .approve(main.session, d)
            .map_err(|e| format!("{e:?}"))?;
        let r = c.web(&main, requests::pending_confirm(view.id, &d));
        prop_assert_eq!(class(&r), Class::Done, "the fresh proof: {:?}", r);
        prop_assert_eq!(appended_kind(&c, CommandKind::PublishCall), 1);
        let taken = c.ports.step_up.taken();
        prop_assert_eq!(taken.len(), 1, "{:?}", taken);
        prop_assert_eq!(taken[0].proof.session, main.session);
        prop_assert_eq!(taken[0].proof.action, d);
        let now = c.ports.clock.read().micros();
        prop_assert!(
            !c.ports
                .step_up
                .held()
                .iter()
                .any(|p| p.session == main.session
                    && p.action == d
                    && now.saturating_sub(p.at.micros()) < P71_MICROS),
            "a fresh proof for the digest is still held after the confirmation"
        );
        let e = c.ports.engine.appended();
        prop_assert_eq!(e[0].meta.step_up, Some(taken[0].proof.step_up));
        prop_assert_eq!(e[0].meta.request, d);
        prop_assert_eq!(e[0].meta.pending, Some(view.id));
        let r = c.web(&main, requests::pending_confirm(view.id, &d));
        prop_assert!(class(&r).refused(), "a second confirmation: {:?}", r);
        prop_assert_eq!(appended_kind(&c, CommandKind::PublishCall), 1);
        Ok(())
    });
}

/// `cmd` with the id of its text set to zero. The content digest stays,
/// so two cells that stored the same text give equal commands.
fn without_text_id(cmd: &Command) -> Command {
    match cmd {
        Command::Core(fstp_domain::Command::EditCall {
            call,
            opens,
            deadline,
            deadline_zone,
            budget,
            text,
        }) => Command::Core(fstp_domain::Command::EditCall {
            call: *call,
            opens: *opens,
            deadline: *deadline,
            deadline_zone: deadline_zone.clone(),
            budget: *budget,
            text: TextRef::new(TextId::from_raw(0), text.digest()),
        }),
        other => other.clone(),
    }
}

/// A random edit of a call, valid for the domain.
fn gen_edit(g: &mut fstp_prop::Gen) -> CallEdit {
    let opens = g.i64_in(0..=1_000_000_000_000);
    let span = g.i64_in(1..=1_000_000_000_000);
    let zones = ["Europe/Brussels", "Europe/Lisbon", "Europe/Helsinki"];
    CallEdit {
        opens: fstp_domain::time::Timestamp::from_micros(opens),
        deadline: fstp_domain::time::Timestamp::from_micros(opens.saturating_add(span)),
        deadline_zone: (*g.pick(&zones)).to_owned(),
        budget_cents: g.i64_in(0..=100_000_000_000),
        text: g.string(1..=120),
    }
}

/// I-85, R-MC-05: a confirmation replays the stored canonical request,
/// never arguments resent by the browser. A confirmation that carries
/// members beside the shown digest is refused. The executed command
/// equals the command a direct web call of the same request executes on a
/// twin cell, and the stored request is RFC 8785 canonical JSON.
#[test]
fn i85_confirmation_replays_stored_request() {
    check("i85_confirmation_replays_stored_request", |g| {
        let edit = gen_edit(g);
        g.note("edit", &edit);
        let c = FakeCell::new().map_err(|e| e.to_string())?;
        let owner = c.login(OWNER, LoginMethod::Passkey);
        let r = c.mcp(&owner_token(&c), requests::edit_mcp(CALL_EDIT, &edit));
        prop_assert_eq!(class(&r), Class::Pending, "{:?}", r);
        let view = only_pending(&c, &owner);
        let parsed = fstp_json::parse_str(&view.request)
            .map_err(|e| format!("the stored request is not JSON: {e:?}"))?;
        let canonical = parsed
            .to_canonical()
            .map_err(|e| format!("the stored request has no canonical form: {e:?}"))?;
        prop_assert_eq!(
            canonical,
            view.request.clone(),
            "the stored request is not canonical"
        );

        let resent = vec![("text", Value::String("RESENT BY THE BROWSER".to_owned()))];
        let r = c.web(
            &owner,
            requests::pending_confirm_with(view.id, &view.digest, resent),
        );
        prop_assert_eq!(
            class(&r),
            Class::Refused(ErrorCode::BadRequest),
            "a confirmation with resent arguments: {:?}",
            r
        );
        prop_assert!(c.ports.engine.appended().is_empty());

        let r = c.web(&owner, requests::pending_confirm(view.id, &view.digest));
        prop_assert_eq!(class(&r), Class::Done, "{:?}", r);
        let confirmed = c.ports.engine.appended();
        prop_assert_eq!(confirmed.len(), 1, "{:?}", confirmed);

        let twin = FakeCell::new().map_err(|e| e.to_string())?;
        let twin_owner = twin.login(OWNER, LoginMethod::Passkey);
        let r = twin.web(&twin_owner, requests::edit_web(CALL_EDIT, &edit));
        prop_assert_eq!(class(&r), Class::Done, "the direct web edit: {:?}", r);
        let direct = twin.ports.engine.appended();
        prop_assert_eq!(direct.len(), 1, "{:?}", direct);
        prop_assert_eq!(
            without_text_id(&confirmed[0].cmd),
            without_text_id(&direct[0].cmd),
            "the confirmation executed another request"
        );
        prop_assert_eq!(confirmed[0].ctx.actor, direct[0].ctx.actor);
        prop_assert_eq!(confirmed[0].ctx.via, Via::Web);
        prop_assert_eq!(confirmed[0].meta.pending, Some(view.id));
        prop_assert_eq!(confirmed[0].meta.request, view.digest);
        Ok(())
    });
}
