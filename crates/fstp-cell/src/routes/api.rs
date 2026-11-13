//! The `/api/v1` routes (I-17, I-18, I-78, ADR-007, ADR-008, ADR-009,
//! design sections 5.4, 6.5, 6.7 and 8.7).
//!
//! - `POST /api/v1/commands` takes `{command, command_id, stepup?}`. The
//!   gate classes the command through `HighRiskAction::of` and checks the
//!   step-up, and the engine runs it.
//! - `POST /api/v1/vault-tickets` and `POST /api/v1/verifications` issue
//!   vault tickets through the engine, so the issue is a ledger record.
//!   Signing and returning the ticket needs the issued ticket's claims and
//!   the cell's `Ticket` key, which the route layer cannot reach yet. So
//!   a request the gate admits answers 501 before the engine runs it. No
//!   issue record commits, and no ticket exists.
//! - The audit anchors and the erasure log are for Auditors and tenant
//!   admins (ADR-007, G30). An Auditor reads the erasure entries of the
//!   programmes its bindings name only (Q42, interim).

use std::collections::BTreeSet;

use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, ReadAction};
use fstp_cell_core::release::ReleaseCommand;
use fstp_domain::roles::Role;
use fstp_http::{Request, StatusCode};
use fstp_json::{Array, Object, Value};
use fstp_vault_proto::ticket::WriteKind;

use crate::http::body::{self, BodyRefusal};
use crate::http::decode_command_body;
use crate::routes::handle::{
    Caller, Ctx, Reply, admit, bad_body, decimal, hex_value, needs_route_input, run, unavailable,
};
use crate::routes::{AUTH_BODY_LIMIT, Backend};

/// `POST /api/v1/commands` (per command, I-78, I-18).
pub(crate) async fn commands<B: Backend>(ctx: &Ctx<B>, req: &Request, caller: &Caller) -> Reply {
    let r = match decode_command_body(&req.body) {
        Ok(r) => r,
        Err(e) => return bad_body(e),
    };
    let Some(command) = r.command.map(|c| *c) else {
        return bad_body(BodyRefusal::Member("command"));
    };
    let blocked = needs_route_input(&command);
    let creator = match &command {
        CellCommand::Engine(fstp_engine::Command::Creator(c)) => Some(c.clone()),
        _ => None,
    };
    let admitted = match admit(
        ctx,
        caller,
        Action::Command(command),
        Some(r.command_id),
        r.stepup,
    )
    .await
    {
        // A creator command reads the shell's facts (`crate::shell`).
        Ok((s, a)) => match &creator {
            Some(c) => a.with_creator(ctx.backend.creator_facts(&s, c)),
            None => a,
        },
        Err(reply) => return reply,
    };
    if blocked {
        // The batch needs a route input that `decide` cannot take yet
        // (`fstp_cell_core::RouteInput`).
        return Reply::not_built();
    }
    run(ctx, admitted).await
}

/// Runs a ticket issue up to the gate, then answers 501 before the engine
/// sees it (I-17, R-AU-01, design section 6.5).
///
/// The issue record and the signed ticket belong in one reply. When the
/// engine commits an issue, it appends `IdentityReleaseIssued` or
/// `TicketIssued`, and that record logs the identity-attribute read. The
/// route cannot sign the ticket yet. Committing now would log a release
/// or a write ticket that never happened, once per retry. So a request
/// the gate admits stops here and decides nothing, as a command that
/// needs a route input does. A gate refusal answers as any command's.
/// Once the issued claims and the `Ticket` key reach the route layer, the
/// route commits the issue and returns the signed ticket in one reply.
async fn issue<B: Backend>(
    ctx: &Ctx<B>,
    caller: &Caller,
    command: CellCommand,
    id: [u8; 16],
    stepup: Option<[u8; 16]>,
) -> Reply {
    match admit(ctx, caller, Action::Command(command), Some(id), stepup).await {
        Ok(_) => Reply::not_built(),
        Err(reply) => reply,
    }
}

/// The members of a vault ticket request.
const TICKET_REQUIRED: [&str; 2] = ["command_id", "kind"];
/// The optional members of a vault ticket request.
const TICKET_OPTIONAL: [&str; 2] = ["proposal", "stepup"];

/// A decimal `u128` with one spelling: no sign, no leading zero.
fn canonical_u128(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    let ok = match b {
        [] => false,
        [b'0'] => true,
        [b'0', ..] => false,
        _ => b.iter().all(u8::is_ascii_digit),
    };
    if ok { s.parse().ok() } else { None }
}

/// The command of a vault ticket request: `{command_id, kind, proposal?,
/// stepup?}`. `kind` is `release` or `download`, which need `proposal`,
/// or `write:<kind label>` of ADR-009, which takes none. A `download` is
/// `IssueDownloadTicket`, the high-risk action `IdentityDownload`
/// (ADR-008, design section 8.7), so the gate asks for its step-up.
/// A decoded vault ticket request.
struct TicketRequest {
    command: CellCommand,
    command_id: [u8; 16],
    stepup: Option<[u8; 16]>,
}

fn decode_ticket(bytes: &[u8]) -> Result<TicketRequest, BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &TICKET_REQUIRED, &TICKET_OPTIONAL)?;
    let id = body::hex_member::<16>(&o, "command_id")?;
    let stepup = body::optional_hex::<16>(&o, "stepup")?;
    let kind = body::string(&o, "kind")?;
    let proposal = match o.get("proposal") {
        None => None,
        Some(_) => Some(
            canonical_u128(body::string(&o, "proposal")?).ok_or(BodyRefusal::Member("proposal"))?,
        ),
    };
    let release = match (kind, proposal) {
        ("release", Some(proposal)) => ReleaseCommand::IssueReleaseTicket { proposal },
        ("download", Some(proposal)) => ReleaseCommand::IssueDownloadTicket { proposal },
        ("release" | "download", None) => return Err(BodyRefusal::Member("proposal")),
        (k, None) => {
            let label = k
                .strip_prefix("write:")
                .ok_or(BodyRefusal::Member("kind"))?;
            let w = WriteKind::ALL
                .iter()
                .find(|w| w.label() == label)
                .ok_or(BodyRefusal::Member("kind"))?;
            ReleaseCommand::IssueWriteTicket { kind: w.code() }
        }
        (_, Some(_)) => return Err(BodyRefusal::Member("proposal")),
    };
    Ok(TicketRequest {
        command: CellCommand::Release(release),
        command_id: id,
        stepup,
    })
}

/// `POST /api/v1/vault-tickets` (Session; `IdentityDownload` for the
/// download scope, I-17, design section 6.5).
pub(crate) async fn vault_tickets<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    match decode_ticket(&req.body) {
        Ok(t) => issue(ctx, caller, t.command, t.command_id, t.stepup).await,
        Err(e) => bad_body(e),
    }
}

/// `POST /api/v1/verifications` (ADR-008 "Manual identity checks"):
/// `{command_id}`. It asks for a `VerificationRecorded` write ticket. The
/// engine decides who may have one: a tenant admin with a verified
/// identity, inside the release window, and never for their own account.
/// Until the ticket can be signed, the route stops after the gate
/// ([`issue`]), so the engine refuses or commits nothing yet.
pub(crate) async fn verifications<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let id = match decode_verification(&req.body) {
        Ok(id) => id,
        Err(e) => return bad_body(e),
    };
    let command = CellCommand::Release(ReleaseCommand::IssueWriteTicket {
        kind: WriteKind::VerificationRecorded.code(),
    });
    issue(ctx, caller, command, id, None).await
}

fn decode_verification(bytes: &[u8]) -> Result<[u8; 16], BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &["command_id"], &[])?;
    body::hex_member::<16>(&o, "command_id")
}

/// `GET /api/v1/audit/anchors` (Auditor or tenant admin, ADR-007, G30).
pub(crate) async fn anchors<B: Backend>(ctx: &Ctx<B>, caller: &Caller) -> Reply {
    if let Err(reply) = admit(ctx, caller, Action::Read(ReadAction::ReadAudit), None, None).await {
        return reply;
    }
    let rows = match ctx.backend.anchors().await {
        Ok(r) => r,
        Err(f) => return unavailable(f),
    };
    let list: Array = rows
        .iter()
        .map(|a| {
            let mut o = Object::with_capacity(4);
            o.insert("at", decimal(a.at));
            o.insert("link", hex_value(&a.link));
            o.insert("n", decimal(a.n));
            o.insert("witness_seq", decimal(a.witness_seq));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::with_capacity(1);
    o.insert("anchors", Value::Array(list));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// `GET /api/v1/erasures` (Auditor or tenant admin, ADR-007, G30, Q42).
/// A tenant admin reads every entry. An Auditor reads the entries of the
/// programmes its active Auditor bindings name, and no tenant-wide entry.
pub(crate) async fn erasures<B: Backend>(ctx: &Ctx<B>, caller: &Caller) -> Reply {
    let (s, _) = match admit(
        ctx,
        caller,
        Action::Read(ReadAction::ReadErasureLog),
        None,
        None,
    )
    .await
    {
        Ok(x) => x,
        Err(reply) => return reply,
    };
    let rows = match ctx.backend.erasures().await {
        Ok(r) => r,
        Err(f) => return unavailable(f),
    };
    let now = ctx.backend.now();
    let account = caller.view.account;
    let admin = s.tenant().is_admin(account);
    let audited: BTreeSet<u128> = s
        .engine()
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| {
            b.account == account
                && b.role == Role::Auditor
                && b.active_at(now)
                && b.scheduled_end.is_none_or(|e| now < e)
        })
        .map(|(_, b)| b.programme.raw())
        .collect();
    let list: Array = rows
        .iter()
        .filter(|e| admin || e.programme.is_some_and(|p| audited.contains(&p)))
        .map(|e| {
            let mut o = Object::with_capacity(4);
            o.insert("cause", decimal(e.cause));
            o.insert("completed_at", e.completed_at.map_or(Value::Null, decimal));
            o.insert("requested_at", decimal(e.requested_at));
            o.insert("text", hex_value(&e.text));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::with_capacity(1);
    o.insert("erasures", Value::Array(list));
    Reply::json(StatusCode::OK, &Value::Object(o))
}
