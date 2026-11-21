//! The `/api/v1` routes (I-17, I-18, I-78, ADR-007, ADR-008, ADR-009,
//! design sections 5.4, 6.5, 6.7 and 8.7).
//!
//! - `POST /api/v1/commands` takes `{command, command_id, stepup?}`. The
//!   gate classes the command through `HighRiskAction::of` and checks the
//!   step-up, and the engine runs it.
//! - `POST /api/v1/vault-tickets` and `POST /api/v1/verifications` issue
//!   vault tickets through the engine, so the issue is a ledger record.
//!   The route then signs the ticket of that record with the cell's
//!   `Ticket` key (ADR-004, design section 6.5) and answers its vault
//!   origin link (lane m3/cell-routes, [`signed_reply`]). A cell with no
//!   `Ticket` key, and a download, which the vault has no ticket kind
//!   for, answer 501 before the engine runs, so no issue record commits
//!   without its ticket.
//! - An `UnmaskParty` through `POST /api/v1/commands` answers the vault
//!   origin link of an `unmask` ticket for the party once its
//!   `PartyUnmasked` record is in the ledger (ADR-023 reading 7).
//! - The audit anchors and the erasure log are for Auditors and tenant
//!   admins (ADR-007, G30). An Auditor reads the erasure entries of the
//!   programmes its bindings name only (Q42, interim).

use std::collections::BTreeSet;

use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, ReadAction};
use fstp_cell_core::release::ReleaseCommand;
use fstp_cell_core::release::{IssuedKind, IssuedTicket};
use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::roles::Role;
use fstp_http::{Request, StatusCode};
use fstp_json::{Array, Object, Value};
use fstp_vault_proto::ticket::WriteKind;
use fstp_vault_proto::{
    TICKET_LIFETIME_MAX_US, TicketClaims, TicketKind, WireAccount, WireProgramme, WireProposal,
    country_scope,
};

use crate::http::body::{self, BodyRefusal};
use crate::http::decode_command_body;
use crate::routes::handle::{
    Caller, Ctx, Reply, admit, bad_body, decimal, exec_failed, hex_value, needs_route_input, run,
    unavailable,
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
    // An address rides with an invitation only (`CommandRequest::email`).
    let invited = match (&command, r.email) {
        (_, None) => None,
        (
            CellCommand::Tenant(fstp_cell_core::tenant::TenantCommand::IssueInvitation {
                token_digest,
                ..
            }),
            Some(email),
        ) => Some((*token_digest, email)),
        (_, Some(_)) => return bad_body(BodyRefusal::Member("email")),
    };
    // ADR-025, issue 6 M9, H-01: a session holder puts a text with an owner
    // and a declared length, which the cell decides on. `PutText` names
    // neither, so this route refuses it.
    if matches!(
        &command,
        CellCommand::Text(fstp_cell_core::text::TextCommand::PutText { .. })
    ) {
        return Reply::refuse(
            fstp_http::StatusCode::FORBIDDEN,
            Some(crate::routes::Rule::Spec("ADR-025")),
            "text",
        );
    }
    // ADR-024: a session holder puts at most `PUT_TEXT_PER_ACCOUNT` texts
    // per window.
    if matches!(
        &command,
        CellCommand::Text(fstp_cell_core::text::TextCommand::PutOwnedText { .. })
    ) && !ctx
        .limits
        .put_text(caller.row.account, ctx.backend.now().micros())
    {
        return Reply::refuse(
            fstp_http::StatusCode::TOO_MANY_REQUESTS,
            Some(crate::routes::Rule::Adr024),
            "rate",
        );
    }
    let blocked = needs_route_input(&command) || runs_no_rerun(&command);
    let unmask = match &command {
        CellCommand::Engine(fstp_engine::Command::Core(
            fstp_domain::command::Command::UnmaskParty {
                programme, subject, ..
            },
        )) => Some((*programme, *subject)),
        _ => None,
    };
    let creator = match &command {
        CellCommand::Engine(fstp_engine::Command::Creator(c)) => Some(c.clone()),
        _ => None,
    };
    // I-52: a publication carries the Guide the shell supplies.
    let published = match &command {
        CellCommand::Engine(fstp_engine::Command::Core(
            fstp_domain::command::Command::PublishCall { call, .. },
        )) => Some(*call),
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
        Ok((s, a)) => match (&creator, published) {
            // ADR-027: fresh facts, so the shell runs its probes and reads
            // the stored texts in this request.
            (Some(c), _) => a.with_creator(ctx.backend.creator_facts_fresh(&s, c).await),
            (None, Some(call)) => a.with_creator(fstp_cell_core::creator::CreatorFacts {
                guide: ctx.backend.guide_inputs_fresh(&s, call).await,
                ..Default::default()
            }),
            (None, None) => a,
        },
        Err(reply) => return reply,
    };
    if blocked {
        // The batch needs a route input that `decide` cannot take yet
        // (`fstp_cell_core::RouteInput`), or it is a re-run this cell
        // cannot run ([`runs_no_rerun`]).
        return Reply::not_built();
    }
    // ADR-023 reading 7: an unmask answers its ticket, so it never
    // commits on a cell that cannot sign one.
    if let Some(unmask) = unmask {
        let Some(key) = ctx.backend.ticket_key() else {
            return Reply::not_built();
        };
        return run_unmask(ctx, admitted, unmask, &key).await;
    }
    // The address is kept for the enrolment once the gate admitted the
    // invitation. A refused invitation leaves a kept address no token
    // can reach.
    if let Some((digest, email)) = invited
        && let Err(f) = ctx.backend.note_invitation_email(digest, email).await
    {
        return unavailable(f);
    }
    run(ctx, admitted).await
}

/// Whether `command` asks for a re-run of an assessment (issue 6 M3, I-10).
///
/// This cell wires no assessor and no API core yet (M7 design section
/// 3.4), so nothing would run the re-run, record its result as the system
/// and end it. A recorded request would hold the proposal's in-flight slot
/// and use one of its `MAX_RERUNS`. So the route answers 501 before the
/// engine runs, as the API core answers "unavailable" when its port cannot
/// re-run. Interim, until the production cell gets an assessor.
fn runs_no_rerun(command: &CellCommand) -> bool {
    matches!(
        command,
        CellCommand::Engine(fstp_engine::Command::Finding(
            fstp_engine::FindingCommand::RequestRerun { .. }
        ))
    )
}

/// Issues a vault ticket (I-17, R-AU-01, design section 6.5).
///
/// The gate admits the issue command first, so a refusal answers as any
/// command's. The engine then commits the issue record
/// (`IdentityReleaseIssued` or `TicketIssued`), which logs the read, and
/// the route signs the ticket of that record ([`signed_reply`]). The
/// record and the signed ticket belong in one reply, so a cell with no
/// `Ticket` key answers 501 before the engine runs and commits nothing.
/// So does a download: the vault has no ticket kind for the download
/// scope yet. A retry under the same command id commits nothing again
/// and signs the stored record's ticket anew, with the same nonce, so
/// the vault still admits one use.
async fn issue<B: Backend>(
    ctx: &Ctx<B>,
    caller: &Caller,
    command: CellCommand,
    id: [u8; 16],
    stepup: Option<[u8; 16]>,
) -> Reply {
    let download = matches!(
        command,
        CellCommand::Release(ReleaseCommand::IssueDownloadTicket { .. })
    );
    let admitted = match admit(ctx, caller, Action::Command(command), Some(id), stepup).await {
        Ok((_, a)) => a,
        Err(reply) => return reply,
    };
    let Some(key) = ctx.backend.ticket_key() else {
        return Reply::not_built();
    };
    if download {
        return Reply::not_built();
    }
    match ctx.backend.execute(admitted).await {
        Err(f) => unavailable(f),
        Ok(Err(e)) => exec_failed(&e),
        Ok(Ok(_)) => {
            let s = match ctx.backend.state().await {
                Ok(s) => s,
                Err(f) => return unavailable(f),
            };
            match s.issued_by(id).and_then(|t| claims_of(ctx, &s, &t)) {
                Some((claims, page)) => signed_reply(ctx, &claims, page, &key),
                None => Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal"),
            }
        }
    }
}

/// The vault origin page a ticket opens: `/r` for a release, `/w` for a
/// write (ADR-009 "Vault origin").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VaultPage {
    Release,
    Write,
}

impl VaultPage {
    const fn path(self) -> &'static str {
        match self {
            VaultPage::Release => "/r",
            VaultPage::Write => "/w",
        }
    }
}

/// The programme of proposal `p`, from its call.
fn programme_of(s: &fstp_cell_core::CellState, p: ProposalId) -> Option<(ProgrammeId, AccountId)> {
    let (call, lead) = s.proposal(p)?;
    let programme = fstp_domain::programme::call(&s.engine().core, call)?.programme();
    Some((programme, lead))
}

/// The claims of the ticket the ledger issued as `t`, and the page it
/// opens (design section 6.5, ADR-009 "Format"):
///
/// - a release names the proposal's lead as its subject, which the
///   vault's negotiation fact must list, and the proposal's programme as
///   its scope. Interim, pending Daniel: the request names no subject, so
///   the lead's identity is the one released;
/// - a write names its holder as the writer, the proposal, and the
///   programme scope.
///
/// The ticket id of the record is the nonce, and the ticket lives for the
/// ADR-009 bound from now.
fn claims_of<B: Backend>(
    ctx: &Ctx<B>,
    s: &fstp_cell_core::CellState,
    t: &IssuedTicket,
) -> Option<(TicketClaims, VaultPage)> {
    // ADR-004 record of lane L13b, row "Ticket": a verification ticket
    // names its person in the scope, and a proposal only for an applicant.
    let (kind, account, page, scope) = match t.kind {
        IssuedKind::Verification(subject) => (
            TicketKind::Write(WriteKind::VerificationRecorded),
            t.holder,
            VaultPage::Write,
            fstp_vault_proto::person_scope(WireAccount(subject.raw())),
        ),
        IssuedKind::Release | IssuedKind::Write(_) => {
            let (programme, lead) = programme_of(s, ProposalId::from_raw(t.proposal?))?;
            let scope = country_scope(WireProgramme(programme.raw()));
            match t.kind {
                IssuedKind::Write(code) => {
                    let w = WriteKind::ALL.iter().copied().find(|w| w.code() == code)?;
                    (TicketKind::Write(w), t.holder, VaultPage::Write, scope)
                }
                _ => (TicketKind::Release, lead, VaultPage::Release, scope),
            }
        }
        IssuedKind::Download => return None,
    };
    let now = ctx.backend.now().micros();
    Some((
        TicketClaims {
            kind,
            cell: ctx.cfg.cell,
            account: WireAccount(account.raw()),
            proposal: t.proposal.map(WireProposal),
            scope,
            issued_at: now,
            expires_at: now.checked_add(TICKET_LIFETIME_MAX_US)?,
            nonce: t.id,
        },
        page,
    ))
}

/// The vault origin of the cell: `id.<cell host>` on the cell's scheme
/// (ADR-009 "Vault origin").
fn vault_origin<B>(ctx: &Ctx<B>) -> String {
    match ctx.cfg.origin.split_once("://") {
        Some((scheme, host)) => format!("{scheme}://id.{host}"),
        None => format!("https://id.{}", ctx.cfg.origin),
    }
}

/// The signed ticket of `claims`, the canonical body followed by the
/// Ed25519 signature of the cell's `Ticket` key over it (the framing of
/// `fstp_vault_proto::ticket`), as the reply
/// `{expires_at, kind, ticket, url}`. `url` is the vault origin page
/// with the ticket in its fragment, which the browser never sends to a
/// server (design section 6.5).
fn signed_reply<B>(
    ctx: &Ctx<B>,
    claims: &TicketClaims,
    page: VaultPage,
    key: &fstp_crypto::sig::Ed25519SigningKey,
) -> Reply {
    let Ok(mut bytes) = claims.canonical() else {
        return Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal");
    };
    let Ok(signature) = key.sign(&bytes) else {
        return unavailable(crate::routes::BackendFault::Unavailable);
    };
    bytes.extend_from_slice(&signature);
    let ticket = crate::http::body::hex(&bytes);
    let mut o = Object::with_capacity(4);
    o.insert("expires_at", decimal(claims.expires_at));
    o.insert("kind", Value::String(claims.kind.label()));
    o.insert(
        "url",
        Value::String(format!("{}{}#{ticket}", vault_origin(ctx), page.path())),
    );
    o.insert("ticket", Value::String(ticket));
    Reply::json(StatusCode::OK, &Value::Object(o))
}

/// Runs an admitted `UnmaskParty` and answers the `unmask` ticket of the
/// party (ADR-023 readings 7 and 8). The ticket names the party's
/// account and the programme scope, and no proposal. It is signed only
/// once the `PartyUnmasked` record is in the ledger: a retry under the
/// same command id finds it there and signs a fresh ticket.
async fn run_unmask<B: Backend>(
    ctx: &Ctx<B>,
    admitted: fstp_cell_core::gate::Admitted,
    unmask: (ProgrammeId, fstp_domain::unmask::UnmaskSubject),
    key: &fstp_crypto::sig::Ed25519SigningKey,
) -> Reply {
    let (programme, subject) = unmask;
    match ctx.backend.execute(admitted).await {
        Err(f) => unavailable(f),
        Ok(Err(e)) => exec_failed(&e),
        Ok(Ok(_)) => {
            let s = match ctx.backend.state().await {
                Ok(s) => s,
                Err(f) => return unavailable(f),
            };
            let Some((_, account)) =
                fstp_domain::unmask::party_of(&s.engine().core, programme, subject)
            else {
                return Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal");
            };
            let nonce = match crate::routes::handle::random::<16>() {
                Ok(n) => n,
                Err(r) => return r,
            };
            let now = ctx.backend.now().micros();
            let Some(expires_at) = now.checked_add(TICKET_LIFETIME_MAX_US) else {
                return Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal");
            };
            let claims = TicketClaims {
                kind: TicketKind::Unmask,
                cell: ctx.cfg.cell,
                account: WireAccount(account.raw()),
                proposal: None,
                scope: country_scope(WireProgramme(programme.raw())),
                issued_at: now,
                expires_at,
                nonce,
            };
            signed_reply(ctx, &claims, VaultPage::Release, key)
        }
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
/// or `write:<kind label>` of ADR-009, which takes none. The one write
/// that names a proposal is `write:country_stated`: the lead states the
/// P-17 country of a draft (`proposal.state_country`, R-NG-01). The
/// ticket opens the vault origin's write page, and the browser sends the
/// country there, so the cell never receives it. A `download` is
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
        // `proposal.state_country` (R-NG-01, overview NOTE 6, lane
        // m4/country): the lead's country write names its draft.
        ("write:country_stated", Some(proposal)) => ReleaseCommand::IssueCountryTicket { proposal },
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

/// `POST /api/v1/verifications` (ADR-008 "Manual identity checks", ADR-004
/// record of lane L13b): `{account, command_id, proposal?}`. It asks for a
/// `VerificationRecorded` write ticket for the person `account`, and for
/// an applicant the proposal. The cell
/// decides who may have one (`IssueVerificationTicket`): a verified tenant
/// admin with no Judging binding and no binding on the proposal, sharing
/// no identity with its accounts, for a proposal in NEGOTIATION or later.
/// The recorder enters the outcome and the identity attributes on the
/// vault origin, so the cell never receives them (I-17).
pub(crate) async fn verifications<B: Backend>(
    ctx: &Ctx<B>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let (id, account, proposal) = match decode_verification(&req.body) {
        Ok(x) => x,
        Err(e) => return bad_body(e),
    };
    let command = CellCommand::Release(ReleaseCommand::IssueVerificationTicket {
        account: AccountId::from_raw(account),
        proposal,
    });
    issue(ctx, caller, command, id, None).await
}

fn decode_verification(bytes: &[u8]) -> Result<([u8; 16], u128, Option<u128>), BodyRefusal> {
    let o = body::object(bytes, AUTH_BODY_LIMIT)?;
    body::members(&o, &["account", "command_id"], &["proposal"])?;
    let id = body::hex_member::<16>(&o, "command_id")?;
    let account =
        canonical_u128(body::string(&o, "account")?).ok_or(BodyRefusal::Member("account"))?;
    let proposal = match o.get("proposal") {
        None => None,
        Some(_) => Some(
            canonical_u128(body::string(&o, "proposal")?).ok_or(BodyRefusal::Member("proposal"))?,
        ),
    };
    Ok((id, account, proposal))
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

/// `GET /api/v1/verification-people` (ADR-004 record of lane L13b, row
/// "Staff app"): the people a tenant admin may record a verification for
/// on the vault origin, as `{people: [{account, proposal, role}]}`. They
/// are the accounts bound to a proposal in NEGOTIATION or later
/// (R-NG-01), by id and role only, never a name or attribute (I-17). The
/// reader is a tenant admin with no Judging binding, as for the ticket
/// itself, and never sees their own account. The cell decides each
/// ticket again (`IssueVerificationTicket`).
pub(crate) async fn verification_people<B: Backend>(ctx: &Ctx<B>, caller: &Caller) -> Reply {
    let s = match ctx.backend.state().await {
        Ok(s) => s,
        Err(f) => return unavailable(f),
    };
    let actor = caller.view.account;
    let core = &s.engine().core;
    let judging = core
        .roster()
        .bindings()
        .any(|(_, b)| b.account == actor && b.group() == fstp_domain::roles::Group::Judging);
    if !s.tenant().is_admin(actor) || judging {
        return Reply::refuse(StatusCode::FORBIDDEN, None, "verification-people");
    }
    let mut rows = Vec::new();
    for (_, b) in core.roster().bindings() {
        let Some(p) = b.proposal() else {
            continue;
        };
        if !b.held() || b.account == actor || b.group() != fstp_domain::roles::Group::Receiving {
            continue;
        }
        let open = fstp_domain::view::proposal_state(core, p)
            .is_some_and(|st| fstp_cell_core::RELEASE_STATES.contains(&st));
        if open {
            rows.push((
                p.raw(),
                b.account.raw(),
                fstp_access::role_wire_name(b.role),
            ));
        }
    }
    rows.sort_unstable();
    rows.dedup();
    let list: Array = rows
        .into_iter()
        .map(|(p, a, role)| {
            let mut o = Object::with_capacity(3);
            o.insert("account", Value::String(a.to_string()));
            o.insert("proposal", Value::String(p.to_string()));
            o.insert("role", Value::String(role.to_owned()));
            Value::Object(o)
        })
        .collect();
    let mut o = Object::with_capacity(1);
    o.insert("people", Value::Array(list));
    Reply::json(StatusCode::OK, &Value::Object(o))
}
