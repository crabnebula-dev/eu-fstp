//! The seeding and command builder routes of `fstp-devstack e2e` (lane
//! m3/devstack-scenarios). Local development and tests only: they live in
//! this test binary, on its loopback control listener, and no cell origin
//! ever answers them.
//!
//! # Who enrols the first admin
//!
//! The world's cycle client ([`fstp_celltest::cycle`]) enrols the first
//! admin itself through the split invitation. A spec that enrols the
//! first admin in the browser has used that invitation. So each route
//! below takes one side:
//!
//! - `POST /test/scenario/negotiation` needs a cell whose first admin
//!   nobody enrolled. Its cycle client enrols the first admin and seeds
//!   the scenario as that admin. On a cell whose first admin the browser
//!   enrolled it answers 409, and the spec resets the cell first.
//! - `POST /test/commands/CreateProgramme` serves the browser's first
//!   admin. It hands that admin each command that only a tenant admin can
//!   send, one per call: the invitation of a stand-in admin, then that
//!   admin's tenant admin grant. The stand-in then runs the creator path
//!   of the cycle in place of the first admin (M4 design section 3.4):
//!   it invites a second tenant admin, opens the draft and grants the
//!   builder, the builder requests activation, and the second admin, who
//!   built nothing, approves it (I-66, I-67). The call after that answers
//!   `{command: null}` with the active programme.
//!
//! # Claims
//!
//! Every verification, the applicants' over-18 attestations and the
//! grantees' verifications are seeded (design section 6.9). The write
//! ticket of `POST /test/vault-tickets/write` is signed by the world with
//! the cell's `Ticket` key (`CellHandle::sign_ticket`), since the cell
//! issues no write ticket of that kind yet.
//!
//! The cell pushes no negotiation fact to its vault when NEGOTIATION
//! opens (design section 6.5 "Second guard"), so its vault refuses every
//! release. The scenario sends the vault that fact for its proposal
//! (`CellHandle::negotiation_opened`), through the vault's own internal
//! request. The I-17 browser specs rest on that stand-in.

#![allow(
    clippy::disallowed_macros,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::collections::BTreeSet;

use fstp_cell_core::CellCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_celltest::cycle::{Cycle, grant};
use fstp_celltest::mc::auth_model::http::{AuthClient, ClientMemory, Cookie, FIRST_ADMIN};
use fstp_celltest::vault_seed::SeedError;
use fstp_celltest::world::CellHandle;
use fstp_domain::id::{AccountId, BindingId, OrganisationId, ProgrammeId, ProposalId};
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::roster::P1;
use fstp_http::StatusCode;
use fstp_json::{Object, Value};
use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProgramme, WriteKind};

use crate::{ENROL_PAGE, hex};

/// The steps that leave a proposal of the first call in RANKED: scored
/// and ranked, with no cut-off.
const RANKED_STEPS: [&str; 8] = [
    "login",
    "create-programme",
    "publish-call",
    "signup",
    "verify-identity",
    "submit-proposal",
    "score",
    "rank",
];

/// The steps that take a proposal of a second call to NEGOTIATION: the
/// cut-off and the IRC validations, which push the negotiation fact to
/// the vault. Its lead then states a country for the programme on the
/// vault origin. The first call's proposal stays RANKED, since the
/// cut-off of the second call names only the second call's proposals.
/// The clock moves no more after this script, so no invitation of the
/// scenario expires and no negotiation closes.
const NEGOTIATION_STEPS: [&str; 8] = [
    "publish-call",
    "signup",
    "verify-identity",
    "submit-proposal",
    "score",
    "rank",
    "negotiate",
    "vault-origin:write:country_stated:250",
];

/// The role of the scenario's Operations holder.
const OPERATIONS_ROLE: Role = Role::FinanceApprover;

/// The role of the scenario's Judging holder.
const JUDGING_ROLE: Role = Role::CommitteeMember;

/// The lifetime of a write ticket the stack signs: the ADR-009 bound.
const WRITE_TICKET_LIFE_US: i64 = fstp_vault_proto::TICKET_LIFETIME_MAX_US;

/// A refused control request: its status, code and detail.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) detail: String,
}

impl Refusal {
    fn conflict(detail: &str) -> Refusal {
        Refusal {
            status: StatusCode::CONFLICT,
            code: "conflict",
            detail: detail.to_owned(),
        }
    }

    fn bad(detail: &str) -> Refusal {
        Refusal {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            detail: detail.to_owned(),
        }
    }

    fn failed(detail: String) -> Refusal {
        eprintln!("fstp-devstack e2e: {detail}");
        Refusal {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "world",
            detail,
        }
    }
}

/// The stand-in admin of a browser's creator path.
struct StandIn {
    /// The stand-in's cell account.
    account: AccountId,
    /// Its invitation token, which the stack keeps.
    token: [u8; 32],
    /// The client once the stand-in enrolled.
    client: Option<ClientMemory>,
}

/// What the stack seeded on one cell since the world started.
#[derive(Default)]
pub(crate) struct Seeded {
    /// The stand-in admin of `CreateProgramme`, once drawn.
    stand_in: Option<StandIn>,
    /// Whether P1 is active.
    programme: bool,
    /// The lead of the negotiation scenario's proposal.
    subject: Option<AccountId>,
    /// The accounts whose verification the command builder seeded.
    verified: BTreeSet<AccountId>,
}

/// `obj` of `members`.
fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// The decimal form of a `u128`, as the cell's ticket route takes a
/// proposal.
fn decimal(n: u128) -> Value {
    Value::from(n.to_string())
}

/// A canonical decimal `u128`: digits only, no leading zero.
fn parse_decimal(s: &str) -> Option<u128> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

/// The JSON of `command` as `POST /api/v1/commands` takes it.
fn command_json(command: &CellCommand) -> Result<Value, Refusal> {
    let bytes = fstp_cell_core::encode_cell_command(command);
    fstp_json::parse(&bytes).map_err(|e| Refusal::failed(format!("the command JSON: {e:?}")))
}

/// Sixteen random bytes as an id.
fn random_id() -> Result<u128, Refusal> {
    fstp_crypto::random_array::<16>()
        .map(u128::from_be_bytes)
        .map_err(|e| Refusal::failed(format!("a random id: {e:?}")))
}

/// A fresh cell account id. The low bit is set, so it is never zero.
fn fresh_account() -> Result<AccountId, Refusal> {
    Ok(AccountId::from_raw(random_id()? | 1))
}

/// The cell's ledger.
fn ledger(
    cell: &CellHandle,
) -> Result<Vec<fstp_ledger::Entry<fstp_cell_core::CellRecord>>, Refusal> {
    cell.ledger()
        .map_err(|e| Refusal::failed(format!("the ledger read: {e}")))
}

/// The cell's state, replayed from its ledger.
fn state(cell: &CellHandle) -> Result<fstp_cell_core::CellState, Refusal> {
    fstp_cell_core::replay(&ledger(cell)?)
        .map_err(|e| Refusal::failed(format!("the ledger replay: {e:?}")))
}

/// The first admin's cell account, once someone enrolled it.
fn first_admin(cell: &CellHandle) -> Result<Option<AccountId>, Refusal> {
    Ok(ledger(cell)?.iter().find_map(|e| match &e.record {
        fstp_cell_core::CellRecord::Auth(fstp_auth::AuthRecord::FirstAdminEnrolled { account }) => {
            Some(*account)
        }
        _ => None,
    }))
}

/// The newest proposal in the cell's ledger and its lead.
fn newest_proposal(cell: &CellHandle) -> Result<(ProposalId, AccountId), Refusal> {
    ledger(cell)?
        .iter()
        .rev()
        .find_map(|e| match &e.record {
            fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(
                fstp_domain::Record::ProposalCreated { proposal, lead, .. },
            )) => Some((*proposal, *lead)),
            _ => None,
        })
        .ok_or_else(|| Refusal::failed("the scenario drafted no proposal".to_owned()))
}

/// Seeds a verification of `account` with a synthetic attribute tuple of
/// its own (design section 6.9), so no two accounts share an identity.
fn seed_verification(cell: &CellHandle, account: AccountId) -> Result<(), Refusal> {
    let tuple = format!("synthetic-devstack-person-{}", account.raw());
    cell.seed_verification(account, tuple.as_bytes())
        .map(|_| ())
        .map_err(|e: SeedError| Refusal::failed(format!("the seeded verification: {e}")))
}

/// The `GrantRole` of `role` on `programme` to `account` from `start`,
/// with the organisation a committee member needs (P-39).
fn grant_command(
    programme: ProgrammeId,
    account: AccountId,
    role: Role,
    start: i64,
) -> Result<(CellCommand, BindingId), Refusal> {
    let binding = BindingId::from_raw(random_id()?);
    let mut command = grant(binding, account, role, start);
    if let CellCommand::Engine(fstp_engine::Command::Core(fstp_domain::Command::GrantRole {
        programme: p,
        organisation,
        ..
    })) = &mut command
    {
        *p = programme;
        if role == Role::CommitteeMember {
            *organisation = Some(OrganisationId::from_raw(account.raw()));
        }
    }
    Ok((command, binding))
}

/// The invitation link of `token` on the cell origin.
fn invite_url(cell: &CellHandle, token: &[u8; 32]) -> String {
    format!("https://{}{ENROL_PAGE}#{}", cell.host(), hex(token))
}

/// Issues an invitation for a new account as the first admin, seeds its
/// verification and grants it `role` on P1, each command with a step-up.
/// The browser enrols the account through the link this gives.
fn invited_holder(
    cycle: &Cycle<'_>,
    admin: &Cookie,
    role: Role,
) -> Result<(AccountId, String), Refusal> {
    let client = cycle.client();
    let cell = client.cell();
    let account = fresh_account()?;
    let token = fstp_crypto::random_array::<32>()
        .map_err(|e| Refusal::failed(format!("an invitation token: {e:?}")))?;
    let invitation = fstp_crypto::random_array::<16>()
        .map_err(|e| Refusal::failed(format!("an invitation id: {e:?}")))?;
    let issue = CellCommand::Tenant(TenantCommand::IssueInvitation {
        invitation,
        account,
        token_digest: fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(token)),
    });
    let sent = |what: &str, c: &CellCommand| -> Result<(), Refusal> {
        match client.command_with_stepup(admin, c) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Refusal::failed(format!("the cell refused {what}"))),
            Err(e) => Err(Refusal::failed(format!("{what}: {e}"))),
        }
    };
    sent("the holder's IssueInvitation", &issue)?;
    seed_verification(cell, account)?;
    let (g, _) = grant_command(P1, account, role, cell.clock().now())?;
    sent(&format!("the {role:?} GrantRole"), &g)?;
    Ok((account, invite_url(cell, &token)))
}

/// Runs `steps` on `cycle`, or refuses with the step's seam.
fn run(cycle: &mut Cycle<'_>, steps: &[&str]) -> Result<(), Refusal> {
    let steps: Vec<String> = steps.iter().map(|s| (*s).to_owned()).collect();
    cycle
        .run(&steps)
        .map_err(|e| Refusal::failed(format!("the scenario's cycle: {e}")))
}

/// The state of `proposal`, which must be `want`.
fn expect_state(cell: &CellHandle, proposal: ProposalId, want: StateTag) -> Result<(), Refusal> {
    let s = state(cell)?;
    let got = fstp_domain::view::proposal_state(&s.engine().core, proposal);
    if got == Some(want) {
        Ok(())
    } else {
        Err(Refusal::failed(format!(
            "proposal {} is in {got:?}, not {want:?}",
            proposal.raw()
        )))
    }
}

/// `POST /test/scenario/negotiation` (design section 6.9 seeding, I-17):
/// a proposal in NEGOTIATION whose lead's verification and country the
/// vault holds, a proposal of the same programme in RANKED, and the
/// invitations of an Operations and a Judging holder of the programme,
/// whom the browser enrols.
///
/// `released` names the subject's account id. The M3 release document
/// shows the subject's account, whether it is verified and its stated
/// country code (`fstp_vault::origin`): no name or document exists in
/// the M3 vault. The country code is a number from 1 to 999, which other
/// text matches by chance, so only the random account id serves as a
/// canary. No response of the cell origin to the Operations holder names
/// it.
pub(crate) fn negotiation(cell: &CellHandle, seeded: &mut Seeded) -> Result<Value, Refusal> {
    if first_admin(cell)?.is_some() || seeded.stand_in.is_some() || seeded.programme {
        return Err(Refusal::conflict(
            "the scenario enrols the first admin itself: reset the cell, then ask for the scenario before anyone uses the first-admin link",
        ));
    }
    let mut cycle = Cycle::new(cell);
    run(&mut cycle, &RANKED_STEPS)?;
    let (ranked, ranked_lead) = newest_proposal(cell)?;
    run(&mut cycle, &NEGOTIATION_STEPS)?;
    let (proposal, lead) = newest_proposal(cell)?;
    seeded.programme = true;
    expect_state(cell, ranked, StateTag::Ranked)?;
    expect_state(cell, proposal, StateTag::Negotiation)?;
    // The cell pushes no negotiation fact yet, so the world sends it
    // (module documentation, "Claims").
    cell.negotiation_opened(proposal, &[lead])
        .map_err(|e| Refusal::failed(format!("the negotiation fact: {e}")))?;
    let admin = cycle
        .admin_session()
        .ok_or_else(|| Refusal::failed("the cycle holds no admin session".to_owned()))?;
    let (_, operations) = invited_holder(&cycle, &admin, OPERATIONS_ROLE)?;
    let (_, judging) = invited_holder(&cycle, &admin, JUDGING_ROLE)?;
    seeded.subject = Some(lead);
    Ok(obj(vec![
        ("programme", decimal(P1.raw())),
        ("proposal", decimal(proposal.raw())),
        ("subject", decimal(lead.raw())),
        ("ranked_proposal", decimal(ranked.raw())),
        ("ranked_subject", decimal(ranked_lead.raw())),
        (
            "operations",
            obj(vec![("invite_url", Value::from(operations))]),
        ),
        ("judging", obj(vec![("invite_url", Value::from(judging))])),
        (
            "released",
            Value::from(vec![Value::from(lead.raw().to_string())]),
        ),
    ]))
}

/// The answer of a command builder: the command and the ids it creates.
fn built(command: Option<&CellCommand>, ids: Vec<(&str, Value)>) -> Result<Value, Refusal> {
    let command = match command {
        Some(c) => command_json(c)?,
        None => Value::Null,
    };
    Ok(obj(vec![("command", command), ("ids", obj(ids))]))
}

/// `POST /test/commands/CreateProgramme` (module documentation): the next
/// command the browser's first admin sends, or `null` once P1 is active.
fn create_programme(cell: &CellHandle, seeded: &mut Seeded) -> Result<Value, Refusal> {
    let ids = || vec![("programme", decimal(P1.raw()))];
    if seeded.programme {
        return built(None, ids());
    }
    let Some(admin) = first_admin(cell)? else {
        return Err(Refusal::conflict(
            "CreateProgramme serves the first admin of the browser, who has not enrolled",
        ));
    };
    let Some(stand_in) = seeded.stand_in.as_mut() else {
        // First call: the stand-in's invitation.
        let account = fresh_account()?;
        let token = fstp_crypto::random_array::<32>()
            .map_err(|e| Refusal::failed(format!("an invitation token: {e:?}")))?;
        let invitation = fstp_crypto::random_array::<16>()
            .map_err(|e| Refusal::failed(format!("an invitation id: {e:?}")))?;
        let issue = CellCommand::Tenant(TenantCommand::IssueInvitation {
            invitation,
            account,
            token_digest: fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(token)),
        });
        seeded.stand_in = Some(StandIn {
            account,
            token,
            client: None,
        });
        return built(Some(&issue), ids());
    };
    let Some(memory) = stand_in.client.take() else {
        // Second call: the stand-in enrols, and its tenant admin grant.
        let client = AuthClient::new(cell);
        match client.enrol_invited(FIRST_ADMIN, stand_in.account, &stand_in.token) {
            Ok(true) => {}
            Ok(false) => {
                return Err(Refusal::conflict(
                    "the stand-in admin's invitation does not enrol: send the IssueInvitation of the last answer first",
                ));
            }
            Err(e) => return Err(Refusal::failed(format!("the stand-in's enrolment: {e}"))),
        }
        stand_in.client = Some(client.into_memory());
        let g = CellCommand::Tenant(TenantCommand::GrantTenantAdmin {
            account: stand_in.account,
        });
        return built(Some(&g), ids());
    };
    // Third call: the creator path, run by the stand-in.
    if !state(cell)?.tenant().is_admin(stand_in.account) {
        stand_in.client = Some(memory);
        return Err(Refusal::conflict(
            "the stand-in admin holds no tenant admin role: send the GrantTenantAdmin of the last answer first",
        ));
    }
    // The browser's admin is verified too, as the cycle's first admin is.
    seed_verification(cell, admin)?;
    let mut cycle = Cycle::with_client(AuthClient::resume(cell, memory));
    run(&mut cycle, &["create-programme"])?;
    seeded.programme = true;
    built(None, ids())
}

/// The string member `name` of the JSON object `body`.
fn member<'a>(body: &'a Value, name: &str) -> Result<&'a str, Refusal> {
    body.as_object()
        .and_then(|o| o.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::bad(name))
}

/// `POST /test/commands/GrantRole {programme, account, role, starts_in?}`:
/// the grant of the M2 role named `role`, after the grantee's
/// verification is seeded (SoD-09 reads it). It starts at the cell's
/// instant, or `starts_in` microseconds after it. The engine refuses a
/// start before its instant (no backdating, design section 2.6), so a
/// spec that moves the clock before it sends the grant names how far.
fn grant_role(cell: &CellHandle, seeded: &mut Seeded, body: &Value) -> Result<Value, Refusal> {
    let starts_in = match body.as_object().and_then(|o| o.get("starts_in")) {
        None => 0,
        Some(_) => parse_decimal(member(body, "starts_in")?)
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| Refusal::bad("starts_in"))?,
    };
    let programme = parse_decimal(member(body, "programme")?)
        .map(ProgrammeId::from_raw)
        .ok_or_else(|| Refusal::bad("programme"))?;
    let account = parse_decimal(member(body, "account")?)
        .map(AccountId::from_raw)
        .ok_or_else(|| Refusal::bad("account"))?;
    let name = member(body, "role")?;
    let role = Role::ALL
        .into_iter()
        .find(|r| format!("{r:?}") == name)
        .ok_or_else(|| Refusal::bad("role"))?;
    if seeded.verified.insert(account) {
        seed_verification(cell, account)?;
    }
    let start = cell.clock().now().saturating_add(starts_in);
    let (command, binding) = grant_command(programme, account, role, start)?;
    built(Some(&command), vec![("binding", decimal(binding.raw()))])
}

/// `POST /test/commands/{kind}`.
pub(crate) fn command(
    cell: &CellHandle,
    seeded: &mut Seeded,
    kind: &str,
    body: &[u8],
) -> Result<Value, Refusal> {
    match kind {
        "CreateProgramme" => create_programme(cell, seeded),
        "GrantRole" => {
            let v = fstp_json::parse(body).map_err(|_| Refusal::bad("body"))?;
            grant_role(cell, seeded, &v)
        }
        _ => Err(Refusal {
            status: StatusCode::NOT_IMPLEMENTED,
            code: "not_implemented",
            detail: format!(
                "no command builder of kind {kind}: the devstack builds CreateProgramme and GrantRole; no command carries P-70, so magic links are a start option"
            ),
        }),
    }
}

/// `GET /test/account?email=`: the account whose login email is `email`,
/// through the cell's login email index. `known` lists the addresses the
/// stack can name: each one a proof mail went to, and the first admin's.
/// The stack compares encoded forms (`matches`), so it decodes nothing.
pub(crate) fn account(
    cell: &CellHandle,
    known: &[String],
    matches: impl Fn(&str) -> bool,
) -> Result<Value, Refusal> {
    let Some(email) = known.iter().find(|e| matches(e)) else {
        return Err(Refusal {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            detail: "no mail went to that address and it is not the first admin's".to_owned(),
        });
    };
    match cell.login_account(email) {
        Ok(Some(a)) => Ok(obj(vec![("account", decimal(a.raw()))])),
        Ok(None) => Err(Refusal {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            detail: "no account has that login email".to_owned(),
        }),
        Err(e) => Err(Refusal::failed(format!("the login email index: {e}"))),
    }
}

/// `POST /test/vault-tickets/write {kind}`: a write ticket of `kind` for
/// the negotiation scenario's subject, as `<vault origin>/w#<ticket>`. The
/// kind is the write kind's label or its name, such as
/// `AffiliationDeclared`. The specs use it only to reach the write page.
pub(crate) fn write_ticket(
    cell: &CellHandle,
    seeded: &Seeded,
    body: &[u8],
) -> Result<Value, Refusal> {
    let v = fstp_json::parse(body).map_err(|_| Refusal::bad("body"))?;
    let name = member(&v, "kind")?;
    let kind = WriteKind::ALL
        .iter()
        .copied()
        .find(|w| w.label() == name || format!("{w:?}") == name)
        .ok_or_else(|| Refusal::bad("kind"))?;
    let Some(subject) = seeded.subject else {
        return Err(Refusal::conflict(
            "a write ticket names the negotiation scenario's subject: ask for the scenario first",
        ));
    };
    let programme = WireProgramme(P1.raw());
    let now = cell.clock().now();
    let claims = TicketClaims {
        kind: TicketKind::Write(kind),
        cell: cell.id(),
        account: WireAccount(subject.raw()),
        proposal: None,
        scope: fstp_vault_proto::country_scope(programme),
        issued_at: now,
        expires_at: now.saturating_add(WRITE_TICKET_LIFE_US),
        nonce: fstp_crypto::random_array::<16>()
            .map_err(|e| Refusal::failed(format!("a ticket nonce: {e:?}")))?,
    };
    let ticket = cell
        .sign_ticket(&claims)
        .map_err(|e| Refusal::failed(format!("the write ticket: {e}")))?;
    Ok(obj(vec![(
        "url",
        Value::from(format!("https://{}/w#{}", cell.vault_host(), hex(&ticket))),
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command builder's ids are canonical decimals, as the cell's
    /// ticket route takes a proposal (`fstp_cell::routes::api`).
    #[test]
    fn devstack_ids_are_canonical_decimals() {
        assert_eq!(parse_decimal("0"), Some(0));
        assert_eq!(parse_decimal("1203"), Some(1203));
        assert_eq!(parse_decimal("01"), None);
        assert_eq!(parse_decimal(""), None);
        assert_eq!(parse_decimal("-1"), None);
        assert_eq!(parse_decimal("1e3"), None);
    }

    /// I-66: the JSON grant the builder hands a browser decodes to the
    /// grant of the programme and role it names, and a committee member's
    /// grant carries an organisation (P-39).
    #[test]
    fn i66_grant_builder_json_names_the_programme_and_role() {
        let programme = ProgrammeId::from_raw(7);
        let account = AccountId::from_raw(41);
        let mut c = grant(BindingId::from_raw(3), account, Role::CommitteeMember, 0);
        if let CellCommand::Engine(fstp_engine::Command::Core(fstp_domain::Command::GrantRole {
            programme: p,
            organisation,
            ..
        })) = &mut c
        {
            *p = programme;
            *organisation = Some(OrganisationId::from_raw(account.raw()));
        }
        let json = command_json(&c).map(|v| fstp_json::to_compact(&v)).unwrap();
        let back = fstp_cell_core::decode_cell_command(json.as_bytes()).unwrap();
        assert_eq!(back, c);
        let CellCommand::Engine(fstp_engine::Command::Core(fstp_domain::Command::GrantRole {
            programme: p,
            role,
            organisation,
            ..
        })) = back
        else {
            panic!("not a GrantRole: {back:?}");
        };
        assert_eq!((p, role), (programme, Role::CommitteeMember));
        assert!(organisation.is_some());
    }
}
