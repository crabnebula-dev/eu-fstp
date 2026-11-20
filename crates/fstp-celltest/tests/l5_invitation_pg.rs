//! The production cell's invitation port over PostgreSQL (ADR-026 record
//! of lane L5, J2, SoD-09, I-25, I-26).
//!
//! A one-cell world mounts the web adapter over the cell's own `ApiCore`.
//! The first admin opens a draft and invites a synthetic address through
//! `/api/v1`. The accounts port issues the enrolment invitation, fires the
//! invitation event with its one message, and delivers it through the
//! world's relay. The invitee reads the link token from the delivered
//! mail, enrols at `/auth/invitations/{token}/register`, accepts, and is
//! granted the role once the SoD-09 verification holds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::CellRecord;
use fstp_cell_core::timeline::TimelineRecord;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_json::Value;

/// The invitee's synthetic address.
const INVITEE_EMAIL: &str = "synthetic-invitee-l5@e2e.invalid";
/// The invitee's model account in the auth client.
const INVITEE: AccountId = AccountId::from_raw(0x0155_0001);

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

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A call of the web API in the session `cookie`.
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

/// `web`, and on `step_up_required` the passkey ceremony of the challenge,
/// then the same request once more.
fn stepped(
    client: &AuthClient<'_>,
    method: &str,
    path: &str,
    cookie: &Cookie,
    body: &str,
) -> HttpReply {
    let cell = client.cell();
    let first = web(cell, method, path, cookie, body);
    let v = json(&first);
    if v.get("code").and_then(Value::as_str) != Some("step_up_required") {
        return first;
    }
    let ch = v.get("challenge").unwrap();
    let id = ch.get("challenge_id").and_then(Value::as_str).unwrap();
    let bytes = ch
        .get("public_key")
        .and_then(|p| p.get("challenge"))
        .and_then(Value::as_str)
        .unwrap();
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    assert!(
        client.prove_api_step_up(cookie, id, challenge).unwrap(),
        "I-78: the passkey step-up was refused"
    );
    web(cell, method, path, cookie, body)
}

/// The first admin enrols and opens a draft: its session and programme.
fn draft(client: &AuthClient<'_>) -> (Cookie, ProgrammeId) {
    assert!(client.enrol(FIRST_ADMIN).unwrap(), "the first admin enrols");
    let admin = client.admin_session().expect("the admin session");
    let r = stepped(
        client,
        "POST",
        "/api/v1/programmes",
        &admin,
        r#"{"name":"Synthetic programme"}"#,
    );
    assert_eq!(r.status, 200, "creator.open_draft: {}", text(&r));
    let p = json(&r)
        .get("programme")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or_else(|| panic!("no programme in {}", text(&r)));
    (admin, ProgrammeId::from_raw(p))
}

/// The admin invites `email` as `role` on `p` through `/api/v1`.
fn invite(
    client: &AuthClient<'_>,
    admin: &Cookie,
    p: ProgrammeId,
    email: &str,
    role: &str,
) -> HttpReply {
    stepped(
        client,
        "POST",
        &format!("/api/v1/programmes/{}/invitations", p.raw()),
        admin,
        &format!(r#"{{"email":"{email}","role":"{role}"}}"#),
    )
}

fn sql_count(world: &World, sql: &str) -> u64 {
    world
        .app_superuser_sql(0, sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// The link tokens of the delivered messages to `to`, read from the text
/// part's `/app/invitation#<token>` link as the recipient reads it.
fn tokens(cell: &CellHandle, to: &str) -> Vec<[u8; 32]> {
    cell.mail()
        .relay()
        .sent()
        .iter()
        .filter(|m| m.to == to)
        .filter_map(|m| {
            let parsed = fstp_mail::parse(&m.body).ok()?;
            let text = parsed
                .parts
                .iter()
                .find(|p| p.content_type == "text/plain")
                .map(|p| String::from_utf8_lossy(&p.decoded).into_owned())?;
            let at = text.find("/app/invitation#")?;
            let hex = text.get(at + 16..at + 80)?;
            let mut out = [0u8; 32];
            for (o, i) in out.iter_mut().zip((0..64).step_by(2)) {
                *o = u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()?;
            }
            Some(out)
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The `ROLE_INVITATION` events the ledger fired, and the template
/// versions it recorded.
fn fired_invitations(world_cell: &CellHandle) -> (usize, usize) {
    let ledger = world_cell.ledger().unwrap();
    let state = world_cell.cell_engine().unwrap().state();
    let fired = ledger
        .iter()
        .filter(|e| match &e.record {
            CellRecord::Timeline(TimelineRecord::EventFired { event, .. }) => state
                .timeline()
                .event(event)
                .is_some_and(|x| x.kind == fstp_timeline::kind::ROLE_INVITATION),
            _ => false,
        })
        .count();
    let code = fstp_timeline::template_code(fstp_mail::TemplateId::RoleInvitation);
    let templates = ledger
        .iter()
        .filter(|e| {
            matches!(
                &e.record,
                CellRecord::Timeline(TimelineRecord::TemplateVersionRecorded { template, .. })
                    if *template == code
            )
        })
        .count();
    (fired, templates)
}

/// I-25, I-26, J2: an invitation through `/api/v1` produces exactly one
/// `ops.outbox` row and one delivery. The row traces to one fired
/// `ROLE_INVITATION` event and one recorded template version. The one
/// delivery has one terminal SENT row in `ops.delivery`, and the relay
/// received the message once. Later timeline ticks send nothing again.
#[test]
fn i26_invitation_produces_one_outbox_row_and_one_delivery() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let (admin, p) = draft(&client);
    let rows_before = sql_count(&world, "SELECT count(*) FROM ops.outbox");
    let sent_before = cell.mail().relay().sent().len();
    let r = invite(&client, &admin, p, INVITEE_EMAIL, "programme_manager");
    assert_eq!(r.status, 200, "creator.invite: {}", text(&r));
    assert_eq!(
        sql_count(&world, "SELECT count(*) FROM ops.outbox") - rows_before,
        1,
        "I-25: one outbox row"
    );
    let sent: Vec<_> = cell
        .mail()
        .relay()
        .sent()
        .into_iter()
        .skip(sent_before)
        .collect();
    assert_eq!(sent.len(), 1, "I-26: one delivery");
    assert_eq!(sent[0].to, INVITEE_EMAIL);
    assert_eq!(
        sql_count(&world, "SELECT count(*) FROM ops.delivery WHERE phase = 3"),
        1,
        "I-26: one SENT row"
    );
    assert_eq!(
        sql_count(&world, "SELECT count(*) FROM ops.delivery WHERE phase = 2"),
        1,
        "I-26: one commit point before the final dot"
    );
    assert_eq!(
        fired_invitations(cell),
        (1, 1),
        "I-25: one event, one template version"
    );
    // The token reaches the mail only: the ledger holds its digest.
    let token = tokens(cell, INVITEE_EMAIL).pop().expect("the link token");
    let ledger = format!("{:?}", cell.ledger().unwrap());
    assert!(
        !ledger.contains(&hex(&token)),
        "the link token in the ledger"
    );
    // I-26: the timeline's own ticks neither fire nor send it again.
    for _ in 0..3 {
        cell.clock().advance(1_000_000);
        cell.timeline_tick().unwrap();
    }
    assert_eq!(
        cell.mail().relay().sent().len(),
        sent_before + 1,
        "I-26: sent twice"
    );
    assert_eq!(fired_invitations(cell), (1, 1));
    assert_eq!(
        sql_count(&world, "SELECT count(*) FROM ops.outbox") - rows_before,
        1
    );
}

/// J2, SoD-09: the invitee enrols with the link token of the delivered
/// mail, the address becomes its login email, and it accepts the terms.
/// The grant of the accepted invitation is refused until the vault holds
/// the invitee's verification, and then binds the invitee in the invited
/// role.
#[test]
fn sod09_accepted_invitation_grants_the_role_under_the_sod_guards() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let client = AuthClient::new(cell);
    let (admin, p) = draft(&client);
    let r = invite(&client, &admin, p, INVITEE_EMAIL, "programme_manager");
    assert_eq!(r.status, 200, "creator.invite: {}", text(&r));
    let token = tokens(cell, INVITEE_EMAIL).pop().expect("the link token");
    let digest = fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(token));
    let account = cell
        .cell_engine()
        .unwrap()
        .state()
        .auth()
        .invitation_by_digest(&digest)
        .map(|(_, i)| i.account)
        .expect("J2: no enrolment invitation for the link token");
    assert!(
        client.enrol_invited(INVITEE, account, &token).unwrap(),
        "J2: the invitee enrols with the mailed token"
    );
    // Design section 4.2: the address is now the invitee's login email.
    assert_eq!(cell.login_account(INVITEE_EMAIL).unwrap(), Some(account));
    let invitee = client
        .login(INVITEE, RefMethod::Passkey)
        .unwrap()
        .expect("the invitee's session");
    let t = hex(&token);
    let landing = web(
        cell,
        "GET",
        &format!("/api/v1/invitations/{t}"),
        &invitee,
        "",
    );
    assert_eq!(
        landing.status,
        200,
        "people.get_invitation: {}",
        text(&landing)
    );
    let version = json(&landing)
        .get("terms_version")
        .cloned()
        .unwrap_or_else(|| panic!("no terms_version: {}", text(&landing)));
    let accepted = web(
        cell,
        "POST",
        &format!("/api/v1/invitations/{t}/accept"),
        &invitee,
        &format!(r#"{{"terms_version":{}}}"#, version.to_compact()),
    );
    assert_eq!(
        accepted.status,
        200,
        "people.accept_invitation: {}",
        text(&accepted)
    );
    let invitation = fstp_api_core_link_invitation(&t);
    let grant = || {
        stepped(
            &client,
            "POST",
            &format!("/api/v1/programmes/{}/roles", p.raw()),
            &admin,
            &format!(r#"{{"invitation":"{invitation}"}}"#),
        )
    };
    let held = || {
        cell.cell_engine()
            .unwrap()
            .state()
            .engine()
            .core
            .roster()
            .bindings()
            .any(|(_, b)| b.account == account && b.role == Role::ProgrammeManager)
    };
    // SoD-09: no verified identity, no grant.
    let early = grant();
    assert_ne!(
        early.status,
        200,
        "SoD-09: granted unverified: {}",
        text(&early)
    );
    assert!(!held(), "SoD-09: bound unverified");
    cell.seed_verification(account, b"synthetic-l5-invitee")
        .unwrap_or_else(|e| panic!("{e:?}"));
    // The cell answers no question on the new vault epoch until it has
    // reacted to it, which its next command does (NOTE 4). A withdrawal of
    // a proposal no one drafts is refused after that reaction.
    let probe = fstp_cell_core::CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::Command::Withdraw {
            proposal: fstp_domain::id::ProposalId::from_raw(0x0155_DEAD),
        },
    ));
    let _ = client.command_reply(&admin, &probe, false).unwrap();
    let granted = grant();
    assert_eq!(
        granted.status,
        200,
        "roles.grant by invitation: {}",
        text(&granted)
    );
    assert!(held(), "J2: the invitee holds the invited role");
}

/// The creator invitation id a link token names, as the API core derives
/// it (`fstp_api_core::creator::link_invitation`): the decimal id the
/// people admin page sends.
fn fstp_api_core_link_invitation(token: &str) -> String {
    let mut text = b"fstp:j2:invitation-link:v1:".to_vec();
    text.extend_from_slice(token.as_bytes());
    let digest = fstp_crypto::sha256(&text);
    let mut head = [0u8; 16];
    head.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(head).to_string()
}
