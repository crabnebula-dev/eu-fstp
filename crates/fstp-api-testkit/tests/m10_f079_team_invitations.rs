//! F-079 (M10 review H-07b and H-08, A-1), ADR-038: the lead invites a
//! person by address, and the person joins only by accepting (I-17,
//! TH-07, TH-08, R-AN-01, R-CF-03).
//!
//! Each test drives the one dispatch of a cell of fake ports over the
//! I-85 world, where LEAD leads the draft PX. Every account, identity and
//! address is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, ErrorCode, OpResult};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{ADMIN, LEAD, OWNER, PX, new_member};
use fstp_api_testkit::fake::{FakeCell, WebLogin, requests};
use fstp_domain::id::AccountId;
use fstp_domain::proposal::team::{INVITATION_TTL_MICROS, MAX_OPEN_PER_PROPOSAL};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster::K1;
use fstp_domain_testkit::vault::IdentityTag;
use fstp_engine::Command;
use fstp_json::ToJson;

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// The accounts holding a binding on PX, active or not.
fn bound(c: &FakeCell) -> Vec<AccountId> {
    let s = c.ports.engine.state();
    s.core
        .roster()
        .bindings()
        .filter(|(_, b)| b.proposal() == Some(PX))
        .map(|(_, b)| b.account)
        .collect()
}

/// The refusal rule of `r`, if refused.
fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(rule),
        _ => None,
    }
}

/// The lead's invitation of `email`, as the lead receives it: its class and
/// its JSON body.
fn invite(c: &FakeCell, lead: &WebLogin, email: &str) -> (Class, Option<String>) {
    let r = c.web(lead, requests::invite_member_web(PX, email));
    let body = match &r {
        Ok(OpResult::Done { body, .. }) => Some(body.to_json().to_string()),
        _ => None,
    };
    (class(&r), body)
}

/// `account` reads its open invitations and accepts the one for PX.
fn accept(c: &FakeCell, account: AccountId) -> Result<OpResult, ApiError> {
    let me = c.login(account, LoginMethod::Passkey);
    let rows = c.my_team_invitations(&me).unwrap();
    let (id, _, _) = rows
        .iter()
        .rev()
        .find(|(_, p, _)| *p == PX.raw())
        .cloned()
        .unwrap_or_else(|| panic!("{account:?} sees no invitation: {rows:?}"));
    c.web(&me, requests::accept_team_invitation_web(id))
}

/// TH-07, I-17 (F-079): the lead's invitation binds nobody and asks the
/// vault nothing: no dry run obtains an answer, the vault audit records
/// none, and the ledger holds no vault outcome and no binding of the
/// invitee. Only the invitee's acceptance asks the vault and binds it.
#[test]
fn m10_f079_th07_an_invitation_binds_nobody_and_asks_the_vault_nothing_before_acceptance() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let member = new_member(3);
    let email = requests::synthetic_email(member);
    c.ports.accounts.set_login_email(member, &email);
    let audited = c.ports.vault_audit.records().len();
    let appended = c.ports.engine.appended().len();
    let (k, _) = invite(&c, &lead, &email);
    assert_eq!(k, Class::Done, "the invitation");
    let asked: usize = c.ports.engine.dry_runs().iter().map(|d| d.asks.len()).sum();
    assert_eq!(asked, 0, "TH-07: the invitation asked the vault");
    assert_eq!(c.ports.vault_audit.records().len(), audited);
    for e in c.ports.engine.appended().iter().skip(appended) {
        assert!(
            matches!(
                &e.cmd,
                Command::Core(fstp_domain::Command::InviteToTeam { .. })
            ),
            "the invitation executed {:?}",
            e.cmd
        );
        assert!(
            e.asks.is_empty(),
            "TH-07: the invitation asked {:?}",
            e.asks
        );
    }
    assert!(
        !bound(&c).contains(&member),
        "the invitation bound the invitee"
    );

    let r = accept(&c, member);
    assert_eq!(class(&r), Class::Done, "the acceptance: {r:?}");
    assert!(bound(&c).contains(&member), "the acceptance bound nobody");
    let accepted = c.ports.engine.dry_runs().into_iter().any(|d| {
        matches!(
            &d.cmd,
            Command::Core(fstp_domain::Command::AcceptTeamInvitation { .. })
        ) && !d.asks.is_empty()
    });
    assert!(accepted, "the acceptance asked the vault nothing");
    let rows = c.lead_team_invitations(&lead, PX).unwrap();
    assert_eq!(
        rows.iter().map(|(_, _, s)| s.as_str()).collect::<Vec<_>>(),
        vec!["joined"]
    );
}

/// TH-08, R-AN-01, R-CF-03 (F-079): the lead's answer and the lead's view
/// are the same for an address with no account, a plain account, a tenant
/// admin (SoD-03), a programme manager of the programme (SoD-01) and an
/// account in an excluded class (SoD-06). Each guard refuses only when its
/// account accepts, and only that account sees the rule. The lead reads
/// `open` for every refused acceptance, and `not_joined` for a decline as
/// for an invitation nobody answered before it expired.
#[test]
fn m10_f079_th08_the_lead_learns_nothing_about_the_invited_account() {
    let c = cell();
    let excluded = new_member(4);
    let tag = IdentityTag::new(0x0f79);
    c.ports.vault.change(|t| {
        t.set_identity(excluded, tag);
        t.verify(excluded);
        t.exclude(tag, K1);
    });
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let plain = new_member(5);
    let cases: [(Option<AccountId>, &str); 5] = [
        (None, "nobody-f079@e2e.invalid"),
        (Some(plain), "plain-f079@e2e.invalid"),
        (Some(ADMIN), "admin-f079@e2e.invalid"),
        (Some(OWNER), "manager-f079@e2e.invalid"),
        (Some(excluded), "excluded-f079@e2e.invalid"),
    ];
    let mut answers = Vec::new();
    for (account, email) in cases {
        if let Some(a) = account {
            c.ports.accounts.set_login_email(a, email);
        }
        answers.push(invite(&c, &lead, email));
    }
    let first = answers.first().cloned().unwrap();
    assert_eq!(first.0, Class::Done);
    for a in &answers {
        assert_eq!(a, &first, "TH-08: the lead's answer differs by invitee");
    }
    let states = |c: &FakeCell| -> Vec<String> {
        let mut rows = c.lead_team_invitations(&lead, PX).unwrap();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        rows.into_iter().map(|(_, _, s)| s).collect()
    };
    assert!(states(&c).iter().all(|s| s == "open"), "{:?}", states(&c));

    for (who, want) in [(ADMIN, "SoD-03"), (OWNER, "SoD-01"), (excluded, "SoD-06")] {
        let r = accept(&c, who);
        assert_eq!(rule(&r), Some(want), "{who:?} at acceptance: {r:?}");
        assert!(!bound(&c).contains(&who), "{who:?} was bound");
    }
    assert!(
        states(&c).iter().all(|s| s == "open"),
        "a refused acceptance changed the lead's view: {:?}",
        states(&c)
    );

    // A decline reads as an expiry does.
    let me = c.login(excluded, LoginMethod::Passkey);
    let (id, _, _) = c.my_team_invitations(&me).unwrap()[0].clone();
    let r = c.web(&me, requests::decline_team_invitation_web(id));
    assert_eq!(class(&r), Class::Done, "the decline: {r:?}");
    c.ports
        .clock
        .advance(INVITATION_TTL_MICROS.saturating_add(1));
    assert!(
        states(&c).iter().all(|s| s == "not_joined"),
        "{:?}",
        states(&c)
    );
}

/// F-079, ADR-038: an invitation that was withdrawn or has expired cannot
/// be accepted, and neither can one addressed to someone else. Each gets
/// the same refusal, and nobody is bound.
#[test]
fn m10_f079_an_expired_or_withdrawn_invitation_cannot_be_accepted() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let (a, b) = (new_member(6), new_member(7));
    for x in [a, b] {
        c.ports
            .accounts
            .set_login_email(x, &requests::synthetic_email(x));
    }
    invite(&c, &lead, &requests::synthetic_email(a));
    let me_a = c.login(a, LoginMethod::Passkey);
    let me_b = c.login(b, LoginMethod::Passkey);
    let (id, _, _) = c.my_team_invitations(&me_a).unwrap()[0].clone();
    assert!(c.my_team_invitations(&me_b).unwrap().is_empty());

    let not_found = |r: &Result<OpResult, ApiError>| {
        class(r) == Class::Refused(ErrorCode::NotFound) && rule(r) == Some("Input")
    };
    let r = c.web(&me_b, requests::accept_team_invitation_web(id));
    assert!(not_found(&r), "another account accepted: {r:?}");

    let r = c.web(&lead, requests::withdraw_team_invitation_web(PX, id));
    assert_eq!(class(&r), Class::Done, "the withdrawal: {r:?}");
    let r = c.web(&me_a, requests::accept_team_invitation_web(id));
    assert!(not_found(&r), "a withdrawn invitation was accepted: {r:?}");
    assert!(c.my_team_invitations(&me_a).unwrap().is_empty());

    invite(&c, &lead, &requests::synthetic_email(a));
    let (id, _, _) = c.my_team_invitations(&me_a).unwrap()[0].clone();
    c.ports
        .clock
        .advance(INVITATION_TTL_MICROS.saturating_add(1));
    let r = c.web(&me_a, requests::accept_team_invitation_web(id));
    assert!(not_found(&r), "an expired invitation was accepted: {r:?}");
    let r = c.web(&me_a, requests::decline_team_invitation_web(id));
    assert!(not_found(&r), "an expired invitation was declined: {r:?}");
    assert!(!bound(&c).contains(&a) && !bound(&c).contains(&b));
}

/// F-079, ADR-038: the bounds. A lead opens at most the bounded number of
/// invitations on one proposal; the next is refused under `ADR-038`, and a
/// withdrawal frees a place. Only the lead invites.
#[test]
fn m10_f079_open_invitations_are_bounded_and_only_the_lead_invites() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let other = c.login(new_member(8), LoginMethod::Passkey);
    let r = c.web(
        &other,
        requests::invite_member_web(PX, "x-f079@e2e.invalid"),
    );
    assert_eq!(rule(&r), Some("actor"), "a non-lead invited: {r:?}");
    for n in 0..MAX_OPEN_PER_PROPOSAL {
        let (k, _) = invite(&c, &lead, &format!("bound-{n}@e2e.invalid"));
        assert_eq!(k, Class::Done, "invitation {n}");
    }
    let r = c.web(&lead, requests::invite_member_web(PX, "over@e2e.invalid"));
    assert_eq!(rule(&r), Some("ADR-038"), "past the bound: {r:?}");
    let (id, _, _) = c.lead_team_invitations(&lead, PX).unwrap()[0].clone();
    let r = c.web(&lead, requests::withdraw_team_invitation_web(PX, id));
    assert_eq!(class(&r), Class::Done, "the withdrawal: {r:?}");
    let (k, _) = invite(&c, &lead, "over@e2e.invalid");
    assert_eq!(k, Class::Done, "after a withdrawal");
}

/// F-079: the team operations take no account id. The old body
/// `{account}` is refused before anything runs, so no route binds an
/// account by its id.
#[test]
fn m10_f079_no_operation_binds_an_account_by_its_id() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let member = new_member(9);
    for path in ["team", "guardian"] {
        let op = fstp_api_core::decode::decode_route(
            fstp_api_core::decode::Method::Post,
            &format!("/proposals/{}/{path}", PX.raw()),
            format!(r#"{{"account":"{}"}}"#, member.raw()).as_bytes(),
        );
        let r = c.web(&lead, op);
        assert!(r.is_err(), "{path} took an account id: {r:?}");
    }
    assert!(!bound(&c).contains(&member));
    let roles: Vec<Role> = c
        .ports
        .engine
        .state()
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| b.account == member)
        .map(|(_, b)| b.role)
        .collect();
    assert!(roles.is_empty(), "{roles:?}");
}

/// F-079, ADR-038, `roles-and-sod.md` "Receiving bindings": the lead reads
/// the invitations while it leads X. Once X is withdrawn, a terminal
/// state, the lead's binding has ended, and the read is refused under
/// R-AC-01, since the former lead's read-only view names other reads only.
#[test]
fn m10_f079_r_ac_01_the_former_lead_reads_no_invitation_list() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    invite(&c, &lead, "former-f079@e2e.invalid");
    assert_eq!(c.lead_team_invitations(&lead, PX).unwrap().len(), 1);
    let withdrawal = fstp_api_core::decode::decode_route(
        fstp_api_core::decode::Method::Post,
        &format!("/proposals/{}/withdrawal", PX.raw()),
        b"{}",
    );
    let r = c.web(&lead, withdrawal);
    assert_eq!(class(&r), Class::Done, "the withdrawal: {r:?}");
    let r = c.web(&lead, requests::team_invitations_web(PX));
    assert_eq!(rule(&r), Some("R-AC-01"), "the former lead read: {r:?}");
}
