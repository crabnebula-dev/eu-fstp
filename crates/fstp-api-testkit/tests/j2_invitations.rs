//! Journey J2: people get their programme roles by invitation (M4 design
//! sections 2.2 J1 and J2, 3.2; `roles-and-sod.md` SoD-09 and
//! "Confidentiality on binding"; `mcp-server.md` P-75 and P-77; ADR-007;
//! I-86; lane inv).
//!
//! The test author of lane inv wrote these tests before the production
//! code. Each drives `ApiCore::dispatch` on a [`FakeCell`] through the
//! adapter-facing decoder (`fake/people_requests.rs`,
//! `fake/creator_requests.rs`) and reads what the ports saw. The
//! reference is `fstp_api_testkit::reference::invitations`.
//!
//! The world is the I-85 world of `fake/fixture.rs`. Tenant admin A1
//! ([`ADMIN`]) opens a draft through dispatch, with its step-up. M1
//! ([`OWNER`]) holds the programme manager role on it, granted through
//! the engine port as a change of the world around the cell. A1 invites.
//! The link token reaches the test only through the M3 accounts port
//! (`FakeAccounts::token_for`), as it reaches the invitee only by mail.
//!
//! Red now for these reasons, each named in the failure:
//!
//! - `creator.invite` draws no link token and hands nothing to M3;
//! - `people.get_invitation`, `people.accept_invitation` and
//!   `people.begin_verification` answer `not_implemented`;
//! - no `TermsAccepted` record exists, so `roles.grant` by account is
//!   composed without one;
//! - `roles.grant` takes no `{invitation}` body, the form the people
//!   admin page sends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_core::port::{AsyncEngine, InviteKind, LoginMethod};
use fstp_api_core::{ApiError, Credential, ErrorCode, Op, OpResult, ReadModel};
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::creator_requests as rq;
use fstp_api_testkit::fake::fixture::{self, ADMIN, ADMIN_2, OWNER, World};
use fstp_api_testkit::fake::people_requests as people;
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_api_testkit::reference::invitations::{
    self as reference, GrantVerdict, LANDING_MEMBERS, RefState,
};
use fstp_domain::id::{AccountId, BindingId, CommandId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::Command;
use fstp_json::{ToJson, Value};
use fstp_prop::{Gen, check_with, prop_assert};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh account the world does not know, numbered `n`.
const fn fresh(n: u128) -> AccountId {
    AccountId::from_raw(0x0171_0000 + n)
}

/// A synthetic invitee address, numbered `n`.
fn email(n: u32) -> String {
    format!("synthetic-invitee-{n}@e2e.invalid")
}

/// A draft opened by A1 through dispatch, with M1 as its programme
/// manager.
struct J2 {
    c: FakeCell,
    p: ProgrammeId,
    admin: WebLogin,
    owner: WebLogin,
}

fn login(c: &FakeCell, a: AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

/// Calls `op` through the web, following a step-up answer once, as the
/// page's step-up dialog does.
fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: impl Fn() -> Result<Op, ApiError>,
) -> Result<OpResult, ApiError> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports
                .step_up
                .approve(l.session, ch.action)
                .unwrap_or_else(|e| panic!("the step-up ceremony: {e:?}"));
            c.web(l, op())
        }
        other => other,
    }
}

/// The JSON body of a completed call, or why it did not complete.
fn done(r: &Result<OpResult, ApiError>, what: &str) -> Result<Value, String> {
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        other => Err(format!("{what} gave {other:?}")),
    }
}

fn str_of(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("no string member {k:?} in {}", v.to_compact()))
}

/// The command id of the `n`-th change of the world in these tests.
fn world_command(n: u8) -> CommandId {
    let mut b = *b"lane-inv:world:\0";
    b[15] = n;
    CommandId::from_bytes(b)
}

/// A1 opens a draft and M1 is granted its programme manager role.
fn draft() -> Result<J2, String> {
    let c = FakeCell::new().map_err(|e| format!("the fake cell: {e}"))?;
    let opening = login(&c, ADMIN);
    let body = done(&stepped(&c, &opening, rq::open_draft), "creator.open_draft")?;
    let p = ProgrammeId::from_raw(
        str_of(&body, "programme")?
            .parse()
            .map_err(|_| "the programme member is not a decimal id".to_owned())?,
    );
    let now = c.ports.clock.read();
    let step = roster::grant(
        BindingId::from_raw(71_001),
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
        .map_err(|e| format!("the grant of M1 on the draft: {e:?}"))?;
    Ok(J2 {
        admin: login(&c, ADMIN),
        owner: login(&c, OWNER),
        c,
        p,
    })
}

/// A1 invites `email` as `role` (wire name) on the draft of `j`, with
/// the committee organisation `organisation`. Returns the link token M3
/// received for the address (scope item 1).
fn invite_with(
    j: &J2,
    email: &str,
    role: &str,
    organisation: Option<&str>,
) -> Result<String, String> {
    let c = &j.c;
    done(
        &c.web(&j.admin, rq::invite(j.p, email, role, organisation)),
        "creator.invite",
    )?;
    c.ports.accounts.token_for(email).ok_or_else(|| {
        format!(
            "J2: creator.invite of {email} handed no link token to M3 through the accounts port \
             (M3 received {:?})",
            c.ports.accounts.invitations()
        )
    })
}

fn invite(j: &J2, email: &str, role: &str) -> Result<String, String> {
    invite_with(j, email, role, None)
}

/// The rows of `creator.invitations` of `p` as `l` reads them.
fn rows_on(c: &FakeCell, l: &WebLogin, p: ProgrammeId) -> Result<Vec<Value>, String> {
    let v = done(&c.web(l, rq::invitations(p)), "creator.invitations")?;
    v.get("invitations")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .ok_or_else(|| format!("no invitations list in {}", v.to_compact()))
}

/// The row of `email` as A1 reads it.
fn row_of(j: &J2, email: &str) -> Result<Value, String> {
    rows_on(&j.c, &j.admin, j.p)?
        .into_iter()
        .find(|r| r.get("email").and_then(Value::as_str) == Some(email))
        .ok_or_else(|| format!("no invitation row of {email}"))
}

fn state_of(j: &J2, email: &str) -> Result<String, String> {
    str_of(&row_of(j, email)?, "state")
}

/// The landing of `token` read with `cred`.
fn landing(c: &FakeCell, cred: Credential, token: &str) -> Result<OpResult, ApiError> {
    c.call(cred, people::get_invitation(token))
}

/// The landing body of `token` read by a caller with no credential.
fn landing_body(c: &FakeCell, token: &str) -> Result<Value, String> {
    done(
        &landing(c, Credential::None, token),
        "people.get_invitation",
    )
}

/// The terms version the landing of `token` shows.
fn terms_version(c: &FakeCell, token: &str) -> Result<u64, String> {
    let v = landing_body(c, token)?;
    v.get("terms_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("no terms_version number in {}", v.to_compact()))
}

/// `l` accepts the terms version the landing of `token` shows.
fn accept(c: &FakeCell, l: &WebLogin, token: &str) -> Result<(), String> {
    let v = terms_version(c, token)?;
    done(
        &c.web(l, people::accept_invitation(token, v)),
        "people.accept_invitation",
    )
    .map(|_| ())
}

/// A token nobody was given: valid in shape, never drawn.
fn unknown_token() -> String {
    "5a".repeat(32)
}

/// The canonical text of every ledger entry.
fn ledger_texts(c: &FakeCell) -> Vec<String> {
    AsyncEngine::ledger(&c.ports.engine)
        .unwrap_or_default()
        .iter()
        .map(|e| {
            e.canonical_text()
                .unwrap_or_else(|e| panic!("entry text: {e:?}"))
        })
        .collect()
}

/// The JSON text of a result's body, or its `Debug` text.
fn reply_text(r: &Result<OpResult, ApiError>) -> String {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json().to_compact(),
        other => format!("{other:?}"),
    }
}

/// Every place a secret might be stored or logged in clear: the ledger,
/// the text store, the audit log, the recorded vault answers, every
/// command and dry run the engine port saw, and the outbox.
fn stores_and_logs(c: &FakeCell) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for t in ledger_texts(c) {
        out.push(("the ledger".to_owned(), t.into_bytes()));
    }
    for t in c.ports.texts.all() {
        out.push(("the text store".to_owned(), t));
    }
    for e in c.ports.audit.entries() {
        out.push(("the audit log".to_owned(), format!("{e:?}").into_bytes()));
    }
    out.push((
        "the vault audit".to_owned(),
        format!("{:?}", c.ports.vault_audit.records()).into_bytes(),
    ));
    for e in c.ports.engine.executions() {
        out.push((
            "an engine execution".to_owned(),
            format!("{e:?}").into_bytes(),
        ));
    }
    for d in c.ports.engine.dry_runs() {
        out.push((
            "an engine dry run".to_owned(),
            format!("{d:?}").into_bytes(),
        ));
    }
    out.push((
        "the outbox".to_owned(),
        format!("{:?}", c.ports.outbox).into_bytes(),
    ));
    out
}

/// A fresh cell over a copy of `c`'s ledger and vault: a restarted core
/// that remembers nothing outside the ledger.
fn restarted(c: &FakeCell) -> FakeCell {
    let base = fixture::pending_world().unwrap();
    let world = World {
        store: c.ports.engine.store_copy(),
        truth: c.ports.vault.truth(),
        start: c.ports.clock.read(),
        admins: base.admins,
    };
    FakeCell::from_world(&world).unwrap_or_else(|e| panic!("the restarted cell: {e}"))
}

/// The bindings the engine state holds of `a` in `role` on `p`.
fn held(c: &FakeCell, a: AccountId, p: ProgrammeId, role: Role) -> bool {
    c.ports
        .engine
        .state()
        .core
        .roster()
        .bindings()
        .any(|(_, b)| b.account == a && b.programme == p && b.role == role && b.held())
}

/// Whether `r` is a refusal: never a completed call and never a stub.
fn refused(r: &Result<OpResult, ApiError>) -> bool {
    matches!(r, Err(ApiError::Refused { .. }))
}

// ---------------------------------------------------------------------------
// Scope item 1: the link token
// ---------------------------------------------------------------------------

/// J2, I-86, ADR-007: `creator.invite` hands the drawn link token and the
/// email to M3 through the accounts port, and to no one else. The token
/// is 32 random bytes in its link spelling. The reply to the inviting
/// admin carries no token, so the admin cannot accept in the invitee's
/// place.
#[test]
fn i86_j2_invite_hands_the_token_and_email_to_m3_only() {
    let j = draft().unwrap();
    let to = email(1);
    let r =
        j.c.web(&j.admin, rq::invite(j.p, &to, "programme_manager", None));
    done(&r, "creator.invite").unwrap();
    let kinds = j.c.ports.accounts.invitations();
    assert_eq!(
        kinds.len(),
        1,
        "J2: M3 must receive exactly one invitation, got {kinds:?}"
    );
    let InviteKind::ProgrammeRole {
        programme,
        role,
        email: sent,
        token,
        ..
    } = &kinds[0];
    assert_eq!((*programme, *role), (j.p, Role::ProgrammeManager));
    assert_eq!(sent, &to);
    let hex = token.hex();
    assert!(reference::is_link_token(&hex), "{hex}");
    for s in reference::secret_spellings(token.bytes()) {
        assert!(
            !reference::contains(reply_text(&r).as_bytes(), &s),
            "J2: the reply to the inviting admin carries the link token"
        );
    }
}

/// ADR-007 (`SecretDigest`), J2, property: no link token is ever stored
/// or logged in clear, in any common spelling, across invitations of
/// every invitable kind and the landing reads of their tokens. The
/// ledger, the text store, the audit log, the vault audit, the engine
/// port's commands and the outbox are scanned.
#[test]
fn adr007_j2_link_token_is_never_stored_or_logged_in_clear() {
    let roles = [
        "programme_manager",
        "call_drafter",
        "committee_member",
        "irc_member",
        "finance_approver",
    ];
    check_with(
        "adr007_j2_link_token_is_never_stored_or_logged_in_clear",
        fstp_prop::Config::default().with_cases(12),
        |g: &mut Gen| {
            let j = draft()?;
            let n = g.u32_in(1..=3);
            let mut tokens = Vec::new();
            for i in 0..n {
                let role = *g.pick(&roles);
                g.note("role", &role);
                let t = invite(&j, &email(i), role)?;
                if g.bool() {
                    let _ = landing(&j.c, Credential::None, &t);
                }
                tokens.push(t);
            }
            for t in &tokens {
                let bytes = reference::token_bytes(t)
                    .ok_or_else(|| format!("the token {t:?} is not in its link spelling"))?;
                for (place, hay) in stores_and_logs(&j.c) {
                    for s in reference::secret_spellings(&bytes) {
                        prop_assert!(
                            !reference::contains(&hay, &s),
                            "ADR-007: {place} holds a link token in clear"
                        );
                    }
                }
            }
            Ok(())
        },
    );
}

/// ADR-007, J2: the invitation records the token's digest in the
/// ledger, so a restarted core, which remembers nothing outside the
/// ledger, still finds the invitation by its token.
#[test]
fn adr007_j2_token_digest_lives_in_the_ledger() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let again = restarted(&j.c);
    let v = landing_body(&again, &t).unwrap();
    assert_eq!(str_of(&v, "role").unwrap(), "programme_manager");
    assert_eq!(str_of(&v, "state").unwrap(), RefState::Invited.as_str());
}

// ---------------------------------------------------------------------------
// Scope item 2: the landing and the uniform refusal
// ---------------------------------------------------------------------------

/// SoD-09, J2, I-86: the landing of a fresh token, read with no
/// credential, names the role, the terms version, the P-75 and P-77
/// choices and the state, and nothing else: no account, no inviter, no
/// address and no programme.
#[test]
fn sod09_j2_landing_names_role_terms_and_state_only() {
    let j = draft().unwrap();
    let to = email(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    let v = landing_body(&j.c, &t).unwrap();
    let keys: Vec<&str> = v
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    assert_eq!(keys, LANDING_MEMBERS.to_vec(), "{}", v.to_compact());
    assert_eq!(str_of(&v, "role").unwrap(), "programme_manager");
    assert_eq!(str_of(&v, "state").unwrap(), "invited");
    assert!(
        v.get("terms_version")
            .and_then(Value::as_u64)
            .is_some_and(|n| n >= 1)
    );
    // Not a Judging role, so the terms state neither choice.
    assert_eq!(v.get("p75"), Some(&Value::Null));
    assert_eq!(v.get("p77"), Some(&Value::Null));
    assert!(
        !v.to_compact().contains(&to),
        "I-86: the landing names the address"
    );
}

/// J2, SoD-09: an unknown token, the token of a withdrawn invitation and
/// the token of an invitation another account accepted get one refusal,
/// equal in code, rule and detail, for the landing, the acceptance and
/// the verification alike. The refusal is a refusal, never a stub, and
/// nothing is appended.
#[test]
fn sod09_j2_unknown_withdrawn_and_used_tokens_get_one_refusal() {
    let j = draft().unwrap();
    let withdrawn = invite(&j, &email(1), "programme_manager").unwrap();
    let id = str_of(&row_of(&j, &email(1)).unwrap(), "id").unwrap();
    done(
        &stepped(&j.c, &j.admin, || rq::withdraw_invitation(j.p, &id)),
        "creator.withdraw_invitation",
    )
    .unwrap();
    let used = invite(&j, &email(2), "programme_manager").unwrap();
    let first = login(&j.c, fresh(1));
    accept(&j.c, &first, &used).unwrap();
    let other = login(&j.c, fresh(2));
    let unknown = unknown_token();

    type Run<'a> = Box<dyn Fn(&str, Credential) -> Result<OpResult, ApiError> + 'a>;
    let ops: [(&str, Run<'_>); 3] = [
        (
            "people.get_invitation",
            Box::new(|t: &str, cred| j.c.call(cred, people::get_invitation(t))),
        ),
        (
            "people.accept_invitation",
            Box::new(|t: &str, cred| j.c.call(cred, people::accept_invitation(t, 1))),
        ),
        (
            "people.begin_verification",
            Box::new(|t: &str, cred| j.c.call(cred, people::begin_verification(t))),
        ),
    ];
    let as_other = || Credential::SessionCookie(other.cookie.clone());
    for (name, run) in &ops {
        let before = j.c.ports.engine.appended().len();
        let base = run(&unknown, as_other());
        assert!(
            refused(&base),
            "J2: {name} of an unknown token must be a refusal, got {base:?}"
        );
        for (case, t) in [("withdrawn", &withdrawn), ("used", &used)] {
            let got = run(t, as_other());
            assert_eq!(
                format!("{got:?}"),
                format!("{base:?}"),
                "SoD-09: {name} of a {case} token differs from an unknown one"
            );
        }
        assert_eq!(
            j.c.ports.engine.appended().len(),
            before,
            "J2: a refused {name} appended"
        );
    }
    // The landing with no credential refuses alike.
    let anon = landing(&j.c, Credential::None, &unknown);
    for t in [&withdrawn, &used] {
        assert_eq!(
            format!("{:?}", landing(&j.c, Credential::None, t)),
            format!("{anon:?}"),
            "SoD-09: an anonymous landing read tells the cases apart"
        );
    }
}

// ---------------------------------------------------------------------------
// Scope item 3: the acceptance
// ---------------------------------------------------------------------------

/// J2, "Confidentiality on binding": the acceptance names the terms
/// version the landing showed. Another version is refused and changes
/// nothing. The shown version is accepted, and the landing and the
/// invitation list then read `accepted`.
#[test]
fn j2_accept_records_the_shown_terms_version_only() {
    let j = draft().unwrap();
    let to = email(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    let v = terms_version(&j.c, &t).unwrap();
    let invitee = login(&j.c, fresh(1));
    let before = j.c.ports.engine.appended().len();
    let wrong = j.c.web(&invitee, people::accept_invitation(&t, v + 1));
    assert!(
        refused(&wrong),
        "J2: a terms version never shown was accepted: {wrong:?}"
    );
    assert_eq!(j.c.ports.engine.appended().len(), before);
    assert_eq!(state_of(&j, &to).unwrap(), "invited");
    done(
        &j.c.web(&invitee, people::accept_invitation(&t, v)),
        "people.accept_invitation",
    )
    .unwrap();
    assert_eq!(state_of(&j, &to).unwrap(), RefState::Accepted.as_str());
    let mine = done(
        &landing(&j.c, Credential::SessionCookie(invitee.cookie.clone()), &t),
        "people.get_invitation by the acceptor",
    )
    .unwrap();
    assert_eq!(str_of(&mine, "state").unwrap(), "accepted");
}

/// J2: the acceptance is recorded in the ledger and folded into the
/// creator state (`observe_invitation_accepted`), so a restarted core
/// still reads it as accepted.
#[test]
fn j2_acceptance_lives_in_the_ledger() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let invitee = login(&j.c, fresh(1));
    accept(&j.c, &invitee, &t).unwrap();
    let again = restarted(&j.c);
    let d = again.ports.engine.state();
    let accepted: Vec<Option<AccountId>> = d
        .creator
        .draft(j.p)
        .map(|d| d.live_invitations().map(|(_, i)| i.accepted).collect())
        .unwrap_or_default();
    assert_eq!(accepted, vec![Some(fresh(1))]);
}

/// J2: a second acceptance by the same account is refused and appends
/// nothing.
#[test]
fn j2_second_acceptance_is_refused() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let invitee = login(&j.c, fresh(1));
    accept(&j.c, &invitee, &t).unwrap();
    let before = j.c.ports.engine.appended().len();
    let v = terms_version(&j.c, &t).ok().unwrap_or(1);
    let again = j.c.web(&invitee, people::accept_invitation(&t, v));
    assert!(
        refused(&again),
        "J2: a second acceptance was admitted: {again:?}"
    );
    assert_eq!(j.c.ports.engine.appended().len(), before);
}

/// J2: once one account accepted, an acceptance by another account is
/// refused. A caller with no session cannot accept at all, since the
/// invitee enrols a passkey first. Neither appends.
#[test]
fn j2_acceptance_by_another_account_or_no_session_is_refused() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let v = terms_version(&j.c, &t).unwrap();
    let before = j.c.ports.engine.appended().len();
    let anon = j.c.call(Credential::None, people::accept_invitation(&t, v));
    assert_eq!(
        class(&anon),
        Class::Refused(ErrorCode::Unauthenticated),
        "J2: an acceptance with no session: {anon:?}"
    );
    assert_eq!(j.c.ports.engine.appended().len(), before);
    accept(&j.c, &login(&j.c, fresh(1)), &t).unwrap();
    let after = j.c.ports.engine.appended().len();
    let other =
        j.c.web(&login(&j.c, fresh(2)), people::accept_invitation(&t, v));
    assert!(refused(&other), "J2: another account accepted: {other:?}");
    assert_eq!(j.c.ports.engine.appended().len(), after);
}

/// J2, I-84: the acceptance body is `{terms_version}` with a positive
/// JSON integer, and nothing else.
#[test]
fn j2_accept_body_is_strict() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let invitee = login(&j.c, fresh(1));
    for body in [
        "{}",
        r#"{"terms_version":"1"}"#,
        r#"{"terms_version":0}"#,
        r#"{"terms_version":1.5}"#,
        r#"{"terms_version":1,"account":"5"}"#,
    ] {
        let r = match people::accept_invitation_raw(&t, body) {
            Ok(op) => j.c.web(&invitee, Ok(op)),
            Err(e) => Err(e),
        };
        assert_eq!(
            class(&r),
            Class::Refused(ErrorCode::BadRequest),
            "I-84: the acceptance body {body} gave {r:?}"
        );
    }
    assert_eq!(state_of(&j, &email(1)).unwrap(), "invited");
}

// ---------------------------------------------------------------------------
// Scope item 4: the verification
// ---------------------------------------------------------------------------

/// J2, SoD-09: the acceptor starts the identity verification through
/// `VaultIntake::begin_verification` and gets the vault's redirect. A
/// caller who did not accept the invitation is refused, and the vault
/// begins nothing for them.
#[test]
fn sod09_j2_begin_verification_runs_through_the_vault_for_the_acceptor() {
    let j = draft().unwrap();
    let t = invite(&j, &email(1), "programme_manager").unwrap();
    let invitee = login(&j.c, fresh(1));
    let early = j.c.web(&invitee, people::begin_verification(&t));
    assert!(
        refused(&early),
        "J2: verification before acceptance: {early:?}"
    );
    accept(&j.c, &invitee, &t).unwrap();
    let other =
        j.c.web(&login(&j.c, fresh(2)), people::begin_verification(&t));
    assert!(
        refused(&other),
        "J2: verification by another account: {other:?}"
    );
    let r = j.c.web(&invitee, people::begin_verification(&t));
    assert!(
        matches!(
            &r,
            Ok(OpResult::Done {
                body: ReadModel::Redirect(_),
                ..
            })
        ),
        "J2: the acceptor's verification gave {r:?}"
    );
    let begun: Vec<AccountId> =
        j.c.ports
            .vault
            .verifications()
            .into_iter()
            .map(|(_, a)| a)
            .collect();
    assert_eq!(begun, vec![fresh(1)]);
}

/// J1, J2: the invitation list moves invited, accepted, verified and
/// granted, as the reference reads each step, and A1's grant by
/// invitation completes with its step-up.
#[test]
fn sod09_j2_list_invitations_moves_invited_accepted_verified_granted() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    assert_eq!(
        state_of(&j, &to).unwrap(),
        reference::listed_state(false, false, false).as_str()
    );
    let invitee = login(&j.c, a);
    accept(&j.c, &invitee, &t).unwrap();
    assert_eq!(
        state_of(&j, &to).unwrap(),
        reference::listed_state(true, false, false).as_str()
    );
    done(
        &j.c.web(&invitee, people::begin_verification(&t)),
        "people.begin_verification",
    )
    .unwrap();
    j.c.ports.vault.change(|truth| truth.verify(a));
    assert_eq!(
        state_of(&j, &to).unwrap(),
        reference::listed_state(true, true, false).as_str()
    );
    let id = str_of(&row_of(&j, &to).unwrap(), "id").unwrap();
    done(
        &stepped(&j.c, &j.admin, || people::grant_invitation(j.p, &id)),
        "roles.grant by invitation",
    )
    .unwrap();
    assert_eq!(
        state_of(&j, &to).unwrap(),
        reference::listed_state(true, true, true).as_str()
    );
    assert!(held(&j.c, a, j.p, Role::ProgrammeManager));
}

// ---------------------------------------------------------------------------
// Scope item 5: the grant composition
// ---------------------------------------------------------------------------

/// J2, "Confidentiality on binding": `roles.grant` by account is refused
/// for a verified account with no `TermsAccepted` record for the role,
/// and for an account whose accepted terms are for another role. No
/// binding is appended.
#[test]
fn j2_grant_without_terms_accepted_is_refused() {
    let j = draft().unwrap();
    let a = fresh(1);
    let b = fresh(2);
    j.c.ports.vault.change(|truth| {
        truth.verify(a);
        truth.verify(b);
    });
    // `b` accepted the terms of a committee member, not of a manager.
    let t = invite(&j, &email(2), "committee_member").unwrap();
    accept(&j.c, &login(&j.c, b), &t).unwrap();
    for who in [a, b] {
        assert_eq!(
            reference::grant_verdict(Role::ProgrammeManager, false, true),
            GrantVerdict::NoTermsAccepted
        );
        let now = j.c.ports.clock.read();
        let r = stepped(&j.c, &j.admin, || {
            people::grant_account(j.p, who, "ProgrammeManager", now, None)
        });
        assert!(
            refused(&r),
            "J2: a grant to {who:?} with no TermsAccepted for the role was composed: {r:?}"
        );
        assert!(!held(&j.c, who, j.p, Role::ProgrammeManager));
    }
}

/// SoD-09, J2: an accepted programme manager invitation whose account
/// the vault does not verify is not granted. The refusal names SoD-09.
#[test]
fn sod09_j2_grant_by_invitation_without_verification_is_refused() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    accept(&j.c, &login(&j.c, a), &t).unwrap();
    assert_eq!(
        reference::grant_verdict(Role::ProgrammeManager, true, false),
        GrantVerdict::Sod09
    );
    let id = str_of(&row_of(&j, &to).unwrap(), "id").unwrap();
    let r = stepped(&j.c, &j.admin, || people::grant_invitation(j.p, &id));
    assert!(
        matches!(&r, Err(ApiError::Refused { rule: "SoD-09", .. })),
        "SoD-09: the grant of an unverified acceptor gave {r:?}"
    );
    assert!(!held(&j.c, a, j.p, Role::ProgrammeManager));
}

/// Activates the draft of `j` as a change of the world around the cell:
/// tenant admin A2, outside the builder set, approves it through the
/// creator path the test kit composes (D2e), as J1's last step does.
fn activate(j: &J2) -> Result<(), String> {
    let now = j.c.ports.clock.read();
    let cmd = fstp_domain::Command::ActivateProgramme {
        programme: j.p,
        decision: fstp_domain::id::DecisionId::from_raw(71_002),
        report: fstp_domain::policy::activation::ReportDigest::from_bytes([7; 32]),
        revision: 0,
        creator_builders: std::collections::BTreeSet::new(),
    };
    let mut ctx = fixture::ctx(ADMIN_2, fstp_domain::Via::Web, now, 0);
    ctx.command = world_command(2);
    j.c.ports
        .engine
        .setup_step(&cmd, ctx)
        .map(|_| ())
        .map_err(|e| format!("the activation of the draft as a world change: {e:?}"))
}

/// SoD-09, J2: a Judging role, invited on the draft (J1 step 9) and
/// accepted, is not granted on the activated programme while the vault
/// does not verify the acceptor. The refusal names SoD-09.
#[test]
fn sod09_j2_judging_grant_without_verification_is_refused() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    // The committee organisation, recorded with the binding (SoD-10).
    let t = invite_with(&j, &to, "committee_member", Some("7")).unwrap();
    accept(&j.c, &login(&j.c, a), &t).unwrap();
    activate(&j).unwrap();
    assert_eq!(
        reference::grant_verdict(Role::CommitteeMember, true, false),
        GrantVerdict::Sod09
    );
    let id = str_of(&row_of(&j, &to).unwrap(), "id").unwrap();
    let r = stepped(&j.c, &j.admin, || people::grant_invitation(j.p, &id));
    assert!(
        matches!(&r, Err(ApiError::Refused { rule: "SoD-09", .. })),
        "SoD-09: the Judging grant of an unverified acceptor gave {r:?}"
    );
    assert!(!held(&j.c, a, j.p, Role::CommitteeMember));
}

/// J2: the grant by invitation composes the core `GrantRole` of the
/// accepting account, the invited role and the programme, never of any
/// account the request names.
#[test]
fn j2_grant_by_invitation_composes_the_accepting_account_and_role() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    accept(&j.c, &login(&j.c, a), &t).unwrap();
    j.c.ports.vault.change(|truth| truth.verify(a));
    let id = str_of(&row_of(&j, &to).unwrap(), "id").unwrap();
    done(
        &stepped(&j.c, &j.admin, || people::grant_invitation(j.p, &id)),
        "roles.grant by invitation",
    )
    .unwrap();
    let grants: Vec<(AccountId, ProgrammeId, Role)> =
        j.c.ports
            .engine
            .appended()
            .into_iter()
            .filter_map(|e| match e.cmd {
                Command::Core(fstp_domain::Command::GrantRole {
                    account,
                    programme,
                    role,
                    ..
                }) => Some((account, programme, role)),
                _ => None,
            })
            .collect();
    assert_eq!(grants, vec![(a, j.p, Role::ProgrammeManager)]);
}

// ---------------------------------------------------------------------------
// I-86 and the bound placeholders
// ---------------------------------------------------------------------------

/// I-86, J2: through the whole journey the invitee's email reaches no
/// ledger entry and no reply of a people operation, and the invitee,
/// who is neither a manager nor a tenant admin, cannot read the
/// invitation list that names it.
#[test]
fn i86_j2_invitee_email_never_reaches_the_ledger_or_a_non_admin_reply() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    let t = invite(&j, &to, "committee_member").unwrap();
    let invitee = login(&j.c, a);
    let mut replies = vec![landing(&j.c, Credential::None, &t)];
    let v = terms_version(&j.c, &t).unwrap();
    let accepted = j.c.web(&invitee, people::accept_invitation(&t, v));
    done(&accepted, "people.accept_invitation").unwrap();
    replies.push(accepted);
    replies.push(landing(
        &j.c,
        Credential::SessionCookie(invitee.cookie.clone()),
        &t,
    ));
    replies.push(j.c.web(&invitee, people::begin_verification(&t)));
    for r in &replies {
        assert!(
            !reply_text(r).contains(&to),
            "I-86: a people reply to the invitee names the address: {}",
            reply_text(r)
        );
    }
    let list = j.c.web(&invitee, rq::invitations(j.p));
    assert!(
        refused(&list),
        "I-86: the invitee read the invitation list: {list:?}"
    );
    for text in ledger_texts(&j.c) {
        assert!(
            !text.contains(&to),
            "I-86: a ledger entry names the invitee's address"
        );
    }
}

/// J2, `mcp-server.md` (P-75, P-77): the terms of a Judging role state
/// the programme's P-75 and P-77 choices through bound placeholders.
/// The landing follows each saved choice, so the values come from the
/// programme and not from a default. The terms of a Drafting role state
/// neither.
#[test]
fn j2_judging_terms_bind_p75_and_p77() {
    let j = draft().unwrap();
    let judging = invite(&j, &email(1), "committee_member").unwrap();
    let drafting = invite(&j, &email(2), "programme_manager").unwrap();
    assert!(reference::terms_bind_p75_p77(Role::CommitteeMember));
    let base = str_of(
        &done(&j.c.web(&j.owner, rq::get_draft(j.p)), "creator.get_draft").unwrap(),
        "revision",
    )
    .unwrap();
    done(
        &j.c.web(&j.owner, rq::apply_start(j.p, &base, rq::supersafe_start())),
        "creator.apply_start",
    )
    .unwrap();
    for (p75, p77) in [
        (true, "allowed"),
        (false, "draft_only"),
        (true, "draft_only"),
    ] {
        let base = str_of(
            &done(&j.c.web(&j.owner, rq::get_draft(j.p)), "creator.get_draft").unwrap(),
            "revision",
        )
        .unwrap();
        done(
            &j.c.web(
                &j.owner,
                rq::save_fields(
                    j.p,
                    &base,
                    &[
                        ("evaluation.p75_agent_content_reads", Value::Bool(p75)),
                        ("evaluation.p77_mcp_binding_actions", Value::from(p77)),
                    ],
                ),
            ),
            "creator.save_fields of P-75 and P-77",
        )
        .unwrap();
        let v = landing_body(&j.c, &judging).unwrap();
        assert_eq!(
            v.get("p75"),
            Some(&Value::Bool(p75)),
            "P-75: {}",
            v.to_compact()
        );
        assert_eq!(
            v.get("p77").and_then(Value::as_str),
            Some(p77),
            "P-77: {}",
            v.to_compact()
        );
        let d = landing_body(&j.c, &drafting).unwrap();
        assert_eq!(d.get("p75"), Some(&Value::Null));
        assert_eq!(d.get("p77"), Some(&Value::Null));
    }
}

// ---------------------------------------------------------------------------
// MB-Q3 (decided by Daniel on 2026-11-13): the mailbox
// ---------------------------------------------------------------------------

/// The `(kind, programme, action)` of each message of `l`'s mailbox.
fn mail(c: &FakeCell, l: &WebLogin) -> Vec<(String, String, bool)> {
    let op =
        fstp_api_core::decode::decode_route(fstp_api_core::decode::Method::Get, "/me/mailbox", &[]);
    let v = done(&c.web(l, op), "me.mailbox").unwrap_or_else(|e| panic!("{e}"));
    let text = v.to_compact();
    assert!(!text.contains('@'), "I-86: an address in {text}");
    v.get("messages")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no messages in {text}"))
        .iter()
        .map(|m| {
            (
                m.get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                m.get("programme")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                m.get("action").and_then(Value::as_bool).unwrap_or(true),
            )
        })
        .collect()
}

/// SoD-09, I-86, I-27, MB-Q3 (decided by Daniel on 2026-11-13): an
/// invitation that an existing account accepted shows in that account's
/// mailbox as a notice naming the programme, until the role is granted.
/// The grant then shows as a notice of its own. Nobody else sees either,
/// and no message holds the link token or the address.
#[test]
fn sod09_i86_j2_invitation_and_grant_show_in_the_invitees_mailbox() {
    let j = draft().unwrap();
    let to = email(1);
    let a = fresh(1);
    let t = invite(&j, &to, "programme_manager").unwrap();
    let invitee = login(&j.c, a);
    let p = j.p.raw().to_string();
    let has = |m: &[(String, String, bool)], kind: &str| {
        m.iter()
            .any(|(k, prog, action)| k == kind && *prog == p && !action)
    };
    assert!(
        !has(&mail(&j.c, &invitee), "invitation.open"),
        "before acceptance"
    );
    accept(&j.c, &invitee, &t).unwrap();
    let after = mail(&j.c, &invitee);
    assert!(has(&after, "invitation.open"), "{after:?}");
    assert!(!has(&after, "role.granted"), "{after:?}");
    let other = mail(&j.c, &login(&j.c, fresh(2)));
    assert!(other.is_empty(), "I-86: {other:?}");
    j.c.ports.vault.change(|truth| truth.verify(a));
    let id = str_of(&row_of(&j, &to).unwrap(), "id").unwrap();
    done(
        &stepped(&j.c, &j.admin, || people::grant_invitation(j.p, &id)),
        "roles.grant by invitation",
    )
    .unwrap();
    let granted = mail(&j.c, &invitee);
    assert!(!has(&granted, "invitation.open"), "{granted:?}");
    assert!(has(&granted, "role.granted"), "{granted:?}");
    let op =
        fstp_api_core::decode::decode_route(fstp_api_core::decode::Method::Get, "/me/mailbox", &[]);
    let text = reply_text(&j.c.web(&invitee, op));
    assert!(!text.contains(&t), "the link token in {text}");
}
