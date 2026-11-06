//! Reproducers of the independent security review of lane inv (journey
//! J2, M4 design section 2.2; `roles-and-sod.md` "Confidentiality on
//! binding" and SoD-09; `mcp-server.md` P-75 and P-77).
//!
//! Each test is red on the reviewed work and names the defect it shows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Credential, OpResult};
use fstp_api_testkit::fake::creator_requests as rq;
use fstp_api_testkit::fake::fixture::{ADMIN, OWNER};
use fstp_api_testkit::fake::people_requests as people;
use fstp_api_testkit::fake::{FakeCell, WebLogin};
use fstp_domain::id::{AccountId, BindingId, CommandId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::Command;
use fstp_json::{ToJson, Value};

struct J2 {
    c: FakeCell,
    p: ProgrammeId,
    admin: WebLogin,
    owner: WebLogin,
}

const fn fresh(n: u128) -> AccountId {
    AccountId::from_raw(0x0172_0000 + n)
}

fn email(n: u32) -> String {
    format!("synthetic-review-{n}@e2e.invalid")
}

fn stepped(
    c: &FakeCell,
    l: &WebLogin,
    op: impl Fn() -> Result<fstp_api_core::Op, ApiError>,
) -> Result<OpResult, ApiError> {
    match c.web(l, op()) {
        Ok(OpResult::StepUpRequired(ch)) => {
            c.ports.step_up.approve(l.session, ch.action).unwrap();
            c.web(l, op())
        }
        other => other,
    }
}

fn done(r: &Result<OpResult, ApiError>, what: &str) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("{what} gave {other:?}"),
    }
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap().to_owned()
}

fn draft() -> J2 {
    let c = FakeCell::new().unwrap();
    let opening = c.login(ADMIN, LoginMethod::Passkey);
    let body = done(&stepped(&c, &opening, rq::open_draft), "creator.open_draft");
    let p = ProgrammeId::from_raw(str_of(&body, "programme").parse().unwrap());
    let now = c.ports.clock.read();
    let step = roster::grant(
        BindingId::from_raw(72_001),
        OWNER,
        p,
        Role::ProgrammeManager,
        now,
    );
    let mut b = *b"review-inv:wrld\0";
    b[15] = 1;
    c.ports
        .engine
        .environment(
            Command::Core(step.cmd.clone()),
            step.ctx(now, CommandId::from_bytes(b)),
        )
        .unwrap();
    J2 {
        admin: c.login(ADMIN, LoginMethod::Passkey),
        owner: c.login(OWNER, LoginMethod::Passkey),
        c,
        p,
    }
}

fn invite(j: &J2, to: &str, role: &str) -> String {
    done(
        &j.c.web(&j.admin, rq::invite(j.p, to, role, None)),
        "creator.invite",
    );
    j.c.ports.accounts.token_for(to).unwrap()
}

fn save_choices(j: &J2, p75: bool, p77: &str) {
    let base = str_of(
        &done(&j.c.web(&j.owner, rq::get_draft(j.p)), "creator.get_draft"),
        "revision",
    );
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
    );
}

/// Review of lane inv, J2, `mcp-server.md` P-75: the terms recorded for
/// an acceptance must be the terms the landing showed. The landing shows
/// P-75 off; the manager then saves P-75 on; the invitee accepts the
/// version the landing showed. The acceptance must be refused, or the
/// recorded terms must state P-75 off. The reviewed work records P-75 on
/// under the same terms version, so the invitee is bound to terms they
/// never saw.
#[test]
fn j2_p75_recorded_terms_are_the_terms_the_landing_showed() {
    let j = draft();
    let t = invite(&j, &email(1), "committee_member");
    let base = str_of(
        &done(&j.c.web(&j.owner, rq::get_draft(j.p)), "creator.get_draft"),
        "revision",
    );
    done(
        &j.c.web(&j.owner, rq::apply_start(j.p, &base, rq::supersafe_start())),
        "creator.apply_start",
    );
    save_choices(&j, false, "draft_only");
    let shown = done(
        &j.c.call(Credential::None, people::get_invitation(&t)),
        "people.get_invitation",
    );
    assert_eq!(shown.get("p75"), Some(&Value::Bool(false)));
    let version = shown.get("terms_version").and_then(Value::as_u64).unwrap();
    // The programme's choice changes after the landing was read.
    save_choices(&j, true, "draft_only");
    let invitee = j.c.login(fresh(1), LoginMethod::Passkey);
    let r = j.c.web(&invitee, people::accept_invitation(&t, version));
    if matches!(r, Err(ApiError::Refused { .. })) {
        return;
    }
    done(&r, "people.accept_invitation");
    let recorded: Vec<String> =
        j.c.ports
            .texts
            .all()
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .filter(|s| s.starts_with("confidentiality-terms;"))
            .collect();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert!(
        recorded[0].contains("p75=off"),
        "J2: the invitee accepted terms showing P-75 off, but the ledger cites terms {:?} \
         under the same version {version}",
        recorded[0]
    );
}

/// Review of lane inv, J2, "Confidentiality on binding": a Drafting grant
/// is composed only from the accepted terms. When the invitee accepted
/// and is verified, a `roles.grant` by account passes the J2 guard, but
/// the binding must still cite the accepted terms text. The reviewed
/// work binds the account under the confidentiality text the admin
/// typed into the request, which the invitee never accepted.
#[test]
fn j2_grant_by_account_binds_the_accepted_terms_text() {
    let j = draft();
    let a = fresh(2);
    let t = invite(&j, &email(2), "programme_manager");
    let invitee = j.c.login(a, LoginMethod::Passkey);
    done(
        &j.c.web(&invitee, people::accept_invitation(&t, 1)),
        "people.accept_invitation",
    );
    j.c.ports.vault.change(|truth| truth.verify(a));
    let accepted =
        j.c.ports
            .engine
            .state()
            .creator
            .draft(j.p)
            .and_then(|d| {
                d.live_invitations()
                    .find(|(_, i)| i.accepted == Some(a))
                    .and_then(|(_, i)| i.terms)
            })
            .map(|(_, r)| r)
            .unwrap();
    let now = j.c.ports.clock.read();
    let r = stepped(&j.c, &j.admin, || {
        people::grant_account(j.p, a, "ProgrammeManager", now, None)
    });
    if matches!(r, Err(ApiError::Refused { .. })) {
        return;
    }
    done(&r, "roles.grant by account");
    let cited: Vec<_> =
        j.c.ports
            .engine
            .appended()
            .into_iter()
            .filter_map(|e| match e.cmd {
                Command::Core(fstp_domain::Command::GrantRole {
                    account,
                    confidentiality,
                    ..
                }) if account == a => Some(confidentiality),
                _ => None,
            })
            .collect();
    assert_eq!(
        cited,
        vec![Some(accepted)],
        "J2: the binding cites a confidentiality text other than the terms the invitee accepted"
    );
}
