//! I-77: accounts holding a Drafting, Judging, Operations or tenant admin
//! role log in with a phishing-resistant method only (design section 14.4,
//! T-AU-ROLES, R-LG-02).
//!
//! Lane W1b wrote these tests before the production code. Each compares
//! production against `fstp_celltest::reference::auth` or M-AUTH. They are
//! red until `fstp-auth` (lane W2b), `fstp-cell-core` (lane W2c), the cell
//! routes (lane W3a) and the tripwire count (lane W4) land. The teeth
//! tests also run on the reference, so each seeded defect is shown to fail
//! its property once the tripwire is recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::SessionDeny;
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, ReadAction};
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, one_cell_world};
use fstp_celltest::mc::auth_model::{
    self as m, AuthAction, AuthBackend, AuthDefect, AuthModel, AuthState, END_AT, Mutant, ProdCell,
    Production, Reference, RosterChange, account, ids, prod_enabled, prod_lifetimes, prod_method,
    prod_session, properties, sessions_ended_in,
};
use fstp_celltest::mc::tripwires::{M_AUTH, NOT_MEASURED, tripwire};
use fstp_celltest::reference::auth::{
    self as r, RefEnabled, RefLifetimes, RefMethod, RefRoster, RefSession,
};
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, B, P1, T0, grant, grant_until};
use fstp_domain_testkit::harness::teeth::{expect_violation, names_property};
use fstp_mc::{Config, Model, check, explore};
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

/// The bound of every M-AUTH run: twice the recorded count (design
/// section 14.1). A count not yet recorded fails here, by name.
fn bound() -> Config {
    assert_ne!(
        M_AUTH, NOT_MEASURED,
        "the M-AUTH tripwire is not recorded yet (lane W4); \
         i77_m_auth_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_AUTH))
}

/// Runs M-AUTH over `backend` and asserts every property passed exhaustively.
fn passes<B: fstp_celltest::mc::auth_model::AuthBackend>(backend: B) {
    let model = AuthModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.exhaustive,
        "M-AUTH did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

/// Runs M-AUTH over `backend` and asserts that property `id` is violated.
fn caught<B: fstp_celltest::mc::auth_model::AuthBackend>(backend: B, id: &str) {
    let model = AuthModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound().with_stop_when_decided(true));
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
    let message = match outcome.verdict(id).and_then(|v| v.violation()) {
        Some(v) => format!("{v:?}"),
        None => String::new(),
    };
    assert!(
        !message.contains("NotImplemented"),
        "teeth: {id} failed on a stub, not on the seeded defect: {message}"
    );
}

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-AUTH production backend: {e} (NotImplemented)"))
}

fn session_at(account: AccountId, method: RefMethod, started: Timestamp) -> RefSession {
    RefSession {
        id: [0x11; 16],
        account,
        method,
        device: (method == RefMethod::Passkey).then_some(0),
        started,
        last_used: started,
        ended: None,
    }
}

// ---------------------------------------------------------------------------
// M-AUTH.

/// I-77, M-AUTH over production: `fstp-auth` and the cell-core batches.
#[test]
fn i77_m_auth() {
    passes(production());
}

/// I-77, M-AUTH over the reference: every property and witness holds.
#[test]
fn i77_m_auth_on_the_reference() {
    passes(Reference);
}

/// I-77, design section 14.1: the recorded tripwire count is the measured
/// state count of M-AUTH over the reference.
#[test]
fn i77_m_auth_tripwire_records_the_measured_count() {
    let space = explore(&AuthModel::new(Reference), &Config::default());
    assert!(space.exhaustive, "M-AUTH over the reference did not finish");
    assert_eq!(
        M_AUTH,
        space.len(),
        "record the measured M-AUTH count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

// ---------------------------------------------------------------------------
// Production against the reference.

/// I-77: `admit_method` equals the reference login rule for every holding,
/// method and tenant setting (P-70). Logins here give user verification.
#[test]
fn i77_admit_method_matches_reference() {
    fstp_prop::check("i77_admit_method_matches_reference", |g: &mut Gen| {
        let holds = g.bool();
        let method = *g.pick(&RefMethod::ALL);
        let enabled = RefEnabled {
            magic_link: g.bool(),
            eudi_wallet: g.bool(),
            opaque: g.bool(),
        };
        let want = r::admit_login(holds, method, true, enabled).is_ok();
        let got = fstp_auth::admit_method(holds, prod_method(method), &prod_enabled(enabled));
        if let Err(fstp_auth::LoginDeny::NotImplemented(op)) = got {
            return Err(format!("{op} is NotImplemented"));
        }
        prop_assert_eq!(got.is_ok(), want, "holds {holds}, {method:?}, {enabled:?}");
        Ok(())
    });
}

/// I-77, P-72: `admit_session` equals the reference session rule around
/// the idle and absolute lifetimes, for holders and others.
#[test]
fn i77_admit_session_matches_reference() {
    fstp_prop::check("i77_admit_session_matches_reference", |g: &mut Gen| {
        let holds = g.bool();
        let method = *g.pick(&[RefMethod::Passkey, RefMethod::MagicLink]);
        let started = Timestamp::from_micros(T0.micros());
        let around = |g: &mut Gen, limit: i64| limit + g.i64_in(-2..=2);
        let used_after = g.i64_in(0..=r::P72_ABSOLUTE_US);
        let last_used = Timestamp::from_micros(started.micros() + used_after);
        let now = if g.bool() {
            Timestamp::from_micros(last_used.micros() + around(g, r::P72_IDLE_US).max(0))
        } else {
            Timestamp::from_micros(started.micros() + around(g, r::P72_ABSOLUTE_US).max(0))
        };
        let mut s = session_at(A, method, started);
        s.last_used = last_used;
        let want = r::admit_session(holds, &s, false, now, RefLifetimes::DEFAULT).is_ok();
        let got = fstp_auth::admit_session(
            holds,
            &prod_session(&s),
            now,
            &prod_lifetimes(RefLifetimes::DEFAULT),
        );
        if let Err(SessionDeny::NotImplemented(op)) = got {
            return Err(format!("{op} is NotImplemented"));
        }
        prop_assert_eq!(got.is_ok(), want, "holds {holds}, {s:?}, now {now:?}");
        Ok(())
    });
}

/// I-77, design section 8.2: `holds_management` counts binding holders and
/// tenant admins, and no one else.
///
/// Gap: `RosterView` carries no binding instants, so the view lists the
/// binding holders at `now` as the reference evaluates them. This checks
/// the union with the tenant fold only. The holding as the cell roster
/// gives it is checked by `i77_suspended_holder_magic_link_login_is_refused`
/// and by M-AUTH over production.
#[test]
fn i77_holds_management_matches_reference() {
    fstp_prop::check("i77_holds_management_matches_reference", |g: &mut Gen| {
        let now = Timestamp::from_micros(T0.micros());
        let mut roster = RefRoster::default();
        let accounts = [ADMIN, A, B];
        for a in accounts {
            if g.bool() {
                roster.admins.push(r::RefAdmin {
                    account: a,
                    end: None,
                });
            }
            if g.bool() {
                let role = *g.pick(&Role::ALL);
                roster.bindings.push(r::RefBinding {
                    account: a,
                    role,
                    end: None,
                    suspended: g.bool(),
                    voided: g.bool(),
                });
            }
        }
        let who = *g.pick(&accounts);
        let want = roster.holds_management(who, now);
        let view = fstp_auth::RosterView {
            management: roster.binding_holders_at(now),
        };
        let tenant = fstp_auth::TenantView {
            admins: roster.admins_at(now),
        };
        match fstp_auth::holds_management(&view, &tenant, who, now) {
            Err(fstp_auth::AuthError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
            Ok(h) => {
                prop_assert_eq!(h, want, "{roster:?} for {who:?}");
                Ok(())
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Scenarios over a production cell from genesis.

/// I-77, Q16 A: a scheduled binding end ends the account's earlier
/// sessions at its instant, with no command at the instant. The gate
/// admits the session 1 µs before the end and refuses it at the end and
/// 1 µs after. The session starts at `T0`, so it is inside the P-72 idle
/// lifetime at every probe, and only the binding end can refuse it.
#[test]
fn i77_scheduled_end_ends_sessions_at_its_instant() {
    let start = session_at(A, RefMethod::Passkey, T0);
    let before_end = Timestamp::from_micros(END_AT.micros() - 1);
    assert_eq!(
        r::admit_session(true, &start, false, before_end, RefLifetimes::DEFAULT),
        Ok(()),
        "the scenario's session must be live by P-72 just before the end"
    );
    let mut cell = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    let step = grant_until(
        BindingId::from_raw(3_001),
        A,
        P1,
        Role::CommitteeMember,
        T0,
        END_AT,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    cell.exec_step(&step, T0).unwrap_or_else(|e| panic!("{e}"));
    let logged = cell.log().len();
    let s = prod_session(&start);
    let policy = LoginPolicy {
        stepup_freshness_us: r::P71_DEFAULT_US,
    };
    let admit = |micros: i64| {
        gate::admit(
            cell.state(),
            &s,
            Action::Read(ReadAction::ReadContent),
            None,
            Timestamp::from_micros(micros),
            &policy,
        )
    };
    let before = admit(END_AT.micros() - 1);
    if let Err(Deny::NotImplemented(op)) = before {
        panic!("{op} is NotImplemented");
    }
    assert!(before.is_ok(), "1 µs before the end: {:?}", before.err());
    assert_eq!(
        admit(END_AT.micros()).err(),
        Some(Deny::SessionEnded),
        "at the end"
    );
    assert_eq!(
        admit(END_AT.micros() + 1).err(),
        Some(Deny::SessionEnded),
        "1 µs after"
    );
    assert_eq!(cell.log().len(), logged, "no command ran at the instant");
}

/// I-77, ADR-008: a grant of a management role ends the grantee's weak
/// sessions in the batch that records the grant. b logs in by magic link
/// before the grant, so the batch must name that session.
///
/// Gap: `decide` sees no session rows, so opening b's session refuses
/// with `SESSIONS_SEAM` for now. The PostgreSQL leg is
/// `i77_role_grant_session_end_rows_commit_with_the_batch`.
#[test]
fn i77_role_grant_ends_weak_sessions_in_the_same_batch() {
    let mut cell = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    let weak = session_at(B, RefMethod::MagicLink, T0);
    cell.open_session(&prod_session(&weak))
        .unwrap_or_else(|e| panic!("{e}"));
    let step = grant(BindingId::from_raw(3_002), B, P1, Role::FinanceApprover, T0);
    let batch = cell.exec_step(&step, T0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        sessions_ended_in(&batch),
        vec![weak.id],
        "the grant batch must end b's magic-link session and no other: {batch:?}"
    );
}

/// I-77, design section 8.2 and m3-base note 2: a binding under a
/// conflict-of-interest suspension still holds. After the suspension, the
/// gate refuses a's magic-link session as a weak session of a holder and
/// admits a's passkey session. Holdings come from the cell roster, not
/// from a holding evaluated outside production.
#[test]
fn i77_suspended_binding_still_holds_at_the_gate() {
    let mut cell = ProdCell::bootstrapped().unwrap_or_else(|e| panic!("{e}"));
    let binding = BindingId::from_raw(3_003);
    let step = grant(binding, A, P1, Role::CommitteeMember, T0);
    cell.exec_step(&step, T0).unwrap_or_else(|e| panic!("{e}"));
    cell.suspend_for_conflict(A, binding, T0)
        .unwrap_or_else(|e| panic!("{e}"));
    let now = Timestamp::from_micros(T0.micros() + 1);
    let policy = LoginPolicy {
        stepup_freshness_us: r::P71_DEFAULT_US,
    };
    let admit = |method: RefMethod| {
        gate::admit(
            cell.state(),
            &prod_session(&session_at(A, method, now)),
            Action::Read(ReadAction::ReadContent),
            None,
            now,
            &policy,
        )
    };
    let weak = admit(RefMethod::MagicLink);
    if let Err(Deny::NotImplemented(op)) = weak {
        panic!("{op} is NotImplemented");
    }
    assert_eq!(
        weak.err(),
        Some(Deny::WeakSessionForRole),
        "a suspended committee member's magic-link session"
    );
    let strong = admit(RefMethod::Passkey);
    assert!(
        strong.is_ok(),
        "a suspended committee member's passkey session: {:?}",
        strong.err()
    );
}

/// I-77, design section 8.2: a suspended holder's magic-link login is
/// refused, with the holding read through the production cell roster.
#[test]
fn i77_suspended_holder_magic_link_login_is_refused() {
    let roster = RefRoster {
        bindings: vec![r::RefBinding {
            account: A,
            role: Role::CommitteeMember,
            end: None,
            suspended: true,
            voided: false,
        }],
        admins: vec![r::RefAdmin {
            account: ADMIN,
            end: None,
        }],
    };
    let p = production();
    let holds = p
        .holds(&roster, A, T0)
        .unwrap_or_else(|e| panic!("{e} (NotImplemented)"));
    assert!(holds, "the cell roster does not count a suspended binding");
    let login = p
        .login(holds, RefMethod::MagicLink, m::ENABLED)
        .unwrap_or_else(|e| panic!("{e} (NotImplemented)"));
    assert!(!login, "a suspended holder logged in by magic link");
}

/// I-77, design section 4.2: a session ends only by an insert into
/// `auth_log.session_end`, made in the append that records `SessionEnded`.
/// The table must be catalogued for the writer to make that insert.
#[test]
fn i77_role_grant_session_end_rows_commit_with_the_batch() {
    let found = fstp_pgstore::CATALOGUE
        .iter()
        .any(|t| t.schema == "auth_log" && t.name == "session_end");
    assert!(
        found,
        "fstp_pgstore::CATALOGUE lists no auth_log.session_end (lane W2e); \
         the PostgreSQL leg of the grant batch waits for it"
    );
}

// ---------------------------------------------------------------------------
// The HTTP machine.

/// I-77 over HTTP: a machine of grants, ends, scheduled ends,
/// conflict-of-interest suspensions, logins by passkey and magic link,
/// and requests, compared step by step with M-AUTH over the reference.
/// The cell clock starts at the model's first tick, so session ages match.
#[test]
fn i77_management_login_requires_phishing_resistant_method_over_http() {
    let model = AuthModel::new(Reference);
    fstp_prop::check(
        "i77_management_login_requires_phishing_resistant_method_over_http",
        |g: &mut Gen| {
            let world = one_cell_world().map_err(|e| e.to_string())?;
            let cell = world.cell(0).ok_or("the world has no cell 0")?;
            let client = AuthClient::new(cell);
            let init = model.init();
            let mut s: AuthState = g.pick(&init).clone();
            client.set_clock(s.now()).map_err(|e| e.to_string())?;
            for who in m::ACCOUNTS {
                if !client.enrol(who).map_err(|e| e.to_string())? {
                    return Err(format!("{who:?} could not enrol"));
                }
            }
            let admin = client
                .login(ADMIN, RefMethod::Passkey)
                .map_err(|e| e.to_string())?
                .ok_or("admin1 cannot log in by passkey")?;
            // Each cookie's model key is its session and the number of its
            // login, so two sessions of one account, method and tick get
            // distinct keys. An ended session's cookie stays ended when a
            // later login opens a session with equal fields. Daniel decided
            // this bookkeeping on 2026-11-13 (M3 exit audit, section 7,
            // item 6). `latest` holds the login number that owns each
            // model session now.
            let mut cookies: Vec<((m::Sess, usize), Cookie)> = Vec::new();
            let mut latest: std::collections::BTreeMap<m::Sess, usize> =
                std::collections::BTreeMap::new();
            for _ in 0..g.usize_in(1..=12) {
                let mut actions = Vec::new();
                model.actions(&s, &mut actions);
                // Device removal is the R-LG-04 machine's, so this one takes no revocation.
                actions.retain(|a| *a != AuthAction::Revoke);
                let a = *g.pick(&actions);
                let next = model.step(&s, &a);
                match a {
                    AuthAction::Tick => {
                        let Some(t) = next else { continue };
                        client.set_clock(t.now()).map_err(|e| e.to_string())?;
                        s = t;
                    }
                    AuthAction::Login(i, method) => {
                        let got = client
                            .login(account(i), method)
                            .map_err(|e| e.to_string())?;
                        prop_assert_eq!(
                            got.is_some(),
                            next.is_some(),
                            "login of {i} by {method:?}"
                        );
                        if let (Some(c), Some(t)) = (got, next) {
                            if let Some(x) = t.sessions.iter().find(|x| !s.sessions.contains(x)) {
                                let n = cookies.len();
                                latest.insert(*x, n);
                                cookies.push(((*x, n), c));
                            }
                            s = t;
                        }
                    }
                    AuthAction::SuspendCm => {
                        let Some(t) = next else { continue };
                        let ok = client.suspend_for_conflict(A).map_err(|e| e.to_string())?;
                        prop_assert_eq!(ok, true, "the conflict-of-interest suspension of a");
                        s = t;
                    }
                    other => {
                        let Some(t) = next else { continue };
                        let change = match other {
                            AuthAction::GrantCm => RosterChange::Grant {
                                account: A,
                                role: Role::CommitteeMember,
                                until: None,
                            },
                            AuthAction::GrantCmUntil => RosterChange::Grant {
                                account: A,
                                role: Role::CommitteeMember,
                                until: Some(END_AT),
                            },
                            AuthAction::EndCm => RosterChange::End {
                                account: A,
                                role: Role::CommitteeMember,
                            },
                            AuthAction::GrantFa => RosterChange::Grant {
                                account: B,
                                role: Role::FinanceApprover,
                                until: None,
                            },
                            AuthAction::EndFa => RosterChange::End {
                                account: B,
                                role: Role::FinanceApprover,
                            },
                            AuthAction::GrantAdmin2 => RosterChange::GrantAdmin {
                                account: fstp_domain_testkit::r#gen::roster::ADMIN_2,
                            },
                            // The cell runs EndSessionsAtBindingEnd itself.
                            _ => {
                                s = t;
                                continue;
                            }
                        };
                        let ok = client.roster(&admin, change).map_err(|e| e.to_string())?;
                        prop_assert_eq!(ok, true, "roster change {change:?}");
                        s = t;
                    }
                }
                for ((x, n), c) in &cookies {
                    let live =
                        latest.get(x) == Some(n) && s.sessions.contains(x) && s.reference_admits(x);
                    let got = client.admitted(c).map_err(|e| e.to_string())?;
                    prop_assert_eq!(got, live, "request in session {x:?} at tick {}", s.tick);
                }
            }
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Teeth.

/// I-77 teeth: a gate that admits a weak session of a holder is caught.
#[test]
fn i77_teeth_weak_session_admitted_is_caught() {
    caught(
        Mutant::new(production(), AuthDefect::WeakSessionAdmitted),
        ids::I77_ADMIT,
    );
}

/// I-77 teeth: the same defect is caught on the reference.
#[test]
fn i77_teeth_weak_session_admitted_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuthDefect::WeakSessionAdmitted),
        ids::I77_ADMIT,
    );
}

/// I-77 teeth: `admit_method` that ignores scheduled bindings is caught.
#[test]
fn i77_teeth_admit_method_ignores_scheduled_bindings_is_caught() {
    caught(
        Mutant::new(production(), AuthDefect::LoginIgnoresScheduledBindings),
        ids::I77,
    );
}

/// I-77 teeth: the same defect is caught on the reference.
#[test]
fn i77_teeth_admit_method_ignores_scheduled_bindings_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuthDefect::LoginIgnoresScheduledBindings),
        ids::I77,
    );
}

/// I-77 teeth: a grant batch that omits `SessionEnded` is caught.
#[test]
fn i77_teeth_grant_batch_omits_session_ended_is_caught() {
    caught(
        Mutant::new(production(), AuthDefect::GrantBatchOmitsSessionEnded),
        ids::I77,
    );
}

/// I-77 teeth: the same defect is caught on the reference.
#[test]
fn i77_teeth_grant_batch_omits_session_ended_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuthDefect::GrantBatchOmitsSessionEnded),
        ids::I77,
    );
}

/// I-77 teeth, Q16 A: an `EndRole` batch that omits `SessionEnded` is
/// caught by the two-way comparison of batches. The gate still refuses
/// the stale session, so no other property sees it.
#[test]
fn i77_teeth_end_batch_omits_session_ended_is_caught() {
    caught(
        Mutant::new(production(), AuthDefect::EndBatchOmitsSessionEnded),
        ids::TWO_WAY,
    );
}

/// I-77 teeth: the same defect is caught on the reference.
#[test]
fn i77_teeth_end_batch_omits_session_ended_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, AuthDefect::EndBatchOmitsSessionEnded),
        ids::TWO_WAY,
    );
}

// ---------------------------------------------------------------------------
// The reference itself.

/// I-77: the reference refuses a magic-link login of every role outside
/// Receiving, and admits it for every Receiving role.
#[test]
fn i77_reference_refuses_magic_link_for_every_management_role() {
    let now = T0;
    let enabled = RefEnabled {
        magic_link: true,
        ..RefEnabled::default()
    };
    for role in Role::ALL {
        let roster = RefRoster {
            bindings: vec![r::RefBinding {
                account: A,
                role,
                end: None,
                suspended: false,
                voided: false,
            }],
            admins: Vec::new(),
        };
        let holds = roster.holds_management(A, now);
        let ok = r::admit_login(holds, RefMethod::MagicLink, true, enabled).is_ok();
        assert_eq!(
            ok,
            r::role_group(role) == r::RefGroup::Receiving,
            "{role:?}"
        );
    }
}

/// I-77, design section 8.2: a suspended binding still holds, a voided
/// one does not, and a scheduled end holds until its instant only.
#[test]
fn i77_reference_holdings_follow_the_strict_reading() {
    let b = |suspended, voided, end| r::RefBinding {
        account: A,
        role: Role::CommitteeMember,
        end,
        suspended,
        voided,
    };
    let holds = |x: r::RefBinding, now: i64| {
        RefRoster {
            bindings: vec![x],
            admins: Vec::new(),
        }
        .holds_management(A, Timestamp::from_micros(now))
    };
    let e = END_AT.micros();
    assert!(holds(b(true, false, None), e));
    assert!(!holds(b(false, true, None), e));
    assert!(holds(b(false, false, Some(END_AT)), e - 1));
    assert!(!holds(b(false, false, Some(END_AT)), e));
}

/// The names the property ids must carry, so the teeth messages name them.
#[test]
fn i77_model_property_ids_name_i77() {
    for id in [ids::I77, ids::I77_LOGIN, ids::I77_ADMIT] {
        assert!(names_property(&format!("{id}: x"), id), "{id}");
        assert!(id.starts_with("I-77"), "{id}");
    }
}
