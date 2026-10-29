//! R-LG-04: users can see and end their sessions and linked devices
//! (design section 8.2, ADR-008 "Sessions"). Removing a device is the
//! high-risk action `ChangeLoginMethods` (I-78).
//!
//! Lane W1b wrote these tests before the production code. They are red
//! until the gate (lane W2c) and the session routes (lane W3a) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::AuthCommand;
use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, Deny, HighRiskAction};
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, one_cell_world};
use fstp_celltest::reference::auth::{
    self as r, EndCause, ROUTES, RefBinding, RefHighRisk, RefLifetimes, RefMethod, RefRisk,
    RefRoster, RefSession,
};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, B};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

const NOW: Timestamp = Timestamp::from_micros(5_000_000_000);

/// The number of entries a `GET /auth/sessions` or `GET /auth/devices`
/// body lists.
///
/// Reading: the body is a JSON array with one object per entry, each with
/// an `id` member. The design names the routes but not the body.
fn entries(body: &[u8]) -> usize {
    body.windows(4).filter(|w| *w == b"\"id\"").count()
}

/// R-LG-04, I-78: removing a device is `ChangeLoginMethods`, so it needs a
/// fresh step-up.
#[test]
fn r_lg_04_removing_a_device_is_change_login_methods() {
    let action = Action::Command(CellCommand::Auth(AuthCommand::RevokeCredential {
        account: A,
        credential: vec![0x5E, 0],
    }));
    match HighRiskAction::of(&action) {
        Err(Deny::NotImplemented(op)) => panic!("{op} is NotImplemented"),
        got => assert_eq!(got, Ok(Some(HighRiskAction::ChangeLoginMethods))),
    }
}

/// R-LG-04, design section 8.7: listing and ending sessions and listing
/// devices need a session; removing a device needs a step-up.
#[test]
fn r_lg_04_reference_session_and_device_routes_have_their_risk_classes() {
    let class = |method: &str, path: &str| {
        ROUTES
            .iter()
            .find(|x| x.method == method && x.path == path)
            .map(|x| x.risk)
    };
    assert_eq!(class("GET", "/auth/sessions"), Some(RefRisk::Session));
    assert_eq!(
        class("DELETE", "/auth/sessions/{id}"),
        Some(RefRisk::Session)
    );
    assert_eq!(class("GET", "/auth/devices"), Some(RefRisk::Session));
    assert_eq!(
        class("DELETE", "/auth/devices/{id}"),
        Some(RefRisk::HighRisk(RefHighRisk::ChangeLoginMethods))
    );
}

/// R-LG-04: the reference lists an account's own live sessions only, and
/// lets an account end only its own live sessions.
#[test]
fn r_lg_04_reference_lists_only_own_live_sessions() {
    fstp_prop::check(
        "r_lg_04_reference_lists_only_own_live_sessions",
        |g: &mut Gen| {
            let mut sessions = Vec::new();
            for n in 0..g.u8_in(0..=6) {
                let account = *g.pick(&[A, B]);
                let started =
                    Timestamp::from_micros(NOW.micros() - g.i64_in(0..=r::P72_IDLE_US + 2));
                let ended = g
                    .bool()
                    .then_some((Timestamp::from_micros(NOW.micros() - 1), EndCause::User));
                sessions.push(RefSession {
                    id: [n; 16],
                    account,
                    method: *g.pick(&[RefMethod::Passkey, RefMethod::MagicLink]),
                    device: Some(0),
                    started,
                    last_used: started,
                    ended,
                });
            }
            let who = *g.pick(&[A, B]);
            let listed = r::listed_sessions(
                &RefRoster::default(),
                &sessions,
                who,
                NOW,
                RefLifetimes::DEFAULT,
            );
            for s in &sessions {
                let live = s.ended.is_none() && r::within(s.last_used, NOW, r::P72_IDLE_US);
                let want = s.account == who && live;
                prop_assert_eq!(listed.contains(&s.id), want, "{s:?} listed for {who:?}");
                prop_assert!(
                    !r::may_end_session(&sessions, who, s.id)
                        || (s.account == who && s.ended.is_none()),
                    "{who:?} may end {s:?}"
                );
            }
            Ok(())
        },
    );
}

/// R-LG-04, I-77, design section 8.2: the reference lists no session that
/// the gate refuses. A weak session of a holder and a session that
/// started before a binding end are not listed; a passkey session that
/// started after the end is.
#[test]
fn r_lg_04_reference_lists_no_session_the_gate_refuses() {
    let end_at = Timestamp::from_micros(NOW.micros() - r::MINUTE_US);
    let roster = RefRoster {
        bindings: vec![
            RefBinding {
                account: A,
                role: fstp_domain::roles::Role::CommitteeMember,
                end: None,
                suspended: false,
                voided: false,
            },
            RefBinding {
                account: A,
                role: fstp_domain::roles::Role::FinanceApprover,
                end: Some(end_at),
                suspended: false,
                voided: false,
            },
        ],
        admins: Vec::new(),
    };
    let at = |offset_us: i64| Timestamp::from_micros(NOW.micros() - offset_us);
    let session = |n: u8, method: RefMethod, started: Timestamp| RefSession {
        id: [n; 16],
        account: A,
        method,
        device: (method == RefMethod::Passkey).then_some(0),
        started,
        last_used: started,
        ended: None,
    };
    let sessions = [
        // A weak session of a holder.
        session(1, RefMethod::MagicLink, at(10 * r::SECOND_US)),
        // A passkey session that started before the binding end.
        session(2, RefMethod::Passkey, at(2 * r::MINUTE_US)),
        // A passkey session that started after the binding end.
        session(3, RefMethod::Passkey, at(10 * r::SECOND_US)),
    ];
    let listed = r::listed_sessions(&roster, &sessions, A, NOW, RefLifetimes::DEFAULT);
    assert_eq!(listed, vec![[3; 16]]);
}

/// One step of the R-LG-04 machine.
#[derive(Clone, Copy, Debug)]
enum Op {
    Login(usize),
    List(usize),
    End(usize, usize),
    Devices(usize),
    RemoveDevice(usize, bool),
}

/// R-LG-04 over HTTP: logins of a and b, listing and ending sessions,
/// ending another account's session, listing devices, and removing a
/// device with and without a step-up, compared with the reference.
///
/// Reading: removing a device ends the sessions it logged in, and the
/// device can log in no more.
#[test]
fn r_lg_04_sessions_and_devices_listed_and_ended() {
    fstp_prop::check(
        "r_lg_04_sessions_and_devices_listed_and_ended",
        |g: &mut Gen| {
            let e = |x: fstp_celltest::NotImplemented| x.to_string();
            let world = one_cell_world().map_err(|x| x.to_string())?;
            let cell = world.cell(0).ok_or("the world has no cell 0")?;
            let client = AuthClient::new(cell);
            let accounts: [AccountId; 2] = [A, B];
            for who in accounts {
                if !client.enrol(who).map_err(e)? {
                    return Err(format!("{who:?} could not enrol"));
                }
            }
            // The reference: each login is (account index, cookie, live).
            let mut logins: Vec<(usize, Cookie, bool)> = Vec::new();
            let mut removed = [false; 2];
            for _ in 0..g.usize_in(1..=10) {
                let n = logins.len();
                let op = if n == 0 {
                    Op::Login(g.usize_in(0..=1))
                } else {
                    match g.u8_in(0..=4) {
                        0 => Op::Login(g.usize_in(0..=1)),
                        1 => Op::List(g.usize_in(0..=n - 1)),
                        2 => Op::End(g.usize_in(0..=n - 1), g.usize_in(0..=n - 1)),
                        3 => Op::Devices(g.usize_in(0..=n - 1)),
                        _ => Op::RemoveDevice(g.usize_in(0..=n - 1), g.bool()),
                    }
                };
                match op {
                    Op::Login(i) => {
                        let got = client.login(accounts[i], RefMethod::Passkey).map_err(e)?;
                        prop_assert_eq!(got.is_some(), !removed[i], "login of {i}");
                        if let Some(c) = got {
                            logins.push((i, c, true));
                        }
                    }
                    Op::List(k) => {
                        let (i, c, live) = logins[k].clone();
                        let got = client.sessions(&c).map_err(e)?;
                        prop_assert_eq!(got.is_some(), live, "list in login {k}");
                        if let Some(body) = got {
                            let own = logins.iter().filter(|(j, _, l)| *j == i && *l).count();
                            prop_assert_eq!(entries(&body), own, "sessions listed for {i}");
                        }
                    }
                    Op::End(k, target) => {
                        let (i, c, live) = logins[k].clone();
                        let (j, t, target_live) = logins[target].clone();
                        // Reading: the cookie value stands in for the listed session id.
                        let id = t.0.clone();
                        let got = client.end_session(&c, &id).map_err(e)?;
                        let want = live && i == j && target_live;
                        prop_assert_eq!(got, want, "login {k} ends login {target}");
                        if want {
                            logins[target].2 = false;
                        }
                    }
                    Op::Devices(k) => {
                        let (i, c, live) = logins[k].clone();
                        let got = client.devices(&c).map_err(e)?;
                        prop_assert_eq!(got.is_some(), live, "devices in login {k}");
                        if let Some(body) = got {
                            prop_assert_eq!(
                                entries(&body),
                                usize::from(!removed[i]),
                                "devices of {i}"
                            );
                        }
                    }
                    Op::RemoveDevice(k, stepup) => {
                        let (i, c, live) = logins[k].clone();
                        let got = client.remove_device(&c, 0, stepup).map_err(e)?;
                        let want = live && stepup && !removed[i];
                        prop_assert_eq!(
                            got,
                            want,
                            "login {k} removes its device, step-up {stepup}"
                        );
                        if want {
                            removed[i] = true;
                            for l in logins.iter_mut().filter(|(j, _, _)| *j == i) {
                                l.2 = false;
                            }
                        }
                    }
                }
                for (k, (_, c, live)) in logins.iter().enumerate() {
                    prop_assert_eq!(client.admitted(c).map_err(e)?, *live, "login {k} admitted");
                }
            }
            Ok(())
        },
    );
}
