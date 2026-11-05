//! SoD-07, SoD-14 to SoD-18 and the re-grant rule of M4 design section
//! 15.0, as one property over random sequences of signatory grants and
//! ends, activation requests and approvals, by both tenant admins.
//!
//! Lane m4/roles, test author. Each case walks a fresh cell to the
//! Administrators step with S1 holding both signatory roles, then runs the
//! sequence through `ApiCore::dispatch`, with a step-up wherever one is
//! asked for. After every operation it compares the dispatch with a small
//! reference written from `SPEC/02-domain/roles-and-sod.md`:
//!
//! - whether the operation completed or was refused, and that a refusal
//!   appended nothing;
//! - the signatory rows of `tenant.list_signatories`;
//! - the activation state of `tenant.get_activation`.
//!
//! The reference:
//!
//! - A grant by a tenant admin to their own account is refused (SoD-07:
//!   no second admin approves it in this model). A grant of a role the
//!   account holds is refused (15.0). Every other grant completes, and
//!   one account may hold both roles (SoD-16).
//! - An end of a role the account does not hold is refused. While the
//!   organisation is active, an end that leaves the role with no holder is
//!   refused (SoD-17). Every other end completes.
//! - A request in an active organisation is refused. Otherwise it
//!   completes only while each role has a holder (SoD-14, SoD-15). The
//!   model sends no request once one was made, and saves the
//!   Administrators step just before each request, so the step reflects
//!   the holders of that instant.
//! - An approval completes only when a request is open, it names that
//!   request, the approver is not the requester (SoD-18), and each role
//!   has a holder at that instant (SoD-14, SoD-15). It makes the
//!   organisation active.
//!
//! Red until the tenant crate holds the two roles and the activation
//! request and approval: the setup's first grant answers that its route
//! does not exist.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod signatories;

use std::collections::BTreeSet;

use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::WebLogin;
use fstp_domain::id::AccountId;
use fstp_json::Value;
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

use signatories::{
    A1, A2, BOTH, FINANCIAL, LEGAL, S1, S2, activation, appended, approve, completed, ending,
    grant, holders, member, onboarded, request, row, save_administrators, stepped, text,
};

/// One operation of the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// `by` grants `role` to `account`.
    Grant {
        by: AccountId,
        account: AccountId,
        role: &'static str,
    },
    /// `by` ends `account`'s binding of `role`.
    End {
        by: AccountId,
        account: AccountId,
        role: &'static str,
    },
    /// `by` saves the Administrators step and requests activation.
    Request { by: AccountId },
    /// `by` approves the open request, or another request id.
    Approve { by: AccountId, right: bool },
}

/// The reference state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Model {
    /// Account and role of every signatory binding held now.
    holders: BTreeSet<(AccountId, &'static str)>,
    /// The requester of the open request, if any.
    requested_by: Option<AccountId>,
    /// Whether an approval made the organisation active.
    active: bool,
}

impl Model {
    fn count(&self, role: &str) -> usize {
        self.holders.iter().filter(|(_, r)| *r == role).count()
    }

    fn both_held(&self) -> bool {
        BOTH.iter().all(|r| self.count(r) > 0)
    }

    /// Whether the reference accepts `step`, and the state after it.
    fn step(&self, step: Step) -> (bool, Model) {
        let mut next = self.clone();
        let accepted = match step {
            Step::Grant { by, account, role } => {
                let ok = account != by && !self.holders.contains(&(account, role));
                if ok {
                    next.holders.insert((account, role));
                }
                ok
            }
            Step::End { account, role, .. } => {
                let held = self.holders.contains(&(account, role));
                let last = self.count(role) == 1;
                let ok = held && !(self.active && last);
                if ok {
                    next.holders.remove(&(account, role));
                }
                ok
            }
            Step::Request { by } => {
                let ok = !self.active && self.requested_by.is_none() && self.both_held();
                if ok {
                    next.requested_by = Some(by);
                }
                ok
            }
            Step::Approve { by, right } => {
                let ok = !self.active
                    && right
                    && self.requested_by.is_some_and(|r| r != by)
                    && self.both_held();
                if ok {
                    next.active = true;
                }
                ok
            }
        };
        (accepted, next)
    }

    fn state(&self) -> &'static str {
        if self.active {
            "active"
        } else if self.requested_by.is_some() {
            "requested"
        } else {
            "not_requested"
        }
    }

    fn rows(&self) -> BTreeSet<(String, String)> {
        self.holders.iter().map(|(a, r)| row(*a, r)).collect()
    }
}

/// Draws the next step, given the reference state. No request is drawn
/// once one was made, open or approved.
fn draw(g: &mut Gen, m: &Model) -> Step {
    let admins = [A1, A2];
    let accounts = [A1, A2, S1, S2];
    let by = *g.pick(&admins);
    let role = *g.pick(&BOTH);
    let account = *g.pick(&accounts);
    let kinds: &[u8] = if m.requested_by.is_some() {
        &[0, 1, 3]
    } else {
        &[0, 1, 2, 3]
    };
    match *g.pick(kinds) {
        0 => Step::Grant { by, account, role },
        1 => Step::End { by, account, role },
        2 => Step::Request { by },
        _ => Step::Approve {
            by,
            right: g.u8_in(0..=3) > 0,
        },
    }
}

/// The open request id as the activation read shows it, if any.
fn open_id(c: &FakeCell, l: &WebLogin) -> Option<String> {
    match member(&activation(c, l), "request") {
        Value::String(s) => Some(s),
        _ => None,
    }
}

/// Runs `step` through dispatch, with a step-up where asked.
fn run(c: &FakeCell, logins: &[(AccountId, WebLogin)], step: Step) -> Result<OpResult, ApiError> {
    let by = match step {
        Step::Grant { by, .. }
        | Step::End { by, .. }
        | Step::Request { by }
        | Step::Approve { by, .. } => by,
    };
    let l = logins
        .iter()
        .find(|(a, _)| *a == by)
        .map(|(_, l)| l)
        .unwrap_or_else(|| panic!("no login for {by:?}"));
    match step {
        Step::Grant { account, role, .. } => stepped(c, l, &|| grant(account, role)),
        Step::End { account, role, .. } => ending(c, l, account, role),
        Step::Request { .. } => {
            let _ = save_administrators(c, l);
            request(c, l)
        }
        Step::Approve { right, .. } => {
            let id = match (open_id(c, l), right) {
                (Some(id), true) => id,
                (Some(id), false) => format!("{id}9"),
                (None, _) => "1".to_owned(),
            };
            approve(c, l, &id)
        }
    }
}

/// SoD-07, SoD-14, SoD-15, SoD-16, SoD-17, SoD-18 and 15.0: dispatch
/// agrees with the reference on every operation of a random sequence.
#[test]
fn sod14_sod18_m_signatories_and_activation_match_the_reference() {
    check_with(
        "sod14_sod18_m_signatories_and_activation_match_the_reference",
        Config::from_env().with_cases(48),
        |g| {
            let (c, l1, l2) = onboarded(&[(S1, FINANCIAL), (S1, LEGAL)]);
            let logins = [(A1, l1), (A2, l2)];
            let mut m = Model::default();
            m.holders.insert((S1, FINANCIAL));
            m.holders.insert((S1, LEGAL));
            let n = g.usize_in(1..=10);
            for i in 0..n {
                let step = draw(g, &m);
                g.note("step", &(i, step));
                let (want, next) = m.step(step);
                let before = appended(&c);
                let r = run(&c, &logins, step);
                if let Err(ApiError::Refused { rule: "route", .. }) = &r {
                    return Err(format!(
                        "SA-01: the route of {step:?} does not exist: {r:?}"
                    ));
                }
                prop_assert_eq!(
                    completed(&r),
                    want,
                    "step {} {:?}: dispatch gave {:?}",
                    i,
                    step,
                    r
                );
                if !want && !matches!(step, Step::Request { .. }) {
                    prop_assert_eq!(appended(&c), before, "step {}: a refusal appended", i);
                }
                m = next;
                let (_, l) = logins.first().ok_or_else(|| "no login".to_owned())?;
                prop_assert_eq!(holders(&c, l), m.rows(), "step {}: the signatory rows", i);
                let v = activation(&c, l);
                prop_assert_eq!(text(&v, "state"), m.state(), "step {}: {:?}", i, v);
                if let Some(by) = m.requested_by {
                    prop_assert!(
                        text(&v, "requested_by") == by.raw().to_string(),
                        "step {}: requested_by in {:?}",
                        i,
                        v
                    );
                }
            }
            Ok(())
        },
    );
}
