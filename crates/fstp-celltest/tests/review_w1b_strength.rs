//! Review reproducers for lane W1b (I-77, I-78, I-79): test strength.
//!
//! Each test fails against the current models and passes once the named
//! defect is fixed. Runs use their own exhaustive bound, so they do not
//! wait for the tripwire counts of lane W4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::NotImplemented;
use fstp_celltest::mc::auth_model::{self as am, AuthBackend, AuthModel, RosterChange};
use fstp_celltest::mc::recover_model::{self as rm, RecoverBackend, RecoverModel};
use fstp_celltest::mc::stepup_model::{self as sm, StepUpBackend, StepUpModel};
use fstp_celltest::reference::auth::{
    RefApproval, RefDeployment, RefEnabled, RefEvidence, RefHoldings, RefLifetimes, RefMethod,
    RefPath, RefRoster, RefSession, RefStepUp, RefTicket,
};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_mc::{Config, check};

/// A bound far above every measured count, so each run is exhaustive.
fn wide() -> Config {
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(1_000_000)
}

// ---------------------------------------------------------------------------
// M-AUTH: the two-way check leaves out the batches of roster changes.

/// A grant batch that ends every session of the grantee, passkey ones too.
struct GrantEndsAll;

/// An `EndRole` batch that carries no `SessionEnded` (Q16 A).
struct EndOmitsSessionEnded;

fn all_of(sessions: &[RefSession], a: AccountId) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = sessions
        .iter()
        .filter(|s| s.account == a)
        .map(|s| s.id)
        .collect();
    out.sort();
    out
}

macro_rules! auth_passthrough {
    () => {
        fn holds(&self, r: &RefRoster, a: AccountId, n: Timestamp) -> Result<bool, NotImplemented> {
            am::Reference.holds(r, a, n)
        }
        fn login(&self, h: bool, m: RefMethod, e: RefEnabled) -> Result<bool, NotImplemented> {
            am::Reference.login(h, m, e)
        }
        fn session(
            &self,
            h: bool,
            s: &RefSession,
            b: bool,
            n: Timestamp,
            p: RefLifetimes,
        ) -> Result<bool, NotImplemented> {
            am::Reference.session(h, s, b, n, p)
        }
    };
}

impl AuthBackend for GrantEndsAll {
    auth_passthrough!();
    fn batch_ends(
        &self,
        change: RosterChange,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        match change {
            RosterChange::Grant { account, .. } | RosterChange::GrantAdmin { account } => {
                Ok(Some(all_of(sessions, account)))
            }
            RosterChange::End { .. } => am::Reference.batch_ends(change, before, sessions, now),
        }
    }
}

impl AuthBackend for EndOmitsSessionEnded {
    auth_passthrough!();
    fn batch_ends(
        &self,
        change: RosterChange,
        before: &RefRoster,
        sessions: &[RefSession],
        now: Timestamp,
    ) -> Result<Option<Vec<[u8; 16]>>, NotImplemented> {
        match change {
            RosterChange::End { .. } => Ok(Some(Vec::new())),
            _ => am::Reference.batch_ends(change, before, sessions, now),
        }
    }
}

fn auth_caught<B: AuthBackend>(b: B) {
    let model = AuthModel::new(b);
    let props = am::properties(&model);
    let outcome = check(&model, &props, &wide());
    assert!(outcome.exhaustive, "M-AUTH did not finish:\n{outcome}");
    assert!(
        outcome.has_failures(),
        "the seeded batch defect passed every M-AUTH property:\n{outcome}"
    );
}

/// I-77 review: a grant batch that also ends the grantee's passkey
/// sessions (over-denial) passes M-AUTH, since `two-way` never compares
/// `batch_ends` with the reference.
#[test]
fn review_i77_m_auth_grant_batch_ending_passkey_sessions_is_caught() {
    auth_caught(GrantEndsAll);
}

/// I-77 review, Q16 A: an `EndRole` batch that omits `SessionEnded`
/// passes M-AUTH. Design section 8.2 says the batch of a recorded end
/// carries the `SessionEnded` records.
#[test]
fn review_i77_m_auth_end_batch_omitting_session_ended_is_caught() {
    auth_caught(EndOmitsSessionEnded);
}

/// I-77 review: the M-AUTH production backend throws away the inputs a
/// correct production needs. `batch_ends` drops the session list and
/// `session` drops the binding end, so a correct `fstp-auth` and
/// `fstp-cell-core` cannot match the reference once the stubs go.
#[test]
fn review_i77_m_auth_production_backend_passes_sessions_and_binding_ends() {
    let src = include_str!("../src/mc/auth_model.rs");
    let start = src
        .find("impl AuthBackend for Production")
        .unwrap_or_else(|| panic!("no production impl"));
    let body = &src[start..];
    let end = body.find("\n}\n").unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        !body.contains("_sessions: &[RefSession]"),
        "Production::batch_ends ignores the sessions the batch must end"
    );
    assert!(
        !body.contains("_binding_ended: bool"),
        "Production::session ignores the binding end (Q16 A) instead of driving gate::admit"
    );
}

// ---------------------------------------------------------------------------
// M-STEPUP: the two-way check leaves out commit, and no magic-link case
// is refused by the magic-link rule alone.

/// A commit check that refuses every `ReleasePayment` (over-denial).
struct CommitRefusesRelease;

impl StepUpBackend for CommitRefusesRelease {
    fn admit(
        &self,
        s: &RefSession,
        c: u8,
        u: Option<&RefStepUp>,
        n: Timestamp,
        p: i64,
    ) -> Result<bool, NotImplemented> {
        sm::Reference.admit(s, c, u, n, p)
    }
    fn commit(
        &self,
        s: &RefSession,
        c: u8,
        u: Option<&RefStepUp>,
        n: Timestamp,
        p: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        if c == 2 {
            return Ok(None);
        }
        sm::Reference.commit(s, c, u, n, p)
    }
}

/// I-78 review: a commit-time check that refuses a valid `ReleasePayment`
/// passes M-STEPUP, since `two-way` compares admission only.
#[test]
fn review_i78_m_stepup_commit_over_denial_is_caught() {
    let model = StepUpModel::new(CommitRefusesRelease);
    let props = sm::properties(&model);
    let outcome = check(&model, &props, &wide());
    assert!(outcome.exhaustive, "M-STEPUP did not finish:\n{outcome}");
    assert!(
        outcome.has_failures(),
        "a commit that refuses every ReleasePayment passed M-STEPUP:\n{outcome}"
    );
}

/// I-78 review, design section 8.3: "A magic-link session never can" add
/// a passkey. The only magic-link admission of M-STEPUP is a role grant
/// by the applicant, which production refuses for lack of permission. So
/// no production run isolates the magic-link rule.
#[test]
fn review_i78_m_stepup_magic_link_session_tries_add_passkey() {
    assert!(
        sm::ADMITS.contains(&(sm::S_MAGIC, 3)),
        "M-STEPUP never admits AddPasskey in the magic-link session"
    );
}

// ---------------------------------------------------------------------------
// M-RECOVER: approvals, tickets and completion records are unchecked.

/// An approval check that ignores the step-up.
struct ApproveWithoutStepUp;

/// A ticket check that accepts one staff member twice.
struct OneStaffTicket;

/// A completion that revokes nothing and shows nothing. The backend trait
/// gives it no way to say so, which is the defect.
struct RevokesNothing;

macro_rules! recover_passthrough {
    (path) => {
        fn path(
            &self,
            h: RefHoldings,
            o: usize,
            m: RefDeployment,
        ) -> Result<RefPath, NotImplemented> {
            rm::Reference.path(h, o, m)
        }
    };
    (complete) => {
        fn complete(
            &self,
            r: &RefRoster,
            h: AccountId,
            q: RefPath,
            e: &RefEvidence,
            m: RefDeployment,
            n: Timestamp,
        ) -> Result<Option<RefPath>, NotImplemented> {
            rm::Reference.complete(r, h, q, e, m, n)
        }
    };
}

impl RecoverBackend for ApproveWithoutStepUp {
    recover_passthrough!(path);
    recover_passthrough!(complete);
    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        let forged = RefApproval {
            stepup_ok: true,
            ..*a
        };
        rm::Reference.approve(holder, &forged)
    }
    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        rm::Reference.ticket(t)
    }
}

impl RecoverBackend for OneStaffTicket {
    recover_passthrough!(path);
    recover_passthrough!(complete);
    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        rm::Reference.approve(holder, a)
    }
    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        Ok(t.case_matches && t.signature_ok)
    }
}

impl RecoverBackend for RevokesNothing {
    recover_passthrough!(path);
    recover_passthrough!(complete);
    fn approve(&self, holder: AccountId, a: &RefApproval) -> Result<bool, NotImplemented> {
        rm::Reference.approve(holder, a)
    }
    fn ticket(&self, t: &RefTicket) -> Result<bool, NotImplemented> {
        rm::Reference.ticket(t)
    }
}

fn recover_outcome<B: RecoverBackend>(
    b: B,
) -> fstp_mc::Outcome<rm::RecoverState, rm::RecoverAction> {
    let model = RecoverModel::new(b);
    let props = rm::properties(&model);
    let outcome = check(&model, &props, &wide());
    assert!(outcome.exhaustive, "M-RECOVER did not finish:\n{outcome}");
    outcome
}

/// I-79 review, design section 8.5: `SecondAdmin` needs `ApproveRecovery`
/// "with a step-up". An approval check that ignores the step-up passes
/// M-RECOVER, since no property and no two-way check reads `approve`.
#[test]
fn review_i79_m_recover_approval_without_step_up_is_caught() {
    let outcome = recover_outcome(ApproveWithoutStepUp);
    assert!(
        outcome.has_failures(),
        "an approval without a step-up passed M-RECOVER:\n{outcome}"
    );
}

/// I-79 review, design section 8.5: `OperatorProcess` needs two staff
/// approvals. A ticket check that accepts one staff member twice passes
/// M-RECOVER.
#[test]
fn review_i79_m_recover_one_staff_ticket_is_caught() {
    let outcome = recover_outcome(OneStaffTicket);
    assert!(
        outcome.has_failures(),
        "an operator ticket with one staff member passed M-RECOVER:\n{outcome}"
    );
}

/// I-79 review, Q15: completion revokes every credential and ends every
/// session, and an operator or console completion is shown to the tenant.
/// The model sets `revoked_all: true` and `shown` itself, so `I-79-shown`
/// holds for every backend. A completion that revokes nothing must fail it.
#[test]
fn review_i79_m_recover_completion_that_revokes_nothing_is_caught() {
    let outcome = recover_outcome(RevokesNothing);
    assert!(
        outcome
            .verdict(rm::ids::I79_SHOWN)
            .is_some_and(|v| v.violation().is_some()),
        "I-79-shown cannot fail: the model, not the backend, decides revocation and display"
    );
}

/// I-79 review: the M-RECOVER production backend recomputes the path at
/// completion and checks the evidence with the reference itself. So a
/// production `recovery::complete` that trusts the request-time path (the
/// design's teeth defect) can never be caught in production.
#[test]
fn review_i79_m_recover_production_complete_decides_in_production() {
    let src = include_str!("../src/mc/recover_model.rs");
    let start = src
        .find("impl RecoverBackend for Production")
        .unwrap_or_else(|| panic!("no production impl"));
    let body = &src[start..];
    let end = body.find("\n}\n").unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        !body.contains("r::evidence_completes"),
        "Production::complete decides the evidence with the reference, not production"
    );
    assert!(
        !body.contains("_requested: RefPath"),
        "Production::complete never gives production the request-time path"
    );
}
