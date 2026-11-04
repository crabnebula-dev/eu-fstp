//! The operator review gate in front of provisioning (TH-46; M4 design
//! sections 2.2 J0 and 3.5; `roles-and-sod.md` "Manual identity checks").
//!
//! Interim, pending Daniel: two distinct operator staff approve the
//! tenant's identity before a SaaS cell is provisioned. The design names
//! "operator staff" and records "the outcome and the reviewer". The
//! decided rule for the first tenant admin verification says two operator
//! staff take part, and these tests read the tenant review the same way.
//!
//! The rules these tests fix, for lane W2f:
//!
//! - `provision_permit` refuses until the tenant signed up, accepted every
//!   agreement at the versions the ledger offers, and two distinct staff
//!   approved.
//! - The gate permits a tenant once. After `TenantProvisioned` it refuses
//!   (`AlreadyProvisioned`), and no review of that tenant folds.
//! - One staff member's second approval is refused (`SameReviewer`).
//! - A rejection by any staff member, before or after approvals, is
//!   final. No permit is issued after it, and later reviews are refused.
//! - Reviews of one tenant never count for another.
//! - The fold applies the same rules, so a forged ledger never permits.
//!
//! Every test is red against the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_prop::{Gen, check};
use fstp_signup::{
    CpRecord, Refusal, ReviewOutcome, SignupError, SignupState, StaffId, decode_cp_record,
    encode_cp_record, provision_permit,
};
use support::{
    S1, S2, S3, T1, T2, V1, V2, accept_cmd, must, offer_cmd, provisioned_cmd, review_cmd, run,
    signed_and_accepted, signup_cmd,
};

use ReviewOutcome::{Approved, Rejected};

fn refused(r: Refusal) -> SignupError {
    SignupError::Refused(r)
}

/// TH-46: a tenant that signed up and accepted the agreements, with no
/// review, gets no permit.
#[test]
fn th46_signup_without_review_gets_no_permit() {
    let s = signed_and_accepted(T1, V1);
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::ReviewPending))
    );
}

/// TH-46: one staff approval holds the sign-up.
#[test]
fn th46_one_staff_approval_is_not_enough() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::ReviewPending))
    );
}

/// TH-46: one staff member cannot approve twice, and the second attempt
/// adds nothing to the review.
#[test]
fn th46_same_staff_cannot_approve_twice() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    let before = s.clone();
    assert_eq!(
        run(&mut s, &review_cmd(T1, S1, Approved)),
        Err(refused(Refusal::SameReviewer))
    );
    assert_eq!(s, before);
    assert!(provision_permit(&s, T1).is_err());
}

/// TH-46: two distinct staff approvals release the permit, which names
/// the tenant. Each review record names its staff member and outcome.
#[test]
fn th46_two_distinct_staff_approvals_permit_provisioning() {
    let mut s = signed_and_accepted(T1, V1);
    let first = must(&mut s, &review_cmd(T1, S1, Approved));
    let second = must(&mut s, &review_cmd(T1, S2, Approved));
    assert_eq!(
        first,
        vec![CpRecord::TenantReviewed {
            tenant: T1,
            outcome: Approved,
            by: S1,
            at: support::AT,
        }]
    );
    assert_eq!(
        second,
        vec![CpRecord::TenantReviewed {
            tenant: T1,
            outcome: Approved,
            by: S2,
            at: support::AT,
        }]
    );
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), Ok(T1));
}

/// TH-46: a rejection after one approval blocks the permit, and a later
/// approval by a third staff member is refused.
#[test]
fn th46_rejection_blocks_provisioning() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    must(&mut s, &review_cmd(T1, S2, Rejected));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::ReviewRejected))
    );
    assert_eq!(
        run(&mut s, &review_cmd(T1, S3, Approved)),
        Err(refused(Refusal::ReviewRejected))
    );
}

/// TH-46: a rejection after two approvals voids the permit. The gate
/// fails closed on the latest word of any staff member.
#[test]
fn th46_rejection_after_two_approvals_voids_the_permit() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    must(&mut s, &review_cmd(T1, S2, Approved));
    assert!(provision_permit(&s, T1).is_ok());
    must(&mut s, &review_cmd(T1, S1, Rejected));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::ReviewRejected))
    );
}

/// TH-46: a review of a tenant that never signed up is refused.
#[test]
fn th46_review_of_unknown_tenant_is_refused() {
    let mut s = signed_and_accepted(T1, V1);
    assert_eq!(
        run(&mut s, &review_cmd(T2, S1, Approved)),
        Err(refused(Refusal::UnknownTenant))
    );
    assert_eq!(
        provision_permit(&s, T2).map(|p| p.tenant()),
        Err(refused(Refusal::UnknownTenant))
    );
}

/// TH-46: approvals of one tenant never count for another.
#[test]
fn th46_approvals_of_another_tenant_never_count() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &signup_cmd(T2));
    must(&mut s, &accept_cmd(T2, V1));
    must(&mut s, &review_cmd(T2, S1, Approved));
    must(&mut s, &review_cmd(T2, S2, Approved));
    must(&mut s, &review_cmd(T1, S3, Approved));
    assert_eq!(provision_permit(&s, T2).map(|p| p.tenant()), Ok(T2));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::ReviewPending))
    );
}

/// TH-46, R-TN-01, Q22: a reviewed tenant that has not accepted the
/// agreements gets no permit.
#[test]
fn th46_permit_needs_the_agreements() {
    let mut s = support::offered(V1);
    must(&mut s, &signup_cmd(T1));
    must(&mut s, &review_cmd(T1, S1, Approved));
    must(&mut s, &review_cmd(T1, S2, Approved));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::AgreementsNotAccepted))
    );
}

/// TH-46, R-TN-01: when the offer changes, a permit needs the new
/// versions accepted. Accepting them releases it again.
#[test]
fn th46_permit_needs_the_offered_versions() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    must(&mut s, &review_cmd(T1, S2, Approved));
    assert_eq!(provision_permit(&s, T1).map(|p| p.versions()), Ok(V1));
    must(&mut s, &offer_cmd(V2));
    assert_eq!(
        provision_permit(&s, T1).map(|p| p.tenant()),
        Err(refused(Refusal::AgreementsNotAccepted))
    );
    must(&mut s, &accept_cmd(T1, V2));
    assert_eq!(provision_permit(&s, T1).map(|p| p.versions()), Ok(V2));
}

/// One generated step of a control plane run.
#[derive(Clone, Copy, Debug)]
enum Step {
    Signup(usize),
    Accept(usize, bool),
    Review(usize, usize, bool),
}

const TENANTS: [fstp_signup::TenantId; 2] = [T1, T2];
const STAFF: [StaffId; 3] = [S1, S2, S3];

fn gen_steps(g: &mut Gen) -> Vec<Step> {
    g.vec(0..=12, |g| match g.u8_in(0..=3) {
        0 => Step::Signup(g.usize_in(0..=1)),
        1 => Step::Accept(g.usize_in(0..=1), g.bool()),
        _ => Step::Review(g.usize_in(0..=1), g.usize_in(0..=2), g.u8_in(0..=4) != 0),
    })
}

/// Runs `steps` live and returns the state and every record it folded.
fn live(steps: &[Step]) -> (SignupState, Vec<CpRecord>) {
    let mut s = SignupState::new();
    let mut ledger = must(&mut s, &offer_cmd(V1));
    for step in steps {
        let cmd = match *step {
            Step::Signup(t) => signup_cmd(TENANTS[t]),
            Step::Accept(t, current) => accept_cmd(TENANTS[t], if current { V1 } else { V2 }),
            Step::Review(t, staff, approve) => review_cmd(
                TENANTS[t],
                STAFF[staff],
                if approve { Approved } else { Rejected },
            ),
        };
        if let Ok(records) = run(&mut s, &cmd) {
            ledger.extend(records);
        }
    }
    (s, ledger)
}

/// TH-46, ADR-007: replaying the stored ledger, after each record went
/// through its codec, gives the live state and the live gate answers.
#[test]
fn th46_replay_gives_the_live_gate() {
    check("th46_replay_gives_the_live_gate", |g| {
        let steps = gen_steps(g);
        let (state, ledger) = live(&steps);
        let mut stored = Vec::new();
        for r in &ledger {
            let bytes = encode_cp_record(r).map_err(|e| format!("encode {r:?}: {e:?}"))?;
            stored.push(decode_cp_record(&bytes).map_err(|e| format!("decode: {e:?}"))?);
        }
        let replayed = SignupState::replay(&stored).map_err(|e| format!("replay: {e:?}"))?;
        if replayed != state {
            return Err(format!(
                "replay differs from the live state after {steps:?}"
            ));
        }
        for t in TENANTS {
            let a = provision_permit(&state, t).map(|p| p.tenant());
            let b = provision_permit(&replayed, t).map(|p| p.tenant());
            if a != b {
                return Err(format!("permit {a:?} live, {b:?} replayed"));
            }
        }
        Ok(())
    });
}

fn offer(versions: fstp_signup::AgreementVersions) -> CpRecord {
    CpRecord::AgreementsOffered {
        versions,
        by: S1,
        at: support::AT,
    }
}

fn signed_up(t: fstp_signup::TenantId) -> CpRecord {
    let f = support::synthetic_signup();
    CpRecord::SignedUp {
        tenant: t,
        legal_name: f.legal_name,
        billing_address: f.billing_address,
        contracting_signatory: f.contracting_signatory,
        at: support::AT,
    }
}

fn accepted(t: fstp_signup::TenantId) -> Vec<CpRecord> {
    [
        (fstp_signup::Agreement::SaasTerms, V1.saas_terms),
        (fstp_signup::Agreement::Dpa, V1.dpa),
        (fstp_signup::Agreement::SubProcessors, V1.sub_processors),
    ]
    .into_iter()
    .map(|(agreement, version)| CpRecord::AgreementAccepted {
        tenant: t,
        agreement,
        version,
        by: "Synthetic Signatory".to_owned(),
        at: support::AT,
    })
    .collect()
}

fn reviewed(t: fstp_signup::TenantId, by: StaffId, outcome: ReviewOutcome) -> CpRecord {
    CpRecord::TenantReviewed {
        tenant: t,
        outcome,
        by,
        at: support::AT,
    }
}

/// The gate over a hand-written ledger: `Ok` only when replay accepts it
/// and the permit is issued.
fn permits(ledger: &[CpRecord]) -> bool {
    SignupState::replay(ledger).is_ok_and(|s| provision_permit(&s, T1).is_ok())
}

/// The honest ledger: T1 signed up, accepted V1 and holds two distinct
/// approvals.
fn honest() -> Vec<CpRecord> {
    let mut ledger = vec![offer(V1), signed_up(T1)];
    ledger.extend(accepted(T1));
    ledger.push(reviewed(T1, S1, Approved));
    ledger.push(reviewed(T1, S2, Approved));
    ledger
}

/// Checks that the honest ledger permits, so that a fold that refuses
/// everything cannot pass, and that `forged` does not.
fn forged_never_permits(forged: &[CpRecord]) {
    assert!(
        permits(&honest()),
        "the honest two-staff ledger must permit"
    );
    assert!(!permits(forged), "the forged ledger permits: {forged:?}");
}

/// TH-46: the hand-written ledger of two distinct approvals replays to a
/// permit.
#[test]
fn th46_fold_of_a_two_staff_ledger_permits() {
    assert!(permits(&honest()));
}

/// TH-46: a forged ledger in which one staff member approves twice never
/// permits provisioning.
#[test]
fn th46_fold_never_counts_one_staff_twice() {
    let mut ledger = vec![offer(V1), signed_up(T1)];
    ledger.extend(accepted(T1));
    ledger.push(reviewed(T1, S1, Approved));
    ledger.push(reviewed(T1, S1, Approved));
    forged_never_permits(&ledger);
}

/// TH-46: a forged ledger with approvals after a rejection never permits.
#[test]
fn th46_fold_never_permits_after_a_rejection() {
    let mut ledger = vec![offer(V1), signed_up(T1)];
    ledger.extend(accepted(T1));
    ledger.push(reviewed(T1, S1, Rejected));
    ledger.push(reviewed(T1, S2, Approved));
    ledger.push(reviewed(T1, S3, Approved));
    forged_never_permits(&ledger);
}

/// TH-46: a forged ledger whose approvals name another tenant never
/// permits T1.
#[test]
fn th46_fold_never_moves_approvals_between_tenants() {
    let mut ledger = vec![offer(V1), signed_up(T1), signed_up(T2)];
    ledger.extend(accepted(T1));
    ledger.push(reviewed(T2, S1, Approved));
    ledger.push(reviewed(T2, S2, Approved));
    forged_never_permits(&ledger);
}

/// TH-46: approvals recorded before the tenant's sign-up record never
/// count.
#[test]
fn th46_fold_never_counts_reviews_before_signup() {
    let mut ledger = vec![
        offer(V1),
        reviewed(T1, S1, Approved),
        reviewed(T1, S2, Approved),
    ];
    ledger.push(signed_up(T1));
    ledger.extend(accepted(T1));
    forged_never_permits(&ledger);
}

/// TH-46: a forged ledger that accepts the next offer's DPA before that
/// offer is recorded never permits under the next offer.
#[test]
fn th46_fold_never_counts_an_acceptance_before_its_offer() {
    let mut ledger = vec![offer(V1), signed_up(T1)];
    ledger.extend(accepted(T1));
    ledger.push(CpRecord::AgreementAccepted {
        tenant: T1,
        agreement: fstp_signup::Agreement::Dpa,
        version: V2.dpa,
        by: "Synthetic Signatory".to_owned(),
        at: support::AT,
    });
    ledger.push(offer(V2));
    ledger.push(reviewed(T1, S1, Approved));
    ledger.push(reviewed(T1, S2, Approved));
    forged_never_permits(&ledger);
}

/// TH-46: once the tenant's provisioning is recorded, the gate refuses a
/// second permit and a second record, and no later review folds.
#[test]
fn th46_gate_permits_a_tenant_once() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    must(&mut s, &review_cmd(T1, S2, Approved));
    let permit = provision_permit(&s, T1).unwrap();
    assert_eq!((permit.tenant(), permit.versions()), (T1, V1));
    let record = must(&mut s, &provisioned_cmd(T1));
    assert_eq!(
        record,
        vec![CpRecord::TenantProvisioned {
            tenant: T1,
            versions: V1,
            at: support::AT,
        }]
    );
    assert!(s.is_provisioned(T1));
    let gone = refused(Refusal::AlreadyProvisioned);
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), Err(gone));
    assert_eq!(run(&mut s, &provisioned_cmd(T1)), Err(gone));
    assert_eq!(run(&mut s, &review_cmd(T1, S3, Rejected)), Err(gone));
    assert_eq!(s.apply(&record[0]), Err(gone));
}

/// TH-46: the provisioning record passes the same gate as the permit, so
/// a tenant with one approval cannot be recorded as provisioned.
#[test]
fn th46_provisioning_record_needs_the_gate() {
    let mut s = signed_and_accepted(T1, V1);
    must(&mut s, &review_cmd(T1, S1, Approved));
    let pending = refused(Refusal::ReviewPending);
    assert_eq!(run(&mut s, &provisioned_cmd(T1)), Err(pending));
    let forged = CpRecord::TenantProvisioned {
        tenant: T1,
        versions: V1,
        at: support::AT,
    };
    assert_eq!(s.apply(&forged), Err(pending));
    assert!(!s.is_provisioned(T1));
}

/// TH-46: a forged provisioning record that names an offer other than
/// the current one is refused by the fold.
#[test]
fn th46_fold_refuses_provisioning_under_a_stale_offer() {
    let mut ledger = honest();
    ledger.push(offer(V2));
    ledger.push(CpRecord::TenantProvisioned {
        tenant: T1,
        versions: V1,
        at: support::AT,
    });
    assert_eq!(
        SignupState::replay(&ledger).map(|_| ()),
        Err(refused(Refusal::AgreementsNotAccepted))
    );
}
