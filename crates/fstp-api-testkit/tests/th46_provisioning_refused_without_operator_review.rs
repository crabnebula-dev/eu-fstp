//! TH-46 (T-WL-DOMAIN seed): provisioning is refused without the
//! operator review of the SaaS tenant's identity (M4 design sections 2.2
//! J0, 3.5 and 5.1).
//!
//! Interim, pending Daniel: the review needs approvals by two distinct
//! operator staff, as the decided first tenant admin verification does
//! (`roles-and-sod.md`). One rejection is final.
//!
//! Three parts:
//!
//! - `th46_provisioning_refused_without_operator_review` walks journey J0
//!   from the submitted form bytes to the provisioning permit.
//! - `th46_m_review` is an exhaustive model over two tenants, three staff
//!   and two agreement offers. It checks production against an
//!   independent reference written from the design text. Its `_on_the_reference`
//!   twin runs the reference alone and fixes the state count.
//! - `th46_teeth_one_approval_permit_is_caught` injects a gate that
//!   permits after one approval and expects `always("TH-46")` to catch it.
//!
//! The production backend records the offer in the ledger: the initial
//! state holds the offer of V1, and `NewOffer` is the operator command
//! that offers V2. The reference keeps the offer as model state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use fstp_domain_testkit::harness::mc::{check_exhaustive, tripwire};
use fstp_domain_testkit::harness::teeth::{Injecting, expect_violation};
use fstp_mc::{Model, Property, check};
use fstp_signup::{
    AgreementFields, AgreementVersions, CpCommand, Refusal, ReviewOutcome, SignupError, SignupForm,
    SignupState, StaffId, TenantId, decide, decode_signup_form, provision_permit,
};

/// The operator command that offers `versions`.
fn offer(versions: AgreementVersions) -> CpCommand {
    CpCommand::OfferAgreements {
        versions,
        staff: STAFF[0],
        at: AT,
    }
}

const AT: i64 = 1_793_404_800;
const T1: TenantId = TenantId::from_raw(0x5e1f_0000_0000_0000_0000_0000_0000_0001);
const T2: TenantId = TenantId::from_raw(0x5e1f_0000_0000_0000_0000_0000_0000_0002);
const TENANTS: [TenantId; 2] = [T1, T2];
const STAFF: [StaffId; 3] = [
    StaffId::from_raw(0x57af_0001),
    StaffId::from_raw(0x57af_0002),
    StaffId::from_raw(0x57af_0003),
];

/// The first offer and a later one in which only the DPA changed.
const V1: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};
const V2: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 2,
    sub_processors: 1,
};

/// The state count of the reference run, measured on the reference twin on
/// 2026-10-31. The tripwire allows twice this many states. The production
/// run uses the same count while the production fold keeps no fact the
/// reference lacks. If it keeps more, the lane measures and records it here.
const REFERENCE_STATES: usize = 5_314;

// ---------------------------------------------------------------------
// Journey J0 through the form decoder
// ---------------------------------------------------------------------

fn decide_and_apply(s: &mut SignupState, cmd: &CpCommand) -> Result<(), SignupError> {
    for r in decide(s, cmd)? {
        s.apply(&r)?;
    }
    Ok(())
}

fn review(s: &mut SignupState, staff: StaffId) -> Result<(), SignupError> {
    decide_and_apply(
        s,
        &CpCommand::ReviewTenant {
            tenant: T1,
            staff,
            outcome: ReviewOutcome::Approved,
            at: AT,
        },
    )
}

/// TH-46, R-TN-01: a tenant signs up and accepts the agreements through
/// the submitted forms. Provisioning is refused with no review and with
/// one approval, and one staff member approving twice changes nothing.
/// The permit is issued after a second staff member approves.
#[test]
fn th46_provisioning_refused_without_operator_review() {
    let signup = b"form=signup&legal_name=Synthetic+Test+Organisation+SRL\
                   &billing_address=1+Synthetic+Street%0D%0A0000+Testville\
                   &contracting_signatory=Synthetic+Signatory";
    let Ok(SignupForm::Signup(fields)) = decode_signup_form(signup) else {
        panic!("the synthetic sign-up form did not decode");
    };
    let mut s = SignupState::new();
    decide_and_apply(&mut s, &offer(V1)).unwrap();
    decide_and_apply(
        &mut s,
        &CpCommand::Signup {
            tenant: T1,
            form: fields,
            at: AT,
        },
    )
    .unwrap();

    let agreements = format!(
        "form=agreements&tenant={:032x}&saas_terms=1&dpa=1&sub_processors=1\
         &accepted_by=Synthetic+Signatory",
        T1.raw()
    );
    let Ok(SignupForm::Agreements(form)) = decode_signup_form(agreements.as_bytes()) else {
        panic!("the synthetic agreement form did not decode");
    };
    assert_eq!(
        form,
        AgreementFields {
            tenant: T1,
            versions: V1,
            accepted_by: "Synthetic Signatory".to_owned(),
        }
    );
    decide_and_apply(&mut s, &CpCommand::AcceptAgreements { form, at: AT }).unwrap();

    let pending = Err(SignupError::Refused(Refusal::ReviewPending));
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), pending);
    review(&mut s, STAFF[0]).unwrap();
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), pending);
    assert_eq!(
        review(&mut s, STAFF[0]),
        Err(SignupError::Refused(Refusal::SameReviewer))
    );
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), pending);
    review(&mut s, STAFF[1]).unwrap();
    assert_eq!(provision_permit(&s, T1).map(|p| p.tenant()), Ok(T1));
}

// ---------------------------------------------------------------------
// M-REVIEW: the reference
// ---------------------------------------------------------------------

/// The reference view of one tenant, written from design section 3.5 and
/// the interim two-staff reading. It shares no code with `fstp-signup`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct RefTenant {
    signed: bool,
    /// Accepted (agreement index, version) pairs.
    accepted: BTreeSet<(u8, u32)>,
    /// Indexes into [`STAFF`] of the staff who approved.
    approvers: BTreeSet<u8>,
    rejected: bool,
}

fn named(v: AgreementVersions) -> BTreeSet<(u8, u32)> {
    [(0, v.saas_terms), (1, v.dpa), (2, v.sub_processors)]
        .into_iter()
        .collect()
}

impl RefTenant {
    /// The reference gate: signed up, every offered version accepted, two
    /// distinct approvals and no rejection.
    fn permits(&self, offered: AgreementVersions) -> bool {
        self.signed
            && !self.rejected
            && self.approvers.len() >= 2
            && named(offered).is_subset(&self.accepted)
    }
}

/// What the reference says production must answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Accept,
    Refuse,
    /// The design leaves the answer open, and the gate is the same either
    /// way: a repeated acceptance, an acceptance by a rejected tenant, or
    /// a third approval.
    Either,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    Signup(u8),
    /// Accept the offered versions (`true`) or the other offer (`false`).
    Accept(u8, bool),
    /// The control plane moves its offer from V1 to V2.
    NewOffer,
    /// A staff member approves (`true`) or rejects (`false`).
    Review(u8, u8, bool),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct St {
    second_offer: bool,
    refs: [RefTenant; 2],
    prod: Option<SignupState>,
    /// The gate answer per tenant: production's on the production
    /// backend, the reference's on the reference backend.
    permitted: [bool; 2],
    /// Production disagreed with the reference on an answer or the gate.
    mismatch: bool,
}

impl St {
    fn offered(&self) -> AgreementVersions {
        if self.second_offer { V2 } else { V1 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Production,
    Reference,
}

struct ReviewModel {
    backend: Backend,
}

fn expect(r: &RefTenant, act: Act, offered: AgreementVersions) -> Expect {
    match act {
        Act::Signup(_) if r.signed => Expect::Refuse,
        Act::Signup(_) => Expect::Accept,
        Act::Accept(..) | Act::Review(..) if !r.signed => Expect::Refuse,
        Act::Accept(_, false) => Expect::Refuse,
        Act::Accept(_, true) if r.rejected || named(offered).is_subset(&r.accepted) => {
            Expect::Either
        }
        Act::Accept(_, true) => Expect::Accept,
        Act::Review(..) if r.rejected => Expect::Refuse,
        Act::Review(_, staff, true) if r.approvers.contains(&staff) => Expect::Refuse,
        Act::Review(_, _, true) if r.approvers.len() >= 2 => Expect::Either,
        Act::Review(..) => Expect::Accept,
        Act::NewOffer => Expect::Accept,
    }
}

fn effect(r: &mut RefTenant, act: Act, offered: AgreementVersions) {
    match act {
        Act::Signup(_) => r.signed = true,
        Act::Accept(_, current) => {
            let versions = if current { offered } else { other(offered) };
            r.accepted.extend(named(versions));
        }
        Act::Review(_, staff, true) => {
            r.approvers.insert(staff);
        }
        Act::Review(_, _, false) => r.rejected = true,
        Act::NewOffer => {}
    }
}

fn other(offered: AgreementVersions) -> AgreementVersions {
    if offered == V1 { V2 } else { V1 }
}

fn command(act: Act, offered: AgreementVersions) -> Option<CpCommand> {
    match act {
        Act::Signup(t) => Some(CpCommand::Signup {
            tenant: TENANTS[usize::from(t)],
            form: fstp_signup::SignupFields {
                legal_name: format!("Synthetic Test Organisation {t}"),
                billing_address: "1 Synthetic Street".to_owned(),
                contracting_signatory: "Synthetic Signatory".to_owned(),
            },
            at: AT,
        }),
        Act::Accept(t, current) => Some(CpCommand::AcceptAgreements {
            form: AgreementFields {
                tenant: TENANTS[usize::from(t)],
                versions: if current { offered } else { other(offered) },
                accepted_by: "Synthetic Signatory".to_owned(),
            },
            at: AT,
        }),
        Act::Review(t, staff, approve) => Some(CpCommand::ReviewTenant {
            tenant: TENANTS[usize::from(t)],
            staff: STAFF[usize::from(staff)],
            outcome: if approve {
                ReviewOutcome::Approved
            } else {
                ReviewOutcome::Rejected
            },
            at: AT,
        }),
        Act::NewOffer => Some(offer(other(offered))),
    }
}

impl Model for ReviewModel {
    type State = St;
    type Action = Act;

    fn init(&self) -> Vec<St> {
        vec![St {
            second_offer: false,
            refs: [RefTenant::default(), RefTenant::default()],
            prod: match self.backend {
                Backend::Production => {
                    let mut s = SignupState::new();
                    decide_and_apply(&mut s, &offer(V1)).expect("the first offer folds");
                    Some(s)
                }
                Backend::Reference => None,
            },
            permitted: [false, false],
            mismatch: false,
        }]
    }

    fn actions(&self, s: &St, out: &mut Vec<Act>) {
        if s.mismatch {
            return;
        }
        out.push(Act::NewOffer);
        for t in 0..2 {
            out.push(Act::Signup(t));
            out.push(Act::Accept(t, true));
            out.push(Act::Accept(t, false));
            for staff in 0..3 {
                out.push(Act::Review(t, staff, true));
                out.push(Act::Review(t, staff, false));
            }
        }
    }

    fn step(&self, s: &St, act: &Act) -> Option<St> {
        let act = *act;
        let mut next = s.clone();
        if act == Act::NewOffer {
            if s.second_offer {
                return None;
            }
            next.second_offer = true;
            // The production ledger records the new offer through its
            // operator command, which must accept it.
            if let (Some(prod), Some(cmd)) = (&mut next.prod, command(act, s.offered()))
                && decide_and_apply(prod, &cmd).is_err()
            {
                next.mismatch = true;
            }
        } else {
            let t = match act {
                Act::Signup(t) | Act::Accept(t, _) | Act::Review(t, _, _) => usize::from(t),
                Act::NewOffer => return None,
            };
            let offered = s.offered();
            let want = expect(&s.refs[t], act, offered);
            let took_effect = match (&mut next.prod, command(act, offered)) {
                (Some(prod), Some(cmd)) => {
                    let got = decide(prod, &cmd).and_then(|records| {
                        for r in &records {
                            prod.apply(r)?;
                        }
                        Ok(())
                    });
                    match (want, got.is_ok()) {
                        (Expect::Accept, false) | (Expect::Refuse, true) => {
                            next.mismatch = true;
                        }
                        _ => {}
                    }
                    if got.is_err() {
                        // A refused command leaves the production state as it was.
                        next.prod = s.prod.clone();
                    }
                    got.is_ok()
                }
                _ => want != Expect::Refuse,
            };
            if took_effect {
                effect(&mut next.refs[t], act, offered);
            }
        }
        let offered = next.offered();
        for (t, tenant) in TENANTS.into_iter().enumerate() {
            let reference = next.refs[t].permits(offered);
            next.permitted[t] = match &next.prod {
                Some(prod) => provision_permit(prod, tenant).is_ok_and(|p| p.tenant() == tenant),
                None => reference,
            };
            if next.permitted[t] != reference {
                next.mismatch = true;
            }
        }
        Some(next)
    }

    fn is_terminal(&self, s: &St) -> bool {
        s.mismatch
    }
}

fn properties<'a, M: Model<State = St>>() -> Vec<Property<'a, M>> {
    vec![
        Property::always("TH-46", |s: &St| {
            (0..2).all(|t| !s.permitted[t] || s.refs[t].permits(s.offered()))
        }),
        Property::always("TH-46 production agrees with the reference", |s: &St| {
            !s.mismatch
        }),
        Property::reachable("TH-46 witness: permit after two approvals", |s: &St| {
            s.permitted[0]
        }),
        Property::reachable("TH-46 witness: one approval holds the sign-up", |s: &St| {
            let r = &s.refs[0];
            r.approvers.len() == 1
                && !r.rejected
                && named(s.offered()).is_subset(&r.accepted)
                && !s.permitted[0]
        }),
        Property::reachable("TH-46 witness: rejection after two approvals", |s: &St| {
            s.refs[0].rejected && s.refs[0].approvers.len() == 2 && !s.permitted[0]
        }),
        Property::reachable("TH-46 witness: permit under the new offer", |s: &St| {
            s.second_offer && s.permitted[0]
        }),
        Property::reachable("TH-46 witness: both tenants permitted", |s: &St| {
            s.permitted[0] && s.permitted[1]
        }),
    ]
}

fn run(backend: Backend) {
    let model = ReviewModel { backend };
    if let Err(e) = check_exhaustive(&model, &properties::<ReviewModel>(), REFERENCE_STATES) {
        panic!("{e}");
    }
}

/// TH-46, R-TN-01: M-REVIEW on production. Every permit has two distinct
/// approvals, no rejection and every offered version accepted, and
/// production agrees with the reference on every answer.
#[test]
fn th46_m_review() {
    run(Backend::Production);
}

/// TH-46: M-REVIEW on the reference alone.
#[test]
fn th46_m_review_on_the_reference() {
    run(Backend::Reference);
}

/// The fault: a gate that permits a tenant with one approval, where the
/// agreements are accepted and no one rejected.
fn one_approval_permit(s: &St) -> Option<St> {
    let r = &s.refs[0];
    let lax = r.signed
        && !r.rejected
        && r.approvers.len() == 1
        && named(s.offered()).is_subset(&r.accepted)
        && !s.permitted[0];
    lax.then(|| {
        let mut next = s.clone();
        next.permitted[0] = true;
        next
    })
}

fn caught(backend: Backend) {
    let model = ReviewModel { backend };
    let mutant = Injecting::new(&model, one_approval_permit);
    let outcome = check(
        &mutant,
        &properties::<Injecting<'_, ReviewModel, _>>(),
        &tripwire(REFERENCE_STATES.saturating_mul(4)).with_stop_when_decided(true),
    );
    if let Err(e) = expect_violation(&outcome, "TH-46") {
        panic!("{e}");
    }
}

/// TH-46 teeth: a permit after one approval is caught, on production.
#[test]
fn th46_teeth_one_approval_permit_is_caught() {
    caught(Backend::Production);
}

/// TH-46 teeth: the same fault is caught on the reference alone.
#[test]
fn th46_teeth_one_approval_permit_is_caught_on_the_reference() {
    caught(Backend::Reference);
}
