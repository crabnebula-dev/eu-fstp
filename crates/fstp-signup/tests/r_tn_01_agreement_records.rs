//! Sign-up and agreement acceptance records in the control plane (R-TN-01,
//! Q22; M4 design sections 3.5 and 4.3; `programme-creator.md` Agreements
//! step).
//!
//! The rules these tests fix, for lane W2f:
//!
//! - A sign-up records the legal entity, billing address and contracting
//!   signatory exactly as the form gave them. A second sign-up of the same
//!   tenant is refused (`TenantExists`).
//! - An acceptance names the exact version of each of the three
//!   agreements: SaaS terms, data processing agreement and sub-processor
//!   list. It records one `AgreementAccepted` per agreement, naming the
//!   tenant, the version, the accepting person and the time.
//! - Operator staff record the offer (`AgreementsOffered`). No version
//!   moves back, and an unchanged or zero offer is refused (`BadOffer`).
//! - An acceptance whose versions differ from the current offer in any
//!   agreement is refused whole (`VersionNotOffered`), and one with no
//!   offer is refused (`NoOffer`). One before sign-up is refused
//!   (`UnknownTenant`), after the form values and versions are checked.
//! - The fold refuses an acceptance record of a version the ledger did
//!   not offer at that point.
//! - No record repeats a (tenant, agreement, version) already accepted,
//!   the key of `cp.agreement_acceptances`.
//!
//! The agreement texts are `TODO(legal)` placeholders. These tests name
//! versions only and hold no agreement wording. Every test is red against
//! the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeSet;

use fstp_prop::check;
use fstp_signup::{
    Agreement, AgreementVersions, CpCommand, CpRecord, Refusal, SignupError, SignupState, TenantId,
};
use support::{
    AT, T1, V1, V2, accept_cmd, gen_agreement_fields, gen_signup_fields, gen_versions, must,
    offer_cmd, run, signup_cmd,
};

/// The (agreement, version) pairs an acceptance of `v` names.
fn named(v: AgreementVersions) -> BTreeSet<(Agreement, u32)> {
    [
        (Agreement::SaasTerms, v.saas_terms),
        (Agreement::Dpa, v.dpa),
        (Agreement::SubProcessors, v.sub_processors),
    ]
    .into_iter()
    .collect()
}

/// R-TN-01, Q22: the sign-up record keeps the form values byte for byte.
#[test]
fn r_tn_01_signup_record_keeps_the_form_values() {
    check("r_tn_01_signup_record_keeps_the_form_values", |g| {
        let form = gen_signup_fields(g);
        let tenant = support::gen_tenant(g);
        let mut s = SignupState::new();
        let cmd = CpCommand::Signup {
            tenant,
            form: form.clone(),
            at: AT,
        };
        let records = run(&mut s, &cmd).map_err(|e| format!("{e:?}"))?;
        let want = vec![CpRecord::SignedUp {
            tenant,
            legal_name: form.legal_name,
            billing_address: form.billing_address,
            contracting_signatory: form.contracting_signatory,
            at: AT,
        }];
        if records == want {
            Ok(())
        } else {
            Err(format!("expected {want:?}, got {records:?}"))
        }
    });
}

/// R-TN-01: a second sign-up of the same tenant is refused.
#[test]
fn r_tn_01_second_signup_of_a_tenant_is_refused() {
    let mut s = SignupState::new();
    must(&mut s, &signup_cmd(T1));
    assert_eq!(
        run(&mut s, &signup_cmd(T1)),
        Err(SignupError::Refused(Refusal::TenantExists))
    );
}

/// R-TN-01, Q22: an acceptance records one `AgreementAccepted` per
/// agreement, each naming the exact version accepted, the tenant, the
/// accepting person and the time.
#[test]
fn r_tn_01_acceptance_records_name_each_exact_version() {
    check("r_tn_01_acceptance_records_name_each_exact_version", |g| {
        let mut form = gen_agreement_fields(g);
        form.tenant = T1;
        let offered = form.versions;
        let mut s = support::offered(offered);
        must(&mut s, &signup_cmd(T1));
        let cmd = CpCommand::AcceptAgreements {
            form: form.clone(),
            at: AT,
        };
        let records = run(&mut s, &cmd).map_err(|e| format!("{e:?}"))?;
        let mut seen = BTreeSet::new();
        for r in &records {
            match r {
                CpRecord::AgreementAccepted {
                    tenant,
                    agreement,
                    version,
                    by,
                    at,
                } if *tenant == T1 && *by == form.accepted_by && *at == AT => {
                    seen.insert((*agreement, *version));
                }
                other => return Err(format!("unexpected record {other:?}")),
            }
        }
        if records.len() == 3 && seen == named(offered) {
            Ok(())
        } else {
            Err(format!("{offered:?} gave {records:?}"))
        }
    });
}

/// R-TN-01: an acceptance whose versions differ from the offer in any
/// agreement is refused whole and records nothing.
#[test]
fn r_tn_01_acceptance_of_a_version_not_offered_is_refused() {
    check(
        "r_tn_01_acceptance_of_a_version_not_offered_is_refused",
        |g| {
            let offered = gen_versions(g);
            let mut given = offered;
            // Moves one version to another valid version. u32::MAX wraps to 1.
            let bump = |v: u32| v.checked_add(1).unwrap_or(1);
            let first = g.u8_in(0..=2);
            let fields = if g.bool() {
                vec![first]
            } else {
                vec![first, (first + 1) % 3]
            };
            for field in fields {
                match field {
                    0 => given.saas_terms = bump(given.saas_terms),
                    1 => given.dpa = bump(given.dpa),
                    _ => given.sub_processors = bump(given.sub_processors),
                }
            }
            let mut s = support::offered(offered);
            must(&mut s, &signup_cmd(T1));
            let before = s.clone();
            let got = run(&mut s, &accept_cmd(T1, given));
            if got != Err(SignupError::Refused(Refusal::VersionNotOffered)) {
                return Err(format!("{given:?} against {offered:?} gave {got:?}"));
            }
            if s == before {
                Ok(())
            } else {
                Err("a refused acceptance changed the state".to_owned())
            }
        },
    );
}

/// R-TN-01: an acceptance before sign-up is refused.
#[test]
fn r_tn_01_acceptance_before_signup_is_refused() {
    let unknown = TenantId::from_raw(0x5e1f_ffff);
    let mut s = support::offered(V1);
    assert_eq!(
        run(&mut s, &accept_cmd(unknown, V1)),
        Err(SignupError::Refused(Refusal::UnknownTenant))
    );
}

/// R-TN-01: no record repeats an accepted (tenant, agreement, version).
/// Accepting the same offer twice adds nothing, and accepting an offer in
/// which only the data processing agreement changed records that
/// agreement alone, at its new version.
#[test]
fn r_tn_01_no_acceptance_record_repeats_its_key() {
    let mut s = support::offered(V1);
    must(&mut s, &signup_cmd(T1));
    let first = must(&mut s, &accept_cmd(T1, V1));
    assert_eq!(first.len(), 3);
    match run(&mut s, &accept_cmd(T1, V1)) {
        Ok(again) => assert!(again.is_empty(), "repeated keys: {again:?}"),
        Err(SignupError::Refused(_)) => {}
        Err(other) => panic!("not a refusal: {other:?}"),
    }
    must(&mut s, &offer_cmd(V2));
    let second = must(&mut s, &accept_cmd(T1, V2));
    assert_eq!(
        second,
        vec![CpRecord::AgreementAccepted {
            tenant: T1,
            agreement: Agreement::Dpa,
            version: V2.dpa,
            by: "Synthetic Signatory".to_owned(),
            at: AT,
        }]
    );
}

/// R-TN-01: with no offer in the ledger, no acceptance is recorded.
#[test]
fn r_tn_01_acceptance_without_an_offer_is_refused() {
    let mut s = SignupState::new();
    must(&mut s, &signup_cmd(T1));
    assert_eq!(
        run(&mut s, &accept_cmd(T1, V1)),
        Err(SignupError::Refused(Refusal::NoOffer))
    );
}

/// R-TN-01: an offer never moves a version back, never repeats the
/// current offer and never holds a zero version.
#[test]
fn r_tn_01_offer_only_moves_forward() {
    let mut s = support::offered(V2);
    let zero = AgreementVersions {
        saas_terms: 3,
        dpa: 0,
        sub_processors: 3,
    };
    for bad in [V1, V2, zero] {
        assert_eq!(
            run(&mut s, &offer_cmd(bad)),
            Err(SignupError::Refused(Refusal::BadOffer)),
            "{bad:?} after {V2:?}"
        );
    }
    assert_eq!(s.offered(), Some(V2));
}

/// R-TN-01, TH-46: a forged record that accepts a version before the
/// ledger offers it is refused by the fold, so it never counts once that
/// version is offered.
#[test]
fn r_tn_01_fold_refuses_acceptance_of_a_version_not_yet_offered() {
    let mut s = support::offered(V1);
    must(&mut s, &signup_cmd(T1));
    let forged = CpRecord::AgreementAccepted {
        tenant: T1,
        agreement: Agreement::Dpa,
        version: V2.dpa,
        by: "Synthetic Signatory".to_owned(),
        at: AT,
    };
    let before = s.clone();
    assert_eq!(
        s.apply(&forged),
        Err(SignupError::Refused(Refusal::VersionNotOffered))
    );
    assert_eq!(s, before);
    must(&mut s, &offer_cmd(V2));
    assert!(!s.has_accepted(T1, Agreement::Dpa, V2.dpa));
}

/// R-TN-01, TH-46: the agreement form's values and versions are checked
/// before the tenant is looked up, so a bad form never tells a caller
/// whether a tenant id exists.
#[test]
fn r_tn_01_agreement_form_is_checked_before_the_tenant_lookup() {
    let unknown = TenantId::from_raw(0x5e1f_ffff);
    let mut s = support::offered(V1);
    must(&mut s, &signup_cmd(T1));
    for tenant in [unknown, T1] {
        let mut form = support::synthetic_agreements(tenant, V1);
        form.accepted_by = " Synthetic".to_owned();
        let bad_value = CpCommand::AcceptAgreements { form, at: AT };
        assert_eq!(
            run(&mut s, &bad_value),
            Err(SignupError::Form(fstp_signup::FormError::BadValue(
                "accepted_by"
            ))),
            "{tenant:?}"
        );
        assert_eq!(
            run(&mut s, &accept_cmd(tenant, V2)),
            Err(SignupError::Refused(Refusal::VersionNotOffered)),
            "{tenant:?}"
        );
    }
}
