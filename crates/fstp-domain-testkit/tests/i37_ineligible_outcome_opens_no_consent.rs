//! I-37, R-LA-09: an INELIGIBLE proposal's outcome notice does not open
//! calibration consent (decided by Daniel on 2026-11-13,
//! `docs/handoff/fast-flow.md`).
//!
//! A failed knock-out enqueues `OutboxEnqueued(ProposalOutcome)` with state
//! INELIGIBLE. That notice is not the outcome notice of R-LA-09 for
//! calibration, so no consent is requested on it, no request record can
//! name it, and no INELIGIBLE proposal enters a calibration set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod i37_support;

use fstp_domain::calibration::{calibration_set, outcome_notice};
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::StateTag;
use fstp_domain::{FoldError, apply};
use fstp_domain_testkit::r#gen::review::{PR1, PR2, PR3};
use fstp_domain_testkit::r#gen::roster::STAFF_PM;
use i37_support::{ConsentWorld, LEADS, requests_follow_notices};

/// Appends the outcome notice of `proposal` with state `tag`.
fn notice_with(w: &mut ConsentWorld, proposal: fstp_domain::id::ProposalId, tag: StateTag) {
    w.append(Record::OutboxEnqueued(OutboxEvent::ProposalOutcome {
        proposal,
        state: tag,
    }))
    .unwrap_or_else(|e| panic!("notice: {e}"));
}

/// I-37, R-LA-09: the INELIGIBLE outcome notice is not counted, so the
/// programme manager's request is refused under I-37 and nothing is recorded.
#[test]
fn i37_ineligible_outcome_notice_opens_no_consent_request() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    notice_with(&mut w, PR1, StateTag::Ineligible);
    assert_eq!(outcome_notice(&w.state, PR1), None);
    let refused = w.request(PR1).unwrap().unwrap_err();
    assert_eq!(refused.rule, RuleRef::I37, "{refused}");
    // Consent cannot be given either, since nothing was requested.
    let refused = w.give(PR1).unwrap().unwrap_err();
    assert_eq!(refused.rule, RuleRef::I37, "{refused}");
    assert!(calibration_set(&w.state).is_empty());
}

/// I-37: the fold refuses a forged request that names an INELIGIBLE
/// outcome notice, so no log the engine writes can hold one.
#[test]
fn i37_fold_refuses_a_request_naming_an_ineligible_notice() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    let notice = w.next;
    notice_with(&mut w, PR1, StateTag::Ineligible);
    let forged = Record::CalibrationConsentRequested {
        proposal: PR1,
        notice,
        by: STAFF_PM,
    };
    let mut s = w.state.clone();
    assert_eq!(
        apply(&mut s, w.next, w.now, &forged),
        Err(FoldError::Inconsistent)
    );
}

/// I-37, R-LA-09: the other outcome notices still open consent, and an
/// INELIGIBLE notice of one proposal does not close another's.
#[test]
fn i37_other_outcome_notices_still_open_consent() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    notice_with(&mut w, PR1, StateTag::Ineligible);
    notice_with(&mut w, PR2, StateTag::NotSelected);
    notice_with(&mut w, PR3, StateTag::Declined);
    assert!(w.request(PR1).unwrap().is_err());
    assert!(w.request(PR2).unwrap().is_ok());
    assert!(w.request(PR3).unwrap().is_ok());
    requests_follow_notices(&w.tail).unwrap_or_else(|e| panic!("{e}"));
}

/// I-37 property: over generated orders of INELIGIBLE and other notices,
/// a request is accepted only for a proposal with a non-INELIGIBLE notice
/// before it, and no INELIGIBLE-only proposal reaches the calibration set.
#[test]
fn i37_property_ineligible_notices_never_open_consent() {
    let start = ConsentWorld::new(true).unwrap_or_else(|e| panic!("world: {e}"));
    fstp_prop::check("i37_property_ineligible_notices_never_open_consent", |g| {
        let mut w = start.clone();
        let mut opened = std::collections::BTreeSet::new();
        let steps = g.vec(0..=16, |g| (g.pick(&LEADS).1, g.weighted(&[3, 1, 3, 2])));
        for (p, kind) in steps {
            match kind {
                0 => notice_with(&mut w, p, StateTag::Ineligible),
                1 => {
                    notice_with(&mut w, p, StateTag::NotSelected);
                    opened.insert(p);
                }
                2 => {
                    let out = w.request(p)?;
                    if out.is_ok() && !opened.contains(&p) {
                        return Err(format!(
                            "I-37: request on {p:?} with only INELIGIBLE notices"
                        ));
                    }
                    if let Err(r) = &out
                        && !opened.contains(&p)
                        && r.rule != RuleRef::I37
                    {
                        return Err(format!("I-37: refused with {r}, not I-37"));
                    }
                }
                _ => {
                    let _ = w.give(p)?;
                }
            }
        }
        for p in calibration_set(&w.state).keys() {
            if !opened.contains(p) {
                return Err(format!(
                    "I-37: {p:?} entered the set on an INELIGIBLE notice"
                ));
            }
        }
        requests_follow_notices(&w.tail)
    });
}
