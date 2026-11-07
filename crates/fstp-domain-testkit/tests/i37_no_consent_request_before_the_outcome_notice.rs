//! I-37, R-LA-09: consent is never requested before the outcome notice.
//!
//! Generated sequences of outcome notices, consent requests, consents,
//! revocations and calibration runs over three submitted proposals. Each
//! step's production verdict must match the test's own reading, and every
//! recorded request must name the proposal's outcome notice at a strictly
//! lower sequence number (M10 to M12 design section 3.1, the stricter
//! reading: the committed notice record counts, not a state change).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod i37_support;

use std::collections::BTreeMap;

use fstp_domain::command::Command;
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::ParamId;
use fstp_domain::{FoldError, apply};
use fstp_domain_testkit::r#gen::review::{L1, PR1, PR2};
use fstp_domain_testkit::r#gen::roster::STAFF_PM;
use i37_support::{Act, ConsentWorld, Did, acts, requests_follow_notices, step};

/// I-37 property: no consent request precedes the proposal's outcome
/// notice. A request without a committed notice is refused under I-37, and
/// every accepted request names an earlier notice of its proposal.
#[test]
fn i37_property_no_consent_request_before_the_outcome_notice() {
    let start = ConsentWorld::new(true).unwrap_or_else(|e| panic!("world: {e}"));
    fstp_prop::check(
        "i37_property_no_consent_request_before_the_outcome_notice",
        |g| {
            let mut w = start.clone();
            let mut ghosts = BTreeMap::new();
            for act in acts(g) {
                let noticed = match act {
                    Act::Request(p) => ghosts
                        .get(&p)
                        .is_some_and(|x: &i37_support::Ghost| x.notice.is_some()),
                    _ => true,
                };
                let did = step(&mut w, &mut ghosts, act)?;
                if let (false, Did::Refused(r)) = (noticed, &did)
                    && r.rule != RuleRef::I37
                {
                    return Err(format!(
                        "I-37: a request before the notice refused with {r}"
                    ));
                }
            }
            requests_follow_notices(&w.tail)
        },
    );
}

/// I-37: the fold refuses a request record whose notice is not an earlier
/// committed outcome notice of the same proposal, so no log the engine
/// writes can hold one.
#[test]
fn i37_fold_refuses_a_request_record_without_an_earlier_notice() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    // No notice at all.
    let forged = Record::CalibrationConsentRequested {
        proposal: PR1,
        notice: w.next,
        by: STAFF_PM,
    };
    let mut s = w.state.clone();
    assert_eq!(
        apply(&mut s, w.next, w.now, &forged),
        Err(FoldError::Inconsistent)
    );
    // A notice of another proposal.
    let other = w.notice(PR2).unwrap();
    let forged = Record::CalibrationConsentRequested {
        proposal: PR1,
        notice: other,
        by: STAFF_PM,
    };
    let mut s = w.state.clone();
    assert_eq!(
        apply(&mut s, w.next, w.now, &forged),
        Err(FoldError::Inconsistent)
    );
    // The right notice, but a request at the same sequence number or lower.
    let notice = w.notice(PR1).unwrap();
    let forged = Record::CalibrationConsentRequested {
        proposal: PR1,
        notice,
        by: STAFF_PM,
    };
    let mut s = w.state.clone();
    assert_eq!(
        apply(&mut s, notice, w.now, &forged),
        Err(FoldError::Inconsistent)
    );
    // At a strictly later sequence number it folds.
    let mut s = w.state.clone();
    assert_eq!(apply(&mut s, w.next, w.now, &forged), Ok(()));
}

/// I-37, R-LA-09: production refuses the request before the notice under
/// I-37 and accepts it after, with the notice's sequence number recorded.
#[test]
fn i37_request_waits_for_the_committed_notice() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    let refused = w.request(PR1).unwrap().unwrap_err();
    assert_eq!(refused.rule, RuleRef::I37, "{refused}");
    // Consent cannot be given before a request either.
    let refused = w.give(PR1).unwrap().unwrap_err();
    assert_eq!(refused.rule, RuleRef::I37, "{refused}");
    let notice = w.notice(PR1).unwrap();
    let records = w.request(PR1).unwrap().unwrap();
    assert_eq!(records.len(), 1, "{records:?}");
    let (seq, r) = &records[0];
    assert!(*seq > notice);
    assert_eq!(
        r,
        &Record::CalibrationConsentRequested {
            proposal: PR1,
            notice,
            by: STAFF_PM,
        }
    );
    // One request per proposal.
    assert!(w.request(PR1).unwrap().is_err());
}

/// R-LA-09, P-42: with P-42 off, no consent is requested, even after the notice.
#[test]
fn r_la_09_request_needs_p42_on() {
    let mut w = ConsentWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    w.notice(PR1).unwrap();
    let refused = w.request(PR1).unwrap().unwrap_err();
    assert_eq!(refused.rule, RuleRef::Param(ParamId::P42), "{refused}");
}

/// R-LA-09: only the programme manager requests consent, and only the lead
/// gives it.
#[test]
fn r_la_09_request_by_the_programme_manager_consent_by_the_lead() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    w.notice(PR1).unwrap();
    assert!(
        w.exec(L1, Command::RequestCalibrationConsent { proposal: PR1 })
            .unwrap()
            .is_err()
    );
    w.request(PR1).unwrap().unwrap();
    assert!(
        w.exec(
            STAFF_PM,
            Command::GiveCalibrationConsent {
                proposal: PR1,
                wording: i37_support::wording(),
            },
        )
        .unwrap()
        .is_err()
    );
    // The lead of another proposal cannot consent for PR1.
    assert!(
        w.exec(
            i37_support::lead_of(PR2),
            Command::GiveCalibrationConsent {
                proposal: PR1,
                wording: i37_support::wording(),
            },
        )
        .unwrap()
        .is_err()
    );
    assert!(w.give(PR1).unwrap().is_ok());
}
