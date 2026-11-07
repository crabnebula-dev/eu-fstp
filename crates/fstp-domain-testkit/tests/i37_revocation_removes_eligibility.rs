//! I-37, R-LA-10: a revocation removes the proposal from calibration
//! eligibility, and the consent records round trip through the codec.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod i37_support;

use fstp_domain::calibration::{admits, calibration_set};
use fstp_domain::command::Command;
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::review::{L1, PR1, PR2};
use fstp_domain_testkit::r#gen::roster::STAFF_PM;
use fstp_json::{FromJson, ToJson};
use fstp_ledger::Seq;
use i37_support::{ConsentWorld, wording};

/// R-LA-10, I-37: consent admits the proposal, and revocation removes it
/// from every later set. A revoked consent is final: it cannot be given or
/// requested again (interim reading, pending Daniel).
#[test]
fn r_la_10_revocation_removes_eligibility() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    w.notice(PR1).unwrap();
    w.notice(PR2).unwrap();
    w.request(PR1).unwrap().unwrap();
    w.request(PR2).unwrap().unwrap();
    assert!(!admits(&w.state, PR1), "a request alone admits nothing");
    let given = w.give(PR1).unwrap().unwrap();
    let consent = given[0].0;
    assert!(admits(&w.state, PR1));
    assert!(!admits(&w.state, PR2));
    assert_eq!(
        calibration_set(&w.state).into_iter().collect::<Vec<_>>(),
        vec![(PR1, consent)]
    );
    // A second consent while one stands is refused.
    assert_eq!(w.give(PR1).unwrap().unwrap_err().rule, RuleRef::I37);
    w.revoke(PR1).unwrap().unwrap();
    assert!(!admits(&w.state, PR1));
    assert!(calibration_set(&w.state).is_empty());
    assert!(w.give(PR1).unwrap().is_err());
    assert!(w.request(PR1).unwrap().is_err());
    assert!(w.revoke(PR1).unwrap().is_err());
    // Revoking without a consent is refused.
    assert_eq!(w.revoke(PR2).unwrap().unwrap_err().rule, RuleRef::I37);
}

/// I-37: the fold refuses a consent record with no request before it, and
/// a revocation with no consent before it.
#[test]
fn i37_fold_refuses_consent_without_request_and_revocation_without_consent() {
    let mut w = ConsentWorld::new(true).unwrap_or_else(|e| panic!("{e}"));
    w.notice(PR1).unwrap();
    let given = Record::CalibrationConsentGiven {
        proposal: PR1,
        wording: wording(),
        by: L1,
    };
    assert!(w.append(given).is_err());
    let revoked = Record::CalibrationConsentRevoked {
        proposal: PR1,
        by: L1,
    };
    assert!(w.append(revoked).is_err());
    assert!(!admits(&w.state, PR1));
}

/// I-37, I-23: the three consent records and commands round trip through
/// the codec, and an unknown member is refused.
#[test]
fn i37_consent_records_and_commands_round_trip() {
    let records = [
        Record::CalibrationConsentRequested {
            proposal: PR1,
            notice: Seq::from_raw(41),
            by: STAFF_PM,
        },
        Record::CalibrationConsentGiven {
            proposal: PR1,
            wording: wording(),
            by: L1,
        },
        Record::CalibrationConsentRevoked {
            proposal: PR1,
            by: L1,
        },
    ];
    for r in &records {
        let v = r.to_json();
        assert_eq!(&Record::from_json(&v).unwrap(), r);
    }
    let commands = [
        Command::RequestCalibrationConsent { proposal: PR1 },
        Command::GiveCalibrationConsent {
            proposal: PR1,
            wording: wording(),
        },
        Command::RevokeCalibrationConsent { proposal: PR1 },
    ];
    for c in &commands {
        let v = c.to_json();
        assert_eq!(&Command::from_json(&v).unwrap(), c);
        let mut o = match v {
            fstp_json::Value::Object(o) => o,
            other => panic!("not an object: {other:?}"),
        };
        let _ = o.insert("extra", fstp_json::Value::Bool(true));
        assert!(Command::from_json(&fstp_json::Value::Object(o)).is_err());
    }
}
