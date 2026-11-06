//! TH-26, I-23: the `Report` ledger envelope has one stored spelling. Every
//! record round-trips, and malformed input is refused without panicking.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_domain::id::{AccountId, CallId, ContentDigest, ProgrammeId};
use fstp_json::{FromJson, ToJson};
use fstp_report::{ENVELOPE, ReportId, ReportKind, ReportRecord, Scope};

fn record(g: &mut fstp_prop::Gen) -> ReportRecord {
    let report = ReportId::from_raw(u128::from(g.u64()));
    if g.bool() {
        ReportRecord::Generated {
            report,
            kind: *g.pick(&ReportKind::ALL),
            scope: if g.bool() {
                Scope::Call(CallId::from_raw(u128::from(g.u64())))
            } else {
                Scope::Programme(ProgrammeId::from_raw(u128::from(g.u64())))
            },
            snapshot: ContentDigest::from_bytes([g.u8(); 32]),
            template: "horizon-europe/audit_file/1".to_owned(),
            document: ContentDigest::from_bytes([g.u8(); 32]),
            by: AccountId::from_raw(u128::from(g.u64())),
        }
    } else {
        ReportRecord::Approved {
            report,
            approver: AccountId::from_raw(u128::from(g.u64())),
        }
    }
}

/// TH-26, I-23: records round-trip through their canonical JSON.
#[test]
fn th26_report_records_round_trip() {
    assert_eq!(ENVELOPE, "report");
    fstp_prop::check("th26_report_records_round_trip", |g| {
        let r = record(g);
        let text = r.to_json().to_canonical().map_err(|e| e.to_string())?;
        let back = ReportRecord::from_json(&fstp_json::parse(text.as_bytes()).unwrap())
            .map_err(|e| format!("{e}"))?;
        if back != r {
            return Err(format!("round trip changed {r:?}"));
        }
        Ok(())
    });
}

/// TH-26: arbitrary JSON never panics the decoder, and an unknown member
/// is refused.
#[test]
fn th26_report_record_decoder_refuses_malformed_input() {
    fstp_prop::check("th26_report_record_decoder_refuses_malformed_input", |g| {
        let bytes = g.bytes(0..=64);
        if let Ok(v) = fstp_json::parse(&bytes) {
            let _ = ReportRecord::from_json(&v);
        }
        Ok(())
    });
    let ok = ReportRecord::Approved {
        report: ReportId::from_raw(1),
        approver: AccountId::from_raw(2),
    }
    .to_json();
    let mut o = ok.as_object().unwrap().clone();
    o.insert("extra", fstp_json::Value::Null);
    assert!(ReportRecord::from_json(&fstp_json::Value::Object(o)).is_err());
}
