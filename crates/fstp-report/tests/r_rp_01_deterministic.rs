//! R-RP-01, `funder-reporting.md` Generation rules: "Regenerating from the
//! same snapshot and template yields an identical document." Each output
//! is a function of the ledger snapshot alone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_report::{Request, generate};
use support::{CALL, PROGRAMME, day, grants, ledger_of, round_tripped};

fn requests(periods: &[fstp_report::Period]) -> Vec<Request<'_>> {
    vec![
        Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN-2026-01",
        },
        Request::PeriodicReportingData {
            programme: PROGRAMME,
            periods,
        },
        Request::AuditFile { call: CALL },
        Request::DeliverableDraft { call: CALL },
    ]
}

/// R-RP-01: equal ledgers give byte-identical outputs, also after the
/// records went through their stored JSON form.
#[test]
fn r_rp_01_each_output_is_deterministic_for_equal_ledgers() {
    let periods = vec![fstp_report::Period {
        start: day(0),
        end: day(600),
    }];
    fstp_prop::check(
        "r_rp_01_each_output_is_deterministic_for_equal_ledgers",
        |g| {
            let spec = grants(g);
            let a = ledger_of(&spec).snapshot();
            let b = ledger_of(&spec).snapshot();
            let c = round_tripped(&a);
            if a.digest().unwrap() != c.digest().unwrap() {
                return Err("R-RP-01: the snapshot digest changed over the stored form".into());
            }
            for r in requests(&periods) {
                let x = generate(&a, &r).map_err(|e| format!("{r:?}: {e}"))?;
                let y = generate(&b, &r).map_err(|e| format!("{r:?}: {e}"))?;
                let z = generate(&c, &r).map_err(|e| format!("{r:?}: {e}"))?;
                if x.bytes != y.bytes || x.bytes != z.bytes || x.digest != z.digest {
                    return Err(format!("R-RP-01: {:?} differs for equal ledgers", x.kind));
                }
            }
            Ok(())
        },
    );
}

/// R-RP-01: a later snapshot that adds a payment changes the snapshot
/// digest, and the periodic data with it.
#[test]
fn r_rp_01_other_snapshot_other_digest() {
    let mut spec = support::fixed();
    let a = ledger_of(&spec).snapshot();
    spec[2].requests[0].outcome = support::Outcome::Released;
    let b = ledger_of(&spec).snapshot();
    assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    let periods = vec![fstp_report::Period {
        start: day(0),
        end: day(600),
    }];
    let r = Request::PeriodicReportingData {
        programme: PROGRAMME,
        periods: &periods,
    };
    assert_ne!(
        generate(&a, &r).unwrap().bytes,
        generate(&b, &r).unwrap().bytes
    );
}
