//! I-44, R-RP-02: every figure in a funder document reconciles with the
//! recorded contracts, payment requests and payments at its snapshot.
//! Generation fails on any mismatch and lists it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_domain::Record;
use fstp_domain::command::{Actor, SystemCause};
use fstp_json::Value;
use fstp_report::{Content, Period, ReportError, Request, generate};
use support::{
    CALL, Closure, GrantSpec, Outcome, PROGRAMME, day, grants, ledger_of, money, proposal,
    released, request_id,
};

fn s<'v>(v: &'v Value, k: &str) -> &'v str {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no string member {k}"))
}

/// The independent fold: what each period and the totals must show,
/// computed from the fixture's own specification.
fn check(spec: &[GrantSpec], periods: &[(i64, i64)], data: &Value) -> Result<(), String> {
    let total_committed: i64 = spec.iter().map(|g| g.granted).sum();
    let total_paid: i64 = spec.iter().map(GrantSpec::paid).sum();
    let released: i64 = spec
        .iter()
        .filter(|g| g.closure != Closure::Open)
        .map(|g| g.granted - g.paid())
        .sum();
    let totals = data.get("totals").ok_or("no totals")?;
    for (k, want) in [
        ("committed", total_committed),
        ("paid", total_paid),
        ("released_commitments", released),
    ] {
        if s(totals, k) != money(want) {
            return Err(format!(
                "I-44: total {k} is {} not {}",
                s(totals, k),
                money(want)
            ));
        }
    }
    let ps = data
        .get("periods")
        .and_then(Value::as_array)
        .ok_or("no periods")?;
    if ps.len() != periods.len() {
        return Err("I-44: period count".into());
    }
    for (p, (from, to)) in ps.iter().zip(periods) {
        let mut sum = 0;
        let rows = p
            .get("recipients")
            .and_then(Value::as_array)
            .ok_or("no rows")?;
        for (i, g) in spec.iter().enumerate() {
            let paid = g.paid_between(*from, *to);
            let row = rows
                .iter()
                .find(|r| s(r, "recipient") == format!("G-{}", proposal(i).raw()));
            let decided = g.day < *to;
            match row {
                None if decided => return Err(format!("I-44: grant {i} missing in a period")),
                None => continue,
                Some(_) if !decided => {
                    return Err(format!("I-44: grant {i} shown before it was decided"));
                }
                Some(r) => {
                    if s(r, "committed") != money(g.granted) {
                        return Err(format!("I-44: grant {i} committed"));
                    }
                    if s(r, "paid") != money(paid) {
                        return Err(format!(
                            "I-44: grant {i} paid {} in period, fold says {}",
                            s(r, "paid"),
                            money(paid)
                        ));
                    }
                    let hardship: i64 = g
                        .requests
                        .iter()
                        .filter(|q| {
                            q.hardship && matches!(q.outcome, Outcome::Released | Outcome::Paid)
                        })
                        .filter(|q| q.day >= *from && q.day < *to)
                        .flat_map(|q| q.lines.iter().map(|l| l.1))
                        .sum();
                    if s(r, "paid_hardship") != money(hardship) {
                        return Err(format!("I-44: grant {i} hardship"));
                    }
                }
            }
            sum += paid;
        }
        if s(p, "paid") != money(sum) {
            return Err("I-44: period paid total".into());
        }
    }
    Ok(())
}

/// I-44, R-RP-02: every figure of the periodic reporting data equals an
/// independent fold of the ledger at the snapshot.
#[test]
fn i44_periodic_figures_equal_an_independent_fold() {
    let periods = [(0, 180), (180, 360), (360, 600)];
    let ps: Vec<Period> = periods
        .iter()
        .map(|(a, b)| Period {
            start: day(*a),
            end: day(*b),
        })
        .collect();
    fstp_prop::check("i44_periodic_figures_equal_an_independent_fold", |g| {
        let spec = grants(g);
        let snap = ledger_of(&spec).snapshot();
        let out = generate(
            &snap,
            &Request::PeriodicReportingData {
                programme: PROGRAMME,
                periods: &ps,
            },
        )
        .map_err(|e| format!("I-44: a reconciling ledger was refused: {e}"))?;
        let Content::Data(v) = &out.content else {
            return Err("periodic data is data".into());
        };
        check(&spec, &periods, v)
    });
}

/// I-44: a seeded mismatch fails generation of every output and is listed
/// with its sequence number.
#[test]
fn i44_seeded_mismatch_fails_generation_and_is_listed() {
    let spec = vec![GrantSpec {
        granted: 100_000,
        day: 90,
        requests: vec![support::ReqSpec {
            lines: vec![(80_000, 80_000)],
            outcome: Outcome::Paid,
            day: 120,
            hardship: false,
        }],
        closure: Closure::Open,
    }];
    let mut l = ledger_of(&spec);
    // A second release of the paid request: paid would reach 1600.00
    // against a commitment of 1000.00.
    l.push(day(130), released(request_id(0, 0), proposal(0)));
    let bad_release = l.entries().len() as u64;
    // A confirmation of a request that was never requested.
    l.push(
        day(131),
        Record::PaymentConfirmed {
            request: request_id(0, 9),
            by: Actor::System(SystemCause::PaymentPort),
        },
    );
    let bad_confirm = l.entries().len() as u64;
    let snap = l.snapshot();
    let periods = [Period {
        start: day(0),
        end: day(600),
    }];
    for r in [
        Request::PeriodicReportingData {
            programme: PROGRAMME,
            periods: &periods,
        },
        Request::AuditFile { call: CALL },
        Request::DeliverableDraft { call: CALL },
        Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN",
        },
    ] {
        match generate(&snap, &r) {
            Err(ReportError::Reconciliation(list)) => {
                let seqs: Vec<u64> = list.iter().map(|m| m.seq.raw()).collect();
                assert!(
                    seqs.contains(&bad_release),
                    "I-44: the double release is listed: {list:?}"
                );
                assert!(
                    seqs.contains(&bad_confirm),
                    "I-44: the stray confirmation is listed: {list:?}"
                );
            }
            other => panic!("I-44: a mismatched ledger gave {other:?}"),
        }
    }
}
