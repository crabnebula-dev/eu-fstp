//! I-44, R-RP-01, R-RP-02 under versioned funder profiles (M9 design
//! sections 2.5 and 3, lane F1).
//!
//! A profile field can name only a ledger fold, never a literal figure.
//! So every figure a profile puts in a funder document is a fold of the
//! ledger at the snapshot, and the reconciliation of I-44 runs before any
//! of them. Each test runs under the shipped Horizon Europe profile,
//! version 1, and under a synthetic second profile with other names,
//! labels, levels and outputs.

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
use fstp_json::{Object, Value};
use fstp_report::profile::{Figure, FunderProfile, Level, parse_profile};
use fstp_report::{Content, Period, ReportError, ReportKind, Request, generate};
use support::{
    CALL, Closure, GrantSpec, Outcome, PROGRAMME, day, grants, ledger_of, money, proposal,
    released, request_id,
};

/// The synthetic second profile: test data only, never shipped.
const SYNTHETIC: &[u8] = include_bytes!("profiles/synthetic-funder/profile.v1.json");

/// The shipped Horizon Europe profile, version 1.
fn he() -> FunderProfile {
    fstp_report::profile::shipped("horizon-europe", 1).unwrap()
}

fn synthetic() -> FunderProfile {
    parse_profile(SYNTHETIC).unwrap()
}

/// Both profiles of every I-44 test.
fn profiles() -> [FunderProfile; 2] {
    [he(), synthetic()]
}

const PERIODS: [(i64, i64); 3] = [(0, 180), (180, 360), (360, 600)];

fn periods() -> Vec<Period> {
    PERIODS
        .iter()
        .map(|(a, b)| Period {
            start: day(*a),
            end: day(*b),
        })
        .collect()
}

// ------------------------------------------------- the independent fold

/// A figure as the reference computes it: cents or a count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Cents(i64),
    Count(u64),
}

fn released_in(g: &GrantSpec, from: i64, to: i64) -> i64 {
    match g.closure {
        Closure::Completed(d) | Closure::Terminated(d) if d >= from && d < to => {
            g.granted - g.paid()
        }
        _ => 0,
    }
}

fn hardship_between(g: &GrantSpec, from: i64, to: i64) -> i64 {
    g.requests
        .iter()
        .filter(|q| q.hardship && matches!(q.outcome, Outcome::Released | Outcome::Paid))
        .filter(|q| q.day >= from && q.day < to)
        .flat_map(|q| q.lines.iter().map(|l| l.1))
        .sum()
}

fn closed(g: &GrantSpec) -> bool {
    g.closure != Closure::Open
}

/// The figure of one recipient row, computed from the fixture's own
/// specification, not from the ledger fold under test.
fn want_recipient(f: Figure, g: &GrantSpec, (from, to): (i64, i64)) -> Want {
    match f {
        Figure::Committed => Want::Cents(g.granted),
        Figure::PaidInPeriod => Want::Cents(g.paid_between(from, to)),
        Figure::PaidHardshipInPeriod => Want::Cents(hardship_between(g, from, to)),
        Figure::ReleasedCommitmentInPeriod => Want::Cents(released_in(g, from, to)),
        other => panic!("{other:?} is not a recipient figure"),
    }
}

/// The figure of one period over the grants decided before its end.
fn want_period(f: Figure, spec: &[GrantSpec], p: (i64, i64)) -> Want {
    let rows: Vec<&GrantSpec> = spec.iter().filter(|g| g.day < p.1).collect();
    let sum = |h: &dyn Fn(&GrantSpec) -> i64| rows.iter().map(|g| h(g)).sum::<i64>();
    match f {
        Figure::PaidInPeriod => Want::Cents(sum(&|g| g.paid_between(p.0, p.1))),
        Figure::PaidHardshipInPeriod => Want::Cents(sum(&|g| hardship_between(g, p.0, p.1))),
        Figure::ReleasedCommitmentInPeriod => Want::Cents(sum(&|g| released_in(g, p.0, p.1))),
        Figure::RecipientCount => Want::Count(rows.len() as u64),
        other => panic!("{other:?} is not a period figure"),
    }
}

/// The figure of the whole programme or of the one call: the fixture has
/// one call, so both scopes hold the same grants.
fn want_scope(f: Figure, spec: &[GrantSpec]) -> Want {
    match f {
        Figure::CallBudget => Want::Cents(50_000_000),
        Figure::ProposalsCreated => Want::Count(spec.len() as u64),
        Figure::ProposalsSubmitted | Figure::KnockOutDecisions => Want::Count(0),
        Figure::RecipientCount => Want::Count(spec.len() as u64),
        Figure::GrantsClosed => Want::Count(spec.iter().filter(|g| closed(g)).count() as u64),
        Figure::Committed => Want::Cents(spec.iter().map(|g| g.granted).sum()),
        Figure::Paid => Want::Cents(spec.iter().map(GrantSpec::paid).sum()),
        Figure::ReleasedCommitments => Want::Cents(
            spec.iter()
                .filter(|g| closed(g))
                .map(|g| g.granted - g.paid())
                .sum(),
        ),
        other => panic!("{other:?} is not a call or programme figure"),
    }
}

/// Whether the JSON value `v` shows `want`.
fn json_shows(v: Option<&Value>, want: Want) -> bool {
    match (v, want) {
        (Some(Value::String(s)), Want::Cents(c)) => *s == money(c),
        (Some(v), Want::Count(n)) => v.as_u64() == Some(n),
        _ => false,
    }
}

/// The document line of a field, as the generator writes it.
fn line(label: &str, want: Want) -> String {
    match want {
        Want::Cents(c) => format!("{label}: {} EUR.", money(c)),
        Want::Count(n) => format!("{label}: {n}."),
    }
}

fn names_at(profile: &FunderProfile, kind: ReportKind, level: Level) -> Vec<(String, Figure)> {
    profile
        .output(kind)
        .map(|o| {
            o.fields()
                .iter()
                .filter(|f| f.level() == level)
                .map(|f| (f.name().to_owned(), f.figure()))
                .collect()
        })
        .unwrap_or_default()
}

/// Every figure of the periodic reporting data equals the independent
/// fold, and no member outside the fixed members and the profile's fields
/// holds one.
fn check_periodic(profile: &FunderProfile, spec: &[GrantSpec], v: &Value) -> Result<(), String> {
    let pid = profile.id();
    let rec = names_at(profile, ReportKind::PeriodicReportingData, Level::Recipient);
    let per = names_at(profile, ReportKind::PeriodicReportingData, Level::Period);
    let tot = names_at(profile, ReportKind::PeriodicReportingData, Level::Total);
    let totals = v
        .get("totals")
        .and_then(Value::as_object)
        .ok_or("no totals")?;
    if totals.len() != tot.len() {
        return Err(format!("I-44 {pid}: the totals hold another member"));
    }
    for (name, f) in &tot {
        if !json_shows(totals.get(name), want_scope(*f, spec)) {
            return Err(format!(
                "I-44 {pid}: total {name} ({f:?}) does not reconcile"
            ));
        }
    }
    let ps = v
        .get("periods")
        .and_then(Value::as_array)
        .ok_or("no periods")?;
    if ps.len() != PERIODS.len() {
        return Err("period count".into());
    }
    for (p, range) in ps.iter().zip(PERIODS) {
        let po = p.as_object().ok_or("a period is no object")?;
        if po.len() != 3 + per.len() {
            return Err(format!("I-44 {pid}: a period holds another member"));
        }
        for (name, f) in &per {
            if !json_shows(po.get(name), want_period(*f, spec, range)) {
                return Err(format!(
                    "I-44 {pid}: period {name} ({f:?}) does not reconcile"
                ));
            }
        }
        let rows = p
            .get("recipients")
            .and_then(Value::as_array)
            .ok_or("no rows")?;
        let decided = spec.iter().filter(|g| g.day < range.1).count();
        if rows.len() != decided {
            return Err(format!(
                "I-44 {pid}: {} rows for {decided} grants",
                rows.len()
            ));
        }
        for (i, g) in spec.iter().enumerate().filter(|(_, g)| g.day < range.1) {
            let tag = format!("G-{}", proposal(i).raw());
            let row = rows
                .iter()
                .find(|r| r.get("recipient").and_then(Value::as_str) == Some(tag.as_str()))
                .and_then(Value::as_object)
                .ok_or_else(|| format!("I-44 {pid}: grant {i} missing in a period"))?;
            if row.len() != 2 + rec.len() {
                return Err(format!("I-44 {pid}: a recipient row holds another member"));
            }
            for (name, f) in &rec {
                if !json_shows(row.get(name), want_recipient(*f, g, range)) {
                    return Err(format!(
                        "I-44 {pid}: grant {i} {name} ({f:?}) does not reconcile"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Every field of a call-level output appears with the figure of the
/// independent fold: as a JSON member of the call publication record, or
/// as a document line of the deliverable draft.
fn check_call(
    profile: &FunderProfile,
    kind: ReportKind,
    spec: &[GrantSpec],
    content: &Content,
) -> Result<(), String> {
    let pid = profile.id();
    let out = profile.output(kind).ok_or("not in the profile")?;
    for f in out.fields() {
        let want = want_scope(f.figure(), spec);
        let ok = match content {
            Content::Data(v) => json_shows(v.get(f.name()), want),
            Content::Document(d) => {
                let l = line(f.label(), want);
                d.blocks.iter().any(|b| b.text == l)
            }
        };
        if !ok {
            return Err(format!(
                "I-44 {pid}: {kind:?} field {} ({:?}) does not reconcile",
                f.name(),
                f.figure()
            ));
        }
    }
    Ok(())
}

fn request<'a>(kind: ReportKind, ps: &'a [Period]) -> Option<Request<'a>> {
    match kind {
        ReportKind::CallPublicationRecord => Some(Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN-2026-01",
        }),
        ReportKind::PeriodicReportingData => Some(Request::PeriodicReportingData {
            programme: PROGRAMME,
            periods: ps,
        }),
        ReportKind::AuditFile => Some(Request::AuditFile { call: CALL }),
        ReportKind::DeliverableDraft => Some(Request::DeliverableDraft { call: CALL }),
        // The package needs a stored Guide and holds no figure.
        ReportKind::OpenCallPackage => None,
    }
}

// ------------------------------------------------------------ the tests

/// I-44 (M9 design section 3): every field of every shipped profile, and
/// of the synthetic profile, names a ledger fold allowed at its level and
/// in its output. Profiles that put a literal or an unknown figure in a
/// field are refused, and for random reconciling ledgers every figure of
/// every output equals an independent fold of the ledger.
#[test]
fn i44_profile_fields_are_ledger_folds() {
    let shipped = fstp_report::profile::shipped_all().unwrap();
    assert!(!shipped.is_empty(), "no shipped profile");
    let mut all: Vec<FunderProfile> = shipped;
    all.push(synthetic());
    for p in &all {
        for o in p.outputs() {
            for f in o.fields() {
                assert!(
                    Figure::ALL.contains(&f.figure()),
                    "I-44: {} names no fold",
                    f.name()
                );
                assert!(
                    f.figure().levels().contains(&f.level()),
                    "I-44: {} {:?} at level {:?}",
                    p.id(),
                    f.figure(),
                    f.level()
                );
                assert!(
                    Level::of_output(o.kind()).contains(&f.level()),
                    "I-44: {} {:?} has a {:?} field",
                    p.id(),
                    o.kind(),
                    f.level()
                );
            }
        }
    }
    // A field that holds anything but a fold is refused.
    let base = fstp_json::parse(fstp_report::profile::HORIZON_EUROPE_V1).unwrap();
    fstp_prop::check("i44_profile_fields_are_ledger_folds_refusals", |g| {
        let mut v = base.clone();
        let outputs = v
            .as_object_mut()
            .and_then(|o| o.get_mut("outputs"))
            .and_then(Value::as_array_mut)
            .ok_or("outputs")?;
        let with_fields: Vec<usize> = (0..outputs.len())
            .filter(|i| {
                outputs[*i]
                    .get("fields")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
            })
            .collect();
        let o = *g.pick(&with_fields);
        let fields = outputs[o]
            .as_object_mut()
            .and_then(|o| o.get_mut("fields"))
            .and_then(Value::as_array_mut)
            .ok_or("fields")?;
        let k = g.usize_in(0..=fields.len() - 1);
        let field: &mut Object = fields[k].as_object_mut().ok_or("field")?;
        let level = field
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let what = match g.u8_in(0..=5) {
            0 => {
                let n = g.u64_in(0..=10_000_000);
                field.insert("figure", Value::Number(n.into()));
                format!("a literal number {n}")
            }
            1 => {
                field.insert("figure", Value::String(format!("{}.00", g.u32())));
                "a literal amount".to_owned()
            }
            2 => {
                let mut name = g.ascii_string(1..=24);
                while Figure::ALL.iter().any(|f| f.name() == name) {
                    name.push('x');
                }
                field.insert("figure", Value::String(name.clone()));
                format!("an unknown figure {name:?}")
            }
            3 => {
                let wrong: Vec<Figure> = Figure::ALL
                    .into_iter()
                    .filter(|f| !f.levels().iter().any(|l| l.name() == level))
                    .collect();
                let f = *g.pick(&wrong);
                field.insert("figure", Value::String(f.name().to_owned()));
                format!("{f:?} at level {level}")
            }
            4 => {
                field.insert("value", Value::Number(g.u64_in(0..=999).into()));
                "a literal value beside the fold".to_owned()
            }
            _ => {
                let mut lit = Object::new();
                lit.insert("literal", Value::String("1000.00".into()));
                field.insert("figure", Value::Object(lit));
                "a literal object".to_owned()
            }
        };
        let bytes = v.to_compact().into_bytes();
        match parse_profile(&bytes) {
            Ok(_) => Err(format!("I-44: a profile with {what} was accepted")),
            Err(_) => Ok(()),
        }
    });
    // Every figure each output shows is the independent fold.
    let ps = periods();
    for profile in profiles() {
        let name = format!("i44_profile_fields_are_ledger_folds_{}", profile.id());
        fstp_prop::check(&name, |g| {
            let spec = grants(g);
            let snap = ledger_of(&spec).snapshot();
            for o in profile.outputs() {
                let Some(r) = request(o.kind(), &ps) else {
                    continue;
                };
                let out = generate(&snap, &profile, &r)
                    .map_err(|e| format!("I-44: a reconciling ledger was refused: {e}"))?;
                if out.profile != profile.pin() {
                    return Err("R-RP-01: the output names another profile".into());
                }
                if out.template != o.template() {
                    return Err("R-RP-01: the output names another template".into());
                }
                match (o.kind(), &out.content) {
                    (ReportKind::PeriodicReportingData, Content::Data(v)) => {
                        check_periodic(&profile, &spec, v)?;
                    }
                    (ReportKind::AuditFile, _) => {}
                    (k, c) => check_call(&profile, k, &spec, c)?,
                }
            }
            Ok(())
        });
    }
}

/// A ledger of `spec` with one seeded discrepancy, and the sequence
/// number the generation must list.
fn seeded(g: &mut fstp_prop::Gen, spec: &[GrantSpec]) -> (fstp_report::Snapshot, u64) {
    let mut l = ledger_of(spec);
    let paid: Vec<(usize, usize)> = spec
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.requests
                .iter()
                .enumerate()
                .filter(|(_, r)| matches!(r.outcome, Outcome::Released | Outcome::Paid))
                .map(move |(k, _)| (i, k))
        })
        .collect();
    let at = day(601);
    let record = match g.u8_in(0..=2) {
        0 if !paid.is_empty() => {
            let (i, k) = *g.pick(&paid);
            released(request_id(i, k), proposal(i))
        }
        1 if !spec.is_empty() => released(request_id(0, 9), proposal(0)),
        _ => Record::PaymentConfirmed {
            request: request_id(7, 7),
            by: Actor::System(SystemCause::PaymentPort),
        },
    };
    l.push(at, record);
    let snap = l.snapshot();
    let seq = snap.head().raw();
    (snap, seq)
}

/// I-44 (M9 design section 3, test plan): generated ledgers with a seeded
/// discrepancy fail generation of every output of the profile, under the
/// Horizon Europe profile and the synthetic profile, and the generation
/// lists the seeded record.
#[test]
fn i44_seeded_mismatch_fails_generation() {
    let ps = periods();
    for profile in profiles() {
        let name = format!("i44_seeded_mismatch_fails_generation_{}", profile.id());
        fstp_prop::check(&name, |g| {
            let spec = grants(g);
            let (snap, bad) = seeded(g, &spec);
            for o in profile.outputs() {
                let Some(r) = request(o.kind(), &ps) else {
                    continue;
                };
                match generate(&snap, &profile, &r) {
                    Err(ReportError::Reconciliation(list)) => {
                        if !list.iter().any(|m| m.seq.raw() == bad) {
                            return Err(format!("I-44: seq {bad} is not listed: {list:?}"));
                        }
                    }
                    other => {
                        return Err(format!(
                            "I-44: {} {:?} of a mismatched ledger gave {other:?}",
                            profile.id(),
                            o.kind()
                        ));
                    }
                }
            }
            Ok(())
        });
    }
}

/// R-RP-04, D3: an output the pinned profile does not define is refused,
/// so a profile cannot be bypassed by asking for another output.
#[test]
fn r_rp_04_output_outside_the_profile_is_refused() {
    let snap = ledger_of(&support::fixed()).snapshot();
    let p = synthetic();
    assert!(p.output(ReportKind::CallPublicationRecord).is_none());
    let r = generate(
        &snap,
        &p,
        &Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN",
        },
    );
    assert!(
        matches!(
            r,
            Err(ReportError::NotInProfile(ReportKind::CallPublicationRecord))
        ),
        "{r:?}"
    );
}
