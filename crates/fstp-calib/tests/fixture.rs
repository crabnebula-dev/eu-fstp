//! The calibration fixture reader (TH-26: strict, bounded, typed errors).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fstp_calib::{FixtureErrorKind as K, parse};
use fstp_prop::{check, prop_assert};

fn err(text: &str) -> (usize, K) {
    let e = parse(text.as_bytes()).unwrap_err();
    (e.line, e.kind)
}

const HEAD: &str = "fstp-calib\t1\ncorpus\tsynthetic\nproposal\tP1\tseeded\n";

#[test]
fn th_26_reader_refuses_bad_header_and_corpus() {
    assert_eq!(err(""), (1, K::BadHeader));
    assert_eq!(err("fstp-calib\t2\ncorpus\tsynthetic\n"), (1, K::BadHeader));
    assert_eq!(err("fstp-calib\t1\n"), (1, K::MissingCorpus));
    assert_eq!(
        err("fstp-calib\t1\nproposal\tP1\tclean\n"),
        (2, K::MissingCorpus)
    );
    assert_eq!(err("fstp-calib\t1\ncorpus\tmixed\n"), (2, K::BadValue));
    assert_eq!(
        err(&format!("{HEAD}corpus\tconsented\n")),
        (4, K::DuplicateCorpus)
    );
}

#[test]
fn th_26_reader_refuses_unknown_records_and_field_counts() {
    assert_eq!(err(&format!("{HEAD}score\tP1\t9\n")), (4, K::UnknownRecord));
    assert_eq!(err(&format!("{HEAD}proposal\tP2\n")), (4, K::FieldCount));
    assert_eq!(err(&format!("{HEAD}proposal\tP 2\tclean\n")), (4, K::BadId));
    assert_eq!(
        err(&format!("{HEAD}proposal\tP1\tclean\n")),
        (4, K::Duplicate)
    );
    assert_eq!(
        err(&format!("{HEAD}proposal\tP2\tclean\r\n")),
        (4, K::BadValue)
    );
}

/// No floats: a fractional rating is refused.
#[test]
fn th_26_reader_refuses_fractional_and_out_of_range_values() {
    assert_eq!(
        err(&format!("{HEAD}rating\tquality\tu1\tr1\t0.5\n")),
        (4, K::BadValue)
    );
    assert_eq!(
        err(&format!("{HEAD}rating\tquality\tu1\tr1\t1000001\n")),
        (4, K::BadValue)
    );
    assert_eq!(
        err(&format!("{HEAD}rating\tquality\tu1\tr1\t+1\n")),
        (4, K::BadValue)
    );
    assert_eq!(
        err(&format!(
            "{HEAD}rating\tquality\tu1\tr1\t-2\nrating\tquality\tu1\tr1\t3\n"
        )),
        (5, K::Duplicate)
    );
    assert_eq!(err(&format!("{HEAD}runs\tP1\t0\n")), (4, K::BadValue));
    assert_eq!(err(&format!("{HEAD}runs\tP1\t101\n")), (4, K::BadValue));
}

#[test]
fn th_26_reader_refuses_dangling_references() {
    assert_eq!(
        err(&format!("{HEAD}seed\tP9\ts1\tomission\n")),
        (4, K::UnknownProposal)
    );
    assert_eq!(
        err(&format!("{HEAD}finding\tP1\t1\tf1\tquality\tminor\ts9\n")),
        (4, K::UnknownSeed)
    );
    assert_eq!(
        err(&format!("{HEAD}mark\tP1\tf9\tr1\tagreed\n")),
        (4, K::UnknownFinding)
    );
    assert_eq!(
        err(&format!("{HEAD}finding\tP1\t2\tf1\tquality\tminor\t-\n")),
        (4, K::RunOutOfRange)
    );
    assert_eq!(
        err(&format!("{HEAD}proposal\tC1\tclean\nseed\tC1\ts1\tclaim\n")),
        (5, K::SeedOnClean)
    );
    assert_eq!(
        err(&format!("{HEAD}variant\tP1\tP1\tfluency\n")),
        (4, K::BadVariant)
    );
}

/// TH-26: arbitrary input never panics, and an accepted input renders a
/// report whose every body line carries the corpus label.
#[test]
fn th_26_reader_never_panics_on_arbitrary_lines() {
    let words = [
        "fstp-calib",
        "1",
        "corpus",
        "synthetic",
        "consented",
        "proposal",
        "seed",
        "finding",
        "mark",
        "variant",
        "rating",
        "runs",
        "P1",
        "P2",
        "s1",
        "f1",
        "clean",
        "seeded",
        "omission",
        "claim",
        "quality",
        "integrity",
        "major",
        "minor",
        "agreed",
        "disputed",
        "injected",
        "fluency",
        "-",
        "2",
        "-1",
        "",
    ];
    check("th_26_reader_never_panics_on_arbitrary_lines", |g| {
        let mut text = String::from("fstp-calib\t1\ncorpus\tsynthetic\n");
        for line in g.vec(0..=20, |g| g.vec(1..=7, |g| *g.pick(&words))) {
            text.push_str(&line.join("\t"));
            text.push('\n');
        }
        if let Ok(d) = parse(text.as_bytes()) {
            let r = fstp_calib::report(vec![d]).map_err(|e| format!("{e:?}"))?;
            prop_assert!(r.lines().skip(1).all(|l| l.starts_with("synthetic\t")));
        }
        Ok(())
    });
}
