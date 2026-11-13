//! R-PR-02, P-26: the SPDX licence expression parser and the licence tag
//! detection that the licence check runs on a deliverable's licence file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_checks::detect::{Detected, detect};
use fstp_checks::spdx::{Expr, MAX_DEPTH, MAX_LEN, SpdxError, parse};
use fstp_domain::policy::{LicenceSet, SpdxId};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn set(ids: &[&str]) -> LicenceSet {
    LicenceSet(
        ids.iter()
            .map(|s| SpdxId((*s).to_owned()))
            .collect::<BTreeSet<_>>(),
    )
}

/// R-PR-02: simple and compound expressions parse, with WITH binding
/// tighter than AND, and AND tighter than OR.
#[test]
fn r_pr_02_spdx_parses_simple_and_compound_expressions() {
    for ok in [
        "MIT",
        "EUPL-1.2",
        "GPL-2.0+",
        "LicenseRef-synthetic-1",
        "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
        "Apache-2.0 OR MIT",
        "(MIT AND BSD-3-Clause) OR Apache-2.0",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "  MIT   AND (Apache-2.0 OR EUPL-1.2)  ",
    ] {
        assert!(parse(ok).is_ok(), "{ok} should parse");
    }
    let e = parse("A AND B OR C WITH X").unwrap();
    match e {
        Expr::Or(l, r) => {
            assert!(matches!(*l, Expr::And(..)));
            assert!(matches!(*r, Expr::With { .. }));
        }
        other => panic!("OR binds loosest: {other:?}"),
    }
}

/// R-PR-02: malformed expressions are refused with a typed error.
#[test]
fn r_pr_02_spdx_refuses_malformed_expressions() {
    for bad in [
        "",
        "   ",
        "MIT AND",
        "AND MIT",
        "(MIT",
        "MIT)",
        "MIT or Apache-2.0",
        "MIT Apache-2.0",
        "MIT WITH",
        "MIT WITH LicenseRef-x",
        "MIT WITH X+",
        "MIT++",
        "LicenseRef-",
        "DocumentRef-a:MIT",
        "MI\u{0}T",
        "MIT; rm",
        "()",
    ] {
        assert!(parse(bad).is_err(), "{bad:?} should be refused");
    }
    let deep = format!(
        "{}MIT{}",
        "(".repeat(MAX_DEPTH + 1),
        ")".repeat(MAX_DEPTH + 1)
    );
    assert_eq!(parse(&deep), Err(SpdxError::TooDeep));
    let long = vec!["MIT"; MAX_LEN].join(" OR ");
    assert_eq!(parse(&long), Err(SpdxError::TooLong));
}

/// P-26: an expression is accepted when every conjunct and at least one
/// alternative of each disjunction is an accepted identifier. A licence
/// reference is never accepted.
#[test]
fn p26_accepted_licences_under_the_expression_operators() {
    let p26 = set(&["MIT", "Apache-2.0", "GPL-2.0-only"]);
    for (expr, ok) in [
        ("MIT", true),
        ("mit", true),
        ("EUPL-1.2", false),
        ("MIT AND Apache-2.0", true),
        ("MIT AND EUPL-1.2", false),
        ("MIT OR EUPL-1.2", true),
        ("GPL-2.0-only WITH Classpath-exception-2.0", true),
        ("LicenseRef-synthetic", false),
        ("LicenseRef-synthetic OR MIT", true),
    ] {
        assert_eq!(parse(expr).unwrap().accepted(&p26), ok, "{expr}");
    }
}

/// R-PR-02: the declared and detected expressions compare without case
/// and without the order of the operands of AND and OR.
#[test]
fn r_pr_02_spdx_same_ignores_case_and_operand_order() {
    let a = parse("MIT OR Apache-2.0").unwrap();
    assert!(a.same(&parse("apache-2.0 OR mit").unwrap()));
    assert!(!a.same(&parse("MIT AND Apache-2.0").unwrap()));
    assert!(!a.same(&parse("MIT").unwrap()));
}

fn random_expr(g: &mut Gen, depth: usize) -> String {
    let ids = ["MIT", "Apache-2.0", "EUPL-1.2", "GPL-2.0+", "LicenseRef-x1"];
    if depth == 0 || g.weighted(&[2, 1]) == 0 {
        return (*g.pick(&ids)).to_owned();
    }
    let l = random_expr(g, depth.saturating_sub(1));
    let r = random_expr(g, depth.saturating_sub(1));
    match g.weighted(&[1, 1, 1, 1]) {
        0 => format!("{l} AND {r}"),
        1 => format!("{l} OR {r}"),
        2 => format!("({l})"),
        _ => format!("{} WITH Classpath-exception-2.0", g.pick(&ids[..3])),
    }
}

/// R-PR-02: rendering a parsed expression and parsing it again gives the
/// same tree, so the canonical form recorded in a snapshot is faithful.
#[test]
fn r_pr_02_spdx_render_round_trips() {
    check("r_pr_02_spdx_render_round_trips", |g| {
        let s = random_expr(g, 4);
        let e = parse(&s).map_err(|e| format!("{s}: {e:?}"))?;
        let again = parse(&e.to_string()).map_err(|x| format!("{e}: {x:?}"))?;
        prop_assert_eq!(e, again);
        Ok(())
    });
}

/// R-PR-02: the parser never panics on arbitrary text.
#[test]
fn r_pr_02_spdx_total_on_arbitrary_text() {
    check("r_pr_02_spdx_total_on_arbitrary_text", |g| {
        let s = g.string(0..=64);
        let _ = parse(&s);
        prop_assert!(true);
        Ok(())
    });
}

/// R-PR-02: detection reads the SPDX-License-Identifier tag of a licence
/// file, refuses conflicting tags, and reports a file without a tag.
#[test]
fn r_pr_02_licence_tag_detection() {
    let one = b"Synthetic Project\nSPDX-License-Identifier: EUPL-1.2\nsynthetic body\n";
    assert_eq!(detect(one), Detected::Found(parse("EUPL-1.2").unwrap()));
    let comment = b"/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n";
    assert_eq!(
        detect(comment),
        Detected::Found(parse("MIT OR Apache-2.0").unwrap())
    );
    let twice = b"SPDX-License-Identifier: MIT\nSPDX-License-Identifier: mit\n";
    assert_eq!(detect(twice), Detected::Found(parse("MIT").unwrap()));
    let clash = b"SPDX-License-Identifier: MIT\nSPDX-License-Identifier: EUPL-1.2\n";
    assert_eq!(detect(clash), Detected::Conflict);
    assert_eq!(detect(b"no tag in this synthetic file\n"), Detected::Absent);
    assert_eq!(
        detect(b"SPDX-License-Identifier: MIT or what\n"),
        Detected::Invalid
    );
    assert_eq!(detect(&[0xff, 0xfe, 0x00]), Detected::Absent);
}

/// The input of CI fuzz run 43337494359 (target `spdx_expression`). It is
/// 510 bytes, but its canonical form is longer than [`MAX_LEN`], because
/// rendering puts a space on both sides of every operator.
const FUZZ_43337494359: &str = concat!(
    "MINoMIT OR (he1-0ADMM\tAND (e\tAND (1 OR .)OR .MM\tAND (e\t",
    "AND (1 OR .)OR .)\t\tAND (1 OR .)OR 8MM\tAND (e\t",
    "AND (1 OR .)OR .)\tAND (e\tAND (e1 OR .)OR .))\tAND(e\t",
    "AND (e1 OR .)AND (e\tAND (e1 OR .)OR .))\tAND(e.0pacse AND",
    " T OR Ref--Apac AND Licenah OR .0 AND T OR .0aah OR .h \tAND (e1 ",
    "OR .)OR .) AND 0 AND MsenseRInLiceLicensnu0 AND T OR .0aah OR .h",
    " OR .ah OR .0h OR .0aah OR .0-1u0 AND MILicc AND Ms OR .0pacse A",
    "ND T OR Ref--Apac AND Licenah OR .0 AND T OR .0aah OR .h OR .0aa",
    "h OR .0h OR .0aah OR .0MseNDp OR .0NT OR (Apa))",
);

/// R-PR-02, TH-26: an expression whose canonical form would exceed
/// [`MAX_LEN`] is refused as too long, so every accepted expression
/// renders to a form that parses to the same tree. Regression for CI fuzz
/// run 43337494359.
#[test]
fn r_pr_02_th_26_spdx_refuses_when_the_canonical_form_is_too_long() {
    assert_eq!(FUZZ_43337494359.len(), 510);
    assert_eq!(parse(FUZZ_43337494359), Err(SpdxError::TooLong));
    // Each `)AND(` gains two spaces when rendered.
    let mut tight = String::from("(A OR B)");
    while tight.len().saturating_add(11) <= MAX_LEN {
        tight.push_str("AND(A OR B)");
    }
    assert_eq!(parse(&tight), Err(SpdxError::TooLong));
    // At the bound itself an expression still parses and round trips.
    let mut fits = String::from("A");
    while fits.len().saturating_add(6) <= MAX_LEN {
        fits.push_str(" AND A");
    }
    let e = parse(&fits).unwrap();
    assert_eq!(e.to_string(), fits);
    assert_eq!(parse(&e.to_string()), Ok(e));
}

/// R-PR-02, TH-26: deep nesting is refused with a typed error and never
/// exhausts the stack, whatever the length of the input.
#[test]
fn r_pr_02_th_26_spdx_deep_nesting_is_refused() {
    let huge = format!("{}MIT{}", "(".repeat(100_000), ")".repeat(100_000));
    assert_eq!(parse(&huge), Err(SpdxError::TooLong));
    let open = "(".repeat(100_000);
    assert_eq!(parse(&open), Err(SpdxError::TooLong));
    let within = format!(
        "{}MIT{}",
        "(".repeat(MAX_LEN / 2 - 2),
        ")".repeat(MAX_LEN / 2 - 2)
    );
    assert_eq!(parse(&within), Err(SpdxError::TooDeep));
    let edge = format!("{}MIT{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
    assert_eq!(parse(&edge), Ok(parse("MIT").unwrap()));
}
