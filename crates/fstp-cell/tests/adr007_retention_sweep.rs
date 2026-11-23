//! The retention sweep of stored documents (ADR-007 section "Decided by
//! Daniel on 2026-11-23", decision 1b, lane L39, R-KY-02, P-41).
//!
//! The sweep erases a document once the period of its class ends. The
//! periods are the ones the SPEC defines. A class with no period is
//! `TODO(legal)` and is never erased, and a brand asset is never erased
//! by a trigger. Every row is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::tasks::retention::{
    DocumentRetention, DocumentRow, KIND_BRAND_ASSET, KIND_IMPORT_DOCUMENT, due, rule,
};

const DAY: i64 = 86_400_000_000;

fn row(kind: i16, n: u8, stored_at: i64) -> DocumentRow {
    DocumentRow {
        kind,
        dek: [n; 16],
        stored_at,
    }
}

/// ADR-007 (Daniel, 2026-11-23, decisions 1b and "Brand assets"; lane
/// L39), property over every `doc.blob` kind and a spread of instants:
/// the production rule table never makes a brand asset, an import
/// document (no SPEC period, `TODO(legal)`) or an unknown kind due, and
/// so with today's table the sweep erases nothing at all.
#[test]
fn adr007_l39_prop_retention_rules_erase_no_brand_and_no_undefined_class() {
    assert_eq!(rule(KIND_BRAND_ASSET), DocumentRetention::Never);
    assert_eq!(rule(KIND_IMPORT_DOCUMENT), DocumentRetention::Undefined);
    let instants = [0, 1, DAY, 400 * DAY, 40 * 365 * DAY, i64::MAX / 2, i64::MAX];
    for kind in i16::MIN..=i16::MAX {
        let r = rule(kind);
        assert!(
            !matches!(r, DocumentRetention::After { .. }),
            "kind {kind}: no SPEC period applies to a stored row today"
        );
        let rows: Vec<DocumentRow> = instants
            .iter()
            .enumerate()
            .map(|(n, t)| row(kind, u8::try_from(n).unwrap(), *t))
            .collect();
        for now in instants {
            assert!(due(&rows, rule, now).is_empty(), "kind {kind} at {now}");
        }
    }
}

/// ADR-007 (lane L39): with a period, the sweep plans exactly the rows
/// whose period ended at `now`, never a row of a class without one, and
/// never a brand asset, whatever the rule says of it. An overflowing end
/// is never due.
#[test]
fn adr007_l39_sweep_plans_only_due_rows() {
    let synthetic = |kind: i16| match kind {
        1 => DocumentRetention::After { micros: 10 * DAY },
        KIND_BRAND_ASSET => DocumentRetention::After { micros: 0 },
        _ => DocumentRetention::Undefined,
    };
    let rows = [
        row(1, 1, 0),
        row(1, 2, 5 * DAY),
        row(1, 3, i64::MAX - 1),
        row(KIND_IMPORT_DOCUMENT, 4, 0),
        row(KIND_BRAND_ASSET, 5, 0),
    ];
    assert!(due(&rows, synthetic, 9 * DAY).is_empty());
    assert_eq!(due(&rows, synthetic, 10 * DAY), vec![[1; 16]]);
    assert_eq!(due(&rows, synthetic, 15 * DAY), vec![[1; 16], [2; 16]]);
    assert_eq!(due(&rows, synthetic, i64::MAX), vec![[1; 16], [2; 16]]);
}
