//! O-55, I-72, I-96: the shipped plain and Voyage packs hold the labels of `docs/design/07-vocabulary-pack.md`, word for word.
//!
//! Catalogues 1, 2, 4 and 5 give a plain and a Voyage label per key.
//! "Same" or a repeat of the plain label means the Voyage pack adds no
//! secondary line, so it may leave the key out. Catalogue 3 gives the
//! plain label and the spec name, which is the Voyage label
//! (`SPEC/12-journey-ui.md` section 4). Rows with a placeholder are diary
//! sentences, not labels, and no pack names them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_journey::vocab::{LABEL_KEYS, plain_v1, voyage_v1};

struct Row {
    catalogue: u8,
    key: String,
    plain: String,
    voyage: String,
}

fn rows() -> Vec<Row> {
    let path = format!(
        "{}/../../docs/design/07-vocabulary-pack.md",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut catalogue = 0u8;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## Catalogue ") {
            catalogue = rest.get(..1).unwrap().parse().unwrap();
            continue;
        }
        if line.starts_with("## ") {
            catalogue = 0;
        }
        if catalogue == 0 || !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
        let cell = |i: usize| *cells.get(i).unwrap_or_else(|| panic!("short row: {line}"));
        let key = cell(0).trim_matches('`').to_owned();
        let (plain, voyage) = match catalogue {
            1 | 2 => (cell(2), cell(3)),
            3 => (cell(2), cell(1)),
            _ => (cell(1), cell(2)),
        };
        out.push(Row {
            catalogue,
            key,
            plain: plain.to_owned(),
            voyage: voyage.to_owned(),
        });
    }
    out
}

/// O-55, I-72: one pack key per design 07 label row, and the plain and
/// Voyage texts of each row.
#[test]
fn o55_packs_follow_design_07_catalogues() {
    let plain = plain_v1().unwrap();
    let voyage = voyage_v1().unwrap();
    let rows = rows();
    assert!(rows.len() > 60, "design 07 rows: {}", rows.len());
    let mut keys = BTreeSet::new();
    for r in &rows {
        if r.plain.contains('{') {
            assert!(!LABEL_KEYS.contains(&r.key.as_str()), "I-72: {}", r.key);
            continue;
        }
        keys.insert(r.key.as_str());
        assert_eq!(plain.get(&r.key), Some(r.plain.as_str()), "O-55: {}", r.key);
        let got = voyage.get(&r.key);
        if r.catalogue == 3 {
            let got = got.unwrap_or_else(|| panic!("no Voyage label for {}", r.key));
            assert!(
                r.voyage.to_lowercase().contains(&got.to_lowercase()),
                "O-55: {} is {got:?}, spec name {:?}",
                r.key,
                r.voyage
            );
        } else if r.voyage == "Same" || r.voyage == r.plain {
            assert!(got.is_none_or(|t| t == r.plain), "O-55: {}", r.key);
        } else {
            assert_eq!(got, Some(r.voyage.as_str()), "O-55: {}", r.key);
        }
    }
    let listed: BTreeSet<&str> = LABEL_KEYS.iter().copied().collect();
    assert_eq!(listed, keys, "I-72: the label keys are the design 07 rows");
}
