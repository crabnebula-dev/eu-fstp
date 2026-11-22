//! ADR-029: the committed tables are a fresh generation of the vendored
//! Unicode Character Database, and their data keeps the assumptions the
//! normaliser relies on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

/// ADR-029 "Committed tables": `crates/fstp-unorm/src/tables.rs` equals,
/// byte for byte, what `unorm-gen` generates from `third_party/unicode`.
/// Run `cargo run -p unorm-gen` after a change to the generator or data.
#[test]
fn adr029_committed_tables_equal_a_fresh_generation() {
    let fresh = unorm_gen::generate(&common::ucd_dir()).unwrap();
    let committed =
        std::fs::read_to_string(common::repo_root().join(unorm_gen::TABLES_RS)).unwrap();
    assert!(
        fresh == committed,
        "{} is stale: run `cargo run -p unorm-gen`",
        unorm_gen::TABLES_RS
    );
    assert_eq!(
        fstp_unorm::UNICODE_VERSION,
        (18, 0, 0),
        "ADR-029 pins Unicode 18.0.0"
    );
}

/// ADR-029 "Composition" and "Expansion bound": no primary composite is
/// longer in UTF-8 than its pair, so composition never lengthens a string,
/// and no decomposition chain is deeper than the normaliser follows.
#[test]
fn adr029_tables_are_sound() {
    let u = unorm_gen::load(&common::ucd_dir()).unwrap();
    let ud = &u.unicode_data;
    let t = unorm_gen::build(ud, &u.exclusions, &u.folding, &u.nfkc_cf).unwrap();
    let len = |cp: u64| {
        char::from_u32(u32::try_from(cp).unwrap())
            .unwrap()
            .len_utf8()
    };
    for e in &t.comp {
        let (a, b, c) = (e >> 42, (e >> 21) & 0x1F_FFFF, e & 0x1F_FFFF);
        assert!(
            len(c) <= len(a) + len(b),
            "U+{c:04X} is longer than its pair"
        );
    }
    // Depth of each decomposition chain, canonical and compatibility,
    // through the one-level tables.
    fn depth(ud: &unorm_gen::ucd::UnicodeData, cp: u32) -> usize {
        ud.canonical
            .get(&cp)
            .or_else(|| ud.compat.get(&cp))
            .map_or(0, |d| {
                1 + d.iter().map(|&x| depth(ud, x)).max().unwrap_or(0)
            })
    }
    let deepest = ud
        .canonical
        .keys()
        .chain(ud.compat.keys())
        .map(|&cp| depth(ud, cp))
        .max()
        .unwrap();
    assert!(deepest < 8, "a decomposition chain of depth {deepest}");
    // The tables are sorted, so binary search finds every entry.
    for v in [&t.ccc, &t.decomp, &t.comp, &t.fold, &t.compat, &t.ignorable] {
        assert!(v.windows(2).all(|w| w[0] < w[1]), "a table is not sorted");
    }
    // The packed class ranges give every code point its class.
    for c in common::every_char() {
        let want = ud.ccc.get(&u32::from(c)).copied().unwrap_or(0);
        assert_eq!(
            fstp_unorm::combining_class(c),
            want,
            "U+{:04X}",
            u32::from(c)
        );
    }
    let multi: Vec<u32> = t.fold_multi.iter().map(|(k, _)| *k).collect();
    assert!(multi.windows(2).all(|w| w[0] < w[1]));
    let single: BTreeSet<u64> = t.fold.iter().map(|e| e >> 21).collect();
    assert!(multi.iter().all(|k| !single.contains(&u64::from(*k))));
}
