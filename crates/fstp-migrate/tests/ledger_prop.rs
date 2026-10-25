//! Property test of the forward-only ledger rules (test plan, "Database"
//! layer: migrations forward-only; R-NF-06).
//!
//! [`check_ledger`] is compared with a reference model over generated
//! ledgers: a prefix of the embedded list with random rows dropped, added,
//! duplicated, renamed, renumbered or given another checksum, in random
//! order.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_migrate::{LedgerProblem, LedgerRow, MigrationLimits, check_ledger, validate_entries};
use fstp_pgwire::Timestamptz;
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

fn name(v: i64) -> String {
    format!("m{v}")
}

fn sql(v: i64) -> String {
    format!("SELECT {v}")
}

fn row(v: i64) -> LedgerRow {
    LedgerRow {
        version: v,
        name: name(v),
        checksum: fstp_crypto::sha256(sql(v).as_bytes()).to_vec(),
        statement_count: 1,
        applied_at: Timestamptz::from_unix_micros(0).unwrap(),
    }
}

/// The reference: consistent exactly when the versions are 1 to the
/// number of rows, no more than `n`, and every row carries the name and
/// checksum of its version.
fn reference(rows: &[LedgerRow], n: usize) -> Option<usize> {
    let mut versions: Vec<i64> = rows.iter().map(|r| r.version).collect();
    versions.sort_unstable();
    let prefix = versions == (1..=rows.len() as i64).collect::<Vec<_>>() && rows.len() <= n;
    let matching = rows.iter().all(|r| {
        r.name == name(r.version)
            && r.checksum == fstp_crypto::sha256(sql(r.version).as_bytes()).to_vec()
    });
    (prefix && matching).then_some(rows.len())
}

fn mutate(g: &mut Gen, rows: &mut Vec<LedgerRow>, n: usize) {
    let pick = |g: &mut Gen, len: usize| g.usize_in(0..=len - 1);
    match g.weighted(&[2, 2, 2, 1, 1, 1, 1]) {
        0 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            rows.remove(i);
        }
        1 => rows.push(row(n as i64 + g.i64_in(1..=3))),
        2 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            let bit = 1 << g.u8_in(0..=7);
            match rows[i].checksum.len() {
                0 => rows[i].checksum.push(bit),
                len => {
                    let b = pick(g, len);
                    rows[i].checksum[b] ^= bit;
                }
            }
        }
        3 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            rows[i].name.push('x');
        }
        4 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            rows.push(rows[i].clone());
        }
        5 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            rows[i].version = *g.pick(&[0, -1, i64::MIN, i64::MAX]);
        }
        6 if !rows.is_empty() => {
            let i = pick(g, rows.len());
            rows[i].checksum.truncate(g.usize_in(0..=31));
        }
        _ => {}
    }
}

/// Forward-only (test plan, Database layer): `check_ledger` accepts
/// exactly the ledgers the reference model accepts. When the database is
/// ahead of the binary, the report names an unknown version.
#[test]
fn forward_only_check_ledger_matches_reference_model() {
    check_with(
        "forward_only_check_ledger",
        Config::from_env().with_cases(2_000),
        |g| {
            let n = g.usize_in(0..=6);
            let names: Vec<String> = (1..=n as i64).map(name).collect();
            let sqls: Vec<String> = (1..=n as i64).map(sql).collect();
            let checked = validate_entries(
                (0..n).map(|i| ((i + 1) as u32, names[i].as_str(), sqls[i].as_str())),
                &MigrationLimits::default(),
            )
            .map_err(|e| e.to_string())?;
            let k = g.usize_in(0..=n);
            let mut rows: Vec<LedgerRow> = (1..=k as i64).map(row).collect();
            for _ in 0..g.usize_in(0..=3) {
                mutate(g, &mut rows, n);
            }
            g.shuffle(&mut rows);
            g.note("rows", &rows.iter().map(|r| r.version).collect::<Vec<_>>());

            let got = check_ledger(&checked, &rows);
            match reference(&rows, n) {
                Some(count) => prop_assert_eq!(got, Ok(count)),
                None => {
                    let err = got.err().ok_or("accepted an inconsistent ledger")?;
                    prop_assert!(!err.problems().is_empty());
                    if let Some(max) = rows
                        .iter()
                        .map(|r| r.version)
                        .filter(|&v| v > n as i64)
                        .max()
                    {
                        prop_assert!(
                            err.problems()
                                .contains(&LedgerProblem::UnknownVersion { version: max }),
                            "{err}"
                        );
                    }
                }
            }
            Ok(())
        },
    );
}
