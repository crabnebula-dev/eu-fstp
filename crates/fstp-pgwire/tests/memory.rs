//! Memory held by `query` versus `Limits::max_result_bytes`.
//!
//! This test reads the resident set size of the whole process, so it runs
//! in its own test binary, away from other tests that allocate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{block_on, connect, fresh};
use fstp_pgwire::{ErrorKind, Limits};

/// The resident set size in bytes, from `/proc/self/statm`.
fn rss_bytes() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = s.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

/// Many tiny rows must not hold many times `max_result_bytes`. Before the
/// fix, two million zero-column rows passed a 4 MiB limit and held about
/// 180 MiB.
#[test]
fn review_pg_result_limit_underaccounts_memory_rss() {
    let (_db, cfg) = fresh();
    let limit = 4usize << 20;
    let mut c = connect(&cfg.limits(Limits {
        max_result_bytes: limit,
        ..Limits::default()
    }));
    block_on(async {
        // Warm up the connection and the allocator.
        c.query("SELECT 1", &[]).await.unwrap();
        for sql in [
            "SELECT FROM generate_series(1, 2000000)",
            "SELECT g FROM generate_series(1, 400000) g",
        ] {
            let before = rss_bytes();
            let err = c.query(sql, &[]).await.unwrap_err();
            let growth = rss_bytes().saturating_sub(before);
            assert_eq!(err.kind(), ErrorKind::ResultTooLarge, "{sql}: {err}");
            assert!(
                growth < (limit as u64) * 4,
                "{sql}: resident memory grew by {} MiB with a limit of {} MiB",
                growth >> 20,
                limit >> 20
            );
        }
    });
}
