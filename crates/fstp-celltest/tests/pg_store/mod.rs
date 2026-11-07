//! The record store seams of the M3 tests (lane F-STORE, M3 design
//! sections 4.1, 5.3 and 14.4).
//!
//! The harness of `fstp-pgstore`'s own tests is shared here, so one
//! harness provisions every cell database a store test uses. Its
//! databases hold `fstp_pgstore::MIGRATIONS` and five login roles named
//! as `fstp_pgstore::role_name` names them. [`prod_db`] grants the
//! production role plan of `fstp_control::pg::cell_role_plan` through the
//! `ApplyGrants` job of `fstp-pgagent`, so no test-side plan stands in
//! for the production one.
//!
//! The crash points between the statements of an append are
//! [`FAULTS`], [`arm`] and [`INJECTED_ROWS`].

#![allow(
    dead_code,
    unreachable_pub,
    reason = "a shared test module: each test binary uses part of it"
)]

#[path = "../../../fstp-pgstore/tests/common/mod.rs"]
pub mod common;

pub use common::*;

use fstp_control::pg::CellDatabase;
use fstp_control::pgagent::{DbIdent, PgagentJob, job_statements};
use fstp_cp_proto::CellId;

/// A fresh application database of a cell with `fstp_pgstore::MIGRATIONS`
/// applied, its placement row, and every grant row of the production
/// plan applied by the `ApplyGrants` job's own statements.
pub fn prod_db() -> CellDb {
    let db = must(CellDb::provision_ungranted());
    let job = PgagentJob::ApplyGrants(DbIdent::new(CellDatabase::App, CellId(db.cell)));
    let statements = job_statements(&job).unwrap_or_else(|e| panic!("ApplyGrants: {e}"));
    for s in statements {
        db.psql(&s.sql)
            .unwrap_or_else(|e| panic!("the production grants: {e:?}"));
    }
    db
}
