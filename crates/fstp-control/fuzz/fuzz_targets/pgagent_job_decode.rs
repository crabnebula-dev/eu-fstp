//! Fuzz target `pgagent_job_decode` of `fstp-control` (TH-26, H-05,
//! ADR-011, M3 design section 15).
//!
//! Design checks: no panic; identifiers outside the grammar refused;
//! rendered DDL never contains input outside the grammar.
//!
//! On every input the decoder returns without a panic, its result formats,
//! and a second decode gives the same result. A job that decodes from
//! SQL text would let SQL cross the wire (ADR-011), so input that starts
//! with an SQL keyword never decodes. An accepted frame is the one
//! encoding of its job.
//!
//! Each decoded job is then rendered with `job_statements`. The only input
//! that may reach the SQL is the job's cell, as 32 hex digits inside its
//! identifiers, and the verifier of `SetRoleCredential`, inside its one
//! single-quoted literal. So the target also renders the job for a fixed
//! cell and a fixed verifier. It puts a placeholder in place of each in
//! both renderings, and requires the two to be equal byte for byte. The
//! verifier holds no quote and no backslash, so it cannot close the
//! literal. A destructive job renders no SQL at all.

#![no_main]

use fstp_control::ControlError;
use fstp_control::pg::cell_hex;
use fstp_control::pgagent::{
    DbIdent, PgagentJob, RoleIdent, decode_pgagent_job, encode_pgagent_job, job_statements,
};
use fstp_cp_proto::{CellId, ScramVerifier};
use libfuzzer_sys::fuzz_target;

/// SQL statement keywords that no job encoding starts with.
const SQL: [&[u8]; 8] = [
    b"CREATE ", b"DROP ", b"ALTER ", b"GRANT ", b"REVOKE ", b"SELECT ", b"COPY ", b"DO ",
];

/// The cell of the reference rendering.
const REFERENCE_CELL: CellId = CellId([0xa5; 16]);

/// The verifier of the reference rendering.
const REFERENCE_VERIFIER: &str = "SCRAM-SHA-256$4096:AAAAAAAAAAAAAAAAAAAAAA==$\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:\
     BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

fn moved_db(d: &DbIdent) -> DbIdent {
    DbIdent::new(d.database(), REFERENCE_CELL)
}

fn moved_role(r: &RoleIdent) -> RoleIdent {
    match RoleIdent::new(moved_db(&r.database()), r.role()) {
        Ok(m) => m,
        Err(e) => panic!("{r:?} has no reference role: {e}"),
    }
}

/// The job for the reference cell and verifier, with the job's own cell
/// and verifier.
fn reference(job: &PgagentJob) -> (PgagentJob, Option<CellId>, Option<String>) {
    match job {
        PgagentJob::HardenCluster | PgagentJob::PrivilegeAudit => (job.clone(), None, None),
        PgagentJob::CreateCellDatabase(d) => (
            PgagentJob::CreateCellDatabase(moved_db(d)),
            Some(d.cell()),
            None,
        ),
        PgagentJob::CreateRoles(d) => (PgagentJob::CreateRoles(moved_db(d)), Some(d.cell()), None),
        PgagentJob::ApplyRevocations(d) => (
            PgagentJob::ApplyRevocations(moved_db(d)),
            Some(d.cell()),
            None,
        ),
        PgagentJob::ApplyGrants(d) => (PgagentJob::ApplyGrants(moved_db(d)), Some(d.cell()), None),
        PgagentJob::SetRoleCredential { role, verifier } => {
            let fixed = match ScramVerifier::parse(REFERENCE_VERIFIER.as_bytes()) {
                Ok(v) => v,
                Err(e) => panic!("the reference verifier is refused: {e:?}"),
            };
            (
                PgagentJob::SetRoleCredential {
                    role: moved_role(role),
                    verifier: fixed,
                },
                Some(role.database().cell()),
                Some(verifier.as_str().to_owned()),
            )
        }
        PgagentJob::SetNoLogin(r) => (
            PgagentJob::SetNoLogin(moved_role(r)),
            Some(r.database().cell()),
            None,
        ),
        PgagentJob::DropCellDatabase(d) => (
            PgagentJob::DropCellDatabase(moved_db(d)),
            Some(d.cell()),
            None,
        ),
        PgagentJob::DropRoles(d) => (PgagentJob::DropRoles(moved_db(d)), Some(d.cell()), None),
    }
}

/// Each statement's target database and SQL, with the verifier literal
/// and then the cell's hex replaced by placeholders.
fn shape(job: &PgagentJob, cell: Option<CellId>, verifier: Option<&str>) -> Vec<(String, String)> {
    let statements = match job_statements(job) {
        Ok(s) => s,
        Err(e) => panic!("{job:?} does not render: {e}"),
    };
    statements
        .iter()
        .map(|s| {
            let mut target = s.target.database_name();
            let mut sql = s.sql.clone();
            if let Some(v) = verifier {
                let literal = format!("'{v}'");
                assert_eq!(
                    sql.matches(&literal).count(),
                    1,
                    "the verifier is not one literal in {sql}"
                );
                sql = sql.replace(&literal, "'<verifier>'");
            }
            if let Some(c) = cell {
                let hex = cell_hex(c);
                sql = sql.replace(&hex, "<cell>");
                target = target.replace(&hex, "<cell>");
            }
            (target, sql)
        })
        .collect()
}

fn check_rendering(job: &PgagentJob) {
    if job.is_destructive() {
        assert_eq!(job_statements(job), Err(ControlError::ApprovalRequired));
        return;
    }
    let (fixed, cell, verifier) = reference(job);
    if let Some(v) = &verifier {
        assert!(
            !v.bytes().any(|b| b == b'\'' || b == b'\\'),
            "the verifier {v:?} holds a quote or a backslash"
        );
    }
    let fixed_verifier = verifier.as_ref().map(|_| REFERENCE_VERIFIER);
    let fixed_cell = cell.map(|_| REFERENCE_CELL);
    assert_eq!(
        shape(job, cell, verifier.as_deref()),
        shape(&fixed, fixed_cell, fixed_verifier),
        "input outside the cell and the verifier reached the SQL of {job:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let first = decode_pgagent_job(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    assert_eq!(decode_pgagent_job(data), first);
    let Ok(job) = first else {
        return;
    };
    let upper = data.to_ascii_uppercase();
    assert!(
        !SQL.iter().any(|k| upper.starts_with(k)),
        "SQL text decoded as {job:?}"
    );
    assert_eq!(
        encode_pgagent_job(&job).as_deref(),
        Ok(data),
        "{job:?} does not round-trip"
    );
    check_rendering(&job);
});
