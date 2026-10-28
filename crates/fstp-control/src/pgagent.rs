//! The provisioning agent on each database host (ADR-011).

use crate::ControlError;

/// A provisioning job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgagentJob {
    /// The job kind, as a closed code.
    pub kind: u16,
}

/// Decodes a job. Fuzzed (`pgagent_job_decode`).
pub fn decode_pgagent_job(bytes: &[u8]) -> Result<PgagentJob, ControlError> {
    let _ = bytes;
    Err(ControlError::NotImplemented(
        "fstp_control::pgagent::decode_pgagent_job",
    ))
}

/// Renders a DDL identifier. Input outside the grammar is refused, so the
/// rendered DDL never contains it. Fuzzed (`ddl_identifier_render`).
pub fn render_ddl_identifier(name: &str) -> Result<String, ControlError> {
    let _ = name;
    Err(ControlError::NotImplemented(
        "fstp_control::pgagent::render_ddl_identifier",
    ))
}

/// Runs the agent until shutdown.
pub fn run() -> Result<(), ControlError> {
    Err(ControlError::NotImplemented("fstp_control::pgagent::run"))
}
