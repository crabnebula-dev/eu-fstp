//! The assessor process, `fstp-assessor` (M7 design section 3.1, lane
//! L-PROC, ADR-009 amendment "assessor egress").
//!
//! The cell spawns it as a child. It has no database credential and no
//! ledger access, so it has no write access to domain state (I-10).
//!
//! - [`queue`](decode_job): jobs arrive on stdin, one canonical JSON
//!   object per line, read by [`LineReader`] and decoded by
//!   [`decode_job`]. Results leave on stdout, one line each. The decoder
//!   is the fuzz target `assessor_queue_ndjson` (TH-26).
//! - [`AssessorDestination`] and [`Fence`]: the only outbound
//!   connections, to the inference endpoint and the retrieval proxy
//!   (I-16, B4).
//! - [`Inference`]: the synthetic, replay or HTTP transport of
//!   `fstp-infer` (ADR-019).
//! - [`ProxyClient`]: the retrieval client of `fstp-retrieve` (TH-12).
//! - [`Assessor`]: retrieval, then stages 3 to 7 of `fstp-assess`.
//!
//! # Data channel (TH-01)
//!
//! Submission and retrieved text stay `UntrustedText` from the queue line
//! to the request body. They reach a model only as `DataPart`s of
//! `fstp-infer`, never inside an instruction.
//!
//! # Runtime
//!
//! The binary uses one runtime, tokio, through `fstp-rt` (ADR-002).

mod assessor;
mod egress;
mod inference;
mod intake;
mod queue;
mod retrieval;

pub use assessor::{Assessor, Premasked, refused, result_bytes};
pub use egress::{AssessorDestination, EgressError, Fence};
pub use inference::{Inference, InferenceMode};
pub use intake::{
    CellJob, Intake, IntakeError, IntakeFinding, Link, LinkError, MAX_REPLIES, MAX_RESULT_BYTES,
    MAX_RESULT_FINDINGS, MAX_RETRIEVALS, PendingCause, decode_result,
};
pub use queue::{
    JobConfig, JobLine, Line, LineReader, MAX_CRITERIA, MAX_LINE_BYTES, MAX_OWN, MAX_PARTS,
    MAX_SOURCES, QueueError, SourceLine, decode_job,
};
pub use retrieval::{NoRetrieval, ProxyClient, Retrieval};
