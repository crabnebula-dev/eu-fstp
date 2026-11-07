//! The assessment pipeline (M7 design sections 2, 3.2 to 3.4, lane L-PIPE).
//!
//! - Stage 1, [`extract_text`]: hidden characters are recorded and
//!   removed, with a span map back to the original.
//! - Stage 2, [`prepare`]: PII becomes stable placeholders. Patterns run in
//!   the cell, and legal names come from the [`NameMask`] port, whose real
//!   implementation is the vault mask query of a later lane.
//! - Stages 3 to 7, [`Pipeline::assess`]: pinned prompts through
//!   `fstp_infer`, with stripped text only in data parts (TH-01).
//! - Stage 8, [`decode_output`] and [`Prepared::locate`]: the closed
//!   output schema, no score-like content, P-01 criteria and rubric tags
//!   only, and evidence located in the original text (I-10, R-LA-02).
//! - [`config_id`]: the pinned configuration id (I-11, R-LA-05).
//!
//! Submission and retrieved text are [`UntrustedText`] throughout. No
//! module here builds a request body.

mod config;
mod extract;
mod pipeline;
mod rubric;
mod span;
mod strip;
mod validate;

pub use config::{ConfigError, ConfigInput, Provider, config_id};
pub use extract::{Extracted, Mark, MarkKind, extract_text, is_hidden, mark_kind};
pub use fstp_findings::UntrustedText;
pub use pipeline::{
    AssessError, AssessedFinding, Assessment, Job, Pipeline, Prepared, PreparedPart,
    SubmissionPart, prepare,
};
pub use rubric::{RUBRIC_V1, Rubric};
pub use span::SpanMap;
pub use strip::{
    Hit, MaskUnavailable, NameMask, NameSpan, PiiClass, Placeholders, SyntheticNameMask, detect,
};
pub use validate::{
    MAX_EVIDENCE, MAX_FINDINGS, MAX_STATEMENT_BYTES, OutputError, RawFinding, Stage, decode_output,
    score_like,
};
