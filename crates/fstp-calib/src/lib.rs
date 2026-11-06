//! Per-corpus calibration metrics (M12, `docs/handoff/m10-m12-design.md`
//! section 3.1, lane L12-METRICS).
//!
//! The crate computes the T-LLM measures of
//! `SPEC/07-test-plan/llm-evaluation.md` that follow from findings and
//! human marks, and Krippendorff's alpha per finding type (T-LLM-CAL).
//! Every figure is an exact integer fraction with a fixed-point rendering
//! in millionths. The crate holds no floats.
//!
//! Every figure is labelled with its corpus (`synthetic` or `consented`).
//! A [`Dataset`] holds one corpus, and [`Dataset::merge`] refuses to pool
//! two corpora, so no figure mixes them.
//!
//! [`fixture`] reads the line-based calibration fixture format. It has a
//! fuzz target in `fuzz/`.

pub mod fixture;
pub mod metrics;

pub use fixture::{FixtureError, FixtureErrorKind, parse};
pub use metrics::{
    Alpha, Corpus, CorpusMetrics, Dataset, Finding, Kind, Level, Mark, MetricError, Proposal,
    ProposalClass, Ratio, SeedKind, Severity, VariantKind, compute, krippendorff_alpha, report,
};
