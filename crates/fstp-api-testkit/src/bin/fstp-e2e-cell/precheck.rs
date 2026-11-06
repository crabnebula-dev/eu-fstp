//! The fake pre-check provider of the e2e cell (Q38 C, Daniel's answer
//! of 2026-11-06 in section 15.0 of the M4 design; R-LA-08). Test only
//! (layering rule A9).
//!
//! The pre-check arrives in M7. Until then the e2e cell runs the
//! pre-check path with this provider: every run answers one fixed
//! synthetic finding and no score, as the Guide says a pre-check does.
//! `POST /test/precheck` on the control base runs it. No cell origin
//! answers it, and no production cell has a provider.
//!
//! Interim, pending M7: the port `fstp_api_core::port::Precheck` has no
//! method yet, so the run is this module's own.

use fstp_api_core::port::Precheck;
use fstp_http::{Response, StatusCode};
use fstp_json::Value;

use crate::wire::{self, obj};

/// The fixed result of every run. Synthetic, not an assessment.
pub(crate) const SYNTHETIC_FINDING: &str =
    "Synthetic pre-check finding for tests. No AI system ran and no score is given.";

/// The fake pre-check provider.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SyntheticPrecheck;

impl Precheck for SyntheticPrecheck {}

impl SyntheticPrecheck {
    /// One run: the fixed synthetic finding, and no score (R-LA-08).
    pub(crate) fn run(&self) -> Value {
        obj(vec![
            ("provider", Value::from("synthetic")),
            (
                "findings",
                Value::Array(vec![Value::from(SYNTHETIC_FINDING)].into_iter().collect()),
            ),
            ("score", Value::Null),
        ])
    }
}

/// `POST /test/precheck`: one run of the provider.
pub(crate) fn handle() -> Response {
    wire::json(StatusCode::OK, &SyntheticPrecheck.run())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q38 C, R-LA-08: the provider answers its fixed synthetic finding
    /// and never a score.
    #[test]
    fn r_la_08_q38_fake_precheck_provider_answers() {
        let v = SyntheticPrecheck.run();
        assert_eq!(v.get("provider").and_then(Value::as_str), Some("synthetic"));
        let findings = v.get("findings").and_then(Value::as_array);
        assert_eq!(
            findings.map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
            Some(vec![SYNTHETIC_FINDING])
        );
        assert_eq!(v.get("score"), Some(&Value::Null));
        assert_eq!(handle().status, StatusCode::OK);
    }
}
