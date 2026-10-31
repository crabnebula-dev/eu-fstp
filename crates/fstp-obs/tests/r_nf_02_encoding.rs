//! R-NF-02: what `fstp-obs` writes for a log event or a metric sample.
//!
//! A log event is one line with no control characters, so no event can
//! forge a second line (M3 design section 11.1). A metric sample names its
//! cell by the 32 lowercase hex digits of the cell id, the form the control
//! plane uses (design section 4.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_obs::{LogEvent, MetricEvent, MetricName, encode_log, encode_metric};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One line: no control character, except one optional final `\n`.
fn is_one_line(s: &str) -> bool {
    let body = s.strip_suffix('\n').unwrap_or(s);
    !body.is_empty() && !body.chars().any(char::is_control)
}

/// R-NF-02 (design section 11.1): every log event encodes as one line.
#[test]
fn r_nf_02_every_log_event_encodes_as_one_line() {
    let bad: Vec<String> = [LogEvent::Started, LogEvent::ShuttingDown]
        .iter()
        .filter_map(|e| match encode_log(e) {
            Ok(line) if is_one_line(&line) => None,
            other => Some(format!("{e:?} -> {other:?}")),
        })
        .collect();
    assert!(bad.is_empty(), "not one line: {bad:?}");
}

/// R-NF-02 (design section 11.1): a metric sample encodes as one line that
/// names its cell id.
#[test]
fn r_nf_02_metric_sample_encodes_with_its_cell_id() {
    fstp_prop::check("r_nf_02_metric_sample_encodes_with_its_cell_id", |g| {
        let cell: [u8; 16] = g.bytes(16..=16).try_into().unwrap();
        let name = *g.pick(&[MetricName::Requests, MetricName::Appends]);
        let value = g.u64();
        let event = MetricEvent { name, cell, value };
        g.note("event", &event);
        let line = encode_metric(&event).map_err(|e| format!("refused: {e:?}"))?;
        if !is_one_line(&line) {
            return Err(format!("not one line: {line:?}"));
        }
        if !line.contains(&hex(&cell)) {
            return Err(format!("cell id missing: {line:?}"));
        }
        Ok(())
    });
}
