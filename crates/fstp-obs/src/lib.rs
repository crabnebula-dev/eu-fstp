//! Closed log and metric event enums (R-NF-02, M3 design section 11.1).
//!
//! Every log line and metric is a variant of a closed enum. No variant has
//! a free-text field, so no identity attribute or content can be logged.
//!
//! Status: W0 stub. Lane W2l fills the crate. Encoding refuses with
//! [`ObsError::NotImplemented`]. The crate has no parser, so it has no fuzz
//! project (design section 15).

/// A log event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogEvent {
    /// A process started.
    Started,
    /// A process began its graceful shutdown.
    ShuttingDown,
}

/// A metric name. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricName {
    /// Requests served.
    Requests,
    /// Ledger appends.
    Appends,
}

/// One metric sample, labelled by cell id only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricEvent {
    /// The metric.
    pub name: MetricName,
    /// The cell, 16 random bytes.
    pub cell: [u8; 16],
    /// The value.
    pub value: u64,
}

/// Why an event could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObsError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Encodes a log event as one line.
pub fn encode_log(event: &LogEvent) -> Result<String, ObsError> {
    let _ = event;
    Err(ObsError::NotImplemented("fstp_obs::encode_log"))
}

/// Encodes a metric sample.
pub fn encode_metric(event: &MetricEvent) -> Result<String, ObsError> {
    let _ = event;
    Err(ObsError::NotImplemented("fstp_obs::encode_metric"))
}
