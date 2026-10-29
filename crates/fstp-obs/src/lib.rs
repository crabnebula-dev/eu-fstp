//! Closed log and metric event enums (R-NF-02, M3 design section 11.1).
//!
//! Every log line is a [`LogEvent`] and every operator metric is a
//! [`Metric`]. Both are closed enums. Their fields are ids, rule references,
//! enums, counts, durations and `&'static str` only. No variant takes a
//! `String`, so free text, proposal content and identity attributes cannot
//! reach a log or a metric by construction (R-NF-02).
//!
//! - Paths are logged as route templates such as `/proposals/{id}`, never as
//!   the concrete request path. [`encode_log`] refuses a route that is not
//!   written in the template alphabet.
//! - Logs stay per cell. A process writes its own events with [`write_log`]
//!   to its own stream, and no operator aggregation reads them.
//! - Operator aggregation receives metrics only. A [`MetricEvent`] is
//!   labelled with the cell id and nothing else.
//!
//! Shipped crates never use `println!` or `eprintln!`. The workspace
//! `clippy.toml` bans the print macros, the functions they expand to and
//! the raw `std::io::stdout` and `std::io::stderr` handles. A binary writes
//! its events through [`log_to_stderr`] and [`metric_to_stdout`] instead.
//!
//! The crate has no parser, so it has no fuzz project (design section 15).

mod encode;

pub use crate::encode::{
    MAX_ROUTE_LEN, MAX_RULE_LEN, UNROUTED, encode_log, encode_metric, log_to_stderr,
    metric_to_stdout, write_log, write_metric,
};

use std::fmt;
use std::io;
use std::time::Duration;

/// Length of a cell id in bytes. A metric names its cell by these bytes as
/// 32 lowercase hex digits.
pub const CELL_ID_LEN: usize = 16;

/// An HTTP request method, closed so that no method text from a request is
/// logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
    /// `CONNECT`
    Connect,
    /// `TRACE`
    Trace,
    /// Any method the platform does not route. Its text is not logged.
    Other,
}

impl Method {
    /// The method as written on the wire, or `OTHER`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other => "OTHER",
        }
    }
}

/// The termination signal a process received.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signal {
    /// SIGTERM, sent by a service manager.
    Terminate,
    /// SIGINT, sent from a terminal.
    Interrupt,
}

impl Signal {
    /// The signal's conventional name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Interrupt => "SIGINT",
        }
    }
}

/// A log event. Closed: a process can log nothing else.
///
/// A `route` field holds a route template, never the concrete request path.
/// A `rule` field holds a rule reference such as `I-78` or `SoD-08`.
///
/// `Debug` shows a `route` or `rule` field only when it passes the check
/// that [`encode_log`] applies, and shows `<refused>` otherwise. So a
/// formatted event in an error or a panic message carries no leaked text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogEvent {
    /// A process started.
    Started,
    /// A process began its graceful shutdown.
    ShuttingDown,
    /// A stub binary refused to run because its work is not built yet.
    NotImplemented,
    /// A termination signal arrived.
    SignalReceived {
        /// Which signal.
        signal: Signal,
    },
    /// Every task that had to finish before exit has finished.
    Drained {
        /// Time from the shutdown trigger to the end of the drain.
        elapsed: Duration,
    },
    /// The drain deadline passed with tasks still running.
    DrainTimedOut {
        /// Tasks still running at the deadline.
        remaining: u64,
    },
    /// A request was served.
    Request {
        /// The request method.
        method: Method,
        /// The route template that matched, or [`UNROUTED`].
        route: &'static str,
        /// The response status code.
        status: u16,
        /// Time from the end of the request head to the end of the response.
        elapsed: Duration,
    },
    /// A request was refused under a rule.
    Refused {
        /// The request method.
        method: Method,
        /// The route template that matched, or [`UNROUTED`].
        route: &'static str,
        /// The rule that refused it.
        rule: &'static str,
        /// The response status code.
        status: u16,
    },
}

impl fmt::Debug for LogEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Started => f.write_str("Started"),
            Self::ShuttingDown => f.write_str("ShuttingDown"),
            Self::NotImplemented => f.write_str("NotImplemented"),
            Self::SignalReceived { signal } => f
                .debug_struct("SignalReceived")
                .field("signal", &signal)
                .finish(),
            Self::Drained { elapsed } => f
                .debug_struct("Drained")
                .field("elapsed", &elapsed)
                .finish(),
            Self::DrainTimedOut { remaining } => f
                .debug_struct("DrainTimedOut")
                .field("remaining", &remaining)
                .finish(),
            Self::Request {
                method,
                route,
                status,
                elapsed,
            } => f
                .debug_struct("Request")
                .field("method", &method)
                .field("route", &encode::shown_route(route))
                .field("status", &status)
                .field("elapsed", &elapsed)
                .finish(),
            Self::Refused {
                method,
                route,
                rule,
                status,
            } => f
                .debug_struct("Refused")
                .field("method", &method)
                .field("route", &encode::shown_route(route))
                .field("rule", &encode::shown_rule(rule))
                .field("status", &status)
                .finish(),
        }
    }
}

/// An operator metric. Closed: no other metric reaches aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Metric {
    /// Requests served.
    Requests,
    /// Requests refused under a rule.
    Refusals,
    /// Ledger appends.
    Appends,
    /// Time spent serving requests, in microseconds.
    RequestDuration,
}

/// Another name for [`Metric`], as the `name` of a [`MetricEvent`].
pub type MetricName = Metric;

/// What a [`Metric`] value counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricUnit {
    /// A number of events.
    Count,
    /// A duration in whole microseconds.
    Microseconds,
}

impl Metric {
    /// Every metric, in declaration order.
    pub const ALL: [Metric; 4] = [
        Self::Requests,
        Self::Refusals,
        Self::Appends,
        Self::RequestDuration,
    ];

    /// The metric's exposition name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Requests => "fstp_requests_total",
            Self::Refusals => "fstp_refusals_total",
            Self::Appends => "fstp_ledger_appends_total",
            Self::RequestDuration => "fstp_request_duration_microseconds_total",
        }
    }

    /// What the metric's value counts.
    #[must_use]
    pub const fn unit(self) -> MetricUnit {
        match self {
            Self::Requests | Self::Refusals | Self::Appends => MetricUnit::Count,
            Self::RequestDuration => MetricUnit::Microseconds,
        }
    }
}

/// One metric sample, labelled by cell id only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricEvent {
    /// The metric.
    pub name: Metric,
    /// The cell, 16 random bytes.
    pub cell: [u8; CELL_ID_LEN],
    /// The value, in the metric's [`MetricUnit`].
    pub value: u64,
}

impl MetricEvent {
    /// A sample of a count.
    #[must_use]
    pub const fn count(name: Metric, cell: [u8; CELL_ID_LEN], value: u64) -> Self {
        Self { name, cell, value }
    }

    /// A sample of a duration, in whole microseconds. A duration beyond
    /// `u64::MAX` microseconds is recorded as `u64::MAX`.
    #[must_use]
    pub fn duration(name: Metric, cell: [u8; CELL_ID_LEN], value: Duration) -> Self {
        Self {
            name,
            cell,
            value: micros(value),
        }
    }
}

/// Whole microseconds of `d`, saturating at `u64::MAX`.
pub(crate) fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Why an event could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObsError {
    /// A `route` field is not a route template. The text is not repeated.
    InvalidRoute,
    /// A `rule` field is not a rule reference. The text is not repeated.
    InvalidRule,
    /// The output stream failed.
    Io(io::ErrorKind),
}

impl fmt::Display for ObsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoute => f.write_str("route field is not a route template"),
            Self::InvalidRule => f.write_str("rule field is not a rule reference"),
            Self::Io(kind) => write!(f, "writing the event failed: {kind:?}"),
        }
    }
}

impl std::error::Error for ObsError {}
