//! Line encodings of log events and metric samples (R-NF-02).
//!
//! A log event is one JSON object on one line. A metric sample is one line
//! in the text exposition form `name{cell="<32 hex digits>"} value`. Both
//! end with `\n` and hold no other control character, so no event can forge
//! a second line.
//!
//! Every text value written is either a constant of this crate or a
//! `&'static str` field that passes a narrow alphabet check. The check
//! refuses text that holds a character a route template or a rule reference
//! never holds, such as `@`, `?`, `%`, `=` or an uppercase letter. Numbers
//! are integers; durations are whole microseconds.
//!
//! The check is a second line of defence, not a proof. It cannot tell a
//! lowercase concrete path such as `/users/alice.smith` from a template.
//! Safe code can also build a `&'static str` at run time, for example by
//! leaking a `String`. Such text passes when it uses only the template
//! alphabet. The first line of defence is that callers pass route templates
//! from the route table, never request text.

use std::fmt::Write as _;
use std::io;

use crate::{CELL_ID_LEN, LogEvent, MetricEvent, ObsError, micros};

/// Longest route template [`encode_log`] accepts, in bytes.
pub const MAX_ROUTE_LEN: usize = 256;

/// Longest rule reference [`encode_log`] accepts, in bytes.
pub const MAX_RULE_LEN: usize = 32;

/// The route template to log when no route matched a request.
pub const UNROUTED: &str = "/*";

/// Rule prefixes of the SPEC ID scheme that a refusal may cite.
const RULE_PREFIXES: [&str; 11] = ["ADR", "SoD", "TH", "B", "G", "H", "I", "L", "O", "P", "R"];

/// Whether `b` may appear in a literal segment of a route template:
/// lowercase ASCII letters, digits, `-`, `.` and `_`.
const fn is_literal_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_')
}

/// A parameter name: a lowercase ASCII letter, then lowercase letters,
/// digits and `_`.
fn is_param_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// One segment of a route template: `{name}` or a literal.
fn is_template_segment(seg: &str) -> bool {
    match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        Some(name) => is_param_name(name),
        None => seg.bytes().all(is_literal_byte),
    }
}

/// A route template is [`UNROUTED`], or `/`-separated segments that are
/// each a lowercase literal or a `{name}` parameter, at most
/// [`MAX_ROUTE_LEN`] bytes. A platform template never holds `@`, `:`,
/// `=`, `+`, uppercase letters, a query or a percent-encoding, so a path
/// that holds one of them, such as one with an email address, is refused.
/// A concrete path written only in the template alphabet still passes, so
/// this check does not replace passing the template itself.
pub(crate) fn check_route(route: &'static str) -> Result<&'static str, ObsError> {
    let ok = route == UNROUTED
        || (route.len() <= MAX_ROUTE_LEN
            && route
                .strip_prefix('/')
                .is_some_and(|rest| rest.split('/').all(is_template_segment)));
    if ok {
        Ok(route)
    } else {
        Err(ObsError::InvalidRoute)
    }
}

/// The part of a rule reference after its prefix. `R` takes one group of
/// two to four uppercase letters (`R-NF-02`). Every other prefix takes
/// none. A final group of one to four digits ends the reference.
fn is_rule_tail(prefix: &str, tail: &str) -> bool {
    let Some(rest) = tail.strip_prefix('-') else {
        return false;
    };
    let (group, number) = match rest.rsplit_once('-') {
        Some((g, n)) => (Some(g), n),
        None => (None, rest),
    };
    let number_ok = (1..=4).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit());
    let group_ok = match group {
        Some(g) => {
            prefix == "R" && (2..=4).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_uppercase())
        }
        None => prefix != "R",
    };
    number_ok && group_ok
}

/// A rule reference such as `I-78`, `R-NF-02`, `SoD-08` or `TH-18`: a known
/// SPEC prefix, then `-` groups that end in a digit group, at most
/// [`MAX_RULE_LEN`] bytes. A name or other word is refused.
pub(crate) fn check_rule(rule: &'static str) -> Result<&'static str, ObsError> {
    let ok = rule.len() <= MAX_RULE_LEN
        && RULE_PREFIXES
            .iter()
            .any(|p| rule.strip_prefix(p).is_some_and(|t| is_rule_tail(p, t)));
    if ok {
        Ok(rule)
    } else {
        Err(ObsError::InvalidRule)
    }
}

/// What `Debug` shows in place of a field that fails its check.
const REFUSED: &str = "<refused>";

/// The route for a `Debug` view: the route when it passes [`check_route`],
/// and `<refused>` otherwise.
pub(crate) fn shown_route(route: &'static str) -> &'static str {
    check_route(route).unwrap_or(REFUSED)
}

/// The rule for a `Debug` view: the rule when it passes [`check_rule`], and
/// `<refused>` otherwise.
pub(crate) fn shown_rule(rule: &'static str) -> &'static str {
    check_rule(rule).unwrap_or(REFUSED)
}

/// Builds one JSON object. Keys are constants of this crate, and string
/// values are checked constants, so no value needs escaping.
struct Line {
    out: String,
}

impl Line {
    fn new(event: &'static str) -> Self {
        let mut out = String::with_capacity(96);
        out.push_str("{\"event\":\"");
        out.push_str(event);
        out.push('"');
        Self { out }
    }

    fn text(mut self, key: &'static str, value: &'static str) -> Self {
        self.out.push_str(",\"");
        self.out.push_str(key);
        self.out.push_str("\":\"");
        self.out.push_str(value);
        self.out.push('"');
        self
    }

    fn number(mut self, key: &'static str, value: u64) -> Self {
        self.out.push_str(",\"");
        self.out.push_str(key);
        self.out.push_str("\":");
        // Writing to a String cannot fail.
        let _ = write!(self.out, "{value}");
        self
    }

    fn finish(mut self) -> String {
        self.out.push_str("}\n");
        self.out
    }
}

/// Encodes a log event as one JSON line, ending with `\n`.
///
/// # Errors
///
/// Returns [`ObsError::InvalidRoute`] or [`ObsError::InvalidRule`] when a
/// `route` or `rule` field fails its alphabet check. The refused text is not
/// repeated in the error.
pub fn encode_log(event: &LogEvent) -> Result<String, ObsError> {
    let line = match *event {
        LogEvent::Started => Line::new("started"),
        LogEvent::ShuttingDown => Line::new("shutting_down"),
        LogEvent::NotImplemented => Line::new("not_implemented"),
        LogEvent::SignalReceived { signal } => {
            Line::new("signal_received").text("signal", signal.as_str())
        }
        LogEvent::Drained { elapsed } => Line::new("drained").number("elapsed_us", micros(elapsed)),
        LogEvent::DrainTimedOut { remaining } => {
            Line::new("drain_timed_out").number("remaining", remaining)
        }
        LogEvent::Request {
            method,
            route,
            status,
            elapsed,
        } => Line::new("request")
            .text("method", method.as_str())
            .text("route", check_route(route)?)
            .number("status", u64::from(status))
            .number("elapsed_us", micros(elapsed)),
        LogEvent::Refused {
            method,
            route,
            rule,
            status,
        } => Line::new("refused")
            .text("method", method.as_str())
            .text("route", check_route(route)?)
            .text("rule", check_rule(rule)?)
            .number("status", u64::from(status)),
    };
    Ok(line.finish())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends the 32 lowercase hex digits of a cell id.
fn push_cell(out: &mut String, cell: &[u8; CELL_ID_LEN]) {
    for b in cell {
        for nibble in [b >> 4, b & 0x0f] {
            let digit = HEX.get(usize::from(nibble)).copied().unwrap_or(b'0');
            out.push(char::from(digit));
        }
    }
}

/// Encodes a metric sample as one exposition line, ending with `\n`:
/// `name{cell="<32 lowercase hex digits>"} value`.
///
/// # Errors
///
/// None today. The `Result` keeps the signature of [`encode_log`], so a
/// later check can refuse without an API change.
pub fn encode_metric(event: &MetricEvent) -> Result<String, ObsError> {
    let mut out = String::with_capacity(96);
    out.push_str(event.name.name());
    out.push_str("{cell=\"");
    push_cell(&mut out, &event.cell);
    out.push_str("\"} ");
    // Writing to a String cannot fail.
    let _ = write!(out, "{}", event.value);
    out.push('\n');
    Ok(out)
}

/// Writes one log event to a process's own log stream.
///
/// # Errors
///
/// Returns the [`encode_log`] refusal, or [`ObsError::Io`] when the stream
/// fails.
pub fn write_log<W: io::Write>(out: &mut W, event: &LogEvent) -> Result<(), ObsError> {
    let line = encode_log(event)?;
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| ObsError::Io(e.kind()))
}

/// Writes one metric sample to the stream that feeds operator aggregation.
///
/// # Errors
///
/// Returns [`ObsError::Io`] when the stream fails.
pub fn write_metric<W: io::Write>(out: &mut W, event: &MetricEvent) -> Result<(), ObsError> {
    let line = encode_metric(event)?;
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| ObsError::Io(e.kind()))
}

/// Writes one log event to standard error, the process's own per-cell log
/// stream. This is the one writer of standard error in a shipped crate. The
/// event is encoded first, so a refused event writes nothing.
///
/// # Errors
///
/// Returns the [`encode_log`] refusal, or [`ObsError::Io`] when the stream
/// fails.
#[allow(
    clippy::disallowed_methods,
    reason = "R-NF-02: fstp-obs is the one writer of standard error"
)]
pub fn log_to_stderr(event: &LogEvent) -> Result<(), ObsError> {
    write_log(&mut io::stderr().lock(), event)
}

/// Writes one metric sample to standard output, the stream that feeds
/// operator aggregation. This is the one writer of standard output in a
/// shipped crate.
///
/// # Errors
///
/// Returns [`ObsError::Io`] when the stream fails.
#[allow(
    clippy::disallowed_methods,
    reason = "R-NF-02: fstp-obs is the one writer of standard output"
)]
pub fn metric_to_stdout(event: &MetricEvent) -> Result<(), ObsError> {
    write_metric(&mut io::stdout().lock(), event)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{Method, Metric, Signal};

    fn every_event() -> Vec<LogEvent> {
        vec![
            LogEvent::Started,
            LogEvent::ShuttingDown,
            LogEvent::NotImplemented,
            LogEvent::SignalReceived {
                signal: Signal::Terminate,
            },
            LogEvent::SignalReceived {
                signal: Signal::Interrupt,
            },
            LogEvent::Drained {
                elapsed: Duration::from_millis(150),
            },
            LogEvent::DrainTimedOut { remaining: 3 },
            LogEvent::Request {
                method: Method::Get,
                route: "/proposals/{id}",
                status: 200,
                elapsed: Duration::MAX,
            },
            LogEvent::Refused {
                method: Method::Post,
                route: UNROUTED,
                rule: "SoD-08",
                status: 403,
            },
        ]
    }

    /// R-NF-02: every event variant encodes as one JSON object on one line.
    #[test]
    fn r_nf_02_every_variant_is_one_json_line() {
        for e in every_event() {
            let line = encode_log(&e).unwrap();
            let body = line.strip_suffix('\n').unwrap();
            assert!(!body.chars().any(char::is_control), "{line:?}");
            let v = fstp_json::parse_str(body).unwrap();
            assert!(matches!(v, fstp_json::Value::Object(_)), "{line:?}");
        }
    }

    /// R-NF-02: a request event logs the route template, not a path.
    #[test]
    fn r_nf_02_request_line_holds_the_template() {
        let line = encode_log(&LogEvent::Request {
            method: Method::Get,
            route: "/proposals/{id}",
            status: 200,
            elapsed: Duration::from_micros(42),
        })
        .unwrap();
        assert_eq!(
            line,
            "{\"event\":\"request\",\"method\":\"GET\",\"route\":\"/proposals/{id}\",\
             \"status\":200,\"elapsed_us\":42}\n"
        );
    }

    /// R-NF-02: route text outside the template alphabet is refused.
    #[test]
    fn r_nf_02_concrete_paths_and_text_are_refused_as_routes() {
        for bad in [
            "",
            "proposals",
            "/a b",
            "/a?q=1",
            "/a#f",
            "/a%20b",
            "/a\"b",
            "/a\\b",
            "/a\nb",
            "/é",
            "/users/alice@example.com",
            "/a:b",
            "/a=b",
            "/a+b",
            "/a&b",
            "/a,b",
            "/a;b",
            "/a!b",
            "/a$b",
            "/a'b",
            "/a~b",
            "/a(b)",
            "/a*",
            "/*/a",
            "/Alice",
            "/users/{Id}",
            "/{a-b}",
            "/{}",
            "/{",
            "/a}",
            "/{1a}",
            "/{a}b",
        ] {
            let e = LogEvent::Request {
                method: Method::Get,
                route: bad,
                status: 200,
                elapsed: Duration::ZERO,
            };
            assert_eq!(encode_log(&e), Err(ObsError::InvalidRoute), "{bad:?}");
        }
        const SEG: &str = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let long: &'static str = concat!(
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/a",
        );
        for ok in [
            UNROUTED,
            "/",
            "/proposals/{id}",
            "/.well-known/x_y-2",
            "/a/{x}/{y_2}",
        ] {
            assert_eq!(check_route(ok), Ok(ok), "{ok:?}");
        }
        assert_eq!(check_route(SEG), Ok(SEG));
        assert!(long.len() > MAX_ROUTE_LEN);
        assert_eq!(check_route(long), Err(ObsError::InvalidRoute));
    }

    /// R-NF-02: rule text outside the rule-reference grammar is refused.
    #[test]
    fn r_nf_02_free_text_is_refused_as_a_rule() {
        for ok in [
            "I-78", "R-NF-02", "SoD-08", "TH-18", "ADR-002", "P-45", "H-03",
        ] {
            assert_eq!(check_rule(ok), Ok(ok));
        }
        for bad in [
            "",
            "-I-78",
            "I-78-",
            "I--78",
            "8-I",
            "I 78",
            "I_78",
            "refused because x",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFG",
            "TH18",
            "Alice",
            "AliceSmith",
            "alice-example-com",
            "I-",
            "I-NF-02",
            "R-02",
            "R-nf-02",
            "R-NF-",
            "X-01",
            "I-12345",
            "I-7a",
        ] {
            assert_eq!(check_rule(bad), Err(ObsError::InvalidRule), "{bad:?}");
        }
    }

    /// R-NF-02: a metric line carries the metric name, the cell id in hex and
    /// the value, and nothing else.
    #[test]
    fn r_nf_02_metric_line_is_name_cell_and_value() {
        let mut cell = [0u8; CELL_ID_LEN];
        cell[0] = 0xab;
        cell[15] = 0x01;
        let line = encode_metric(&MetricEvent::count(Metric::Requests, cell, 7)).unwrap();
        assert_eq!(
            line,
            "fstp_requests_total{cell=\"ab000000000000000000000000000001\"} 7\n"
        );
        let d = MetricEvent::duration(Metric::RequestDuration, cell, Duration::from_millis(2));
        assert_eq!(d.value, 2000);
    }

    /// R-NF-02: every metric has a distinct exposition name.
    #[test]
    fn r_nf_02_metric_names_are_distinct() {
        let mut names: Vec<&str> = Metric::ALL.iter().map(|m| m.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Metric::ALL.len());
    }

    /// R-NF-02: `write_log` writes exactly the encoded line.
    #[test]
    fn r_nf_02_write_log_writes_the_line() {
        let mut out = Vec::new();
        write_log(&mut out, &LogEvent::Started).unwrap();
        assert_eq!(out, b"{\"event\":\"started\"}\n");
        let mut bad = Vec::new();
        let e = LogEvent::Refused {
            method: Method::Get,
            route: "/a",
            rule: "not a rule",
            status: 403,
        };
        assert_eq!(write_log(&mut bad, &e), Err(ObsError::InvalidRule));
        assert!(bad.is_empty());
    }

    /// R-NF-02: the stream writers refuse what `encode_log` refuses, before
    /// anything reaches the stream.
    #[test]
    fn r_nf_02_log_to_stderr_refuses_a_concrete_path() {
        let e = LogEvent::Request {
            method: Method::Get,
            route: "/users/alice@example.com",
            status: 200,
            elapsed: Duration::ZERO,
        };
        assert_eq!(log_to_stderr(&e), Err(ObsError::InvalidRoute));
    }

    /// R-NF-02: a `Debug` view of a log event shows a route or rule only
    /// when it passes its check, so leaked text cannot ride on `{event:?}`.
    #[test]
    fn r_nf_02_debug_view_hides_refused_route_and_rule() {
        let leaked = LogEvent::Refused {
            method: Method::Post,
            route: "/users/alice@example.com",
            rule: "Alice Smith",
            status: 403,
        };
        let shown = format!("{leaked:?}");
        let fine = LogEvent::Refused {
            method: Method::Post,
            route: "/proposals/{id}",
            rule: "SoD-08",
            status: 403,
        };
        let fine_shown = format!("{fine:?}");
        assert!(
            !shown.contains("alice")
                && !shown.contains("Alice")
                && shown.matches("<refused>").count() == 2
                && fine_shown.contains("/proposals/{id}")
                && fine_shown.contains("SoD-08"),
            "{shown} / {fine_shown}"
        );
    }
}
