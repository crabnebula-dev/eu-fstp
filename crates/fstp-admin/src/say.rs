//! The one module that writes human output (ADR-028 "Human output",
//! R-NF-02, interim, pending Daniel).
//!
//! R-NF-02 bans free text on the standard streams of shipped crates.
//! `fstp-admin` is an interactive operator tool, so ADR-028 proposes an
//! exception for this module alone. A line is built only from [`Part`]s:
//! fixed text known at compile time, paths, numbers, member names of the
//! configuration file (already cut to printable ASCII), the host's own
//! domain and ids. No part can hold an email address, a passphrase, a
//! token, proposal content or an identity attribute.

use std::io::Write as _;
use std::path::Path;

/// One piece of a line.
#[derive(Clone, Copy, Debug)]
pub enum Part<'a> {
    /// Fixed text.
    T(&'static str),
    /// A path.
    P(&'a Path),
    /// A number.
    N(u64),
    /// A configuration member name, a step name, a service name, a domain
    /// or an id. The caller passes only names the host chose itself.
    Name(&'a str),
}

fn render(parts: &[Part<'_>]) -> String {
    let mut s = String::new();
    for p in parts {
        match p {
            Part::T(t) => s.push_str(t),
            Part::P(p) => s.push_str(&p.display().to_string()),
            Part::N(n) => s.push_str(&n.to_string()),
            Part::Name(n) => s.extend(n.chars().filter(|c| c.is_ascii_graphic()).take(80)),
        }
    }
    s.push('\n');
    s
}

/// Writes one line to standard output.
#[allow(
    clippy::disallowed_methods,
    reason = "ADR-028 Human output, interim, pending Daniel"
)]
pub fn out(parts: &[Part<'_>]) {
    let mut o = std::io::stdout();
    let _ = o
        .write_all(render(parts).as_bytes())
        .and_then(|()| o.flush());
}

/// Writes one line to standard error.
#[allow(
    clippy::disallowed_methods,
    reason = "ADR-028 Human output, interim, pending Daniel"
)]
pub fn err(parts: &[Part<'_>]) {
    let mut o = std::io::stderr();
    let _ = o
        .write_all(render(parts).as_bytes())
        .and_then(|()| o.flush());
}

/// Asks a question on standard output and reads one line of standard
/// input. `None` when standard input is closed.
#[allow(
    clippy::disallowed_methods,
    reason = "ADR-028 Human output, interim, pending Daniel"
)]
pub fn ask(question: &'static str) -> Option<String> {
    let mut o = std::io::stdout();
    let _ = o.write_all(question.as_bytes()).and_then(|()| o.flush());
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-NF-02, ADR-028: a name part keeps printable ASCII only.
    #[test]
    fn r_nf_02_name_parts_keep_printable_ascii_only() {
        let line = render(&[Part::T("x "), Part::Name("a\nb\u{1b}[31mc"), Part::N(7)]);
        assert_eq!(line, "x ab[31mc7\n");
    }
}
