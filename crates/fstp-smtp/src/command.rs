//! The SMTP commands the client sends, in one canonical form.
//!
//! The client encodes each command and checks that [`parse_command`] reads
//! it back, so an address can never inject a second command. The test sink
//! accepts only this canonical form: upper-case verbs, `MAIL FROM:<path>`
//! with single-space parameters and `RCPT TO:<path>`. An accepted line
//! re-encodes to its exact bytes.

use std::fmt;

use crate::lines::{LineError, content, split_line};

/// Most octets in a command line with its CRLF (RFC 5321 section 4.5.3.1.4).
pub const MAX_COMMAND_LINE: usize = 512;

/// Most octets in a path between `<` and `>` (RFC 5321 section 4.5.3.1.3).
pub const MAX_PATH: usize = 254;

/// One command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `EHLO domain`.
    Ehlo(String),
    /// `AUTH PLAIN [initial-response]`.
    AuthPlain(Option<String>),
    /// `MAIL FROM:<path> [param ...]`. The path is empty for a null sender.
    MailFrom {
        /// The reverse path, without the angle brackets.
        path: String,
        /// ESMTP parameters such as `BODY=8BITMIME`.
        params: Vec<String>,
    },
    /// `RCPT TO:<path>`.
    RcptTo(String),
    /// `DATA`.
    Data,
    /// `RSET`.
    Rset,
    /// `NOOP`.
    Noop,
    /// `QUIT`.
    Quit,
}

/// Why a command line was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The line framing failed.
    Line(LineError),
    /// The input is not exactly one complete line.
    NotOneLine,
    /// The verb is not one this sink knows, in canonical form.
    UnknownVerb,
    /// The argument is malformed.
    BadArgument,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Line(e) => write!(f, "command line: {e}"),
            CommandError::NotOneLine => f.write_str("not exactly one command line"),
            CommandError::UnknownVerb => f.write_str("unknown command"),
            CommandError::BadArgument => f.write_str("bad command argument"),
        }
    }
}

impl std::error::Error for CommandError {}

fn token_byte(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b'<' && b != b'>'
}

fn valid_domain(d: &str) -> bool {
    let b = d.as_bytes();
    if b.is_empty() || b.len() > 255 {
        return false;
    }
    if let Some(inner) = d.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return !inner.is_empty()
            && inner
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b'.' || c == b':');
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
}

/// A mailbox `local@domain` as the client and the sink accept it.
pub fn valid_mailbox(m: &str) -> bool {
    let b = m.as_bytes();
    if b.is_empty() || b.len() > MAX_PATH || !b.iter().all(|&c| token_byte(c)) {
        return false;
    }
    let mut parts = m.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(l), Some(d), None) if !l.is_empty() && valid_domain(d)
    )
}

fn valid_base64(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
}

fn parse_path(rest: &str) -> Result<(&str, &str), CommandError> {
    let inner = rest.strip_prefix('<').ok_or(CommandError::BadArgument)?;
    let end = inner.find('>').ok_or(CommandError::BadArgument)?;
    let path = inner.get(..end).ok_or(CommandError::BadArgument)?;
    let after = inner
        .get(end.saturating_add(1)..)
        .ok_or(CommandError::BadArgument)?;
    Ok((path, after))
}

/// Parses one command line, with its CRLF.
///
/// # Errors
///
/// [`CommandError`] unless `line` is exactly one canonical command line.
pub fn parse_command(line: &[u8]) -> Result<Command, CommandError> {
    match split_line(line, MAX_COMMAND_LINE).map_err(CommandError::Line)? {
        Some(n) if n == line.len() => {}
        _ => return Err(CommandError::NotOneLine),
    }
    let body = content(line);
    if !body.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(CommandError::BadArgument);
    }
    let text = std::str::from_utf8(body).map_err(|_| CommandError::BadArgument)?;
    match text {
        "DATA" => return Ok(Command::Data),
        "RSET" => return Ok(Command::Rset),
        "NOOP" => return Ok(Command::Noop),
        "QUIT" => return Ok(Command::Quit),
        "AUTH PLAIN" => return Ok(Command::AuthPlain(None)),
        _ => {}
    }
    if let Some(d) = text.strip_prefix("EHLO ") {
        return if valid_domain(d) {
            Ok(Command::Ehlo(d.to_owned()))
        } else {
            Err(CommandError::BadArgument)
        };
    }
    if let Some(r) = text.strip_prefix("AUTH PLAIN ") {
        return if valid_base64(r) {
            Ok(Command::AuthPlain(Some(r.to_owned())))
        } else {
            Err(CommandError::BadArgument)
        };
    }
    if let Some(r) = text.strip_prefix("MAIL FROM:") {
        let (path, after) = parse_path(r)?;
        if !path.is_empty() && !valid_mailbox(path) {
            return Err(CommandError::BadArgument);
        }
        let mut params = Vec::new();
        if !after.is_empty() {
            let list = after.strip_prefix(' ').ok_or(CommandError::BadArgument)?;
            for p in list.split(' ') {
                if p.is_empty() || !p.bytes().all(token_byte) {
                    return Err(CommandError::BadArgument);
                }
                params.push(p.to_owned());
            }
        }
        return Ok(Command::MailFrom {
            path: path.to_owned(),
            params,
        });
    }
    if let Some(r) = text.strip_prefix("RCPT TO:") {
        let (path, after) = parse_path(r)?;
        return if valid_mailbox(path) && after.is_empty() {
            Ok(Command::RcptTo(path.to_owned()))
        } else {
            Err(CommandError::BadArgument)
        };
    }
    Err(CommandError::UnknownVerb)
}

impl Command {
    /// The wire form with CRLF.
    pub fn encode(&self) -> Vec<u8> {
        let mut s = match self {
            Command::Ehlo(d) => format!("EHLO {d}"),
            Command::AuthPlain(None) => "AUTH PLAIN".to_owned(),
            Command::AuthPlain(Some(r)) => format!("AUTH PLAIN {r}"),
            Command::MailFrom { path, params } => {
                let mut s = format!("MAIL FROM:<{path}>");
                for p in params {
                    s.push(' ');
                    s.push_str(p);
                }
                s
            }
            Command::RcptTo(p) => format!("RCPT TO:<{p}>"),
            Command::Data => "DATA".to_owned(),
            Command::Rset => "RSET".to_owned(),
            Command::Noop => "NOOP".to_owned(),
            Command::Quit => "QUIT".to_owned(),
        };
        s.push_str("\r\n");
        s.into_bytes()
    }

    /// The wire form, only if it parses back to this command.
    ///
    /// # Errors
    ///
    /// [`CommandError`] when a field would make the line malformed.
    pub fn checked_encode(&self) -> Result<Vec<u8>, CommandError> {
        let bytes = self.encode();
        if parse_command(&bytes)? == *self {
            Ok(bytes)
        } else {
            Err(CommandError::BadArgument)
        }
    }
}
