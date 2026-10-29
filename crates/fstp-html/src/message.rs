//! The catalogue message grammar (R-NF-04).
//!
//! Interim reading, pending Daniel. The design names the catalogue syntax
//! (`message_format_parse`) but not its grammar. The grammar is shared
//! with the TypeScript `i18n.ts` through
//! `crates/fstp-html/testdata/message_format.corpus`:
//!
//! - a message is valid UTF-8 of 1 to 4096 bytes, of plain characters;
//! - `{name}` is a placeholder, where `name` is a lower-case ASCII letter
//!   then up to 31 lower-case letters, digits or `_`;
//! - `{{` and `}}` stand for literal braces;
//! - any other `{` or `}` is an error.

use std::collections::BTreeSet;

use crate::HtmlError;
use crate::subset::is_plain;

/// The longest message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// The longest placeholder name, in bytes.
pub const MAX_PLACEHOLDER_BYTES: usize = 32;

/// One part of a parsed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// Literal text, with `{{` and `}}` decoded.
    Lit(String),
    /// A placeholder, by name.
    Arg(String),
}

/// One parsed catalogue message: literal text and placeholders.
///
/// Its literals hold plain characters only. They are not dynamic: the
/// render trace records the message id, not its literal text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageFormat {
    parts: Vec<Part>,
}

fn syntax(at: usize, rule: &'static str) -> HtmlError {
    HtmlError::MessageSyntax { at, rule }
}

fn is_placeholder_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PLACEHOLDER_BYTES
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Parses one catalogue message with its placeholders. Fuzzed
/// (`message_format_parse`).
pub fn parse_message_format(bytes: &[u8]) -> Result<MessageFormat, HtmlError> {
    if bytes.is_empty() {
        return Err(syntax(0, "the message is empty"));
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(syntax(MAX_MESSAGE_BYTES, "the message is over 4096 bytes"));
    }
    let s = std::str::from_utf8(bytes)
        .map_err(|e| syntax(e.valid_up_to(), "the message is not UTF-8"))?;
    if let Some((at, _)) = s.char_indices().find(|&(_, c)| !is_plain(c)) {
        return Err(syntax(
            at,
            "the message holds a character that is not plain",
        ));
    }
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut it = s.char_indices().peekable();
    while let Some((at, c)) = it.next() {
        let next = it.peek().map(|&(_, n)| n);
        match c {
            '{' if next == Some('{') => {
                it.next();
                lit.push('{');
            }
            '}' if next == Some('}') => {
                it.next();
                lit.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match it.next() {
                        Some((_, '}')) => break,
                        Some((_, n)) => name.push(n),
                        None => return Err(syntax(at, "an unclosed placeholder")),
                    }
                }
                if !is_placeholder_name(&name) {
                    return Err(syntax(at, "a bad placeholder name"));
                }
                if !lit.is_empty() {
                    parts.push(Part::Lit(std::mem::take(&mut lit)));
                }
                parts.push(Part::Arg(name));
            }
            '}' => return Err(syntax(at, "a lone closing brace")),
            _ => lit.push(c),
        }
    }
    if !lit.is_empty() {
        parts.push(Part::Lit(lit));
    }
    Ok(MessageFormat { parts })
}

impl MessageFormat {
    /// The parts, in order.
    pub(crate) fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// The distinct placeholder names, sorted.
    pub fn placeholder_names(&self) -> BTreeSet<&str> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Arg(n) => Some(n.as_str()),
                Part::Lit(_) => None,
            })
            .collect()
    }

    /// Checks that `args` names each placeholder exactly once and nothing
    /// else.
    pub(crate) fn check_args(&self, args: &[(String, String)]) -> Result<(), &'static str> {
        let given: BTreeSet<&str> = args.iter().map(|(n, _)| n.as_str()).collect();
        if given.len() != args.len() {
            return Err("an argument is given twice");
        }
        if given != self.placeholder_names() {
            return Err("the arguments differ from the placeholders");
        }
        Ok(())
    }

    /// The message with each placeholder replaced by its argument, as
    /// given. This is plain text, not HTML.
    pub(crate) fn format(&self, args: &[(String, String)]) -> Result<String, &'static str> {
        self.check_args(args)?;
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(l) => out.push_str(l),
                Part::Arg(n) => out.push_str(arg(args, n)),
            }
        }
        Ok(out)
    }
}

/// The value of argument `name`, or the empty string.
pub(crate) fn arg<'a>(args: &'a [(String, String)], name: &str) -> &'a str {
    args.iter()
        .find(|(k, _)| k == name)
        .map_or("", |(_, v)| v.as_str())
}
