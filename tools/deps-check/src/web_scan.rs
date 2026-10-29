//! The TypeScript source scan of `web/src` (M4 design sections 1.1 and
//! 3.9, ADR-014).
//!
//! A token scanner reads every file below `web/src`. It is a scanner for
//! the rules below, not a TypeScript parser. Finding code: `web-scan`.
//!
//! It fails on:
//!
//! - the HTML sinks `innerHTML`, `outerHTML` and `insertAdjacentHTML`, as
//!   names or as string keys, and `document.write` and `document.writeln`;
//! - `eval`, `new Function` and a call of `Function`;
//! - string timers: `setTimeout`, `setInterval` or `setImmediate` whose
//!   first argument is a string or template literal;
//! - `on*` attribute strings, such as `"onclick"`, and lower-case `on*`
//!   object keys, such as `{ onclick: ... }`;
//! - imports from outside `web/src`: every `import` and `export ... from`
//!   specifier must be a relative path that stays inside `web/src`. A
//!   dynamic `import()` needs a string literal, `require` is refused, and
//!   so is a triple-slash reference directive.
//!
//! Strict additions, interim pending Daniel:
//!
//! - The HTML sinks `setHTMLUnsafe`, `parseHTMLUnsafe` and
//!   `createContextualFragment` are refused too.
//! - A backslash outside a literal is refused, since a Unicode escape in an
//!   identifier would hide a name.
//! - A file the scanner cannot lex to the end is refused.
//! - A JavaScript or TSX file below `web/src` is refused, since the scan
//!   reads `.ts` files only.
//! - String literals are compared by value, after their escapes are
//!   decoded, so `"inner\x48TML"` is the sink `innerHTML`.
//! - The string keys `eval`, `Function`, `write` and `writeln` are refused
//!   as computed keys of any object, such as `window["eval"]`.
//! - `on*` words are refused by prefix, so a handler added to HTML later
//!   is refused too. The plain words in `NOT_HANDLERS` pass, among them
//!   `onboarding`, the name of a feature folder of design section 3.9.
//!
//! A `/` is a division after a token that ends an expression, and starts a
//! regular expression elsewhere. These tokens end one: an identifier other
//! than a keyword such as `return`, a literal, `]`, `++` and `--`. So do a
//! TypeScript non-null `!` on the same line as its operand, and a `)` that
//! closes no `if`, `while`, `for` or `with` head.

use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::repo::{Kind, Walk};
use crate::report::Finding;

/// The scanned directory.
pub(crate) const WEB_SRC: &str = "web/src";
/// Upper bound on the size of one scanned file.
const MAX_TS: u64 = 8 << 20;

/// HTML sinks, refused as names and as string keys.
const SINKS: [&str; 6] = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "setHTMLUnsafe",
    "parseHTMLUnsafe",
    "createContextualFragment",
];
/// Timers that run a string as code.
const TIMERS: [&str; 3] = ["setTimeout", "setInterval", "setImmediate"];
/// Words that start with `on` but name no event handler attribute. The
/// `onboard` words name the design's own onboarding feature (section 3.9).
const NOT_HANDLERS: [&str; 14] = [
    "on",
    "one",
    "once",
    "only",
    "online",
    "onto",
    "onset",
    "ongoing",
    "onward",
    "onwards",
    "onboard",
    "onboards",
    "onboarded",
    "onboarding",
];
/// Names that run code when read as a computed key, refused as string
/// keys such as `window["eval"]`.
const CODE_KEYS: [&str; 4] = ["eval", "Function", "write", "writeln"];
/// Script extensions the scan does not read, so none may sit below `web/src`.
const UNSCANNED_SCRIPTS: [&str; 7] = [".js", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts"];

/// The kind of a TypeScript token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TsKind {
    /// An identifier or keyword.
    Ident,
    /// A numeric literal.
    Num,
    /// One punctuation byte, or `++` or `--`.
    Punct,
    /// The contents of a string literal, or of one template literal chunk.
    Str,
    /// A regular expression literal, with its slashes and flags.
    Regex,
}

/// One token: a slice of the input with its 1-based line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TsTok<'a> {
    /// The text.
    pub(crate) s: &'a str,
    /// The line where it starts.
    pub(crate) line: usize,
    /// What it is.
    pub(crate) kind: TsKind,
    /// For a string, whether it was a template chunk next to a
    /// substitution.
    pub(crate) split: bool,
}

/// The tokens of one file.
pub(crate) struct TsLexed<'a> {
    /// The tokens, in order.
    pub(crate) toks: Vec<TsTok<'a>>,
    /// Whether every comment, literal and template closed, so the end of
    /// the input is at the top level.
    pub(crate) closed: bool,
    /// Lines of triple-slash directives.
    pub(crate) directives: Vec<usize>,
    /// Lines of backslashes outside literals.
    pub(crate) escapes: Vec<usize>,
}

/// Keywords after which a `/` starts a regular expression.
const REGEX_AFTER_WORDS: [&str; 15] = [
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
    "extends",
];

/// Keywords whose parenthesised head is not an expression, so a `/` after
/// its closing `)` starts a regular expression.
const CONTROL_HEADS: [&str; 4] = ["if", "while", "for", "with"];

struct Lexer<'a> {
    text: &'a str,
    i: usize,
    line: usize,
    out: TsLexed<'a>,
    /// The brace depth at which each open template substitution started.
    templates: Vec<usize>,
    depth: usize,
    /// Whether the last token ends an expression, so a `/` after it is a
    /// division.
    prev_ends: bool,
    /// The line where the last token ended.
    prev_end_line: usize,
    /// For each open `(`, whether it opens the head of a control keyword.
    parens: Vec<bool>,
    /// Whether the last `)` closed the head of a control keyword.
    close_ctrl: bool,
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

impl<'a> Lexer<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.text.as_bytes().get(self.i.saturating_add(k)).copied()
    }

    fn bump(&mut self) {
        if self.peek(0) == Some(b'\n') {
            self.line = self.line.saturating_add(1);
        }
        self.i = self.i.saturating_add(1);
    }

    fn push(&mut self, start: usize, end: usize, line: usize, kind: TsKind, split: bool) {
        if let Some(s) = self.text.get(start..end) {
            let ends = match kind {
                TsKind::Ident => !REGEX_AFTER_WORDS.contains(&s),
                TsKind::Num | TsKind::Regex => true,
                TsKind::Str => !split,
                TsKind::Punct => match s {
                    ")" => !self.close_ctrl,
                    // A `/` after `++` or `--` is a division: after a
                    // postfix operator by the grammar, and after a prefix
                    // one because a regular expression is no valid
                    // operand.
                    "]" | "++" | "--" => true,
                    // A TypeScript non-null assertion follows an
                    // expression on the same line. Otherwise `!` is the
                    // prefix logical not.
                    "!" => self.prev_ends && self.prev_end_line == line,
                    _ => false,
                },
            };
            self.prev_ends = ends;
            self.prev_end_line = self.line;
            self.out.toks.push(TsTok {
                s,
                line,
                kind,
                split,
            });
        }
    }

    /// Whether a `/` here starts a regular expression.
    fn regex_allowed(&self) -> bool {
        !self.prev_ends
    }

    /// Whether a `(` here opens the head of a control keyword, such as
    /// `if (` or `for await (`, and not a call of a member of that name.
    fn opens_control(&self) -> bool {
        let toks = &self.out.toks;
        let n = toks.len();
        let at = |back: usize| {
            n.checked_sub(back)
                .and_then(|j| toks.get(j))
                .filter(|t| t.kind == TsKind::Ident || t.kind == TsKind::Punct)
                .map_or("", |t| t.s)
        };
        let head = if at(1) == "await" && at(2) == "for" {
            2
        } else {
            1
        };
        CONTROL_HEADS.contains(&at(head)) && at(head.saturating_add(1)) != "."
    }

    /// A quoted string at its opening quote. A raw newline ends it unclosed.
    fn string(&mut self, quote: u8) {
        let line = self.line;
        self.i = self.i.saturating_add(1);
        let start = self.i;
        while let Some(x) = self.peek(0) {
            if x == b'\\' {
                self.bump();
                if self.peek(0).is_some() {
                    self.bump();
                }
                continue;
            }
            if x == quote {
                let end = self.i;
                self.i = self.i.saturating_add(1);
                self.push(start, end, line, TsKind::Str, false);
                return;
            }
            if x == b'\n' {
                break;
            }
            self.bump();
        }
        self.push(start, self.i, line, TsKind::Str, false);
        self.out.closed = false;
    }

    /// A template chunk from the current position to the closing backtick
    /// or the next substitution.
    fn template_chunk(&mut self) {
        let line = self.line;
        let start = self.i;
        while let Some(x) = self.peek(0) {
            if x == b'\\' {
                self.bump();
                if self.peek(0).is_some() {
                    self.bump();
                }
                continue;
            }
            if x == b'`' {
                let end = self.i;
                self.i = self.i.saturating_add(1);
                self.push(start, end, line, TsKind::Str, false);
                return;
            }
            if x == b'$' && self.peek(1) == Some(b'{') {
                let end = self.i;
                self.i = self.i.saturating_add(2);
                self.push(start, end, line, TsKind::Str, true);
                self.templates.push(self.depth);
                return;
            }
            self.bump();
        }
        self.push(start, self.i, line, TsKind::Str, false);
        self.out.closed = false;
    }

    /// A regular expression at its opening slash.
    fn regex(&mut self) {
        let line = self.line;
        let start = self.i;
        self.i = self.i.saturating_add(1);
        let mut class = false;
        loop {
            match self.peek(0) {
                None | Some(b'\n') => {
                    self.push(start, self.i, line, TsKind::Regex, false);
                    self.out.closed = false;
                    return;
                }
                Some(b'\\') => {
                    self.i = self.i.saturating_add(1);
                    if self.peek(0).is_some_and(|x| x != b'\n') {
                        self.i = self.i.saturating_add(1);
                    }
                }
                Some(b'[') => {
                    class = true;
                    self.i = self.i.saturating_add(1);
                }
                Some(b']') => {
                    class = false;
                    self.i = self.i.saturating_add(1);
                }
                Some(b'/') if !class => {
                    self.i = self.i.saturating_add(1);
                    while self.peek(0).is_some_and(ident_byte) {
                        self.i = self.i.saturating_add(1);
                    }
                    self.push(start, self.i, line, TsKind::Regex, false);
                    return;
                }
                Some(_) => self.i = self.i.saturating_add(1),
            }
        }
    }

    fn run(mut self) -> TsLexed<'a> {
        while let Some(c) = self.peek(0) {
            let next = self.peek(1);
            if c == b'\n' || c == b' ' || c == b'\t' || c == b'\r' || c == 0x0c || c == 0x0b {
                self.bump();
            } else if c == b'/' && next == Some(b'/') {
                let start = self.i;
                while self.peek(0).is_some_and(|x| x != b'\n') {
                    self.i = self.i.saturating_add(1);
                }
                let comment = self.text.get(start..self.i).unwrap_or("");
                if comment.starts_with("///") && comment.contains('<') {
                    self.out.directives.push(self.line);
                }
            } else if c == b'/' && next == Some(b'*') {
                self.i = self.i.saturating_add(2);
                loop {
                    match self.peek(0) {
                        None => {
                            self.out.closed = false;
                            break;
                        }
                        Some(b'*') if self.peek(1) == Some(b'/') => {
                            self.i = self.i.saturating_add(2);
                            break;
                        }
                        Some(_) => self.bump(),
                    }
                }
            } else if c == b'\'' || c == b'"' {
                self.string(c);
            } else if c == b'`' {
                self.i = self.i.saturating_add(1);
                self.template_chunk();
            } else if c == b'/' && self.regex_allowed() {
                self.regex();
            } else if c.is_ascii_digit() || (c == b'.' && next.is_some_and(|n| n.is_ascii_digit()))
            {
                let (start, line) = (self.i, self.line);
                while self
                    .peek(0)
                    .is_some_and(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'.')
                {
                    self.i = self.i.saturating_add(1);
                }
                self.push(start, self.i, line, TsKind::Num, false);
            } else if ident_byte(c) {
                let (start, line) = (self.i, self.line);
                while self.peek(0).is_some_and(ident_byte) {
                    self.i = self.i.saturating_add(1);
                }
                // A non-ASCII byte may end inside a character; extend to a
                // character boundary so the token is a valid slice.
                while self.i < self.text.len() && !self.text.is_char_boundary(self.i) {
                    self.i = self.i.saturating_add(1);
                }
                self.push(start, self.i, line, TsKind::Ident, false);
            } else {
                let (at, line) = (self.i, self.line);
                if c == b'\\' {
                    self.out.escapes.push(line);
                }
                // `++` and `--` are one token each, by the longest match.
                let width = if (c == b'+' || c == b'-') && next == Some(c) {
                    2
                } else {
                    1
                };
                self.i = self.i.saturating_add(width);
                match c {
                    b'(' => {
                        let ctrl = self.opens_control();
                        self.parens.push(ctrl);
                    }
                    b')' => self.close_ctrl = self.parens.pop().unwrap_or(false),
                    b'{' => self.depth = self.depth.saturating_add(1),
                    b'}' => {
                        if self.templates.last() == Some(&self.depth) {
                            self.templates.pop();
                            self.template_chunk();
                            continue;
                        }
                        self.depth = self.depth.saturating_sub(1);
                    }
                    _ => {}
                }
                if c.is_ascii_graphic() {
                    self.push(at, self.i, line, TsKind::Punct, false);
                }
            }
        }
        if !self.templates.is_empty() {
            self.out.closed = false;
        }
        self.out
    }
}

/// Splits TypeScript source into tokens.
pub(crate) fn lex_ts(text: &str) -> TsLexed<'_> {
    Lexer {
        text,
        i: 0,
        line: 1,
        out: TsLexed {
            toks: Vec::new(),
            closed: true,
            directives: Vec::new(),
            escapes: Vec::new(),
        },
        templates: Vec::new(),
        depth: 0,
        prev_ends: false,
        prev_end_line: 1,
        parens: Vec::new(),
        close_ctrl: false,
    }
    .run()
}

/// Whether `s` names an event handler attribute: `on` and lower-case
/// letters, outside the plain words that start with `on`.
fn handler_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.len() > 2
        && lower.starts_with("on")
        && lower.bytes().all(|b| b.is_ascii_lowercase())
        && !NOT_HANDLERS.contains(&lower.as_str())
}

/// The value of a string literal or template chunk, as written between
/// its delimiters, with its escapes decoded. A text without a backslash
/// is returned as it is. A malformed numeric escape yields nothing, and a
/// lone surrogate becomes U+FFFD. tsc refuses a malformed escape, and no
/// banned name holds a surrogate, so neither hides a name.
pub(crate) fn decode_str(raw: &str) -> Cow<'_, str> {
    if !raw.contains('\\') {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut it = raw.chars().peekable();
    // A high surrogate waiting for its low half.
    let mut high: Option<u32> = None;
    while let Some(c) = it.next() {
        let unit = if c == '\\' {
            match it.next() {
                None => break,
                Some('x') => hex_digits(&mut it, 2).map(Unit::Code),
                Some('u') if it.peek() == Some(&'{') => {
                    it.next();
                    let mut v: u32 = 0;
                    let (mut any, mut bad) = (false, false);
                    for d in it.by_ref() {
                        if d == '}' {
                            break;
                        }
                        match d.to_digit(16) {
                            Some(x) if v <= 0x10_ffff => {
                                v = v.saturating_mul(16).saturating_add(x);
                                any = true;
                            }
                            _ => bad = true,
                        }
                    }
                    (any && !bad && v <= 0x10_ffff).then_some(Unit::Code(v))
                }
                Some('u') => hex_digits(&mut it, 4).map(Unit::Code),
                Some(d @ '0'..='7') => {
                    let mut v = d.to_digit(8).unwrap_or(0);
                    for _ in 0..2 {
                        match it.peek().and_then(|n| n.to_digit(8)) {
                            Some(x) if v.saturating_mul(8).saturating_add(x) <= 0o377 => {
                                v = v.saturating_mul(8).saturating_add(x);
                                it.next();
                            }
                            _ => break,
                        }
                    }
                    Some(Unit::Code(v))
                }
                Some('\r') => {
                    if it.peek() == Some(&'\n') {
                        it.next();
                    }
                    Some(Unit::Nothing)
                }
                Some('\n' | '\u{2028}' | '\u{2029}') => Some(Unit::Nothing),
                Some('n') => Some(Unit::Char('\n')),
                Some('t') => Some(Unit::Char('\t')),
                Some('r') => Some(Unit::Char('\r')),
                Some('b') => Some(Unit::Char('\u{8}')),
                Some('f') => Some(Unit::Char('\u{c}')),
                Some('v') => Some(Unit::Char('\u{b}')),
                Some(other) => Some(Unit::Char(other)),
            }
            .unwrap_or(Unit::Nothing)
        } else {
            Unit::Char(c)
        };
        let code = match unit {
            Unit::Nothing => continue,
            Unit::Char(ch) => {
                if high.take().is_some() {
                    out.push('\u{fffd}');
                }
                out.push(ch);
                continue;
            }
            Unit::Code(v) => v,
        };
        match (high.take(), code) {
            (Some(h), 0xdc00..=0xdfff) => {
                let v = 0x1_0000u32
                    .saturating_add((h.saturating_sub(0xd800)) << 10)
                    .saturating_add(code.saturating_sub(0xdc00));
                out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
            }
            (h, 0xd800..=0xdbff) => {
                if h.is_some() {
                    out.push('\u{fffd}');
                }
                high = Some(code);
            }
            (h, _) => {
                if h.is_some() {
                    out.push('\u{fffd}');
                }
                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
            }
        }
    }
    if high.is_some() {
        out.push('\u{fffd}');
    }
    Cow::Owned(out)
}

/// One decoded piece of a string literal.
enum Unit {
    /// A line continuation or a malformed escape that yields nothing.
    Nothing,
    /// One character.
    Char(char),
    /// One code point or UTF-16 code unit, from a numeric escape.
    Code(u32),
}

/// Reads exactly `n` hexadecimal digits.
fn hex_digits(it: &mut std::iter::Peekable<std::str::Chars<'_>>, n: usize) -> Option<u32> {
    let mut v: u32 = 0;
    for _ in 0..n {
        let d = it.peek().and_then(|c| c.to_digit(16))?;
        it.next();
        v = v.saturating_mul(16).saturating_add(d);
    }
    Some(v)
}

/// Whether the import specifier `spec`, in a file of the directory `dir`
/// below `web/src` (relative to it), stays inside `web/src`.
pub(crate) fn specifier_inside(dir: &Path, spec: &str) -> bool {
    if !(spec.starts_with("./") || spec.starts_with("../")) || spec.contains('\\') {
        return false;
    }
    let mut parts: Vec<String> = dir
        .components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return false;
                }
            }
            _ => parts.push(seg.to_owned()),
        }
    }
    !parts.is_empty()
}

/// Every rule violation in one file, as a line and a description. `dir`
/// is the file's directory relative to `web/src`.
pub(crate) fn scan_ts(dir: &Path, text: &str) -> Vec<(usize, String)> {
    let lx = lex_ts(text);
    let mut out = Vec::new();
    if !lx.closed {
        out.push((
            lx.toks.last().map_or(1, |t| t.line),
            "a comment, literal or template that does not close; the scan cannot read the rest"
                .to_owned(),
        ));
    }
    for &line in &lx.directives {
        out.push((line, "a triple-slash directive".to_owned()));
    }
    for &line in &lx.escapes {
        out.push((line, "a backslash outside a literal".to_owned()));
    }
    let toks = &lx.toks;
    let get = |j: usize| toks.get(j);
    let s = |j: usize| get(j).map_or("", |t| t.s);
    let kind = |j: usize| get(j).map(|t| t.kind);
    for (i, t) in toks.iter().enumerate() {
        let next = i.saturating_add(1);
        let prev = i.checked_sub(1).map(s).unwrap_or("");
        match t.kind {
            TsKind::Ident => {
                if SINKS.contains(&t.s) {
                    out.push((t.line, format!("the HTML sink `{}`", t.s)));
                }
                if t.s == "eval" {
                    out.push((t.line, "`eval`".to_owned()));
                }
                if t.s == "Function" && (prev == "new" || s(next) == "(") {
                    out.push((t.line, "`new Function`".to_owned()));
                }
                // `document.write` and `document?.write`. The computed key
                // forms are refused below, for any object.
                let member = if s(next) == "?" && s(next.saturating_add(1)) == "." {
                    next.saturating_add(2)
                } else if s(next) == "." {
                    next.saturating_add(1)
                } else {
                    usize::MAX
                };
                if t.s == "document"
                    && kind(member) == Some(TsKind::Ident)
                    && matches!(s(member), "write" | "writeln")
                {
                    out.push((t.line, "`document.write`".to_owned()));
                }
                if TIMERS.contains(&t.s)
                    && s(next) == "("
                    && kind(next.saturating_add(1)) == Some(TsKind::Str)
                {
                    out.push((t.line, format!("a string timer `{}`", t.s)));
                }
                if handler_name(t.s)
                    && t.s.bytes().all(|b| b.is_ascii_lowercase())
                    && (s(next) == ":" || (s(next) == "?" && s(next.saturating_add(1)) == ":"))
                {
                    out.push((t.line, format!("the event handler key `{}`", t.s)));
                }
                if t.s == "require" && s(next) == "(" {
                    out.push((t.line, "`require`".to_owned()));
                }
                // Import specifiers: `import "x"`, `import("x")` and
                // `... from "x"`.
                let spec_at = if t.s == "import" && kind(next) == Some(TsKind::Str) {
                    Some(next)
                } else if t.s == "import" && s(next) == "(" && prev != "." {
                    if kind(next.saturating_add(1)) == Some(TsKind::Str)
                        && s(next.saturating_add(2)) == ")"
                    {
                        Some(next.saturating_add(1))
                    } else {
                        out.push((
                            t.line,
                            "a dynamic `import()` without a plain string literal".to_owned(),
                        ));
                        None
                    }
                } else if t.s == "from" && kind(next) == Some(TsKind::Str) {
                    Some(next)
                } else {
                    None
                };
                if let Some(j) = spec_at
                    && let Some(spec) = get(j)
                    && (spec.split || !specifier_inside(dir, spec.s))
                {
                    out.push((
                        spec.line,
                        format!("the import `{}` from outside web/src", spec.s),
                    ));
                }
            }
            TsKind::Str => {
                // Compare the value, so an escape hides no name.
                let value = decode_str(t.s);
                let value = value.as_ref();
                if SINKS.contains(&value) {
                    out.push((t.line, format!("the HTML sink `{value}` as a string")));
                }
                if handler_name(value) {
                    out.push((
                        t.line,
                        format!("the event handler attribute string `{value}`"),
                    ));
                }
                if !t.split && prev == "[" && s(next) == "]" && CODE_KEYS.contains(&value) {
                    out.push((t.line, format!("the computed key `{value}`")));
                }
            }
            TsKind::Num | TsKind::Punct | TsKind::Regex => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Scans every file below `web/src` and reports each violation.
pub(crate) fn check(root: &Path, walk: &Walk) -> Vec<Finding> {
    let mut out = Vec::new();
    let base = Path::new(WEB_SRC);
    for f in walk.files.iter().filter(|f| f.rel.starts_with(base)) {
        let rel = f.rel.display().to_string();
        if f.kind != Kind::File {
            out.push(Finding::error(
                "web-scan",
                format!(
                    "{rel} is not a regular file; the web scan reads regular files only (ADR-014)"
                ),
            ));
            continue;
        }
        let name = f.rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if UNSCANNED_SCRIPTS.iter().any(|e| name.ends_with(e)) {
            out.push(Finding::error(
                "web-scan",
                format!("{rel} is a script the web scan does not read; the application is TypeScript in .ts files only (ADR-014)"),
            ));
            continue;
        }
        if !name.ends_with(".ts") {
            continue;
        }
        let path = root.join(&f.rel);
        match fs::metadata(&path) {
            Ok(m) if m.len() > MAX_TS => {
                out.push(Finding::error(
                    "scan-limit",
                    format!("{rel} is larger than {MAX_TS} bytes"),
                ));
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                out.push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
                continue;
            }
        }
        let text = match fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                out.push(Finding::error("scan-io", format!("cannot read {rel}: {e}")));
                continue;
            }
        };
        let dir: PathBuf = f
            .rel
            .strip_prefix(base)
            .ok()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        for (line, what) in scan_ts(&dir, &text) {
            out.push(Finding::error(
                "web-scan",
                format!("{rel}:{line} has {what} (M4 design section 3.9, ADR-014)"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<(usize, String)> {
        scan_ts(Path::new("core"), text)
    }

    /// ADR-014, design section 3.9: the web scan rejects `innerHTML` and
    /// the other banned sinks, whatever form the name takes.
    #[test]
    fn adr014_web_scan_rejects_inner_html() {
        for text in [
            "el.innerHTML = s;\n",
            "el[\"innerHTML\"] = s;\n",
            "el['outerHTML'] = s;\n",
            "el.insertAdjacentHTML(\"beforeend\", s);\n",
            "document.write(s);\n",
            "document.writeln(s);\n",
            "document[\"write\"](s);\n",
            "eval(s);\n",
            "const f = new Function(\"return 1\");\n",
            "const f = Function(\"return 1\");\n",
            "setTimeout(\"alert(1)\", 10);\n",
            "setInterval(`tick()`, 10);\n",
            "el.setAttribute(\"onclick\", s);\n",
            "h(\"a\", { onclick: f });\n",
            "interface A { onload?: () => void }\n",
            "el.setHTMLUnsafe(s);\n",
            "el.\\u0069nnerHTML = s;\n",
            "const s = \"open;\nel.innerHTML = x;\n",
            "const t = `${ a }`; el.innerHTML = s;\n",
            "const b = a++ / 2; el.innerHTML = s; const c = b / 1;\n",
            "const b = a-- / 2; el.innerHTML = s; const c = b / 1;\n",
            "const h = n! / 2; el.innerHTML = s; const q = h / 1;\n",
            "const h = xs[0]! / 2; el.outerHTML = s; const q = h / 1;\n",
            "const h = f(x)! / 2; el.innerHTML = s; const q = h / 1;\n",
            "el[\"inner\\x48TML\"] = s;\n",
            "el['\\u0069nnerHTML'] = s;\n",
            "el[`\\u{69}nnerHTML`] = s;\n",
            "el.setAttribute(\"on\\x63lick\", s);\n",
            "window[\"eval\"](s);\n",
            "globalThis['Function'](\"return 1\");\n",
            "document?.write(s);\n",
            "document?.writeln(s);\n",
            "document?.[\"write\"](s);\n",
            "doc[\"writeln\"](s);\n",
            "if (ok) /x/.test(s); el.innerHTML = s;\n",
        ] {
            assert!(!found(text).is_empty(), "not refused: {text:?}");
        }
    }

    /// ADR-014, design section 3.9: imports stay inside web/src.
    #[test]
    fn adr014_web_scan_rejects_imports_from_outside_web_src() {
        for text in [
            "import { x } from \"typescript\";\n",
            "import \"node:fs\";\n",
            "export * from \"../../e2e/x.js\";\n",
            "import { y } from '../../../etc/passwd';\n",
            "const m = await import(\"https://example.org/m.js\");\n",
            "const m = await import(name);\n",
            "const fs = require(\"fs\");\n",
            "/// <reference path=\"../../x.d.ts\" />\n",
            "import { z } from `./${a}.js`;\n",
        ] {
            assert!(!found(text).is_empty(), "not refused: {text:?}");
        }
    }

    /// ADR-014: the application's own patterns pass.
    #[test]
    fn adr014_web_scan_accepts_safe_code() {
        let text = concat!(
            "import { h } from \"./dom.js\";\n",
            "import type { Operation } from \"../gen/api.js\";\n",
            "export { money } from \"./money.js\";\n",
            "const m = await import(\"./lazy.js\");\n",
            "// innerHTML in a comment is fine\n",
            "/* so is eval in a block comment */\n",
            "el.textContent = \"onclick and innerHTML inside text\";\n",
            "const re = /\"innerHTML/g; const half = a / b / c;\n",
            "el.addEventListener(\"click\", f, { once: true });\n",
            "setTimeout(() => tick(), 10);\n",
            "const label = \"online\";\n",
            "const t = `count ${n + 1} done`;\n",
            "class A { constructor() {} override toString(): string { return `a${1}`; } }\n",
            "const x = import.meta.url;\n",
            "let k = i++ / 2; let m = j-- / 2;\n",
            "const r = xs[0]! / 2;\n",
            "const q = n! / d!;\n",
            "if (ok) /'/.test(s);\n",
            "for (const x of xs) /'/.test(x);\n",
            "while (go()) /'/.test(s);\n",
            "const v = a\n!/'/.test(s);\n",
            "const w = !/'/.test(s) && f(s) / 2;\n",
            "const ok2 = x.if(a) / 2;\n",
            "export const SEGMENTS = { onboarding: \"onboarding\" } as const;\n",
            "const step = \"onboarded\"; el.dataset[\"state\"] = step;\n",
            "const tab = \"\\u0041\\x42\";\n",
        );
        let got = found(text);
        assert!(got.is_empty(), "{got:?}");
    }

    /// ADR-014: string values are compared after their escapes are
    /// decoded, as JavaScript reads them.
    #[test]
    fn adr014_decode_str_reads_escapes() {
        for (raw, want) in [
            ("innerHTML", "innerHTML"),
            ("inner\\x48TML", "innerHTML"),
            ("\\u0069nnerHTML", "innerHTML"),
            ("\\u{69}nner\\u{0048}TML", "innerHTML"),
            ("on\\143lick", "onclick"),
            ("a\\\nb", "ab"),
            ("\\n\\t\\q", "\n\tq"),
            ("\\uD83D\\uDE00", "\u{1f600}"),
            ("\\uD83Dx", "\u{fffd}x"),
            ("\\x4", ""),
            ("\\u{110000}", ""),
        ] {
            assert_eq!(decode_str(raw), want, "{raw:?}");
        }
    }

    /// ADR-014: the specifier check resolves `..` lexically.
    #[test]
    fn adr014_specifiers_resolve_inside_web_src() {
        assert!(specifier_inside(Path::new("core"), "./dom.js"));
        assert!(specifier_inside(Path::new("core"), "../gen/api.js"));
        assert!(!specifier_inside(Path::new("core"), "../../package.json"));
        assert!(!specifier_inside(Path::new(""), "../x.js"));
        assert!(!specifier_inside(Path::new("core"), "/abs.js"));
        assert!(!specifier_inside(Path::new("core"), "dom.js"));
    }

    /// ADR-014: the lexer properties the `ts_token_scan` fuzz target checks
    /// hold on the review inputs.
    #[test]
    fn adr014_ts_token_scan_fuzz_properties_hold_on_review_inputs() {
        for data in [
            &b"a / b"[..],
            b"x = /[/]/; y",
            b"`${`${a}`}`",
            b"}`",
            b"\"\\",
            b"/*",
            b"\xff\xfe\xc3",
            b"return /a/",
            b"\xe2\x82",
        ] {
            assert_eq!(crate::fuzzing::ts_token_scan(data), Ok(()), "{data:?}");
        }
    }
}
