//! A PostgreSQL token scanner, just detailed enough to find statement
//! boundaries.
//!
//! The scanner follows the lexical rules of the PostgreSQL 16 server
//! scanner (`scan.l`) for everything that can hide a semicolon:
//!
//! - standard strings `'...'` with `''` escapes, including the `B`, `X`,
//!   `N` and `U&` prefixed forms, which share the quoting rule;
//! - escape strings `E'...'` with backslash escapes, `''` escapes, and
//!   continuation over whitespace that contains a newline;
//! - quoted identifiers `"..."` with `""` escapes, including `U&"..."`;
//! - dollar-quoted strings `$tag$...$tag$` with an optional tag;
//! - line comments `--` and nested block comments `/* ... */`.
//!
//! Identifiers, parameters and numbers are scanned as the server scans
//! them, so a `$` or an `e` that belongs to one of them never opens a
//! dollar quote or an escape string:
//!
//! - an identifier takes letters, digits, `_`, `$` and bytes from 0x80;
//! - a parameter is `$` and digits, as in `$1`;
//! - a number is a decimal integer with `_` separators, an optional
//!   fraction and an optional exponent with an optional sign.
//!
//! The server reads an identifier directly after a number or parameter as
//! trailing junk and rejects it. Its longest-match rule decides how far
//! that junk reaches, for example over the `$a$` in `1e5$a$` but not in
//! `1e+5$a$`. The scanner follows the same rule. Junk never reaches over
//! a `.`, so `$1.x.$q$` ends in a dollar quote.
//!
//! Whitespace is space, tab, newline, carriage return and form feed. A
//! vertical tab is not whitespace in PostgreSQL 16, so it is a token of
//! its own, which the server rejects. The scanner assumes
//! `standard_conforming_strings = on`, the server default since
//! PostgreSQL 9.1.
//!
//! Every token boundary falls on an ASCII byte or after a complete run of
//! non-ASCII bytes, so slicing a `str` at token boundaries never splits a
//! UTF-8 character.

/// The kinds of token the splitter distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenKind {
    /// An identifier or keyword.
    Word,
    /// A numeric literal, possibly with trailing junk the server rejects.
    Number,
    /// A parameter such as `$1`, possibly with trailing junk the server
    /// rejects.
    Param,
    /// A double-quoted identifier.
    QuotedIdent,
    /// A single-quoted string of any flavour.
    String,
    /// A dollar-quoted string.
    DollarString,
    /// `;`.
    Semicolon,
    /// `(`.
    OpenParen,
    /// `)`.
    CloseParen,
    /// Any other single byte: operators and punctuation.
    Other,
}

/// One token: its kind and byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// Why scanning failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LexErrorKind {
    UnterminatedString,
    UnterminatedEscapeString,
    UnterminatedQuotedIdentifier,
    UnterminatedDollarQuote,
    UnterminatedBlockComment,
    CommentTooDeep,
}

/// A scanning failure at a byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LexError {
    pub(crate) kind: LexErrorKind,
    pub(crate) offset: usize,
}

/// Whitespace as the PostgreSQL 16 scanner defines it. A vertical tab
/// (0x0b) is not whitespace there.
pub(crate) fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

fn is_horiz_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | 0x0c)
}

fn is_newline(b: u8) -> bool {
    matches!(b, b'\n' | b'\r')
}

/// First byte of an identifier. Bytes from 0x80 up cover every non-ASCII
/// UTF-8 sequence.
fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_ident_cont(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit() || b == b'$'
}

fn is_dolq_cont(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

/// A cursor over SQL text that yields tokens and skips whitespace and
/// comments. Copying it gives an independent cursor, used for lookahead.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    max_comment_depth: usize,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(src: &'a [u8], max_comment_depth: usize) -> Self {
        Self {
            src,
            pos: 0,
            max_comment_depth,
        }
    }

    fn at(&self, i: usize) -> Option<u8> {
        self.src.get(i).copied()
    }

    /// The next token, or `None` at the end of the input.
    pub(crate) fn next_token(&mut self) -> Result<Option<Token>, LexError> {
        loop {
            match (self.at(self.pos), self.at(self.pos.saturating_add(1))) {
                (None, _) => return Ok(None),
                (Some(b), _) if is_space(b) => self.pos = self.pos.saturating_add(1),
                (Some(b'-'), Some(b'-')) => self.pos = self.line_comment_end(self.pos),
                (Some(b'/'), Some(b'*')) => self.pos = self.block_comment_end(self.pos)?,
                (Some(_), _) => break,
            }
        }
        let start = self.pos;
        let Some(c) = self.at(start) else {
            return Ok(None);
        };
        let next = start.saturating_add(1);
        let (kind, end) = match c {
            b';' => (TokenKind::Semicolon, next),
            b'(' => (TokenKind::OpenParen, next),
            b')' => (TokenKind::CloseParen, next),
            b'\'' => (TokenKind::String, self.standard_string_end(start)?),
            b'"' => (TokenKind::QuotedIdent, self.quoted_ident_end(start)?),
            b'$' => match self.dollar_delimiter_end(start) {
                Some(open_end) => (
                    TokenKind::DollarString,
                    self.dollar_body_end(start, open_end)?,
                ),
                None if self.at(next).is_some_and(|b| b.is_ascii_digit()) => {
                    (TokenKind::Param, self.param_end(next))
                }
                // A `$` the server rejects.
                None => (TokenKind::Other, next),
            },
            b if b.is_ascii_digit() => (TokenKind::Number, self.number_end(start)),
            b if is_ident_start(b) => {
                let end = self.ident_end(start);
                if end == next && (c == b'e' || c == b'E') && self.at(end) == Some(b'\'') {
                    (TokenKind::String, self.escape_string_end(start, end)?)
                } else {
                    (TokenKind::Word, end)
                }
            }
            _ => (TokenKind::Other, next),
        };
        self.pos = end;
        Ok(Some(Token { kind, start, end }))
    }

    /// The end of a `--` comment: the newline (not consumed) or the input end.
    fn line_comment_end(&self, start: usize) -> usize {
        let mut i = start.saturating_add(2);
        while let Some(b) = self.at(i) {
            if is_newline(b) {
                break;
            }
            i = i.saturating_add(1);
        }
        i
    }

    /// The end of a nested block comment that starts at `start`.
    fn block_comment_end(&self, start: usize) -> Result<usize, LexError> {
        let mut depth = 1usize;
        let mut i = start.saturating_add(2);
        loop {
            match (self.at(i), self.at(i.saturating_add(1))) {
                (None, _) => {
                    return Err(LexError {
                        kind: LexErrorKind::UnterminatedBlockComment,
                        offset: start,
                    });
                }
                (Some(b'/'), Some(b'*')) => {
                    depth = depth.saturating_add(1);
                    if depth > self.max_comment_depth {
                        return Err(LexError {
                            kind: LexErrorKind::CommentTooDeep,
                            offset: i,
                        });
                    }
                    i = i.saturating_add(2);
                }
                (Some(b'*'), Some(b'/')) => {
                    depth = depth.saturating_sub(1);
                    i = i.saturating_add(2);
                    if depth == 0 {
                        return Ok(i);
                    }
                }
                (Some(_), _) => i = i.saturating_add(1),
            }
        }
    }

    /// The end of a standard string whose opening quote is at `start`.
    ///
    /// Continuation over a newline (`'a'\n'b'`) is not followed: both
    /// pieces use the same quoting rule, so the extent is the same either
    /// way.
    fn standard_string_end(&self, start: usize) -> Result<usize, LexError> {
        let mut i = start.saturating_add(1);
        loop {
            match self.at(i) {
                None => {
                    return Err(LexError {
                        kind: LexErrorKind::UnterminatedString,
                        offset: start,
                    });
                }
                Some(b'\'') if self.at(i.saturating_add(1)) == Some(b'\'') => {
                    i = i.saturating_add(2);
                }
                Some(b'\'') => return Ok(i.saturating_add(1)),
                Some(_) => i = i.saturating_add(1),
            }
        }
    }

    /// The end of an escape string. `prefix` is the position of the `E`,
    /// `quote` the position of the opening quote.
    fn escape_string_end(&self, prefix: usize, quote: usize) -> Result<usize, LexError> {
        let unterminated = LexError {
            kind: LexErrorKind::UnterminatedEscapeString,
            offset: prefix,
        };
        let mut i = quote.saturating_add(1);
        loop {
            match self.at(i) {
                None => return Err(unterminated),
                Some(b'\\') => {
                    if self.at(i.saturating_add(1)).is_none() {
                        return Err(unterminated);
                    }
                    i = i.saturating_add(2);
                }
                Some(b'\'') if self.at(i.saturating_add(1)) == Some(b'\'') => {
                    i = i.saturating_add(2);
                }
                Some(b'\'') => {
                    let end = i.saturating_add(1);
                    // The server continues an escape string, still with
                    // backslash escapes, after whitespace with a newline.
                    match self.continuation_quote(end) {
                        Some(q) => i = q.saturating_add(1),
                        None => return Ok(end),
                    }
                }
                Some(_) => i = i.saturating_add(1),
            }
        }
    }

    /// The position of the quote that continues a string ending at `end`,
    /// following the server's `quotecontinue` rule: horizontal whitespace
    /// or `--` comments, a newline, then whitespace or `--` comments each
    /// followed by a newline, then a quote.
    fn continuation_quote(&self, end: usize) -> Option<usize> {
        let mut i = end;
        loop {
            match (self.at(i), self.at(i.saturating_add(1))) {
                (Some(b), _) if is_horiz_space(b) => i = i.saturating_add(1),
                (Some(b'-'), Some(b'-')) => i = self.line_comment_end(i),
                _ => break,
            }
        }
        if !self.at(i).is_some_and(is_newline) {
            return None;
        }
        i = i.saturating_add(1);
        loop {
            match (self.at(i), self.at(i.saturating_add(1))) {
                (Some(b), _) if is_space(b) => i = i.saturating_add(1),
                (Some(b'-'), Some(b'-')) => {
                    let j = self.line_comment_end(i);
                    if !self.at(j).is_some_and(is_newline) {
                        return None;
                    }
                    i = j.saturating_add(1);
                }
                _ => break,
            }
        }
        (self.at(i) == Some(b'\'')).then_some(i)
    }

    /// The end of a quoted identifier whose opening quote is at `start`.
    fn quoted_ident_end(&self, start: usize) -> Result<usize, LexError> {
        let mut i = start.saturating_add(1);
        loop {
            match self.at(i) {
                None => {
                    return Err(LexError {
                        kind: LexErrorKind::UnterminatedQuotedIdentifier,
                        offset: start,
                    });
                }
                Some(b'"') if self.at(i.saturating_add(1)) == Some(b'"') => {
                    i = i.saturating_add(2);
                }
                Some(b'"') => return Ok(i.saturating_add(1)),
                Some(_) => i = i.saturating_add(1),
            }
        }
    }

    /// When a dollar-quote delimiter `$tag$` starts at `start`, the
    /// position just after it.
    fn dollar_delimiter_end(&self, start: usize) -> Option<usize> {
        let mut i = start.saturating_add(1);
        match self.at(i) {
            Some(b'$') => return Some(i.saturating_add(1)),
            Some(b) if is_ident_start(b) => {}
            _ => return None,
        }
        while self.at(i).is_some_and(is_dolq_cont) {
            i = i.saturating_add(1);
        }
        (self.at(i) == Some(b'$')).then(|| i.saturating_add(1))
    }

    /// The end of a dollar-quoted string: just after the first occurrence
    /// of the opening delimiter after `open_end`.
    ///
    /// Every candidate starts at a `$`, and the delimiter has no `$`
    /// between its ends, so the comparisons do not overlap and the search
    /// is linear.
    fn dollar_body_end(&self, start: usize, open_end: usize) -> Result<usize, LexError> {
        let unterminated = LexError {
            kind: LexErrorKind::UnterminatedDollarQuote,
            offset: start,
        };
        let delimiter = self.src.get(start..open_end).ok_or(unterminated)?;
        let mut i = open_end;
        while let Some(rest) = self.src.get(i..) {
            let Some(found) = rest.iter().position(|&b| b == b'$') else {
                break;
            };
            let at = i.saturating_add(found);
            let end = at.saturating_add(delimiter.len());
            if self.src.get(at..end) == Some(delimiter) {
                return Ok(end);
            }
            i = at.saturating_add(1);
        }
        Err(unterminated)
    }

    /// The end of an identifier or keyword.
    fn ident_end(&self, start: usize) -> usize {
        let mut i = start.saturating_add(1);
        while self.at(i).is_some_and(is_ident_cont) {
            i = i.saturating_add(1);
        }
        i
    }

    /// The end of a parameter whose digits start at `digits`. As in the
    /// server's `param_junk` rule, an identifier directly after the digits
    /// joins the token.
    fn param_end(&self, digits: usize) -> usize {
        let mut i = digits;
        while self.at(i).is_some_and(|b| b.is_ascii_digit()) {
            i = i.saturating_add(1);
        }
        if self.at(i).is_some_and(is_ident_start) {
            self.ident_end(i)
        } else {
            i
        }
    }

    /// The end of a number that starts with a digit at `start`.
    ///
    /// The server matches the longest of a decimal integer, a numeric with
    /// a fraction, a real with an exponent, and any of these followed by an
    /// identifier as trailing junk. Junk can start at a `_` inside a
    /// digit group, so after a group with a separator even a `$` joins it.
    /// An exponent without a sign starts an identifier, so it is junk or a
    /// real of the same extent. `1e+` without digits is junk too.
    fn number_end(&self, start: usize) -> usize {
        let (mut i, mut separated) = self.decinteger_end(start);
        let after = i.saturating_add(1);
        if self.at(i) == Some(b'.') && self.at(after) != Some(b'.') {
            (i, separated) = self.decinteger_end(after);
        }
        if matches!(self.at(i), Some(b'e' | b'E')) {
            let sign = i.saturating_add(1);
            if !matches!(self.at(sign), Some(b'+' | b'-')) {
                return self.ident_end(i);
            }
            let digits = sign.saturating_add(1);
            if !self.at(digits).is_some_and(|b| b.is_ascii_digit()) {
                return digits;
            }
            (i, separated) = self.decinteger_end(digits);
        }
        if self.at(i).is_some_and(is_ident_start) || (separated && self.at(i) == Some(b'$')) {
            self.ident_end(i)
        } else {
            i
        }
    }

    /// The end of the longest decimal integer at `start`: digits with
    /// single `_` separators between them. The flag is true when it holds
    /// a separator. Without a digit at `start` the end is `start`.
    fn decinteger_end(&self, start: usize) -> (usize, bool) {
        if !self.at(start).is_some_and(|b| b.is_ascii_digit()) {
            return (start, false);
        }
        let mut i = start.saturating_add(1);
        let mut separated = false;
        loop {
            match (self.at(i), self.at(i.saturating_add(1))) {
                (Some(b), _) if b.is_ascii_digit() => i = i.saturating_add(1),
                (Some(b'_'), Some(b)) if b.is_ascii_digit() => {
                    separated = true;
                    i = i.saturating_add(2);
                }
                _ => return (i, separated),
            }
        }
    }
}

/// True when `word` equals the ASCII keyword `keyword`, ignoring case.
pub(crate) fn is_keyword(word: &[u8], keyword: &str) -> bool {
    word.eq_ignore_ascii_case(keyword.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(sql: &str) -> Vec<(TokenKind, &str)> {
        let mut lx = Lexer::new(sql.as_bytes(), 16);
        let mut out = Vec::new();
        while let Some(t) = lx.next_token().unwrap() {
            out.push((t.kind, &sql[t.start..t.end]));
        }
        out
    }

    fn error(sql: &str) -> LexError {
        let mut lx = Lexer::new(sql.as_bytes(), 4);
        loop {
            match lx.next_token() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("no error for {sql:?}"),
                Err(e) => return e,
            }
        }
    }

    #[test]
    fn words_numbers_and_strings() {
        use TokenKind::*;
        assert_eq!(
            kinds("select e'a\\'b', x'1F', 1e5 from t$x$"),
            vec![
                (Word, "select"),
                (String, "e'a\\'b'"),
                (Other, ","),
                (Word, "x"),
                (String, "'1F'"),
                (Other, ","),
                (Number, "1e5"),
                (Word, "from"),
                (Word, "t$x$"),
            ]
        );
    }

    #[test]
    fn e_prefix_only_as_a_whole_word() {
        use TokenKind::*;
        // `filee'...'` is an identifier and a standard string, so the
        // backslash is literal and the string ends at the second quote.
        assert_eq!(
            kinds(r"filee'\' ;"),
            vec![(Word, "filee"), (String, r"'\'"), (Semicolon, ";")]
        );
        // After a digit the `e` is numeric junk, not an escape prefix.
        assert_eq!(
            kinds(r"1e'\' ;"),
            vec![(Number, "1e"), (String, r"'\'"), (Semicolon, ";")]
        );
    }

    #[test]
    fn dollar_quotes() {
        use TokenKind::*;
        assert_eq!(
            kinds("$$a;b$$ $fn$ $$ ; $fn$ $1 $x"),
            vec![
                (DollarString, "$$a;b$$"),
                (DollarString, "$fn$ $$ ; $fn$"),
                (Param, "$1"),
                (Other, "$"),
                (Word, "x"),
            ]
        );
        // `$junk$delim$`: the closing delimiter overlaps another tag.
        assert_eq!(
            kinds("$delim$ $junk$delim$"),
            vec![(DollarString, "$delim$ $junk$delim$")]
        );
        // A number directly before a dollar quote ends at the `$`.
        assert_eq!(
            kinds("1$$x$$"),
            vec![(Number, "1"), (DollarString, "$$x$$")]
        );
    }

    /// Review finding `lexer-param-and-vtab-disagree` (TH-26). Token
    /// extents follow PostgreSQL 16. The server's verdict on each input is
    /// in the comments: "junk" is its "trailing junk" error, whose
    /// `at or near` text shows the token it read.
    #[test]
    fn review_lexer_param_and_vtab_disagree() {
        use TokenKind::*;
        // Parameters end before a dot, so the dollar quote opens.
        assert_eq!(
            kinds("$1.x.$q$;$q$"),
            vec![
                (Param, "$1"),
                (Other, "."),
                (Word, "x"),
                (Other, "."),
                (DollarString, "$q$;$q$"),
            ]
        );
        // Junk "$1x$a$" and "$1_0"; "$1" then a dollar quote.
        assert_eq!(kinds("$1x$a$ ;"), vec![(Param, "$1x$a$"), (Semicolon, ";")]);
        assert_eq!(kinds("$1_0"), vec![(Param, "$1_0")]);
        assert_eq!(
            kinds("$1$a$;$a$"),
            vec![(Param, "$1"), (DollarString, "$a$;$a$")]
        );
        // Junk "1.x" ends at the dot, before a dollar quote.
        assert_eq!(
            kinds("1.x.$q$;$q$"),
            vec![(Number, "1.x"), (Other, "."), (DollarString, "$q$;$q$")]
        );
        // Junk "1e5$a$", "1_0$a$", "1.5e5$a$", "1.5_0$a$" and "1e+1_0$a$".
        for sql in ["1e5$a$", "1_0$a$", "1.5e5$a$", "1.5_0$a$", "1e+1_0$a$"] {
            assert_eq!(kinds(sql), vec![(Number, sql)], "{sql}");
        }
        // Valid numbers, then a dollar quote that the server opens.
        for (sql, number) in [
            ("10$a$;$a$", "10"),
            ("1e+5$a$;$a$", "1e+5"),
            ("1.$a$;$a$", "1."),
        ] {
            assert_eq!(
                kinds(sql),
                vec![(Number, number), (DollarString, &sql[number.len()..])],
                "{sql}"
            );
        }
        // "1.5", ".", then an escape string, in which the backslash
        // escapes the quote.
        assert_eq!(
            kinds(r"1.5.e'\';'"),
            vec![(Number, "1.5"), (Other, "."), (String, r"e'\';'")]
        );
        // Junk "1.e" and "1e+": the quotes after them open standard strings.
        assert_eq!(kinds(r"1.e'\'"), vec![(Number, "1.e"), (String, r"'\'")]);
        assert_eq!(kinds("1e+'x'"), vec![(Number, "1e+"), (String, "'x'")]);
        // Hexadecimal, junk "0x1Fg", and "1" then ".." for "1..2".
        assert_eq!(
            kinds("0x1F 0x1Fg"),
            vec![(Number, "0x1F"), (Number, "0x1Fg")]
        );
        assert_eq!(
            kinds("1..2"),
            vec![(Number, "1"), (Other, "."), (Other, "."), (Number, "2")]
        );
        // A vertical tab is a token of its own, which the server rejects.
        assert_eq!(
            kinds("SELECT\x0b1"),
            vec![(Word, "SELECT"), (Other, "\x0b"), (Number, "1")]
        );
        // It does not continue an escape string either.
        assert_eq!(
            kinds("E'a'\x0b\n'b'"),
            vec![(String, "E'a'"), (Other, "\x0b"), (String, "'b'")]
        );
    }

    #[test]
    fn comments_nest_and_hide_everything() {
        use TokenKind::*;
        assert_eq!(
            kinds("a /* x /* ; ' */ \" */ b -- ; '\nc"),
            vec![(Word, "a"), (Word, "b"), (Word, "c")]
        );
        assert_eq!(kinds("a--x"), vec![(Word, "a")]);
        assert_eq!(kinds("+--x\n-"), vec![(Other, "+"), (Other, "-")]);
    }

    #[test]
    fn escape_string_continuation() {
        use TokenKind::*;
        // The continuation keeps backslash escapes, so `\'` does not end it.
        assert_eq!(
            kinds("E'a'\n'\\'; x' ;"),
            vec![(String, "E'a'\n'\\'; x'"), (Semicolon, ";")]
        );
        // Without a newline there is no continuation.
        assert_eq!(kinds("E'a' 'b'"), vec![(String, "E'a'"), (String, "'b'")]);
        // A comment before the newline is allowed.
        assert_eq!(
            kinds("E'a' -- c\n  'b'"),
            vec![(String, "E'a' -- c\n  'b'")]
        );
        // A block comment breaks the continuation.
        assert_eq!(
            kinds("E'a'\n/**/'b'"),
            vec![(String, "E'a'"), (String, "'b'")]
        );
    }

    #[test]
    fn unterminated_constructs() {
        assert_eq!(
            error("select 'abc"),
            LexError {
                kind: LexErrorKind::UnterminatedString,
                offset: 7
            }
        );
        assert_eq!(
            error("x E'abc\\'").kind,
            LexErrorKind::UnterminatedEscapeString
        );
        assert_eq!(
            error("x E'abc\\").kind,
            LexErrorKind::UnterminatedEscapeString
        );
        assert_eq!(
            error("\"abc\"\"").kind,
            LexErrorKind::UnterminatedQuotedIdentifier
        );
        assert_eq!(error("$a$ $b$").kind, LexErrorKind::UnterminatedDollarQuote);
        assert_eq!(
            error("/* /* */").kind,
            LexErrorKind::UnterminatedBlockComment
        );
        assert_eq!(
            error("/*/*/*/*/*").kind,
            LexErrorKind::CommentTooDeep,
            "depth 5 exceeds the limit of 4"
        );
    }

    #[test]
    fn non_ascii_identifiers_stay_whole() {
        use TokenKind::*;
        assert_eq!(
            kinds("über$x$ ünï;"),
            vec![(Word, "über$x$"), (Word, "ünï"), (Semicolon, ";")]
        );
    }
}
