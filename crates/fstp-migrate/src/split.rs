//! Splitting a migration file into statements.
//!
//! The PostgreSQL extended query protocol takes one statement per Parse
//! message, so a migration file is split before it runs. [`split_statements`]
//! scans the file with the lexical rules of the server scanner (see the
//! list below) and cuts it at every semicolon outside those constructs.
//!
//! - Standard strings `'...'` with `''` escapes. The `B`, `X`, `N` and
//!   `U&` prefixed forms quote the same way.
//! - Escape strings `E'...'` with backslash escapes, including their
//!   continuation over a newline.
//! - Quoted identifiers `"..."` with `""` escapes.
//! - Dollar-quoted strings `$tag$...$tag$`, where the tag is optional.
//! - Line comments `--` and nested block comments `/* ... */`.
//! - Parentheses: a semicolon inside them does not end a statement, as in
//!   `CREATE RULE ... DO ALSO (INSERT ...; INSERT ...)`.
//! - SQL-standard routine bodies: in a statement that starts with
//!   `CREATE [OR REPLACE] FUNCTION` or `PROCEDURE`, a semicolon between
//!   `BEGIN ATOMIC` and the `END` of the body does not end the
//!   statement. See below for how that `END` is found.
//!
//! The splitter assumes `standard_conforming_strings = on`, the server
//! default. The migration runner checks that setting before it applies
//! anything, and again after every statement.
//!
//! # Routine bodies
//!
//! The server's grammar ends a `BEGIN ATOMIC` body with an `END` that
//! directly follows a semicolon, or the `ATOMIC` of an empty body. No
//! statement inside a body starts with `END`, so that `END` is never
//! anything else. The splitter closes the body at the first such `END`
//! outside parentheses. Every other `END` closes a `CASE` or is a
//! column name or label, as in `CASE ... END`, `SELECT 1 AS end`,
//! `SELECT 1 end` or `t.end`.
//!
//! Inside a body, `BEGIN` is a plain word, as in
//! `SELECT begin atomic FROM t`. PostgreSQL 16 refuses a routine
//! definition inside a body, so bodies do not nest. This is stricter than
//! the heuristic of `psql`, which counts every `BEGIN`, `CASE` and `END`.
//!
//! # Output
//!
//! Each statement is a subslice of the input that starts at its first
//! token and ends at the end of its last token. Whitespace and comments
//! around a statement, and the terminating semicolon, are not part of it.
//! Comments inside a statement stay. Statements made only of whitespace
//! and comments are dropped.
//!
//! # Limits
//!
//! [`SplitLimits`] bounds the input size, the number of statements and
//! the nesting depth of block comments and parentheses.
//! Unterminated constructs and unbalanced parentheses are errors with the
//! byte offset and line where the construct starts.

use std::fmt;

use crate::lex::{LexError, LexErrorKind, Lexer, TokenKind, is_keyword};

/// Limits that bound [`split_statements`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SplitLimits {
    /// Largest input in bytes. Default 16 MiB.
    pub max_input_bytes: usize,
    /// Most statements in one input. Default 10 000.
    pub max_statements: usize,
    /// Deepest nesting of block comments. Default 32.
    pub max_comment_depth: usize,
    /// Deepest nesting of parentheses. Default 256.
    pub max_paren_depth: usize,
}

impl Default for SplitLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 << 20,
            max_statements: 10_000,
            max_comment_depth: 32,
            max_paren_depth: 256,
        }
    }
}

/// One statement found by [`split_statements`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlStatement<'a> {
    text: &'a str,
    offset: usize,
    line: usize,
}

impl<'a> SqlStatement<'a> {
    /// The statement text: a subslice of the input without the terminating
    /// semicolon and without surrounding whitespace and comments.
    #[must_use]
    pub fn text(&self) -> &'a str {
        self.text
    }

    /// The byte offset of the statement in the input.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The 1-based line of the input on which the statement starts.
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }
}

/// The reason [`split_statements`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SplitErrorKind {
    /// A `'...'` string has no closing quote.
    UnterminatedString,
    /// An `E'...'` string has no closing quote.
    UnterminatedEscapeString,
    /// A `"..."` identifier has no closing quote.
    UnterminatedQuotedIdentifier,
    /// A `$tag$` string has no closing delimiter.
    UnterminatedDollarQuote,
    /// A `/*` comment has no matching `*/`.
    UnterminatedBlockComment,
    /// A `(` has no matching `)`.
    UnterminatedParenthesis,
    /// A `)` has no matching `(`.
    UnbalancedParenthesis,
    /// A `BEGIN ATOMIC` routine body has no matching `END`.
    UnterminatedRoutineBody,
    /// The input exceeds [`SplitLimits::max_input_bytes`].
    InputTooLarge,
    /// The input holds more than [`SplitLimits::max_statements`]
    /// statements.
    TooManyStatements,
    /// Block comments nest deeper than [`SplitLimits::max_comment_depth`].
    CommentTooDeep,
    /// Parentheses nest deeper than [`SplitLimits::max_paren_depth`].
    ParenthesesTooDeep,
}

impl SplitErrorKind {
    fn describe(self) -> &'static str {
        match self {
            Self::UnterminatedString => "unterminated quoted string",
            Self::UnterminatedEscapeString => "unterminated escape string",
            Self::UnterminatedQuotedIdentifier => "unterminated quoted identifier",
            Self::UnterminatedDollarQuote => "unterminated dollar-quoted string",
            Self::UnterminatedBlockComment => "unterminated block comment",
            Self::UnterminatedParenthesis => "unclosed parenthesis",
            Self::UnbalancedParenthesis => "closing parenthesis without an opening one",
            Self::UnterminatedRoutineBody => "BEGIN ATOMIC without a matching END",
            Self::InputTooLarge => "input exceeds the size limit",
            Self::TooManyStatements => "too many statements",
            Self::CommentTooDeep => "block comments nest too deeply",
            Self::ParenthesesTooDeep => "parentheses nest too deeply",
        }
    }
}

/// A failure of [`split_statements`], with the position of the construct
/// that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SplitError {
    kind: SplitErrorKind,
    offset: usize,
    line: usize,
}

impl SplitError {
    fn at(kind: SplitErrorKind, src: &[u8], offset: usize) -> Self {
        Self {
            kind,
            offset,
            line: line_at(src, offset),
        }
    }

    /// What went wrong.
    #[must_use]
    pub fn kind(&self) -> SplitErrorKind {
        self.kind
    }

    /// The byte offset where the offending construct starts. For the size
    /// limit it is 0.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The 1-based line of [`SplitError::offset`].
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {} (byte {})",
            self.kind.describe(),
            self.line,
            self.offset
        )
    }
}

impl std::error::Error for SplitError {}

/// The 1-based line number of byte `offset`.
fn line_at(src: &[u8], offset: usize) -> usize {
    let before = src.get(..offset).unwrap_or(src);
    count_newlines(before).saturating_add(1)
}

fn count_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'\n').count()
}

impl SplitError {
    fn from_lex(e: LexError, src: &[u8]) -> Self {
        let kind = match e.kind {
            LexErrorKind::UnterminatedString => SplitErrorKind::UnterminatedString,
            LexErrorKind::UnterminatedEscapeString => SplitErrorKind::UnterminatedEscapeString,
            LexErrorKind::UnterminatedQuotedIdentifier => {
                SplitErrorKind::UnterminatedQuotedIdentifier
            }
            LexErrorKind::UnterminatedDollarQuote => SplitErrorKind::UnterminatedDollarQuote,
            LexErrorKind::UnterminatedBlockComment => SplitErrorKind::UnterminatedBlockComment,
            LexErrorKind::CommentTooDeep => SplitErrorKind::CommentTooDeep,
        };
        SplitError::at(kind, src, e.offset)
    }
}

/// Tracks whether the current statement starts with
/// `CREATE [OR REPLACE] FUNCTION` or `PROCEDURE`.
#[derive(Debug, Default)]
struct Lead {
    /// The number of tokens seen so far, up to 4.
    seen: usize,
    /// True while the tokens so far still match the routine prefix.
    possible: bool,
    /// True once the full prefix has been seen.
    routine: bool,
}

impl Lead {
    fn reset(&mut self) {
        *self = Lead::default();
    }

    /// Records the next token: `Some(word)` for a word, `None` otherwise.
    fn push(&mut self, word: Option<&[u8]>) {
        if self.routine || self.seen >= 4 {
            return;
        }
        let w = |k: &str| word.is_some_and(|w| is_keyword(w, k));
        let routine_kw = w("FUNCTION") || w("PROCEDURE");
        match self.seen {
            0 => self.possible = w("CREATE"),
            1 if self.possible => {
                if routine_kw {
                    self.routine = true;
                } else {
                    self.possible = w("OR");
                }
            }
            2 if self.possible => self.possible = w("REPLACE"),
            3 if self.possible => self.routine = routine_kw,
            _ => self.possible = false,
        }
        self.seen = self.seen.saturating_add(1);
    }
}

/// Where the current statement is relative to its `BEGIN ATOMIC` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    /// No body has opened.
    None,
    /// Inside the body: semicolons do not end the statement.
    Open,
    /// The body has ended. A statement has at most one body.
    Closed,
}

/// Splits `sql` into statements.
///
/// See the [module documentation](self) for the lexical rules and the
/// shape of the output.
///
/// # Errors
///
/// Returns a [`SplitError`] for an unterminated string, identifier,
/// dollar quote, block comment, parenthesis or routine body, for an
/// unbalanced closing parenthesis, and when a [`SplitLimits`] bound is
/// exceeded.
pub fn split_statements<'a>(
    sql: &'a str,
    limits: &SplitLimits,
) -> Result<Vec<SqlStatement<'a>>, SplitError> {
    let src = sql.as_bytes();
    if src.len() > limits.max_input_bytes {
        return Err(SplitError {
            kind: SplitErrorKind::InputTooLarge,
            offset: 0,
            line: 1,
        });
    }
    let mut lexer = Lexer::new(src, limits.max_comment_depth);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut current: Option<(usize, usize)> = None;
    let mut parens = 0usize;
    let mut outer_paren = 0usize;
    let mut body = Body::None;
    let mut body_start = 0usize;
    // True when the previous token is a semicolon or the `ATOMIC` that
    // opened the body: the only places where the body's `END` can be.
    let mut body_boundary = false;
    let mut lead = Lead::default();

    let push = |ranges: &mut Vec<(usize, usize)>, range: (usize, usize)| {
        if ranges.len() >= limits.max_statements {
            return Err(SplitError::at(
                SplitErrorKind::TooManyStatements,
                src,
                range.0,
            ));
        }
        ranges.push(range);
        Ok(())
    };

    loop {
        let token = match lexer.next_token() {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(e) => return Err(SplitError::from_lex(e, src)),
        };
        let word = (token.kind == TokenKind::Word)
            .then(|| src.get(token.start..token.end))
            .flatten();
        match token.kind {
            TokenKind::Semicolon if parens == 0 && body != Body::Open => {
                if let Some(range) = current.take() {
                    push(&mut ranges, range)?;
                }
                lead.reset();
                body = Body::None;
                continue;
            }
            TokenKind::OpenParen => {
                if parens == 0 {
                    outer_paren = token.start;
                }
                parens = parens.saturating_add(1);
                if parens > limits.max_paren_depth {
                    return Err(SplitError::at(
                        SplitErrorKind::ParenthesesTooDeep,
                        src,
                        token.start,
                    ));
                }
            }
            TokenKind::CloseParen => {
                if parens == 0 {
                    return Err(SplitError::at(
                        SplitErrorKind::UnbalancedParenthesis,
                        src,
                        token.start,
                    ));
                }
                parens = parens.saturating_sub(1);
            }
            _ => {}
        }
        lead.push(word);
        let mut end = token.end;
        let mut boundary = token.kind == TokenKind::Semicolon;
        if let Some(w) = word
            && lead.routine
            && parens == 0
        {
            match body {
                Body::None if is_keyword(w, "BEGIN") => {
                    let mut ahead = lexer;
                    if let Ok(Some(atomic)) = ahead.next_token()
                        && atomic.kind == TokenKind::Word
                        && src
                            .get(atomic.start..atomic.end)
                            .is_some_and(|a| is_keyword(a, "ATOMIC"))
                    {
                        lexer = ahead;
                        end = atomic.end;
                        body = Body::Open;
                        body_start = token.start;
                        boundary = true;
                    }
                }
                Body::Open if body_boundary && is_keyword(w, "END") => body = Body::Closed,
                _ => {}
            }
        }
        body_boundary = boundary;
        current = Some((current.map_or(token.start, |c| c.0), end));
    }
    if parens > 0 {
        return Err(SplitError::at(
            SplitErrorKind::UnterminatedParenthesis,
            src,
            outer_paren,
        ));
    }
    if body == Body::Open {
        return Err(SplitError::at(
            SplitErrorKind::UnterminatedRoutineBody,
            src,
            body_start,
        ));
    }
    if let Some(range) = current {
        push(&mut ranges, range)?;
    }

    let mut out = Vec::with_capacity(ranges.len());
    let mut line = 1usize;
    let mut counted = 0usize;
    for (start, end) in ranges {
        line = line.saturating_add(count_newlines(src.get(counted..start).unwrap_or_default()));
        counted = start;
        // Token boundaries are always character boundaries (see `lex`), so
        // `get` succeeds; a miss would be a scanner bug, reported as the
        // input being malformed rather than as a panic.
        let Some(text) = sql.get(start..end) else {
            return Err(SplitError::at(
                SplitErrorKind::UnterminatedString,
                src,
                start,
            ));
        };
        out.push(SqlStatement {
            text,
            offset: start,
            line,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(sql: &str) -> Vec<&str> {
        split_statements(sql, &SplitLimits::default())
            .unwrap_or_else(|e| panic!("{sql:?}: {e}"))
            .into_iter()
            .map(|s| s.text())
            .collect()
    }

    fn fail(sql: &str) -> SplitError {
        match split_statements(sql, &SplitLimits::default()) {
            Ok(v) => panic!("{sql:?} split into {v:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn empty_and_comment_only_inputs_have_no_statements() {
        assert!(split("").is_empty());
        assert!(split(" \n\t ").is_empty());
        assert!(split(";;; ;").is_empty());
        assert!(split("-- just a comment").is_empty());
        assert!(split("/* a */ ; /* b /* c */ */ ;\n-- d\n").is_empty());
    }

    #[test]
    fn statements_exclude_surrounding_comments_and_semicolons() {
        assert_eq!(
            split("-- lead\nSELECT 1 -- trail\n; /* x */ SELECT /* in */ 2 ;\n SELECT 3"),
            vec!["SELECT 1", "SELECT /* in */ 2", "SELECT 3"]
        );
    }

    #[test]
    fn semicolons_inside_quotes_and_comments_do_not_split() {
        let sql = "INSERT INTO t VALUES ('a;b', 'it''s;', E'x\\';y', \"c;d\"); \
                   SELECT $$;$$, $tag$ $$ ; $tag$; /* ; */ -- ;\nSELECT 2";
        assert_eq!(
            split(sql),
            vec![
                "INSERT INTO t VALUES ('a;b', 'it''s;', E'x\\';y', \"c;d\")",
                "SELECT $$;$$, $tag$ $$ ; $tag$",
                "SELECT 2",
            ]
        );
    }

    #[test]
    fn plpgsql_function_bodies_stay_whole() {
        let sql = r#"
CREATE FUNCTION f(x int) RETURNS text LANGUAGE plpgsql AS $body$
DECLARE
    s text := 'semi;colon ''quoted''';
BEGIN
    IF x > 0 THEN
        RETURN s || $$;$$;
    END IF;
    RETURN E'back\\slash\';';
END;
$body$;
SELECT f(1);
"#;
        let parts = split(sql);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with("CREATE FUNCTION"));
        assert!(parts[0].ends_with("$body$"));
        assert_eq!(parts[1], "SELECT f(1)");
    }

    #[test]
    fn begin_atomic_bodies_stay_whole() {
        let sql = "CREATE OR REPLACE FUNCTION g() RETURNS int LANGUAGE sql\n\
                   BEGIN ATOMIC\n  SELECT 1;\n  SELECT CASE WHEN true THEN 2 ELSE 3 END;\nEND;\n\
                   create procedure p() begin /* c */ atomic insert into t values (1); end;\n\
                   SELECT 4";
        assert_eq!(
            split(sql),
            vec![
                "CREATE OR REPLACE FUNCTION g() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  \
                 SELECT 1;\n  SELECT CASE WHEN true THEN 2 ELSE 3 END;\nEND",
                "create procedure p() begin /* c */ atomic insert into t values (1); end",
                "SELECT 4",
            ]
        );
    }

    /// Review finding `begin-atomic-reserved-labels` (TH-26). PostgreSQL 16
    /// accepts `END` and `CASE` as column labels with and without `AS`
    /// and after a dot, and `begin` as a column name. Each routine below is
    /// one statement for the server, which the `pg` tests confirm.
    #[test]
    fn review_begin_atomic_reserved_labels() {
        for routine in [
            "CREATE FUNCTION span() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  SELECT 2 AS end;\nEND",
            "CREATE FUNCTION last_end() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  \
             SELECT r.end FROM (SELECT 7 AS \"end\") r;\nEND",
            "CREATE FUNCTION kind() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  SELECT 3 AS case;\nEND",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 4 end; END",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 3 case; END",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC \
             SELECT CASE WHEN true THEN 1 END case; END",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC \
             SELECT t.case, t . end FROM t; END",
            "CREATE FUNCTION f() RETURNS SETOF int LANGUAGE sql BEGIN ATOMIC \
             SELECT t.begin atomic FROM (SELECT 1 AS begin) t; SELECT begin atomic FROM t; END",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC ; SELECT 1 ; ; END",
            "CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC END",
        ] {
            assert_eq!(split(routine), vec![routine], "{routine}");
            let script = format!("{routine};\nCREATE TABLE after_fn (id int);\nSELECT 1 AS end;");
            assert_eq!(
                split(&script),
                vec![routine, "CREATE TABLE after_fn (id int)", "SELECT 1 AS end"],
                "{script}"
            );
        }
    }

    /// Review finding `lexer-param-and-vtab-disagree` (TH-26). The server
    /// reads `$1` as one parameter token and ends trailing junk after a
    /// number at a dot, so the dollar quotes and escape strings below open
    /// where the server opens them. Its verdicts are in the comments.
    #[test]
    fn review_lexer_param_and_vtab_disagree() {
        // Server: syntax error at or near "$q$;$q$", so one statement.
        assert_eq!(split("SELECT $1.x.$q$;$q$"), vec!["SELECT $1.x.$q$;$q$"]);
        // Server: unterminated dollar-quoted string at or near "$e$".
        assert_eq!(
            fail("SELECT $1._u$1a1.$e$").kind(),
            SplitErrorKind::UnterminatedDollarQuote
        );
        // Server: unterminated quoted string at or near "E'UESCAPE\'".
        assert_eq!(
            fail("SELECT $1.E'UESCAPE\\'").kind(),
            SplitErrorKind::UnterminatedEscapeString
        );
        // Server: trailing junk after numeric literal at or near "1.x".
        assert_eq!(split("SELECT 1.x.$q$;$q$"), vec!["SELECT 1.x.$q$;$q$"]);
        // Server: syntax error at or near "$a$;$a$" after a parameter, an
        // integer and a real.
        for sql in ["SELECT $1$a$;$a$", "SELECT 10$a$;$a$", "SELECT 1e+5$a$;$a$"] {
            assert_eq!(split(sql), vec![sql]);
        }
        // Server: trailing junk at or near "1e5$a$", "1_0$a$" and
        // "$1x$a$", so the `$a$` is not a dollar quote and `;` splits.
        for sql in [
            "SELECT 1e5$a$;$a$",
            "SELECT 1_0$a$;$a$",
            "SELECT $1x$a$;$a$",
        ] {
            assert_eq!(
                fail(sql).kind(),
                SplitErrorKind::UnterminatedDollarQuote,
                "{sql}"
            );
        }
        // Server: syntax error at or near "", since a vertical tab is not
        // whitespace in PostgreSQL 16. It stays in the text as a piece of
        // its own, which the server then rejects.
        assert_eq!(split("SELECT 1\x0b"), vec!["SELECT 1\x0b"]);
        assert_eq!(split("SELECT 1;\x0b"), vec!["SELECT 1", "\x0b"]);
    }

    #[test]
    fn begin_outside_routines_or_without_atomic_is_a_plain_word() {
        // A function named `begin` and a column named `begin` do not open
        // a block.
        assert_eq!(
            split("CREATE FUNCTION begin() RETURNS int AS 'select 1' LANGUAGE sql; SELECT 1"),
            vec![
                "CREATE FUNCTION begin() RETURNS int AS 'select 1' LANGUAGE sql",
                "SELECT 1"
            ]
        );
        assert_eq!(
            split("BEGIN; SELECT 1; END"),
            vec!["BEGIN", "SELECT 1", "END"]
        );
        assert_eq!(
            split("CREATE TABLE t (begin int); SELECT begin FROM t"),
            vec!["CREATE TABLE t (begin int)", "SELECT begin FROM t"]
        );
    }

    #[test]
    fn semicolons_inside_parentheses_do_not_split() {
        assert_eq!(
            split(
                "CREATE RULE r AS ON INSERT TO t DO ALSO (INSERT INTO a VALUES (1); INSERT INTO b VALUES (2)); SELECT 1"
            ),
            vec![
                "CREATE RULE r AS ON INSERT TO t DO ALSO (INSERT INTO a VALUES (1); INSERT INTO b VALUES (2))",
                "SELECT 1",
            ]
        );
    }

    #[test]
    fn offsets_and_lines() {
        let sql = "\n\nSELECT 1;\n  SELECT\n2; SELECT 3";
        let stmts = split_statements(sql, &SplitLimits::default()).unwrap();
        let got: Vec<(usize, usize)> = stmts.iter().map(|s| (s.offset(), s.line())).collect();
        assert_eq!(got, vec![(2, 3), (14, 4), (24, 5)]);
        for s in &stmts {
            assert_eq!(&sql[s.offset()..s.offset() + s.text().len()], s.text());
        }
    }

    #[test]
    fn unterminated_constructs_report_their_start() {
        let e = fail("SELECT 1;\nSELECT 'abc;\n");
        assert_eq!(e.kind(), SplitErrorKind::UnterminatedString);
        assert_eq!((e.offset(), e.line()), (17, 2));
        assert_eq!(
            fail("SELECT E'\\'").kind(),
            SplitErrorKind::UnterminatedEscapeString
        );
        assert_eq!(
            fail("SELECT \"x").kind(),
            SplitErrorKind::UnterminatedQuotedIdentifier
        );
        assert_eq!(
            fail("SELECT $a$ x $b$").kind(),
            SplitErrorKind::UnterminatedDollarQuote
        );
        assert_eq!(
            fail("SELECT 1 /* /* */").kind(),
            SplitErrorKind::UnterminatedBlockComment
        );
        let e = fail("SELECT (1, (2);\nSELECT 3");
        assert_eq!(e.kind(), SplitErrorKind::UnterminatedParenthesis);
        assert_eq!(e.offset(), 7);
        assert_eq!(
            fail("SELECT 1)").kind(),
            SplitErrorKind::UnbalancedParenthesis
        );
        assert_eq!(
            fail("CREATE FUNCTION f() RETURNS int BEGIN ATOMIC SELECT 1;").kind(),
            SplitErrorKind::UnterminatedRoutineBody
        );
        assert!(fail("SELECT 'x").to_string().contains("line 1"));
    }

    #[test]
    fn limits_are_enforced() {
        let tight = SplitLimits {
            max_input_bytes: 32,
            max_statements: 2,
            max_comment_depth: 2,
            max_paren_depth: 2,
        };
        let kind = |sql: &str| split_statements(sql, &tight).unwrap_err().kind();
        assert_eq!(kind(&"x".repeat(33)), SplitErrorKind::InputTooLarge);
        assert!(split_statements(&"x".repeat(32), &tight).is_ok());
        assert_eq!(kind("a; b; c"), SplitErrorKind::TooManyStatements);
        assert!(split_statements("a; b;;", &tight).is_ok());
        assert_eq!(kind("/*/*/* */ */ */"), SplitErrorKind::CommentTooDeep);
        assert_eq!(kind("(((1)))"), SplitErrorKind::ParenthesesTooDeep);
    }
}
