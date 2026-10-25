//! Property tests of the statement splitter (TH-26, H-05).
//!
//! Generated statements, joined with semicolons, random whitespace and
//! random comments, split back into exactly the original statements. The
//! statements hold every construct that can hide a semicolon: standard,
//! escape, prefixed and dollar-quoted strings, quoted identifiers, nested
//! block comments, line comments, parentheses and `BEGIN ATOMIC` routine
//! bodies.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_migrate::{SplitLimits, split_statements};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Words for plain statements. `create` is left out so that no plain
/// statement looks like a routine definition.
const WORDS: &[&str] = &[
    "select", "SELECT", "from", "t", "x", "e", "E", "u", "U", "b", "n", "begin", "BEGIN", "end",
    "case", "atomic", "commit", "foo$bar", "_t1", "über", "x1$",
];

/// Words for a routine header, before `BEGIN ATOMIC`: no `begin`, which
/// could open the body early.
const HEADER_WORDS: &[&str] = &[
    "select", "SELECT", "from", "t", "x", "e", "E", "atomic", "foo$bar", "_t1", "über",
];

/// Words inside a routine body. `end` and `case` appear as column names
/// and labels, as in `t.end` or `x AS case`, and `begin` as a column.
/// Review finding `begin-atomic-reserved-labels`.
const BODY_WORDS: &[&str] = &[
    "select", "SELECT", "from", "t", "x", "e", "E", "atomic", "foo$bar", "_t1", "über", "end",
    "END", "case", "Case", "begin", "AS", ".",
];

const NUMBERS: &[&str] = &[
    "1", "42", "1.5", "1e10", "0x1F", "1_000", "7.", "1e+5", "2.5E-3", "1_0.2_5",
];

const OPERATORS: &[&str] = &[
    "+", "-", "*", "/", "<", ">", "=", "<>", "!=", "::", ",", ".", "%", "^", "|", "&", "@", "#",
    "~", "?", ":", "$1", "$", "[", "]",
];

const PREFIXED: &[&str] = &[
    "U&'d\\0061t'",
    "B'0101'",
    "X'1F'",
    "N'it''s;'",
    "u&'\\'",
    "U&\"a;b\"",
];

/// Separators between tokens. Comments start with a space so that they
/// never merge with a preceding operator.
const SEPARATORS: &[&str] = &[
    " ",
    "\n",
    "\t",
    "  ",
    "\r\n",
    " \x0c ",
    " /* c; */ ",
    " /* a /* nested; ' \" $$ */ b */ ",
    " -- line; ' \" $$ /*\n",
    " --\n",
];

/// Separators allowed after an escape string: none of them continues the
/// string, which a newline before a quote would do.
const AFTER_ESCAPE: &[&str] = &[" ", "  ", " /* c */ ", "\t"];

/// Fillers around semicolons between statements.
const FILLERS: &[&str] = &[
    "",
    " ",
    "\n",
    "\n\n",
    "\t",
    " /* between; */",
    " /* x /* y */ */ ",
    " -- trailing; ' $$\n",
    " -- at end",
];

fn pieces(g: &mut Gen, from: &[&str], len: std::ops::RangeInclusive<usize>) -> String {
    g.vec(len, |g| (*g.pick(from)).to_owned()).concat()
}

fn standard_string(g: &mut Gen) -> String {
    let body = pieces(
        g,
        &[
            "a", ";", "\"", "$$", "$", "--", "/*", "*/", "\\", "\n", " ", "é", "''", "E",
        ],
        0..=6,
    );
    format!("'{body}'")
}

const ESCAPE_PIECES: &[&str] = &[
    "a", ";", "\"", "$$", "--", "/*", "\\'", "\\\\", "\\n", "''", " ", "é", "\n",
];

/// An escape string, sometimes continued over a newline. The server keeps
/// backslash escapes in the continuation, so a `\'` there does not end it.
fn escape_string(g: &mut Gen) -> String {
    let body = pieces(g, ESCAPE_PIECES, 0..=6);
    let prefix = if g.bool() { "E" } else { "e" };
    let mut s = format!("{prefix}'{body}'");
    for _ in 0..g.usize_in(0..=2) {
        let gap = *g.pick(&["\n", " \n  ", "\r\n", " -- c; '\n", "\n-- c\n\t"]);
        let more = pieces(g, ESCAPE_PIECES, 0..=4);
        s.push_str(gap);
        s.push_str("'\\';");
        s.push_str(&more);
        s.push('\'');
    }
    s
}

fn quoted_ident(g: &mut Gen) -> String {
    let body = pieces(
        g,
        &["a", ";", "'", "$$", "--", "/*", "\"\"", " ", "é"],
        1..=5,
    );
    format!("\"{body}\"")
}

fn dollar_string(g: &mut Gen) -> String {
    let tag = *g.pick(&["", "a", "fn", "_x1", "über", "T"]);
    let delim = format!("${tag}$");
    let mut body = pieces(
        g,
        &[
            "a", ";", "'", "\"", "$", "$a", "$$", "--", "/*", " ", "\n", "é", "\\",
        ],
        0..=6,
    );
    // The body must not contain the delimiter, nor end in a way that
    // forms it early together with the closing delimiter.
    if format!("{body}{delim}").find(&delim) != Some(body.len()) {
        body.retain(|c| c != '$');
    }
    format!("{delim}{body}{delim}")
}

/// One token. `words` is the word list; `depth` limits nested groups.
fn token(g: &mut Gen, words: &[&str], depth: u32) -> String {
    let group = if depth < 3 { 2 } else { 0 };
    match g.weighted(&[6, 2, 3, 3, 2, 2, 2, 1, group]) {
        0 => (*g.pick(words)).to_owned(),
        1 => (*g.pick(NUMBERS)).to_owned(),
        2 => (*g.pick(OPERATORS)).to_owned(),
        3 => standard_string(g),
        4 => escape_string(g),
        5 => quoted_ident(g),
        6 => dollar_string(g),
        7 => (*g.pick(PREFIXED)).to_owned(),
        _ => {
            // Semicolons inside parentheses do not end the statement.
            let inner = g.vec(0..=4, |g| {
                if g.weighted(&[4, 1]) == 0 {
                    token(g, words, depth + 1)
                } else {
                    ";".to_owned()
                }
            });
            let mut s = String::from("(");
            for t in &inner {
                s.push(' ');
                s.push_str(t);
            }
            s.push_str(" )");
            s
        }
    }
}

fn is_escape_string(t: &str) -> bool {
    t.starts_with("E'") || t.starts_with("e'")
}

/// Joins tokens with random separators.
fn join(g: &mut Gen, tokens: &[String]) -> String {
    let mut s = String::new();
    for (i, t) in tokens.iter().enumerate() {
        if i > 0 {
            let prev = &tokens[i - 1];
            let sep = if is_escape_string(prev) {
                *g.pick(AFTER_ESCAPE)
            } else {
                *g.pick(SEPARATORS)
            };
            s.push_str(sep);
        }
        s.push_str(t);
    }
    s
}

fn plain_statement(g: &mut Gen) -> String {
    let tokens = g.vec(1..=8, |g| token(g, WORDS, 0));
    join(g, &tokens)
}

/// `CREATE [OR REPLACE] FUNCTION|PROCEDURE ... BEGIN ATOMIC ...; END`, or
/// a routine with a dollar-quoted body.
fn routine_statement(g: &mut Gen) -> String {
    let mut tokens: Vec<String> = vec![(*g.pick(&["CREATE", "create", "Create"])).to_owned()];
    if g.bool() {
        tokens.push((*g.pick(&["OR", "or"])).to_owned());
        tokens.push((*g.pick(&["REPLACE", "replace"])).to_owned());
    }
    tokens.push((*g.pick(&["FUNCTION", "function", "PROCEDURE", "procedure"])).to_owned());
    tokens.push("f".to_owned());
    tokens.push("( a int , b text )".to_owned());
    tokens.extend(g.vec(0..=3, |g| token(g, HEADER_WORDS, 1)));
    if g.bool() {
        tokens.push((*g.pick(&["BEGIN", "begin"])).to_owned());
        tokens.push((*g.pick(&["ATOMIC", "atomic"])).to_owned());
        let body = g.vec(1..=3, |g| {
            let mut stmt = g.vec(1..=4, |g| token(g, BODY_WORDS, 1));
            // No statement in a body starts with `END`: the server reads
            // an `END` there as the end of the body.
            if stmt[0].eq_ignore_ascii_case("end") {
                stmt.insert(0, "select".to_owned());
            }
            if g.bool() {
                stmt.extend(
                    ["CASE", "WHEN", "x", "THEN", "1", "ELSE", "';'", "END"]
                        .iter()
                        .map(|s| (*s).to_owned()),
                );
            }
            stmt.push(";".to_owned());
            stmt
        });
        tokens.extend(body.into_iter().flatten());
        tokens.push((*g.pick(&["END", "end"])).to_owned());
    } else {
        tokens.push("AS".to_owned());
        tokens.push(dollar_string(g));
        tokens.push("LANGUAGE plpgsql".to_owned());
    }
    join(g, &tokens)
}

fn statement(g: &mut Gen) -> String {
    if g.weighted(&[4, 1]) == 0 {
        plain_statement(g)
    } else {
        routine_statement(g)
    }
}

/// A script from statements: fillers, semicolons and empty statements in
/// between, and an optional semicolon after the last one.
fn script(g: &mut Gen, statements: &[String]) -> String {
    let mut s = (*g.pick(FILLERS)).to_owned();
    if s.starts_with(" --") && !s.ends_with('\n') {
        s.push('\n');
    }
    for (i, stmt) in statements.iter().enumerate() {
        s.push_str(stmt);
        let last = i + 1 == statements.len();
        if !last || g.bool() {
            let before = *g.pick(FILLERS);
            s.push_str(before);
            if before.starts_with(" --") && !before.ends_with('\n') {
                s.push('\n');
            }
            s.push(';');
            for _ in 0..g.usize_in(0..=2) {
                s.push_str(g.pick(&[";", " ;", "\n;"]));
            }
        }
        let after = *g.pick(FILLERS);
        s.push_str(after);
        if !last && after.starts_with(" --") && !after.ends_with('\n') {
            s.push('\n');
        }
    }
    s
}

fn cfg() -> Config {
    Config::from_env()
}

/// TH-26: statements joined with semicolons and random comments split back
/// into the originals, with correct offsets and line numbers.
#[test]
fn th26_generated_statements_split_back_to_originals() {
    check_with("th26_split_round_trip", cfg().with_cases(2_000), |g| {
        let statements = g.vec(0..=6, statement);
        let sql = script(g, &statements);
        g.note("sql", &sql);
        let split = split_statements(&sql, &SplitLimits::default())
            .map_err(|e| format!("split failed: {e}"))?;
        let texts: Vec<&str> = split.iter().map(|s| s.text()).collect();
        prop_assert_eq!(texts, statements);
        for s in &split {
            prop_assert_eq!(&sql[s.offset()..s.offset() + s.text().len()], s.text());
            let line = sql[..s.offset()].matches('\n').count() + 1;
            prop_assert_eq!(s.line(), line);
        }
        Ok(())
    });
}

/// TH-26: splitting is stable. Each statement splits into itself, and the
/// statements joined again with `;\n` split into the same list.
#[test]
fn th26_splitting_is_idempotent() {
    check_with("th26_split_idempotent", cfg().with_cases(1_000), |g| {
        let statements = g.vec(1..=5, statement);
        let sql = script(g, &statements);
        g.note("sql", &sql);
        let limits = SplitLimits::default();
        let split = split_statements(&sql, &limits).map_err(|e| e.to_string())?;
        for s in &split {
            let again = split_statements(s.text(), &limits).map_err(|e| e.to_string())?;
            prop_assert_eq!(again.len(), 1);
            prop_assert_eq!(again[0].text(), s.text());
        }
        let joined = split
            .iter()
            .map(|s| s.text())
            .collect::<Vec<_>>()
            .join(";\n");
        let rejoined = split_statements(&joined, &limits).map_err(|e| e.to_string())?;
        prop_assert!(
            rejoined
                .iter()
                .map(|s| s.text())
                .eq(split.iter().map(|s| s.text()))
        );
        Ok(())
    });
}

/// TH-26: arbitrary text never makes the splitter panic, and every
/// statement it returns is an in-order, non-overlapping subslice of the
/// input that starts and ends with a token.
#[test]
fn th26_arbitrary_text_yields_ordered_subslices() {
    check_with("th26_split_arbitrary", cfg().with_cases(3_000), |g| {
        let sql: String = g
            .vec(0..=60, |g| {
                if g.weighted(&[3, 1]) == 0 {
                    (*g.pick(&[
                        "'", "\"", "$", "$$", "$a$", "--", "/*", "*/", ";", "(", ")", "E'", "\\",
                        "\n", " ", "begin", "atomic", "end", "case", "create", "function", "x",
                    ]))
                    .to_owned()
                } else {
                    g.char().to_string()
                }
            })
            .concat();
        g.note("sql", &sql);
        if let Ok(split) = split_statements(&sql, &SplitLimits::default()) {
            let base = sql.as_ptr() as usize;
            let mut end = 0usize;
            for s in &split {
                let start = s.text().as_ptr() as usize - base;
                prop_assert_eq!(start, s.offset());
                prop_assert!(start >= end, "statements overlap or are out of order");
                end = start + s.text().len();
                prop_assert!(end <= sql.len());
                prop_assert!(!s.text().is_empty());
                // The server's whitespace is ASCII only; other characters
                // from 0x80 up belong to identifiers. PostgreSQL 16 does not
                // count a vertical tab as whitespace.
                let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c');
                prop_assert!(!s.text().starts_with(space));
                prop_assert!(!s.text().ends_with(space));
                prop_assert!(!s.text().starts_with("--") && !s.text().starts_with("/*"));
            }
        }
        Ok(())
    });
}
