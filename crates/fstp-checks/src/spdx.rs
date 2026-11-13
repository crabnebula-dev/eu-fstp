//! SPDX licence expressions (SPDX 2.3 Annex D), parsed strictly and
//! within fixed bounds (TH-26).
//!
//! - Operators are `AND`, `OR` and `WITH`, upper case only. `WITH` binds
//!   tighter than `AND`, and `AND` tighter than `OR`. Both binary
//!   operators associate to the left.
//! - An identifier is 1*(ALPHA / DIGIT / "-" / "."), optionally followed by
//!   one `+`. `LicenseRef-` and `DocumentRef-…:LicenseRef-` references are
//!   kept as references. The parser does not hold the SPDX licence list, so
//!   P-26 is the gate on which identifiers count (R-PR-02).
//! - The input and its canonical form are each at most [`MAX_LEN`] bytes,
//!   and the input nests at most [`MAX_DEPTH`] parentheses.

use std::fmt;

use fstp_domain::policy::LicenceSet;

/// The longest expression the parser reads, in bytes.
pub const MAX_LEN: usize = 512;
/// The deepest nesting of parentheses the parser reads.
pub const MAX_DEPTH: usize = 16;
/// The longest identifier, in bytes.
const MAX_ID: usize = 96;

/// A parsed licence expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// A licence identifier, with `+` for "or any later version".
    Licence {
        /// The identifier as written.
        id: String,
        /// Whether it ends in `+`.
        or_later: bool,
    },
    /// A `LicenseRef-` reference, with its optional `DocumentRef-` prefix.
    Ref(String),
    /// A licence with an exception.
    With {
        /// The licence: a [`Expr::Licence`] or [`Expr::Ref`].
        licence: Box<Expr>,
        /// The exception identifier.
        exception: String,
    },
    /// Both operands apply.
    And(Box<Expr>, Box<Expr>),
    /// Either operand applies.
    Or(Box<Expr>, Box<Expr>),
}

/// Why an expression was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpdxError {
    /// No expression.
    Empty,
    /// Longer than [`MAX_LEN`], as written or in canonical form.
    TooLong,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A byte outside the expression alphabet, at this offset.
    BadChar(usize),
    /// A malformed identifier or reference, at this token.
    BadId(usize),
    /// A token that does not fit the grammar, at this token.
    Unexpected(usize),
    /// The expression ended early.
    Truncated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok<'a> {
    Open,
    Close,
    And,
    Or,
    With,
    Word(&'a str),
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+' | b':')
}

fn tokens(s: &str) -> Result<Vec<Tok<'_>>, SpdxError> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b' ' | b'\t' => i = i.saturating_add(1),
            b'(' => {
                out.push(Tok::Open);
                i = i.saturating_add(1);
            }
            b')' => {
                out.push(Tok::Close);
                i = i.saturating_add(1);
            }
            b if word_byte(b) => {
                let start = i;
                while bytes.get(i).copied().is_some_and(word_byte) {
                    i = i.saturating_add(1);
                }
                let w = s.get(start..i).ok_or(SpdxError::BadChar(start))?;
                out.push(match w {
                    "AND" => Tok::And,
                    "OR" => Tok::Or,
                    "WITH" => Tok::With,
                    _ => Tok::Word(w),
                });
            }
            _ => return Err(SpdxError::BadChar(i)),
        }
    }
    Ok(out)
}

fn idstring(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn simple(w: &str, at: usize) -> Result<Expr, SpdxError> {
    if let Some(rest) = w.strip_prefix("DocumentRef-") {
        let (doc, lic) = rest.split_once(':').ok_or(SpdxError::BadId(at))?;
        let r = lic
            .strip_prefix("LicenseRef-")
            .ok_or(SpdxError::BadId(at))?;
        if idstring(doc) && idstring(r) {
            return Ok(Expr::Ref(w.to_owned()));
        }
        return Err(SpdxError::BadId(at));
    }
    if let Some(r) = w.strip_prefix("LicenseRef-") {
        if idstring(r) {
            return Ok(Expr::Ref(w.to_owned()));
        }
        return Err(SpdxError::BadId(at));
    }
    let (id, or_later) = match w.strip_suffix('+') {
        Some(id) => (id, true),
        None => (w, false),
    };
    if idstring(id) {
        Ok(Expr::Licence {
            id: id.to_owned(),
            or_later,
        })
    } else {
        Err(SpdxError::BadId(at))
    }
}

struct Parser<'a> {
    toks: Vec<Tok<'a>>,
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok<'a>> {
        self.toks.get(self.at)
    }

    fn bump(&mut self) -> Option<Tok<'a>> {
        let t = self.toks.get(self.at).cloned();
        self.at = self.at.saturating_add(1);
        t
    }

    fn or(&mut self, depth: usize) -> Result<Expr, SpdxError> {
        let mut left = self.and(depth)?;
        while self.peek() == Some(&Tok::Or) {
            self.bump();
            let right = self.and(depth)?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize) -> Result<Expr, SpdxError> {
        let mut left = self.with(depth)?;
        while self.peek() == Some(&Tok::And) {
            self.bump();
            let right = self.with(depth)?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn with(&mut self, depth: usize) -> Result<Expr, SpdxError> {
        let at = self.at;
        let e = self.atom(depth)?;
        if self.peek() != Some(&Tok::With) {
            return Ok(e);
        }
        if !matches!(e, Expr::Licence { .. } | Expr::Ref(_)) {
            return Err(SpdxError::Unexpected(at));
        }
        self.bump();
        let at = self.at;
        match self.bump() {
            Some(Tok::Word(x)) if idstring(x) && !x.starts_with("LicenseRef-") => Ok(Expr::With {
                licence: Box::new(e),
                exception: x.to_owned(),
            }),
            Some(_) => Err(SpdxError::BadId(at)),
            None => Err(SpdxError::Truncated),
        }
    }

    fn atom(&mut self, depth: usize) -> Result<Expr, SpdxError> {
        let at = self.at;
        match self.bump() {
            Some(Tok::Open) => {
                let depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(SpdxError::TooDeep);
                }
                let e = self.or(depth)?;
                match self.bump() {
                    Some(Tok::Close) => Ok(e),
                    Some(_) => Err(SpdxError::Unexpected(self.at.saturating_sub(1))),
                    None => Err(SpdxError::Truncated),
                }
            }
            Some(Tok::Word(w)) => simple(w, at),
            Some(_) => Err(SpdxError::Unexpected(at)),
            None => Err(SpdxError::Truncated),
        }
    }
}

/// Parses `s` as an SPDX licence expression.
///
/// # Errors
///
/// A [`SpdxError`] for empty, oversized, too deep or malformed input.
pub fn parse(s: &str) -> Result<Expr, SpdxError> {
    if s.len() > MAX_LEN {
        return Err(SpdxError::TooLong);
    }
    let toks = tokens(s)?;
    if toks.is_empty() {
        return Err(SpdxError::Empty);
    }
    let mut p = Parser { toks, at: 0 };
    let e = p.or(0)?;
    if p.at < p.toks.len() {
        return Err(SpdxError::Unexpected(p.at));
    }
    // The canonical form can be longer than the input, since it puts a
    // space on both sides of every operator. Refusing it here keeps every
    // accepted expression within reach of its own canonical form.
    if rendered_len(&e) > MAX_LEN {
        return Err(SpdxError::TooLong);
    }
    Ok(e)
}

/// Counts the bytes of a rendering without keeping them.
struct Counter(usize);

impl fmt::Write for Counter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 = self.0.saturating_add(s.len());
        Ok(())
    }
}

fn rendered_len(e: &Expr) -> usize {
    let mut c = Counter(0);
    // Counter never fails, and the Display impl only forwards its errors.
    let _ = fmt::Write::write_fmt(&mut c, format_args!("{e}"));
    c.0
}

fn listed(set: &LicenceSet, id: &str) -> bool {
    set.0.iter().any(|s| s.0.eq_ignore_ascii_case(id))
}

impl Expr {
    /// Whether the expression is accepted under P-26 (interim reading,
    /// pending Daniel):
    ///
    /// - an identifier is accepted when P-26 lists it, without case; `X+`
    ///   when P-26 lists `X+` or `X`;
    /// - a licence reference is never accepted, since P-26 holds exact SPDX
    ///   identifiers;
    /// - `X WITH E` when `X` is accepted, since an exception only adds
    ///   permissions;
    /// - `A AND B` when both are, `A OR B` when either is.
    pub fn accepted(&self, set: &LicenceSet) -> bool {
        match self {
            Expr::Licence { id, or_later } => {
                listed(set, id) || (*or_later && listed(set, &format!("{id}+")))
            }
            Expr::Ref(_) => false,
            Expr::With { licence, .. } => licence.accepted(set),
            Expr::And(a, b) => a.accepted(set) && b.accepted(set),
            Expr::Or(a, b) => a.accepted(set) || b.accepted(set),
        }
    }

    /// Whether `self` and `other` state the same licensing: identifiers
    /// compare without case, and the operands of `AND` and `OR` in either
    /// order.
    pub fn same(&self, other: &Expr) -> bool {
        match (self, other) {
            (Expr::Licence { id: a, or_later: x }, Expr::Licence { id: b, or_later: y }) => {
                a.eq_ignore_ascii_case(b) && x == y
            }
            (Expr::Ref(a), Expr::Ref(b)) => a.eq_ignore_ascii_case(b),
            (
                Expr::With {
                    licence: a,
                    exception: x,
                },
                Expr::With {
                    licence: b,
                    exception: y,
                },
            ) => a.same(b) && x.eq_ignore_ascii_case(y),
            (Expr::And(a, b), Expr::And(c, d)) | (Expr::Or(a, b), Expr::Or(c, d)) => {
                (a.same(c) && b.same(d)) || (a.same(d) && b.same(c))
            }
            _ => false,
        }
    }
}

/// The canonical form: single spaces, and parentheses only where the
/// tree needs them, so parsing it gives the same tree.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Licence { id, or_later } => {
                write!(f, "{id}{}", if *or_later { "+" } else { "" })
            }
            Expr::Ref(r) => f.write_str(r),
            Expr::With { licence, exception } => write!(f, "{licence} WITH {exception}"),
            Expr::And(a, b) => {
                wrap(f, a, matches!(**a, Expr::Or(..)))?;
                f.write_str(" AND ")?;
                wrap(f, b, matches!(**b, Expr::Or(..) | Expr::And(..)))
            }
            Expr::Or(a, b) => {
                wrap(f, a, false)?;
                f.write_str(" OR ")?;
                wrap(f, b, matches!(**b, Expr::Or(..)))
            }
        }
    }
}

fn wrap(f: &mut fmt::Formatter<'_>, e: &Expr, parens: bool) -> fmt::Result {
    if parens {
        write!(f, "({e})")
    } else {
        write!(f, "{e}")
    }
}
