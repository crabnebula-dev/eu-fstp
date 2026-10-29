//! A source-level scanner of the `fstp-obs` type surface (R-NF-02).
//!
//! Rust has no runtime reflection, so the R-NF-02 tests read the crate's own
//! sources. The scanner collects every `enum`, `struct`, `union`, `type`
//! alias and numeric `const` in `src/`. It then walks every type that a root
//! such as `LogEvent` reaches through its fields. A field type passes only
//! when it is on a short allowlist: integers, `bool`, `Duration`,
//! `&'static str`, small fixed arrays, `Option` of those, and crate types
//! that pass the same rule. Anything else fails, including types the
//! scanner cannot resolve. The scanner errs towards refusing.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};

/// Largest fixed array a field may hold, in elements. A 16-byte id and a
/// 32-byte digest fit. A larger array could smuggle free text.
pub const MAX_ARRAY_LEN: u64 = 32;

/// A token of Rust source, with comments, literals and attributes reduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// An identifier or keyword.
    Ident(String),
    /// A lifetime, without the leading quote.
    Life(String),
    /// A numeric literal as written.
    Num(String),
    /// A string, byte string or character literal.
    Lit,
    /// `::`
    PathSep,
    /// `->`
    Arrow,
    /// `=>`
    FatArrow,
    /// Any other punctuation character.
    P(char),
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Ident(s) => write!(f, "{s}"),
            Tok::Life(s) => write!(f, "'{s}"),
            Tok::Num(s) => write!(f, "{s}"),
            Tok::Lit => write!(f, "\"..\""),
            Tok::PathSep => write!(f, "::"),
            Tok::Arrow => write!(f, "->"),
            Tok::FatArrow => write!(f, "=>"),
            Tok::P(c) => write!(f, "{c}"),
        }
    }
}

/// Renders tokens as readable source.
pub fn show(toks: &[Tok]) -> String {
    let mut out = String::new();
    for (i, t) in toks.iter().enumerate() {
        let glue = matches!(t, Tok::PathSep | Tok::P('<' | '>' | ',' | ';' | ']' | ')'))
            || matches!(
                toks.get(i.wrapping_sub(1)),
                Some(Tok::PathSep | Tok::P('<' | '&' | '[' | '('))
            )
            || i == 0;
        if !glue {
            out.push(' ');
        }
        out.push_str(&t.to_string());
    }
    out
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Tokenizes Rust source. Comments vanish, literals become [`Tok::Lit`].
pub fn tokenize(src: &str) -> Vec<Tok> {
    let s: Vec<char> = src.chars().collect();
    let n = s.len();
    let at = |i: usize| -> char { s.get(i).copied().unwrap_or('\0') };
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = s[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            while i < n && s[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0usize;
            while i < n {
                if s[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if s[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if (c == 'r' || (c == 'b' && at(i + 1) == 'r')) && {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            while at(j) == '#' {
                j += 1;
            }
            at(j) == '"' && (c == 'b' || j > i + 1 || at(i + 1) == '"')
        } {
            // Raw string: r"..", r#".."#, br#".."#.
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0usize;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
            j += 1;
            loop {
                if j >= n {
                    break;
                }
                if s[j] == '"' && (0..hashes).all(|k| at(j + 1 + k) == '#') {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            out.push(Tok::Lit);
            i = j;
        } else if c == '"' || (c == 'b' && at(i + 1) == '"') {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            while j < n && s[j] != '"' {
                if s[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            out.push(Tok::Lit);
            i = j + 1;
        } else if c == '\'' || (c == 'b' && at(i + 1) == '\'') {
            let q = if c == 'b' { i + 1 } else { i };
            if at(q + 1) == '\\' {
                let mut j = q + 2;
                while j < n && s[j] != '\'' {
                    j += 1;
                }
                out.push(Tok::Lit);
                i = j + 1;
            } else if at(q + 2) == '\'' {
                out.push(Tok::Lit);
                i = q + 3;
            } else {
                let mut j = q + 1;
                while j < n && is_ident_char(s[j]) {
                    j += 1;
                }
                out.push(Tok::Life(s[q + 1..j].iter().collect()));
                i = j;
            }
        } else if c == 'r' && at(i + 1) == '#' && is_ident_start(at(i + 2)) {
            let mut j = i + 2;
            while j < n && is_ident_char(s[j]) {
                j += 1;
            }
            out.push(Tok::Ident(s[i + 2..j].iter().collect()));
            i = j;
        } else if is_ident_start(c) {
            let mut j = i;
            while j < n && is_ident_char(s[j]) {
                j += 1;
            }
            out.push(Tok::Ident(s[i..j].iter().collect()));
            i = j;
        } else if c.is_ascii_digit() {
            let mut j = i;
            while j < n && is_ident_char(s[j]) {
                j += 1;
            }
            out.push(Tok::Num(s[i..j].iter().collect()));
            i = j;
        } else if c == ':' && at(i + 1) == ':' {
            out.push(Tok::PathSep);
            i += 2;
        } else if c == '-' && at(i + 1) == '>' {
            out.push(Tok::Arrow);
            i += 2;
        } else if c == '=' && at(i + 1) == '>' {
            out.push(Tok::FatArrow);
            i += 2;
        } else {
            out.push(Tok::P(c));
            i += 1;
        }
    }
    strip_attributes(out)
}

/// Removes `#[..]` and `#![..]`.
fn strip_attributes(toks: Vec<Tok>) -> Vec<Tok> {
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        if toks[i] == Tok::P('#') {
            let mut j = i + 1;
            if toks.get(j) == Some(&Tok::P('!')) {
                j += 1;
            }
            if toks.get(j) == Some(&Tok::P('[')) {
                let mut depth = 0usize;
                while j < toks.len() {
                    match toks[j] {
                        Tok::P('[') => depth += 1,
                        Tok::P(']') => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j + 1;
                continue;
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    out
}

/// What kind of item a definition is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `enum`
    Enum,
    /// `struct`
    Struct,
    /// `union`
    Union,
    /// `type X = ..;`
    Alias,
}

/// One field of a struct or enum variant.
#[derive(Clone, Debug)]
pub struct Field {
    /// `Type` or `Type::Variant`.
    pub owner: String,
    /// The variant name, for enum fields.
    pub variant: Option<String>,
    /// The field name, or `None` for a tuple field.
    pub name: Option<String>,
    /// The field type.
    pub ty: Vec<Tok>,
}

impl Field {
    /// `Owner.name` or `Owner.0`.
    pub fn place(&self, index: usize) -> String {
        match &self.name {
            Some(n) => format!("{}.{n}", self.owner),
            None => format!("{}.{index}", self.owner),
        }
    }
}

/// One item definition.
#[derive(Clone, Debug)]
pub struct Item {
    /// The item name.
    pub name: String,
    /// Its kind.
    pub kind: Kind,
    /// Whether it declares generic parameters (lifetimes included).
    pub generic: bool,
    /// Variant names, for enums.
    pub variants: Vec<String>,
    /// Fields, for structs, unions and enums.
    pub fields: Vec<Field>,
    /// The aliased type, for aliases.
    pub alias: Vec<Tok>,
    /// The file the item is in.
    pub file: String,
}

/// Every item and numeric constant found in a crate.
#[derive(Clone, Debug, Default)]
pub struct Defs {
    /// Items by name. A name defined twice keeps both.
    pub items: BTreeMap<String, Vec<Item>>,
    /// Numeric constants by name.
    pub consts: BTreeMap<String, u64>,
    /// Free functions by name: the first parameter's type.
    pub fn_first_param: BTreeMap<String, Vec<Tok>>,
}

fn matching(toks: &[Tok], open_at: usize) -> usize {
    let (open, close) = match toks[open_at] {
        Tok::P('(') => ('(', ')'),
        Tok::P('[') => ('[', ']'),
        Tok::P('{') => ('{', '}'),
        Tok::P('<') => ('<', '>'),
        _ => return open_at,
    };
    let mut depth = 0usize;
    let mut j = open_at;
    while j < toks.len() {
        if toks[j] == Tok::P(open) {
            depth += 1;
        } else if toks[j] == Tok::P(close) {
            depth -= 1;
            if depth == 0 {
                return j;
            }
        }
        j += 1;
    }
    toks.len().saturating_sub(1)
}

/// Splits at commas outside any bracket.
pub fn split_top(toks: &[Tok]) -> Vec<Vec<Tok>> {
    let mut parts = Vec::new();
    let mut cur = Vec::new();
    let mut depth = 0i64;
    for t in toks {
        match t {
            Tok::P('(' | '[' | '{' | '<') => depth += 1,
            Tok::P(')' | ']' | '}' | '>') => depth -= 1,
            Tok::P(',') if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(t.clone());
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

fn strip_vis(toks: &[Tok]) -> &[Tok] {
    if toks.first() == Some(&Tok::Ident("pub".into())) {
        if toks.get(1) == Some(&Tok::P('(')) {
            let close = matching(toks, 1);
            return &toks[close + 1..];
        }
        return &toks[1..];
    }
    toks
}

fn named_fields(owner: &str, variant: Option<&str>, body: &[Tok]) -> Vec<Field> {
    split_top(body)
        .iter()
        .filter_map(|part| {
            let part = strip_vis(part);
            match (part.first(), part.get(1)) {
                (Some(Tok::Ident(name)), Some(Tok::P(':'))) => Some(Field {
                    owner: owner.to_owned(),
                    variant: variant.map(str::to_owned),
                    name: Some(name.clone()),
                    ty: part[2..].to_vec(),
                }),
                _ => None,
            }
        })
        .collect()
}

fn tuple_fields(owner: &str, variant: Option<&str>, body: &[Tok]) -> Vec<Field> {
    split_top(body)
        .iter()
        .map(|part| Field {
            owner: owner.to_owned(),
            variant: variant.map(str::to_owned),
            name: None,
            ty: strip_vis(part).to_vec(),
        })
        .collect()
}

fn parse_num(s: &str) -> Option<u64> {
    let digits: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    digits.parse().ok()
}

/// Collects the definitions of one source file into `defs`.
pub fn collect(defs: &mut Defs, file: &str, toks: &[Tok]) {
    let mut i = 0;
    while i < toks.len() {
        let kw = match &toks[i] {
            Tok::Ident(k) => k.as_str(),
            _ => {
                i += 1;
                continue;
            }
        };
        let Some(Tok::Ident(name)) = toks.get(i + 1) else {
            i += 1;
            continue;
        };
        let name = name.clone();
        match kw {
            "enum" | "struct" | "union" => {
                let kind = match kw {
                    "enum" => Kind::Enum,
                    "struct" => Kind::Struct,
                    _ => Kind::Union,
                };
                let mut j = i + 2;
                let mut generic = false;
                if toks.get(j) == Some(&Tok::P('<')) {
                    generic = true;
                    j = matching(toks, j) + 1;
                }
                // Skip a where clause up to the body.
                while j < toks.len() && !matches!(toks[j], Tok::P('{' | '(' | ';')) {
                    j += 1;
                }
                let mut item = Item {
                    name: name.clone(),
                    kind,
                    generic,
                    variants: Vec::new(),
                    fields: Vec::new(),
                    alias: Vec::new(),
                    file: file.to_owned(),
                };
                let end = match toks.get(j) {
                    Some(Tok::P('{')) => {
                        let close = matching(toks, j);
                        let body = &toks[j + 1..close];
                        if kind == Kind::Enum {
                            for part in split_top(body) {
                                let Some(Tok::Ident(v)) = part.first() else {
                                    continue;
                                };
                                let owner = format!("{name}::{v}");
                                item.variants.push(v.clone());
                                match part.get(1) {
                                    Some(Tok::P('(')) => {
                                        let c = matching(&part, 1);
                                        item.fields.extend(tuple_fields(
                                            &owner,
                                            Some(v),
                                            &part[2..c],
                                        ));
                                    }
                                    Some(Tok::P('{')) => {
                                        let c = matching(&part, 1);
                                        item.fields.extend(named_fields(
                                            &owner,
                                            Some(v),
                                            &part[2..c],
                                        ));
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            item.fields = named_fields(&name, None, body);
                        }
                        close
                    }
                    Some(Tok::P('(')) => {
                        let close = matching(toks, j);
                        item.fields = tuple_fields(&name, None, &toks[j + 1..close]);
                        close
                    }
                    _ => j,
                };
                defs.items.entry(name).or_default().push(item);
                i = end + 1;
            }
            "type" => {
                let mut j = i + 2;
                let mut generic = false;
                if toks.get(j) == Some(&Tok::P('<')) {
                    generic = true;
                    j = matching(toks, j) + 1;
                }
                if toks.get(j) == Some(&Tok::P('=')) {
                    let start = j + 1;
                    let mut k = start;
                    while k < toks.len() && toks[k] != Tok::P(';') {
                        k += 1;
                    }
                    defs.items.entry(name.clone()).or_default().push(Item {
                        name,
                        kind: Kind::Alias,
                        generic,
                        variants: Vec::new(),
                        fields: Vec::new(),
                        alias: toks[start..k].to_vec(),
                        file: file.to_owned(),
                    });
                    i = k + 1;
                } else {
                    i = j;
                }
            }
            "const" | "static" => {
                // const NAME: ty = 16;
                let mut j = i + 2;
                while j < toks.len() && toks[j] != Tok::P('=') && toks[j] != Tok::P(';') {
                    j += 1;
                }
                if let (Some(Tok::P('=')), Some(Tok::Num(v)), Some(Tok::P(';'))) =
                    (toks.get(j), toks.get(j + 1), toks.get(j + 2))
                    && let Some(v) = parse_num(v)
                {
                    defs.consts.insert(name, v);
                }
                i += 2;
            }
            "fn" => {
                let mut j = i + 2;
                if toks.get(j) == Some(&Tok::P('<')) {
                    j = matching(toks, j) + 1;
                }
                if toks.get(j) == Some(&Tok::P('(')) {
                    let close = matching(toks, j);
                    let params = split_top(&toks[j + 1..close]);
                    if let Some(first) = params.first()
                        && let Some(colon) = first.iter().position(|t| *t == Tok::P(':'))
                    {
                        defs.fn_first_param
                            .entry(name)
                            .or_insert_with(|| first[colon + 1..].to_vec());
                    }
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
}

/// Reads every `.rs` file under `dir`, sorted by path.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The definitions of the `fstp-obs` sources under test.
pub fn crate_defs() -> Defs {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&src);
    assert!(!files.is_empty(), "no sources under {}", src.display());
    let mut defs = Defs::default();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        collect(&mut defs, &f.display().to_string(), &tokenize(&text));
    }
    defs
}

/// Definitions parsed from a source string. Used by the teeth tests.
pub fn defs_from(src: &str) -> Defs {
    let mut defs = Defs::default();
    collect(&mut defs, "<seeded>", &tokenize(src));
    defs
}

/// A field type that breaks the R-NF-02 surface rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Where: `Type::Variant.field`, or the item name.
    pub at: String,
    /// The offending type as written.
    pub ty: String,
    /// Why it fails.
    pub reason: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: `{}`: {}", self.at, self.ty, self.reason)
    }
}

/// Names that can carry free text or unbounded bytes, with the reason.
const FORBIDDEN: &[(&str, &str)] = &[
    ("String", "owned free text"),
    ("str", "free text without a 'static bound"),
    ("char", "a text character"),
    ("Vec", "unbounded collection"),
    ("VecDeque", "unbounded collection"),
    ("LinkedList", "unbounded collection"),
    ("BinaryHeap", "unbounded collection"),
    ("HashMap", "unbounded collection"),
    ("BTreeMap", "unbounded collection"),
    ("HashSet", "unbounded collection"),
    ("BTreeSet", "unbounded collection"),
    ("Box", "heap value, can hold any text"),
    ("Rc", "shared heap value"),
    ("Arc", "shared heap value"),
    ("Cow", "borrowed or owned text"),
    ("OsString", "operating system text"),
    ("OsStr", "operating system text"),
    ("PathBuf", "a concrete path, not a route template"),
    ("Path", "a concrete path, not a route template"),
    ("CString", "C text"),
    ("CStr", "C text"),
    ("Arguments", "formatted text"),
    ("Error", "an error value can carry any message"),
    ("f32", "floats are not allowed"),
    ("f64", "floats are not allowed"),
    ("Self", "self reference cannot be checked"),
];

const INTEGERS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

const NONZERO: &[&str] = &[
    "NonZeroU8",
    "NonZeroU16",
    "NonZeroU32",
    "NonZeroU64",
    "NonZeroU128",
    "NonZeroUsize",
    "NonZeroI8",
    "NonZeroI16",
    "NonZeroI32",
    "NonZeroI64",
    "NonZeroI128",
    "NonZeroIsize",
];

const STD_ROOTS: &[&str] = &["std", "core", "alloc"];
const LOCAL_ROOTS: &[&str] = &["crate", "self", "super"];

/// Whether a type is a value: an integer, `NonZero*` or `Duration`, or an
/// `Option` of one. Values are what metrics count and time.
pub fn is_value_type(ty: &[Tok]) -> bool {
    let idents: Vec<&str> = ty
        .iter()
        .filter_map(|t| match t {
            Tok::Ident(s) => Some(s.as_str()),
            _ => None,
        })
        .filter(|s| !STD_ROOTS.contains(s) && *s != "time" && *s != "num" && *s != "Option")
        .collect();
    idents.len() == 1
        && (INTEGERS.contains(&idents[0])
            || NONZERO.contains(&idents[0])
            || idents[0] == "Duration")
}

/// Whether the type is exactly `&'static str`.
pub fn is_static_str(ty: &[Tok]) -> bool {
    ty == [
        Tok::P('&'),
        Tok::Life("static".into()),
        Tok::Ident("str".into()),
    ]
}

/// The last path segment of a simple path type, if it is one.
pub fn last_segment(ty: &[Tok]) -> Option<&str> {
    let mut last = None;
    for t in ty {
        match t {
            Tok::Ident(s) => last = Some(s.as_str()),
            Tok::PathSep => {}
            Tok::P('<') => break,
            _ => return None,
        }
    }
    last
}

struct TypeCheck<'a> {
    defs: &'a Defs,
    toks: &'a [Tok],
    pos: usize,
    refs: BTreeSet<String>,
}

impl TypeCheck<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, want: &Tok) -> Result<(), String> {
        match self.bump() {
            Some(t) if &t == want => Ok(()),
            other => Err(format!(
                "cannot parse the type: wanted `{want}`, found {other:?}"
            )),
        }
    }

    fn ty(&mut self) -> Result<(), String> {
        match self.bump() {
            None => Err("empty type".into()),
            Some(Tok::P('&')) => {
                let life = match self.peek() {
                    Some(Tok::Life(l)) => {
                        let l = l.clone();
                        self.pos += 1;
                        Some(l)
                    }
                    _ => None,
                };
                if self.peek() == Some(&Tok::Ident("mut".into())) {
                    return Err("mutable reference".into());
                }
                let inner_is_str = self.peek() == Some(&Tok::Ident("str".into()))
                    && self.toks.get(self.pos + 1) != Some(&Tok::PathSep);
                if life.as_deref() == Some("static") && inner_is_str {
                    self.pos += 1;
                    return Ok(());
                }
                if inner_is_str {
                    return Err(
                        "a borrowed str that is not &'static str can be request text".into(),
                    );
                }
                Err("only &'static str may be borrowed; any other reference can point at request data".into())
            }
            Some(Tok::P('(')) => {
                if self.peek() == Some(&Tok::P(')')) {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.ty()?;
                    match self.bump() {
                        Some(Tok::P(',')) => {
                            if self.peek() == Some(&Tok::P(')')) {
                                self.pos += 1;
                                return Ok(());
                            }
                        }
                        Some(Tok::P(')')) => return Ok(()),
                        other => return Err(format!("cannot parse tuple: {other:?}")),
                    }
                }
            }
            Some(Tok::P('[')) => {
                self.ty()?;
                match self.bump() {
                    Some(Tok::P(';')) => {}
                    _ => return Err("a slice is unbounded bytes or values".into()),
                }
                let len = match self.bump() {
                    Some(Tok::Num(n)) => parse_num(&n),
                    Some(Tok::Ident(c)) => self.defs.consts.get(&c).copied(),
                    _ => None,
                };
                self.expect(&Tok::P(']'))?;
                match len {
                    Some(n) if n <= MAX_ARRAY_LEN => Ok(()),
                    Some(n) => Err(format!(
                        "array of {n} elements exceeds {MAX_ARRAY_LEN} and can smuggle free text"
                    )),
                    None => Err("array length is not a resolvable numeric constant".into()),
                }
            }
            Some(Tok::P('*')) => Err("raw pointer".into()),
            Some(Tok::P('!')) => Err("never type".into()),
            Some(Tok::P('<')) => Err("qualified path type cannot be checked".into()),
            Some(Tok::PathSep) => self.path(None),
            Some(Tok::Ident(first)) => match first.as_str() {
                "fn" | "dyn" | "impl" | "unsafe" | "extern" | "for" | "_" => {
                    Err(format!("`{first}` type can carry anything"))
                }
                _ => self.path(Some(first)),
            },
            Some(other) => Err(format!("cannot parse the type at {other:?}")),
        }
    }

    fn path(&mut self, first: Option<String>) -> Result<(), String> {
        let mut segs = Vec::new();
        match first {
            Some(f) => segs.push(f),
            None => match self.bump() {
                Some(Tok::Ident(s)) => segs.push(s),
                other => return Err(format!("cannot parse path at {other:?}")),
            },
        }
        while self.peek() == Some(&Tok::PathSep) {
            match self.toks.get(self.pos + 1) {
                Some(Tok::Ident(s)) => {
                    segs.push(s.clone());
                    self.pos += 2;
                }
                _ => break,
            }
        }
        let Some(name) = segs.last().cloned() else {
            return Err("empty path".into());
        };
        let mut args: Vec<Vec<Tok>> = Vec::new();
        if self.peek() == Some(&Tok::P('<')) {
            let close = matching(self.toks, self.pos);
            args = split_top(&self.toks[self.pos + 1..close]);
            self.pos = close + 1;
        }
        let root = segs[0].as_str();
        let external = segs.len() > 1 && !STD_ROOTS.contains(&root) && !LOCAL_ROOTS.contains(&root);
        let from_std = STD_ROOTS.contains(&root);
        if external {
            return Err(format!(
                "type from another crate (`{root}`) is outside the checked surface"
            ));
        }
        if let Some((_, why)) = FORBIDDEN.iter().find(|(n, _)| *n == name) {
            return Err((*why).to_owned());
        }
        let local = self.defs.items.contains_key(&name) && !from_std;
        if local {
            if !args.is_empty() {
                return Err("generic arguments on a crate type".into());
            }
            self.refs.insert(name);
            return Ok(());
        }
        if INTEGERS.contains(&name.as_str()) || name == "bool" || NONZERO.contains(&name.as_str()) {
            return no_args(&args);
        }
        if name == "Duration" {
            return no_args(&args);
        }
        if name == "Option" || name == "NonZero" {
            if args.len() != 1 {
                return Err(format!("{name} needs one type argument"));
            }
            let arg = args.remove(0);
            if name == "NonZero"
                && !arg
                    .iter()
                    .all(|t| matches!(t, Tok::Ident(s) if INTEGERS.contains(&s.as_str())))
            {
                return Err("NonZero of a non-integer".into());
            }
            let mut inner = TypeCheck {
                defs: self.defs,
                toks: &arg,
                pos: 0,
                refs: BTreeSet::new(),
            };
            inner.ty()?;
            if inner.pos != arg.len() {
                return Err("trailing tokens in type argument".into());
            }
            self.refs.extend(inner.refs);
            return Ok(());
        }
        Err(format!(
            "`{name}` is neither on the allowlist nor defined in fstp-obs"
        ))
    }
}

fn no_args(args: &[Vec<Tok>]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err("unexpected type arguments".into())
    }
}

/// Checks one field type. On success, returns the crate types it names.
pub fn check_type(defs: &Defs, ty: &[Tok]) -> Result<BTreeSet<String>, String> {
    let mut tc = TypeCheck {
        defs,
        toks: ty,
        pos: 0,
        refs: BTreeSet::new(),
    };
    tc.ty()?;
    if tc.pos != ty.len() {
        return Err(format!(
            "trailing tokens after the type: `{}`",
            show(&ty[tc.pos..])
        ));
    }
    Ok(tc.refs)
}

/// The result of walking the closure of one or more roots.
#[derive(Clone, Debug, Default)]
pub struct Surface {
    /// Every rule violation.
    pub violations: Vec<Violation>,
    /// Every field reached, with its place.
    pub fields: Vec<(String, Field)>,
    /// Every item reached.
    pub items: Vec<Item>,
}

/// Walks every type `roots` reach and checks each field (R-NF-02).
pub fn surface(defs: &Defs, roots: &[&str]) -> Surface {
    let mut out = Surface::default();
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for r in roots {
        match defs.items.get(*r) {
            None => out.violations.push(Violation {
                at: (*r).to_owned(),
                ty: String::new(),
                reason: "named in design section 11.1 but not defined in fstp-obs".into(),
            }),
            Some(items) => {
                for it in items {
                    if it.kind != Kind::Enum {
                        out.violations.push(Violation {
                            at: (*r).to_owned(),
                            ty: format!("{:?}", it.kind),
                            reason: "design section 11.1 makes it a closed enum".into(),
                        });
                    }
                }
                queue.push_back((*r).to_owned());
            }
        }
    }
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(items) = defs.items.get(&name) else {
            continue;
        };
        for it in items {
            out.items.push(it.clone());
            if it.generic {
                out.violations.push(Violation {
                    at: name.clone(),
                    ty: String::new(),
                    reason: "a generic type can carry any type argument".into(),
                });
            }
            if it.kind == Kind::Union {
                out.violations.push(Violation {
                    at: name.clone(),
                    ty: String::new(),
                    reason: "a union reinterprets bytes".into(),
                });
            }
            let mut checks: Vec<(String, Vec<Tok>, Option<Field>)> = Vec::new();
            if it.kind == Kind::Alias {
                checks.push((format!("type {name}"), it.alias.clone(), None));
            }
            let mut index_by_owner: BTreeMap<String, usize> = BTreeMap::new();
            for f in &it.fields {
                let idx = index_by_owner.entry(f.owner.clone()).or_insert(0);
                let place = f.place(*idx);
                *idx += 1;
                checks.push((place, f.ty.clone(), Some(f.clone())));
            }
            for (place, ty, field) in checks {
                if let Some(f) = field {
                    out.fields.push((place.clone(), f));
                }
                match check_type(defs, &ty) {
                    Ok(refs) => queue.extend(refs),
                    Err(reason) => out.violations.push(Violation {
                        at: place,
                        ty: show(&ty),
                        reason,
                    }),
                }
            }
        }
    }
    out
}

/// Renders violations one per line.
pub fn report(v: &[Violation]) -> String {
    v.iter().map(|x| format!("  {x}\n")).collect()
}
