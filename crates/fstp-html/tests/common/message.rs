//! Catalogue messages: the grammar, a reference formatter and fixtures
//! (R-NF-04, I-72).
//!
//! Interim reading, pending Daniel. The design names the catalogue syntax
//! (`message_format_parse`) but not its grammar. This module fixes it, and
//! `testdata/message_format.corpus` shares it with the TypeScript
//! `i18n.ts` target of lane W1c:
//!
//! - a message is valid UTF-8 of 1 to 4096 bytes, of plain characters;
//! - `{name}` is a placeholder, where `name` is a lower-case ASCII letter
//!   then up to 31 lower-case letters, digits or `_`;
//! - `{{` and `}}` stand for literal braces;
//! - any other `{` or `}` is an error.
//!
//! A catalogue set has one default locale and other locales. Every locale
//! defines exactly the ids of the default locale, with the same kind and
//! the same placeholder names. Each id is a `Label` (an interface string,
//! which a terminology override may replace) or an `ApprovedText`
//! (approved wording, which no override reaches, I-72).

use std::collections::BTreeSet;

use super::chars::is_plain;

/// The longest message, in bytes.
pub(crate) const MAX_MESSAGE_BYTES: usize = 4096;
/// The longest placeholder name, in bytes.
pub(crate) const MAX_NAME_BYTES: usize = 32;

/// One part of a parsed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// Literal text, with `{{` and `}}` already decoded.
    Lit(String),
    /// A placeholder.
    Arg(String),
}

/// The kind of a catalogue entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kind {
    /// An interface string. Terminology overrides apply (I-72).
    Label,
    /// Approved wording. Overrides never apply (I-72).
    Approved,
}

/// Parses one message with the reference grammar.
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Part>, String> {
    if bytes.is_empty() {
        return Err("empty message".to_owned());
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(format!("message of {} bytes", bytes.len()));
    }
    let s = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    if let Some(c) = s.chars().find(|&c| !is_plain(c)) {
        return Err(format!("U+{:04X} is not plain", u32::from(c)));
    }
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut it = s.char_indices().peekable();
    while let Some((at, c)) = it.next() {
        match c {
            '{' if it.peek().map(|&(_, n)| n) == Some('{') => {
                it.next();
                lit.push('{');
            }
            '}' if it.peek().map(|&(_, n)| n) == Some('}') => {
                it.next();
                lit.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match it.next() {
                        Some((_, '}')) => break,
                        Some((_, n)) => name.push(n),
                        None => return Err(format!("unclosed placeholder at byte {at}")),
                    }
                }
                if !is_name(&name) {
                    return Err(format!("bad placeholder name {name:?} at byte {at}"));
                }
                if !lit.is_empty() {
                    parts.push(Part::Lit(std::mem::take(&mut lit)));
                }
                parts.push(Part::Arg(name));
            }
            '}' => return Err(format!("lone }} at byte {at}")),
            _ => lit.push(c),
        }
    }
    if !lit.is_empty() {
        parts.push(Part::Lit(lit));
    }
    Ok(parts)
}

fn is_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME_BYTES
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// The placeholder names of a parsed message.
pub(crate) fn names(parts: &[Part]) -> BTreeSet<String> {
    parts
        .iter()
        .filter_map(|p| match p {
            Part::Arg(n) => Some(n.clone()),
            Part::Lit(_) => None,
        })
        .collect()
}

/// Formats `parts` with `args`. The argument names must equal the
/// placeholder names exactly, each given once.
pub(crate) fn format(parts: &[Part], args: &[(String, String)]) -> Result<String, String> {
    let given: BTreeSet<String> = args.iter().map(|(n, _)| n.clone()).collect();
    if given.len() != args.len() {
        return Err("an argument is given twice".to_owned());
    }
    if given != names(parts) {
        return Err(format!(
            "arguments {given:?} differ from placeholders {:?}",
            names(parts)
        ));
    }
    let mut out = String::new();
    for p in parts {
        match p {
            Part::Lit(l) => out.push_str(l),
            Part::Arg(n) => {
                let v = args
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                out.push_str(v);
            }
        }
    }
    Ok(out)
}

/// The argument names of `parts` in order of use, one per occurrence.
pub(crate) fn uses(parts: &[Part]) -> Vec<String> {
    parts
        .iter()
        .filter_map(|p| match p {
            Part::Arg(n) => Some(n.clone()),
            Part::Lit(_) => None,
        })
        .collect()
}

/// One catalogue entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The message id.
    pub(crate) id: String,
    /// Label or approved wording.
    pub(crate) kind: Kind,
    /// The message source.
    pub(crate) message: String,
}

/// The catalogue of one locale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocaleCat {
    /// The locale, a language tag.
    pub(crate) locale: String,
    /// The entries.
    pub(crate) entries: Vec<Entry>,
}

impl LocaleCat {
    /// The entry for `id`, if any.
    pub(crate) fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }
}

/// A catalogue set: the default locale first, then the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatSpec {
    /// The default locale's catalogue.
    pub(crate) default: LocaleCat,
    /// Every other locale's catalogue.
    pub(crate) others: Vec<LocaleCat>,
}

impl CatSpec {
    /// The catalogue of `locale`.
    pub(crate) fn locale(&self, locale: &str) -> Option<&LocaleCat> {
        std::iter::once(&self.default)
            .chain(self.others.iter())
            .find(|c| c.locale == locale)
    }

    /// Every locale, the default first.
    pub(crate) fn locales(&self) -> Vec<&str> {
        std::iter::once(&self.default)
            .chain(self.others.iter())
            .map(|c| c.locale.as_str())
            .collect()
    }

    /// The reference resolution of `id` in `locale`: kind check, parse
    /// and format.
    pub(crate) fn resolve(
        &self,
        locale: &str,
        kind: Kind,
        id: &str,
        args: &[(String, String)],
    ) -> Result<(String, Vec<String>), String> {
        let cat = self
            .locale(locale)
            .ok_or_else(|| format!("no locale {locale}"))?;
        let e = cat.get(id).ok_or_else(|| format!("no id {id}"))?;
        if e.kind != kind {
            return Err(format!("{id} is {:?}, not {kind:?}", e.kind));
        }
        let parts = parse(e.message.as_bytes())?;
        let text = format(&parts, args)?;
        Ok((text, uses(&parts)))
    }

    /// The reference check of a catalogue set: the rules of the module
    /// documentation.
    pub(crate) fn check(&self) -> Result<(), String> {
        let mut seen = BTreeSet::new();
        for c in std::iter::once(&self.default).chain(self.others.iter()) {
            if !super::reference::is_lang_tag(&c.locale) {
                return Err(format!("locale {:?} is not a language tag", c.locale));
            }
            if !seen.insert(c.locale.to_ascii_lowercase()) {
                return Err(format!("locale {} twice", c.locale));
            }
            let mut ids = BTreeSet::new();
            for e in &c.entries {
                if !ids.insert(e.id.as_str()) {
                    return Err(format!("{}: id {} twice", c.locale, e.id));
                }
                parse(e.message.as_bytes()).map_err(|m| format!("{}: {}: {m}", c.locale, e.id))?;
            }
        }
        for c in &self.others {
            if c.entries.len() != self.default.entries.len() {
                return Err(format!("{} does not hold every default id", c.locale));
            }
            for d in &self.default.entries {
                let e = c
                    .get(&d.id)
                    .ok_or_else(|| format!("{} lacks {}", c.locale, d.id))?;
                if e.kind != d.kind {
                    return Err(format!("{}: {} changes kind", c.locale, d.id));
                }
                let dn = names(&parse(d.message.as_bytes())?);
                let en = names(&parse(e.message.as_bytes())?);
                if dn != en {
                    return Err(format!("{}: {} changes placeholders", c.locale, d.id));
                }
            }
        }
        Ok(())
    }
}

/// A terminology override of one entry in one locale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Override {
    /// The locale.
    pub(crate) locale: String,
    /// The id overridden.
    pub(crate) id: String,
    /// The replacement message source.
    pub(crate) message: String,
}

/// An entry of a fixture.
pub(crate) fn entry(id: &str, kind: Kind, message: &str) -> Entry {
    Entry {
        id: id.to_owned(),
        kind,
        message: message.to_owned(),
    }
}

/// The fixture catalogue set: English by default, and French. Its
/// literals hold characters every context must escape. The approved
/// wording is synthetic, never legal text.
pub(crate) fn fixture() -> CatSpec {
    use Kind::{Approved, Label};
    CatSpec {
        default: LocaleCat {
            locale: "en".to_owned(),
            entries: vec![
                entry("nav.home", Label, "Home"),
                entry("call.deadline", Label, "Deadline: {date}"),
                entry(
                    "call.budget",
                    Label,
                    "Budget & costs <up to> {amount} \"EUR\" {{fixed}}",
                ),
                entry("form.name", Label, "Name's field"),
                entry(
                    "notice.synthetic",
                    Approved,
                    "SYNTHETIC TEST WORDING for {org}, version {version}. NOT LEGAL TEXT.",
                ),
                entry(
                    "guide.synthetic",
                    Approved,
                    "SYNTHETIC GUIDE WORDING: apply before {date} & read <all> of it.",
                ),
            ],
        },
        others: vec![LocaleCat {
            locale: "fr".to_owned(),
            entries: vec![
                entry("nav.home", Label, "Accueil"),
                entry("call.deadline", Label, "Date limite\u{a0}: {date}"),
                entry(
                    "call.budget",
                    Label,
                    "{amount} & co\u{fb}ts {{fixe}} <{amount}>",
                ),
                entry("form.name", Label, "Champ \u{ab}\u{a0}nom\u{a0}\u{bb}"),
                entry(
                    "notice.synthetic",
                    Approved,
                    "TEXTE DE TEST SYNTH\u{c9}TIQUE, version {version}, pour {org}.",
                ),
                entry(
                    "guide.synthetic",
                    Approved,
                    "TEXTE SYNTH\u{c9}TIQUE\u{a0}: avant le {date} & <tout>.",
                ),
            ],
        }],
    }
}
