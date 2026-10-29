//! Message catalogues for server-rendered text (R-NF-04) and the `Label`
//! and `ApprovedText` kinds (I-72 seam, R-WL-05).
//!
//! Every server-rendered string comes from a catalogue per locale. Each
//! entry is a [`Label`], an interface string that a terminology override
//! may replace, or an [`ApprovedText`], approved wording that no override
//! reaches (I-72). The two kinds are kept in separate tables, and
//! [`Catalogues::with_overrides`] only ever writes the label table.
//!
//! Interim reading, pending Daniel. A catalogue set has one default
//! locale and other locales. Every locale is a language tag, named once
//! (ignoring case). Every locale defines exactly the ids of the default
//! locale, with the same kind and the same placeholder names. An id is 1
//! to 128 bytes of lower-case ASCII letters, digits, `.`, `_` and `-`.

use std::collections::{BTreeMap, BTreeSet};

use crate::HtmlError;
use crate::lang::parse_accept_language;
use crate::message::{MessageFormat, parse_message_format};
use crate::subset::is_lang_tag;

/// The longest message id, in bytes.
pub const MAX_ID_BYTES: usize = 128;

/// The kind of a catalogue entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageKind {
    /// An interface string. Terminology overrides apply (I-72).
    Label,
    /// Approved wording. Overrides never apply (I-72).
    Approved,
}

/// A reference to an interface string of the catalogue (I-72).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// The label with message id `id`. The id is checked when the label
    /// is resolved or rendered.
    pub fn new(id: &str) -> Label {
        Label(id.to_owned())
    }

    /// The message id.
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// A reference to approved wording of the catalogue, such as a notice or
/// the Guide for Applicants. No terminology override reaches it (I-72).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovedText(String);

impl ApprovedText {
    /// The approved wording with message id `id`. The id is checked when
    /// the text is resolved or rendered.
    pub fn new(id: &str) -> ApprovedText {
        ApprovedText(id.to_owned())
    }

    /// The message id.
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// One catalogue entry as written in a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntrySource<'a> {
    /// The message id.
    pub id: &'a str,
    /// Label or approved wording.
    pub kind: MessageKind,
    /// The message, in the grammar of
    /// [`parse_message_format`](crate::parse_message_format).
    pub message: &'a str,
}

/// The catalogue of one locale as written in a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogueSource<'a> {
    /// The locale, a language tag.
    pub locale: &'a str,
    /// The entries.
    pub entries: &'a [EntrySource<'a>],
}

/// A terminology override of one label in one locale (R-WL-05).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabelOverride<'a> {
    /// The locale.
    pub locale: &'a str,
    /// The id of the label replaced.
    pub id: &'a str,
    /// The replacement message. It must have the placeholder names of
    /// the entry it replaces.
    pub message: &'a str,
}

/// The built catalogue of one locale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocaleCatalogue {
    locale: String,
    labels: BTreeMap<String, MessageFormat>,
    approved: BTreeMap<String, MessageFormat>,
}

impl LocaleCatalogue {
    /// The entry for `id` of `kind`, or why there is none.
    pub(crate) fn get(&self, kind: MessageKind, id: &str) -> Result<&MessageFormat, HtmlError> {
        let (table, other) = match kind {
            MessageKind::Label => (&self.labels, &self.approved),
            MessageKind::Approved => (&self.approved, &self.labels),
        };
        match table.get(id) {
            Some(m) => Ok(m),
            None if other.contains_key(id) => Err(message_err(
                id,
                match kind {
                    MessageKind::Label => "the id is approved wording, not a label",
                    MessageKind::Approved => "the id is a label, not approved wording",
                },
            )),
            // The id is unknown, so it may not be a code constant. It is
            // not copied into the error (R-NF-02).
            None => Err(message_err("", "the catalogue has no such id")),
        }
    }

    fn kind_of(&self, id: &str) -> Option<MessageKind> {
        if self.labels.contains_key(id) {
            Some(MessageKind::Label)
        } else if self.approved.contains_key(id) {
            Some(MessageKind::Approved)
        } else {
            None
        }
    }

    fn len(&self) -> usize {
        self.labels.len().saturating_add(self.approved.len())
    }
}

/// A built and checked catalogue set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Catalogues {
    /// The default locale first, then the others in source order.
    locales: Vec<LocaleCatalogue>,
}

/// A catalogue error naming `locale` and `id`. A locale that is not a
/// language tag and an id that is not an id are left out, so the error
/// never copies an unchecked string into a log (R-NF-02).
fn cat_err(rule: &'static str, locale: &str, id: &str) -> HtmlError {
    let locale = if is_lang_tag(locale) { locale } else { "" };
    let id = if is_id(id) { id } else { "" };
    let entry = match (locale.is_empty(), id.is_empty()) {
        (true, _) => String::new(),
        (false, true) => locale.to_owned(),
        (false, false) => format!("{locale} {id}"),
    };
    HtmlError::Catalogue { rule, entry }
}

/// A message error naming `id`. Callers pass an id the catalogue knows,
/// or the empty string. An id that is not an id is left out all the same
/// (R-NF-02).
pub(crate) fn message_err(id: &str, rule: &'static str) -> HtmlError {
    HtmlError::Message {
        rule,
        id: if is_id(id) {
            id.to_owned()
        } else {
            String::new()
        },
    }
}

fn is_id(id: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&id.len())
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}

fn build_locale(src: &CatalogueSource<'_>) -> Result<LocaleCatalogue, HtmlError> {
    if !is_lang_tag(src.locale) {
        return Err(cat_err("the locale is not a language tag", src.locale, ""));
    }
    let mut cat = LocaleCatalogue {
        locale: src.locale.to_owned(),
        labels: BTreeMap::new(),
        approved: BTreeMap::new(),
    };
    for e in src.entries {
        if !is_id(e.id) {
            return Err(cat_err("the message id is not an id", src.locale, ""));
        }
        if cat.kind_of(e.id).is_some() {
            return Err(cat_err("the id is defined twice", src.locale, e.id));
        }
        let m = parse_message_format(e.message.as_bytes())
            .map_err(|_| cat_err("the message is outside the grammar", src.locale, e.id))?;
        let table = match e.kind {
            MessageKind::Label => &mut cat.labels,
            MessageKind::Approved => &mut cat.approved,
        };
        table.insert(e.id.to_owned(), m);
    }
    Ok(cat)
}

/// Checks that `other` defines exactly the ids of `default`, with the
/// same kinds and placeholder names.
fn check_same_shape(default: &LocaleCatalogue, other: &LocaleCatalogue) -> Result<(), HtmlError> {
    if other.len() != default.len() {
        return Err(cat_err(
            "the locale does not define exactly the default ids",
            &other.locale,
            "",
        ));
    }
    for kind in [MessageKind::Label, MessageKind::Approved] {
        let table = match kind {
            MessageKind::Label => &default.labels,
            MessageKind::Approved => &default.approved,
        };
        for (id, d) in table {
            let e = match other.kind_of(id) {
                None => return Err(cat_err("the locale lacks the id", &other.locale, id)),
                Some(k) if k != kind => {
                    return Err(cat_err("the locale changes the kind", &other.locale, id));
                }
                Some(_) => other.get(kind, id)?,
            };
            if e.placeholder_names() != d.placeholder_names() {
                return Err(cat_err(
                    "the locale changes the placeholders",
                    &other.locale,
                    id,
                ));
            }
        }
    }
    Ok(())
}

impl Catalogues {
    /// Builds a catalogue set from its default locale and the others.
    /// Refuses a set that breaks a rule of the module documentation.
    pub fn new(
        default: &CatalogueSource<'_>,
        others: &[CatalogueSource<'_>],
    ) -> Result<Catalogues, HtmlError> {
        let mut locales = vec![build_locale(default)?];
        let mut seen = BTreeSet::from([default.locale.to_ascii_lowercase()]);
        for src in others {
            if !seen.insert(src.locale.to_ascii_lowercase()) {
                return Err(cat_err("the locale is named twice", src.locale, ""));
            }
            let cat = build_locale(src)?;
            if let Some(d) = locales.first() {
                check_same_shape(d, &cat)?;
            }
            locales.push(cat);
        }
        Ok(Catalogues { locales })
    }

    /// A copy of the set with terminology overrides applied (R-WL-05).
    ///
    /// Refuses an override of an unknown locale or id, of approved wording
    /// (I-72), with a message outside the grammar, with placeholder names
    /// other than the entry's, or a second override of one entry.
    pub fn with_overrides(&self, overrides: &[LabelOverride<'_>]) -> Result<Catalogues, HtmlError> {
        let mut out = self.clone();
        let mut done = BTreeSet::new();
        for o in overrides {
            let cat = out
                .locales
                .iter_mut()
                .find(|c| c.locale == o.locale)
                .ok_or_else(|| cat_err("the override names an unknown locale", "", ""))?;
            match cat.kind_of(o.id) {
                None => return Err(cat_err("the override names an unknown id", o.locale, "")),
                Some(MessageKind::Approved) => {
                    return Err(cat_err(
                        "approved wording cannot be overridden (I-72)",
                        o.locale,
                        o.id,
                    ));
                }
                Some(MessageKind::Label) => {}
            }
            // Checked once the id is known, so the error names only a
            // known id.
            if !done.insert((o.locale, o.id)) {
                return Err(cat_err("the entry is overridden twice", o.locale, o.id));
            }
            let m = parse_message_format(o.message.as_bytes()).map_err(|_| {
                cat_err(
                    "the override is outside the message grammar",
                    o.locale,
                    o.id,
                )
            })?;
            let Some(slot) = cat.labels.get_mut(o.id) else {
                return Err(cat_err("the override names an unknown id", o.locale, ""));
            };
            if slot.placeholder_names() != m.placeholder_names() {
                return Err(cat_err(
                    "the override changes the placeholders",
                    o.locale,
                    o.id,
                ));
            }
            *slot = m;
        }
        Ok(out)
    }

    /// The default locale.
    pub fn default_locale(&self) -> &str {
        self.locales.first().map_or("", |c| c.locale.as_str())
    }

    /// Every locale, the default first.
    pub fn locales(&self) -> Vec<&str> {
        self.locales.iter().map(|c| c.locale.as_str()).collect()
    }

    /// The catalogue of `locale`, by exact spelling.
    pub(crate) fn locale(&self, locale: &str) -> Result<&LocaleCatalogue, HtmlError> {
        self.locales
            .iter()
            .find(|c| c.locale == locale)
            .ok_or(HtmlError::UnknownLocale)
    }

    /// The locale for an `Accept-Language` value: the best match among
    /// this set's locales, or the default locale.
    pub fn negotiate(&self, header: &[u8]) -> &str {
        let available = self.locales();
        match parse_accept_language(header) {
            Ok(al) => al.choose(&available, self.default_locale()),
            Err(_) => self.default_locale(),
        }
    }

    /// The text of `label` in `locale`, with `args` as given. This is
    /// plain text, not HTML: the writer escapes it where it renders it.
    pub fn resolve_label(
        &self,
        locale: &str,
        label: &Label,
        args: &[(&str, &str)],
    ) -> Result<String, HtmlError> {
        self.resolve(locale, MessageKind::Label, label.id(), &owned_args(args))
    }

    /// The text of approved wording `text` in `locale`, with `args` as
    /// given. Overrides never change it (I-72).
    pub fn resolve_approved(
        &self,
        locale: &str,
        text: &ApprovedText,
        args: &[(&str, &str)],
    ) -> Result<String, HtmlError> {
        self.resolve(locale, MessageKind::Approved, text.id(), &owned_args(args))
    }

    fn resolve(
        &self,
        locale: &str,
        kind: MessageKind,
        id: &str,
        args: &[(String, String)],
    ) -> Result<String, HtmlError> {
        let m = self.locale(locale)?.get(kind, id)?;
        m.format(args).map_err(|rule| message_err(id, rule))
    }
}

/// `args` as owned pairs.
pub(crate) fn owned_args(args: &[(&str, &str)]) -> Vec<(String, String)> {
    args.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}
