//! The name mask (M7 Q4, ADR-033 record of lane L31, decided by Daniel on
//! 2026-11-22).
//!
//! The vault finds, in a text the application is about to hand to an
//! agent or a model, the spans that hold a team member's verified names
//! or date of birth. It answers spans only: byte offsets into the text it
//! was given, a person index and a class. It never returns a name, and it
//! answers only about text the application already holds (I-17).
//!
//! - Names match word by word. A word of the text is a maximal run of
//!   letters, digits and combining marks. Each word is compared through
//!   [`fstp_unorm::name_key`], the compatibility caseless key of ADR-029,
//!   with each part of the verified family and given names. A part is a
//!   piece of the name between spaces, hyphens or apostrophes, of two or
//!   more characters.
//! - Masked words of one person that only spaces, hyphens, apostrophes or
//!   full stops separate are one span, so a full name becomes one
//!   placeholder.
//! - A date of birth matches as `YYYY-MM-DD`, and in day, month, year order
//!   with `.`, `/` or `-` and one or two digits for the day and the month.
//! - Spans are sorted, never overlap and lie on character boundaries.
//!
//! The work is linear in the text times the number of name parts, which
//! the request bounds. Fuzz target `mask_spans`.

use fstp_unorm::name_key;

/// What a span holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaskClass {
    /// A verified family or given name.
    Name,
    /// The verified date of birth.
    BirthDate,
}

impl MaskClass {
    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            MaskClass::Name => "name",
            MaskClass::BirthDate => "birth_date",
        }
    }

    /// The class spelt `s`.
    pub fn from_label(s: &str) -> Option<MaskClass> {
        match s {
            "name" => Some(MaskClass::Name),
            "birth_date" => Some(MaskClass::BirthDate),
            _ => None,
        }
    }
}

/// One span to mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MaskSpan {
    /// The first byte offset.
    pub start: u32,
    /// The byte offset just after the span.
    pub end: u32,
    /// The person, by its index in the request's account order.
    pub person: u32,
    /// What the span holds.
    pub class: MaskClass,
}

/// One team member's verified attributes, as the matcher needs them. The
/// debug form names no attribute (R-NF-02).
#[derive(Clone, PartialEq, Eq)]
pub struct MaskPerson {
    /// The name parts: the family and given names, each through
    /// `name_key` and split into parts of two or more characters.
    parts: Vec<String>,
    /// The date of birth as year, month and day.
    birth: Option<(u16, u8, u8)>,
}

impl std::fmt::Debug for MaskPerson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskPerson")
            .field("parts", &self.parts.len())
            .finish_non_exhaustive()
    }
}

/// Whether `c` belongs to a word: a letter, a digit or a combining mark.
fn is_word(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            u32::from(c),
            0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F
        )
}

/// Whether `c` may join two masked words of one name.
fn is_joiner(c: char) -> bool {
    c.is_whitespace() || matches!(c, '-' | '\'' | '\u{2019}' | '.' | '\u{2010}' | '\u{2011}')
}

impl MaskPerson {
    /// The person with these verified names and date of birth
    /// (`YYYY-MM-DD`). Names may be given in any spelling, since each
    /// passes through `name_key`.
    pub fn new(family_names: &str, given_names: &str, birth_date: Option<&str>) -> MaskPerson {
        let mut parts: Vec<String> = Vec::new();
        for name in [family_names, given_names] {
            let key = name_key(name);
            for p in key.split(|c: char| !is_word(c)) {
                if p.chars().count() >= 2 && !parts.iter().any(|q| q == p) {
                    parts.push(p.to_owned());
                }
            }
        }
        MaskPerson {
            parts,
            birth: birth_date.and_then(iso_date),
        }
    }

    fn names(&self, key: &str) -> bool {
        self.parts.iter().any(|p| p == key)
    }
}

/// `YYYY-MM-DD` as year, month and day.
fn iso_date(s: &str) -> Option<(u16, u8, u8)> {
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    Some((y.parse().ok()?, m.parse().ok()?, d.parse().ok()?))
}

/// The date a run of digits and separators spells, if it is one.
fn date_of(run: &str) -> Option<(u16, u8, u8)> {
    if let Some(d) = iso_date(run) {
        return Some(d);
    }
    let sep = run.chars().find(|c| matches!(c, '.' | '/' | '-'))?;
    let mut it = run.split(sep);
    let (d, m, y) = (it.next()?, it.next()?, it.next()?);
    let short = |s: &str| (1..=2).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if it.next().is_some() || !short(d) || !short(m) || y.len() != 4 {
        return None;
    }
    Some((y.parse().ok()?, m.parse().ok()?, d.parse().ok()?))
}

fn span(start: usize, end: usize, person: usize, class: MaskClass) -> Option<MaskSpan> {
    Some(MaskSpan {
        start: u32::try_from(start).ok()?,
        end: u32::try_from(end).ok()?,
        person: u32::try_from(person).ok()?,
        class,
    })
}

/// The spans of `text` that hold a verified name or date of birth of one
/// of `people`, sorted and disjoint. The person index is the position in
/// `people`.
pub fn mask_spans(text: &str, people: &[MaskPerson]) -> Vec<MaskSpan> {
    let mut out: Vec<MaskSpan> = Vec::new();
    // Words, as byte ranges.
    let mut words: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (is_word(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                words.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, text.len()));
    }
    // Names: each word against each person's parts, then joined runs.
    let mut last: Option<(usize, usize, usize)> = None;
    for (a, b) in words.iter().copied() {
        let Some(word) = text.get(a..b) else {
            continue;
        };
        let key = name_key(word);
        let who = people.iter().position(|p| p.names(&key));
        match (who, last) {
            (Some(w), Some((ls, le, lw)))
                if lw == w && text.get(le..a).is_some_and(|g| g.chars().all(is_joiner)) =>
            {
                last = Some((ls, b, lw));
            }
            (Some(w), prev) => {
                if let Some((ls, le, lw)) = prev {
                    out.extend(span(ls, le, lw, MaskClass::Name));
                }
                last = Some((a, b, w));
            }
            (None, Some((ls, le, lw))) => {
                out.extend(span(ls, le, lw, MaskClass::Name));
                last = None;
            }
            (None, None) => {}
        }
    }
    if let Some((ls, le, lw)) = last {
        out.extend(span(ls, le, lw, MaskClass::Name));
    }
    // Dates: maximal runs of ASCII digits and date separators.
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let is_date = |b: u8| b.is_ascii_digit() || matches!(b, b'.' | b'/' | b'-');
        if !bytes.get(i).copied().is_some_and(|b| b.is_ascii_digit()) {
            i = i.saturating_add(1);
            continue;
        }
        let mut j = i;
        while bytes.get(j).copied().is_some_and(is_date) {
            j = j.saturating_add(1);
        }
        // A trailing full stop ends a sentence, not the date.
        let mut end = j;
        while end > i && matches!(bytes.get(end.saturating_sub(1)), Some(b'.' | b'/' | b'-')) {
            end = end.saturating_sub(1);
        }
        if let Some(run) = text.get(i..end)
            && let Some(d) = date_of(run)
            && let Some(w) = people.iter().position(|p| p.birth == Some(d))
            && !out
                .iter()
                .any(|s| (s.start as usize) < end && i < s.end as usize)
        {
            out.extend(span(i, end, w, MaskClass::BirthDate));
        }
        i = j.max(i.saturating_add(1));
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn masked(text: &str, spans: &[MaskSpan]) -> String {
        let mut out = String::new();
        let mut at = 0usize;
        for s in spans {
            out.push_str(&text[at..s.start as usize]);
            out.push_str(match s.class {
                MaskClass::Name => "[P]",
                MaskClass::BirthDate => "[D]",
            });
            at = s.end as usize;
        }
        out.push_str(&text[at..]);
        out
    }

    /// M7 Q4, I-17, ADR-029: names match in any case and compatibility
    /// spelling, word by word, and a full name is one span. A word that only
    /// contains a name part is not masked.
    #[test]
    fn m7_q4_names_match_by_name_key_and_join() {
        let p = MaskPerson::new("Velinorra-Quist", "Maradine Ilse", Some("1990-04-07"));
        let text = "Lead: MARADINE velinorra-quist, born 07.04.1990. See Maradinestra and ＭＡＲＡＤＩＮＥ.";
        let spans = mask_spans(text, std::slice::from_ref(&p));
        assert_eq!(
            masked(text, &spans),
            "Lead: [P], born [D]. See Maradinestra and [P]."
        );
        assert!(spans.iter().all(|s| s.person == 0));
    }

    /// M7 Q4: the person index is the position in the request, dates match
    /// in each spelling, and a one-letter part never matches.
    #[test]
    fn m7_q4_person_index_and_dates() {
        let a = MaskPerson::new("Iloorvul", "O", None);
        let b = MaskPerson::new("Zorsef", "Kal", Some("2001-12-31"));
        let text =
            "O Iloorvul and Kal Zorsef, 2001-12-31 or 31/12/2001 or 31-12-2001, not 2001-12-30.";
        let spans = mask_spans(text, &[a, b]);
        assert_eq!(
            masked(text, &spans),
            "O [P] and [P], [D] or [D] or [D], not 2001-12-30."
        );
        let persons: Vec<u32> = spans.iter().map(|s| s.person).collect();
        assert_eq!(persons, vec![0, 1, 1, 1, 1]);
    }

    /// R-NF-02: the debug form names no attribute.
    #[test]
    fn r_nf_02_mask_person_debug_names_nothing() {
        let p = MaskPerson::new("Velinorra", "Maradine", Some("1990-04-07"));
        let shown = format!("{p:?}");
        assert!(!shown.to_lowercase().contains("velinorra"), "{shown}");
        assert!(!shown.contains("1990"), "{shown}");
    }
}
