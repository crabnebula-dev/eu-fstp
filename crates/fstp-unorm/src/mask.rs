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

use crate::name_key;

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

/// The longest piece of text one mask request carries, in bytes: the
/// vault's cap per text (`fstp_vault_proto::MAX_MASK_TEXT_BYTES`), which
/// stays as it is (Daniel, 2026-11-23).
pub const MASK_PIECE_BYTES: usize = 64 << 10;

/// The most pieces one mask request carries: the vault's cap on texts
/// per request (`fstp_vault_proto::MAX_MASK_TEXTS`).
pub const MASK_PIECES_PER_REQUEST: usize = 3;

/// The most pieces of one text, 4 MiB at [`MASK_PIECE_BYTES`]. A longer
/// text fails closed, so one text cannot spend the vault's mask rate
/// (ADR-033 record of lane L40, interim, pending Daniel).
pub const MAX_MASK_PIECES: usize = 64;

/// Whether a cut may fall just after `c` when no white space is in reach:
/// `c` belongs to no word and to no date run, so no word and no date
/// crosses the cut.
fn safe_cut(c: char) -> bool {
    !is_word(c) && !matches!(c, '.' | '/' | '-')
}

/// The cut in `window`, a byte offset after its first byte: after the
/// last paragraph break, else after the last line break, else after the
/// last white space, else after the last character that no word or date
/// run holds. `None` when the window holds none of these.
fn cut_in(window: &str) -> Option<usize> {
    let paragraph = ["\n\n", "\n\r\n"]
        .iter()
        .filter_map(|p| window.rfind(p).map(|i| i.saturating_add(p.len())))
        .max();
    let line = || window.rfind('\n').map(|i| i.saturating_add(1));
    let last = |keep: fn(char) -> bool| {
        window
            .char_indices()
            .rev()
            .find(|(_, c)| keep(*c))
            .map(|(i, c)| i.saturating_add(c.len_utf8()))
    };
    paragraph
        .or_else(line)
        .or_else(|| last(char::is_whitespace))
        .or_else(|| last(safe_cut))
        .filter(|cut| *cut > 0)
}

/// Splits `text` into pieces of at most `max` bytes for a mask whose
/// requests carry at most `max` bytes per text (Daniel, 2026-11-23,
/// ADR-033 record of lane L40). The pieces are byte ranges that cover the
/// text in order, so joining them gives the text back.
///
/// - Each cut falls at the last paragraph break in reach, else the last
///   line break, else the last white space, else after the last character
///   that no word and no date run holds.
/// - So no word, which [`mask_spans`] reads as a maximal run of letters,
///   digits and combining marks, and no run of date digits and separators
///   ever crosses a cut, and no cut splits a UTF-8 sequence.
/// - `None` when a window of `max` bytes holds no such cut, such as one
///   word longer than the window. The caller then fails closed.
///
/// An empty text is one empty piece.
pub fn mask_pieces(text: &str, max: usize) -> Option<Vec<std::ops::Range<usize>>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while text.len().saturating_sub(start) > max {
        let mut end = start.saturating_add(max);
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        let cut = cut_in(text.get(start..end)?)?;
        out.push(start..start.saturating_add(cut));
        start = start.saturating_add(cut);
    }
    out.push(start..text.len());
    Some(out)
}

/// Joins the spans the mask gave for each of `pieces` of `text` into the
/// spans of the whole text (Daniel, 2026-11-23, ADR-033 record of lane
/// L40). `spans` holds one answer per piece, in piece order, with offsets
/// into that piece.
///
/// - Each span moves by its piece's start.
/// - A name span of one person whose gap to the next name span of the
///   same person holds only joiners and crosses a cut becomes one span,
///   as [`mask_spans`] of the whole text joins them.
/// - `None` when the answers do not match the pieces, a span is empty or
///   lies outside its piece or off a character boundary, or the spans of
///   a piece are not sorted and disjoint. The caller then fails closed.
///
/// For pieces of [`mask_pieces`], the result equals [`mask_spans`] of the
/// whole text.
pub fn join_piece_spans(
    text: &str,
    pieces: &[std::ops::Range<usize>],
    spans: &[Vec<MaskSpan>],
) -> Option<Vec<MaskSpan>> {
    if pieces.len() != spans.len() {
        return None;
    }
    let mut out: Vec<MaskSpan> = Vec::new();
    for (piece, answer) in pieces.iter().zip(spans) {
        let base = u32::try_from(piece.start).ok()?;
        let len = piece.end.checked_sub(piece.start)?;
        let mut floor = 0u32;
        for s in answer {
            let (a, b) = (s.start as usize, s.end as usize);
            if s.start < floor || a >= b || b > len {
                return None;
            }
            floor = s.end;
            let moved = MaskSpan {
                start: base.checked_add(s.start)?,
                end: base.checked_add(s.end)?,
                ..*s
            };
            let (ga, gb) = (moved.start as usize, moved.end as usize);
            if !text.is_char_boundary(ga) || !text.is_char_boundary(gb) {
                return None;
            }
            let joins = out.last().is_some_and(|l| {
                l.class == MaskClass::Name
                    && moved.class == MaskClass::Name
                    && l.person == moved.person
                    && (l.end as usize) <= piece.start
                    && text
                        .get(l.end as usize..ga)
                        .is_some_and(|g| g.chars().all(is_joiner))
            });
            match out.last_mut() {
                Some(l) if joins => l.end = moved.end,
                Some(l) if l.end > moved.start => return None,
                _ => out.push(moved),
            }
        }
    }
    Some(out)
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
