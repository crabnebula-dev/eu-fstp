//! Stage 2: PII stripping to stable placeholders (M7 design section 3.2,
//! T-PRIV-CANARY).
//!
//! Patterns run in the cell: IBAN-shaped strings, email addresses, phone
//! numbers, postal addresses anchored on a postcode, and the team's
//! handles. Legal names are vault facts, so the cell asks the [`NameMask`]
//! port for them (15.0, "M7 name masking"). The same value gets the same
//! placeholder across every part of one job. The placeholder map never
//! leaves the cell and has no accessor for its values.
//!
//! Fuzz target `strip_patterns`.

use std::collections::BTreeMap;
use std::future::Future;

use fstp_domain::id::ProposalId;

use crate::span::SpanMap;

/// A PII class with its placeholder spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PiiClass {
    /// A legal name, found by the name-mask port.
    Person,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// An IBAN-shaped string.
    Iban,
    /// A postal address.
    Address,
    /// A team member's handle.
    Handle,
}

impl PiiClass {
    /// The placeholder label, as in `[EMAIL-1]`.
    pub const fn label(self) -> &'static str {
        match self {
            PiiClass::Person => "PERSON",
            PiiClass::Email => "EMAIL",
            PiiClass::Phone => "PHONE",
            PiiClass::Iban => "IBAN",
            PiiClass::Address => "ADDRESS",
            PiiClass::Handle => "HANDLE",
        }
    }
}

/// One name occurrence the port found: a byte span of the text it was
/// given, and a stable index of the person within the team.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameSpan {
    /// The first byte offset.
    pub start: usize,
    /// The byte offset just after the name.
    pub end: usize,
    /// The person within the team, stable for one proposal.
    pub person: u32,
}

/// The name-mask port could not answer. The assessment stays pending and
/// no request is sent (R-NF-10, T-PRIV-CANARY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskUnavailable;

/// The name-mask port (15.0, "M7 name masking").
///
/// Seam: the real implementation is the vault mask query over the
/// proposal team's legal names, added by spec change as for Q35. A later
/// vault lane builds it. Until then the cell has only
/// [`SyntheticNameMask`], whose names come from the synthetic corpus.
pub trait NameMask: Send + Sync {
    /// The spans of the team's legal names in `text`, which is already
    /// stripped of the pattern classes.
    fn names(
        &self,
        proposal: ProposalId,
        text: &str,
    ) -> impl Future<Output = Result<Vec<NameSpan>, MaskUnavailable>> + Send;
}

/// A synthetic name mask over a fixed list of team names. It matches each
/// full name, then each of its words, as whole words and ignoring ASCII
/// case. For tests and the demo cell only.
#[derive(Clone, Debug, Default)]
pub struct SyntheticNameMask {
    team: Vec<String>,
}

impl SyntheticNameMask {
    /// A mask over these team names. Index order is the person index.
    pub fn new(team: Vec<String>) -> SyntheticNameMask {
        SyntheticNameMask { team }
    }

    /// The name spans in `text`, without overlaps, in text order.
    pub fn find(&self, text: &str) -> Vec<NameSpan> {
        let lower = text.to_ascii_lowercase();
        let mut found: Vec<NameSpan> = Vec::new();
        let mut needles: Vec<(String, u32)> = Vec::new();
        for (i, name) in self.team.iter().enumerate() {
            let person = u32::try_from(i).unwrap_or(u32::MAX);
            needles.push((name.to_ascii_lowercase(), person));
        }
        for (i, name) in self.team.iter().enumerate() {
            let person = u32::try_from(i).unwrap_or(u32::MAX);
            for w in name.split_whitespace().filter(|w| w.len() >= 2) {
                needles.push((w.to_ascii_lowercase(), person));
            }
        }
        for (needle, person) in needles {
            for (start, end) in whole_words(&lower, &needle) {
                if !found.iter().any(|f| f.start < end && start < f.end) {
                    found.push(NameSpan { start, end, person });
                }
            }
        }
        found.sort();
        found
    }
}

impl NameMask for SyntheticNameMask {
    async fn names(&self, _p: ProposalId, text: &str) -> Result<Vec<NameSpan>, MaskUnavailable> {
        Ok(self.find(text))
    }
}

/// The stable placeholder numbering of one job. Values stay in the cell:
/// there is no accessor and `Debug` shows only the count.
#[derive(Clone, Default)]
pub struct Placeholders {
    numbers: BTreeMap<(PiiClass, String), u32>,
    next: BTreeMap<PiiClass, u32>,
}

impl core::fmt::Debug for Placeholders {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Placeholders")
            .field("count", &self.numbers.len())
            .finish()
    }
}

impl Placeholders {
    /// The placeholder for `value` of `class`, assigned on first use.
    fn placeholder(&mut self, class: PiiClass, value: String) -> String {
        let n = match self.numbers.get(&(class, value.clone())) {
            Some(n) => *n,
            None => {
                let next = self.next.entry(class).or_insert(0);
                *next = next.saturating_add(1);
                let n = *next;
                self.numbers.insert((class, value), n);
                n
            }
        };
        format!("[{}-{n}]", class.label())
    }

    /// How many distinct values were replaced.
    pub fn len(&self) -> usize {
        self.numbers.len()
    }

    /// Whether nothing was replaced.
    pub fn is_empty(&self) -> bool {
        self.numbers.is_empty()
    }
}

/// One detected span of `text`, with its class and the key that numbers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// The class.
    pub class: PiiClass,
    /// The first byte offset.
    pub start: usize,
    /// The byte offset just after the value.
    pub end: usize,
    /// The numbering key: the value, or the person index for names.
    key: String,
}

fn byte(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

fn word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Whole-word occurrences of `needle` in `hay`. Both are ASCII-lowercased
/// already, so offsets are those of the original text.
fn whole_words(hay: &str, needle: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    let b = hay.as_bytes();
    let mut from = 0;
    while let Some(at) = hay
        .get(from..)
        .and_then(|h| h.find(needle))
        .map(|i| i.saturating_add(from))
    {
        let end = at.saturating_add(needle.len());
        let before = at.checked_sub(1).map_or(0, |i| byte(b, i));
        if !word_char(before) && !word_char(byte(b, end)) {
            out.push((at, end));
        }
        from = end.max(at.saturating_add(1));
        while from < hay.len() && !hay.is_char_boundary(from) {
            from = from.saturating_add(1);
        }
    }
    out
}

fn ibans(s: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0_usize;
    while i.saturating_add(4) <= s.len() {
        let at_word = i == 0 || !word_char(byte(s, i.saturating_sub(1)));
        let head = byte(s, i).is_ascii_uppercase()
            && byte(s, i.saturating_add(1)).is_ascii_uppercase()
            && byte(s, i.saturating_add(2)).is_ascii_digit()
            && byte(s, i.saturating_add(3)).is_ascii_digit();
        if at_word && head {
            let mut j = i.saturating_add(4);
            let mut count = 4_usize;
            let mut end = j;
            loop {
                let c = byte(s, j);
                if c.is_ascii_uppercase() || c.is_ascii_digit() {
                    count = count.saturating_add(1);
                    j = j.saturating_add(1);
                    end = j;
                } else if c == b' ' && {
                    let n = byte(s, j.saturating_add(1));
                    n.is_ascii_uppercase() || n.is_ascii_digit()
                } {
                    j = j.saturating_add(1);
                } else {
                    break;
                }
                if count >= 34 {
                    break;
                }
            }
            if (15..=34).contains(&count) && !word_char(byte(s, end)) {
                out.push((i, end));
                i = end;
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    out
}

fn emails(s: &[u8]) -> Vec<(usize, usize)> {
    let local = |b: u8| b.is_ascii_alphanumeric() || b"._%+-".contains(&b);
    let domain = |b: u8| b.is_ascii_alphanumeric() || b".-".contains(&b);
    let mut out = Vec::new();
    for (at, _) in s.iter().enumerate().filter(|(_, b)| **b == b'@') {
        let mut l = at;
        while l > 0 && local(byte(s, l.saturating_sub(1))) {
            l = l.saturating_sub(1);
        }
        let mut r = at.saturating_add(1);
        while r < s.len() && domain(byte(s, r)) {
            r = r.saturating_add(1);
        }
        while r > at.saturating_add(1) && b".-".contains(&byte(s, r.saturating_sub(1))) {
            r = r.saturating_sub(1);
        }
        let dom = s.get(at.saturating_add(1)..r).unwrap_or(&[]);
        let tld_ok = dom
            .rsplit(|b| *b == b'.')
            .next()
            .is_some_and(|t| t.len() >= 2 && t.iter().all(u8::is_ascii_alphabetic));
        if l < at && dom.contains(&b'.') && tld_ok {
            out.push((l, r));
        }
    }
    out
}

fn phones(s: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0_usize;
    while i < s.len() {
        let c = byte(s, i);
        let at_word = i == 0 || !word_char(byte(s, i.saturating_sub(1)));
        let plus = c == b'+' && byte(s, i.saturating_add(1)).is_ascii_digit();
        let national = c == b'0' && at_word;
        if (plus || national) && at_word {
            let mut j = if plus { i.saturating_add(1) } else { i };
            let mut digits = 0_usize;
            let mut end = j;
            loop {
                let d = byte(s, j);
                if d.is_ascii_digit() {
                    digits = digits.saturating_add(1);
                    j = j.saturating_add(1);
                    end = j;
                } else if (d == b' ' || d == b'-') && byte(s, j.saturating_add(1)).is_ascii_digit()
                {
                    j = j.saturating_add(1);
                } else {
                    break;
                }
            }
            let min = if plus { 7 } else { 9 };
            if digits >= min && digits <= 15 && !word_char(byte(s, end)) {
                out.push((i, end));
                i = end;
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    out
}

/// A UK-style postcode at `i`, such as `ZZ6 9ZZ` or `SW1A 1AA`: its end.
fn postcode_at(s: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    let mut letters = 0_u8;
    while letters < 2 && byte(s, j).is_ascii_uppercase() {
        letters = letters.saturating_add(1);
        j = j.saturating_add(1);
    }
    if letters == 0 || !byte(s, j).is_ascii_digit() {
        return None;
    }
    j = j.saturating_add(1);
    let c = byte(s, j);
    if c.is_ascii_digit() || c.is_ascii_uppercase() {
        j = j.saturating_add(1);
    }
    if byte(s, j) != b' ' {
        return None;
    }
    j = j.saturating_add(1);
    let ok = byte(s, j).is_ascii_digit()
        && byte(s, j.saturating_add(1)).is_ascii_uppercase()
        && byte(s, j.saturating_add(2)).is_ascii_uppercase();
    let end = j.saturating_add(3);
    (ok && !word_char(byte(s, end))).then_some(end)
}

fn addresses(s: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0_usize;
    while i < s.len() {
        let at_word = i == 0 || !word_char(byte(s, i.saturating_sub(1)));
        if let Some(end) = at_word.then(|| postcode_at(s, i)).flatten() {
            // The nearest preceding house number on the same line, such
            // as `12 Some Way`, within 120 bytes.
            let floor = i.saturating_sub(120);
            let mut start = i;
            let mut p = i;
            while p > floor {
                p = p.saturating_sub(1);
                let c = byte(s, p);
                if c == b'\n' || c == b'.' {
                    break;
                }
                let at = p == 0 || !word_char(byte(s, p.saturating_sub(1)));
                if at && c.is_ascii_digit() {
                    let mut q = p;
                    while byte(s, q).is_ascii_digit() {
                        q = q.saturating_add(1);
                    }
                    if byte(s, q) == b' ' && byte(s, q.saturating_add(1)).is_ascii_uppercase() {
                        start = p;
                        break;
                    }
                }
            }
            out.push((start, end));
            i = end;
            continue;
        }
        i = i.saturating_add(1);
    }
    out
}

fn handles(text: &str, team: &[String]) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let b = text.as_bytes();
    let mut out = Vec::new();
    for h in team.iter().filter(|h| h.len() >= 2) {
        for (mut start, end) in whole_words(&lower, &h.to_ascii_lowercase()) {
            if start > 0 && byte(b, start.saturating_sub(1)) == b'@' {
                start = start.saturating_sub(1);
            }
            out.push((start, end));
        }
    }
    out
}

/// Every pattern hit in `text`, without overlaps, in text order. Earlier
/// classes win an overlap: IBAN, email, phone, address, handle.
pub fn detect(text: &str, team_handles: &[String]) -> Vec<Hit> {
    let s = text.as_bytes();
    let mut hits: Vec<Hit> = Vec::new();
    let groups = [
        (PiiClass::Iban, ibans(s)),
        (PiiClass::Email, emails(s)),
        (PiiClass::Phone, phones(s)),
        (PiiClass::Address, addresses(s)),
        (PiiClass::Handle, handles(text, team_handles)),
    ];
    for (class, spans) in groups {
        for (start, end) in spans {
            let Some(value) = text.get(start..end) else {
                continue;
            };
            if hits.iter().any(|h| h.start < end && start < h.end) {
                continue;
            }
            let key = if class == PiiClass::Handle {
                value.trim_start_matches('@').to_ascii_lowercase()
            } else {
                value.to_owned()
            };
            hits.push(Hit {
                class,
                start,
                end,
                key,
            });
        }
    }
    hits.sort_by_key(|h| h.start);
    hits
}

/// Name spans as hits: checked for range, char boundaries and overlaps.
/// A span that fails a check is dropped from the port's answer, and the
/// caller fails closed when the port gave spans it could not use.
pub(crate) fn name_hits(text: &str, spans: &[NameSpan]) -> Option<Vec<Hit>> {
    let mut hits: Vec<Hit> = Vec::new();
    let mut sorted = spans.to_vec();
    sorted.sort();
    for n in sorted {
        if n.start >= n.end || text.get(n.start..n.end).is_none() {
            return None;
        }
        if hits.iter().any(|h| h.start < n.end && n.start < h.end) {
            continue;
        }
        hits.push(Hit {
            class: PiiClass::Person,
            start: n.start,
            end: n.end,
            key: n.person.to_string(),
        });
    }
    Some(hits)
}

/// Replaces every hit with its placeholder.
pub(crate) fn apply(text: &str, hits: &[Hit], ph: &mut Placeholders) -> (String, SpanMap) {
    let mut out = String::with_capacity(text.len());
    let mut map = SpanMap::new();
    let mut at = 0;
    for h in hits {
        let Some(before) = text.get(at..h.start) else {
            continue;
        };
        out.push_str(before);
        map.push_copy(before.len());
        let p = ph.placeholder(h.class, h.key.clone());
        out.push_str(&p);
        map.push_replace(h.end.saturating_sub(h.start), p.len());
        at = h.end;
    }
    let rest = text.get(at..).unwrap_or("");
    out.push_str(rest);
    map.push_copy(rest.len());
    (out, map)
}
