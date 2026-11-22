//! The folded views the phrase and markup detectors read (crate
//! documentation).
//!
//! Each byte of a view remembers the span of the original character it
//! came from, so a match in a view maps back to the original text.

use crate::hidden::is_removed;

/// A derived text with its map back to the original.
pub(crate) struct View {
    /// The derived text: lowercase, compatibility-folded, look-alikes
    /// mapped to Latin.
    pub(crate) s: String,
    /// For each byte of `s`, the original start of its source character.
    starts: Vec<usize>,
    /// For each byte of `s`, the original end of its source character.
    ends: Vec<usize>,
}

/// The Latin twin of a Cyrillic or Greek look-alike lowercase letter.
fn latin_twin(c: char) -> Option<char> {
    Some(match c {
        'а' => 'a',
        'в' => 'b',
        'е' | 'ё' => 'e',
        'к' => 'k',
        'м' => 'm',
        'н' => 'h',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        'ѕ' => 's',
        'ԁ' => 'd',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'ɡ' => 'g',
        'α' => 'a',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        _ => return None,
    })
}

impl View {
    fn with_capacity(n: usize) -> View {
        View {
            s: String::with_capacity(n),
            starts: Vec::with_capacity(n),
            ends: Vec::with_capacity(n),
        }
    }

    fn push(&mut self, c: char, start: usize, end: usize) {
        self.s.push(c);
        for _ in 0..c.len_utf8() {
            self.starts.push(start);
            self.ends.push(end);
        }
    }

    /// The folded view of `text`: hidden characters dropped, each other
    /// character folded and its look-alikes mapped, white space runs
    /// collapsed to one space, or to one newline when the run holds one.
    pub(crate) fn folded(text: &str) -> View {
        let mut v = View::with_capacity(text.len());
        let mut space: Option<(char, usize, usize)> = None;
        for (at, c) in text.char_indices() {
            let end = at.saturating_add(c.len_utf8());
            if is_removed(c) {
                continue;
            }
            if c.is_whitespace() {
                let nl = c == '\n' || c == '\r';
                space = match space {
                    None => Some((if nl { '\n' } else { ' ' }, at, end)),
                    Some((k, s, _)) => Some((if nl { '\n' } else { k }, s, end)),
                };
                continue;
            }
            if let Some((k, s, e)) = space.take() {
                v.push(k, s, e);
            }
            if c.is_ascii() {
                v.push(c.to_ascii_lowercase(), at, end);
                continue;
            }
            let mut buf = [0u8; 4];
            let folded = fstp_unorm::fold_nfkc(c.encode_utf8(&mut buf));
            for f in folded.chars() {
                let f = latin_twin(f).unwrap_or(f);
                if f.is_whitespace() {
                    v.push(' ', at, end);
                } else {
                    v.push(f, at, end);
                }
            }
        }
        if let Some((k, s, e)) = space {
            v.push(k, s, e);
        }
        v
    }

    /// The view without any white space, for markup and JSON literals.
    pub(crate) fn compact(&self) -> View {
        let mut v = View::with_capacity(self.s.len());
        for (i, c) in self.s.char_indices() {
            if c.is_whitespace() {
                continue;
            }
            let (Some(s), Some(e)) = (self.starts.get(i), self.ends.get(i)) else {
                continue;
            };
            v.push(c, *s, *e);
        }
        v
    }

    /// The original span of the view span `a..b`, which must be non-empty.
    pub(crate) fn span(&self, a: usize, b: usize) -> Option<(usize, usize)> {
        let start = *self.starts.get(a)?;
        let end = *self.ends.get(b.checked_sub(1)?)?;
        (start <= end).then_some((start, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-035: look-alikes and full-width letters fold to Latin, hidden
    /// characters drop, and spans map back.
    #[test]
    fn adr035_folded_view_maps_back() {
        let t = "\u{456}gn\u{43e}re\u{200b} \u{ff21}";
        let v = View::folded(t);
        assert_eq!(v.s, "ignore a");
        let (a, b) = v.span(0, 6).unwrap_or((0, 0));
        assert_eq!(&t[a..b], "\u{456}gn\u{43e}re");
        assert_eq!(v.compact().s, "ignorea");
    }
}
