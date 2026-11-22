//! The hidden-character classes (ADR-035, "Detectors").
//!
//! [`is_removed`] is the class [`crate::neutralise`] removes, without
//! context. [`detect`] flags the same characters with context, so that
//! joiners in joining scripts and emoji, direction marks in right-to-left
//! text, subdivision flags, one variation selector after its base and the
//! soft hyphen are removed but not flagged.

use crate::{Detection, Reason};

/// Whether `c` is in a hidden class, so the neutralised view leaves it out.
pub fn is_removed(c: char) -> bool {
    class(c).is_some()
}

/// The class of a hidden character, before context.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    ZeroWidth,
    Joiner,
    BidiControl,
    BidiMark,
    Tag,
    Selector,
    SupplementSelector,
    MongolianSelector,
    Format,
    SoftHyphen,
}

fn class(c: char) -> Option<Class> {
    Some(match c {
        '\u{200b}'
        | '\u{2060}'..='\u{2064}'
        | '\u{feff}'
        | '\u{180e}'
        | '\u{034f}'
        | '\u{115f}'
        | '\u{1160}'
        | '\u{3164}'
        | '\u{ffa0}'
        | '\u{17b4}'
        | '\u{17b5}' => Class::ZeroWidth,
        '\u{200c}' | '\u{200d}' => Class::Joiner,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => Class::BidiControl,
        '\u{200e}' | '\u{200f}' | '\u{061c}' => Class::BidiMark,
        '\u{e0000}'..='\u{e007f}' => Class::Tag,
        '\u{fe00}'..='\u{fe0f}' => Class::Selector,
        '\u{e0100}'..='\u{e01ef}' => Class::SupplementSelector,
        '\u{180b}'..='\u{180d}' | '\u{180f}' => Class::MongolianSelector,
        '\u{fff9}'..='\u{fffb}' | '\u{1d173}'..='\u{1d17a}' => Class::Format,
        '\u{ad}' => Class::SoftHyphen,
        _ => return None,
    })
}

/// A letter or mark of a script that uses joiners: Hebrew to the end of
/// the South-East Asian blocks, and the Indic extensions.
fn joining(c: char) -> bool {
    let u = u32::from(c);
    (0x0590..=0x1cff).contains(&u) && !c.is_whitespace()
        || (0xa800..=0xabff).contains(&u)
        || (0x11000..=0x11fff).contains(&u)
}

/// A pictograph or symbol that emoji sequences join.
fn pictograph(c: char) -> bool {
    let u = u32::from(c);
    (0x2190..=0x2bff).contains(&u)
        || (0x1f000..=0x1faff).contains(&u)
        || u == 0xfe0f
        || u == 0x20e3
        || u == 0x00a9
        || u == 0x00ae
}

/// A right-to-left letter.
fn rtl(c: char) -> bool {
    let u = u32::from(c);
    (0x0590..=0x08ff).contains(&u)
        || (0xfb1d..=0xfdff).contains(&u)
        || (0xfe70..=0xfefe).contains(&u)
        || (0x10800..=0x10fff).contains(&u)
        || (0x1e800..=0x1efff).contains(&u)
}

/// A CJK ideograph, the base of an ideographic variation sequence.
fn ideograph(c: char) -> bool {
    let u = u32::from(c);
    (0x3400..=0x9fff).contains(&u)
        || (0xf900..=0xfaff).contains(&u)
        || (0x20000..=0x3ffff).contains(&u)
}

fn push(out: &mut Vec<Detection>, reason: Reason, start: usize, end: usize) {
    out.push(Detection { start, end, reason });
}

/// Flags the hidden characters of `text` (module documentation).
pub(crate) fn detect(text: &str, out: &mut Vec<Detection>) {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let any_rtl = chars.iter().any(|(_, c)| rtl(*c));
    let end_of = |i: usize| -> usize {
        chars
            .get(i)
            .map_or(text.len(), |(at, c)| at.saturating_add(c.len_utf8()))
    };
    let mut i = 0usize;
    while let Some(&(at, c)) = chars.get(i) {
        let Some(k) = class(c) else {
            i = i.saturating_add(1);
            continue;
        };
        let prev = i.checked_sub(1).and_then(|p| chars.get(p)).map(|(_, c)| *c);
        let next = chars.get(i.saturating_add(1)).map(|(_, c)| *c);
        match k {
            Class::SoftHyphen => {}
            Class::ZeroWidth => {
                // A byte order mark that opens the text is benign.
                if !(c == '\u{feff}' && i == 0) {
                    push(out, Reason::ZeroWidth, at, end_of(i));
                }
            }
            Class::Joiner => {
                let ok = match (prev, next) {
                    (Some(p), Some(n)) => {
                        (joining(p) && joining(n)) || (pictograph(p) && pictograph(n))
                    }
                    _ => false,
                };
                if !ok {
                    push(out, Reason::ZeroWidth, at, end_of(i));
                }
            }
            Class::BidiControl => push(out, Reason::Bidi, at, end_of(i)),
            Class::BidiMark => {
                if !any_rtl {
                    push(out, Reason::Bidi, at, end_of(i));
                }
            }
            Class::Tag => {
                // A subdivision flag: U+1F3F4, tag letters, U+E007F.
                let mut j = i;
                while chars
                    .get(j)
                    .is_some_and(|(_, c)| class(*c) == Some(Class::Tag))
                {
                    j = j.saturating_add(1);
                }
                let run = j.saturating_sub(i);
                let last = chars.get(j.saturating_sub(1)).map(|(_, c)| *c);
                let flag = prev == Some('\u{1f3f4}') && last == Some('\u{e007f}') && run <= 8;
                if !flag {
                    push(out, Reason::Tag, at, end_of(j.saturating_sub(1)));
                }
                i = j;
                continue;
            }
            Class::Selector | Class::SupplementSelector | Class::MongolianSelector => {
                let mut j = i;
                while chars.get(j).is_some_and(|(_, c)| {
                    matches!(
                        class(*c),
                        Some(
                            Class::Selector | Class::SupplementSelector | Class::MongolianSelector
                        )
                    )
                }) {
                    j = j.saturating_add(1);
                }
                let run = j.saturating_sub(i);
                let base_ok = prev.is_some_and(|p| class(p).is_none() && !p.is_whitespace());
                let ok = run == 1
                    && base_ok
                    && match k {
                        Class::Selector => true,
                        Class::SupplementSelector => prev.is_some_and(ideograph),
                        _ => prev.is_some_and(|p| ('\u{1800}'..='\u{18af}').contains(&p)),
                    };
                if !ok {
                    push(out, Reason::VariationRun, at, end_of(j.saturating_sub(1)));
                }
                i = j;
                continue;
            }
            Class::Format => push(out, Reason::Format, at, end_of(i)),
        }
        i = i.saturating_add(1);
    }
}
