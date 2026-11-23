//! M7 Q4, I-17, TH-60 (ADR-033 record of lane L40, Daniel 2026-11-23):
//! a text longer than the vault's cap is masked in pieces. The pieces
//! cover the text in order, each fits the cap, each cut falls where no
//! word and no date run crosses it, and the joined spans of the pieces are
//! exactly the spans of the whole text. So the mask is as strong as one
//! request over the whole text, and a name across a cut is still masked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::ops::Range;

use fstp_prop::{Gen, check, prop_assert};
use fstp_unorm::mask::{
    MASK_PIECE_BYTES, MASK_PIECES_PER_REQUEST, MAX_MASK_PIECES, MaskClass, MaskPerson, MaskSpan,
    join_piece_spans, mask_pieces, mask_spans,
};

/// Invented syllables, as the synthetic corpus builds its names.
const SYLLABLES: [&str; 8] = ["vel", "ino", "rra", "mar", "adi", "ne", "zor", "sef"];

fn name(g: &mut Gen) -> String {
    let n = g.usize_in(2..=3);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(g.pick(&SYLLABLES));
    }
    s
}

/// A text of names, words, separators, dates and characters of one to
/// four UTF-8 bytes, with paragraph and line breaks.
fn text(g: &mut Gen, names: &[String]) -> String {
    let tokens = [
        "word",
        " ",
        "  ",
        ", ",
        "-",
        ".",
        "/",
        "\n",
        "\n\n",
        "\r\n",
        "\t",
        "\u{301}",
        "ＶＥＬ",
        "2001-12-31",
        "31.12.2001",
        "31/12/2001",
        "é",
        "名前",
        "😀",
        "\u{a0}",
        "'",
        "’",
        ";",
    ];
    let mut s = String::new();
    for _ in 0..g.usize_in(0..=60) {
        if g.bool() && !names.is_empty() {
            let n = g.pick(names);
            match g.usize_in(0..=2) {
                0 => s.push_str(&n.to_uppercase()),
                1 => s.push_str(n),
                _ => {
                    // A full name, given then family, joined by a joiner.
                    s.push_str(n);
                    s.push_str(g.pick(&[" ", "-", "\n", "  "]));
                    s.push_str(g.pick(names));
                }
            }
        } else {
            s.push_str(g.pick(&tokens));
        }
        if g.bool() {
            s.push(' ');
        }
    }
    s
}

/// Whether `c` may stand just before a cut: white space, or a character
/// that is neither part of a word nor of a date run.
fn cut_char(c: char) -> bool {
    c.is_whitespace()
        || !(c.is_alphanumeric()
            || matches!(
                u32::from(c),
                0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F
            )
            || matches!(c, '.' | '/' | '-'))
}

/// The mask of `text` in `pieces`, each masked alone as the vault masks
/// one piece, then joined.
fn masked_in_pieces(
    text: &str,
    pieces: &[Range<usize>],
    people: &[MaskPerson],
) -> Option<Vec<MaskSpan>> {
    let spans: Vec<Vec<MaskSpan>> = pieces
        .iter()
        .map(|r| mask_spans(&text[r.clone()], people))
        .collect();
    join_piece_spans(text, pieces, &spans)
}

/// The longest run of characters, in bytes, before none of which a cut
/// may fall.
fn longest_uncut_run(text: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for c in text.chars() {
        if cut_char(c) {
            run = 0;
        } else {
            run += c.len_utf8();
            best = best.max(run);
        }
    }
    best
}

/// M7 Q4, I-17 (property): for any text and any piece size, the pieces
/// cover the text in order with nothing lost, added or reordered, each
/// fits the size, each cut follows white space or a character that no
/// word or date run holds, and the joined spans of the pieces equal the
/// spans of the whole text. A text whose window holds no such cut fails
/// closed, and only then.
#[test]
fn m7_q4_i17_pieces_mask_exactly_as_the_whole_text() {
    check(
        "m7_q4_i17_pieces_mask_exactly_as_the_whole_text",
        |g: &mut Gen| {
            let family = name(g);
            let given = name(g);
            let people = vec![
                MaskPerson::new(&family, &given, Some("2001-12-31")),
                MaskPerson::new(&name(g), &name(g), None),
            ];
            let t = text(g, &[family.clone(), given.clone()]);
            let max = g.usize_in(8..=48);
            let Some(pieces) = mask_pieces(&t, max) else {
                prop_assert!(
                    longest_uncut_run(&t) + 3 >= max,
                    "a refusal with a cut in reach"
                );
                return Ok(());
            };
            prop_assert!(!pieces.is_empty());
            let mut at = 0usize;
            for r in &pieces {
                prop_assert!(r.start == at, "the pieces are contiguous");
                prop_assert!(r.end - r.start <= max, "a piece over the size");
                prop_assert!(r.start < r.end || t.is_empty(), "an empty piece");
                prop_assert!(t.is_char_boundary(r.start) && t.is_char_boundary(r.end));
                at = r.end;
            }
            prop_assert!(at == t.len(), "the pieces cover the text");
            let joined: String = pieces.iter().map(|r| &t[r.clone()]).collect();
            prop_assert!(joined == t, "order and content are kept");
            for r in &pieces[..pieces.len() - 1] {
                let before = t[..r.end].chars().next_back();
                prop_assert!(before.is_some_and(cut_char), "a cut inside a word or date");
            }
            let whole = mask_spans(&t, &people);
            prop_assert!(
                masked_in_pieces(&t, &pieces, &people) == Some(whole),
                "the pieces mask otherwise than the whole text"
            );
            Ok(())
        },
    );
}

/// M7 Q4, I-17 (property): a piece answer that does not fit its piece, or
/// that is not sorted and disjoint, fails the join closed.
#[test]
fn m7_q4_i17_a_span_outside_its_piece_fails_the_join() {
    check(
        "m7_q4_i17_a_span_outside_its_piece_fails_the_join",
        |g: &mut Gen| {
            let family = name(g);
            let given = name(g);
            let people = vec![MaskPerson::new(&family, &given, None)];
            let mut t = text(g, &[family.clone(), given.clone()]);
            t.push_str(" word word word word word word word word");
            let Some(pieces) = mask_pieces(&t, 16) else {
                return Ok(());
            };
            let mut spans: Vec<Vec<MaskSpan>> = pieces
                .iter()
                .map(|r| mask_spans(&t[r.clone()], &people))
                .collect();
            let i = g.usize_in(0..=pieces.len() - 1);
            let len = u32::try_from(pieces[i].len()).unwrap();
            spans[i].push(MaskSpan {
                start: len,
                end: len + 1,
                person: 0,
                class: MaskClass::Name,
            });
            prop_assert!(join_piece_spans(&t, &pieces, &spans).is_none());
            spans[i].pop();
            if let Some(first) = spans[i].first().copied() {
                spans[i].push(first);
                prop_assert!(
                    join_piece_spans(&t, &pieces, &spans).is_none(),
                    "a repeated span"
                );
                spans[i].pop();
            }
            spans.pop();
            prop_assert!(
                join_piece_spans(&t, &pieces, &spans).is_none(),
                "a missing piece answer"
            );
            Ok(())
        },
    );
}

/// M7 Q4, I-17: a full name whose cut falls between its given and family
/// names is one span, as in the whole text, and the window that ends inside
/// the family name moves its cut back to the space.
#[test]
fn m7_q4_i17_a_name_across_a_cut_is_masked_as_one() {
    let p = MaskPerson::new("Velinorra-Quist", "Maradine", None);
    let t = "Lead is Maradine Velinorra-Quist here.";
    let max = "Lead is Maradine Veli".len();
    let pieces = mask_pieces(t, max).unwrap();
    assert_eq!(&t[pieces[0].clone()], "Lead is Maradine ");
    let whole = mask_spans(t, std::slice::from_ref(&p));
    assert_eq!(whole.len(), 1);
    let joined = masked_in_pieces(t, &pieces, std::slice::from_ref(&p)).unwrap();
    assert_eq!(joined, whole);
    assert_eq!(
        &t[joined[0].start as usize..joined[0].end as usize],
        "Maradine Velinorra-Quist"
    );
}

/// M7 Q4: the cut prefers a paragraph break, then a line break, then white
/// space, then a character that no word or date holds.
#[test]
fn m7_q4_cuts_prefer_paragraph_then_line_then_space() {
    let t = "aa\n\nbb\ncc dd";
    assert_eq!(mask_pieces(t, 10).unwrap(), vec![0..4, 4..12]);
    let t = "aa bb\ncc dd ee";
    assert_eq!(mask_pieces(t, 12).unwrap(), vec![0..6, 6..14]);
    let t = "aa bb cc dd ee";
    assert_eq!(mask_pieces(t, 10).unwrap(), vec![0..9, 9..14]);
    let t = "aa,bb;31.12.2001,cc";
    let pieces = mask_pieces(t, 12).unwrap();
    assert_eq!(pieces, vec![0..6, 6..17, 17..19]);
    assert_eq!(&t[pieces[1].clone()], "31.12.2001,");
}

/// M7 Q4, I-17: a window that holds no cut, such as one long word, fails
/// closed rather than cut a word or a UTF-8 sequence.
#[test]
fn m7_q4_i17_a_window_without_a_cut_fails_closed() {
    assert!(mask_pieces(&"a".repeat(40), 16).is_none());
    assert!(mask_pieces(&"名".repeat(40), 16).is_none());
    assert!(mask_pieces(&format!("aa {}", "31.12.2001".repeat(4)), 16).is_none());
    assert_eq!(mask_pieces("", 16).unwrap(), vec![0..0]);
    assert_eq!(mask_pieces("short text", 16).unwrap(), vec![0..10]);
}

/// M7 Q4, ADR-033: the vault cap is unchanged. A piece is at most 64 KiB,
/// one request carries at most three, and a text is at most 64 pieces.
#[test]
fn m7_q4_piece_bounds_keep_the_vault_cap() {
    assert_eq!(MASK_PIECE_BYTES, 64 << 10);
    assert_eq!(MASK_PIECES_PER_REQUEST, 3);
    assert_eq!(MAX_MASK_PIECES, 64);
    let long = "Maradine word, 2001-12-31.\n".repeat(10_000);
    let pieces = mask_pieces(&long, MASK_PIECE_BYTES).unwrap();
    assert!(pieces.len() > 1);
    assert!(pieces.iter().all(|r| r.len() <= MASK_PIECE_BYTES));
    let p = MaskPerson::new("Quist", "Maradine", Some("2001-12-31"));
    assert_eq!(
        masked_in_pieces(&long, &pieces, std::slice::from_ref(&p)),
        Some(mask_spans(&long, std::slice::from_ref(&p)))
    );
}
