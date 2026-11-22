//! M7 Q4, I-17 (ADR-033 record of lane L31): properties of the vault name
//! mask over generated texts and synthetic names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fstp_prop::{Gen, check, prop_assert};
use fstp_unorm::mask::{MaskClass, MaskPerson, mask_spans};

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

fn text(g: &mut Gen, names: &[String]) -> String {
    let pieces = [
        "word",
        " ",
        ", ",
        "-",
        ".",
        "\u{301}",
        "ＶＥＬ",
        "2001-12-31",
        "31.12.2001",
        "é",
    ];
    let mut s = String::new();
    for _ in 0..g.usize_in(0..=24) {
        if g.bool() && !names.is_empty() {
            let n = g.pick(names);
            if g.bool() {
                s.push_str(&n.to_uppercase())
            } else {
                s.push_str(n)
            }
        } else {
            s.push_str(g.pick(&pieces));
        }
        s.push(' ');
    }
    s
}

/// M7 Q4, I-17: every span lies on character boundaries inside the text,
/// the spans are sorted and disjoint, each names a person of the request,
/// and after masking no word of the text equals a name part of a person.
#[test]
fn m7_q4_i17_spans_are_sound_and_mask_every_name_word() {
    check(
        "m7_q4_i17_spans_are_sound_and_mask_every_name_word",
        |g: &mut Gen| {
            let family = name(g);
            let given = name(g);
            let people = vec![
                MaskPerson::new(&family, &given, Some("2001-12-31")),
                MaskPerson::new(&name(g), &name(g), None),
            ];
            let t = text(g, &[family.clone(), given.clone()]);
            let spans = mask_spans(&t, &people);
            let mut last = 0u32;
            for s in &spans {
                prop_assert!(s.start < s.end && s.start >= last);
                prop_assert!(
                    t.is_char_boundary(s.start as usize) && t.is_char_boundary(s.end as usize)
                );
                prop_assert!((s.end as usize) <= t.len() && (s.person as usize) < people.len());
                last = s.end;
            }
            let mut masked = String::new();
            let mut at = 0usize;
            for s in &spans {
                masked.push_str(&t[at..s.start as usize]);
                masked.push_str(match s.class {
                    MaskClass::Name => " ",
                    MaskClass::BirthDate => " ",
                });
                at = s.end as usize;
            }
            masked.push_str(&t[at..]);
            let parts: Vec<String> = [&family, &given]
                .iter()
                .map(|n| fstp_unorm::name_key(n))
                .collect();
            for w in masked.split(|c: char| !c.is_alphanumeric()) {
                let k = fstp_unorm::name_key(w);
                prop_assert!(!parts.contains(&k), "an unmasked name word");
            }
            prop_assert!(!masked.contains("2001-12-31") && !masked.contains("31.12.2001"));
            Ok(())
        },
    );
}
