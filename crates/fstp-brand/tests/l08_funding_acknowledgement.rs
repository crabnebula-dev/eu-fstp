//! L-08 (ADR-036, ADR-034 section 1 "Usage rules"): the funding
//! acknowledgement on the card, and the emblem's minimum size and clear
//! space in the stylesheets (I-69, R-NF-04).
//!
//! The usage rules come from the European Commission's "The use of the EU
//! emblem in the context of EU programmes 2021-2027, Operational
//! guidelines for recipients of EU funding" (March 2021), as ADR-034
//! cites it: the emblem's minimum height is 1 cm, and its protection area
//! stays free of competing texts, logos and images.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_brand::funding::{
    EMBLEM_CLEAR_SPACE, EMBLEM_MIN_HEIGHT, FUNDED_BY_EU_SVG, FundingCard, NOT_SET,
};

const SENTENCE: &str = "Synthetic programme is funded by the European Union under the Horizon Europe grant agreement SYNTHETIC-000000000, SYN.";

fn card(acknowledgement: Option<&str>) -> FundingCard {
    FundingCard {
        programme: 7,
        name: "Synthetic programme".to_owned(),
        grant_number: Some("SYNTHETIC-000000000".to_owned()),
        coordinator_name: Some("Synthetic coordinator".to_owned()),
        coordinator_contact: Some("contact@example.org".to_owned()),
        acknowledgement: acknowledgement.map(str::to_owned),
        acknowledgement_missing: if acknowledgement.is_some() {
            Vec::new()
        } else {
            vec!["action_acronym"]
        },
    }
}

/// I-69, L-08: PDFs and emails carry the card's text lines, and the
/// approved sentence is their last line.
#[test]
fn i69_l08_text_lines_end_with_the_acknowledgement() {
    let lines = card(Some(SENTENCE)).text_lines();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines.last().map(String::as_str), Some(SENTENCE));
}

/// L-08 (Daniel, 2026-11-22): a card whose acknowledgement cannot be
/// rendered shows no sentence and no placeholder.
#[test]
fn l08_no_acknowledgement_means_no_line() {
    let lines = card(None).text_lines();
    assert_eq!(lines.len(), 3);
    for l in &lines {
        assert!(!l.contains("pending"), "{l}");
        assert!(!l.contains("funded by the European Union"), "{l}");
        assert_ne!(l, NOT_SET);
    }
}

/// The number before `suffix` that ends at `at` in `s`.
fn number_before(s: &str, suffix: &str) -> f64 {
    s.strip_suffix(suffix).unwrap().parse().unwrap()
}

/// L-08: the logo's minimum height keeps the flag at least 1 cm high. The
/// flag is 44 of the artwork's 47.519501 units of height, so the logo
/// needs at least 1 cm times 47.519501 / 44.
#[test]
fn l08_emblem_minimum_height_keeps_the_flag_one_centimetre() {
    assert!(FUNDED_BY_EU_SVG.contains("viewBox=\"0 0 230.88268 47.519501\""));
    assert!(FUNDED_BY_EU_SVG.contains("d=\"m -24.167449,57.3242 h 66 v 44 h -66 z m 0,0\""));
    let need = 47.519501 / 44.0;
    let min = number_before(EMBLEM_MIN_HEIGHT, "cm");
    assert!(min >= need, "{min} < {need}");
    assert!(min - need < 0.01, "no more than the rounding");
}

/// L-08: the clear space around the logo is at least the gap the
/// artwork leaves between the flag and the words, as a share of the
/// logo's height. The flag ends at x = 41.832551, the words start at
/// x = 56.223181, and the height is 47.519501.
#[test]
fn l08_emblem_clear_space_is_the_flag_to_words_gap() {
    assert!(FUNDED_BY_EU_SVG.contains(
        "d=\"m 57.816931,64.957 v 4.3594 h 6.51562 v 1.3125 h -6.51562 v 4.7344 h -1.59375 V"
    ));
    let gap = (57.816931 - 1.59375) - (-24.167449 + 66.0);
    let share = gap / 47.519501;
    for (height, space) in EMBLEM_CLEAR_SPACE {
        let h = number_before(height, "rem");
        let s = number_before(space, "rem");
        assert!(s / h >= share, "{space} around {height}");
    }
}

/// L-08, I-69: the stylesheets of the app, public and sign-in pages give
/// both logo rules the minimum height and the clear space, and keep no
/// 32 px placeholder.
#[test]
fn l08_stylesheets_apply_the_emblem_rules() {
    for css in [
        include_str!("../../../web/src/site/tokens.css"),
        include_str!("../../../web/src/auth/tokens.css"),
    ] {
        for (selector, (height, space)) in [".eu-emblem {", ".funding-card .eu-emblem {"]
            .into_iter()
            .zip(EMBLEM_CLEAR_SPACE)
        {
            let rule = css
                .lines()
                .find(|l| l.starts_with(selector))
                .unwrap_or_else(|| panic!("no rule {selector}"));
            assert!(rule.contains(&format!("height: {height};")), "{rule}");
            assert!(
                rule.contains(&format!("min-height: {EMBLEM_MIN_HEIGHT};")),
                "{rule}"
            );
            assert!(rule.contains(&format!("margin: {space};")), "{rule}");
        }
        assert!(!css.contains("min-height: 32px"));
    }
}

/// ADR-034 Q11 (Daniel, 2026-11-23): the Commission's emblem rules say
/// not to write the programme's name in conjunction with the EU emblem.
/// The card's text lines, which follow the logo in PDFs and emails, never
/// name the programme on a line of their own. The name shows only inside
/// the acknowledgement sentence, and not at all while it cannot render.
#[test]
fn adr034_q11_text_lines_name_the_programme_only_in_the_acknowledgement() {
    let c = card(Some(SENTENCE));
    let lines = c.text_lines();
    let named: Vec<&String> = lines.iter().filter(|l| l.contains(&c.name)).collect();
    assert_eq!(named, [&SENTENCE.to_owned()], "{lines:?}");
    assert!(
        !lines[0].contains(&c.name),
        "the line after the logo: {lines:?}"
    );
    let c = card(None);
    let lines = c.text_lines();
    assert!(
        lines.iter().all(|l| !l.contains(&c.name)),
        "no sentence, no name: {lines:?}"
    );
}
