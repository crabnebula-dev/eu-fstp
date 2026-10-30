//! The required sections of the Guide (I-52, `SPEC/02-domain/guide-for-applicants.md`
//! "Required sections").
//!
//! A section is present when the template holds a level 2 heading with
//! its title, whatever its number: `## N. Title` or `## Title`. Section 1
//! is titled with the programme name, as the shipped template writes it.
//! A renamed heading leaves its section missing. Interim, pending Daniel.

use crate::markdown::{Block, encode_inlines};

/// One required section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredSection {
    /// Its name in the table of `SPEC/02-domain/guide-for-applicants.md`.
    pub name: &'static str,
    /// The title of its heading in a template, after the section number.
    pub heading: &'static str,
}

const fn section(name: &'static str, heading: &'static str) -> RequiredSection {
    RequiredSection { name, heading }
}

/// The required sections, in the order of the specification's table.
pub const REQUIRED_SECTIONS: &[RequiredSection] = &[
    section("About the programme", "About {{programme.name}}"),
    section("Call at a glance", "Call at a glance"),
    section("What we fund", "What we fund"),
    section("Who can apply", "Who can apply"),
    section("How to apply", "How to apply"),
    section("How proposals are evaluated", "How proposals are evaluated"),
    section("How the amount is set", "How the amount is set"),
    section("Support programme", "Support programme"),
    section(
        "Financial support to third parties",
        "Financial support to third parties",
    ),
    section("Contract and payments", "Contract and payments"),
    section("Visibility and publication", "Visibility and publication"),
    section(
        "Data protection and confidentiality",
        "Data protection and confidentiality",
    ),
    section("Timeline", "Timeline"),
    section("Complaints", "Complaints"),
    section("Contact and FAQ", "Contact and FAQ"),
];

/// `title` without a leading section number `N. `.
fn unnumbered(title: &str) -> &str {
    let d = title.bytes().take_while(u8::is_ascii_digit).count();
    match title.get(d..).and_then(|r| r.strip_prefix(". ")) {
        Some(rest) if d > 0 => rest,
        _ => title,
    }
}

/// The names of the required sections `blocks` lack, in table order.
pub(crate) fn missing(blocks: &[Block]) -> Vec<&'static str> {
    let titles: Vec<String> = blocks
        .iter()
        .filter_map(|b| match b {
            Block::Heading { level: 2, content } => {
                Some(unnumbered(&encode_inlines(content)).to_owned())
            }
            _ => None,
        })
        .collect();
    REQUIRED_SECTIONS
        .iter()
        .filter(|s| !titles.iter().any(|t| t == s.heading))
        .map(|s| s.name)
        .collect()
}
