//! The Markdown subset of the Guide (TH-26, I-68, R-GA-01, M4 design
//! section 3.10: "`fstp-guide` parses only the subset the template uses
//! (headings, paragraphs, lists, tables, emphasis and links), refuses
//! anything else").
//!
//! The subset, read from the shipped template (interim, pending Daniel):
//!
//! - ATX headings of levels 1 to 3;
//! - paragraphs, with soft line breaks;
//! - the thematic break `---` after a blank line;
//! - pipe tables with a header row and a `| --- |` delimiter row;
//! - flat bullet lists with `- ` and flat ordered lists with `1. `;
//! - strong emphasis with `**`, and code spans;
//! - inline links to `https:` addresses, which the design names although
//!   the template uses none.
//!
//! The template uses the thematic break and a code span, which the
//! design's list omits, so the subset holds both. Every other construct is
//! refused, never passed through as text.
//!
//! A code span holds its text literally, but not every text. The
//! characters `<`, `\` and `~`, the pairs `![` and `[^` and character
//! references such as `&lt;` are refused everywhere, inside code spans
//! and link addresses too. That is stricter than CommonMark, and it keeps
//! the `guide_markdown_parse` oracle a plain scan of the input.
//!
//! The tests were written red against the W0 stub, which refused every
//! input with `NotImplemented`. The refusal tests accept only a real
//! refusal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_prop::{Gen, check, prop_assert};
use support::{
    Fail, SPEC_TEMPLATE, markdown_round_trips, parse_markdown, parse_markdown_is_stable,
};

/// One document per construct of the subset.
const IN_SUBSET: &[(&str, &str)] = &[
    ("heading 1", "# Guide for Applicants\n"),
    ("heading 2", "## 1. About the programme\n"),
    ("heading 3", "### Eligibility check\n"),
    ("paragraph", "Proposals must fit the scope.\n"),
    (
        "paragraph with a soft break",
        "Reviewers may use AI assistants.\nThey declare conflicts first.\n",
    ),
    ("bare ampersand", "Funding & Tenders Portal, R&D first.\n"),
    (
        "parentheses and ids",
        "Parameter-bound text is locked (I-51).\n",
    ),
    ("thematic break", "Intro.\n\n---\n\n## 1. Next\n"),
    (
        "table",
        "| Item | Value |\n| --- | --- |\n| Call | one |\n| Opens | today |\n",
    ),
    ("bullet list", "- first,\n- second,\n- third.\n"),
    (
        "ordered list",
        "1. Create an account.\n2. Draft.\n3. Submit.\n",
    ),
    ("strong in a list", "- **Mentoring** by an expert.\n"),
    (
        "strong in a paragraph",
        "A **chance to present** results.\n",
    ),
    ("code span", "Sections marked `TODO(legal)` need wording.\n"),
    (
        "link",
        "Read the [privacy statement](https://example.org/privacy).\n",
    ),
];

/// One document per construct outside the subset.
const OUTSIDE_SUBSET: &[(&str, &str)] = &[
    ("raw HTML block", "<div>block</div>\n"),
    ("script element", "<script>alert(1)</script>\n"),
    ("inline HTML", "Text <b>bold</b> here.\n"),
    ("HTML in a table cell", "| A |\n| --- |\n| <i>x</i> |\n"),
    ("HTML comment", "<!-- hidden -->\n"),
    ("autolink", "See <https://example.org>.\n"),
    ("fenced code with backticks", "```\ncode\n```\n"),
    ("fenced code with tildes", "~~~\ncode\n~~~\n"),
    ("indented code block", "Text.\n\n    code\n"),
    ("block quote", "> quoted\n"),
    ("setext heading with =", "Title\n=====\n"),
    ("setext heading with -", "Title\n---\n"),
    ("image", "![alt](https://example.org/a.png)\n"),
    (
        "reference link",
        "See [the call][call].\n\n[call]: https://example.org/\n",
    ),
    (
        "link reference definition",
        "[call]: https://example.org/\n",
    ),
    ("footnote", "Text[^1].\n\n[^1]: Note.\n"),
    ("strikethrough", "Text ~~struck~~ here.\n"),
    ("task list item", "- [ ] open\n"),
    ("nested list", "- outer\n  - inner\n"),
    ("named character reference", "Text &lt;b&gt; here.\n"),
    ("decimal character reference", "Text &#60; here.\n"),
    ("hexadecimal character reference", "Text &#x3C; here.\n"),
    ("backslash escape", "Text \\*not emphasis\\* here.\n"),
    ("backslash hard break", "Line one\\\nline two.\n"),
    ("two-space hard break", "Line one  \nline two.\n"),
    ("javascript link", "[x](javascript:alert(1))\n"),
    ("data link", "[x](data:text/html,hi)\n"),
    ("GFM table without bars", "a | b\n:-- | ---\n"),
    (
        "GFM table with aligned cells",
        "Item | Value\n:---: | ---:\n",
    ),
    ("GFM table with a trailing bar", "a |\n:- |\n"),
    ("GFM aligned delimiter row with bars", "| a |\n| :-- |\n"),
];

/// TH-26, R-GA-01: every construct of the subset is accepted on its own.
#[test]
fn th26_markdown_subset_accepts_each_construct_the_template_uses() {
    let mut wrong = Vec::new();
    for (name, doc) in IN_SUBSET {
        if let Err(e) = parse_markdown(doc.as_bytes()) {
            wrong.push(format!("{name}: {e}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// TH-26, I-68: every construct outside the subset is refused, never passed
/// through.
#[test]
fn th26_markdown_subset_refuses_every_construct_outside_it() {
    let mut wrong = Vec::new();
    for (name, doc) in OUTSIDE_SUBSET {
        match parse_markdown(doc.as_bytes()) {
            Err(Fail::Refused(_)) => {}
            Err(Fail::Missing(m)) => wrong.push(format!("{name}: {m}")),
            Ok(()) => wrong.push(format!("{name}: accepted {doc:?}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// TH-26, R-GA-01: the shipped template, with each placeholder replaced by
/// a word, is inside the subset.
#[test]
fn th26_markdown_subset_covers_the_shipped_template() {
    let mut text = String::new();
    let mut rest = SPEC_TEMPLATE;
    while let Some(start) = rest.find("{{") {
        text.push_str(&rest[..start]);
        let end = rest[start..].find("}}").expect("closed placeholder") + start + 2;
        text.push_str("value");
        rest = &rest[end..];
    }
    text.push_str(rest);
    if let Err(e) = parse_markdown(text.as_bytes()) {
        panic!("the shipped template leaves the subset: {e}");
    }
}

/// TH-26: parsing the same document twice gives equal documents.
#[test]
fn th26_markdown_parse_is_deterministic() {
    let doc = IN_SUBSET
        .iter()
        .map(|(_, d)| *d)
        .collect::<Vec<_>>()
        .join("\n");
    match parse_markdown_is_stable(doc.as_bytes()) {
        Ok(true) => {}
        Ok(false) => panic!("two parses differ"),
        Err(e) => panic!("{e}"),
    }
}

/// Words that keep a generated line inside the subset wherever they stand.
const WORDS: &[&str] = &[
    "grant", "call", "EUR", "Horizon", "Europe", "&", "(I-51)", "open", "R&D", "review", "5000.00",
    "2", "Guide,", "scope.",
];

fn words(g: &mut Gen, n: std::ops::RangeInclusive<usize>) -> String {
    g.vec(n, |g| (*g.pick(WORDS)).to_owned()).join(" ")
}

/// An inline run: words, strong words, a code span or a link.
fn inline(g: &mut Gen) -> String {
    match g.usize_in(0..=3) {
        0 => words(g, 1..=4),
        1 => format!("**{}**", words(g, 1..=2)),
        2 => format!("`{}`", words(g, 1..=2)),
        _ => format!("[{}](https://example.org/{})", words(g, 1..=2), g.u8()),
    }
}

/// A line of inline runs.
fn line(g: &mut Gen) -> String {
    let first = words(g, 1..=2);
    let more = g.vec(0..=3, inline);
    std::iter::once(first)
        .chain(more)
        .collect::<Vec<_>>()
        .join(" ")
}

/// One block of the subset, of kind `kind` (0 to 5).
fn block(g: &mut Gen, kind: usize) -> String {
    match kind {
        0 => format!("{} {}", "#".repeat(g.usize_in(1..=3)), words(g, 1..=4)),
        1 => g.vec(1..=2, line).join("\n"),
        2 => g.vec(1..=3, |g| format!("- {}", line(g))).join("\n"),
        3 => g
            .vec(1..=3, line)
            .into_iter()
            .enumerate()
            .map(|(i, l)| format!("{}. {l}", i + 1))
            .collect::<Vec<_>>()
            .join("\n"),
        4 => {
            let rows = g.vec(1..=2, |g| format!("| {} | {} |", line(g), line(g)));
            format!(
                "| {} | {} |\n| --- | --- |\n{}",
                words(g, 1..=2),
                words(g, 1..=2),
                rows.join("\n")
            )
        }
        _ => "---".to_owned(),
    }
}

/// TH-26, I-68: a document of subset blocks is accepted, and the same
/// document with one construct from outside the subset added as its own
/// block is refused.
#[test]
fn th26_markdown_accepts_the_subset_and_refuses_one_construct_outside_it() {
    check(
        "th26_markdown_accepts_the_subset_and_refuses_one_construct_outside_it",
        |g| {
            let kinds = g.vec(1..=6, |g| g.usize_in(0..=5));
            let mut blocks = Vec::new();
            for (i, k) in kinds.iter().enumerate() {
                // Two lists of one kind with only a blank line between them
                // are one loose list, which the template never uses.
                if i > 0 && (*k == 2 || *k == 3) && kinds[i - 1] == *k {
                    blocks.push(words(g, 1..=3));
                }
                blocks.push(block(g, *k));
            }
            let injected = if g.bool() {
                let (name, doc) = *g.pick(OUTSIDE_SUBSET);
                let at = g.usize_in(0..=blocks.len());
                blocks.insert(at, doc.trim_end().to_owned());
                Some(name)
            } else {
                None
            };
            let doc = format!("{}\n", blocks.join("\n\n"));
            g.note("doc", &doc);
            match (injected, parse_markdown(doc.as_bytes())) {
                (None, Ok(())) | (Some(_), Err(Fail::Refused(_))) => Ok(()),
                (_, Err(Fail::Missing(m))) => Err(m),
                (None, Err(Fail::Refused(m))) => Err(format!("refused a subset document: {m}")),
                (Some(name), Ok(())) => {
                    prop_assert!(false, "accepted a document holding {name}");
                    Ok(())
                }
            }
        },
    );
}

/// TH-26, I-68: inside a code span, an escape, a tilde, a character
/// reference, HTML, an image opener and a footnote opener are refused as
/// they are everywhere else (module documentation).
#[test]
fn th26_code_spans_refuse_what_the_subset_refuses_everywhere() {
    let cases = [
        "Code `a\\*b` here.\n",
        "Code `x~~y` here.\n",
        "Code `&lt;` here.\n",
        "Code `&#60;` here.\n",
        "Code `<b>` here.\n",
        "Code `![x](https://a.example/)` here.\n",
        "Code `[^1]` here.\n",
    ];
    let mut wrong = Vec::new();
    for doc in cases {
        match parse_markdown(doc.as_bytes()) {
            Err(Fail::Refused(_)) => {}
            other => wrong.push(format!("{doc:?}: {other:?}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// TH-26: a document of subset blocks round-trips through its canonical
/// spelling: parsing the spelling gives an equal document.
#[test]
fn th26_markdown_round_trips_through_its_canonical_spelling() {
    check(
        "th26_markdown_round_trips_through_its_canonical_spelling",
        |g| {
            let kinds = g.vec(1..=6, |g| g.usize_in(0..=5));
            let mut blocks = Vec::new();
            for (i, k) in kinds.iter().enumerate() {
                if i > 0 && (*k == 2 || *k == 3) && kinds[i - 1] == *k {
                    blocks.push(words(g, 1..=3));
                }
                blocks.push(block(g, *k));
            }
            let doc = format!("{}\n", blocks.join("\n\n"));
            g.note("doc", &doc);
            match markdown_round_trips(doc.as_bytes()) {
                Ok(same) => {
                    prop_assert!(same, "the canonical spelling parses to another document");
                    Ok(())
                }
                Err(e) => Err(format!("{e}")),
            }
        },
    );
}
