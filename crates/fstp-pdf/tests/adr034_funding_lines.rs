//! ADR-034: the funding card's lines in a PDF of a programme (I-69,
//! R-NF-04). They follow the letterhead band, whose emblem slot holds the
//! Funded by the European Union logo, as tagged paragraphs, so a screen
//! reader reads them like the rest of the text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use fstp_pdf::{Block, BlockKind, Letterhead, WriteError, write_with_letterhead};
use fstp_prop::{check, prop_assert};

fn lines() -> Vec<String> {
    vec![
        "Grant agreement number: SYNTHETIC-000000000".to_owned(),
        "Coordinator: Synthetic coordinator org".to_owned(),
        "Contact: role@example.org".to_owned(),
    ]
}

/// I-69, R-NF-04: a letterhead with the card's lines writes the same file
/// as the document with those lines as its first paragraphs.
#[test]
fn i69_funding_lines_are_the_first_tagged_paragraphs() {
    check("i69_funding_lines_are_the_first_tagged_paragraphs", |g| {
        let doc = common::random_document(g);
        let head = Letterhead {
            funding: lines(),
            ..Letterhead::default()
        };
        let a = write_with_letterhead(&doc, &head).map_err(|e| format!("{e}"))?;
        let mut longer = doc.clone();
        let mut blocks: Vec<Block> = lines()
            .into_iter()
            .map(|text| Block {
                kind: BlockKind::Paragraph,
                text,
            })
            .collect();
        blocks.append(&mut longer.blocks);
        longer.blocks = blocks;
        let b =
            write_with_letterhead(&longer, &Letterhead::default()).map_err(|e| format!("{e}"))?;
        prop_assert!(a == b, "the funding lines are not the first paragraphs");
        Ok(())
    });
}

/// I-68: a line with a control character is refused like any block text.
#[test]
fn i68_funding_line_with_a_control_character_is_refused() {
    let doc = fstp_pdf::Document {
        title: "Synthetic".into(),
        lang: "en".into(),
        blocks: vec![Block {
            kind: BlockKind::Paragraph,
            text: "Synthetic clause.".into(),
        }],
        signature_fields: Vec::new(),
    };
    let head = Letterhead {
        funding: vec!["bad\u{7}line".to_owned()],
        ..Letterhead::default()
    };
    assert_eq!(
        write_with_letterhead(&doc, &head).err(),
        Some(WriteError::Text { index: 0 })
    );
}
