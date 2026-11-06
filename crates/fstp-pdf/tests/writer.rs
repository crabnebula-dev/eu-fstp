//! Writer tests: determinism (R-CT-01, R-GA-02, I-53), every output
//! parses with the verifier's parser, tagged structure (M5 design section
//! 3.3) and the one pinned font (ADR-017).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use fstp_pdf::object::Object;
use fstp_pdf::{Block, BlockKind, PdfFile, WriteError, prepare_increment, verify_increment, write};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// R-CT-01, R-GA-02, I-53: equal input gives equal bytes, so re-rendering
/// a stored contract version or a published Guide gives the same PDF.
#[test]
fn r_ct_01_r_ga_02_i_53_writer_is_deterministic() {
    check("r_ct_01_r_ga_02_i_53_writer_is_deterministic", |g| {
        let doc = common::random_document(g);
        let a = write(&doc).map_err(|e| format!("{e}"))?;
        let b = write(&doc.clone()).map_err(|e| format!("{e}"))?;
        prop_assert!(a == b, "two renderings differ");
        Ok(())
    });
}

/// R-GA-02, ADR-016: every writer output parses with the increment
/// verifier's parser, holds no stream filter, and every declared field
/// accepts the canonical increment.
#[test]
fn r_ga_02_adr_016_writer_output_parses_with_the_verifier_parser() {
    check(
        "r_ga_02_adr_016_writer_output_parses_with_the_verifier_parser",
        |g| {
            let doc = common::random_document(g);
            let pdf = write(&doc).map_err(|e| format!("{e}"))?;
            let file = PdfFile::open(&pdf).map_err(|e| format!("{e}"))?;
            let objects = file.parse_all().map_err(|e| format!("{e}"))?;
            prop_assert_eq!(objects.len() + 1, file.size() as usize);
            for (_, o) in &objects {
                if let Object::Stream(s) = o {
                    prop_assert!(s.dict.get(b"Filter").is_none(), "a filtered stream");
                }
            }
            let catalog = file
                .dict(file.root().unwrap())
                .map_err(|e| format!("{e}"))?;
            prop_assert!(catalog.get(b"StructTreeRoot").is_some(), "untagged");
            prop_assert!(catalog.get(b"MarkInfo").is_some(), "no MarkInfo");
            prop_assert!(catalog.get(b"Lang").is_some(), "no Lang");
            for f in &doc.signature_fields {
                let inc = prepare_increment(&pdf, &f.name, 2048).map_err(|e| format!("{e}"))?;
                verify_increment(&pdf, &inc, &f.name).map_err(|e| format!("{}: {e}", f.name))?;
            }
            Ok(())
        },
    );
}

/// R-CT-01: the synthetic contract renders across pages, and a byte-equal
/// re-render holds.
#[test]
fn r_ct_01_long_contract_spans_pages_and_is_stable() {
    let doc = common::contract(120);
    let a = write(&doc).unwrap();
    assert_eq!(a, write(&doc).unwrap());
    let file = PdfFile::open(&a).unwrap();
    let pages = file
        .dict(
            file.dict(file.root().unwrap())
                .unwrap()
                .reference(b"Pages")
                .unwrap(),
        )
        .unwrap();
    assert!(pages.int(b"Count").unwrap() > 3);
    assert!(a.starts_with(b"%PDF-1.7\n"));
    assert!(a.ends_with(b"%%EOF\n"));
}

/// R-CT-01: a change of one character gives other bytes.
#[test]
fn r_ct_01_content_change_changes_bytes() {
    let doc = common::contract(3);
    let mut other = doc.clone();
    other.blocks[1].text.push('!');
    assert_ne!(write(&doc).unwrap(), write(&other).unwrap());
}

/// The writer refuses what it cannot render faithfully.
#[test]
fn r_ga_02_writer_refuses_unrenderable_input() {
    let mut doc = common::contract(1);
    doc.blocks.push(Block {
        kind: BlockKind::Paragraph,
        text: "\u{4e00}".into(),
    });
    assert_eq!(write(&doc), Err(WriteError::GlyphMissing('\u{4e00}')));

    let mut doc = common::contract(1);
    doc.blocks[0].text = "tab\there".into();
    assert_eq!(write(&doc), Err(WriteError::Text { index: 0 }));

    let mut doc = common::contract(1);
    doc.signature_fields[1].name = "lead".into();
    assert_eq!(write(&doc), Err(WriteError::FieldName { index: 1 }));

    let mut doc = common::contract(1);
    doc.signature_fields[0].name = "a.b".into();
    assert_eq!(write(&doc), Err(WriteError::FieldName { index: 0 }));

    let mut doc = common::contract(1);
    doc.lang = "en)".into();
    assert_eq!(write(&doc), Err(WriteError::Lang));
}

/// ADR-017: the embedded font is the pinned file, and it parses.
#[test]
fn adr_017_embedded_font_matches_its_pin() {
    assert_eq!(
        fstp_crypto::sha256(fstp_pdf::font::EMBEDDED_FONT),
        fstp_pdf::font::EMBEDDED_FONT_SHA256
    );
    let font = fstp_pdf::embedded_font().unwrap();
    assert_eq!(font.units_per_em, 1000);
    for c in ['A', 'z', '0', '€', 'ł', 'ß', ' '] {
        let g = font.glyph(c).unwrap_or_else(|| panic!("no glyph for {c}"));
        assert!(font.advance(g) > 0 || c == ' ');
    }
    assert_eq!(font.glyph('\u{4e00}'), None);
}

/// TH-26: the TrueType reader refuses truncations and stays in bounds.
#[test]
fn adr_017_truetype_reader_refuses_truncations() {
    let bytes = fstp_pdf::font::EMBEDDED_FONT;
    for cut in [0, 4, 12, 100, 300, 5000] {
        assert!(
            fstp_pdf::TrueType::parse(&bytes[..cut]).is_err(),
            "cut {cut}"
        );
    }
}
