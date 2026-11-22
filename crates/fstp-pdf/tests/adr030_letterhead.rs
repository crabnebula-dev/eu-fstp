//! Letterhead tests (ADR-030 section 6; R-WL-03, R-CT-01, ADR-016): the
//! logos pass through without decoding, the file still parses with the
//! verifier's parser, every signature field still takes its increment,
//! and an empty letterhead changes nothing.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use fstp_pdf::object::Object;
use fstp_pdf::{
    Image, ImageColours, Letterhead, PdfFile, WriteError, prepare_increment, verify_increment,
    write, write_with_letterhead,
};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// A synthetic image: a fixed zlib stream that nothing here decodes.
fn image(colours: ImageColours, width: u32, height: u32) -> Image {
    Image {
        width,
        height,
        colours,
        bits: 8,
        mask: None,
        data: vec![0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01],
        smask: None,
    }
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// R-CT-01: an empty letterhead writes exactly the bytes of `write`, so
/// every stored contract and Guide renders as before.
#[test]
fn r_ct_01_empty_letterhead_changes_nothing() {
    check("r_ct_01_empty_letterhead_changes_nothing", |g| {
        let doc = common::random_document(g);
        let a = write(&doc).map_err(|e| format!("{e}"))?;
        let b = write_with_letterhead(&doc, &Letterhead::default()).map_err(|e| format!("{e}"))?;
        prop_assert!(a == b, "an empty letterhead changed the file");
        Ok(())
    });
}

/// R-WL-03, I-68, ADR-016, ADR-030: with logos, one of them transparent
/// with an `/SMask`, and the emblem slot filled, the
/// file is deterministic, parses with the verifier's parser, holds each
/// image as one artifact-marked XObject with the PNG predictor, and every
/// field accepts the canonical increment. The only filtered streams are
/// the images.
#[test]
fn r_wl_03_letterhead_passes_images_through() {
    check("r_wl_03_letterhead_passes_images_through", |g| {
        let doc = common::random_document(g);
        let head = Letterhead {
            logos: vec![
                Image {
                    smask: Some(vec![0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]),
                    ..image(ImageColours::Rgb, 320, 80)
                },
                Image {
                    mask: Some(vec![1, 1]),
                    ..image(ImageColours::Indexed(vec![0, 0, 0, 255, 255, 255]), 64, 64)
                },
            ],
            emblem: g.bool().then(|| image(ImageColours::Gray, 120, 80)),
            funding: Vec::new(),
        };
        let pdf = write_with_letterhead(&doc, &head).map_err(|e| format!("{e}"))?;
        let again = write_with_letterhead(&doc, &head).map_err(|e| format!("{e}"))?;
        prop_assert!(pdf == again, "not deterministic");
        prop_assert!(has(&pdf, b"/Artifact BMC"), "no artifact mark");
        prop_assert!(has(&pdf, b"/Predictor 15"), "no predictor");
        prop_assert!(has(&pdf, b"/Mask [1 1]"), "no colour key");
        prop_assert!(has(&pdf, b"/SMask "), "no soft mask");
        let file = PdfFile::open(&pdf).map_err(|e| format!("{e}"))?;
        let objects = file.parse_all().map_err(|e| format!("{e}"))?;
        let mut images = 0usize;
        for (_, o) in &objects {
            if let Object::Stream(s) = o
                && s.dict.get(b"Filter").is_some()
            {
                prop_assert!(s.dict.get(b"Subtype").is_some(), "a filtered non-image");
                images += 1;
            }
        }
        // Each image, and the soft mask of the transparent one.
        prop_assert_eq!(
            images,
            head.logos.len() + usize::from(head.emblem.is_some()) + 1
        );
        for f in &doc.signature_fields {
            let inc = prepare_increment(&pdf, &f.name, 2048).map_err(|e| format!("{e}"))?;
            verify_increment(&pdf, &inc, &f.name).map_err(|e| format!("{}: {e}", f.name))?;
        }
        Ok(())
    });
}

/// ADR-030: an image outside the bounds, or a third logo, is refused.
#[test]
fn adr030_letterhead_bounds() {
    let doc = common::contract(2);
    let wide = image(ImageColours::Rgb, 4096, 10);
    let sixteen = Image {
        bits: 16,
        ..image(ImageColours::Gray, 10, 10)
    };
    let rgb_four = Image {
        bits: 4,
        ..image(ImageColours::Rgb, 10, 10)
    };
    let empty_palette = image(ImageColours::Indexed(Vec::new()), 10, 10);
    let three = Letterhead {
        logos: vec![image(ImageColours::Rgb, 10, 10); 3],
        emblem: None,
        funding: Vec::new(),
    };
    for head in [
        Letterhead {
            logos: vec![wide],
            emblem: None,
            funding: Vec::new(),
        },
        Letterhead {
            logos: vec![sixteen],
            emblem: None,
            funding: Vec::new(),
        },
        Letterhead {
            logos: Vec::new(),
            emblem: Some(rgb_four),
            funding: Vec::new(),
        },
        Letterhead {
            logos: vec![empty_palette],
            emblem: None,
            funding: Vec::new(),
        },
        three,
    ] {
        assert_eq!(
            write_with_letterhead(&doc, &head).err(),
            Some(WriteError::Image)
        );
    }
}
