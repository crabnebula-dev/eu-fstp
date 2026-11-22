//! Branded messages (ADR-030 section 5; I-68, I-72, I-26, R-WL-03).
//!
//! The logos travel as inline PNG parts of a `multipart/related` HTML
//! part. The plain-text part and every approved text stay unchanged, and
//! the message stays the same bytes on every attempt.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use fstp_mail::{MailBrand, MailLogo, compose, parse};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// A synthetic PNG: the signature and bytes that nothing here decodes.
fn png(tag: u8) -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    b.extend_from_slice(&[tag; 300]);
    b
}

fn brand() -> MailBrand {
    MailBrand {
        colour: [0x1e, 0x40, 0xaf],
        logos: vec![
            MailLogo {
                png: png(1),
                alt: "Harbour <b>Fund</b>".to_owned(),
            },
            MailLogo {
                png: b"RIFF\0\0\0\0WEBP".to_vec(),
                alt: String::new(),
            },
            MailLogo {
                png: png(2),
                alt: String::new(),
            },
        ],
    }
}

fn part<'a>(m: &'a fstp_mail::ParsedMessage, ty: &str) -> Vec<&'a fstp_mail::ParsedPart> {
    m.parts.iter().filter(|p| p.content_type == ty).collect()
}

/// R-WL-03, I-68, I-72: a branded message carries each PNG logo as an
/// inline part, names it by `Content-ID` in the HTML header with its
/// text alternative escaped, and draws the rule from the colour's bytes.
/// A logo that is no PNG is left out. The plain-text part is the same as
/// without the brand, so no approved wording changes.
#[test]
fn r_wl_03_branded_mail_carries_inline_logos() {
    check("r_wl_03_branded_mail_carries_inline_logos", |g| {
        let m = common::Owned::random(g);
        let plain = common::config();
        let mut cfg = common::config();
        cfg.brand = Some(brand());
        let a = compose(&plain, &m.message()).map_err(|e| format!("{e}"))?;
        let b = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let again = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        prop_assert!(b == again, "I-26: not deterministic");
        let pa = parse(&a).map_err(|e| format!("{e}"))?;
        let pb = parse(&b).map_err(|e| format!("{e}"))?;
        prop_assert_eq!(
            part(&pa, "text/plain")[0].decoded.clone(),
            part(&pb, "text/plain")[0].decoded.clone()
        );
        let images = part(&pb, "image/png");
        prop_assert_eq!(images.len(), 2);
        prop_assert_eq!(images[0].decoded.clone(), png(1));
        prop_assert_eq!(images[1].decoded.clone(), png(2));
        let html = String::from_utf8(part(&pb, "text/html")[0].decoded.clone()).unwrap();
        prop_assert!(html.contains("src=\"cid:logo-0@fstp\""), "{html}");
        prop_assert!(html.contains("src=\"cid:logo-1@fstp\""), "{html}");
        prop_assert!(
            html.contains("alt=\"Harbour &lt;b&gt;Fund&lt;/b&gt;\""),
            "{html}"
        );
        prop_assert!(!html.contains("<b>Fund"), "{html}");
        prop_assert!(html.contains("#1e40af"), "{html}");
        let plain_html = String::from_utf8(part(&pa, "text/html")[0].decoded.clone()).unwrap();
        prop_assert!(!plain_html.contains("cid:"), "{plain_html}");
        Ok(())
    });
}

/// I-68: with the brand set but no logo, the message has no image part
/// and keeps the `multipart/alternative` shape.
#[test]
fn i68_brand_without_logos_adds_no_image() {
    let mut cfg = common::config();
    cfg.brand = Some(MailBrand {
        colour: [0, 0, 0],
        logos: Vec::new(),
    });
    check("i68_brand_without_logos_adds_no_image", |g| {
        let m = common::Owned::random(g);
        let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let p = parse(&raw).map_err(|e| format!("{e}"))?;
        prop_assert!(part(&p, "image/png").is_empty());
        prop_assert!(!String::from_utf8_lossy(&raw).contains("multipart/related"));
        Ok(())
    });
}
