//! The funding card in a message about a programme (ADR-034; I-68, I-69,
//! I-26, R-NF-04).
//!
//! The Funded by the European Union logo travels as an inline PNG part
//! named by its `Content-ID`, with its alternative text. The card's lines
//! close the HTML part, escaped, and the plain-text part. The body before
//! them is unchanged.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use fstp_mail::{FUNDING_CID, MailFunding, compose, parse};
use fstp_prop::{check, prop_assert, prop_assert_eq};

fn png() -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    b.extend_from_slice(&[7; 300]);
    b
}

fn funding() -> MailFunding {
    MailFunding {
        png: png(),
        alt: "Funded by the European Union".to_owned(),
        lines: vec![
            "Grant agreement number: SYNTHETIC-000000000".to_owned(),
            "Coordinator: Synthetic <b>coordinator</b> org".to_owned(),
            "Contact: role@example.org".to_owned(),
        ],
    }
}

fn part<'a>(m: &'a fstp_mail::ParsedMessage, ty: &str) -> Vec<&'a fstp_mail::ParsedPart> {
    m.parts.iter().filter(|p| p.content_type == ty).collect()
}

/// I-69, R-NF-04, I-68, I-26: a message about a programme carries the
/// logo inline with its alternative text and the card's lines, escaped,
/// at the end of both parts. The bytes are the same on every attempt.
#[test]
fn i69_programme_mail_carries_the_funding_card() {
    check("i69_programme_mail_carries_the_funding_card", |g| {
        let m = common::Owned::random(g);
        let plain = common::config();
        let mut cfg = common::config();
        cfg.funding = Some(funding());
        let a = compose(&plain, &m.message()).map_err(|e| format!("{e}"))?;
        let b = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        prop_assert!(b == compose(&cfg, &m.message()).unwrap(), "I-26");
        let pa = parse(&a).map_err(|e| format!("{e}"))?;
        let pb = parse(&b).map_err(|e| format!("{e}"))?;
        let images = part(&pb, "image/png");
        prop_assert_eq!(images.len(), 1);
        prop_assert_eq!(images[0].decoded.clone(), png());
        let html = String::from_utf8(part(&pb, "text/html")[0].decoded.clone()).unwrap();
        prop_assert!(
            html.contains(&format!("src=\"cid:{FUNDING_CID}\"")),
            "{html}"
        );
        prop_assert!(
            html.contains("alt=\"Funded by the European Union\""),
            "{html}"
        );
        prop_assert!(
            html.contains("Synthetic &lt;b&gt;coordinator&lt;/b&gt; org"),
            "{html}"
        );
        prop_assert!(html.contains("role@example.org"), "{html}");
        let text_a = String::from_utf8(part(&pa, "text/plain")[0].decoded.clone()).unwrap();
        let text_b = String::from_utf8(part(&pb, "text/plain")[0].decoded.clone()).unwrap();
        prop_assert!(
            text_b.starts_with(text_a.trim_end()),
            "the body is unchanged"
        );
        prop_assert!(text_b.contains("Grant agreement number: SYNTHETIC-000000000"));
        prop_assert!(text_b.contains("Funded by the European Union"));
        Ok(())
    });
}

/// ADR-034: a message about no programme carries no card.
#[test]
fn adr034_no_programme_no_card() {
    let cfg = common::config();
    assert!(cfg.funding.is_none());
}
