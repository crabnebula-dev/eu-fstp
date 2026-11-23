//! L-08 (ADR-034 section 1 "Usage rules", ADR-036): in a programme email
//! the Funded by the European Union logo keeps the official minimum
//! height and clear space, and the card's last line is the approved
//! funding acknowledgement (I-69, R-NF-04).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use fstp_mail::{MailFunding, compose, parse};
use fstp_prop::{check, prop_assert};

const SENTENCE: &str = "Synthetic programme is funded by the European Union under the Horizon Europe grant agreement SYNTHETIC-000000000, SYN.";

fn funding() -> MailFunding {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[7; 300]);
    MailFunding {
        png,
        alt: "Funded by the European Union".to_owned(),
        lines: vec![
            "Grant agreement number: SYNTHETIC-000000000".to_owned(),
            "Coordinator: Synthetic coordinator org".to_owned(),
            "Contact: role@example.org".to_owned(),
            SENTENCE.to_owned(),
        ],
    }
}

/// L-08, I-69: the logo is 48 px high, above the 1.08 cm (41 px) that
/// keeps the flag 1 cm high. Its clear space is at least 30.3 % of its
/// height (15 px) on every side inside the card, and the acknowledgement
/// closes both parts.
#[test]
fn l08_mail_logo_keeps_size_and_clear_space() {
    check("l08_mail_logo_keeps_size_and_clear_space", |g| {
        let m = common::Owned::random(g);
        let mut cfg = common::config();
        cfg.funding = Some(funding());
        let b = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let p = parse(&b).map_err(|e| format!("{e}"))?;
        let html = p
            .parts
            .iter()
            .find(|x| x.content_type == "text/html")
            .map(|x| String::from_utf8(x.decoded.clone()).unwrap())
            .unwrap();
        prop_assert!(html.contains("height:48px"), "{html}");
        prop_assert!(html.contains("padding:12px"), "{html}");
        prop_assert!(html.contains("margin:4px 15px 15px 4px"), "{html}");
        prop_assert!(html.contains(SENTENCE), "{html}");
        let text = p
            .parts
            .iter()
            .find(|x| x.content_type == "text/plain")
            .map(|x| String::from_utf8(x.decoded.clone()).unwrap())
            .unwrap();
        prop_assert!(text.trim_end().ends_with(SENTENCE), "{text}");
        Ok(())
    });
}
