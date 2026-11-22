//! L-08 (ADR-036): the approved funding acknowledgement on the funding
//! card of every public page (I-68, I-69, R-NF-04).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{Chrome, PublicFunding, PublicLogos, render_html};
use support::{count, sample_view, scriptless, traced_pages};

const SENTENCE: &str = "Synthetic programme is funded by the European Union under the Horizon Europe grant agreement SYNTHETIC-000000000, SYN.";

fn chrome(acknowledgement: Option<&str>, card: bool) -> Chrome {
    Chrome {
        stylesheet: None,
        funder: None,
        logos: PublicLogos {
            emblem: Some("/brand/funded-by-eu.svg".to_owned()),
            funding: card.then(|| PublicFunding {
                programme: "Synthetic programme".to_owned(),
                grant_number: "SYNTHETIC-000000000".to_owned(),
                coordinator: "Synthetic coordinator org".to_owned(),
                contact: "role@example.org".to_owned(),
                acknowledgement: acknowledgement.map(str::to_owned),
            }),
            ..PublicLogos::default()
        },
    }
}

fn footer(html: &str) -> String {
    html.split("<footer").nth(1).unwrap_or("").to_owned()
}

/// I-69, L-08: the card ends with the approved sentence, once, inside the
/// card region, and no page keeps the pending placeholder.
#[test]
fn i69_l08_public_card_shows_the_acknowledgement() {
    let view = sample_view(true);
    let c = chrome(Some(SENTENCE), true);
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
        let f = footer(&html);
        assert_eq!(count(&f, SENTENCE), 1, "{p:?}");
        let card = f.split("data-mandatory=\"funding_card\"").nth(1).unwrap();
        assert!(card.contains(SENTENCE), "{p:?}: inside the card");
        assert!(
            !html.contains("approved wording is pending.</span></p>"),
            "{p:?}"
        );
        assert!(!html.contains("EU funding acknowledgement"), "{p:?}");
        scriptless(&html).unwrap();
    }
}

/// L-08 (Daniel, 2026-11-22): a programme that lacks a value shows no
/// sentence at all, and no placeholder in its place.
#[test]
fn l08_public_card_without_values_shows_no_sentence() {
    let view = sample_view(true);
    for card in [true, false] {
        let c = chrome(None, card);
        for p in traced_pages(&view) {
            let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
            let f = footer(&html);
            assert!(!f.contains("is funded by the European Union"), "{p:?}");
            assert!(!f.contains("EU funding acknowledgement"), "{p:?}");
            assert!(f.contains("alt=\"Funded by the European Union\""), "{p:?}");
        }
    }
}

/// I-68: the sentence is a text node. A programme value that looks like
/// markup is escaped.
#[test]
fn i68_public_acknowledgement_is_text() {
    let view = sample_view(true);
    let c = chrome(Some("<b>x</b> is funded by the European Union"), true);
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
        assert!(!html.contains("<b>x</b>"), "{p:?}");
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt; is funded"), "{p:?}");
    }
}
