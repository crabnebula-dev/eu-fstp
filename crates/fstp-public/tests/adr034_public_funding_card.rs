//! The funding card in the footer of every public page (ADR-034; I-68,
//! I-69, R-WL-04, R-NF-04).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{Chrome, PublicFunding, PublicLogos, render_html};
use support::{count, sample_view, scriptless, traced_pages};

const SVG: &str = "/brand/funded-by-eu.svg";

fn chrome(contact: &str) -> Chrome {
    Chrome {
        stylesheet: None,
        funder: None,
        logos: PublicLogos {
            emblem: Some(SVG.to_owned()),
            funding: Some(PublicFunding {
                programme: "Synthetic programme".to_owned(),
                grant_number: "SYNTHETIC-000000000".to_owned(),
                coordinator: "Synthetic coordinator org".to_owned(),
                contact: contact.to_owned(),
            }),
            ..PublicLogos::default()
        },
    }
}

/// I-69, R-NF-04: every public page's one footer holds the funding card:
/// a labelled region with the Funded by the EU logo, its alternative
/// text, the grant agreement number and the coordinator's name and
/// contact. The platform attribution stays beside it (R-WL-04).
#[test]
fn i69_public_footer_holds_the_funding_card() {
    let view = sample_view(true);
    let c = chrome("role@example.org");
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
        assert_eq!(count(&html, "<footer"), 1, "{p:?}");
        let footer = html.split("<footer").nth(1).unwrap_or("");
        assert_eq!(count(footer, "data-mandatory=\"funding_card\""), 1, "{p:?}");
        assert!(footer.contains("aria-label=\"EU funding\""), "{p:?}");
        assert!(
            footer.contains(&format!("src=\"{SVG}\"")),
            "{p:?}: the logo"
        );
        assert!(
            footer.contains("alt=\"Funded by the European Union\""),
            "{p:?}: alt text"
        );
        for text in [
            "Synthetic programme",
            "Grant agreement number",
            "SYNTHETIC-000000000",
            "Coordinator",
            "Synthetic coordinator org",
            "Contact",
            "role@example.org",
            "EU funding acknowledgement",
        ] {
            assert!(footer.contains(text), "{p:?}: {text}");
        }
        assert!(footer.contains("<dl"), "{p:?}: label and value pairs");
        assert!(
            footer.contains("data-mandatory=\"platform_attribution\""),
            "{p:?}"
        );
        scriptless(&html).unwrap();
    }
}

/// I-68: a card value is text, never markup.
#[test]
fn i68_funding_card_values_are_escaped() {
    let view = sample_view(true);
    let c = chrome("<script>x</script>");
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
        assert!(!html.contains("<script>x"), "{p:?}");
        assert!(html.contains("&lt;script&gt;x"), "{p:?}");
    }
}

/// I-69: a page with no card shows the logo slot only, and never a card
/// region without its values.
#[test]
fn i69_no_card_means_no_card_region() {
    let view = sample_view(true);
    let mut c = chrome("role@example.org");
    c.logos.funding = None;
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &c).unwrap().as_str().to_owned();
        assert!(!html.contains("data-mandatory=\"funding_card\""), "{p:?}");
        assert!(
            html.contains("alt=\"Funded by the European Union\""),
            "{p:?}"
        );
    }
}
