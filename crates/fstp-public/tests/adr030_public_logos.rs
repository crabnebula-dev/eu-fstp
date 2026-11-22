//! Logos and the EU funding slot on the public pages (ADR-030; I-68,
//! I-69, R-WL-03, R-WL-04).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{Chrome, PublicLogos, render_html};
use support::{count, sample_view, scriptless, traced_pages};

fn path(n: u8, ext: &str) -> String {
    format!("/brand/{}.{ext}", format!("{n:02x}").repeat(32))
}

fn logos(emblem: bool) -> PublicLogos {
    PublicLogos {
        tenant_light: Some(path(0xa1, "png")),
        tenant_dark: Some(path(0xa2, "webp")),
        programme_light: Some(path(0xb1, "png")),
        programme_dark: None,
        emblem: emblem.then(|| "/brand/eu-emblem.png".to_owned()),
        funding: None,
    }
}

/// R-WL-03, I-68: the header shows the tenant's light and dark logos and
/// then the programme's, each by its digest path, decorative with an
/// empty `alt`, before the programme's name. No logo turns into a script
/// or a style.
#[test]
fn r_wl_03_public_header_shows_tenant_then_programme_logos() {
    let view = sample_view(true);
    let chrome = Chrome {
        stylesheet: None,
        funder: None,
        logos: logos(false),
    };
    for p in traced_pages(&view) {
        let html = render_html(&view, &p, &chrome).unwrap().as_str().to_owned();
        let header = html.split("</header>").next().unwrap_or("");
        let t = header.find(&path(0xa1, "png")).expect("tenant light");
        let d = header.find(&path(0xa2, "webp")).expect("tenant dark");
        let g = header.find(&path(0xb1, "png")).expect("programme");
        assert!(t < d && d < g, "{p:?}: order");
        assert!(header.contains("brand-logo--tenant brand-logo--light"));
        assert!(header.contains("brand-logo--tenant brand-logo--dark"));
        assert!(header.contains("brand-logo--programme brand-logo--any"));
        assert_eq!(count(header, "<img"), 3, "{p:?}");
        assert_eq!(count(header, "alt=\"\""), 3, "{p:?}");
        scriptless(&html).unwrap();
    }
}

/// I-69, R-WL-04: with logos set, every page keeps one footer with each
/// mandatory element and the platform attribution. The EU funding slot
/// shows its pending wording, and the emblem only once the platform
/// holds its file. TODO(legal): the approved wording (L-08).
#[test]
fn i69_footer_and_funding_slot_survive_logos() {
    let view = sample_view(true);
    for emblem in [false, true] {
        let chrome = Chrome {
            stylesheet: None,
            funder: None,
            logos: logos(emblem),
        };
        for p in traced_pages(&view) {
            let html = render_html(&view, &p, &chrome).unwrap().as_str().to_owned();
            assert_eq!(count(&html, "<footer"), 1, "{p:?}");
            let footer = html.split("<footer").nth(1).unwrap_or("");
            for k in [
                "funder_visibility",
                "ai_disclosure",
                "privacy_notice",
                "accessibility_statement",
                "data_act_information",
                "platform_attribution",
            ] {
                assert!(
                    footer.contains(&format!("data-mandatory=\"{k}\"")),
                    "{p:?}: {k}"
                );
            }
            assert!(footer.contains("class=\"eu-funding\""), "{p:?}");
            // L-08 (ADR-036): no placeholder for the acknowledgement.
            assert!(!footer.contains("EU funding acknowledgement"), "{p:?}");
            assert_eq!(
                footer.contains("src=\"/brand/eu-emblem.png\""),
                emblem,
                "{p:?}"
            );
        }
    }
}
