//! ADR-034 (lead decision of 2026-11-22): the funding card's contact is a
//! `mailto:` link. Only the `href` of an `a` takes one, and only for one
//! address with no query (I-68).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_html::{CatalogueSource, Catalogues, Document, Element, Node, SafeUrl, check_wellformed};

fn cats() -> Catalogues {
    Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: &[],
        },
        &[],
    )
    .unwrap()
}

fn page(e: Element) -> Document {
    Document::new("en").title(Node::text("t")).body(e)
}

/// I-68, ADR-034: a link to one address renders and passes the checker.
#[test]
fn i68_mailto_link_renders_in_an_a_href() {
    let a = Element::new("a")
        .attr_url("href", SafeUrl::mailto("privacy@crabnebula.dev").unwrap())
        .text("privacy@crabnebula.dev");
    let doc = page(Element::new("p").child(a)).render(&cats()).unwrap();
    assert!(
        doc.as_str()
            .contains("href=\"mailto:privacy@crabnebula.dev\"")
    );
    check_wellformed(doc.as_str().as_bytes()).unwrap();
}

/// I-68: a mailto URL anywhere else, or with a query, is refused.
#[test]
fn i68_mailto_is_refused_outside_links_and_with_a_query() {
    for bad in ["a@example.org?bcc=x@example.org", "a@b", "<a>@example.org"] {
        assert!(SafeUrl::mailto(bad).is_err(), "{bad}");
    }
    assert!(SafeUrl::new("mailto:a@example.org").is_err());
    let img = Element::new("img")
        .attr_url("src", SafeUrl::mailto("a@example.org").unwrap())
        .attr("alt", "");
    assert!(page(Element::new("p").child(img)).render(&cats()).is_err());
    let ok = Element::new("img")
        .attr_url("src", SafeUrl::new("/x.png").unwrap())
        .attr("alt", "");
    let html = page(Element::new("p").child(ok)).render(&cats()).unwrap();
    check_wellformed(html.as_str().as_bytes()).unwrap();
    let swapped = html.as_str().replace("/x.png", "mailto:a@example.org");
    assert!(check_wellformed(swapped.as_bytes()).is_err());
}
