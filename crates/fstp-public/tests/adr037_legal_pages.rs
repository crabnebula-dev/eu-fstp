//! ADR-037 section 2: the legal pages behind the footer render each
//! `legal/` draft as escaped text with the tenant's values (I-68), show a
//! visible marker for every unset value and every pending point, carry
//! the draft banner until approval, hold no script (R-PB-04) and link
//! every legal page from their footer (I-69).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_prop::{check, prop_assert};
use fstp_public::legal::{LegalPage, LegalText, markdown, render_legal, render_source};

fn none(_: &str) -> Option<String> {
    None
}

fn page<'a>(
    text: LegalText,
    approved: bool,
    value: &'a dyn Fn(&str) -> Option<String>,
) -> LegalPage<'a> {
    LegalPage {
        text,
        approved,
        value,
        stylesheet: None,
    }
}

fn render(text: LegalText, approved: bool, value: &dyn Fn(&str) -> Option<String>) -> String {
    render_legal(&page(text, approved, value))
        .unwrap_or_else(|e| panic!("{text:?}: {e}"))
        .as_str()
        .to_owned()
}

/// ADR-037, I-68, R-PB-04: every page renders well-formed, with one
/// `h1`, no script, no raw template syntax and no raw marker token.
#[test]
fn i68_adr037_every_legal_page_renders_as_text() {
    for t in LegalText::ALL {
        let html = render(t, false, &none);
        assert!(
            fstp_html::check_wellformed(html.as_bytes()).is_ok(),
            "{t:?}"
        );
        assert_eq!(html.matches("<h1>").count(), 1, "{t:?}");
        assert!(!html.to_ascii_lowercase().contains("<script"), "{t:?}");
        assert!(!html.contains("{{"), "{t:?}: raw template syntax");
        assert!(!html.contains("TODO(legal)"), "{t:?}: a raw marker");
        assert!(!html.contains("[NOT BUILT"), "{t:?}: a raw marker");
    }
}

/// ADR-037: until approval each page carries the draft banner, and every
/// pending point of the draft shows as a visible marker.
#[test]
fn adr037_draft_banner_and_pending_markers_show() {
    for t in LegalText::ALL {
        let html = render(t, false, &none);
        assert!(html.contains("Draft, not yet approved"), "{t:?}");
        assert!(html.contains("role=\"note\""), "{t:?}");
        let blocks = markdown::parse(t.shown()).unwrap();
        let points = markdown::pending_points(&blocks);
        let shown = html.matches("class=\"legal-pending").count();
        assert_eq!(shown, points, "{t:?}: every pending point is shown");
        if points > 0 {
            assert!(
                html.contains(&format!("pending legal review: {points}.")),
                "{t:?}"
            );
        }
        // The drafting notes above the first rule are not part of the page.
        assert!(!html.contains("Drafting notes for Daniel"), "{t:?}");
    }
    // Every draft of the five still holds pending points today.
    assert!(
        LegalText::ALL
            .into_iter()
            .all(|t| fstp_public::legal::pending_points(t.source()) > 0)
    );
}

/// ADR-037 section 3: an approved page has no banner. Approval is the
/// caller's flag, so no code change removes it.
#[test]
fn adr037_approved_page_has_no_banner() {
    for t in LegalText::ALL {
        let html = render(t, true, &none);
        assert!(!html.contains("Draft, not yet approved"), "{t:?}");
        assert!(!html.contains("legal-banner"), "{t:?}");
    }
}

/// ADR-037: an unset placeholder shows "[not set: name]"; a set one shows
/// its value, escaped (I-68).
#[test]
fn i68_adr037_placeholders_fill_or_show_not_set() {
    let html = render(LegalText::Imprint, false, &none);
    assert!(html.contains("[not set: tenant.legal_name]"), "{html}");
    assert!(html.contains("[not set: tenant.vat_number]"));
    let value = |name: &str| match name {
        "tenant.legal_name" => Some("Synthetic <b>Org</b> & Co".to_owned()),
        "tenant.vat_number" => Some("XX0000".to_owned()),
        _ => None,
    };
    let html = render(LegalText::Imprint, false, &value);
    assert!(
        html.contains("Synthetic &lt;b&gt;Org&lt;/b&gt; &amp; Co"),
        "{html}"
    );
    assert!(!html.contains("<b>Org"));
    assert!(html.contains("XX0000"));
    assert!(!html.contains("[not set: tenant.legal_name]"));
    assert!(html.contains("[not set: tenant.registered_address]"));
}

/// I-69: the footer links every legal page with its mandatory key and
/// keeps the platform attribution; the current page is marked.
#[test]
fn i69_adr037_footer_links_every_legal_page() {
    for t in LegalText::ALL {
        let html = render(t, false, &none);
        for other in LegalText::ALL {
            assert!(
                html.contains(&format!("href=\"{}\"", other.path())),
                "{t:?} links {other:?}"
            );
            assert!(html.contains(&format!("data-mandatory=\"{}\"", other.mandatory_key())));
        }
        assert!(html.contains("data-mandatory=\"platform_attribution\""));
        assert_eq!(html.matches("aria-current=\"page\"").count(), 1);
    }
}

/// I-68, R-PB-04 (property): any source renders well-formed with no
/// script, no raw placeholder and no raw marker, whatever it holds.
#[test]
fn i68_adr037_any_source_renders_as_text() {
    let pieces = [
        "# ",
        "## ",
        "- ",
        "1. ",
        "| a | b |\n",
        "|---|---|\n",
        "---\n",
        "\n",
        "\n\n",
        "**",
        "`",
        "{{",
        "}}",
        "tenant.legal_name",
        "TODO(legal)",
        "[NOT BUILT",
        "]",
        ":",
        "<script>",
        "&amp;",
        "\"",
        "'",
        "  ",
        "x",
        "é",
        "\u{7f}",
        "\r",
        "{{a}}",
        "[",
        "(",
        ")",
    ];
    check("i68_adr037_any_source_renders_as_text", |g| {
        let n = g.usize_in(0..=60);
        let src: String = (0..n).map(|_| *g.pick(&pieces)).collect();
        let value = |name: &str| (name == "a").then(|| "<i>v</i>".to_owned());
        let p = page(LegalText::Terms, false, &value);
        let doc = render_source(&p, &src).map_err(|e| e.to_string())?;
        let html = doc.as_str();
        prop_assert!(fstp_html::check_wellformed(html.as_bytes()).is_ok());
        prop_assert!(!html.contains("<script"));
        prop_assert!(!html.contains("<i>"));
        prop_assert!(!html.contains("TODO(legal)"));
        Ok(())
    });
}
