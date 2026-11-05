//! The public pages over a hand-built view (R-PB-01, R-PB-04, R-JV-06,
//! R-GA-02, R-LA-08, M4 design section 3.10).
//!
//! Each test renders the pages of `support::sample_view` through
//! `fstp_public::render_html` and reads the bytes. No filter runs here, so
//! a failure is the renderer's. Every name and text is synthetic.
//!
//! Status: red. The W0 stub of `render_html` refuses with
//! `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::{PublicError, PublicPage, render_html};
use support::{all_pages, chrome, count, sample_view, scriptless};

/// The page `page` of the sample view, as text.
fn page(page: &PublicPage) -> String {
    let view = sample_view(true);
    match render_html(&view, page, &chrome()) {
        Ok(doc) => doc.as_str().to_owned(),
        Err(e) => panic!("{page:?}: {e}"),
    }
}

/// R-PB-04, R-JV-06, TH-37: every public page is well formed and holds no
/// script, frame, object, form, event handler or asset from another
/// origin, so it works with scripts off.
#[test]
fn r_pb_04_every_page_is_wellformed_and_scriptless() {
    let view = sample_view(true);
    let mut failures = Vec::new();
    for p in all_pages(&view) {
        match render_html(&view, &p, &chrome()) {
            Ok(doc) => {
                if let Err(e) = fstp_html::check_wellformed(doc.as_bytes()) {
                    failures.push(format!("{p:?}: not well formed: {e}"));
                }
                if let Err(e) = scriptless(doc.as_str()) {
                    failures.push(format!("{p:?}: {e}"));
                }
            }
            Err(e) => failures.push(format!("{p:?}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// R-PB-04, R-NF-03: every page with a trace has one `main` landmark with
/// one `h1`, as the approved prototypes do.
#[test]
fn r_pb_04_every_page_has_one_main_and_one_h1() {
    let view = sample_view(true);
    for p in support::traced_pages(&view) {
        let html = page(&p);
        assert_eq!(count(&html, "<main"), 1, "{p:?}: {html}");
        assert_eq!(count(&html, "<h1"), 1, "{p:?}: {html}");
    }
}

/// R-PB-01: the programme page names every open call and links its call
/// page on the same origin.
#[test]
fn r_pb_01_programme_page_links_every_open_call() {
    let view = sample_view(true);
    let html = page(&PublicPage::Programme);
    for c in &view.open_calls {
        assert!(html.contains(&c.title), "{} is not listed: {html}", c.title);
        let href = format!("href=\"/p/{}/calls/{}\"", view.programme.slug, c.id);
        assert!(html.contains(&href), "no {href}: {html}");
    }
}

/// R-PB-01: the funded and finished pages name each grant of their phase,
/// and no grant of the other phase.
#[test]
fn r_pb_01_funded_and_finished_pages_list_their_own_grants() {
    let view = sample_view(true);
    let funded = page(&PublicPage::Funded);
    let finished = page(&PublicPage::Finished);
    for g in &view.funded {
        assert!(funded.contains(&g.title), "{}: {funded}", g.title);
        assert!(!finished.contains(&g.title), "{} is finished", g.title);
    }
    for g in &view.finished {
        assert!(finished.contains(&g.title), "{}: {finished}", g.title);
        assert!(!funded.contains(&g.title), "{} is funded", g.title);
    }
}

/// R-GA-01, R-GA-02: a call page links its Guide for Applicants when the
/// view holds one, and only then.
#[test]
fn r_ga_02_call_page_links_its_guide() {
    let view = sample_view(true);
    for c in &view.open_calls {
        let html = page(&PublicPage::Call(c.id.clone()));
        let href = format!("href=\"/p/{}/calls/{}/guide\"", view.programme.slug, c.id);
        assert_eq!(html.contains(&href), c.guide.is_some(), "{}: {html}", c.id);
    }
}

/// R-GA-02: the Guide page is the call's published Guide document, byte
/// for byte, so the page cannot drift from the published version (I-53).
#[test]
fn r_ga_02_guide_page_is_the_published_document() {
    let view = sample_view(true);
    for c in view.open_calls.iter().filter(|c| c.guide.is_some()) {
        let doc = render_html(&view, &PublicPage::Guide(c.id.clone()), &chrome())
            .unwrap_or_else(|e| panic!("{}: {e}", c.id));
        let want = c.guide.as_ref().map(|g| g.document.as_bytes().to_vec());
        assert_eq!(Some(doc.as_bytes().to_vec()), want, "{}", c.id);
    }
}

/// R-LA-08, AI Act Article 50: every call page holds the AI disclosure
/// section, `section#ai-disclosure`, which tells applicants that AI
/// assessment is used.
#[test]
fn r_la_08_call_page_discloses_ai_assessment() {
    let view = sample_view(true);
    for c in &view.open_calls {
        let html = page(&PublicPage::Call(c.id.clone()));
        let at = html
            .find("id=\"ai-disclosure\"")
            .unwrap_or_else(|| panic!("{}: no AI disclosure: {html}", c.id));
        let open = html[..at].rfind('<').unwrap_or(0);
        assert!(
            html[open..].starts_with("<section"),
            "{}: the disclosure is not a section: {html}",
            c.id
        );
    }
}

/// R-PB-04: a call page, a Guide page or a page of a call the view does
/// not hold is not found, never an empty page.
#[test]
fn r_pb_04_page_of_an_unknown_call_is_not_found() {
    let view = sample_view(true);
    let no_guide = view
        .open_calls
        .iter()
        .find(|c| c.guide.is_none())
        .map(|c| c.id.clone())
        .unwrap_or_else(|| panic!("the sample has a call without a Guide"));
    for p in [
        PublicPage::Call("999".to_owned()),
        PublicPage::Guide("999".to_owned()),
        PublicPage::Guide(no_guide),
    ] {
        assert_eq!(
            render_html(&view, &p, &chrome()),
            Err(PublicError::NotFound),
            "{p:?}"
        );
    }
}

/// R-PB-04, I-68: view text is escaped, never markup. A title holding
/// markup reaches the page as text only.
#[test]
fn r_pb_04_view_text_is_escaped_never_markup() {
    let mut view = sample_view(true);
    let hostile = "<script>alert(1)</script> & \"quoted\"";
    view.open_calls[0].title = hostile.to_owned();
    view.programme.narrative = "<img src=x onerror=alert(1)>".to_owned();
    for p in [
        PublicPage::Programme,
        PublicPage::Call(view.open_calls[0].id.clone()),
    ] {
        let doc = render_html(&view, &p, &chrome()).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        scriptless(doc.as_str()).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert!(doc.as_str().contains("&lt;script&gt;"), "{p:?}");
    }
}
