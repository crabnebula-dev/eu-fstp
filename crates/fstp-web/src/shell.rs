//! The application shell served for `/app/` (ADR-014 "Shell, assets and
//! headers").

use fstp_web_assets::AssetSet;

/// The shell document for `assets`.
///
/// It holds exactly one `<script type="module">`, which names the entry
/// module by its content-addressed path, and no inline script, inline
/// style or event handler attribute. Every text in it is a constant or an
/// asset path of the form `/app/assets/{sha256}.js`, so nothing needs
/// escaping.
///
/// Interim, pending Daniel:
///
/// - The shell links every stylesheet of the manifest, in manifest path
///   order, since ADR-014 names no stylesheet entry.
/// - The application mounts itself on the empty `<div id="app">`. The
///   footer's mandatory elements are the application's to render
///   (design section 3.9), so the shell holds no wording of its own.
/// - `lang="en"` is the document default. The application sets the
///   language of the chosen locale (R-NF-04).
pub(crate) fn render(assets: &AssetSet, brand: Option<&str>) -> Vec<u8> {
    render_marked(assets, brand, None)
}

/// The marker of the "Page not found" answer (SA-09): the client mounts
/// the not-found page when the shell carries it.
pub(crate) const NOT_FOUND: &str = "not-found";

/// [`render`] with the page marker `marker`: a
/// `<meta name="fstp-page">` whose content is a constant, such as
/// [`NOT_FOUND`].
pub(crate) fn render_marked(
    assets: &AssetSet,
    brand: Option<&str>,
    marker: Option<&str>,
) -> Vec<u8> {
    let mut html = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>FSTP</title>\n",
    );
    if let Some(m) = marker.filter(|m| *m == NOT_FOUND) {
        html.push_str(&format!("<meta name=\"fstp-page\" content=\"{m}\">\n"));
    }
    for href in assets.style_paths() {
        html.push_str(&format!("<link rel=\"stylesheet\" href=\"{href}\">\n"));
    }
    // After the platform sheets, so the tenant tokens win (M9 lane B2).
    // The digest is 64 hex digits, checked by the caller's grammar.
    if let Some(d) = brand.filter(|d| crate::brand::digest_in(&format!("/brand/{d}.css")).is_some())
    {
        html.push_str(&format!(
            "<link rel=\"stylesheet\" href=\"/brand/{d}.css\">\n"
        ));
    }
    html.push_str(&format!(
        "<script type=\"module\" src=\"{}\"></script>\n</head>\n<body>\n<div id=\"app\"></div>\n</body>\n</html>\n",
        assets.entry_path()
    ));
    html.into_bytes()
}

/// A public page (`/p`, rendered by `fstp-public`) with the platform
/// stylesheets of `assets` linked first in its `<head>`, so the page
/// looks like every other page (Daniel, 2026-11-15: the `/p` pages had
/// no styling). The tenant brand sheet the renderer links, if any, comes
/// after them, so the tenant tokens still win (M9 lane B2). Each link is
/// a content-addressed path of the form `/app/assets/{sha256}.css`, which
/// the `/p` policy `style-src 'self'` admits. A page with no `<head>`
/// is returned unchanged.
pub(crate) fn public_page(html: &str, assets: &AssetSet) -> Vec<u8> {
    const HEAD: &str = "<head>";
    let Some(at) = html.find(HEAD).and_then(|i| i.checked_add(HEAD.len())) else {
        return html.as_bytes().to_vec();
    };
    let (before, after) = html.split_at(at);
    let mut out = String::with_capacity(html.len().saturating_add(256));
    out.push_str(before);
    for href in assets.style_paths() {
        out.push_str(&format!("<link rel=\"stylesheet\" href=\"{href}\">"));
    }
    out.push_str(after);
    out.into_bytes()
}

/// The plain page a `/p` page answers before the organisation is
/// activated (ADR-021 decision 3, Daniel, 2026-11-15): its pages are not
/// published yet. It links the platform stylesheets of `assets`, as
/// [`public_page`] does, and holds no script. Every text is a constant,
/// so nothing needs escaping and no rule id is shown. No brand sheet is
/// linked, since the page names no programme.
pub(crate) fn not_published(assets: &AssetSet) -> Vec<u8> {
    let mut html = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Not published yet</title>\n",
    );
    for href in assets.style_paths() {
        html.push_str(&format!("<link rel=\"stylesheet\" href=\"{href}\">\n"));
    }
    html.push_str(
        "</head>\n<body>\n<main>\n<h1>Not published yet</h1>\n\
         <p>This organisation's pages are not published yet. \
         They open once its activation has been approved.</p>\n\
         </main>\n</body>\n</html>\n",
    );
    html.into_bytes()
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// I-68, I-70: the shell links the brand sheet after the platform
    /// sheets only for a well-formed digest.
    #[test]
    fn i68_shell_links_brand_sheet_for_a_valid_digest_only() {
        let Ok(assets) = fstp_web_assets::AssetSet::from_files(
            "main.js",
            &[("main.js", b"export {};" as &[u8])],
        ) else {
            panic!("assets");
        };
        let good = "ab".repeat(32);
        let html = String::from_utf8(render(&assets, Some(&good))).unwrap_or_default();
        assert!(html.contains(&format!("href=\"/brand/{good}.css\"")));
        let bad = String::from_utf8(render(&assets, Some("x\"><script>"))).unwrap_or_default();
        assert!(!bad.contains("/brand/"));
        let none = String::from_utf8(render(&assets, None)).unwrap_or_default();
        assert!(!none.contains("/brand/"));
    }

    /// ADR-021 decision 3, R-PB-04: the not-published page links the
    /// platform stylesheets, says the pages are not published yet and
    /// holds no script.
    #[test]
    fn adr021_not_published_page_links_platform_sheets_and_holds_no_script() {
        let Ok(assets) = fstp_web_assets::AssetSet::from_files(
            "main.js",
            &[
                ("main.js", b"export {};" as &[u8]),
                ("site/ui.css", b"body{margin:0}" as &[u8]),
            ],
        ) else {
            panic!("assets");
        };
        let Some(sheet) = assets.style_paths().into_iter().next() else {
            panic!("no sheet");
        };
        let html = String::from_utf8(not_published(&assets)).unwrap_or_default();
        assert!(html.contains(&format!("href=\"{sheet}\"")), "{html}");
        assert!(html.contains("not published yet"), "{html}");
        assert!(!html.to_ascii_lowercase().contains("<script"), "{html}");
        assert!(!html.contains("ADR-021"), "{html}");
    }

    /// R-NF-03, I-70: a public page links the platform stylesheets first
    /// in its head, before the brand sheet the renderer wrote.
    #[test]
    fn r_nf_03_public_page_links_platform_sheets_before_the_brand() {
        let Ok(assets) = fstp_web_assets::AssetSet::from_files(
            "main.js",
            &[
                ("main.js", b"export {};" as &[u8]),
                ("site/ui.css", b"body{margin:0}" as &[u8]),
            ],
        ) else {
            panic!("assets");
        };
        let Some(sheet) = assets.style_paths().into_iter().next() else {
            panic!("no sheet");
        };
        let page = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"/brand/b.css\"></head><body></body></html>";
        let html = String::from_utf8(public_page(page, &assets)).unwrap_or_default();
        let platform = html
            .find(&format!("href=\"{sheet}\""))
            .unwrap_or(usize::MAX);
        let brand = html.find("/brand/b.css").unwrap_or(0);
        assert!(platform < brand, "{html}");
        assert_eq!(
            public_page("<p>no head</p>", &assets),
            b"<p>no head</p>".to_vec()
        );
    }
}
