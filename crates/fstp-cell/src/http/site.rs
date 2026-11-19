//! The platform stylesheets of the cell's public pages, and its two
//! static pages (R-NF-03, R-PB-04, I-70, ADR-021 decision 3, SA-09; lane
//! m4/pubtext).
//!
//! The web adapter links the platform stylesheets first in every `/p`
//! page (`fstp_web::shell::public_page`). Its asset set holds the sheets
//! of `web/src/site`, copied byte for byte by `web/build/pack.ts`, in
//! name order: `tokens.css`, then `ui.css`. Each is served at
//! `/app/assets/{sha256}.css`. The cell embeds the same two files at
//! build time, so it needs no asset directory at start. It serves each at
//! the same content-addressed path and links them in the same order. A
//! page the cell renders is then the bytes the web adapter answers for
//! the same view, when the web adapter's set holds exactly these sheets.
//!
//! Every link is same-origin, so the `/p` policy `style-src 'self'`
//! admits it. No page here holds a script, an inline style or a form.
//!
//! - [`public_page`] links the sheets first in a page's `<head>`, before
//!   the tenant brand sheet the renderer wrote, so the tenant tokens win.
//! - [`not_published`] is the page a `/p` page answers before the
//!   organisation is activated (ADR-021 decision 3).
//! - [`not_found`] is the "Page not found" page (SA-09). The cell serves
//!   no `/app/` shell yet, so its home `/app/` answers this page with 404
//!   where the web adapter's client renders the same words. Interim,
//!   pending Daniel: the page holds no footer, since the footer wording
//!   of design section 3.9 is still `TODO(legal)`.

use std::sync::OnceLock;

/// The platform stylesheets, in the order the web adapter links them.
const SHEETS: [&[u8]; 2] = [
    include_bytes!("../../../../web/src/site/tokens.css"),
    include_bytes!("../../../../web/src/site/ui.css"),
];

/// The prefix of every content-addressed asset path (`fstp_web_assets`).
pub const ASSET_PREFIX: &str = "/app/assets/";

/// The route of the sheets ([`crate::routes::site_table`]).
pub const SHEET_ROUTE: &str = "/app/assets/{file}";

/// The media type of a sheet.
pub const CSS: &str = "text/css; charset=utf-8";

/// Each sheet with its request path, in link order.
fn sheets() -> &'static [(String, &'static [u8])] {
    static PATHS: OnceLock<Vec<(String, &'static [u8])>> = OnceLock::new();
    PATHS.get_or_init(|| {
        SHEETS
            .iter()
            .map(|bytes| {
                let hex: String = fstp_crypto::sha256(bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                (format!("{ASSET_PREFIX}{hex}.css"), *bytes)
            })
            .collect()
    })
}

/// The request path of each platform sheet, in link order.
pub fn sheet_paths() -> impl Iterator<Item = &'static str> {
    sheets().iter().map(|(p, _)| p.as_str())
}

/// The bytes of the sheet served at `path`, or `None` for any other path.
pub fn sheet(path: &str) -> Option<&'static [u8]> {
    sheets()
        .iter()
        .find(|(p, _)| p == path)
        .map(|(_, bytes)| *bytes)
}

/// The `<link>` elements of the sheets, one per line when `lines`.
fn links(lines: bool) -> String {
    sheet_paths()
        .map(|href| {
            let end = if lines { "\n" } else { "" };
            format!("<link rel=\"stylesheet\" href=\"{href}\">{end}")
        })
        .collect()
}

/// `html` with the platform sheets linked first in its `<head>`, as
/// `fstp_web::shell::public_page` links them. A page with no `<head>` is
/// returned unchanged.
pub fn public_page(html: &str) -> String {
    const HEAD: &str = "<head>";
    let Some(at) = html.find(HEAD).and_then(|i| i.checked_add(HEAD.len())) else {
        return html.to_owned();
    };
    let (before, after) = html.split_at(at);
    let mut out = String::with_capacity(html.len().saturating_add(256));
    out.push_str(before);
    out.push_str(&links(false));
    out.push_str(after);
    out
}

/// The start of a static page titled `title`, through its sheet links.
fn head(title: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n{}",
        links(true)
    )
}

/// The page a `/p` page answers before the organisation is activated
/// (ADR-021 decision 3), as `fstp_web::shell::not_published` writes it.
/// Every text is a constant, so nothing needs escaping.
pub fn not_published() -> String {
    let mut html = head("Not published yet");
    html.push_str(
        "</head>\n<body>\n<main>\n<h1>Not published yet</h1>\n\
         <p>This organisation's pages are not published yet. \
         They open once its activation has been approved.</p>\n\
         </main>\n</body>\n</html>\n",
    );
    html
}

/// The "Page not found" page (SA-09), in the words of the web client's
/// not-found page (`web/src/applicant/messages.en.ts`).
pub fn not_found() -> String {
    let mut html = head("Page not found");
    html.push_str(
        "</head>\n<body>\n<main id=\"main\">\n<h1>Page not found</h1>\n\
         <p>This address names no page.</p>\n\
         </main>\n</body>\n</html>\n",
    );
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-NF-03, I-70: the sheets are the platform's, in the web adapter's
    /// order, each at its content-addressed path, and no other path
    /// serves one.
    #[test]
    fn r_nf_03_platform_sheets_are_served_at_their_content_address() {
        let paths: Vec<&str> = sheet_paths().collect();
        assert_eq!(paths.len(), 2);
        for (path, bytes) in paths.iter().zip(SHEETS) {
            let hex: String = fstp_crypto::sha256(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(*path, format!("/app/assets/{hex}.css"));
            assert_eq!(sheet(path), Some(bytes));
        }
        assert!(std::str::from_utf8(SHEETS[0]).is_ok_and(|s| s.contains("--color-surface-0")));
        assert_eq!(sheet("/app/assets/tokens.css"), None);
        assert_eq!(sheet(&format!("{}x", paths[0])), None);
    }

    /// R-NF-03, I-70: a public page links the platform sheets first in
    /// its head, before the brand sheet the renderer wrote. A page with no
    /// head is unchanged.
    #[test]
    fn r_nf_03_public_page_links_platform_sheets_before_the_brand() {
        let page = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"/brand/b.css\"></head><body></body></html>";
        let html = public_page(page);
        let mut at = 0;
        for href in sheet_paths() {
            let i = html.find(&format!("href=\"{href}\"")).unwrap_or(usize::MAX);
            assert!(i >= at, "{html}");
            at = i;
        }
        assert!(at < html.find("/brand/b.css").unwrap_or(0), "{html}");
        assert_eq!(public_page("<p>no head</p>"), "<p>no head</p>");
    }

    /// ADR-021 decision 3, SA-09, R-PB-04: the not-published and the
    /// not-found pages link the platform sheets, say what they mean and
    /// hold no script and no rule id.
    #[test]
    fn adr021_sa09_static_pages_link_platform_sheets_and_hold_no_script() {
        for (html, words) in [
            (not_published(), "not published yet"),
            (not_found(), "Page not found"),
        ] {
            for href in sheet_paths() {
                assert!(html.contains(&format!("href=\"{href}\"")), "{html}");
            }
            assert!(html.contains(words), "{html}");
            assert!(!html.to_ascii_lowercase().contains("<script"), "{html}");
            assert!(!html.contains("style="), "{html}");
            assert!(!html.contains("ADR-021"), "{html}");
            assert!(html.ends_with("</html>\n"), "{html}");
        }
    }
}
