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
pub(crate) fn render(assets: &AssetSet) -> Vec<u8> {
    let mut html = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>FSTP</title>\n",
    );
    for href in assets.style_paths() {
        html.push_str(&format!("<link rel=\"stylesheet\" href=\"{href}\">\n"));
    }
    html.push_str(&format!(
        "<script type=\"module\" src=\"{}\"></script>\n</head>\n<body>\n<div id=\"app\"></div>\n</body>\n</html>\n",
        assets.entry_path()
    ));
    html.into_bytes()
}
