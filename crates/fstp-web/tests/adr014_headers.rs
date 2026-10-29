//! The shell, the assets and the security headers of the web adapter
//! (ADR-014 "Shell, assets and headers", M4 design section 3.9).
//!
//! `web_common` states the readings these tests share. Lane W4e's test
//! author wrote them before the adapter exists, so each is red because
//! the W0 stub of `fstp_web::handle_op_request` refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod web_common;

use web_common::{
    APP_CSP, SURFACES, all, baseline, get, header_is, is_hash, no_cookie_no_cors, one_header,
};

/// The `src` of every `<script` element of `html`, with whether the
/// element is `type="module"` and whether it holds inline text.
fn scripts(html: &str) -> Vec<(Option<String>, bool, bool)> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<script") {
        let start = from + i;
        let Some(gt) = lower[start..].find('>') else {
            out.push((None, false, true));
            break;
        };
        let tag = &html[start..start + gt];
        let src = attr(tag, "src");
        let module = attr(tag, "type").as_deref() == Some("module");
        let body_start = start + gt + 1;
        let inline = match lower[body_start..].find("</script>") {
            Some(end) => !html[body_start..body_start + end].trim().is_empty(),
            None => true,
        };
        out.push((src, module, inline));
        from = body_start;
    }
    out
}

/// The double-quoted value of attribute `name` in the start tag `tag`.
fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let i = tag.to_ascii_lowercase().find(&needle)?;
    let rest = &tag[i + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// The entry module path that the shell's one script names.
fn entry_of_shell() -> String {
    let shell = get("/app/");
    let html = String::from_utf8(shell.body).unwrap();
    let s = scripts(&html);
    assert_eq!(s.len(), 1, "{s:?}");
    s[0].0.clone().unwrap()
}

/// ADR-014: every `/app` response carries the CSP of design section 3.9,
/// byte for byte and exactly once, the shell and its assets included.
#[test]
fn adr014_app_csp_is_exact() {
    let entry = entry_of_shell();
    let paths = ["/app/".to_owned(), "/app/creator/drafts".to_owned(), entry];
    all(&paths, |p| {
        header_is(&get(p), "content-security-policy", APP_CSP)
    });
}

/// ADR-014: the shell is HTML with exactly one `<script type="module">`
/// that names a content-addressed asset, no inline script, no inline
/// style and no event handler attribute.
#[test]
fn adr014_shell_has_one_module_script_and_nothing_inline() {
    let shell = get("/app/");
    assert_eq!(shell.status.as_u16(), 200);
    let ct = one_header(&shell, "content-type").unwrap();
    assert_eq!(ct, "text/html; charset=utf-8");
    let html = String::from_utf8(shell.body).unwrap();
    let s = scripts(&html);
    assert_eq!(s.len(), 1, "{s:?}");
    let (src, module, inline) = s[0].clone();
    assert!(module, "the script is not a module");
    assert!(!inline, "the script holds inline text");
    let src = src.unwrap();
    let name = src
        .strip_prefix("/app/assets/")
        .and_then(|n| n.strip_suffix(".js"))
        .unwrap_or_else(|| panic!("{src:?} is not an asset path"));
    assert!(is_hash(name), "{src:?}");
    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("<style"), "inline style element");
    assert!(!lower.contains(" style="), "inline style attribute");
    for tag in lower.split('<').skip(1) {
        let head = tag.split('>').next().unwrap_or("");
        for word in head.split_ascii_whitespace().skip(1) {
            assert!(
                !word.starts_with("on"),
                "event handler attribute in <{head}>"
            );
        }
    }
}

/// ADR-014: every `/app/` path outside the assets serves the same shell,
/// so the client router can handle deep links.
#[test]
fn adr014_app_deep_links_serve_the_shell() {
    let shell = get("/app/").body;
    let paths = ["/app/calls/c1", "/app/creator/p1/steps/3", "/app/reviewer"];
    all(&paths, |p| {
        let r = get(p);
        if r.status.as_u16() == 200 && r.body == shell {
            Ok(())
        } else {
            Err(format!(
                "status {}, same body {}",
                r.status.as_u16(),
                r.body == shell
            ))
        }
    });
}

/// ADR-014: the shell's entry module is served at its content-addressed
/// path, immutable, as JavaScript.
#[test]
fn adr014_shell_entry_is_served_immutable() {
    let entry = entry_of_shell();
    let r = get(&entry);
    assert_eq!(r.status.as_u16(), 200);
    assert!(!r.body.is_empty());
    header_is(&r, "content-type", "text/javascript; charset=utf-8").unwrap();
    header_is(&r, "cache-control", "public, max-age=31536000, immutable").unwrap();
}

/// ADR-014: an asset path that names no listed asset gets 404, and so do
/// other spellings of an asset path.
#[test]
fn adr014_unknown_asset_paths_are_not_found() {
    let entry = entry_of_shell();
    let hash = &entry["/app/assets/".len()..entry.len() - ".js".len()];
    let paths = [
        format!("/app/assets/{}.js", "ab".repeat(32)),
        format!("/app/assets/{}.js", hash.to_ascii_uppercase()),
        format!("/app/assets/{hash}.mjs"),
        format!("/app/assets/{hash}"),
        format!("/app/assets/{}.js", &hash[..63]),
        "/app/assets/main.js".to_owned(),
        "/app/assets/".to_owned(),
    ];
    all(&paths, |p| {
        let s = get(p).status.as_u16();
        if s == 404 {
            Ok(())
        } else {
            Err(format!("status {s}"))
        }
    });
}

/// ADR-014: the shell and every `/api/v1` response carry
/// `Cache-Control: no-store`.
#[test]
fn adr014_shell_and_api_responses_are_not_stored() {
    let paths = [
        "/app/",
        "/app/calls/c1",
        "/api/v1/me/notices",
        "/api/v1/no-such-route",
    ];
    all(&paths, |p| header_is(&get(p), "cache-control", "no-store"));
}

/// ADR-014: every response, on every surface and for every status,
/// carries the baseline headers and exactly one CSP of its surface.
#[test]
fn adr014_every_response_carries_the_baseline_headers() {
    let mut paths: Vec<String> = SURFACES.iter().map(|p| (*p).to_owned()).collect();
    paths.push(entry_of_shell());
    all(&paths, |p| baseline(&get(p), p));
}

/// ADR-014, TH-37: no response of the adapter sets a cookie or grants a
/// cross-origin read.
#[test]
fn adr014_no_response_sets_a_cookie_or_grants_cors() {
    let mut paths: Vec<String> = SURFACES.iter().map(|p| (*p).to_owned()).collect();
    paths.push(entry_of_shell());
    all(&paths, |p| no_cookie_no_cors(&get(p)));
}
