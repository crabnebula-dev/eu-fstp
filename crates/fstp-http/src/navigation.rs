//! Whether a request is a browser page request (SA-09 amendment, Daniel
//! 2026-11-15: an unknown or closed page sends the browser home, while
//! an API or machine route keeps its JSON answer).
//!
//! The decision, in order:
//!
//! 1. Only `GET` and `HEAD` load a page.
//! 2. A browser that sends Fetch metadata names the request mode in
//!    `Sec-Fetch-Mode`. A script cannot set that field (it is a forbidden
//!    request header of the Fetch standard), so `navigate` names a page
//!    the browser loads into a window, and every other mode (`cors`,
//!    `no-cors`, `same-origin`, `websocket`) names a fetch, a script, a
//!    stylesheet or an image. The field must appear exactly once.
//! 3. A client that sends no `Sec-Fetch-Mode`, such as an older browser,
//!    asks for a page when its `Accept` field names `text/html` as a
//!    media range. A bare `*/*`, which every HTTP library sends, does not.
//!
//! The decision reads two field values and never fails: anything it
//! cannot read counts as no page request, so the caller keeps its machine
//! answer. The fuzz target `http_request_parse` runs it on every request
//! it accepts.

use crate::message::Request;
use crate::method::Method;

/// Whether `req` is a page a browser navigates to (module documentation).
#[must_use]
pub fn is_page_navigation(req: &Request) -> bool {
    if req.method != Method::GET && req.method != Method::HEAD {
        return false;
    }
    let mut modes = req.headers.get_all("sec-fetch-mode");
    match (modes.next(), modes.next()) {
        (Some(mode), None) => mode.as_bytes().eq_ignore_ascii_case(b"navigate"),
        (Some(_), Some(_)) => false,
        (None, _) => req
            .headers
            .get_all("accept")
            .any(|v| names_html(v.as_bytes())),
    }
}

/// Whether the `Accept` value `v` lists the media range `text/html`.
fn names_html(v: &[u8]) -> bool {
    v.split(|b| *b == b',').any(|range| {
        let media = range.split(|b| *b == b';').next().unwrap_or(range);
        media.trim_ascii().eq_ignore_ascii_case(b"text/html")
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::target::RequestTarget;

    fn req(method: Method, fields: &[(&str, &str)]) -> Request {
        let mut r = Request::new(method, RequestTarget::origin("/nonexistent").unwrap());
        for (n, v) in fields {
            r.headers.try_append(n, *v).unwrap();
        }
        r
    }

    const CHROME_ACCEPT: &str =
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

    /// SA-09 amendment: a navigation with Fetch metadata is a page request,
    /// whatever its `Accept`.
    #[test]
    fn sa09_navigate_mode_is_a_page_request() {
        for m in [Method::GET, Method::HEAD] {
            assert!(is_page_navigation(&req(
                m.clone(),
                &[("sec-fetch-mode", "navigate"), ("accept", CHROME_ACCEPT)]
            )));
            assert!(is_page_navigation(&req(
                m,
                &[("sec-fetch-mode", "Navigate")]
            )));
        }
    }

    /// SA-09 amendment: a fetch, a script or a stylesheet is no page
    /// request, even when it accepts HTML, so the shell's link check and
    /// every API call keep their answers.
    #[test]
    fn sa09_other_fetch_modes_are_not_page_requests() {
        for mode in ["cors", "no-cors", "same-origin", "websocket", ""] {
            let r = req(
                Method::GET,
                &[("sec-fetch-mode", mode), ("accept", CHROME_ACCEPT)],
            );
            assert!(!is_page_navigation(&r), "{mode}");
        }
        let twice = req(
            Method::GET,
            &[
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-mode", "navigate"),
            ],
        );
        assert!(!is_page_navigation(&twice));
    }

    /// SA-09 amendment: with no Fetch metadata, `Accept: text/html` names
    /// a page request and `*/*` or JSON do not.
    #[test]
    fn sa09_accept_decides_without_fetch_metadata() {
        assert!(is_page_navigation(&req(
            Method::GET,
            &[("accept", CHROME_ACCEPT)]
        )));
        assert!(is_page_navigation(&req(
            Method::HEAD,
            &[
                ("accept", "application/json"),
                ("accept", "TEXT/HTML ;level=1")
            ]
        )));
        for accept in [
            "*/*",
            "application/json",
            "text/*",
            "text/htmlx",
            "application/xhtml+xml",
            "",
        ] {
            assert!(
                !is_page_navigation(&req(Method::GET, &[("accept", accept)])),
                "{accept}"
            );
        }
        assert!(!is_page_navigation(&req(Method::GET, &[])));
    }

    /// SA-09 amendment: only `GET` and `HEAD` load a page.
    #[test]
    fn sa09_only_get_and_head_are_page_requests() {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let r = req(
                m,
                &[("sec-fetch-mode", "navigate"), ("accept", CHROME_ACCEPT)],
            );
            assert!(!is_page_navigation(&r));
        }
    }
}
