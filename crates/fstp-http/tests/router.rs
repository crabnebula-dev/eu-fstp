//! Router tests. The router is a plain future, so these run on the minimal
//! `block_on` executor without a reactor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_http::{
    Handler, Method, Request, RequestTarget, Response, Router, StatusCode, handler_fn,
};
use fstp_rt::future::block_on;

fn named(label: &'static str) -> impl Handler {
    handler_fn(move |req: Request| async move {
        let params: Vec<String> = req.params().map(|(k, v)| format!("{k}={v}")).collect();
        Response::text(StatusCode::OK, format!("{label} {}", params.join(",")))
    })
}

fn call(router: &Router, method: Method, target: &str) -> Response {
    let t = if target == "*" {
        RequestTarget::asterisk()
    } else {
        RequestTarget::origin(target).unwrap()
    };
    block_on(router.handle(Request::new(method, t)))
}

fn body(r: &Response) -> String {
    String::from_utf8(r.body.clone()).unwrap()
}

#[test]
fn literal_segments_win_regardless_of_order() {
    let router = Router::new()
        .get("/users/{id}", named("param"))
        .unwrap()
        .get("/users/me", named("literal"))
        .unwrap()
        .get("/users/{id}/posts/{post}", named("nested"))
        .unwrap();
    assert_eq!(body(&call(&router, Method::GET, "/users/me")), "literal ");
    assert_eq!(
        body(&call(&router, Method::GET, "/users/42")),
        "param id=42"
    );
    assert_eq!(
        body(&call(&router, Method::GET, "/users/a%40b/posts/x%20y")),
        "nested id=a@b,post=x y"
    );
    // An encoded separator never ends up inside a captured value.
    assert_eq!(
        call(&router, Method::GET, "/users/a%2Fb/posts/x").status,
        StatusCode::BAD_REQUEST
    );
    // A parameter never matches an empty segment.
    assert_eq!(
        call(&router, Method::GET, "/users/").status,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn methods_head_fallback_and_allow() {
    let router = Router::new()
        .get("/x", named("get"))
        .unwrap()
        .post("/x", named("post"))
        .unwrap()
        .put("/x", named("put"))
        .unwrap()
        .route(Method::HEAD, "/h", named("head"))
        .unwrap()
        .get("/h", named("get-h"))
        .unwrap();
    assert_eq!(body(&call(&router, Method::POST, "/x")), "post ");
    assert_eq!(body(&call(&router, Method::HEAD, "/x")), "get ");
    assert_eq!(body(&call(&router, Method::HEAD, "/h")), "head ");
    let r = call(&router, Method::DELETE, "/x");
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        r.headers.get("allow").unwrap().to_str(),
        Some("GET, HEAD, POST, PUT")
    );
    assert_eq!(call(&router, Method::OPTIONS, "*").status, StatusCode::OK);
}

#[test]
fn fallback_and_rejected_paths() {
    let router = Router::new()
        .get("/files/{name}", named("file"))
        .unwrap()
        .fallback(named("fallback"));
    assert_eq!(
        body(&call(&router, Method::GET, "/nothing/here")),
        "fallback "
    );
    for bad in ["/files/..", "/files/%2e%2E", "/files/.", "/files/%ff"] {
        assert_eq!(
            call(&router, Method::GET, bad).status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
}

#[test]
fn invalid_routes_are_rejected() {
    assert!(Router::new().get("no-slash", named("x")).is_err());
    assert!(Router::new().get("/{a}/{a}", named("x")).is_err());
    assert!(Router::new().get("/a b", named("x")).is_err());
    let r = Router::new().get("/a/{x}", named("x")).unwrap();
    assert!(r.get("/a/{y}", named("y")).is_err(), "same shape twice");
    let r = Router::new().get("/a/{x}", named("x")).unwrap();
    assert!(
        r.post("/a/{y}", named("y")).is_ok(),
        "same shape, other method"
    );
}

/// TH-26, review finding router-param-traversal. A percent-encoded `/`,
/// `\`, NUL or other control character inside a segment gets 400, whether
/// or not a route matches. A captured value is therefore one path
/// component that can never climb a directory tree.
#[test]
fn review_router_param_traversal() {
    let router = Router::new()
        .get("/files/{name}", named("file"))
        .unwrap()
        .fallback(named("fallback"));
    for bad in [
        "/files/..%2F..%2Fetc%2Fpasswd",
        "/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/files/..%5C..%5Cwindows",
        "/files/a%00b",
        "/files/a%2Fb",
        "/files/a%2fb",
        "/files/a%5cb",
        "/files/..%2f",
        "/files/%2F",
        "/files/a%0Ab",
        "/files/a%0Db",
        "/files/a%09b",
        "/files/a%7Fb",
        // U+0085 (NEL), a C1 control character, encoded as UTF-8.
        "/files/a%C2%85b",
        // No route matches, and the fallback still never sees it.
        "/other/..%2F..%2Fetc",
    ] {
        let r = call(&router, Method::GET, bad);
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", body(&r));
    }
    // Ordinary encoded characters still reach the handler, decoded.
    assert_eq!(
        body(&call(&router, Method::GET, "/files/a%20b%C3%A9.txt")),
        "file name=a b\u{e9}.txt"
    );
    assert_eq!(
        body(&call(&router, Method::GET, "/files/...")),
        "file name=..."
    );
    assert_eq!(
        body(&call(&router, Method::GET, "/files/..a")),
        "file name=..a"
    );
}

/// TH-26, review finding router-param-traversal (double encoding). The
/// router decodes each segment exactly once. A segment whose decoded form
/// still holds a percent-encoded triple, such as `%252F`, gets 400. A
/// handler that decodes a value again therefore cannot meet a separator.
#[test]
fn review_router_double_encoded_traversal() {
    let router = Router::new()
        .get("/files/{name}", named("file"))
        .unwrap()
        .fallback(named("fallback"));
    for bad in [
        "/files/..%252F..%252Fetc%252Fpasswd",
        "/files/%252e%252e",
        "/files/%252E%252E%252F",
        "/files/a%255Cb",
        "/files/a%2500b",
        "/files/%25252F",
        "/files/%2541",
        "/other/..%252F",
    ] {
        let r = call(&router, Method::GET, bad);
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", body(&r));
    }
    // Decoding happens once. A `%` that does not start a triple after
    // decoding stays a literal character and is never decoded again.
    for (path, want) in [
        ("/files/100%25", "file name=100%"),
        ("/files/%25zz", "file name=%zz"),
        ("/files/50%25%20off", "file name=50% off"),
        ("/files/%25", "file name=%"),
        ("/files/%252", "file name=%2"),
    ] {
        assert_eq!(body(&call(&router, Method::GET, path)), want, "{path}");
    }
}
