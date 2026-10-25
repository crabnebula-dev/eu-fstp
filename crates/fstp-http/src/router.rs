//! A small router: method plus path, with named segments. See [`Router`].

use std::fmt;
use std::future::Future;

use crate::chars::{has_pct_triple, is_pchar_plain, pct_decode};
use crate::handler::{DynHandler, Handler};
use crate::header::{HeaderName, HeaderValue};
use crate::message::{Request, Response};
use crate::method::Method;
use crate::status::StatusCode;
use crate::target::TargetForm;

/// A pattern rejected by [`Router::route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteError {
    what: &'static str,
}

impl RouteError {
    /// A fixed description of the problem.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.what
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid route: {}", self.what)
    }
}

impl std::error::Error for RouteError {}

const fn route_err(what: &'static str) -> RouteError {
    RouteError { what }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(Box<str>),
    Param(Box<str>),
}

struct Route {
    method: Method,
    segments: Vec<Segment>,
    handler: Box<dyn DynHandler>,
}

impl Route {
    fn matches(&self, path: &[String]) -> bool {
        self.segments.len() == path.len()
            && self.segments.iter().zip(path).all(|(s, p)| match s {
                Segment::Literal(l) => **l == **p,
                Segment::Param(_) => !p.is_empty(),
            })
    }

    /// Literal segments rank above parameters, position by position.
    fn specificity(&self) -> Vec<bool> {
        self.segments
            .iter()
            .map(|s| matches!(s, Segment::Literal(_)))
            .collect()
    }
}

/// Routes requests by method and path. It implements [`Handler`].
///
/// Patterns are absolute paths. A segment written `{name}` captures one
/// non-empty path segment; every other segment matches literally.
///
/// ```
/// use fstp_http::{handler_fn, Method, Request, Response, Router, StatusCode};
///
/// let router = Router::new()
///     .route(Method::GET, "/proposals/{id}", handler_fn(|req: Request| async move {
///         let id = req.param("id").unwrap_or_default().to_owned();
///         Response::text(StatusCode::OK, id)
///     }))
///     .expect("valid pattern");
/// # let _ = router;
/// ```
///
/// Matching rules:
///
/// - Request path segments are percent-decoded exactly once before
///   comparison and must be UTF-8. Captured values are the decoded
///   segments.
/// - A path gets 400 when a decoded segment is `.` or `..`, holds `/`,
///   `\` or a control character, or still holds a percent-encoded triple.
///   The last rule covers double encoding, such as `%252F` decoding to
///   `%2F`. The check runs before routing, so the fallback handler never
///   sees such a path either.
/// - A captured value is therefore a single path component with no
///   separator and no dot segment. It cannot climb a directory tree, even
///   when a handler decodes it again. The router applies no Unicode
///   normalization, so a handler that normalizes a value checks the result
///   itself.
/// - When several patterns match, the one with a literal segment at the
///   first position where they differ wins.
/// - A HEAD request falls back to the GET route. The server driver then
///   leaves the body out.
/// - A path that matches only routes with other methods gets 405 with an
///   `Allow` field. Otherwise the fallback handler runs, or 404 is sent.
#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
    fallback: Option<Box<dyn DynHandler>>,
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("routes", &self.routes.len())
            .field("fallback", &self.fallback.is_some())
            .finish()
    }
}

fn parse_pattern(pattern: &str) -> Result<Vec<Segment>, RouteError> {
    let rest = pattern
        .strip_prefix('/')
        .ok_or(route_err("pattern must start with /"))?;
    let mut segments = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if inner.is_empty()
                || !inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(route_err("parameter names use letters, digits and _"));
            }
            if names.contains(&inner) {
                return Err(route_err("duplicate parameter name"));
            }
            names.push(inner);
            segments.push(Segment::Param(inner.into()));
        } else {
            if !seg.bytes().all(is_pchar_plain) {
                return Err(route_err("literal segments use unencoded path characters"));
            }
            if seg == "." || seg == ".." {
                return Err(route_err("dot segments never match"));
            }
            segments.push(Segment::Literal(seg.into()));
        }
    }
    Ok(segments)
}

fn same_shape(a: &[Segment], b: &[Segment]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| match (x, y) {
            (Segment::Literal(l), Segment::Literal(r)) => l == r,
            (Segment::Param(_), Segment::Param(_)) => true,
            _ => false,
        })
}

/// Splits and decodes a request path. `None` means the path must be
/// rejected with 400.
///
/// Each segment is percent-decoded exactly once, then checked with
/// [`is_safe_segment`].
fn decode_path(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix('/')?;
    let mut out = Vec::new();
    for raw in rest.split('/') {
        let bytes = pct_decode(raw.as_bytes())?;
        let s = String::from_utf8(bytes).ok()?;
        if !is_safe_segment(&s) {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

/// True for a decoded segment that is one path component and stays one
/// after another round of decoding.
///
/// It rejects dot segments, both separators (`/` and `\`), control
/// characters (C0, DEL and C1) and any remaining percent-encoded triple.
fn is_safe_segment(s: &str) -> bool {
    s != "."
        && s != ".."
        && !s.chars().any(|c| c == '/' || c == '\\' || c.is_control())
        && !has_pct_triple(s.as_bytes())
}

impl Router {
    /// An empty router. Every request gets 404 until routes are added.
    #[must_use]
    pub fn new() -> Router {
        Router::default()
    }

    /// Adds a route.
    ///
    /// # Errors
    ///
    /// Returns [`RouteError`] for a pattern that does not start with `/`,
    /// has an invalid or duplicate parameter name, a literal segment with
    /// characters that need encoding, or the same method and shape as an
    /// existing route.
    pub fn route<H: Handler>(
        mut self,
        method: Method,
        pattern: &str,
        handler: H,
    ) -> Result<Router, RouteError> {
        let segments = parse_pattern(pattern)?;
        if self
            .routes
            .iter()
            .any(|r| r.method == method && same_shape(&r.segments, &segments))
        {
            return Err(route_err("a route with this method and shape exists"));
        }
        self.routes.push(Route {
            method,
            segments,
            handler: Box::new(handler),
        });
        Ok(self)
    }

    /// Adds a GET route. HEAD requests use it too.
    ///
    /// # Errors
    ///
    /// See [`Router::route`].
    pub fn get<H: Handler>(self, pattern: &str, handler: H) -> Result<Router, RouteError> {
        self.route(Method::GET, pattern, handler)
    }

    /// Adds a POST route.
    ///
    /// # Errors
    ///
    /// See [`Router::route`].
    pub fn post<H: Handler>(self, pattern: &str, handler: H) -> Result<Router, RouteError> {
        self.route(Method::POST, pattern, handler)
    }

    /// Adds a PUT route.
    ///
    /// # Errors
    ///
    /// See [`Router::route`].
    pub fn put<H: Handler>(self, pattern: &str, handler: H) -> Result<Router, RouteError> {
        self.route(Method::PUT, pattern, handler)
    }

    /// Adds a DELETE route.
    ///
    /// # Errors
    ///
    /// See [`Router::route`].
    pub fn delete<H: Handler>(self, pattern: &str, handler: H) -> Result<Router, RouteError> {
        self.route(Method::DELETE, pattern, handler)
    }

    /// Sets the handler for requests whose path matches no route.
    #[must_use]
    pub fn fallback<H: Handler>(mut self, handler: H) -> Router {
        self.fallback = Some(Box::new(handler));
        self
    }

    fn best<'a>(&'a self, method: &Method, path: &[String]) -> Option<&'a Route> {
        self.routes
            .iter()
            .filter(|r| r.method == *method && r.matches(path))
            .max_by(|a, b| a.specificity().cmp(&b.specificity()))
    }

    async fn dispatch(&self, mut req: Request) -> Response {
        if req.target.form() == TargetForm::Asterisk {
            return Response::new(StatusCode::OK);
        }
        let Some(path) = decode_path(req.target.path()) else {
            return Response::new(StatusCode::BAD_REQUEST);
        };
        let route = self.best(&req.method, &path).or_else(|| {
            if req.method == Method::HEAD {
                self.best(&Method::GET, &path)
            } else {
                None
            }
        });
        if let Some(route) = route {
            req.context.params = route
                .segments
                .iter()
                .zip(&path)
                .filter_map(|(s, p)| match s {
                    Segment::Param(name) => Some((name.clone(), p.as_str().into())),
                    Segment::Literal(_) => None,
                })
                .collect();
            return route.handler.call(req).await;
        }
        let mut allowed: Vec<&str> = self
            .routes
            .iter()
            .filter(|r| r.matches(&path))
            .map(|r| r.method.as_str())
            .collect();
        if !allowed.is_empty() {
            if allowed.contains(&"GET") {
                allowed.push("HEAD");
            }
            allowed.sort_unstable();
            allowed.dedup();
            let mut resp = Response::new(StatusCode::METHOD_NOT_ALLOWED);
            if let (Ok(name), Ok(value)) = (
                HeaderName::new("allow"),
                HeaderValue::new(allowed.join(", ")),
            ) {
                resp.headers.append(name, value);
            }
            return resp;
        }
        match &self.fallback {
            Some(h) => h.call(req).await,
            None => Response::new(StatusCode::NOT_FOUND),
        }
    }
}

impl Handler for Router {
    fn handle(&self, req: Request) -> impl Future<Output = Response> + Send {
        self.dispatch(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert!(parse_pattern("/").is_ok());
        assert!(parse_pattern("/a/{id}/b").is_ok());
        assert!(parse_pattern("a").is_err());
        assert!(parse_pattern("/{}").is_err());
        assert!(parse_pattern("/{a-b}").is_err());
        assert!(parse_pattern("/{a}/{a}").is_err());
        assert!(parse_pattern("/a b").is_err());
        assert!(parse_pattern("/a/../b").is_err());
        assert!(parse_pattern("/%41").is_err());
    }

    #[test]
    fn path_decoding() {
        assert_eq!(decode_path("/a/b%20c").unwrap(), vec!["a", "b c"]);
        assert_eq!(decode_path("/").unwrap(), vec![""]);
        assert!(decode_path("/a/%2e%2E/b").is_none());
        assert!(decode_path("/a/./b").is_none());
        assert!(decode_path("/%ff").is_none());
    }

    /// TH-26, review finding router-param-traversal: separators, control
    /// characters and double encoding never survive into a segment.
    #[test]
    fn review_router_param_traversal_segments() {
        for bad in [
            "/..%2F..%2Fetc",
            "/a%2fb",
            "/a%5Cb",
            "/a%00b",
            "/a%1Fb",
            "/a%7Fb",
            "/a%C2%9Fb",
            "/%252F",
            "/%252e%252e",
            "/%2541",
        ] {
            assert!(decode_path(bad).is_none(), "{bad}");
        }
        // Decoding happens once: `%2525` becomes `%25`, which is a triple,
        // so it is rejected, while `%25` alone becomes a plain `%`.
        assert!(decode_path("/%2525").is_none());
        assert_eq!(decode_path("/%25").unwrap(), vec!["%"]);
        assert_eq!(decode_path("/%25g0").unwrap(), vec!["%g0"]);
        assert_eq!(decode_path("/a/.../..b").unwrap(), vec!["a", "...", "..b"]);
    }
}
