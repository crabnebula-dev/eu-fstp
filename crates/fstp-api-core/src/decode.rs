//! Strict request decoders, one per operation, under limits (design
//! section 3.7 step 1).
//!
//! An adapter builds an [`Op`] in one of two ways:
//!
//! - [`decode_route`] for a web request below `/api/v1`, matched against
//!   the routes of the registry, which `fstp-web` cannot read (rule A2);
//! - [`decode_tool`] for an MCP `tools/call`, by tool name.
//!
//! Both give the same request object for the same operation: the path
//! parameters, each a canonical decimal string, and the body members.
//! The object is checked by the operation's form, so unknown, missing and
//! mistyped members are refused, and amounts sent as JSON numbers are
//! refused (ADR-006). Errors name no request content.

use std::collections::BTreeMap;

use fstp_access::{OPS, OpKind, OpSpec};
use fstp_json::{Object, ParseLimits, Value};

use crate::forms::{self, REQUEST_RULE};
use crate::{ApiError, Op};

/// The largest request body, in bytes: the body limit of `fstp-web`.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// The largest query string, in bytes (interim, pending Daniel).
pub const QUERY_LIMIT: usize = 2048;

/// The parse limits of a request body.
fn limits() -> ParseLimits {
    limits_with(forms::TEXT_LIMIT)
}

/// The parse limits of a request body whose strings may hold up to
/// `strings` bytes.
fn limits_with(strings: usize) -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(BODY_LIMIT)
        .with_max_depth(16)
        .with_max_string_bytes(strings)
        .with_max_container_len(10_000)
        .with_max_nodes(100_000)
        .with_max_memory_bytes(8 << 20)
}

fn bad() -> ApiError {
    ApiError::bad_request(REQUEST_RULE)
}

/// A decoded query string: each name once, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryParams {
    params: BTreeMap<String, String>,
}

impl QueryParams {
    /// The value of `name`, if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// Whether the query string held no parameter.
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

/// A decoded page cursor: the offset of the first item.
///
/// Interim, pending Daniel: a cursor is the canonical decimal offset. It
/// carries no state, so a forged cursor reaches nothing the caller could
/// not page to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The offset of the first item.
    pub offset: u32,
}

/// A stored pending request, decoded again at confirmation: the
/// operation name and its request object, as canonical JSON
/// `{"op": "...", "request": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    op: Op,
}

impl PendingRequest {
    /// The operation name.
    pub fn op_name(&self) -> &'static str {
        self.op.spec.name
    }

    /// The operation it replays.
    pub(crate) fn into_op(self) -> Op {
        self.op
    }
}

/// The canonical text of the pending request of `op`.
pub(crate) fn pending_request_text(op: &Op) -> Option<String> {
    let mut o = Object::new();
    let _ = o.insert("op", Value::from(op.spec.name));
    let _ = o.insert("request", Value::Object(op.request.clone()));
    fstp_json::to_canonical(&Value::Object(o)).ok()
}

/// The HTTP method of a web route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// The registry's method.
    fn access(self) -> fstp_access::Method {
        match self {
            Method::Get => fstp_access::Method::Get,
            Method::Post => fstp_access::Method::Post,
            Method::Put => fstp_access::Method::Put,
            Method::Delete => fstp_access::Method::Delete,
        }
    }
    /// The method of the registry's `m`.
    const fn of(m: fstp_access::Method) -> Method {
        match m {
            fstp_access::Method::Get => Method::Get,
            fstp_access::Method::Post => Method::Post,
            fstp_access::Method::Put => Method::Put,
            fstp_access::Method::Delete => Method::Delete,
        }
    }
}

/// Parses a body that must be one JSON object. An empty body is the
/// empty object.
fn body_object(body: &[u8]) -> Result<Object, ApiError> {
    body_object_with(body, &limits())
}

/// Parses the body of `spec`. An upload carries its document as one
/// string, up to the body limit (Q24, lane m4wire). Every other string
/// is held to the text limit.
fn body_object_for(spec: &OpSpec, body: &[u8]) -> Result<Object, ApiError> {
    if matches!(
        spec.kind,
        OpKind::Import(fstp_access::ImportKind::RegisterDocument)
    ) {
        return body_object_with(body, &limits_with(BODY_LIMIT));
    }
    body_object(body)
}

/// Parses a body that must be one JSON object under `limits`.
fn body_object_with(body: &[u8], limits: &ParseLimits) -> Result<Object, ApiError> {
    if body.is_empty() {
        return Ok(Object::new());
    }
    match fstp_json::parse_with(body, limits) {
        Ok(Value::Object(o)) => Ok(o),
        _ => Err(bad()),
    }
}

/// Matches `path` against the route pattern `pattern`, returning the
/// path parameters, or `None`.
fn match_route(pattern: &'static str, path: &str) -> Option<Vec<(&'static str, String)>> {
    let pat: Vec<&str> = pattern.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    if pat.len() != got.len() {
        return None;
    }
    let mut params = Vec::new();
    for (p, g) in pat.iter().zip(got.iter()) {
        match p.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => {
                if !forms::param_str_ok(name, g) {
                    return None;
                }
                let name = static_name(pattern, name)?;
                params.push((name, (*g).to_owned()));
            }
            None if p == g => {}
            None => return None,
        }
    }
    Some(params)
}

/// The `'static` parameter name of `pattern` that equals `name`.
fn static_name(pattern: &'static str, name: &str) -> Option<&'static str> {
    fstp_access::route_params(pattern).find(|p| *p == name)
}

/// Checks a request object for `spec` and wraps it.
fn finish(spec: &'static OpSpec, mut request: Object, from_tool: bool) -> Result<Op, ApiError> {
    crate::pageforms::rewrite(spec, &mut request)?;
    forms::check(spec, &request)?;
    Ok(Op {
        spec,
        request,
        from_tool,
    })
}

/// Decodes one web request into its operation (design sections 2.2 and
/// 3.6). `path` is the route below `/api/v1`, such as
/// `/calls/7/publication`, with no query. `body` is the JSON body, or
/// empty for a route that takes none. Path segments name the target ids.
/// The body holds the other members of the operation's request.
///
/// The route table is `OpSpec::route` of the registry, which `fstp-web`
/// cannot read (rule A2), so the match runs here. Public pages live under
/// `/p`, outside the API, so no public operation matches here.
pub fn decode_route(method: Method, path: &str, body: &[u8]) -> Result<Op, ApiError> {
    decode_route_in(OPS, method, path, body)
}

/// [`decode_route`] over the operation table `ops`.
pub(crate) fn decode_route_in(
    ops: &'static [OpSpec],
    method: Method,
    path: &str,
    body: &[u8],
) -> Result<Op, ApiError> {
    if body.len() > BODY_LIMIT {
        return Err(bad());
    }
    let found = ops.iter().find_map(|spec| {
        let (m, pattern) = spec.route?;
        if m != method.access() || matches!(spec.kind, OpKind::Public(_)) {
            return None;
        }
        match_route(pattern, path).map(|params| (spec, params))
    });
    let Some((spec, params)) = found else {
        return Err(ApiError::refused(crate::ErrorCode::NotFound, "route"));
    };
    if method == Method::Get && !body.is_empty() {
        return Err(bad());
    }
    let mut request = body_object_for(spec, body)?;
    for (name, value) in params {
        if request.insert(name, Value::String(value)).is_some() {
            // A body member may not repeat a path parameter.
            return Err(bad());
        }
    }
    finish(spec, request, false)
}

/// Decodes one MCP `tools/call` into its operation (design section 3.8).
/// `tool` is a tool name of the registry, such as
/// `fstp_prepare_call_publication`. `arguments` is the JSON object of the
/// call's arguments: the tool's path parameters and, for a tool with a
/// request object, its members. A name outside the registry is refused.
pub fn decode_tool(tool: &str, arguments: &[u8]) -> Result<Op, ApiError> {
    decode_tool_in(OPS, tool, arguments)
}

/// [`decode_tool`] over the operation table `ops`.
pub(crate) fn decode_tool_in(
    ops: &'static [OpSpec],
    tool: &str,
    arguments: &[u8],
) -> Result<Op, ApiError> {
    if arguments.len() > BODY_LIMIT {
        return Err(bad());
    }
    let spec = ops
        .iter()
        .find(|s| s.tool.is_some_and(|t| t.name == tool))
        .ok_or(ApiError::refused(crate::ErrorCode::NotFound, "tool"))?;
    let request = body_object_for(spec, arguments)?;
    let input = spec.tool.map(|t| t.input);
    if let Some(input) = input
        && !input.body
        && request.len() != input.params.len()
    {
        return Err(bad());
    }
    finish(spec, request, true)
}

/// Decodes one operation's request through one of the adapter-facing
/// paths. Fuzzed (`api_request_decode`). The first byte picks the path,
/// modulo 5:
///
/// - 0, direct: the next byte selects an operation in registry order, and
///   the rest is its request object.
/// - 1, guided route: the next byte selects a routed operation. The bytes
///   up to the first zero byte fill its path parameters in order, split at
///   `\n`. The rest is the body, through [`decode_route`].
/// - 2, raw route: the next byte selects the method, the bytes up to the
///   first zero byte are the path, and the rest is the body.
/// - 3, guided tool: the next byte selects a tool, and the rest is its
///   arguments, through [`decode_tool`].
/// - 4, raw tool: the bytes up to the first zero byte are the tool name,
///   and the rest is the arguments.
///
/// Each path checks the request with the operation's strict form, so
/// JSON numbers for amounts are refused (ADR-006).
pub fn decode_request(bytes: &[u8]) -> Result<Op, ApiError> {
    decode_request_in(OPS, bytes)
}

/// The bytes before the first zero byte, and the bytes after it. With no
/// zero byte, all of them and none.
fn split_zero(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().position(|b| *b == 0) {
        Some(i) => (
            bytes.get(..i).unwrap_or_default(),
            bytes.get(i.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (bytes, &[]),
    }
}

/// The item of `items` that `selector` picks, modulo their count.
fn pick<T>(items: &[T], selector: u8) -> Option<&T> {
    let index = usize::from(selector).checked_rem(items.len())?;
    items.get(index)
}

/// [`decode_request`] over the operation table `ops`.
pub(crate) fn decode_request_in(ops: &'static [OpSpec], bytes: &[u8]) -> Result<Op, ApiError> {
    let (mode, rest) = bytes.split_first().ok_or_else(bad)?;
    let (selector, tail) = rest.split_first().map_or((0, &[][..]), |(s, t)| (*s, t));
    let none = || ApiError::refused(crate::ErrorCode::NotFound, "route");
    match mode % 5 {
        0 => {
            let spec = pick(ops, selector).ok_or_else(none)?;
            if tail.len() > BODY_LIMIT {
                return Err(bad());
            }
            finish(spec, body_object_for(spec, tail)?, false)
        }
        1 => {
            let routed: Vec<&'static OpSpec> = ops.iter().filter(|s| s.route.is_some()).collect();
            let spec = pick(&routed, selector).ok_or_else(none)?;
            let (m, pattern) = spec.route.ok_or_else(none)?;
            let (segments, body) = split_zero(tail);
            let segments = std::str::from_utf8(segments).map_err(|_| bad())?;
            let mut values = segments.split('\n');
            let path: Vec<String> = pattern
                .split('/')
                .map(
                    |p| match p.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
                        Some(_) => values.next().unwrap_or_default().to_owned(),
                        None => p.to_owned(),
                    },
                )
                .collect();
            decode_route_in(ops, Method::of(m), &path.join("/"), body)
        }
        2 => {
            let methods = [Method::Get, Method::Post, Method::Put, Method::Delete];
            let method = pick(&methods, selector).copied().ok_or_else(none)?;
            let (path, body) = split_zero(tail);
            let path = std::str::from_utf8(path).map_err(|_| bad())?;
            decode_route_in(ops, method, path, body)
        }
        3 => {
            let tools: Vec<&'static str> =
                ops.iter().filter_map(|s| s.tool.map(|t| t.name)).collect();
            let name = pick(&tools, selector).copied().ok_or_else(none)?;
            decode_tool_in(ops, name, tail)
        }
        _ => {
            let (name, arguments) = split_zero(rest);
            let name = std::str::from_utf8(name).map_err(|_| bad())?;
            decode_tool_in(ops, name, arguments)
        }
    }
}

/// Decodes one percent-encoded query component: unreserved characters
/// and `%XX` only, as UTF-8.
fn query_component(s: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = s.iter();
    while let Some(&c) = i.next() {
        match c {
            b'%' => {
                let hi = *i.next()?;
                let lo = *i.next()?;
                let pair = [hi.to_ascii_lowercase(), lo.to_ascii_lowercase()];
                let text = std::str::from_utf8(&pair).ok()?;
                out.push(crate::action::from_hex::<1>(text)?.first().copied()?);
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(c),
            _ => return None,
        }
    }
    let s = String::from_utf8(out).ok()?;
    if s.chars().any(char::is_control) {
        return None;
    }
    Some(s)
}

/// Decodes a query string: `name=value` pairs separated by `&`. Names are
/// `[a-z_]{1,32}` and appear once. Fuzzed (`query_params_decode`).
pub fn decode_query_params(bytes: &[u8]) -> Result<QueryParams, ApiError> {
    if bytes.len() > QUERY_LIMIT {
        return Err(bad());
    }
    let mut params = BTreeMap::new();
    if bytes.is_empty() {
        return Ok(QueryParams { params });
    }
    for pair in bytes.split(|b| *b == b'&') {
        let eq = pair.iter().position(|b| *b == b'=').ok_or_else(bad)?;
        let (name, value) = pair.split_at(eq);
        let value = value.get(1..).ok_or_else(bad)?;
        let name_ok = (1..=32).contains(&name.len())
            && name.iter().all(|c| c.is_ascii_lowercase() || *c == b'_');
        if !name_ok {
            return Err(bad());
        }
        let name = String::from_utf8(name.to_vec()).map_err(|_| bad())?;
        let value = query_component(value).ok_or_else(bad)?;
        if params.insert(name, value).is_some() {
            return Err(bad());
        }
    }
    Ok(QueryParams { params })
}

/// Decodes a page cursor: a canonical decimal offset. Fuzzed
/// (`cursor_decode`).
pub fn decode_cursor(bytes: &[u8]) -> Result<Cursor, ApiError> {
    let s = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let n = forms::canonical_id(s).ok_or_else(bad)?;
    let offset = u32::try_from(n).map_err(|_| bad())?;
    Ok(Cursor { offset })
}

/// Decodes a stored pending request, `{"op": "...", "request": {...}}`
/// in canonical form, and checks the request with the operation's form
/// again. Fuzzed (`pending_request_decode`).
pub fn decode_pending_request(bytes: &[u8]) -> Result<PendingRequest, ApiError> {
    decode_pending_request_in(OPS, bytes)
}

/// [`decode_pending_request`] over the operation table `ops`.
pub(crate) fn decode_pending_request_in(
    ops: &'static [OpSpec],
    bytes: &[u8],
) -> Result<PendingRequest, ApiError> {
    let v = fstp_json::parse_with(bytes, &limits()).map_err(|_| bad())?;
    let canonical = v.to_canonical().map_err(|_| bad())?;
    if canonical.as_bytes() != bytes {
        return Err(bad());
    }
    let Value::Object(mut o) = v else {
        return Err(bad());
    };
    if o.len() != 2 {
        return Err(bad());
    }
    let name = o
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(bad)?
        .to_owned();
    let Some(Value::Object(request)) = o.remove("request") else {
        return Err(bad());
    };
    let spec = ops.iter().find(|s| s.name == name).ok_or_else(bad)?;
    Ok(PendingRequest {
        op: finish(spec, request, false)?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use fstp_access::{Classification, RoleOrApplicant, Schema, Scope, SessionNeed, ToolDef};
    use fstp_domain::CommandKind;
    use fstp_domain::roles::Role;

    use super::*;

    const AUTHOR: &[RoleOrApplicant] = &[RoleOrApplicant::Role(Role::ProgrammeManager)];
    const CALL_BODY: Schema = Schema {
        params: &["call"],
        body: true,
    };

    /// Two operations as the registry of lane W3a states them, so these
    /// tests hold whatever the registry in this tree holds.
    static OPS_UNDER_TEST: [OpSpec; 2] = [
        OpSpec {
            name: "call.edit",
            kind: OpKind::Command(CommandKind::EditCall),
            route: Some((fstp_access::Method::Put, "/calls/{call}")),
            tool: Some(ToolDef {
                name: "fstp_edit_call",
                description: "Edit a call.",
                input: &CALL_BODY,
                scope: Scope::CallsDraft,
                prepare_only: false,
            }),
            high_risk: false,
            binding: true,
            session: SessionNeed::Any,
            scope: Some(Scope::CallsDraft),
            acting: AUTHOR,
            classification: Classification::Confidential,
        },
        OpSpec {
            name: "call.publish",
            kind: OpKind::Command(CommandKind::PublishCall),
            route: Some((fstp_access::Method::Post, "/calls/{call}/publication")),
            tool: None,
            high_risk: true,
            binding: true,
            session: SessionNeed::PhishingResistant,
            scope: None,
            acting: AUTHOR,
            classification: Classification::Confidential,
        },
    ];

    fn route(method: Method, path: &str, body: &[u8]) -> Result<Op, ApiError> {
        decode_route_in(&OPS_UNDER_TEST, method, path, body)
    }

    /// I-84, design section 3.7: a route and its tool give the same
    /// request object.
    #[test]
    fn i84_route_and_tool_give_one_request() {
        let body = br#"{"opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.00","text":"t"}"#;
        let web = route(Method::Put, "/calls/7", body).unwrap();
        let args = br#"{"call":"7","opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.00","text":"t"}"#;
        let mcp = decode_tool_in(&OPS_UNDER_TEST, "fstp_edit_call", args).unwrap();
        assert_eq!(web.request, mcp.request);
        assert_eq!(web.spec.name, mcp.spec.name);
        assert!(mcp.from_tool && !web.from_tool);
    }

    /// I-84, design section 3.7 step 1: unknown members, missing members,
    /// path parameters in the body and non-canonical ids are refused.
    #[test]
    fn i84_strict_decoders_refuse_unknown_and_repeated_members() {
        let publish = "/calls/7/publication";
        assert!(route(Method::Post, publish, br#"{"x":1}"#).is_err());
        assert!(route(Method::Post, publish, br#"{"call":"7"}"#).is_err());
        assert!(route(Method::Post, "/calls/07/publication", b"").is_err());
        assert!(route(Method::Get, publish, b"").is_err(), "wrong method");
        assert!(route(Method::Post, publish, b"").is_ok());
        assert!(route(Method::Put, "/calls/7", br#"{"text":"t"}"#).is_err());
        assert!(decode_tool_in(&OPS_UNDER_TEST, "fstp_unknown", b"{}").is_err());
    }

    /// ADR-006: an amount sent as a JSON number is refused by the decoder,
    /// and so is a member of the wrong type.
    #[test]
    fn adr006_amounts_as_json_numbers_are_refused() {
        let number = br#"{"opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":10,"text":"t"}"#;
        assert!(route(Method::Put, "/calls/7", number).is_err());
        let scale = br#"{"opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.0","text":"t"}"#;
        assert!(route(Method::Put, "/calls/7", scale).is_err());
        let opens = br#"{"opens":1,"deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.00","text":"t"}"#;
        assert!(route(Method::Put, "/calls/7", opens).is_err());
    }

    /// I-85: a pending request decodes only in canonical form.
    #[test]
    fn i85_pending_request_round_trips_in_canonical_form() {
        let op = route(Method::Post, "/calls/7/publication", b"").unwrap();
        let text = pending_request_text(&op).unwrap();
        let back = decode_pending_request_in(&OPS_UNDER_TEST, text.as_bytes()).unwrap();
        assert_eq!(back.op_name(), "call.publish");
        assert_eq!(back.into_op().request, op.request);
        let spaced = text.replace(':', ": ");
        assert!(decode_pending_request_in(&OPS_UNDER_TEST, spaced.as_bytes()).is_err());
    }

    /// I-84, ADR-006, design section 9: the fuzzed entry reaches the route
    /// and tool decoders, guided by the registry and raw, and every path
    /// refuses an amount sent as a JSON number.
    #[test]
    fn adr006_fuzz_entry_reaches_route_and_tool_decoders() {
        let body = br#"{"opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.00","text":"t"}"#;
        let number = br#"{"opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":10,"text":"t"}"#;
        let with = |head: &[u8], tail: &[u8]| [head, tail].concat();
        let decode = |b: &[u8]| decode_request_in(&OPS_UNDER_TEST, b);
        let guided = decode(&with(b"\x01\x007\x00", body)).unwrap();
        assert_eq!((guided.spec.name, guided.from_tool), ("call.edit", false));
        assert!(decode(&with(b"\x01\x007\x00", number)).is_err());
        assert!(
            decode(&with(b"\x01\x0007\x00", body)).is_err(),
            "a non-canonical id"
        );
        let raw = decode(&with(b"\x02\x02/calls/7\x00", body)).unwrap();
        assert_eq!(raw.request, guided.request);
        assert!(
            decode(b"\x02\x00/calls/7/publication\x00").is_err(),
            "wrong method"
        );
        let args = br#"{"call":"7","opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":"10.00","text":"t"}"#;
        let tool = decode(&with(b"\x03\x00", args)).unwrap();
        assert_eq!(tool.request, guided.request);
        assert!(tool.from_tool);
        let named = decode(&with(b"\x04fstp_edit_call\x00", args)).unwrap();
        assert_eq!(named.request, guided.request);
        let numeric = br#"{"call":"7","opens":"1","deadline":"2","deadline_zone":"Europe/Brussels","currency":"EUR","budget":10,"text":"t"}"#;
        assert!(decode(&with(b"\x03\x00", numeric)).is_err());
        assert!(decode(&with(b"\x00\x00", numeric)).is_err());
        assert!(decode(b"").is_err());
    }

    /// Design section 3.7 step 1, a support test: query strings and cursors
    /// are strict.
    #[test]
    fn query_strings_and_cursors_are_strict() {
        let q = decode_query_params(b"cursor=10&limit=5").unwrap();
        assert_eq!(q.get("cursor"), Some("10"));
        assert!(decode_query_params(b"a=1&a=2").is_err());
        assert!(decode_query_params(b"A=1").is_err());
        assert!(decode_query_params(b"a=%zz").is_err());
        assert_eq!(decode_cursor(b"12").unwrap().offset, 12);
        assert!(decode_cursor(b"012").is_err());
    }
}
