//! The retrieval request and result on the wire (M7 design section 3.2).
//!
//! The assessor asks the proxy with `GET /v1/retrieve?url=<percent-encoded
//! URL>`. Every other method is refused by the router. The reply is one
//! JSON object, always with status 200:
//!
//! - `{"chain": [url, ...], "text": "...", "truncated": false}` on success;
//! - `{"refusal": "<code>"}`, plus `"status": n` for `http_status`.
//!
//! Fixture files: `testdata/result-retrieved.json` and
//! `testdata/result-refused.json`.

use fstp_findings::UntrustedText;
use fstp_http::{Request, Response, Router, StatusCode, handler_fn};
use fstp_json::{Array, FromJsonError, FromJsonErrorKind, Object, Value};
use fstp_rt::Runtime;

use crate::fetch::{Retrieved, Retriever};
use crate::refusal::Refusal;
use crate::url::{SourceUrl, percent_decode};

/// The path of the retrieval endpoint.
pub const RETRIEVE_PATH: &str = "/v1/retrieve";

/// The outcome of one retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The source was retrieved.
    Retrieved(Retrieved),
    /// The proxy refused.
    Refused(Refusal),
}

fn invalid(why: &'static str) -> FromJsonError {
    FromJsonError::new(FromJsonErrorKind::Invalid(why))
}

impl Outcome {
    /// The wire form.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            Outcome::Retrieved(r) => {
                let chain: Array = r
                    .chain
                    .iter()
                    .map(|u| Value::String(u.as_str().to_owned()))
                    .collect();
                o.insert("chain", Value::Array(chain));
                o.insert("text", Value::String(r.text.as_data().to_owned()));
                o.insert("truncated", Value::Bool(r.truncated));
            }
            Outcome::Refused(f) => {
                o.insert("refusal", Value::String(f.code().to_owned()));
                if let Refusal::HttpStatus(s) = f {
                    o.insert("status", fstp_json::ToJson::to_json(s));
                }
            }
        }
        Value::Object(o)
    }

    /// Reads the wire form. Unknown members fail.
    ///
    /// # Errors
    ///
    /// A [`FromJsonError`] for any member that does not fit.
    pub fn from_json(v: &Value) -> Result<Outcome, FromJsonError> {
        let o = v.as_object().ok_or_else(|| invalid("not an object"))?;
        if let Some(code) = o.get("refusal") {
            if o.keys().any(|k| k != "refusal" && k != "status") {
                return Err(FromJsonError::new(FromJsonErrorKind::UnknownField));
            }
            let code = code.as_str().ok_or_else(|| invalid("refusal"))?;
            let status = match o.get("status") {
                Some(s) => Some(
                    s.as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .ok_or_else(|| invalid("status"))?,
                ),
                None => None,
            };
            if status.is_some() && code != "http_status" {
                return Err(invalid("status"));
            }
            return Refusal::from_code(code, status)
                .map(Outcome::Refused)
                .ok_or_else(|| invalid("refusal"));
        }
        if o.keys()
            .any(|k| !matches!(k, "chain" | "text" | "truncated"))
        {
            return Err(FromJsonError::new(FromJsonErrorKind::UnknownField));
        }
        let missing = || FromJsonError::new(FromJsonErrorKind::MissingField);
        let chain = o
            .get("chain")
            .ok_or_else(missing)?
            .as_array()
            .ok_or_else(|| invalid("chain"))?
            .into_iter()
            .map(|u| {
                u.as_str()
                    .and_then(|s| SourceUrl::parse(s).ok())
                    .ok_or_else(|| invalid("chain"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if chain.is_empty() {
            return Err(invalid("chain"));
        }
        let text = o
            .get("text")
            .ok_or_else(missing)?
            .as_str()
            .ok_or_else(|| invalid("text"))?;
        let truncated = o
            .get("truncated")
            .ok_or_else(missing)?
            .as_bool()
            .ok_or_else(|| invalid("truncated"))?;
        Ok(Outcome::Retrieved(Retrieved {
            chain,
            text: UntrustedText::new(text.to_owned()),
            truncated,
        }))
    }
}

/// The `url` parameter of a retrieval query. `None` when it is missing,
/// repeated, badly escaped or not UTF-8.
#[must_use]
pub fn url_param(query: &str) -> Option<String> {
    let mut found = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "url" {
            if found.is_some() {
                return None;
            }
            found = Some(percent_decode(v)?);
        }
    }
    found
}

/// The query string that asks for `url`.
#[must_use]
pub fn query_for(url: &SourceUrl) -> String {
    let mut q = String::from("url=");
    for b in url.as_str().bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            q.push(char::from(b));
        } else {
            q.push_str(&format!("%{b:02X}"));
        }
    }
    q
}

async fn answer<R: Runtime>(retriever: &Retriever<R>, req: &Request) -> Outcome {
    let Some(raw) = req.query().and_then(url_param) else {
        return Outcome::Refused(Refusal::MalformedUrl);
    };
    let url = match SourceUrl::parse(&raw) {
        Ok(u) => u,
        Err(f) => return Outcome::Refused(f),
    };
    match retriever.get(&url).await {
        Ok(r) => Outcome::Retrieved(r),
        Err(f) => Outcome::Refused(f),
    }
}

/// The proxy's router: `GET /v1/retrieve` only.
///
/// # Errors
///
/// Never in practice: the route pattern is a constant.
pub fn router<R: Runtime>(retriever: Retriever<R>) -> Result<Router, fstp_http::RouteError> {
    let handler = handler_fn(move |req: Request| {
        let r = retriever.clone();
        async move {
            let outcome = answer(&r, &req).await;
            Response::with_body(
                StatusCode::OK,
                "application/json",
                fstp_json::to_compact(&outcome.to_json()).into_bytes(),
            )
        }
    });
    Router::new().get(RETRIEVE_PATH, handler)
}
