//! The legal pages and the tenant's legal details (ADR-037).
//!
//! - `GET /legal/{text}` renders a `legal/` draft with the tenant's legal
//!   details (`fstp_public::legal`). The banner "Draft, not yet approved"
//!   stays until the text is approved (section 3).
//! - `GET /legal/details` answers the set details as JSON, for the
//!   branding page's form. Every value is shown on the pages anyway.
//!
//! Approval lives in `legal/page-approvals.json`, embedded at build time:
//! per text `null`, or the date and the SHA-256 of the exact draft file
//! Daniel approved. A text counts as approved only while the digest
//! matches its embedded draft and its shown part holds no pending point.
//! So an approval later removes the banner with no code change, and any
//! edit to the draft brings the banner back.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use fstp_brand::legal::LegalDetails;
use fstp_engine::EngineState;
use fstp_json::{Object, Value};
use fstp_public::legal::LegalText;

/// The legal text whose key in the approval file is `key`.
fn text_of(key: &str) -> Option<LegalText> {
    LegalText::ALL.into_iter().find(|t| t.key() == key)
}

/// The key of every legal text, in footer order: `privacy`,
/// `accessibility`, `imprint`, `terms`, `data_act`.
pub fn text_keys() -> impl Iterator<Item = &'static str> {
    LegalText::ALL.into_iter().map(LegalText::key)
}

/// The approval file as shipped.
pub const APPROVALS_JSON: &str = include_str!("../../../legal/page-approvals.json");

/// The path of the JSON answer of the set details.
pub const DETAILS_PATH: &str = "/legal/details";

/// One recorded approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    /// The day Daniel approved the text, `YYYY-MM-DD`.
    pub approved_on: String,
    /// The lower-case hex SHA-256 of the draft file he approved.
    pub sha256: String,
}

/// Whether `s` is a date of the form `YYYY-MM-DD`.
fn date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

/// Whether `s` is 64 lower-case hex digits.
fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parses an approval file: an object with exactly one member per text
/// key, each `null` or `{"approved_on": "YYYY-MM-DD", "sha256": hex}`.
///
/// # Errors
///
/// A constant naming the rule the file breaks.
pub fn parse_approvals(
    text: &str,
) -> Result<BTreeMap<&'static str, Option<Approval>>, &'static str> {
    let v = fstp_json::parse(text.as_bytes()).map_err(|_| "the file is not JSON")?;
    let o = v.as_object().ok_or("the file is not an object")?;
    if o.len() != LegalText::ALL.len() {
        return Err("the file must name each text exactly once");
    }
    let mut out = BTreeMap::new();
    for t in LegalText::ALL {
        let e = o.get(t.key()).ok_or("a text is missing")?;
        if e.is_null() {
            out.insert(t.key(), None);
            continue;
        }
        let e = e.as_object().ok_or("an approval is not an object")?;
        let (Some(on), Some(sha), 2) = (
            e.get("approved_on").and_then(Value::as_str),
            e.get("sha256").and_then(Value::as_str),
            e.len(),
        ) else {
            return Err("an approval needs exactly approved_on and sha256");
        };
        if !date(on) || !hex64(sha) {
            return Err("an approval holds a malformed date or digest");
        }
        out.insert(
            t.key(),
            Some(Approval {
                approved_on: on.to_owned(),
                sha256: sha.to_owned(),
            }),
        );
    }
    Ok(out)
}

/// The shipped approvals. A malformed file approves nothing, and a test
/// fails on it.
pub fn approvals() -> &'static BTreeMap<&'static str, Option<Approval>> {
    static A: OnceLock<BTreeMap<&'static str, Option<Approval>>> = OnceLock::new();
    A.get_or_init(|| parse_approvals(APPROVALS_JSON).unwrap_or_default())
}

/// The lower-case hex SHA-256 of the draft file of the text `key`, as
/// `shasum -a 256` prints it, or `None` for an unknown key.
pub fn digest_hex(key: &str) -> Option<String> {
    let text = text_of(key)?;
    Some(
        fstp_crypto::sha256(text.source().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The file name under `legal/` of the text `key`.
pub fn file_of(key: &str) -> Option<&'static str> {
    text_of(key).map(LegalText::file)
}

/// Whether `approval` approves the text `key` as embedded: the digest
/// matches and the shown part holds no pending point.
pub fn approves(key: &str, approval: Option<&Approval>) -> bool {
    let Some(text) = text_of(key) else {
        return false;
    };
    approval.is_some_and(|a| Some(&a.sha256) == digest_hex(key).as_ref())
        && fstp_public::legal::pending_points(text.source()) == 0
}

/// Whether the text `key` is approved by the shipped file. Computed once.
pub fn approved(key: &str) -> bool {
    static A: OnceLock<BTreeMap<&'static str, bool>> = OnceLock::new();
    A.get_or_init(|| {
        text_keys()
            .map(|k| (k, approves(k, approvals().get(k).and_then(Option::as_ref))))
            .collect()
    })
    .get(key)
    .copied()
    .unwrap_or(false)
}

/// The tenant's legal details, if an admin set them.
pub(crate) fn details(state: &EngineState) -> Option<&LegalDetails> {
    state.tenant.state()?.legal_details()
}

/// The JSON answer of `GET /legal/details`: one member per set field.
pub fn details_json(details: Option<&LegalDetails>) -> Value {
    let mut o = Object::new();
    for (f, v) in details.into_iter().flat_map(LegalDetails::pairs) {
        let _ = o.insert(f.key(), Value::from(v));
    }
    Value::Object(o)
}

/// The legal page at `path` (such as `/legal/privacy`) with `details`
/// and the brand sheet `stylesheet`, as HTML. `None` for any other path,
/// and on a writer defect.
pub fn page_html(
    path: &str,
    details: Option<&LegalDetails>,
    stylesheet: Option<&str>,
) -> Option<String> {
    let text = LegalText::from_path(path)?;
    let value = |name: &str| details.and_then(|d| d.placeholder(name)).map(str::to_owned);
    fstp_public::legal::render_legal(&fstp_public::legal::LegalPage {
        text,
        approved: approved(text.key()),
        value: &value,
        stylesheet,
    })
    .ok()
    .map(|d| d.as_str().to_owned())
}
