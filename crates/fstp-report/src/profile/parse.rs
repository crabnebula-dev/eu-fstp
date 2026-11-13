//! The funder profile parser (M9 design section 2.5). Profile files are
//! untrusted input (section 5): every member is required, unknown members
//! are refused, and the input is bounded. Fuzzed
//! (`funder_profile_parse`).

use std::collections::BTreeSet;

use fstp_domain::id::ContentDigest;
use fstp_json::{Object, ParseLimits, Value};
use fstp_report_core::{ReportKind, is_profile_id};

use super::{
    FieldSpec, Figure, FunderProfile, Level, OutputSpec, PeriodSource, VisibilityElement,
    WordingStatus,
};

/// The largest profile file accepted, in bytes.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// The most fields one output may hold.
const MAX_FIELDS: usize = 64;
/// The most visibility elements a profile may name.
const MAX_ELEMENTS: usize = 16;
/// The longest field name or element key, in bytes.
const MAX_NAME: usize = 40;
/// The longest label, in bytes.
const MAX_LABEL: usize = 80;
/// The longest template or wording ref, in bytes.
const MAX_REF: usize = 128;
/// The only format version this parser reads.
const FORMAT: u64 = 1;
/// The stored status of a wording that waits for approved text.
const PENDING_LEGAL: &str = "TODO(legal)";

/// Why a profile was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// The file is not I-JSON or exceeds the limits.
    Json,
    /// The file does not have the profile shape. The reason names the
    /// rule, never input content.
    Shape(&'static str),
    /// No shipped profile has that id and version.
    NotShipped,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Json => f.write_str("the funder profile is not bounded I-JSON"),
            ProfileError::Shape(r) => write!(f, "malformed funder profile: {r}"),
            ProfileError::NotShipped => f.write_str("no shipped funder profile has that version"),
        }
    }
}

impl std::error::Error for ProfileError {}

fn shape(r: &'static str) -> ProfileError {
    ProfileError::Shape(r)
}

/// `v` as an object with exactly `members`.
fn exact<'v>(
    v: &'v Value,
    members: &[&str],
    what: &'static str,
) -> Result<&'v Object, ProfileError> {
    let o = v.as_object().ok_or(shape(what))?;
    if o.len() != members.len() || !members.iter().all(|m| o.contains_key(m)) {
        return Err(shape(what));
    }
    Ok(o)
}

fn string<'v>(o: &'v Object, k: &str, what: &'static str) -> Result<&'v str, ProfileError> {
    o.get(k).and_then(Value::as_str).ok_or(shape(what))
}

/// A field name or element key: 1 to [`MAX_NAME`] bytes of lower-case
/// ASCII letters, digits and underscores, starting with a letter.
fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// A template or wording ref: `<profile id>/` then 1 to [`MAX_REF`]
/// bytes in all of lower-case ASCII letters, digits, `_`, `-`, `.` and
/// `/`.
fn is_ref(s: &str, id: &str) -> bool {
    s.len() <= MAX_REF
        && s.strip_prefix(id)
            .and_then(|r| r.strip_prefix('/'))
            .is_some_and(|r| !r.is_empty())
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.' | b'/')
        })
}

/// A label: 1 to [`MAX_LABEL`] bytes with no control character, not
/// blank, and no angle bracket.
fn is_label(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= MAX_LABEL
        && !s.chars().any(|c| c.is_control() || c == '<' || c == '>')
}

/// The member names an output writes itself at `level`. A field may not
/// take one.
fn reserved(kind: ReportKind, level: Level) -> &'static [&'static str] {
    const HEADER: [&str; 15] = [
        "profile",
        "profile_version",
        "profile_digest",
        "output",
        "template",
        "snapshot",
        "call",
        "programme",
        "opens",
        "deadline",
        "deadline_time_zone",
        "currency",
        "frozen_policy",
        "publication_sequence",
        "published_at",
    ];
    match (kind, level) {
        (ReportKind::CallPublicationRecord, Level::Call) => &HEADER,
        (ReportKind::PeriodicReportingData, Level::Recipient) => &["recipient", "call"],
        (ReportKind::PeriodicReportingData, Level::Period) => &["start", "end", "recipients"],
        _ => &[],
    }
}

fn field(v: &Value, kind: ReportKind) -> Result<FieldSpec, ProfileError> {
    let o = exact(
        v,
        &["name", "label", "level", "figure"],
        "a field has other members",
    )?;
    let name = string(o, "name", "a field name is not a string")?;
    if !is_name(name) {
        return Err(shape("a field name is not a name"));
    }
    let label = string(o, "label", "a field label is not a string")?;
    if !is_label(label) {
        return Err(shape("a field label is not a label"));
    }
    let level = Level::from_name(string(o, "level", "a field level is not a string")?)
        .ok_or(shape("a field names an unknown level"))?;
    if !Level::of_output(kind).contains(&level) {
        return Err(shape("a field level the output does not take"));
    }
    // I-44: the figure is a fold of the closed list, never a literal.
    let figure = o
        .get("figure")
        .and_then(Value::as_str)
        .and_then(Figure::from_name)
        .ok_or(shape("a field figure names no ledger fold"))?;
    if !figure.levels().contains(&level) {
        return Err(shape("a field figure is not defined at its level"));
    }
    if reserved(kind, level).contains(&name) {
        return Err(shape("a field name the output writes itself"));
    }
    Ok(FieldSpec {
        name: name.to_owned(),
        label: label.to_owned(),
        level,
        figure,
    })
}

fn output(v: &Value, id: &str) -> Result<OutputSpec, ProfileError> {
    let o = exact(
        v,
        &["kind", "template", "fields"],
        "an output has other members",
    )?;
    let kind = ReportKind::from_name(string(o, "kind", "an output kind is not a string")?)
        .ok_or(shape("an output names an unknown kind"))?;
    let template = string(o, "template", "a template is not a string")?;
    if !is_ref(template, id) {
        return Err(shape("a template ref is not a ref of the profile"));
    }
    let raw = o
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(shape("the fields are not an array"))?;
    if raw.len() > MAX_FIELDS {
        return Err(shape("an output holds too many fields"));
    }
    let fields = raw
        .iter()
        .map(|f| field(f, kind))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    if !fields
        .iter()
        .all(|f| seen.insert((f.level, f.name.as_str())))
    {
        return Err(shape("two fields share a name at one level"));
    }
    Ok(OutputSpec {
        kind,
        template: template.to_owned(),
        fields,
    })
}

fn element(v: &Value, id: &str) -> Result<VisibilityElement, ProfileError> {
    let o = exact(
        v,
        &["key", "wording"],
        "a visibility element has other members",
    )?;
    let key = string(o, "key", "an element key is not a string")?;
    if !is_name(key) {
        return Err(shape("an element key is not a name"));
    }
    let w = exact(
        o.get("wording").ok_or(shape("an element has no wording"))?,
        &["ref", "status"],
        "a wording has other members",
    )?;
    let wording = string(w, "ref", "a wording ref is not a string")?;
    if !is_ref(wording, id) {
        return Err(shape("a wording ref is not a ref of the profile"));
    }
    // Only pending wording exists until Daniel supplies approved text.
    let status = match string(w, "status", "a wording status is not a string")? {
        PENDING_LEGAL => WordingStatus::PendingLegal,
        _ => return Err(shape("a wording status is unknown")),
    };
    Ok(VisibilityElement {
        key: key.to_owned(),
        wording: wording.to_owned(),
        status,
    })
}

fn periods(v: &Value) -> Result<PeriodSource, ProfileError> {
    let o = exact(
        v,
        &["source", "parameter"],
        "the reporting periods have other members",
    )?;
    match (
        string(o, "source", "a period source is not a string")?,
        string(o, "parameter", "a period parameter is not a string")?,
    ) {
        ("data_sheet", "P-57") => Ok(PeriodSource::DataSheetP57),
        _ => Err(shape("the reporting periods name no Data Sheet parameter")),
    }
}

/// Parses a funder profile file (module documentation of `profile`).
pub fn parse_profile(bytes: &[u8]) -> Result<FunderProfile, ProfileError> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(ProfileError::Json);
    }
    let limits = ParseLimits {
        max_input_bytes: MAX_PROFILE_BYTES,
        max_depth: 8,
        max_string_bytes: 1024,
        max_number_len: 8,
        ..ParseLimits::default()
    };
    let v = fstp_json::parse_with(bytes, &limits).map_err(|_| ProfileError::Json)?;
    let o = exact(
        &v,
        &[
            "funder_profile_version",
            "id",
            "version",
            "outputs",
            "visibility_elements",
            "reporting_periods",
        ],
        "the profile has other members",
    )?;
    if o.get("funder_profile_version").and_then(Value::as_u64) != Some(FORMAT) {
        return Err(shape("an unknown profile format version"));
    }
    let id = string(o, "id", "the profile id is not a string")?;
    if !is_profile_id(id) {
        return Err(shape("the profile id is not an id"));
    }
    let version = o
        .get("version")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n >= 1)
        .ok_or(shape("the profile version is not from 1 to 65535"))?;
    let raw = o
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or(shape("the outputs are not an array"))?;
    if raw.is_empty() || raw.len() > ReportKind::ALL.len() {
        return Err(shape("the profile holds no output or too many"));
    }
    let outputs = raw
        .iter()
        .map(|x| output(x, id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut kinds = BTreeSet::new();
    if !outputs.iter().all(|x| kinds.insert(x.kind)) {
        return Err(shape("two outputs share a kind"));
    }
    let raw = o
        .get("visibility_elements")
        .and_then(Value::as_array)
        .ok_or(shape("the visibility elements are not an array"))?;
    if raw.len() > MAX_ELEMENTS {
        return Err(shape("too many visibility elements"));
    }
    let visibility = raw
        .iter()
        .map(|x| element(x, id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = BTreeSet::new();
    if !visibility.iter().all(|e| keys.insert(e.key.as_str())) {
        return Err(shape("two visibility elements share a key"));
    }
    let periods = periods(
        o.get("reporting_periods")
            .ok_or(shape("no reporting periods"))?,
    )?;
    Ok(FunderProfile {
        id: id.to_owned(),
        version,
        digest: ContentDigest::from_bytes(fstp_crypto::sha256(bytes)),
        outputs,
        visibility,
        periods,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_refs_and_labels() {
        assert!(is_name("paid_hardship"));
        assert!(!is_name("Paid") && !is_name("_x") && !is_name("") && !is_name("a-b"));
        assert!(is_ref("horizon-europe/audit_file/1", "horizon-europe"));
        assert!(!is_ref("other/audit_file/1", "horizon-europe"));
        assert!(!is_ref("horizon-europe/", "horizon-europe"));
        assert!(!is_ref("horizon-europe/A", "horizon-europe"));
        assert!(is_label("Amount paid"));
        assert!(!is_label(" ") && !is_label("a\nb") && !is_label("<b>"));
    }
}
