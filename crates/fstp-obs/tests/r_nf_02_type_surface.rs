//! R-NF-02: logs and metrics contain no proposal content or identity
//! attributes. M3 design section 11.1 holds that by construction.
//!
//! - `LogEvent` and `Metric` are closed enums.
//! - Their fields are ids, rule references, enums, counts, durations and
//!   `&'static str`. No variant takes a `String`.
//! - Paths are logged as route templates.
//! - Operator metrics are labelled with the cell id only.
//!
//! These tests read the crate's sources through the scanner in
//! `tests/common`. Each rule has a teeth twin that seeds one violation and
//! checks that the rule catches it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    Defs, Kind, Tok, crate_defs, defs_from, is_static_str, is_value_type, last_segment, report,
    show, surface,
};

/// Field names that hold a path, so they must be route templates.
const PATH_WORDS: &[&str] = &[
    "path", "route", "target", "uri", "url", "endpoint", "location", "query",
];

/// Field names that would label a metric with something other than the cell.
const LABEL_WORDS: &[&str] = &[
    "route",
    "path",
    "tenant",
    "user",
    "account",
    "host",
    "ip",
    "addr",
    "label",
    "tag",
    "programme",
    "proposal",
    "session",
    "device",
];

fn has_word(name: &str, words: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    words.iter().any(|w| lower.contains(w))
}

// ------------------------------------------------------------------ rules

/// The R-NF-02 surface rule over the closure of `roots`.
fn surface_violations(defs: &Defs, roots: &[&str]) -> String {
    report(&surface(defs, roots).violations)
}

/// Whether a type is a route template: `&'static str`, or a crate type with
/// `Route` in its name whose own fields are `&'static str` only (a unit-only
/// enum of routes has none).
fn is_route_template(defs: &Defs, ty: &[Tok]) -> bool {
    if is_static_str(ty) {
        return true;
    }
    let Some(name) = last_segment(ty) else {
        return false;
    };
    if !name.contains("Route") {
        return false;
    }
    let Some(items) = defs.items.get(name) else {
        return false;
    };
    items
        .iter()
        .all(|it| it.kind != Kind::Alias || is_static_str(&it.alias))
        && items
            .iter()
            .flat_map(|it| it.fields.iter())
            .all(|f| is_static_str(&f.ty))
}

/// Path-like fields reached from `LogEvent` and `Metric` that are not route
/// templates.
fn route_violations(defs: &Defs) -> Vec<String> {
    let s = surface(defs, &["LogEvent", "Metric"]);
    s.fields
        .iter()
        .filter(|(_, f)| {
            f.name.as_deref().is_some_and(|n| has_word(n, PATH_WORDS))
                || last_segment(&f.ty).is_some_and(|t| has_word(t, PATH_WORDS))
        })
        .filter(|(_, f)| !is_route_template(defs, &f.ty))
        .map(|(place, f)| format!("{place}: `{}` is not a route template", show(&f.ty)))
        .collect()
}

/// Whether some `LogEvent` variant carries a route template field.
fn log_event_has_route(defs: &Defs) -> bool {
    let s = surface(defs, &["LogEvent"]);
    s.fields.iter().any(|(_, f)| {
        let named = f.name.as_deref().is_some_and(|n| n.contains("route"));
        let typed = last_segment(&f.ty).is_some_and(|t| t.contains("Route"));
        (named || typed) && is_route_template(defs, &f.ty)
    })
}

fn is_cell_field(f: &common::Field) -> bool {
    matches!(f.name.as_deref(), Some("cell" | "cell_id")) || last_segment(&f.ty) == Some("CellId")
}

/// A crate enum whose variants all carry no data, such as a metric name.
fn is_unit_enum(defs: &Defs, ty: &[Tok]) -> bool {
    let Some(name) = last_segment(ty) else {
        return false;
    };
    defs.items.get(name).is_some_and(|items| {
        items
            .iter()
            .all(|it| it.kind == Kind::Enum && !it.generic && it.fields.is_empty())
    })
}

/// The metric labelling rule. The sample type is what `encode_metric`
/// takes, since that is what reaches operator aggregation. Every sample (each
/// variant, for an enum) has exactly one cell id field. Every other
/// top-level field is a count or a duration, or a data-free enum that names
/// the metric. No field anywhere in its closure is named like a label.
fn metric_label_violations(defs: &Defs) -> Vec<String> {
    let Some(param) = defs.fn_first_param.get("encode_metric") else {
        return vec!["fstp-obs defines no `encode_metric` function".into()];
    };
    let Some(sample) = last_segment(
        param
            .iter()
            .skip_while(|t| **t == Tok::P('&'))
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .map(str::to_owned) else {
        return vec![format!("cannot read the sample type `{}`", show(param))];
    };
    let Some(items) = defs.items.get(&sample) else {
        return vec![format!("sample type `{sample}` is not defined in fstp-obs")];
    };
    let mut out = Vec::new();
    for it in items {
        let groups: Vec<(String, Vec<&common::Field>)> = match it.kind {
            Kind::Enum => it
                .variants
                .iter()
                .map(|v| {
                    (
                        format!("{sample}::{v}"),
                        it.fields
                            .iter()
                            .filter(|f| f.variant.as_deref() == Some(v.as_str()))
                            .collect(),
                    )
                })
                .collect(),
            _ => vec![(sample.clone(), it.fields.iter().collect())],
        };
        for (owner, fields) in groups {
            let cells = fields.iter().filter(|f| is_cell_field(f)).count();
            if cells != 1 {
                out.push(format!(
                    "{owner} has {cells} cell id fields, wants exactly 1"
                ));
            }
            for f in fields.iter().filter(|f| !is_cell_field(f)) {
                if !(is_value_type(&f.ty) || is_unit_enum(defs, &f.ty)) {
                    out.push(format!(
                        "{owner}.{}: `{}` is a label, not a count, duration or metric name",
                        f.name.as_deref().unwrap_or("_"),
                        show(&f.ty)
                    ));
                }
            }
        }
    }
    for (place, f) in &surface(defs, &[sample.as_str()]).fields {
        if f.name.as_deref().is_some_and(|n| has_word(n, LABEL_WORDS)) {
            out.push(format!("{place}: a metric label other than the cell id"));
        }
    }
    out
}

// --------------------------------------------------------- against the crate

/// R-NF-02 (design section 11.1): no `LogEvent` variant, and no type it
/// reaches, can hold a `String`, arbitrary bytes or any other free text.
#[test]
fn r_nf_02_log_events_take_no_free_text() {
    let v = surface_violations(&crate_defs(), &["LogEvent"]);
    assert!(v.is_empty(), "LogEvent surface breaks R-NF-02:\n{v}");
}

/// R-NF-02 (design section 11.1): `Metric` is a closed enum, and no variant
/// or type it reaches can hold free text or arbitrary bytes.
#[test]
fn r_nf_02_metrics_take_no_free_text() {
    let v = surface_violations(&crate_defs(), &["Metric"]);
    assert!(v.is_empty(), "Metric surface breaks R-NF-02:\n{v}");
}

/// R-NF-02 (design section 11.1): operator metrics are labelled with the
/// cell id only.
#[test]
fn r_nf_02_metric_samples_are_labelled_by_cell_id_only() {
    let v = metric_label_violations(&crate_defs());
    assert!(
        v.is_empty(),
        "metric labels break R-NF-02:\n{}",
        v.join("\n")
    );
}

/// R-NF-02 (design section 11.1): paths are logged as route templates, so
/// a request log event carries a route template field.
#[test]
fn r_nf_02_request_log_event_carries_a_route_template() {
    assert!(
        log_event_has_route(&crate_defs()),
        "no LogEvent variant carries a route template (a `route` field of \
         type &'static str or a `*Route*` type of static templates)"
    );
}

/// R-NF-02 (design section 11.1): every path-like field of a log event or
/// metric is a route template, never the concrete request path.
#[test]
fn r_nf_02_path_like_fields_are_static_route_templates() {
    let v = route_violations(&crate_defs());
    assert!(v.is_empty(), "path fields break R-NF-02:\n{}", v.join("\n"));
}

// ------------------------------------------------------------------- teeth

/// Seeded sources that each break the surface rule once.
const BAD_SURFACES: &[(&str, &str)] = &[
    ("String field", "pub enum LogEvent { A { note: String } }"),
    (
        "std String path",
        "pub enum LogEvent { A(std::string::String) }",
    ),
    ("byte vector", "pub enum LogEvent { A { body: Vec<u8> } }"),
    ("boxed str", "pub enum LogEvent { A(Box<str>) }"),
    ("borrowed str", "pub enum LogEvent<'a> { A(&'a str) }"),
    ("non-static str", "pub enum LogEvent { A(&'static [u8]) }"),
    (
        "cow",
        "pub enum LogEvent { A(std::borrow::Cow<'static, str>) }",
    ),
    ("large array", "pub enum LogEvent { A([u8; 4096]) }"),
    (
        "large const array",
        "const N: usize = 64; pub enum LogEvent { A([u8; N]) }",
    ),
    (
        "unknown const array",
        "pub enum LogEvent { A([u8; UNKNOWN]) }",
    ),
    ("float", "pub enum LogEvent { A { ratio: f64 } }"),
    ("char", "pub enum LogEvent { A(char) }"),
    ("generic", "pub enum LogEvent<T> { A(T) }"),
    (
        "nested String",
        "pub struct Wrap(String); pub enum LogEvent { A(Wrap) }",
    ),
    (
        "deep nested String",
        "pub struct In { s: String } pub enum Mid { X(In) } pub enum LogEvent { A(Option<Mid>) }",
    ),
    (
        "alias to String",
        "pub type Label = String; pub enum LogEvent { A(Label) }",
    ),
    (
        "option of String",
        "pub enum LogEvent { A(Option<String>) }",
    ),
    ("tuple with String", "pub enum LogEvent { A((u8, String)) }"),
    (
        "dyn",
        "pub enum LogEvent { A(&'static dyn core::fmt::Debug) }",
    ),
    ("fn pointer", "pub enum LogEvent { A(fn() -> u8) }"),
    (
        "foreign crate type",
        "pub enum LogEvent { A(fstp_json::Value) }",
    ),
    ("unknown type", "pub enum LogEvent { A(Label) }"),
    (
        "arguments",
        "pub enum LogEvent { A(core::fmt::Arguments<'static>) }",
    ),
    ("io error", "pub enum LogEvent { A(std::io::Error) }"),
    ("struct root", "pub struct LogEvent { note: u64 }"),
    ("missing root", "pub enum Other { A }"),
];

/// Teeth for the surface rule: every seeded free-text field is caught.
#[test]
fn r_nf_02_teeth_surface_rule_catches_each_seeded_free_text_field() {
    let missed: Vec<&str> = BAD_SURFACES
        .iter()
        .filter(|(_, src)| {
            surface(&defs_from(src), &["LogEvent"])
                .violations
                .is_empty()
        })
        .map(|(what, _)| *what)
        .collect();
    assert!(missed.is_empty(), "surface rule missed: {missed:?}");
}

/// A seeded source with every allowed field kind of design section 11.1.
const GOOD_SURFACE: &str = r#"
    /// Cell id.
    #[derive(Clone, Copy)]
    pub struct CellId(pub [u8; 16]);
    const DIGEST_LEN: usize = 32;
    pub type RuleRef = &'static str;
    #[derive(Clone, Copy)]
    pub enum Outcome { Ok, Refused }
    pub enum LogEvent {
        Started,
        Request {
            cell: CellId,
            route: &'static str,
            status: u16,
            elapsed: std::time::Duration,
            outcome: Outcome,
        },
        Rule(RuleRef, Option<core::num::NonZeroU32>),
        Digest { d: [u8; DIGEST_LEN], n: u64, ok: bool, t: (u8, i64) },
    }
    pub enum Metric {
        Requests { cell: CellId, count: u64 },
        Latency { cell: CellId, p99: core::time::Duration },
    }
    pub fn encode_metric(m: &Metric) -> u8 { 0 }
"#;

/// Teeth for the surface rule: the allowed field kinds pass, so the rule
/// does not pass the crate merely by refusing nothing.
#[test]
fn r_nf_02_teeth_surface_rule_accepts_the_allowed_field_kinds() {
    let v = surface_violations(&defs_from(GOOD_SURFACE), &["LogEvent", "Metric"]);
    assert!(v.is_empty(), "allowed kinds refused:\n{v}");
}

/// Teeth for the route rule: a path held as an id-free but runtime value is
/// caught. Each seed must produce a route violation.
#[test]
fn r_nf_02_teeth_route_rule_catches_concrete_paths() {
    let seeds = [
        "pub enum LogEvent { Request { path: [u8; 32] } } pub enum Metric { A { cell: [u8; 16] } }",
        "pub enum LogEvent { Request { route: u64 } } pub enum Metric { A { cell: [u8; 16] } }",
        "pub struct Route { raw: [u8; 16] } pub enum LogEvent { Request { route: Route } } pub enum Metric { A { cell: [u8; 16] } }",
        "pub enum LogEvent { Request { target: Option<&'static str> } } pub enum Metric { A { cell: [u8; 16] } }",
    ];
    let missed: Vec<&str> = seeds
        .iter()
        .filter(|s| route_violations(&defs_from(s)).is_empty())
        .copied()
        .collect();
    assert!(missed.is_empty(), "route rule missed: {missed:?}");
}

/// Teeth for the route presence check: a log surface without a route field
/// is reported, and the allowed seed has one.
#[test]
fn r_nf_02_teeth_route_presence_check_has_both_outcomes() {
    let without = defs_from("pub enum LogEvent { Started }");
    let with = defs_from(GOOD_SURFACE);
    assert!(
        !log_event_has_route(&without) && log_event_has_route(&with),
        "presence check does not separate the two seeds"
    );
}

/// Teeth for the metric label rule: each seed labels a metric with
/// something other than the cell id, or with no cell id.
#[test]
fn r_nf_02_teeth_metric_label_rule_catches_other_labels() {
    let seeds = [
        "pub enum Metric { A { count: u64 } } pub fn encode_metric(m: &Metric) {}",
        "pub enum Metric { A { cell: [u8; 16], other_cell: CellId, count: u64 } } pub struct CellId([u8; 16]); pub fn encode_metric(m: &Metric) {}",
        "pub enum Metric { A { cell: [u8; 16], route: &'static str } } pub fn encode_metric(m: &Metric) {}",
        "pub enum Metric { A { cell: [u8; 16], tenant: [u8; 16] } } pub fn encode_metric(m: &Metric) {}",
        "pub enum Kind { R { x: u8 } } pub struct S { cell: [u8; 16], kind: Kind } pub fn encode_metric(m: &S) {}",
        "pub enum Metric { A }",
    ];
    let missed: Vec<&str> = seeds
        .iter()
        .filter(|s| metric_label_violations(&defs_from(s)).is_empty())
        .copied()
        .collect();
    assert!(missed.is_empty(), "metric label rule missed: {missed:?}");
}

/// Teeth for the metric label rule: the allowed seed passes.
#[test]
fn r_nf_02_teeth_metric_label_rule_accepts_cell_only_samples() {
    let v = metric_label_violations(&defs_from(GOOD_SURFACE));
    assert!(v.is_empty(), "cell-only samples refused:\n{}", v.join("\n"));
}

/// Teeth for the scanner: comments, doc text, attributes and string
/// literals do not hide or invent fields.
#[test]
fn r_nf_02_teeth_scanner_ignores_comments_and_literals() {
    let src = r##"
        // pub enum LogEvent { Fake(String) }
        /* pub enum LogEvent { Fake(String) } */
        /// A doc line naming String.
        #[doc = "enum LogEvent { Fake(String) }"]
        pub enum LogEvent {
            /// `String` in a doc comment.
            A { n: u64 },
            #[allow(dead_code)]
            B(String),
        }
        const S: &str = r#"pub enum LogEvent { C(String) }"#;
        const Q: char = '"';
    "##;
    let s = surface(&defs_from(src), &["LogEvent"]);
    let places: Vec<&str> = s.violations.iter().map(|v| v.at.as_str()).collect();
    assert!(places == ["LogEvent::B.0"], "found {places:?}");
}
