//! Locations inside a JSON value, rendered in a JSONPath-like form.
//!
//! A path starts at the root `$`. Member names that look like identifiers
//! render as `.name`. Other member names render as `["name"]` with JSON string
//! escaping. Array indices render as `[2]`. An example is `$.calls[2].deadline`.
//!
//! Member names come from two sources. A [`Segment::Field`] name comes from a
//! schema, such as a struct mapping, and is never input content. A
//! [`Segment::Key`] name comes from the input itself, such as a map key or an
//! unknown member. [`Path::redacted`] masks the second kind as `[*]`, so the
//! rendered path is safe for logs (R-NF-02).

use core::fmt;

/// One step in a [`Path`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Segment {
    /// A member name defined by a schema, such as a struct field.
    Field(&'static str),
    /// A member name taken from the input, such as a map key.
    Key(String),
    /// An array index, starting at 0.
    Index(usize),
}

/// A location inside a JSON value, from the root down.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Path {
    segments: Vec<Segment>,
}

impl Path {
    /// The root path `$`.
    pub fn root() -> Path {
        Path::default()
    }

    /// Builds a path from segments ordered from the root down.
    pub fn from_segments(segments: Vec<Segment>) -> Path {
        Path { segments }
    }

    /// The segments, ordered from the root down.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Returns true for the root path `$`.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Appends a segment at the leaf end.
    pub fn push(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    /// Renders the path with every member name, including names taken from
    /// the input. The output may contain input content.
    pub fn full(&self) -> String {
        self.render(false)
    }

    /// Renders the path with input-derived member names masked as `[*]`.
    ///
    /// Schema field names and indices stay visible. The output never contains
    /// input content (R-NF-02).
    pub fn redacted(&self) -> String {
        self.render(true)
    }

    fn render(&self, redact: bool) -> String {
        let mut out = String::from("$");
        for segment in &self.segments {
            match segment {
                Segment::Field(name) => push_name(&mut out, name),
                Segment::Key(name) if redact => out.push_str("[*]"),
                Segment::Key(name) => push_name(&mut out, name),
                Segment::Index(i) => {
                    out.push('[');
                    out.push_str(&i.to_string());
                    out.push(']');
                }
            }
        }
        out
    }
}

/// Renders the full path, including input-derived member names.
impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full())
    }
}

fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn push_name(out: &mut String, name: &str) {
    if is_identifier(name) {
        out.push('.');
        out.push_str(name);
    } else {
        out.push('[');
        crate::ser::write_string(out, name, false);
        out.push(']');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_fields_indices_and_quoted_keys() {
        let path = Path::from_segments(vec![
            Segment::Field("calls"),
            Segment::Index(2),
            Segment::Field("deadline"),
        ]);
        assert_eq!(path.full(), "$.calls[2].deadline");
        assert_eq!(path.redacted(), "$.calls[2].deadline");

        let path = Path::from_segments(vec![
            Segment::Key("a b".to_owned()),
            Segment::Key("9x".to_owned()),
            Segment::Key("q\"".to_owned()),
        ]);
        assert_eq!(path.full(), "$[\"a b\"][\"9x\"][\"q\\\"\"]");
        assert_eq!(path.redacted(), "$[*][*][*]");
        assert_eq!(Path::root().full(), "$");
    }
}
