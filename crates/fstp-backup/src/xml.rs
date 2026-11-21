//! The XML subset parser for S3 response bodies (ADR-012 "S3 subset",
//! record of lane L10). Fuzzed (`s3_xml_decode`).
//!
//! It reads exactly what the three response shapes need: the multipart
//! create result, the multipart complete result and the error document.
//!
//! - The body is UTF-8, at most [`MAX_BODY`] bytes.
//! - An XML declaration may open the body, at offset 0 only, with
//!   `version="1.0"`, then optionally `encoding="UTF-8"` and
//!   `standalone="yes"` or `"no"`.
//! - One root element. Elements nest at most [`MAX_DEPTH`] deep, at most
//!   [`MAX_ELEMENTS`] in all. Names are ASCII letters, digits, `_`, `-`,
//!   `.` and `:`, at most [`MAX_NAME`] bytes. Attributes are read and
//!   checked, then dropped. A name given twice on one element is refused.
//! - Text takes the five predefined entity references and nothing else.
//!   An element with child elements holds whitespace only.
//! - Refused: a DTD, an entity declaration, a processing instruction, a
//!   comment, CDATA, a numeric character reference, any other entity
//!   reference, a control character other than tab, CR and LF, and any
//!   byte after the root element other than whitespace.
//!
//! A refusal names its rule and never quotes the input (R-NF-02).

use crate::{BackupError, S3Response, XmlElement};

/// The largest response body read, in bytes (record at first use).
pub const MAX_BODY: usize = 16 * 1024;
/// The most elements in one body.
pub const MAX_ELEMENTS: usize = 64;
/// The deepest nesting: the root is depth 1.
pub const MAX_DEPTH: usize = 4;
/// The longest element or attribute name.
pub const MAX_NAME: usize = 64;
/// The longest text of one element or attribute value, after references.
pub const MAX_TEXT: usize = 2048;

fn bad(rule: &'static str) -> BackupError {
    BackupError::Xml(rule)
}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn rest(&self) -> &'a str {
        self.s.get(self.pos..).unwrap_or("")
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.pos = self.pos.saturating_add(lit.len());
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos = self.pos.saturating_add(c.len_utf8());
        Some(c)
    }

    fn skip_space(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
            self.pos = self.pos.saturating_add(1);
        }
        self.pos != start
    }

    fn name(&mut self) -> Result<&'a str, BackupError> {
        let start = self.pos;
        match self.peek() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return Err(bad("name")),
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
        let name = self.s.get(start..self.pos).ok_or(bad("name"))?;
        if name.len() > MAX_NAME {
            return Err(bad("name length"));
        }
        Ok(name)
    }

    /// Refuses what the subset never admits at a `<`.
    fn refuse_markup(&self) -> Result<(), BackupError> {
        let r = self.rest();
        if r.starts_with("<?") {
            return Err(bad("processing instruction"));
        }
        if r.starts_with("<!DOCTYPE") {
            return Err(bad("DTD"));
        }
        if r.starts_with("<!ENTITY") {
            return Err(bad("entity declaration"));
        }
        if r.starts_with("<!--") {
            return Err(bad("comment"));
        }
        if r.starts_with("<![CDATA[") {
            return Err(bad("CDATA"));
        }
        if r.starts_with("<!") {
            return Err(bad("markup declaration"));
        }
        Ok(())
    }
}

fn char_ok(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\r' | '\n')
}

/// Reads one reference after its `&`.
fn reference(c: &mut Cursor<'_>) -> Result<char, BackupError> {
    for (lit, ch) in [
        ("lt;", '<'),
        ("gt;", '>'),
        ("amp;", '&'),
        ("quot;", '"'),
        ("apos;", '\''),
    ] {
        if c.eat(lit) {
            return Ok(ch);
        }
    }
    if c.rest().starts_with('#') {
        return Err(bad("character reference"));
    }
    Err(bad("entity reference"))
}

/// Reads a quoted attribute value and returns it decoded.
fn attr_value(c: &mut Cursor<'_>) -> Result<String, BackupError> {
    let quote = match c.bump() {
        Some(q @ ('"' | '\'')) => q,
        _ => return Err(bad("attribute quote")),
    };
    let mut out = String::new();
    loop {
        let ch = c.bump().ok_or(bad("truncated"))?;
        let ch = match ch {
            x if x == quote => return Ok(out),
            '<' => return Err(bad("attribute value")),
            '&' => reference(c)?,
            x if char_ok(x) => x,
            _ => return Err(bad("control character")),
        };
        if out.len() >= MAX_TEXT {
            return Err(bad("text length"));
        }
        out.push(ch);
    }
}

/// Reads the attributes of a tag up to `>` or `/>`. Returns whether the
/// element is empty (`/>`).
fn attributes(c: &mut Cursor<'_>) -> Result<bool, BackupError> {
    let mut seen: Vec<&str> = Vec::new();
    loop {
        let spaced = c.skip_space();
        if c.eat("/>") {
            return Ok(true);
        }
        if c.eat(">") {
            return Ok(false);
        }
        if !spaced {
            return Err(bad("attribute"));
        }
        let name = c.name()?;
        if seen.contains(&name) {
            return Err(bad("attribute given twice"));
        }
        if seen.len() >= 8 {
            return Err(bad("attribute count"));
        }
        seen.push(name);
        c.skip_space();
        if !c.eat("=") {
            return Err(bad("attribute"));
        }
        c.skip_space();
        attr_value(c)?;
    }
}

/// The XML declaration at offset 0, if any.
fn declaration(c: &mut Cursor<'_>) -> Result<(), BackupError> {
    if !c.eat("<?xml") {
        return Ok(());
    }
    let mut want = ["version", "encoding", "standalone"].into_iter();
    let mut first = true;
    loop {
        let spaced = c.skip_space();
        if c.eat("?>") {
            return if first {
                Err(bad("XML declaration"))
            } else {
                Ok(())
            };
        }
        if !spaced {
            return Err(bad("XML declaration"));
        }
        let name = c.name()?;
        // Pseudo-attributes come in their order, and version first.
        let found = loop {
            match want.next() {
                Some(w) if w == name => break true,
                Some(_) if !first => {}
                _ => break false,
            }
        };
        if !found {
            return Err(bad("XML declaration"));
        }
        c.skip_space();
        if !c.eat("=") {
            return Err(bad("XML declaration"));
        }
        c.skip_space();
        let v = attr_value(c)?;
        let ok = match name {
            "version" => v == "1.0",
            "encoding" => v.eq_ignore_ascii_case("UTF-8"),
            _ => v == "yes" || v == "no",
        };
        if !ok {
            return Err(bad("XML declaration"));
        }
        first = false;
    }
}

/// Decodes a response body (module documentation).
///
/// # Errors
///
/// [`BackupError::Xml`] with the first rule the input breaks.
pub fn decode(bytes: &[u8]) -> Result<S3Response, BackupError> {
    if bytes.len() > MAX_BODY {
        return Err(bad("body length"));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| bad("UTF-8"))?;
    let mut c = Cursor { s, pos: 0 };
    declaration(&mut c)?;
    c.skip_space();
    let mut out: Vec<XmlElement> = Vec::new();
    // The open elements: their index in `out`, their name, and whether
    // they hold a child element.
    let mut open: Vec<(usize, &str, bool)> = Vec::new();
    let mut done = false;
    loop {
        if done {
            c.skip_space();
            if c.rest().is_empty() {
                break;
            }
            if c.rest().starts_with('<') {
                c.refuse_markup()?;
            }
            return Err(bad("content after the root"));
        }
        if c.rest().is_empty() {
            return Err(bad("truncated"));
        }
        if c.rest().starts_with('<') {
            c.refuse_markup()?;
            if c.eat("</") {
                let name = c.name()?;
                c.skip_space();
                if !c.eat(">") {
                    return Err(bad("end tag"));
                }
                let (index, open_name, has_child) = open.pop().ok_or(bad("end tag"))?;
                if open_name != name {
                    return Err(bad("end tag name"));
                }
                if has_child {
                    let e = out.get_mut(index).ok_or(bad("end tag"))?;
                    if !e
                        .text
                        .chars()
                        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
                    {
                        return Err(bad("mixed content"));
                    }
                    e.text.clear();
                }
                done = open.is_empty();
                continue;
            }
            c.pos = c.pos.saturating_add(1);
            let name = c.name()?;
            if out.len() >= MAX_ELEMENTS {
                return Err(bad("element count"));
            }
            if open.len() >= MAX_DEPTH {
                return Err(bad("depth"));
            }
            if let Some(parent) = open.last_mut() {
                parent.2 = true;
            }
            let empty = attributes(&mut c)?;
            let depth = u8::try_from(open.len().saturating_add(1)).map_err(|_| bad("depth"))?;
            out.push(XmlElement {
                depth,
                name: name.to_owned(),
                text: String::new(),
            });
            if empty {
                done = open.is_empty();
            } else {
                open.push((out.len().saturating_sub(1), name, false));
            }
            continue;
        }
        // Text: only inside an element.
        let (index, _, _) = *open.last().ok_or(bad("text outside the root"))?;
        if c.rest().starts_with("]]>") {
            return Err(bad("CDATA end"));
        }
        let ch = c.bump().ok_or(bad("truncated"))?;
        let ch = match ch {
            '&' => reference(&mut c)?,
            x if char_ok(x) => x,
            _ => return Err(bad("control character")),
        };
        let e = out.get_mut(index).ok_or(bad("text"))?;
        if e.text.len() >= MAX_TEXT {
            return Err(bad("text length"));
        }
        e.text.push(ch);
    }
    if out.is_empty() {
        return Err(bad("no root element"));
    }
    Ok(S3Response { elements: out })
}

impl S3Response {
    /// The root element's name.
    #[must_use]
    pub fn root(&self) -> Option<&str> {
        self.elements.first().map(|e| e.name.as_str())
    }

    /// The text of the one child of the root named `name`, if exactly one
    /// exists.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&str> {
        let mut found = self
            .elements
            .iter()
            .filter(|e| e.depth == 2 && e.name == name);
        let first = found.next()?;
        if found.next().is_some() {
            return None;
        }
        Some(first.text.as_str())
    }
}

/// The upload id of a multipart create result.
///
/// # Errors
///
/// [`BackupError::Xml`] for another shape, or an upload id that is empty,
/// longer than 1024 bytes or not printable ASCII.
pub fn create_upload_id(bytes: &[u8]) -> Result<String, BackupError> {
    let r = decode(bytes)?;
    if r.root() != Some("InitiateMultipartUploadResult") {
        return Err(bad("create result shape"));
    }
    let id = r.child("UploadId").ok_or(bad("create result shape"))?;
    if id.is_empty() || id.len() > 1024 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad("upload id"));
    }
    Ok(id.to_owned())
}

/// Checks a multipart complete result. S3 may answer 200 with an error
/// document, so the root name decides.
///
/// # Errors
///
/// [`BackupError::Xml`] for another shape, and [`BackupError::S3Refused`]
/// for an error document.
pub fn complete_result(bytes: &[u8]) -> Result<(), BackupError> {
    let r = decode(bytes)?;
    match r.root() {
        Some("CompleteMultipartUploadResult") => Ok(()),
        Some("Error") => Err(BackupError::S3Refused(code_of(&r))),
        _ => Err(bad("complete result shape")),
    }
}

/// The code of an error document, or [`S3Code::Other`] for any body that
/// is not one.
#[must_use]
pub fn error_code(bytes: &[u8]) -> S3Code {
    match decode(bytes) {
        Ok(r) if r.root() == Some("Error") => code_of(&r),
        _ => S3Code::Other,
    }
}

fn code_of(r: &S3Response) -> S3Code {
    match r.child("Code") {
        Some("NoSuchKey") => S3Code::NoSuchKey,
        Some("NoSuchUpload") => S3Code::NoSuchUpload,
        Some("AccessDenied") => S3Code::AccessDenied,
        Some("SignatureDoesNotMatch") => S3Code::SignatureDoesNotMatch,
        Some("InvalidAccessKeyId") => S3Code::InvalidAccessKeyId,
        Some("RequestTimeTooSkewed") => S3Code::RequestTimeTooSkewed,
        Some("SlowDown") => S3Code::SlowDown,
        Some("InternalError") => S3Code::InternalError,
        _ => S3Code::Other,
    }
}

/// The error codes of the S3 error document that the agent tells apart.
/// Any other code is [`S3Code::Other`], so no server text reaches a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3Code {
    /// The object does not exist.
    NoSuchKey,
    /// The multipart upload does not exist.
    NoSuchUpload,
    /// The credentials may not do this.
    AccessDenied,
    /// The signature does not verify.
    SignatureDoesNotMatch,
    /// The access key id is unknown.
    InvalidAccessKeyId,
    /// The request time is too far from the server's.
    RequestTimeTooSkewed,
    /// The service asks for fewer requests.
    SlowDown,
    /// The service failed.
    InternalError,
    /// Any other code, or no error document.
    Other,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const CREATE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Bucket>b</Bucket><Key>k/base/1/0</Key><UploadId>abc.DEF-1_2~3</UploadId>\
        </InitiateMultipartUploadResult>";

    /// ADR-012 "S3 subset": the three shapes decode.
    #[test]
    fn adr012_xml_reads_the_three_shapes() {
        assert_eq!(
            create_upload_id(CREATE.as_bytes()).unwrap(),
            "abc.DEF-1_2~3"
        );
        let done = "<CompleteMultipartUploadResult><Location>l</Location>\
            <Bucket>b</Bucket><Key>k</Key><ETag>&quot;3858f62230ac3c915f300c664312c11f-2&quot;</ETag>\
            </CompleteMultipartUploadResult>";
        complete_result(done.as_bytes()).unwrap();
        let r = decode(done.as_bytes()).unwrap();
        assert_eq!(
            r.child("ETag").unwrap(),
            "\"3858f62230ac3c915f300c664312c11f-2\""
        );
        let err = "<?xml version='1.0'?><Error><Code>NoSuchKey</Code>\
            <Message>The resource you requested does not exist</Message>\
            <Resource>/b/k</Resource><RequestId>4442587FB7D0A2F9</RequestId></Error>";
        assert_eq!(error_code(err.as_bytes()), S3Code::NoSuchKey);
        assert_eq!(
            complete_result(err.as_bytes()).unwrap_err(),
            BackupError::S3Refused(S3Code::NoSuchKey)
        );
        assert_eq!(error_code(b"not xml"), S3Code::Other);
    }

    /// ADR-012 "S3 subset", TH-26: a DTD, an entity declaration, a
    /// processing instruction, a comment, CDATA and any reference beyond
    /// the five predefined ones are refused, wherever they sit.
    #[test]
    fn adr012_xml_refuses_hostile_input() {
        let hostile = [
            "<!DOCTYPE r [<!ENTITY x \"y\">]><r>&x;</r>",
            "<?xml version=\"1.0\"?><!DOCTYPE r SYSTEM \"file:///etc/passwd\"><r/>",
            "<r><!ENTITY x \"y\"></r>",
            "<r><?php x ?></r>",
            "<?xml-stylesheet href=\"x\"?><r/>",
            " <?xml version=\"1.0\"?><r/>",
            "<r/><?pi?>",
            "<r><!-- c --></r>",
            "<r><![CDATA[x]]></r>",
            "<r>&#60;</r>",
            "<r>&#x3c;</r>",
            "<r>&xxe;</r>",
            "<r a=\"&#34;\"/>",
            "<r>x]]>y</r>",
            "<r>\u{0}</r>",
            "<r>\u{1b}</r>",
            "<r>a<b/>c</r>",
            "<r/><s/>",
            "<r/>x",
            "<r></s>",
            "<r>",
            "",
            "text",
            "<r a='1' a='2'/>",
            "<r a=1/>",
            "<1r/>",
            "<?xml version=\"1.1\"?><r/>",
            "<?xml encoding=\"UTF-8\"?><r/>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><r/>",
            "<?xml version=\"1.0\" standalone=\"maybe\"?><r/>",
            "<?xml version=\"1.0\" foo=\"x\"?><r/>",
            "<a><b><c><d><e/></d></c></b></a>",
        ];
        for h in hostile {
            assert!(decode(h.as_bytes()).is_err(), "{h:?}");
        }
        assert!(decode(&[0xff, 0xfe, b'<', b'r', b'/', b'>']).is_err());
        let wide = format!("<r>{}</r>", "<a/>".repeat(MAX_ELEMENTS));
        assert_eq!(decode(wide.as_bytes()).unwrap_err(), bad("element count"));
        let long = format!("<r>{}</r>", "x".repeat(MAX_TEXT + 1));
        assert_eq!(decode(long.as_bytes()).unwrap_err(), bad("text length"));
        let big = vec![b' '; MAX_BODY + 1];
        assert_eq!(decode(&big).unwrap_err(), bad("body length"));
    }

    /// ADR-012: the five predefined references decode, and whitespace
    /// around the root and between children is admitted.
    #[test]
    fn adr012_xml_takes_the_five_references() {
        let r =
            decode(b"\n<r a=\"&lt;&amp;\">\n  <t>&lt;&gt;&amp;&quot;&apos;</t>\n</r>\n").unwrap();
        assert_eq!(r.root(), Some("r"));
        assert_eq!(r.child("t"), Some("<>&\"'"));
        assert_eq!(r.elements[0].text, "");
        let d =
            decode(b"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?><r/>").unwrap();
        assert_eq!(d.root(), Some("r"));
    }

    /// R-NF-02: a refusal never quotes the input.
    #[test]
    fn r_nf_02_xml_refusal_never_quotes_input() {
        let secret = "<r>&canary-4f1c9;</r>";
        let e = decode(secret.as_bytes()).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("canary"));
    }
}
