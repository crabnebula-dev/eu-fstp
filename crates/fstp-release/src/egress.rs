//! The only code that builds requests to CrabNebula hosts (I-38, design
//! section 10.1).
//!
//! A request is one of two fixed templates. Only the version, the channel
//! and the licence id vary, and each has a closed grammar that cannot hold
//! arbitrary text. So no request can carry tenant data.
//!
//! [`decode_response`] reads the reply of either service and hands its
//! body on. The body's own signature is checked next by the token,
//! transition or metadata decoder, never here.

use crate::ReleaseError;
use crate::licence::LicenceId;
use crate::wire;

/// The host of the update service.
///
/// Reading: design section 10.1 names no host. This is the lane W2j
/// proposal, for Daniel to confirm.
pub const UPDATE_HOST: &str = "updates.fstp.crabnebula.dev";

/// The host of the licence service.
///
/// Reading: design section 10.1 names no host. This is the lane W2j
/// proposal, for Daniel to confirm.
pub const LICENCE_HOST: &str = "licences.fstp.crabnebula.dev";

/// A product version, `major.minor.patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProductVersion(pub u16, pub u16, pub u16);

impl ProductVersion {
    /// `major.minor.patch` in decimal without leading zeros.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(17);
        wire::push_decimal(&mut out, u64::from(self.0));
        out.push('.');
        wire::push_decimal(&mut out, u64::from(self.1));
        out.push('.');
        wire::push_decimal(&mut out, u64::from(self.2));
        out
    }

    /// Reads back exactly what [`ProductVersion::render`] gives: three
    /// decimals without sign or leading zero, each at most 65535.
    #[must_use]
    pub fn parse(text: &[u8]) -> Option<ProductVersion> {
        let mut parts = text.split(|b| *b == b'.');
        let mut next = || -> Option<u16> {
            let n = wire::parse_plain_decimal(parts.next()?, 5)?;
            u16::try_from(n).ok()
        };
        let version = ProductVersion(next()?, next()?, next()?);
        if parts.next().is_some() {
            return None;
        }
        Some(version)
    }
}

/// An update channel. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    /// The stable channel.
    Stable,
}

impl Channel {
    /// Every channel.
    pub const ALL: [Channel; 1] = [Channel::Stable];

    /// The channel's path segment.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
        }
    }

    /// The channel whose path segment is `label`.
    #[must_use]
    pub fn from_label(label: &[u8]) -> Option<Channel> {
        Channel::ALL
            .into_iter()
            .find(|c| c.label().as_bytes() == label)
    }

    /// The channel's byte in signed release metadata.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Channel::Stable => 1,
        }
    }

    /// The channel whose metadata byte is `code`.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Channel> {
        match code {
            1 => Some(Channel::Stable),
            _ => None,
        }
    }
}

/// An update check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateCheck {
    /// The running version.
    pub version: ProductVersion,
    /// The channel.
    pub channel: Channel,
}

/// A licence refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenceRefresh {
    /// The licence.
    pub licence: LicenceId,
    /// The running version.
    pub version: ProductVersion,
}

/// A call to a CrabNebula host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnCall {
    /// `GET /v1/updates/{channel}/{version}`, Host only.
    Update(UpdateCheck),
    /// `POST /v1/licences/{licence}/refresh`, body `{"version":"x.y.z"}`.
    Licence(LicenceRefresh),
}

impl CnCall {
    /// The host the call goes to.
    #[must_use]
    pub const fn host(&self) -> &'static str {
        match self {
            CnCall::Update(_) => UPDATE_HOST,
            CnCall::Licence(_) => LICENCE_HOST,
        }
    }
}

/// The request bytes of a call. Exactly one of the two templates of
/// [`update_request`] and [`refresh_request`].
///
/// # Errors
///
/// None in practice. The `Result` stays so that callers keep one error
/// path for every operation of this crate.
pub fn encode(call: &CnCall) -> Result<Vec<u8>, ReleaseError> {
    Ok(match call {
        CnCall::Update(u) => update_request(u),
        CnCall::Licence(l) => refresh_request(l),
    })
}

/// The update check request: `GET /v1/updates/{channel}/{version}` with
/// the `Host` header only, and no body, cookies or `User-Agent`.
#[must_use]
pub fn update_request(check: &UpdateCheck) -> Vec<u8> {
    let mut out = String::with_capacity(96);
    out.push_str("GET /v1/updates/");
    out.push_str(check.channel.label());
    out.push('/');
    out.push_str(&check.version.render());
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(UPDATE_HOST);
    out.push_str("\r\n\r\n");
    out.into_bytes()
}

/// The licence refresh body: `{"version":"x.y.z"}`, nothing else.
#[must_use]
pub fn refresh_body(version: ProductVersion) -> String {
    let mut out = String::with_capacity(32);
    out.push_str("{\"version\":\"");
    out.push_str(&version.render());
    out.push_str("\"}");
    out
}

/// The licence refresh request: `POST /v1/licences/{licence}/refresh`
/// with `Host`, `Content-Type` and `Content-Length`, in that order, and
/// the body of [`refresh_body`]. The licence id is 32 lowercase hex
/// digits.
///
/// Reading: design section 10.1 names `Content-Type` without a value.
/// The body is JSON, so the request sends `application/json`.
#[must_use]
pub fn refresh_request(refresh: &LicenceRefresh) -> Vec<u8> {
    let body = refresh_body(refresh.version);
    let mut out = String::with_capacity(192);
    out.push_str("POST /v1/licences/");
    out.push_str(&refresh.licence.hex());
    out.push_str("/refresh HTTP/1.1\r\nHost: ");
    out.push_str(LICENCE_HOST);
    out.push_str("\r\nContent-Type: application/json\r\nContent-Length: ");
    wire::push_decimal(&mut out, body.len() as u64);
    out.push_str("\r\n\r\n");
    out.push_str(&body);
    out.into_bytes()
}

/// A decoded response from a CrabNebula host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressResponse {
    /// The HTTP status, 200 to 599. A 204 or 304 always has an empty body.
    pub status: u16,
    /// The body. Its signature is not checked here.
    pub body: Vec<u8>,
}

/// The longest response head [`decode_response`] reads, in bytes.
pub const MAX_HEAD_LEN: usize = 8 * 1024;

/// The longest response body [`decode_response`] accepts, in bytes. A
/// refresh response is a few hundred bytes and signed metadata under
/// 4 KiB.
pub const MAX_BODY_LEN: usize = 64 * 1024;

/// The most header fields a response may have.
pub const MAX_HEADERS: usize = 32;

/// Decodes one response to one request. Fuzzed
/// (`egress_response_decode`).
///
/// The grammar is strict:
///
/// - The status line is `HTTP/1.1 SP 3DIGIT SP reason`, with a status
///   from 200 to 599. An interim 1xx response is refused, since it is
///   never the answer to a request.
/// - Every line ends in CRLF. A bare CR or LF, an obsolete line fold, or a
///   field name outside the token grammar is refused.
/// - No `Transfer-Encoding`, and at most one `Content-Length`, of one
///   plain decimal.
/// - Every status but 204 and 304 needs a `Content-Length`. The body is
///   exactly that many bytes and ends the input.
/// - A 204 or 304 carries no content (RFC 9110 section 6.4.1), and its
///   message ends at the blank line (RFC 9112 section 6.3). So any byte
///   after the head is refused.
/// - A server never sends `Content-Length` in a 204 (RFC 9110 section
///   8.6), so a 204 that carries one is refused. A 304 may carry the
///   length of the 200 body it stands for, or none.
///
/// Reading: one request gets one response, so bytes past the body are
/// refused, not kept for later.
///
/// # Errors
///
/// Returns [`ReleaseError::TooLarge`] past [`MAX_HEAD_LEN`] or
/// [`MAX_BODY_LEN`], and [`ReleaseError::Http`] for every other refusal.
pub fn decode_response(bytes: &[u8]) -> Result<EgressResponse, ReleaseError> {
    let limit = MAX_HEAD_LEN.saturating_add(4).saturating_add(MAX_BODY_LEN);
    if bytes.len() > limit {
        return Err(ReleaseError::TooLarge);
    }
    let head_end = find(bytes, b"\r\n\r\n").ok_or(ReleaseError::Http)?;
    if head_end > MAX_HEAD_LEN {
        return Err(ReleaseError::TooLarge);
    }
    let head = bytes.get(..head_end).ok_or(ReleaseError::Http)?;
    let body = bytes
        .get(head_end.saturating_add(4)..)
        .ok_or(ReleaseError::Http)?;
    let mut lines = crlf_lines(head)?.into_iter();
    let status = status_line(lines.next().ok_or(ReleaseError::Http)?)?;
    let mut content_length: Option<u64> = None;
    let mut fields = 0usize;
    for line in lines {
        fields = fields.saturating_add(1);
        if fields > MAX_HEADERS {
            return Err(ReleaseError::TooLarge);
        }
        let (name, value) = header_field(line)?;
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(ReleaseError::Http);
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(ReleaseError::Http);
            }
            content_length = Some(wire::parse_plain_decimal(value, 19).ok_or(ReleaseError::Http)?);
        }
    }
    let no_content = matches!(status, 204 | 304);
    let length = match content_length {
        // RFC 9110 section 8.6: a server never sends Content-Length in a 204.
        Some(_) if status == 204 => return Err(ReleaseError::Http),
        Some(n) => usize::try_from(n).map_err(|_| ReleaseError::TooLarge)?,
        // RFC 9112 section 6.3: a 204 or 304 ends at the blank line.
        None if no_content => 0,
        None => return Err(ReleaseError::Http),
    };
    if length > MAX_BODY_LEN {
        return Err(ReleaseError::TooLarge);
    }
    // A 304 may give the length of the 200 body it stands for (RFC 9110
    // section 8.6), but it carries no content (RFC 9110 section 6.4.1).
    let expected = if no_content { 0 } else { length };
    if body.len() != expected {
        return Err(ReleaseError::Http);
    }
    Ok(EgressResponse {
        status,
        body: body.to_vec(),
    })
}

/// The index of the first `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The lines of `head`, each of which ended in CRLF. A CR or LF anywhere
/// else is refused.
fn crlf_lines(head: &[u8]) -> Result<Vec<&[u8]>, ReleaseError> {
    let mut out = Vec::new();
    let mut rest = head;
    loop {
        match find(rest, b"\r\n") {
            Some(at) => {
                let (line, tail) = rest.split_at_checked(at).ok_or(ReleaseError::Http)?;
                out.push(line);
                rest = tail.get(2..).ok_or(ReleaseError::Http)?;
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    if out
        .iter()
        .any(|l| l.iter().any(|b| *b == b'\r' || *b == b'\n'))
    {
        return Err(ReleaseError::Http);
    }
    Ok(out)
}

/// The status of `HTTP/1.1 SP 3DIGIT SP reason`, 200 to 599.
fn status_line(line: &[u8]) -> Result<u16, ReleaseError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ".as_slice())
        .ok_or(ReleaseError::Http)?;
    let digits: [u8; 3] = wire::array(rest, 0).ok_or(ReleaseError::Http)?;
    if !matches!(digits[0], b'2'..=b'5') || !digits.iter().all(u8::is_ascii_digit) {
        return Err(ReleaseError::Http);
    }
    let reason = rest
        .get(3..)
        .and_then(|r| r.strip_prefix(b" ".as_slice()))
        .ok_or(ReleaseError::Http)?;
    if !reason.iter().all(|b| field_byte(*b)) {
        return Err(ReleaseError::Http);
    }
    let value = digits.iter().fold(0u16, |n, d| {
        n.saturating_mul(10)
            .saturating_add(u16::from(d.wrapping_sub(b'0')))
    });
    Ok(value)
}

/// Whether `b` may appear in a field value or reason phrase: HTAB, SP,
/// visible ASCII or obs-text (RFC 9110 section 5.5).
const fn field_byte(b: u8) -> bool {
    b == b'\t' || b == b' ' || (b >= 0x21 && b != 0x7f)
}

/// Whether `b` is a token character (RFC 9110 section 5.6.2).
const fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The name and the value, without surrounding whitespace, of one field
/// line.
fn header_field(line: &[u8]) -> Result<(&[u8], &[u8]), ReleaseError> {
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(ReleaseError::Http)?;
    let (name, rest) = line.split_at_checked(colon).ok_or(ReleaseError::Http)?;
    if name.is_empty() || !name.iter().all(|b| tchar(*b)) {
        return Err(ReleaseError::Http);
    }
    let value = rest.get(1..).ok_or(ReleaseError::Http)?;
    if !value.iter().all(|b| field_byte(*b)) {
        return Err(ReleaseError::Http);
    }
    let value = value.trim_ascii();
    Ok((name, value))
}
