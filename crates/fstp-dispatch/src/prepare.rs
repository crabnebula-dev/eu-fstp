//! S2 of the attempt protocol: what a stored message becomes before it is
//! staged (M6 design sections 3.1, 5.1 and 5.3, I-25).
//!
//! The timeline stores each message as the bytes `fstp_mail::compose`
//! built. [`prepare`] reads back what the dispatcher needs from them: the
//! recipient for the envelope, the event id of `X-FSTP-Event` and the
//! template version of `X-FSTP-Template`. The body is sent byte for byte,
//! so its digest on the COMMITTING row is the digest of what the server
//! receives.
//!
//! The header values are parsed strictly. The fuzz target
//! `dispatch_prepare` in `fuzz/` covers this module (TH-26).

use std::fmt;

/// The SMTP envelope of one message: one sender, one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Envelope {
    /// The reverse path.
    pub from: String,
    /// The forward path.
    pub to: String,
}

/// A message ready to stage.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Prepared {
    /// The envelope.
    pub envelope: Envelope,
    /// The message as it is sent.
    pub body: Vec<u8>,
    /// The timeline event id.
    pub event: [u8; 32],
    /// The template version.
    pub template_version: u16,
}

impl fmt::Debug for Prepared {
    /// The body is content, so only its length shows (R-NF-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("event", &self.event)
            .field("template_version", &self.template_version)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Why a stored message cannot be sent. Each is permanent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrepareError {
    /// The message does not parse.
    Malformed,
    /// The field is missing or not in its form.
    Field(&'static str),
}

impl fmt::Display for PrepareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrepareError::Malformed => f.write_str("the stored message does not parse"),
            PrepareError::Field(name) => write!(f, "the stored message lacks a valid {name}"),
        }
    }
}

impl std::error::Error for PrepareError {}

/// Reads the envelope, event and template version of the composed message
/// `raw`, sent from `sender`.
///
/// # Errors
///
/// [`PrepareError`] when `raw` does not parse or a field is missing or
/// not in the form `fstp_mail::compose` writes.
pub fn prepare(raw: &[u8], sender: &str) -> Result<Prepared, PrepareError> {
    let parsed = fstp_mail::parse(raw).map_err(|_| PrepareError::Malformed)?;
    let to = parsed
        .header("To")
        .and_then(angle_addr)
        .ok_or(PrepareError::Field("To"))?;
    let to = fstp_mail::Mailbox::new(to).map_err(|_| PrepareError::Field("To"))?;
    let from = fstp_mail::Mailbox::new(sender).map_err(|_| PrepareError::Field("sender"))?;
    let event = parsed
        .header("X-FSTP-Event")
        .and_then(hex32)
        .ok_or(PrepareError::Field("X-FSTP-Event"))?;
    let template_version = parsed
        .header("X-FSTP-Template")
        .and_then(template_version)
        .ok_or(PrepareError::Field("X-FSTP-Template"))?;
    Ok(Prepared {
        envelope: Envelope {
            from: from.as_str().to_owned(),
            to: to.as_str().to_owned(),
        },
        body: raw.to_vec(),
        event,
        template_version,
    })
}

/// The address of `<addr>`, the only form `compose` writes in `To`.
fn angle_addr(v: &str) -> Option<&str> {
    let inner = v.trim().strip_prefix('<')?.strip_suffix('>')?;
    (!inner.contains(['<', '>'])).then_some(inner)
}

/// Exactly 64 lowercase hex digits.
fn hex32(v: &str) -> Option<[u8; 32]> {
    let b = v.trim().as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let [hi, lo] = pair else { return None };
        *o = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// The version of `code/version/locale`: a decimal from 1 to 65535 with
/// no leading zero, between two non-empty fields.
fn template_version(v: &str) -> Option<u16> {
    let mut parts = v.trim().split('/');
    let (Some(code), Some(version), Some(locale), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if code.is_empty()
        || locale.is_empty()
        || version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    version.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(to: &str, event: &str, template: &str) -> Vec<u8> {
        format!(
            "Date: Fri, 06 Nov 2026 14:00:00 +0000\r\nFrom: <noreply@fund.test>\r\n\
             To: {to}\r\nSubject: s\r\nMessage-ID: <ab@fund.test>\r\nMIME-Version: 1.0\r\n\
             X-FSTP-Event: {event}\r\nX-FSTP-Template: {template}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n"
        )
        .into_bytes()
    }

    /// I-25, M6 design section 5.3: the event and template version on the
    /// COMMITTING row are the ones the composed message carries.
    #[test]
    fn i25_prepare_reads_event_and_template_version() {
        let ev = "0a".repeat(32);
        let m = raw("<lead@example.test>", &ev, "proposal-outcome/3/en");
        let p = prepare(&m, "noreply@fund.test").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.event, [0x0a; 32]);
        assert_eq!(p.template_version, 3);
        assert_eq!(p.envelope.to, "lead@example.test");
        assert_eq!(p.envelope.from, "noreply@fund.test");
        assert_eq!(p.body, m);
    }

    /// TH-26: a field outside its form refuses the message.
    #[test]
    fn th26_prepare_refuses_fields_outside_their_form() {
        let ev = "0a".repeat(32);
        for (to, event, template) in [
            ("lead@example.test", ev.as_str(), "x/1/en"),
            ("<lead@example.test>", "0A", "x/1/en"),
            ("<lead@example.test>", ev.as_str(), "x/01/en"),
            ("<lead@example.test>", ev.as_str(), "x/1"),
            ("<lead@example.test>", ev.as_str(), "x/70000/en"),
            ("<a<b@example.test>", ev.as_str(), "x/1/en"),
        ] {
            assert!(
                prepare(&raw(to, event, template), "noreply@fund.test").is_err(),
                "{to} {event} {template}"
            );
        }
        assert_eq!(
            prepare(b"\xff", "noreply@fund.test"),
            Err(PrepareError::Malformed)
        );
    }
}
