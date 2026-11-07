//! The MIME builder and its parser (M6 design section 5.3, lane L6-MAIL).
//!
//! I-26 relies on a message being the same bytes on every attempt, with a
//! `Message-ID` taken from its idempotency key. I-25 relies on the event
//! id and template version travelling in headers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use fstp_mail::encode::{
    base64_decode, base64_encode, decode_unstructured, encode_unstructured, qp_decode, qp_encode,
};
use fstp_mail::{MailError, compose, parse};
use fstp_prop::{check, prop_assert, prop_assert_eq};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// I-26: equal input gives equal bytes, so a retry sends the same message
/// and a receiver can drop a duplicate by its `Message-ID`.
#[test]
fn i_26_mime_output_is_deterministic() {
    let cfg = common::config();
    check("i_26_mime_output_is_deterministic", |g| {
        let m = common::Owned::random(g);
        let a = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let b = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        prop_assert!(a == b, "two compositions differ");
        Ok(())
    });
}

/// I-25, I-26: the output parses back. The headers carry the stable
/// `Message-ID`, the event id and the template version. Each part decodes
/// to the rendered text, the rendered HTML and the attached PDF.
#[test]
fn i_25_i_26_mime_output_parses_back() {
    let cfg = common::config();
    check("i_25_i_26_mime_output_parses_back", |g| {
        let m = common::Owned::random(g);
        let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        let p = parse(&raw).map_err(|e| format!("{e}"))?;
        let header = |n: &str| p.header(n).map(str::to_owned);
        prop_assert_eq!(
            header("Message-ID"),
            Some(format!("<{}@tenant-a.example>", hex(&m.idem)))
        );
        prop_assert_eq!(header("X-FSTP-Event"), Some(hex(&m.event)));
        prop_assert_eq!(
            header("X-FSTP-Template"),
            Some(format!(
                "{}/{}/{}",
                m.template.id().code(),
                m.template.version(),
                m.template.locale().code()
            ))
        );
        prop_assert_eq!(header("To"), Some(format!("<{}>", m.to.as_str())));
        prop_assert_eq!(header("MIME-Version"), Some("1.0".to_owned()));
        prop_assert_eq!(header("Auto-Submitted"), Some("auto-generated".to_owned()));
        let from = header("From").ok_or("no From")?;
        prop_assert_eq!(
            decode_unstructured(&from).map_err(|e| format!("{e}"))?,
            "Synthetic Fund Zürich <noreply@tenant-a.example>"
        );

        let r = m
            .template
            .render(&m.bindings, &cfg.origin)
            .map_err(|e| format!("{e}"))?;
        let subject = header("Subject").ok_or("no Subject")?;
        prop_assert_eq!(
            decode_unstructured(&subject).map_err(|e| format!("{e}"))?,
            r.subject
        );
        let text = p.parts.iter().find(|x| x.content_type == "text/plain");
        let html = p.parts.iter().find(|x| x.content_type == "text/html");
        prop_assert_eq!(
            text.map(|x| x.decoded.clone()),
            Some(r.text.replace('\n', "\r\n").into_bytes())
        );
        prop_assert_eq!(
            html.map(|x| x.decoded.clone()),
            Some(r.html.replace('\n', "\r\n").into_bytes())
        );
        let pdf = p.parts.iter().find(|x| x.content_type == "application/pdf");
        prop_assert_eq!(pdf.map(|x| x.decoded.clone()), m.pdf.clone());
        if let Some(pdf) = pdf {
            prop_assert_eq!(pdf.filename.as_deref(), Some("notice.pdf"));
        }
        prop_assert_eq!(p.parts.len(), 2 + usize::from(m.pdf.is_some()));
        Ok(())
    });
}

/// The message is 7-bit with CRLF line ends. Body lines hold at most 78
/// octets and header lines at most 998 (RFC 5322 section 2.1.1). So the
/// SMTP client never needs 8BITMIME, and dot-stuffing is the only body
/// change in transit.
#[test]
fn mime_output_is_seven_bit_with_short_crlf_lines() {
    let cfg = common::config();
    check("mime_output_is_seven_bit_with_short_crlf_lines", |g| {
        let m = common::Owned::random(g);
        let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        prop_assert!(raw.iter().all(|b| *b < 0x80 && *b != 0), "non 7-bit byte");
        for (i, w) in raw.windows(2).enumerate() {
            prop_assert!(w[1] != b'\n' || w[0] == b'\r', "bare LF at {i}");
            prop_assert!(w[0] != b'\r' || w[1] == b'\n', "bare CR at {i}");
        }
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("no header end")?;
        let (head, body) = raw.split_at(split);
        for line in head.split(|b| *b == b'\n') {
            prop_assert!(line.len() <= 999, "header line over 998 octets");
        }
        for line in body.split(|b| *b == b'\n') {
            prop_assert!(line.len() <= 79, "body line over 78 octets: {line:?}");
        }
        prop_assert!(raw.ends_with(b"\r\n"));
        Ok(())
    });
}

/// A PDF goes only with a template that allows one (P-48).
#[test]
fn attachment_refused_where_template_has_none() {
    let cfg = common::config();
    check("attachment_refused_where_template_has_none", |g| {
        let mut m = common::Owned::random(g);
        g.assume(!m.template.allows_pdf());
        m.pdf = Some(b"%PDF-1.7".to_vec());
        prop_assert!(matches!(
            compose(&cfg, &m.message()),
            Err(MailError::AttachmentNotAllowed)
        ));
        Ok(())
    });
}

/// The encoders round-trip through the in-house decoders.
#[test]
fn encoders_round_trip() {
    check("encoders_round_trip_base64", |g| {
        let b = g.bytes(0..=300);
        prop_assert_eq!(base64_decode(base64_encode(&b).as_bytes()).ok(), Some(b));
        Ok(())
    });
    check("encoders_round_trip_qp", |g| {
        let s = g.string(0..=300).replace('\r', "");
        let enc = qp_encode(&s);
        prop_assert!(enc.lines().all(|l| l.len() <= 76), "QP line too long");
        let dec = qp_decode(enc.as_bytes()).map_err(|e| format!("{e}"))?;
        prop_assert_eq!(dec, s.replace('\n', "\r\n").into_bytes());
        Ok(())
    });
    check("encoders_round_trip_encoded_words", |g| {
        let s: String = g
            .string(0..=120)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let enc = encode_unstructured(&s);
        prop_assert!(enc.is_ascii());
        let unfolded = enc.replace("\r\n", "");
        prop_assert_eq!(
            decode_unstructured(&unfolded).map_err(|e| format!("{e}"))?,
            s
        );
        Ok(())
    });
}

/// The parser refuses malformed input without panicking: bare LF, a
/// missing close delimiter and bad base64.
#[test]
fn parser_refuses_malformed_messages() {
    assert!(parse(b"Subject: x\nTo: y\n\nbody").is_err());
    assert!(
        parse(
            b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n"
        )
        .is_err()
    );
    assert!(
        parse(b"Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%\r\n")
            .is_err()
    );
    assert!(parse(b"").is_err());
}
