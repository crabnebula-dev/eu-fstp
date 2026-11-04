//! Review reproducers for the text value rules of the sign-up form
//! (TH-46, TH-26; M4 design sections 3.5 and 9).
//!
//! `check_text` claims that a legal name cannot render as another
//! organisation's name, and that only `billing_address` holds line
//! breaks. These tests show inputs that break both claims.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_signup::{FormError, SignupError, decode_signup_form};

fn with_legal_name(encoded: &str) -> Vec<u8> {
    format!(
        "form=signup&legal_name={encoded}&billing_address=1+Synthetic+Street\
         &contracting_signatory=Synthetic+Signatory"
    )
    .into_bytes()
}

fn refused_as_bad_legal_name(encoded: &str) -> bool {
    decode_signup_form(&with_legal_name(encoded))
        == Err(SignupError::Form(FormError::BadValue("legal_name")))
}

/// TH-46: an invisible format character (Unicode `Cf`) makes a legal
/// name render exactly as another one. Zero width space, zero width
/// non-joiner, word joiner, soft hyphen and a byte order mark are shown.
#[test]
fn review_th46_invisible_format_char_in_legal_name_is_refused() {
    let accepted: Vec<&str> = [
        "Synthetic%E2%80%8BOrg",
        "Synthetic%E2%80%8COrg",
        "Synthetic%E2%81%A0Org",
        "Synthetic%C2%ADOrg",
        "%EF%BB%BFSynthetic+Org",
    ]
    .into_iter()
    .filter(|v| !refused_as_bad_legal_name(v))
    .collect();
    assert!(
        accepted.is_empty(),
        "invisible characters accepted in legal_name: {accepted:?}"
    );
}

/// TH-26: only `billing_address` may hold a line break. U+2028 LINE
/// SEPARATOR and U+2029 PARAGRAPH SEPARATOR inside a legal name are
/// line breaks too.
#[test]
fn review_th26_unicode_line_separator_in_legal_name_is_refused() {
    let accepted: Vec<&str> = ["Synthetic%E2%80%A8Org", "Synthetic%E2%80%A9Org"]
        .into_iter()
        .filter(|v| !refused_as_bad_legal_name(v))
        .collect();
    assert!(
        accepted.is_empty(),
        "line separators accepted in legal_name: {accepted:?}"
    );
}
