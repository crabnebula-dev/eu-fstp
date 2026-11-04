//! The strict decoder of the server-rendered sign-up and agreement forms
//! (TH-26, H-05, TH-46; M4 design sections 3.5 and 9, fuzz target
//! `signup_form_decode`).
//!
//! The wire format these tests fix, for lane W2f:
//!
//! - The body is `application/x-www-form-urlencoded`: `name=value` pairs
//!   joined by `&`. A `+` in a value is a space, and `%XX` is one byte.
//! - The `form` pair selects the form: `signup` or `agreements`. Without
//!   it the decoder refuses with `MissingField("form")`.
//! - Sign-up fields: `form`, `legal_name`, `billing_address`,
//!   `contracting_signatory`. Agreement fields: `form`, `tenant` (32
//!   lower-case hex digits), `saas_terms`, `dpa`, `sub_processors` (each a
//!   canonical decimal from 1 to `u32::MAX`) and `accepted_by`.
//! - Each field appears exactly once, in any order. A name outside the
//!   selected form is unknown, including a name of the other form.
//! - Text values are kept byte for byte. They are not empty, hold at most
//!   [`MAX_FIELD_BYTES`] bytes after decoding, and hold no Unicode `Cc`
//!   control, no `Cf` format character and no U+2028 or U+2029.
//!   `billing_address` alone may hold CR LF line breaks.
//! - A body longer than [`MAX_FORM_BYTES`] is refused before anything
//!   else is read.
//! - An empty pair or a pair without `=` is refused as malformed before
//!   any field name is checked.
//!
//! Every test is red against the W0 stub, which refuses each input with
//! `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_prop::{Gen, check};
use fstp_signup::{
    AgreementFields, FormError, MAX_FIELD_BYTES, MAX_FORM_BYTES, SignupError, SignupFields,
    SignupForm, decode_signup_form,
};
use support::{
    AGREEMENT_FIELDS, AGREEMENT_NUMBER_FIELDS, AGREEMENT_TEXT_FIELDS, SIGNUP_FIELDS,
    SIGNUP_TEXT_FIELDS, T1, V1, agreement_pairs, body, body_encoded, encode_value,
    gen_agreement_fields, gen_signup_fields, signup_pairs, synthetic_agreements, synthetic_signup,
};

/// Which form a generated case uses.
#[derive(Clone, Debug)]
enum Valid {
    Signup(SignupFields),
    Agreements(AgreementFields),
}

impl Valid {
    fn pairs(&self) -> Vec<(String, String)> {
        match self {
            Valid::Signup(f) => signup_pairs(f),
            Valid::Agreements(f) => agreement_pairs(f),
        }
    }

    fn expected(&self) -> SignupForm {
        match self {
            Valid::Signup(f) => SignupForm::Signup(f.clone()),
            Valid::Agreements(f) => SignupForm::Agreements(f.clone()),
        }
    }

    fn fields(&self) -> &'static [&'static str] {
        match self {
            Valid::Signup(_) => &SIGNUP_FIELDS,
            Valid::Agreements(_) => &AGREEMENT_FIELDS,
        }
    }

    fn text_fields(&self) -> &'static [&'static str] {
        match self {
            Valid::Signup(_) => &SIGNUP_TEXT_FIELDS,
            Valid::Agreements(_) => &AGREEMENT_TEXT_FIELDS,
        }
    }
}

fn gen_valid(g: &mut Gen) -> Valid {
    if g.bool() {
        Valid::Signup(gen_signup_fields(g))
    } else {
        Valid::Agreements(gen_agreement_fields(g))
    }
}

/// The pairs of `v` in a generated order.
fn shuffled(g: &mut Gen, v: &Valid) -> Vec<(String, String)> {
    let mut pairs = v.pairs();
    g.shuffle(&mut pairs);
    pairs
}

fn form_error(bytes: &[u8]) -> Result<FormError, String> {
    match decode_signup_form(bytes) {
        Err(SignupError::Form(e)) => Ok(e),
        other => Err(format!(
            "expected a form refusal for {:?}, got {other:?}",
            String::from_utf8_lossy(bytes)
        )),
    }
}

fn expect_form_error(bytes: &[u8], want: FormError) -> Result<(), String> {
    let got = form_error(bytes)?;
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "expected {want:?} for {:?}, got {got:?}",
            String::from_utf8_lossy(bytes)
        ))
    }
}

/// TH-26, H-05, R-TN-01: a valid sign-up or agreement form, with its pairs
/// in any order and its values encoded as a browser encodes them, decodes
/// to exactly its values.
#[test]
fn th26_h05_valid_forms_decode_to_their_values() {
    check("th26_h05_valid_forms_decode_to_their_values", |g| {
        let v = gen_valid(g);
        let bytes = body(&shuffled(g, &v));
        match decode_signup_form(&bytes) {
            Ok(got) if got == v.expected() => Ok(()),
            other => Err(format!("expected {:?}, got {other:?}", v.expected())),
        }
    });
}

/// TH-26, TH-46: a field name outside the selected form is refused as
/// unknown, wherever it appears. Near misses of real names and the names
/// of the other form are unknown too.
#[test]
fn th26_th46_unknown_field_is_refused() {
    const NEAR_MISSES: [&str; 10] = [
        "legal_name2",
        "Legal_name",
        "legal-name",
        "LEGAL_NAME",
        "x",
        "forms",
        "tenant_id",
        "dpa_version",
        "csrf",
        "_method",
    ];
    check("th26_th46_unknown_field_is_refused", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let other: &[&str] = match v {
            Valid::Signup(_) => &AGREEMENT_FIELDS[1..],
            Valid::Agreements(_) => &SIGNUP_FIELDS[1..],
        };
        let name = if g.bool() {
            *g.pick(&NEAR_MISSES)
        } else {
            *g.pick(other)
        };
        let at = g.usize_in(0..=pairs.len());
        pairs.insert(at, (name.to_owned(), "a".to_owned()));
        expect_form_error(&body(&pairs), FormError::UnknownField)
    });
}

/// TH-26: a field that appears twice is refused, whether the second value
/// equals the first or not, and wherever the copy appears.
#[test]
fn th26_duplicate_field_is_refused() {
    check("th26_duplicate_field_is_refused", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let i = g.usize_in(0..=pairs.len() - 1);
        let mut copy = pairs[i].clone();
        if g.bool() && copy.0 != "form" && copy.0 != "tenant" {
            // A different but valid value for the same field.
            copy.1 = if AGREEMENT_NUMBER_FIELDS.contains(&copy.0.as_str()) {
                "7".to_owned()
            } else {
                "other".to_owned()
            };
        }
        let at = g.usize_in(0..=pairs.len());
        pairs.insert(at, copy);
        expect_form_error(&body(&pairs), FormError::DuplicateField)
    });
}

/// TH-26: a `%` that does not start two hex digits is refused.
#[test]
fn th26_bad_percent_encoding_is_refused() {
    const BAD: [&str; 6] = ["%", "%4", "%G1", "%4g", "%%41", "%-1"];
    check("th26_bad_percent_encoding_is_refused", |g| {
        let v = gen_valid(g);
        let pairs = shuffled(g, &v);
        let mut encoded: Vec<(String, String)> = pairs
            .iter()
            .map(|(n, val)| (n.clone(), encode_value(val)))
            .collect();
        let name = *g.pick(v.text_fields());
        let i = encoded.iter().position(|(n, _)| n == name).unwrap();
        // Appended at the end of the value, so no following hex digit can
        // complete the escape.
        encoded[i].1.push_str(g.pick(&BAD));
        expect_form_error(&body_encoded(&encoded), FormError::BadPercentEncoding)
    });
}

/// TH-26: percent-decoded bytes that are not UTF-8 are refused: a lone
/// continuation byte, a truncated sequence, an overlong encoding and an
/// encoded surrogate.
#[test]
fn th26_decoded_value_must_be_utf8() {
    const BAD: [&str; 6] = ["%FF", "%80", "%C3", "%C0%AF", "%ED%A0%80", "%F4%90%80%80"];
    check("th26_decoded_value_must_be_utf8", |g| {
        let v = gen_valid(g);
        let pairs = shuffled(g, &v);
        let mut encoded: Vec<(String, String)> = pairs
            .iter()
            .map(|(n, val)| (n.clone(), encode_value(val)))
            .collect();
        let name = *g.pick(v.text_fields());
        let i = encoded.iter().position(|(n, _)| n == name).unwrap();
        encoded[i].1.push_str(g.pick(&BAD));
        expect_form_error(&body_encoded(&encoded), FormError::NotUtf8)
    });
}

/// TH-26: a missing field is refused and named. Without `form` the
/// decoder cannot select a form, so it names `form`.
#[test]
fn th26_missing_field_is_refused_and_named() {
    check("th26_missing_field_is_refused_and_named", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let i = g.usize_in(0..=pairs.len() - 1);
        let (removed, _) = pairs.remove(i);
        let name = *v.fields().iter().find(|f| removed.as_str() == **f).unwrap();
        expect_form_error(&body(&pairs), FormError::MissingField(name))
    });
}

/// TH-26: an empty pair, a leading or trailing `&`, and a pair without
/// `=` are refused as malformed.
#[test]
fn th26_malformed_pair_is_refused() {
    check("th26_malformed_pair_is_refused", |g| {
        let v = gen_valid(g);
        let pairs = shuffled(g, &v);
        let mut bytes = body(&pairs);
        match g.u8_in(0..=3) {
            0 => bytes.insert(0, b'&'),
            1 => bytes.push(b'&'),
            2 => {
                let at = bytes.iter().position(|b| *b == b'&').unwrap();
                bytes.insert(at, b'&');
            }
            _ => {
                // Replace one pair by its name alone.
                let mut parts: Vec<String> = pairs
                    .iter()
                    .map(|(n, val)| format!("{n}={}", encode_value(val)))
                    .collect();
                let i = g.usize_in(0..=parts.len() - 1);
                parts[i] = pairs[i].0.clone();
                bytes = parts.join("&").into_bytes();
            }
        }
        expect_form_error(&bytes, FormError::Malformed)
    });
}

/// TH-26: a text value one byte over [`MAX_FIELD_BYTES`] after decoding
/// is refused and named, however it is encoded.
#[test]
fn th26_over_long_value_is_refused_and_named() {
    check("th26_over_long_value_is_refused_and_named", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let name = *g.pick(v.text_fields());
        let i = pairs.iter().position(|(n, _)| n == name).unwrap();
        // '~' is always percent-encoded, 'a' never is.
        let unit = if g.bool() { "a" } else { "~" };
        pairs[i].1 = unit.repeat(MAX_FIELD_BYTES + 1);
        expect_form_error(&body(&pairs), FormError::ValueTooLong(name))
    });
}

/// TH-26: a text value of exactly [`MAX_FIELD_BYTES`] bytes is accepted,
/// in one-byte and in two-byte characters.
#[test]
fn th26_value_of_max_field_bytes_is_accepted() {
    let mut f = synthetic_signup();
    f.legal_name = "a".repeat(MAX_FIELD_BYTES);
    let mut name = "\u{e9}".repeat(MAX_FIELD_BYTES / 2);
    name.push_str(&"a".repeat(MAX_FIELD_BYTES % 2));
    f.contracting_signatory = name;
    let got = decode_signup_form(&body(&signup_pairs(&f)));
    assert_eq!(got, Ok(SignupForm::Signup(f)));
}

/// TH-26: every form whose values are valid fits [`MAX_FORM_BYTES`],
/// even when every byte of every text value is percent-encoded. So the
/// body limit never refuses a valid form.
#[test]
fn th26_largest_valid_forms_fit_the_body_limit() {
    let big = "~".repeat(MAX_FIELD_BYTES);
    let signup = SignupFields {
        legal_name: big.clone(),
        billing_address: big.clone(),
        contracting_signatory: big.clone(),
    };
    let s = body(&signup_pairs(&signup));
    assert!(
        s.len() <= MAX_FORM_BYTES,
        "sign-up body of {} bytes",
        s.len()
    );
    assert_eq!(decode_signup_form(&s), Ok(SignupForm::Signup(signup)));

    let mut agreements = synthetic_agreements(T1, V1);
    agreements.versions.saas_terms = u32::MAX;
    agreements.versions.dpa = u32::MAX;
    agreements.versions.sub_processors = u32::MAX;
    agreements.accepted_by = big;
    let a = body(&agreement_pairs(&agreements));
    assert!(
        a.len() <= MAX_FORM_BYTES,
        "agreement body of {} bytes",
        a.len()
    );
    assert_eq!(
        decode_signup_form(&a),
        Ok(SignupForm::Agreements(agreements))
    );
}

/// TH-26: a body of [`MAX_FORM_BYTES`] plus one byte is refused as too
/// long, before any pair is read.
#[test]
fn th26_body_over_max_form_bytes_is_refused() {
    let mut pairs = signup_pairs(&synthetic_signup());
    let without = body(&pairs).len();
    let pad = MAX_FORM_BYTES + 1 - without;
    pairs[1].1.push_str(&"a".repeat(pad));
    let bytes = body(&pairs);
    assert_eq!(bytes.len(), MAX_FORM_BYTES + 1);
    assert_eq!(
        decode_signup_form(&bytes),
        Err(SignupError::Form(FormError::TooLong))
    );
}

/// TH-26, TH-46: a Unicode `Cc` control in a text value is refused and
/// named. CR and LF count as controls outside `billing_address`, and a
/// lone CR or LF counts as one there too.
#[test]
fn th26_th46_control_character_is_refused() {
    const CONTROLS: [char; 8] = [
        '\u{0}', '\t', '\u{b}', '\u{1b}', '\u{7f}', '\u{85}', '\u{9f}', '\n',
    ];
    check("th26_th46_control_character_is_refused", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let name = *g.pick(v.text_fields());
        let i = pairs.iter().position(|(n, _)| n == name).unwrap();
        let mut c = *g.pick(&CONTROLS);
        if name == "billing_address" && c == '\n' {
            // A lone LF, not part of a CR LF pair.
            pairs[i].1 = pairs[i].1.replace("\r\n", " ");
        } else if c == '\n' && g.bool() {
            c = '\r';
        }
        let at = if g.bool() { 0 } else { pairs[i].1.len() };
        pairs[i].1.insert(at, c);
        expect_form_error(&body(&pairs), FormError::BadValue(name))
    });
}

/// TH-26: an empty text value is refused and named.
#[test]
fn th26_empty_text_value_is_refused() {
    check("th26_empty_text_value_is_refused", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let name = *g.pick(v.text_fields());
        let i = pairs.iter().position(|(n, _)| n == name).unwrap();
        pairs[i].1.clear();
        expect_form_error(&body(&pairs), FormError::BadValue(name))
    });
}

/// R-TN-01: `billing_address` keeps CR LF line breaks byte for byte.
#[test]
fn r_tn_01_billing_address_keeps_crlf_line_breaks() {
    let f = synthetic_signup();
    assert!(f.billing_address.contains("\r\n"));
    assert_eq!(
        decode_signup_form(&body(&signup_pairs(&f))),
        Ok(SignupForm::Signup(f))
    );
}

/// TH-26: a `form` value other than `signup` or `agreements` is refused,
/// including an empty value and a different case.
#[test]
fn th26_unknown_form_is_refused() {
    const FORMS: [&str; 6] = ["", "Signup", "SIGNUP", "agreement", "review", "signup "];
    check("th26_unknown_form_is_refused", |g| {
        let v = gen_valid(g);
        let mut pairs = shuffled(g, &v);
        let i = pairs.iter().position(|(n, _)| n == "form").unwrap();
        pairs[i].1 = (*g.pick(&FORMS)).to_owned();
        expect_form_error(&body(&pairs), FormError::UnknownForm)
    });
}

/// TH-26, R-TN-01: agreement versions and the tenant id have one
/// spelling. Leading zeros, signs, spaces, zero, overflow, upper-case or
/// short hex are refused and named.
#[test]
fn th26_r_tn_01_agreement_numbers_and_tenant_are_canonical() {
    const BAD_NUMBERS: [&str; 9] = ["", "0", "01", "+1", "-1", " 1", "1 ", "4294967296", "1.0"];
    check(
        "th26_r_tn_01_agreement_numbers_and_tenant_are_canonical",
        |g| {
            let f = gen_agreement_fields(g);
            let mut pairs = agreement_pairs(&f);
            g.shuffle(&mut pairs);
            let (name, value) = if g.bool() {
                let name = *g.pick(&AGREEMENT_NUMBER_FIELDS);
                (name, (*g.pick(&BAD_NUMBERS)).to_owned())
            } else {
                let hex = support::tenant_hex(f.tenant);
                let bad = match g.u8_in(0..=4) {
                    0 => hex
                        .to_uppercase()
                        .replace(|c: char| c.is_ascii_digit(), "A"),
                    1 => hex[1..].to_owned(),
                    2 => format!("{hex}0"),
                    3 => format!("{}g", &hex[1..]),
                    _ => String::new(),
                };
                ("tenant", bad)
            };
            let i = pairs.iter().position(|(n, _)| n == name).unwrap();
            pairs[i].1 = value;
            expect_form_error(&body(&pairs), FormError::BadValue(name))
        },
    );
}

/// TH-26, H-05: over mutated valid bodies the decoder is total. It never
/// reports `NotImplemented`, and every form it accepts decodes again to
/// itself once re-encoded.
#[test]
fn th26_h05_decoder_is_total_and_accepted_forms_round_trip() {
    check(
        "th26_h05_decoder_is_total_and_accepted_forms_round_trip",
        |g| {
            let v = gen_valid(g);
            let mut bytes = body(&shuffled(g, &v));
            for _ in 0..g.usize_in(0..=4) {
                let at = g.usize_in(0..=bytes.len());
                match g.u8_in(0..=2) {
                    0 => bytes.insert(at, g.u8()),
                    1 if at < bytes.len() => {
                        bytes.remove(at);
                    }
                    _ if at < bytes.len() => bytes[at] = g.u8(),
                    _ => {}
                }
            }
            match decode_signup_form(&bytes) {
                Err(SignupError::Form(_)) => Ok(()),
                Ok(form) => {
                    let again = match &form {
                        SignupForm::Signup(f) => body(&signup_pairs(f)),
                        SignupForm::Agreements(f) => body(&agreement_pairs(f)),
                    };
                    match decode_signup_form(&again) {
                        Ok(f2) if f2 == form => Ok(()),
                        other => Err(format!("{form:?} re-encoded decodes to {other:?}")),
                    }
                }
                Err(other) => Err(format!("not a form refusal: {other:?}")),
            }
        },
    );
}
