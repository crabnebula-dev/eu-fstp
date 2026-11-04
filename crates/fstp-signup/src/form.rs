//! The strict decoder of the server-rendered forms (TH-26, H-05, TH-46).
//!
//! The wire format:
//!
//! - The body is `application/x-www-form-urlencoded`: `name=value` pairs
//!   joined by `&`. A `+` is a space and `%XX` is one byte, with upper or
//!   lower case hex digits. ASCII letters, digits and `*-._~` may appear
//!   raw. Every other byte must be percent-encoded.
//! - The `form` pair selects the form: `signup` or `agreements`.
//! - Each field of the selected form appears exactly once, in any order.
//!   Any other name is unknown, including a name of the other form.
//! - Text values are kept byte for byte. The rules of `check_text` apply,
//!   and only `billing_address` may hold CR LF line breaks.
//! - Versions are canonical decimals from 1 to `u32::MAX`. The tenant is
//!   32 lower-case hex digits.
//!
//! The decoder refuses in a fixed order: body size, then pair syntax and
//! decoding, then the form, then names, then missing fields, then values.
//! It never panics (fuzz target `signup_form_decode`).

use crate::error::{FormError, SignupError};
use crate::text::{TextFault, check_text, id_hex, parse_id_hex, parse_version};
use crate::types::{AgreementFields, AgreementVersions, SignupFields, SignupForm, TenantId};

/// The largest form body the decoder reads, in bytes.
///
/// The largest valid sign-up form encodes three values of
/// [`crate::MAX_FIELD_BYTES`] bytes with every byte as `%XX`, about 4.7
/// KiB. This limit leaves room for that and refuses anything larger.
pub const MAX_FORM_BYTES: usize = 8 * 1024;

pub(crate) const FORM: &str = "form";
pub(crate) const SIGNUP: &str = "signup";
pub(crate) const AGREEMENTS: &str = "agreements";

pub(crate) const LEGAL_NAME: &str = "legal_name";
pub(crate) const BILLING_ADDRESS: &str = "billing_address";
pub(crate) const CONTRACTING_SIGNATORY: &str = "contracting_signatory";
const SIGNUP_FIELDS: [&str; 3] = [LEGAL_NAME, BILLING_ADDRESS, CONTRACTING_SIGNATORY];

pub(crate) const TENANT: &str = "tenant";
const SAAS_TERMS: &str = "saas_terms";
const DPA: &str = "dpa";
const SUB_PROCESSORS: &str = "sub_processors";
pub(crate) const ACCEPTED_BY: &str = "accepted_by";
const AGREEMENT_FIELDS: [&str; 5] = [TENANT, SAAS_TERMS, DPA, SUB_PROCESSORS, ACCEPTED_BY];

/// Decodes a submitted sign-up or agreement form. Duplicate fields,
/// unknown fields, bad percent-encoding and over-long values are refused.
/// Fuzzed (`signup_form_decode`).
pub fn decode_signup_form(bytes: &[u8]) -> Result<SignupForm, SignupError> {
    decode(bytes).map_err(SignupError::Form)
}

/// Encodes a form as a browser submits it, in rendering order. ASCII
/// letters, digits and `*-._` stay, a space becomes `+`, and every other
/// byte becomes `%XX`. A valid form decodes back to itself.
pub fn encode_signup_form(form: &SignupForm) -> Vec<u8> {
    let pairs: Vec<(&str, String)> = match form {
        SignupForm::Signup(f) => vec![
            (FORM, SIGNUP.to_owned()),
            (LEGAL_NAME, f.legal_name.clone()),
            (BILLING_ADDRESS, f.billing_address.clone()),
            (CONTRACTING_SIGNATORY, f.contracting_signatory.clone()),
        ],
        SignupForm::Agreements(f) => vec![
            (FORM, AGREEMENTS.to_owned()),
            (TENANT, id_hex(f.tenant.raw())),
            (SAAS_TERMS, f.versions.saas_terms.to_string()),
            (DPA, f.versions.dpa.to_string()),
            (SUB_PROCESSORS, f.versions.sub_processors.to_string()),
            (ACCEPTED_BY, f.accepted_by.clone()),
        ],
    };
    let mut out = Vec::new();
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i != 0 {
            out.push(b'&');
        }
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        encode_value(value, &mut out);
    }
    out
}

fn encode_value(value: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => out.push(b),
            b' ' => out.push(b'+'),
            _ => {
                out.push(b'%');
                out.push(
                    HEX.get(usize::from(b.wrapping_shr(4)))
                        .copied()
                        .unwrap_or(b'0'),
                );
                out.push(HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'));
            }
        }
    }
}

/// One decoded pair.
struct Pair {
    name: String,
    value: String,
}

fn decode(bytes: &[u8]) -> Result<SignupForm, FormError> {
    if bytes.len() > MAX_FORM_BYTES {
        return Err(FormError::TooLong);
    }
    let pairs = split_pairs(bytes)?;

    let mut forms = pairs.iter().filter(|p| p.name == FORM);
    let selected = forms.next().ok_or(FormError::MissingField(FORM))?;
    if forms.next().is_some() {
        return Err(FormError::DuplicateField);
    }
    let fields: &[&'static str] = match selected.value.as_str() {
        SIGNUP => &SIGNUP_FIELDS,
        AGREEMENTS => &AGREEMENT_FIELDS,
        _ => return Err(FormError::UnknownForm),
    };

    // Each slot holds the value of the field at the same position.
    let mut slots: Vec<Option<&str>> = vec![None; fields.len()];
    for p in pairs.iter().filter(|p| p.name != FORM) {
        let at = fields
            .iter()
            .position(|f| *f == p.name)
            .ok_or(FormError::UnknownField)?;
        let slot = slots.get_mut(at).ok_or(FormError::UnknownField)?;
        if slot.is_some() {
            return Err(FormError::DuplicateField);
        }
        *slot = Some(p.value.as_str());
    }
    let mut values = Vec::with_capacity(fields.len());
    for (name, slot) in fields.iter().zip(slots) {
        values.push(slot.ok_or(FormError::MissingField(name))?);
    }

    match (selected.value.as_str(), values.as_slice()) {
        (SIGNUP, [legal, billing, signatory]) => Ok(SignupForm::Signup(SignupFields {
            legal_name: text(LEGAL_NAME, legal, false)?,
            billing_address: text(BILLING_ADDRESS, billing, true)?,
            contracting_signatory: text(CONTRACTING_SIGNATORY, signatory, false)?,
        })),
        (AGREEMENTS, [tenant, saas, dpa, sub, by]) => Ok(SignupForm::Agreements(AgreementFields {
            tenant: TenantId::from_raw(parse_id_hex(tenant).ok_or(FormError::BadValue(TENANT))?),
            versions: AgreementVersions {
                saas_terms: parse_version(saas).ok_or(FormError::BadValue(SAAS_TERMS))?,
                dpa: parse_version(dpa).ok_or(FormError::BadValue(DPA))?,
                sub_processors: parse_version(sub).ok_or(FormError::BadValue(SUB_PROCESSORS))?,
            },
            accepted_by: text(ACCEPTED_BY, by, false)?,
        })),
        // The field tables above fix the arity, so this arm is never taken.
        _ => Err(FormError::Malformed),
    }
}

/// Checks a text value of field `name` and returns it.
fn text(name: &'static str, value: &str, line_breaks: bool) -> Result<String, FormError> {
    match check_text(value, line_breaks) {
        Ok(()) => Ok(value.to_owned()),
        Err(TextFault::TooLong) => Err(FormError::ValueTooLong(name)),
        Err(TextFault::Bad) => Err(FormError::BadValue(name)),
    }
}

/// Splits the body into decoded pairs. Every pair is checked for syntax
/// and decoded before any name is looked at.
fn split_pairs(bytes: &[u8]) -> Result<Vec<Pair>, FormError> {
    let mut pairs = Vec::new();
    for part in bytes.split(|b| *b == b'&') {
        let eq = part
            .iter()
            .position(|b| *b == b'=')
            .ok_or(FormError::Malformed)?;
        let (name, rest) = part.split_at(eq);
        let value = rest.get(1..).unwrap_or_default();
        if name.is_empty() || value.contains(&b'=') {
            return Err(FormError::Malformed);
        }
        pairs.push(Pair {
            name: unescape(name)?,
            value: unescape(value)?,
        });
    }
    Ok(pairs)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|d| d.checked_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').and_then(|d| d.checked_add(10)),
        _ => None,
    }
}

/// Decodes one percent-encoded name or value into UTF-8.
fn unescape(raw: &[u8]) -> Result<String, FormError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter().copied();
    while let Some(b) = it.next() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b);
            }
            b'+' => out.push(b' '),
            b'%' => {
                let hi = it.next().and_then(hex_digit);
                let lo = it.next().and_then(hex_digit);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push(hi.wrapping_shl(4) | lo),
                    _ => return Err(FormError::BadPercentEncoding),
                }
            }
            _ => return Err(FormError::BadPercentEncoding),
        }
    }
    String::from_utf8(out).map_err(|_| FormError::NotUtf8)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SIGNUP_BODY: &str = "form=signup&legal_name=Synthetic+Org&billing_address=1+Street\
                               &contracting_signatory=Synthetic+Signatory";

    fn with_legal_name(encoded: &str) -> Vec<u8> {
        SIGNUP_BODY
            .replace("legal_name=Synthetic+Org", &format!("legal_name={encoded}"))
            .into_bytes()
    }

    /// TH-46 (interim strict reading): a bidirectional formatting
    /// character in a legal name is refused, so the name cannot render as
    /// another organisation's.
    #[test]
    fn th46_bidi_control_in_legal_name_is_refused() {
        for c in ["%E2%80%AE", "%E2%81%A6", "%D8%9C", "%E2%80%8F"] {
            let body = with_legal_name(&format!("Synthetic{c}Org"));
            assert_eq!(
                decode_signup_form(&body),
                Err(SignupError::Form(FormError::BadValue(LEGAL_NAME)))
            );
        }
    }

    /// TH-46, TH-26 (interim strict reading): whitespace at either end of
    /// a text value is refused, so two names differ visibly.
    #[test]
    fn th46_edge_whitespace_in_text_value_is_refused() {
        for v in [
            "+Synthetic",
            "Synthetic+",
            "%C2%A0Synthetic",
            "Synthetic%E2%80%A8",
        ] {
            assert_eq!(
                decode_signup_form(&with_legal_name(v)),
                Err(SignupError::Form(FormError::BadValue(LEGAL_NAME)))
            );
        }
    }

    /// TH-26: a byte a form body must percent-encode is refused raw.
    #[test]
    fn th26_raw_byte_that_needs_encoding_is_refused() {
        for v in ["Synthetic Org", "Synthetic\"Org", "Synth\u{e9}tic", "a;b"] {
            assert_eq!(
                decode_signup_form(&with_legal_name(v)),
                Err(SignupError::Form(FormError::BadPercentEncoding))
            );
        }
    }

    /// TH-26: lower-case hex digits in an escape and a raw `~` decode.
    #[test]
    fn th26_lower_case_escape_and_raw_tilde_decode() {
        let Ok(SignupForm::Signup(f)) = decode_signup_form(&with_legal_name("Synth%c3%a9tic~Org"))
        else {
            panic!("the form did not decode");
        };
        assert_eq!(f.legal_name, "Synth\u{e9}tic~Org");
    }

    /// TH-26, H-05: the encoder writes what the decoder reads back.
    #[test]
    fn th26_encoded_form_decodes_to_itself() {
        let form = decode_signup_form(SIGNUP_BODY.as_bytes()).unwrap();
        let again = encode_signup_form(&form);
        assert_eq!(again, SIGNUP_BODY.as_bytes());
        assert_eq!(decode_signup_form(&again), Ok(form));
    }
}
