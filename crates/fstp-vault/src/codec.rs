//! The codecs of the vault service (design sections 4.3 and 6.5, ADR-009
//! "Vault origin").
//!
//! - An origin write is canonical JSON `{"body":<object>,"ticket":"<hex>"}`.
//!   The ticket is the signed ticket in lowercase hex, as the loader script
//!   reads it from the URL fragment. The body is the canonical fact body of
//!   the write. [`decode_origin_write`] only frames the request. It reads
//!   no ticket claim and does not interpret the body, since the signature
//!   is checked before any other field is used.
//! - A stored fact body (`vault.fact.body` before sealing) is canonical
//!   JSON `{"fields":<object>,"kind":<code>}`, with lane W1c's kind codes.

use fstp_json::Value;
use fstp_vault_core::{Fact, decode_fact, fact::fact_from_value};
use fstp_vault_proto::json::{self, parse_canonical};
use fstp_vault_proto::{MAX_TICKET_LEN, ProtoError};

use crate::VaultError;

/// The largest origin write request, in bytes: the largest body limit of
/// any write kind, plus the ticket in hex and the frame.
pub const MAX_ORIGIN_WRITE_LEN: usize = (64 << 10) + 2 * MAX_TICKET_LEN + 64;

/// A write that arrives on the vault origin (design section 6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginWrite {
    /// The ticket bytes.
    pub ticket: Vec<u8>,
    /// The body bytes: the canonical fact body.
    pub body: Vec<u8>,
}

/// A stored fact body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactBody {
    /// The fact kind.
    pub kind: u16,
    /// The canonical fields.
    pub fields: Vec<u8>,
}

const ORIGIN: &str = "origin write";
const STORED: &str = "stored fact body";

fn limits() -> fstp_json::ParseLimits {
    fstp_vault_proto::json::limits().with_max_input_bytes(MAX_ORIGIN_WRITE_LEN)
}

fn malformed(_: ProtoError) -> VaultError {
    VaultError::Malformed(ORIGIN)
}

/// Decodes an origin write. Fuzzed (`origin_write_decode`). It frames the
/// request only: the ticket signature is checked before any field of the
/// ticket or the body is used.
///
/// # Errors
///
/// [`VaultError::Malformed`] for any spelling other than the canonical
/// frame, an empty or odd ticket, or a body that is not an object.
pub fn decode_origin_write(bytes: &[u8]) -> Result<OriginWrite, VaultError> {
    let v = parse_canonical(bytes, &limits()).map_err(malformed)?;
    let o = json::object(&v, &["body", "ticket"], ORIGIN).map_err(malformed)?;
    let body = json::member(o, "body", ORIGIN).map_err(malformed)?;
    if body.as_object().is_none() {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let ticket = json::unhex(
        json::string(o, "ticket", ORIGIN).map_err(malformed)?,
        ORIGIN,
    )
    .map_err(malformed)?;
    if ticket.is_empty() || ticket.len() > MAX_TICKET_LEN {
        return Err(VaultError::Malformed(ORIGIN));
    }
    Ok(OriginWrite {
        ticket,
        body: json::to_canonical(body).map_err(malformed)?,
    })
}

/// Encodes an origin write, as the loader script sends it.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the body is not a canonical object or
/// the ticket is empty or too long.
pub fn encode_origin_write(w: &OriginWrite) -> Result<Vec<u8>, VaultError> {
    if w.ticket.is_empty() || w.ticket.len() > MAX_TICKET_LEN {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let body = parse_canonical(&w.body, &limits()).map_err(malformed)?;
    if body.as_object().is_none() {
        return Err(VaultError::Malformed(ORIGIN));
    }
    let v = json::obj(vec![
        ("body", body),
        ("ticket", Value::String(json::hex(&w.ticket))),
    ])
    .map_err(malformed)?;
    json::to_canonical(&v).map_err(malformed)
}

/// Decodes a stored fact body. Fuzzed (`fact_body_decode`). A stored body
/// is decoded after unsealing, so a refusal means a corrupt row, and the
/// caller fails closed (NOTE 2).
///
/// # Errors
///
/// [`VaultError::Malformed`] for any spelling other than the canonical
/// frame, an unknown kind, or fields that are not the kind's canonical
/// fields.
pub fn decode_fact_body(bytes: &[u8]) -> Result<FactBody, VaultError> {
    let bad = |_: ProtoError| VaultError::Malformed(STORED);
    let v = parse_canonical(bytes, &fstp_vault_proto::json::limits()).map_err(bad)?;
    let o = json::object(&v, &["fields", "kind"], STORED).map_err(bad)?;
    let kind = json::small(o, "kind", STORED).map_err(bad)?;
    let fields = json::member(o, "fields", STORED).map_err(bad)?;
    fact_from_value(kind, fields).map_err(bad)?;
    Ok(FactBody {
        kind,
        fields: json::to_canonical(fields).map_err(bad)?,
    })
}

/// The stored body of `fact`.
///
/// # Errors
///
/// [`VaultError::Malformed`] when the fact has no canonical body.
pub fn encode_fact_body(fact: &Fact) -> Result<Vec<u8>, VaultError> {
    let bad = |_: ProtoError| VaultError::Malformed(STORED);
    let v = json::obj(vec![
        ("fields", fact.body_value().map_err(bad)?),
        (
            "kind",
            json::uint_json(u64::from(fact.kind()), STORED).map_err(bad)?,
        ),
    ])
    .map_err(bad)?;
    json::to_canonical(&v).map_err(bad)
}

/// The fact a stored body holds.
///
/// # Errors
///
/// As [`decode_fact_body`].
pub fn stored_fact(bytes: &[u8]) -> Result<Fact, VaultError> {
    let b = decode_fact_body(bytes)?;
    decode_fact(b.kind, &b.fields).map_err(|_| VaultError::Malformed(STORED))
}

/// The four identity fields a recorder enters with a verification (ADR-004
/// record of lane L13b, Q17). They reach the vault only, and leave it only
/// as the sealed tuple of the identity. No document number is among them
/// (R-ID-02).
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityAttributes {
    /// The family names, as printed.
    pub family_names: String,
    /// The given names, as printed.
    pub given_names: String,
    /// The date of birth, `YYYY-MM-DD`.
    pub birth_date: String,
    /// The ISO 3166-1 alpha-3 code of the state that issued the evidence.
    pub issuing_state: String,
}

impl std::fmt::Debug for IdentityAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // R-NF-02: identity attributes never reach a debug line.
        f.debug_struct("IdentityAttributes").finish_non_exhaustive()
    }
}

/// A recorder's verification write on the vault origin (kind 6, ADR-004
/// record of lane L13b, row "Origin body").
#[derive(Clone, PartialEq, Eq)]
pub struct VerificationWrite {
    /// The method.
    pub method: fstp_vault_core::fact::VerificationMethod,
    /// The type of the checked document.
    pub document_type: fstp_vault_core::fact::DocumentType,
    /// The checks performed, at least one.
    pub checks: std::collections::BTreeSet<fstp_vault_core::fact::Check>,
    /// The identity fields.
    pub identity: IdentityAttributes,
}

impl std::fmt::Debug for VerificationWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationWrite")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// The longest identity name field, in characters. Interim, no P- id.
pub const MAX_NAME_CHARS: usize = 200;

/// The label that starts every identity tuple (ADR-004 record of lane
/// L13b, row "Tuple"). Version 2 names are [`tuple_name`]s, NFKC and case
/// folded (ADR-029; decided by Daniel on 2026-11-21).
pub const TUPLE_LABEL: &[u8] = b"fstp-identity-tuple-v2";

/// The labels of earlier tuple versions. A vault that stores a tuple
/// under one of them refuses to start, since its match keys would not
/// find the same person again (ADR-004 row "Normalisation").
pub const OLD_TUPLE_LABELS: [&[u8]; 1] = [b"fstp-identity-tuple-v1"];

const VERIFICATION: &str = "verification write";

fn name_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=MAX_NAME_CHARS).contains(&n)
        && !tuple_name(s).is_empty()
        && !s.chars().any(char::is_control)
}

/// Whether `s` is a calendar date `YYYY-MM-DD` from 1900-01-01 on.
fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(r)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return false;
    }
    let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1900 && (1..=days).contains(&d)
}

fn state_ok(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|c| c.is_ascii_uppercase())
}

fn labels<T: Copy + Ord>(
    v: &Value,
    all: &[T],
    label: fn(T) -> &'static str,
) -> Result<std::collections::BTreeSet<T>, VaultError> {
    let bad = VaultError::Malformed(VERIFICATION);
    let a = v.as_array().ok_or(bad)?;
    let mut out = std::collections::BTreeSet::new();
    for item in a.iter() {
        let s = item.as_str().ok_or(bad)?;
        let x = all.iter().copied().find(|x| label(*x) == s).ok_or(bad)?;
        if out.last().is_some_and(|l| *l >= x) {
            return Err(bad);
        }
        out.insert(x);
    }
    if out.is_empty() {
        return Err(bad);
    }
    Ok(out)
}

fn one<T: Copy>(s: &str, all: &[T], label: fn(T) -> &'static str) -> Result<T, VaultError> {
    all.iter()
        .copied()
        .find(|x| label(*x) == s)
        .ok_or(VaultError::Malformed(VERIFICATION))
}

/// Decodes the body of a recorder's verification write. Fuzzed
/// (`verification_write_decode`). It takes exactly the canonical members
/// of ADR-004 record of lane L13b, row "Origin body".
///
/// # Errors
///
/// [`VaultError::Malformed`] for any other spelling, member or label, a
/// name outside 1 to [`MAX_NAME_CHARS`] characters or with a control
/// character, a date that is not a calendar date from 1900, or a state
/// that is not three capital letters. The error never quotes the body.
pub fn decode_verification_write(bytes: &[u8]) -> Result<VerificationWrite, VaultError> {
    use fstp_vault_core::fact::{Check, DocumentType, VerificationMethod};
    let bad = |_: ProtoError| VaultError::Malformed(VERIFICATION);
    let v = parse_canonical(bytes, &fstp_vault_proto::json::limits()).map_err(bad)?;
    let o = json::object(
        &v,
        &["checks", "document_type", "identity", "method"],
        VERIFICATION,
    )
    .map_err(bad)?;
    let i = json::object(
        json::member(o, "identity", VERIFICATION).map_err(bad)?,
        &["birth_date", "family_names", "given_names", "issuing_state"],
        VERIFICATION,
    )
    .map_err(bad)?;
    let text = |name: &str| -> Result<String, VaultError> {
        Ok(json::string(i, name, VERIFICATION).map_err(bad)?.to_owned())
    };
    let identity = IdentityAttributes {
        family_names: text("family_names")?,
        given_names: text("given_names")?,
        birth_date: text("birth_date")?,
        issuing_state: text("issuing_state")?,
    };
    let fields_ok = name_ok(&identity.family_names)
        && name_ok(&identity.given_names)
        && date_ok(&identity.birth_date)
        && state_ok(&identity.issuing_state);
    if !fields_ok {
        return Err(VaultError::Malformed(VERIFICATION));
    }
    Ok(VerificationWrite {
        method: one(
            json::string(o, "method", VERIFICATION).map_err(bad)?,
            &VerificationMethod::ALL,
            VerificationMethod::label,
        )?,
        document_type: one(
            json::string(o, "document_type", VERIFICATION).map_err(bad)?,
            &DocumentType::ALL,
            DocumentType::label,
        )?,
        checks: labels(
            json::member(o, "checks", VERIFICATION).map_err(bad)?,
            &Check::ALL,
            Check::label,
        )?,
        identity,
    })
}

/// The canonical body of `w`, as the write page sends it.
///
/// # Errors
///
/// [`VaultError::Malformed`] when a field is outside its form.
pub fn encode_verification_write(w: &VerificationWrite) -> Result<Vec<u8>, VaultError> {
    let bad = |_: ProtoError| VaultError::Malformed(VERIFICATION);
    let s = |x: &str| Value::String(x.to_owned());
    let identity = json::obj(vec![
        ("birth_date", s(&w.identity.birth_date)),
        ("family_names", s(&w.identity.family_names)),
        ("given_names", s(&w.identity.given_names)),
        ("issuing_state", s(&w.identity.issuing_state)),
    ])
    .map_err(bad)?;
    let checks = Value::Array(w.checks.iter().map(|c| s(c.label())).collect());
    let v = json::obj(vec![
        ("checks", checks),
        ("document_type", s(w.document_type.label())),
        ("identity", identity),
        ("method", s(w.method.label())),
    ])
    .map_err(bad)?;
    let bytes = json::to_canonical(&v).map_err(bad)?;
    decode_verification_write(&bytes)?;
    Ok(bytes)
}

/// A name as the tuple holds it: [`fstp_unorm::name_key`], the
/// compatibility caseless key `toNFKC_Casefold(NFD(s))` with white space
/// trimmed and each inner run one U+0020 (ADR-029; ADR-004 row
/// "Normalisation", decided by Daniel on 2026-11-21: NFKC plus case
/// folding). Case, canonical equivalence, compatibility variants and
/// default ignorables do not separate two spellings of one name.
#[must_use]
pub fn tuple_name(s: &str) -> String {
    fstp_unorm::name_key(s)
}

/// The identity tuple of `a` (ADR-004 record of lane L13b, row "Tuple"):
/// [`TUPLE_LABEL`], then each field as `be16(len) || UTF-8`, in the order
/// family names, given names, date of birth, issuing state.
#[must_use]
pub fn identity_tuple(a: &IdentityAttributes) -> Vec<u8> {
    let mut out = TUPLE_LABEL.to_vec();
    for field in [
        tuple_name(&a.family_names),
        tuple_name(&a.given_names),
        a.birth_date.clone(),
        a.issuing_state.clone(),
    ] {
        let len = u16::try_from(field.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// The attributes an identity tuple holds, the inverse of
/// [`identity_tuple`] (ADR-033 record of lane L31, the name mask). The
/// names come back as the tuple holds them, through `name_key`. `None` for
/// bytes that are not one tuple of [`TUPLE_LABEL`]. Fuzzed through
/// `identity_tuple_decode`.
#[must_use]
pub fn parse_identity_tuple(t: &[u8]) -> Option<IdentityAttributes> {
    let mut rest = t.strip_prefix(TUPLE_LABEL)?;
    let mut fields: Vec<String> = Vec::with_capacity(4);
    for _ in 0..4 {
        let (len, tail) = rest.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len));
        let field = tail.get(..len)?;
        fields.push(String::from_utf8(field.to_vec()).ok()?);
        rest = tail.get(len..)?;
    }
    if !rest.is_empty() {
        return None;
    }
    let mut it = fields.into_iter();
    Some(IdentityAttributes {
        family_names: it.next()?,
        given_names: it.next()?,
        birth_date: it.next()?,
        issuing_state: it.next()?,
    })
}

/// The largest identity file of `fstp-vault verify-first-admin`, in bytes.
pub const MAX_IDENTITY_FILE: usize = 4 << 10;

/// Decodes the identity file of `fstp-vault verify-first-admin` (ADR-004
/// record of lane L13b, row "Identity file"): one JSON object with the
/// members of the recorder's body, in any spelling, since a person writes
/// it by hand. The issuing state is upper-cased. Fuzzed through
/// `verification_write_decode`.
///
/// # Errors
///
/// [`VaultError::Config`] for a file over [`MAX_IDENTITY_FILE`] bytes, a
/// file that is not JSON, or members outside the recorder's body. The
/// error never quotes the file.
pub fn decode_identity_file(bytes: &[u8]) -> Result<VerificationWrite, VaultError> {
    let refused = VaultError::Config("identity file");
    if bytes.len() > MAX_IDENTITY_FILE {
        return Err(refused);
    }
    let mut v =
        fstp_json::parse_with(bytes, &fstp_vault_proto::json::limits()).map_err(|_| refused)?;
    // A hand-written list of checks may come in any order.
    if let Some(Value::Array(a)) = v.as_object_mut().and_then(|o| o.get_mut("checks")) {
        let mut items: Vec<Value> = a.iter().cloned().collect();
        items.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
        *a = items.into_iter().collect();
    }
    if let Some(Value::Object(i)) = v.as_object_mut().and_then(|o| o.get_mut("identity"))
        && let Some(Value::String(s)) = i.get_mut("issuing_state")
    {
        *s = s.trim().to_ascii_uppercase();
    }
    let canonical = json::to_canonical(&v).map_err(|_| refused)?;
    decode_verification_write(&canonical).map_err(|_| refused)
}
