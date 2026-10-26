//! JSON codec of findings and finding records (design sections 2.13 and 7).
//!
//! - Every value has one spelling. The decoder refuses unknown members,
//!   other spellings of numbers and ids, and malformed evidence spans.
//! - Ids are decimal strings, because RFC 8785 numbers are exact only up to
//!   2^53. Digests are 64 lowercase hex digits.
//! - The statement is a JSON string holding the statement byte for byte.
//!   The codec never trims, normalises or interprets it (TH-01). A
//!   statement that spells JSON members stays inside its string, so it
//!   never changes another field.
//! - Errors name schema members only, never input content (R-NF-02). An
//!   unknown member is reported without its name, so even
//!   `FromJsonError::path` carries no input text.
//! - The decoder refuses a finding with no evidence pointer (R-LA-02), and
//!   a `regenerated` record whose findings name another call or
//!   configuration (I-11).
//!
//! A finding is an object with the members `id`, `call`, `proposal`,
//! `config_id`, `type`, `criterion` (`null` when none applies), `severity`,
//! `confidence` (integer permille), `statement`, `evidence` and `trace_id`.
//! The names follow the schema outline of
//! `SPEC/04-llm-assessment/assessment.md`.
//!
//! A record is an object whose member `record` is `recorded`, `marked` or
//! `regenerated`, with that variant's members beside it. A `regenerated`
//! record has the members `call`, `fallback` (integer position in the
//! frozen P-21 fallback list), `config_model` (the model as a string),
//! `config_id` and `findings`.

use fstp_domain::id::{
    AccountId, CallId, ContentDigest, CriterionId, LlmConfigId, ProposalId, TextId, TextRef,
};
use fstp_domain::policy::ModelRef;
use fstp_json::typed::expect_object;
use fstp_json::{Array, FromJson, FromJsonError, FromJsonErrorKind, Number, Object, ToJson, Value};

use crate::finding::{
    Confidence, EvidenceRef, Finding, FindingId, FindingKind, Mark, Severity, TraceRef,
};
use crate::record::FindingRecord;
use crate::text::UntrustedText;

// ---------------------------------------------------------------------------
// Scalars.
// ---------------------------------------------------------------------------

/// A `u128` id as a decimal string.
fn id_to_json(raw: u128) -> Value {
    Value::String(raw.to_string())
}

/// A `u128` id from a decimal string without sign or leading zeros.
fn id_from_json(v: &Value) -> Result<u128, FromJsonError> {
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a decimal id string", v))?;
    let bytes = s.as_bytes();
    let canonical = match bytes {
        [] => false,
        [b'0'] => true,
        [b'0', ..] => false,
        _ => bytes.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(FromJsonError::invalid("not a canonical decimal id"));
    }
    let mut acc: u128 = 0;
    for b in bytes {
        let digit = char::from(*b).to_digit(10).map(u128::from);
        acc = digit
            .and_then(|d| acc.checked_mul(10)?.checked_add(d))
            .ok_or_else(|| FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "u128" }))?;
    }
    Ok(acc)
}

/// An unsigned integer within `0..=max`, spelled as Rust prints it. This
/// refuses fractions, exponents, signs and `-0`.
fn uint_from_json(v: &Value, max: u64, target: &'static str) -> Result<u64, FromJsonError> {
    let n = v
        .as_number()
        .ok_or_else(|| FromJsonError::wrong_type("an integer", v))?;
    if !n.is_integer() {
        return Err(FromJsonError::new(FromJsonErrorKind::NotAnInteger));
    }
    let out_of_range = || FromJsonError::new(FromJsonErrorKind::OutOfRange { target });
    let i = n.as_u64().ok_or_else(out_of_range)?;
    if i > max {
        return Err(out_of_range());
    }
    if n.as_str() != i.to_string() {
        return Err(FromJsonError::invalid("not a canonical integer"));
    }
    Ok(i)
}

fn u32_from_json(v: &Value) -> Result<u32, FromJsonError> {
    let i = uint_from_json(v, u64::from(u32::MAX), "u32")?;
    u32::try_from(i)
        .map_err(|_| FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "u32" }))
}

/// Lowercase hex digits for a digest.
const HEX: &[u8; 16] = b"0123456789abcdef";

fn digest_to_json(d: ContentDigest) -> Value {
    let mut s = String::with_capacity(64);
    for b in d.bytes() {
        let hi = HEX
            .get(usize::from(b.wrapping_shr(4)))
            .copied()
            .unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0');
        s.push(char::from(hi));
        s.push(char::from(lo));
    }
    Value::String(s)
}

/// The value of one lowercase hex digit.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' | b'a'..=b'f' => char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok()),
        _ => None,
    }
}

fn digest_from_json(v: &Value) -> Result<ContentDigest, FromJsonError> {
    let bad = || FromJsonError::invalid("not 64 lowercase hex digits");
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type("64 lowercase hex digits", v))?;
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (dst, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return Err(bad());
        };
        let (hi, lo) = hex_digit(*hi).zip(hex_digit(*lo)).ok_or_else(bad)?;
        *dst = hi.wrapping_shl(4) | lo;
    }
    Ok(ContentDigest::from_bytes(out))
}

/// One of a closed set of names, read with `from_name`.
fn name_from_json<T>(
    v: &Value,
    from_name: fn(&str) -> Option<T>,
    expected: &'static str,
) -> Result<T, FromJsonError> {
    let s = v
        .as_str()
        .ok_or_else(|| FromJsonError::wrong_type(expected, v))?;
    from_name(s).ok_or_else(|| FromJsonError::invalid("not a known name"))
}

/// A name as a JSON string.
fn name_to_json(name: &'static str) -> Value {
    Value::String(name.to_owned())
}

// Each encoder is an exhaustive match, so a new variant cannot compile
// until it has a name. Each decoder is its inverse.

const fn kind_name(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Completeness => "completeness",
        FindingKind::Quality => "quality",
        FindingKind::Accuracy => "accuracy",
        FindingKind::Integrity => "integrity",
    }
}

fn kind_from_name(s: &str) -> Option<FindingKind> {
    match s {
        "completeness" => Some(FindingKind::Completeness),
        "quality" => Some(FindingKind::Quality),
        "accuracy" => Some(FindingKind::Accuracy),
        "integrity" => Some(FindingKind::Integrity),
        _ => None,
    }
}

const fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Minor => "minor",
        Severity::Major => "major",
    }
}

fn severity_from_name(s: &str) -> Option<Severity> {
    match s {
        "info" => Some(Severity::Info),
        "minor" => Some(Severity::Minor),
        "major" => Some(Severity::Major),
        _ => None,
    }
}

const fn mark_name(m: Mark) -> &'static str {
    match m {
        Mark::Agreed => "agreed",
        Mark::Disputed => "disputed",
    }
}

fn mark_from_name(s: &str) -> Option<Mark> {
    match s {
        "agreed" => Some(Mark::Agreed),
        "disputed" => Some(Mark::Disputed),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Objects.
// ---------------------------------------------------------------------------

/// A required member of `o`, read with `read`. Errors carry the path.
fn member<T>(
    o: &Object,
    key: &'static str,
    read: impl FnOnce(&Value) -> Result<T, FromJsonError>,
) -> Result<T, FromJsonError> {
    match o.get(key) {
        Some(v) => read(v).map_err(|e| e.at_field(key)),
        None => Err(FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key)),
    }
}

/// The string member `key` of `o`, which names a variant.
fn tag_member<'a>(
    o: &'a Object,
    key: &'static str,
    expected: &'static str,
) -> Result<&'a str, FromJsonError> {
    match o.get(key) {
        Some(v) => v
            .as_str()
            .ok_or_else(|| FromJsonError::wrong_type(expected, v).at_field(key)),
        None => Err(FromJsonError::new(FromJsonErrorKind::MissingField).at_field(key)),
    }
}
/// Refuses a member of `o` outside `fields` (R-NF-02).
///
/// The error names no member, because an unknown name is input text.
/// `fstp_json::typed::reject_unknown` puts that name into the path.
fn reject_unknown(o: &Object, fields: &[&str]) -> Result<(), FromJsonError> {
    if o.keys().all(|k| fields.contains(&k)) {
        Ok(())
    } else {
        Err(FromJsonError::new(FromJsonErrorKind::UnknownField))
    }
}

/// The object inside `v` with no member outside `fields`.
fn object<'a>(v: &'a Value, fields: &[&str]) -> Result<&'a Object, FromJsonError> {
    let o = expect_object(v)?;
    reject_unknown(o, fields)?;
    Ok(o)
}

fn text_ref_to_json(t: TextRef) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("id", id_to_json(t.id().raw()));
    o.insert("digest", digest_to_json(t.digest()));
    Value::Object(o)
}

fn text_ref_from_json(v: &Value) -> Result<TextRef, FromJsonError> {
    let o = object(v, &["id", "digest"])?;
    let id = member(o, "id", id_from_json)?;
    let digest = member(o, "digest", digest_from_json)?;
    Ok(TextRef::new(TextId::from_raw(id), digest))
}

impl ToJson for EvidenceRef {
    fn to_json(&self) -> Value {
        let mut o = Object::with_capacity(4);
        match *self {
            EvidenceRef::Submission { text, start, end } => {
                o.insert("kind", Value::String("submission".to_owned()));
                o.insert("text", text_ref_to_json(text));
                o.insert("start", Value::Number(Number::from(start)));
                o.insert("end", Value::Number(Number::from(end)));
            }
            EvidenceRef::Retrieved { source } => {
                o.insert("kind", Value::String("retrieved".to_owned()));
                o.insert("source", text_ref_to_json(source));
            }
        }
        Value::Object(o)
    }
}

impl FromJson for EvidenceRef {
    fn from_json(v: &Value) -> Result<EvidenceRef, FromJsonError> {
        let o = expect_object(v)?;
        let kind = tag_member(o, "kind", "an evidence kind")?;
        match kind {
            "submission" => {
                reject_unknown(o, &["kind", "text", "start", "end"])?;
                let text = member(o, "text", text_ref_from_json)?;
                let start = member(o, "start", u32_from_json)?;
                let end = member(o, "end", u32_from_json)?;
                if start > end {
                    return Err(
                        FromJsonError::invalid("span ends before it starts").at_field("end")
                    );
                }
                Ok(EvidenceRef::Submission { text, start, end })
            }
            "retrieved" => {
                reject_unknown(o, &["kind", "source"])?;
                let source = member(o, "source", text_ref_from_json)?;
                Ok(EvidenceRef::Retrieved { source })
            }
            _ => Err(FromJsonError::invalid("not a known evidence kind").at_field("kind")),
        }
    }
}

/// The members of an encoded finding.
const FINDING_FIELDS: [&str; 11] = [
    "id",
    "call",
    "proposal",
    "config_id",
    "type",
    "criterion",
    "severity",
    "confidence",
    "statement",
    "evidence",
    "trace_id",
];

impl ToJson for Finding {
    fn to_json(&self) -> Value {
        let mut o = Object::with_capacity(FINDING_FIELDS.len());
        o.insert("id", id_to_json(self.id.raw()));
        o.insert("call", id_to_json(self.call.raw()));
        o.insert("proposal", id_to_json(self.proposal.raw()));
        o.insert("config_id", id_to_json(self.config.raw()));
        o.insert("type", name_to_json(kind_name(self.kind)));
        o.insert(
            "criterion",
            match self.criterion {
                Some(c) => id_to_json(c.raw()),
                None => Value::Null,
            },
        );
        o.insert("severity", name_to_json(severity_name(self.severity)));
        o.insert(
            "confidence",
            Value::Number(Number::from(self.confidence.permille())),
        );
        // The statement bytes, unchanged (TH-01).
        o.insert(
            "statement",
            Value::String(self.statement.as_data().to_owned()),
        );
        o.insert(
            "evidence",
            Value::Array(self.evidence.iter().map(ToJson::to_json).collect()),
        );
        o.insert("trace_id", id_to_json(self.trace.raw()));
        Value::Object(o)
    }
}

impl FromJson for Finding {
    fn from_json(v: &Value) -> Result<Finding, FromJsonError> {
        let o = object(v, &FINDING_FIELDS)?;
        Ok(Finding {
            id: FindingId::from_raw(member(o, "id", id_from_json)?),
            call: CallId::from_raw(member(o, "call", id_from_json)?),
            proposal: ProposalId::from_raw(member(o, "proposal", id_from_json)?),
            config: LlmConfigId::from_raw(member(o, "config_id", id_from_json)?),
            kind: member(o, "type", |k| {
                name_from_json(k, kind_from_name, "a finding type")
            })?,
            criterion: member(o, "criterion", |c| match c {
                Value::Null => Ok(None),
                c => id_from_json(c).map(|r| Some(CriterionId::from_raw(r))),
            })?,
            severity: member(o, "severity", |s| {
                name_from_json(s, severity_from_name, "a severity")
            })?,
            confidence: member(o, "confidence", |c| {
                let p = uint_from_json(c, u64::from(Confidence::FULL.permille()), "permille")?;
                u16::try_from(p)
                    .ok()
                    .and_then(Confidence::from_permille)
                    .ok_or_else(|| {
                        FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "permille" })
                    })
            })?,
            // The statement bytes, unchanged and never read (TH-01).
            statement: member(o, "statement", |s| {
                s.as_str()
                    .map(|s| UntrustedText::new(s.to_owned()))
                    .ok_or_else(|| FromJsonError::wrong_type("a string", s))
            })?,
            evidence: member(o, "evidence", |e| {
                let evidence = Vec::<EvidenceRef>::from_json(e)?;
                if evidence.is_empty() {
                    return Err(FromJsonError::invalid("no evidence pointer"));
                }
                Ok(evidence)
            })?,
            trace: TraceRef::from_raw(member(o, "trace_id", id_from_json)?),
        })
    }
}

impl ToJson for FindingRecord {
    fn to_json(&self) -> Value {
        let mut o = Object::with_capacity(6);
        match self {
            FindingRecord::Recorded(f) => {
                o.insert("record", Value::String("recorded".to_owned()));
                o.insert("finding", f.to_json());
            }
            FindingRecord::Marked { finding, by, mark } => {
                o.insert("record", Value::String("marked".to_owned()));
                o.insert("finding", id_to_json(finding.raw()));
                o.insert("by", id_to_json(by.raw()));
                o.insert("mark", name_to_json(mark_name(*mark)));
            }
            FindingRecord::Regenerated {
                call,
                fallback,
                config_model,
                config,
                findings,
            } => {
                o.insert("record", Value::String("regenerated".to_owned()));
                o.insert("call", id_to_json(call.raw()));
                o.insert("fallback", Value::Number(Number::from(*fallback)));
                o.insert("config_model", Value::String(config_model.0.clone()));
                o.insert("config_id", id_to_json(config.raw()));
                o.insert(
                    "findings",
                    Value::Array(findings.iter().map(ToJson::to_json).collect::<Array>()),
                );
            }
        }
        Value::Object(o)
    }
}

impl FromJson for FindingRecord {
    fn from_json(v: &Value) -> Result<FindingRecord, FromJsonError> {
        let o = expect_object(v)?;
        let tag = tag_member(o, "record", "a finding record name")?;
        match tag {
            "recorded" => {
                reject_unknown(o, &["record", "finding"])?;
                Ok(FindingRecord::Recorded(member(
                    o,
                    "finding",
                    Finding::from_json,
                )?))
            }
            "marked" => {
                reject_unknown(o, &["record", "finding", "by", "mark"])?;
                Ok(FindingRecord::Marked {
                    finding: FindingId::from_raw(member(o, "finding", id_from_json)?),
                    by: AccountId::from_raw(member(o, "by", id_from_json)?),
                    mark: member(o, "mark", |m| name_from_json(m, mark_from_name, "a mark"))?,
                })
            }
            "regenerated" => {
                reject_unknown(
                    o,
                    &[
                        "record",
                        "call",
                        "fallback",
                        "config_model",
                        "config_id",
                        "findings",
                    ],
                )?;
                let call = CallId::from_raw(member(o, "call", id_from_json)?);
                let fallback = member(o, "fallback", u32_from_json)?;
                let config_model = member(o, "config_model", |m| {
                    m.as_str()
                        .map(|s| ModelRef(s.to_owned()))
                        .ok_or_else(|| FromJsonError::wrong_type("a model string", m))
                })?;
                let config = LlmConfigId::from_raw(member(o, "config_id", id_from_json)?);
                let findings = member(o, "findings", |v| {
                    let findings = Vec::<Finding>::from_json(v)?;
                    // I-11: the record holds one call under one configuration.
                    for (i, f) in findings.iter().enumerate() {
                        if f.call != call {
                            return Err(FromJsonError::invalid("a finding of another call")
                                .at_field("call")
                                .at_index(i));
                        }
                        if f.config != config {
                            return Err(FromJsonError::invalid(
                                "a finding of another configuration",
                            )
                            .at_field("config_id")
                            .at_index(i));
                        }
                    }
                    Ok(findings)
                })?;
                Ok(FindingRecord::Regenerated {
                    call,
                    fallback,
                    config_model,
                    config,
                    findings,
                })
            }
            _ => Err(FromJsonError::invalid("not a known finding record").at_field("record")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// TH-26: ids keep their exact value over the whole `u128` range, and
    /// other spellings are refused.
    #[test]
    fn th26_id_codec_is_exact_and_canonical() {
        for raw in [0, 1, 9, 10, u128::from(u64::MAX), u128::MAX] {
            assert_eq!(id_from_json(&id_to_json(raw)), Ok(raw));
        }
        for bad in [
            "",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1e3",
            "340282366920938463463374607431768211456",
        ] {
            assert!(
                id_from_json(&Value::String(bad.to_owned())).is_err(),
                "{bad:?}"
            );
        }
        assert!(id_from_json(&Value::Number(Number::from(1u8))).is_err());
    }

    /// TH-26, TH-01: the `finding_decode` fuzz seeds decode, so the fuzzer
    /// starts from accepted findings and records of every variant.
    #[test]
    fn th26_fuzz_seeds_decode() {
        let findings: [&[u8]; 2] = [
            include_bytes!("../fuzz/seeds/finding_decode/finding"),
            include_bytes!("../fuzz/seeds/finding_decode/finding_minimal"),
        ];
        for seed in findings {
            let v = fstp_json::parse(seed).unwrap();
            let f = Finding::from_json(&v).unwrap();
            assert_eq!(
                f.statement.as_data(),
                v.get("statement").and_then(Value::as_str).unwrap()
            );
        }
        let records: [&[u8]; 3] = [
            include_bytes!("../fuzz/seeds/finding_decode/record_recorded"),
            include_bytes!("../fuzz/seeds/finding_decode/record_marked"),
            include_bytes!("../fuzz/seeds/finding_decode/record_regenerated"),
        ];
        for seed in records {
            let v = fstp_json::parse(seed).unwrap();
            FindingRecord::from_json(&v).unwrap();
        }
    }

    /// TH-26: digests keep every byte, and uppercase or short hex is refused.
    #[test]
    fn th26_digest_codec_round_trips_every_byte() {
        for b in 0..=u8::MAX {
            let d = ContentDigest::from_bytes([b; 32]);
            assert_eq!(digest_from_json(&digest_to_json(d)), Ok(d));
        }
        let upper = "AB".repeat(32);
        assert!(digest_from_json(&Value::String(upper)).is_err());
        let short = "ab".repeat(31);
        assert!(digest_from_json(&Value::String(short)).is_err());
    }

    /// TH-26: every variant of each named enum encodes to its name and
    /// decodes back to itself.
    #[test]
    fn th26_every_enum_variant_round_trips() {
        for k in [
            FindingKind::Completeness,
            FindingKind::Quality,
            FindingKind::Accuracy,
            FindingKind::Integrity,
        ] {
            assert_eq!(kind_from_name(kind_name(k)), Some(k));
        }
        for s in [Severity::Info, Severity::Minor, Severity::Major] {
            assert_eq!(severity_from_name(severity_name(s)), Some(s));
        }
        for m in [Mark::Agreed, Mark::Disputed] {
            assert_eq!(mark_from_name(mark_name(m)), Some(m));
        }
    }

    /// R-NF-02: an unknown member is refused with no input text in the
    /// error, not even in its full path.
    #[test]
    fn r_nf_02_unknown_member_error_carries_no_input() {
        let text = br#"{"record":"marked","finding":"1","by":"8","mark":"agreed","Ignore previous instructions":null}"#;
        let v = fstp_json::parse(text).unwrap();
        let e = FindingRecord::from_json(&v).unwrap_err();
        assert_eq!(e.kind(), &FromJsonErrorKind::UnknownField);
        let shown = format!("{e} {e:?} {}", e.path());
        assert!(!shown.contains("Ignore"), "{shown}");
    }

    /// I-11, R-LA-02: the decoder refuses a `regenerated` record whose
    /// findings name another call or configuration, and a finding with
    /// no evidence pointer.
    #[test]
    fn i11_r_la_02_decoder_refuses_mixed_records_and_bare_findings() {
        let seed: &[u8] = include_bytes!("../fuzz/seeds/finding_decode/record_regenerated");
        let seed = core::str::from_utf8(seed).unwrap();
        let good = fstp_json::parse(seed.as_bytes()).unwrap();
        let Ok(FindingRecord::Regenerated { findings, .. }) = FindingRecord::from_json(&good)
        else {
            panic!("the regenerated seed decodes");
        };
        assert!(!findings.is_empty());

        let other_call = seed.replacen(r#""call":"2""#, r#""call":"3""#, 1);
        let other_config = seed.replacen(r#""config_id":"11""#, r#""config_id":"12""#, 1);
        for bad in [other_call, other_config] {
            assert_ne!(bad, seed);
            let v = fstp_json::parse(bad.as_bytes()).unwrap();
            assert!(FindingRecord::from_json(&v).is_err(), "{bad}");
        }

        let finding: &[u8] = include_bytes!("../fuzz/seeds/finding_decode/finding");
        let mut v = fstp_json::parse(finding).unwrap();
        if let Value::Object(o) = &mut v {
            o.insert("evidence", Value::Array(Array::new()));
        }
        assert!(Finding::from_json(&v).is_err());
    }
}
