//! JSON codecs of import records, proposer output and fixtures (TH-26,
//! H-05, M4 design section 9).
//!
//! - Every value has one spelling. The decoders refuse unknown and missing
//!   members, other spellings of numbers and ids, and malformed spans.
//! - Ids are decimal strings, because RFC 8785 numbers are exact only up
//!   to 2^53. Digests are 64 lowercase hex digits.
//! - A record never holds a proposed value (ADR-007, design 4.2). It names
//!   the stored text by `text`, an object with `digest` (the salted digest)
//!   and `id`. The value may hold personal data, and erasure destroys the
//!   text's key without touching the body (I-23, I-81).
//! - In proposer output and fixtures, the value is inline JSON. The decoder
//!   keeps it unchanged except for the order of object members.
//! - Errors name schema members only, never input content (R-NF-02).
//!
//! A record is an object whose member `record` is `document_registered`,
//! `proposals_recorded` or `proposal_resolved`, with that variant's
//! members beside it:
//!
//! - `document_registered`: `document`, an object with `blob`, `digest`,
//!   `id`, `media`, `programme`, `text_bytes` and `uploaded_by`;
//! - `proposals_recorded`: `document` (an id) and `proposals`, 1 to
//!   `MAX_BATCH` objects with `config`, `conflicts`, `document`,
//!   `evidence`, `field`, `id` and `text`;
//! - `proposal_resolved`: `by`, `proposal` and `resolution` (`confirmed`,
//!   `edited` or `dismissed`).
//!
//! A field is its `FieldId::key`, such as `money.p05_recipient_cap`.

use fstp_json::{
    Array, FromJson, FromJsonError, Object, ParseLimits, ToJson, Value, to_canonical, to_compact,
};
use fstp_programme::FieldId;

use crate::error::ImportError;
use crate::ids::{
    AccountRef, BlobAddress, ImportConfigId, ImportDocumentId, ImportProposalId, ProgrammeRef,
    SaltedDigest, TextDigest, ValueTextId, ValueTextRef,
};
use crate::model::{
    ConflictRule, ImportDocument, ImportRecord, ImportResolution, RecordedProposal,
};
use crate::proposer::{FakeProposer, FixtureEntry, RawProposal};
use crate::store::MAX_BATCH;
use crate::text::{ImportMedia, MAX_IMPORT_BYTES, MAX_SPANS, Span};
use crate::value::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_NODES, UntrustedValue};

/// A decoding failure: the schema member or rule, never input content.
type R<T> = Result<T, &'static str>;

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// A `u128` id as a decimal string.
fn id_json(raw: u128) -> Value {
    Value::String(raw.to_string())
}

/// A `u128` id from a decimal string without sign or leading zeros.
fn id_from(v: Option<&Value>, what: &'static str) -> R<u128> {
    let s = v.and_then(Value::as_str).ok_or(what)?;
    let b = s.as_bytes();
    let canonical = match b {
        [] => false,
        [b'0'] => true,
        [b'0', ..] => false,
        _ => b.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(what);
    }
    let mut acc: u128 = 0;
    for d in b {
        let digit = char::from(*d).to_digit(10).map(u128::from).ok_or(what)?;
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_add(digit))
            .ok_or(what)?;
    }
    Ok(acc)
}

/// Lowercase hex digits for a digest.
const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_json(bytes: [u8; 32]) -> Value {
    let mut s = String::with_capacity(64);
    for b in bytes {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nibble)) {
                s.push(char::from(*c));
            }
        }
    }
    Value::String(s)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|x| x.checked_add(10)),
        _ => None,
    }
}

/// 32 bytes from 64 lowercase hex digits.
fn hex_from(v: Option<&Value>, what: &'static str) -> R<[u8; 32]> {
    let s = v.and_then(Value::as_str).ok_or(what)?;
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(what);
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let [hi, lo] = pair else { return Err(what) };
        let (hi, lo) = hex_digit(*hi).zip(hex_digit(*lo)).ok_or(what)?;
        *o = hi.wrapping_shl(4) | lo;
    }
    Ok(out)
}

/// A `u32` as a JSON integer.
fn u32_json(n: u32) -> Value {
    Value::from(n)
}

/// A `u32` spelled as Rust prints it: no fraction, exponent, sign or
/// leading zero.
fn u32_from(v: Option<&Value>, what: &'static str) -> R<u32> {
    let n = v.and_then(Value::as_number).ok_or(what)?;
    let i = n.as_u64().ok_or(what)?;
    let i = u32::try_from(i).map_err(|_| what)?;
    if n.as_str() != i.to_string() {
        return Err(what);
    }
    Ok(i)
}

/// `v` as an object with exactly the members `names`, all present.
fn exact<'a>(v: &'a Value, names: &[&str], what: &'static str) -> R<&'a Object> {
    let o = v.as_object().ok_or(what)?;
    if o.len() != names.len() || !names.iter().all(|n| o.contains_key(n)) {
        return Err(what);
    }
    Ok(o)
}

fn array<'a>(v: Option<&'a Value>, what: &'static str) -> R<&'a Array> {
    v.and_then(Value::as_array).ok_or(what)
}

fn field_json(f: FieldId) -> Value {
    Value::String(f.key())
}

fn field_from(v: Option<&Value>) -> R<FieldId> {
    let s = v.and_then(Value::as_str).ok_or("field: not a string")?;
    FieldId::from_key(s).ok_or("field: unknown field key")
}

// ---------------------------------------------------------------------------
// Spans, documents and proposals
// ---------------------------------------------------------------------------

fn spans_json(spans: &[Span]) -> Value {
    let mut a = Array::with_capacity(spans.len());
    for s in spans {
        let mut o = Object::with_capacity(2);
        o.insert("end", u32_json(s.end));
        o.insert("start", u32_json(s.start));
        a.push(Value::Object(o));
    }
    Value::Array(a)
}

/// 1 to [`MAX_SPANS`] non-empty spans in strictly ascending order.
fn spans_from(v: Option<&Value>) -> R<Vec<Span>> {
    let a = array(v, "evidence: not an array")?;
    if a.is_empty() || a.len() > MAX_SPANS {
        return Err("evidence: 1 to 8 spans");
    }
    let mut out: Vec<Span> = Vec::with_capacity(a.len());
    for s in a.iter() {
        let o = exact(s, &["end", "start"], "evidence: a span has start and end")?;
        let span = Span {
            start: u32_from(o.get("start"), "evidence: start")?,
            end: u32_from(o.get("end"), "evidence: end")?,
        };
        if span.start >= span.end {
            return Err("evidence: an empty span");
        }
        if out.last().is_some_and(|last| *last >= span) {
            return Err("evidence: spans not ascending");
        }
        out.push(span);
    }
    Ok(out)
}

fn document_json(d: &ImportDocument) -> Value {
    let mut o = Object::with_capacity(7);
    o.insert("blob", hex_json(d.blob.bytes()));
    o.insert("digest", hex_json(d.digest.bytes()));
    o.insert("id", id_json(d.id.raw()));
    o.insert("media", Value::String(d.media.mime().to_owned()));
    o.insert("programme", id_json(d.programme.raw()));
    o.insert("text_bytes", u32_json(d.text_bytes));
    o.insert("uploaded_by", id_json(d.uploaded_by.raw()));
    Value::Object(o)
}

fn document_from(v: &Value) -> R<ImportDocument> {
    let o = exact(
        v,
        &[
            "blob",
            "digest",
            "id",
            "media",
            "programme",
            "text_bytes",
            "uploaded_by",
        ],
        "document: members",
    )?;
    let text_bytes = u32_from(o.get("text_bytes"), "document: text_bytes")?;
    if !usize::try_from(text_bytes).is_ok_and(|n| (1..=MAX_IMPORT_BYTES).contains(&n)) {
        return Err("document: text_bytes out of range");
    }
    let media = o
        .get("media")
        .and_then(Value::as_str)
        .and_then(ImportMedia::from_mime)
        .ok_or("document: media")?;
    Ok(ImportDocument {
        id: ImportDocumentId::from_raw(id_from(o.get("id"), "document: id")?),
        programme: ProgrammeRef::from_raw(id_from(o.get("programme"), "document: programme")?),
        blob: BlobAddress::from_bytes(hex_from(o.get("blob"), "document: blob")?),
        media,
        digest: TextDigest::from_bytes(hex_from(o.get("digest"), "document: digest")?),
        text_bytes,
        uploaded_by: AccountRef::from_raw(id_from(o.get("uploaded_by"), "document: uploaded_by")?),
    })
}

fn text_ref_json(t: ValueTextRef) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("digest", hex_json(t.digest().bytes()));
    o.insert("id", id_json(t.id().raw()));
    Value::Object(o)
}

fn text_ref_from(v: Option<&Value>) -> R<ValueTextRef> {
    let o = exact(
        v.ok_or("proposal: text")?,
        &["digest", "id"],
        "proposal: text members",
    )?;
    Ok(ValueTextRef::new(
        ValueTextId::from_raw(id_from(o.get("id"), "proposal: text id")?),
        SaltedDigest::from_bytes(hex_from(o.get("digest"), "proposal: text digest")?),
    ))
}

fn proposal_json(p: &RecordedProposal) -> Value {
    let mut conflicts = Array::with_capacity(p.conflicts_with_profile.len());
    for c in &p.conflicts_with_profile {
        conflicts.push(Value::String(c.as_str().to_owned()));
    }
    let mut o = Object::with_capacity(7);
    o.insert("config", id_json(p.config.raw()));
    o.insert("conflicts", Value::Array(conflicts));
    o.insert("document", id_json(p.document.raw()));
    o.insert("evidence", spans_json(&p.evidence));
    o.insert("field", field_json(p.field));
    o.insert("id", id_json(p.id.raw()));
    o.insert("text", text_ref_json(p.text));
    Value::Object(o)
}

fn proposal_from(v: &Value) -> R<RecordedProposal> {
    let o = exact(
        v,
        &[
            "config",
            "conflicts",
            "document",
            "evidence",
            "field",
            "id",
            "text",
        ],
        "proposal: members",
    )?;
    let mut conflicts: Vec<ConflictRule> = Vec::new();
    for c in array(o.get("conflicts"), "proposal: conflicts")?.iter() {
        let rule = c
            .as_str()
            .and_then(ConflictRule::from_name)
            .ok_or("proposal: unknown conflict rule")?;
        if conflicts.last().is_some_and(|last| *last >= rule) {
            return Err("proposal: conflicts not ascending");
        }
        conflicts.push(rule);
    }
    Ok(RecordedProposal {
        id: ImportProposalId::from_raw(id_from(o.get("id"), "proposal: id")?),
        document: ImportDocumentId::from_raw(id_from(o.get("document"), "proposal: document")?),
        field: field_from(o.get("field"))?,
        text: text_ref_from(o.get("text"))?,
        evidence: spans_from(o.get("evidence"))?,
        config: ImportConfigId::from_raw(id_from(o.get("config"), "proposal: config")?),
        conflicts_with_profile: conflicts,
    })
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

fn record_json(r: &ImportRecord) -> Value {
    let mut o = Object::with_capacity(4);
    match r {
        ImportRecord::DocumentRegistered(d) => {
            o.insert("document", document_json(d));
            o.insert("record", Value::String("document_registered".to_owned()));
        }
        ImportRecord::ProposalsRecorded {
            document,
            proposals,
        } => {
            let mut a = Array::with_capacity(proposals.len());
            for p in proposals {
                a.push(proposal_json(p));
            }
            o.insert("document", id_json(document.raw()));
            o.insert("proposals", Value::Array(a));
            o.insert("record", Value::String("proposals_recorded".to_owned()));
        }
        ImportRecord::ProposalResolved {
            proposal,
            resolution,
            by,
        } => {
            o.insert("by", id_json(by.raw()));
            o.insert("proposal", id_json(proposal.raw()));
            o.insert("record", Value::String("proposal_resolved".to_owned()));
            o.insert("resolution", Value::String(resolution.as_str().to_owned()));
        }
    }
    Value::Object(o)
}

fn record_from(v: &Value) -> R<ImportRecord> {
    let tag = v
        .get("record")
        .and_then(Value::as_str)
        .ok_or("record: missing tag")?;
    match tag {
        "document_registered" => {
            let o = exact(v, &["document", "record"], "document_registered: members")?;
            let d = o.get("document").ok_or("document_registered: document")?;
            Ok(ImportRecord::DocumentRegistered(document_from(d)?))
        }
        "proposals_recorded" => {
            let o = exact(
                v,
                &["document", "proposals", "record"],
                "proposals_recorded: members",
            )?;
            let document = ImportDocumentId::from_raw(id_from(
                o.get("document"),
                "proposals_recorded: document",
            )?);
            let a = array(o.get("proposals"), "proposals_recorded: proposals")?;
            if a.is_empty() || a.len() > MAX_BATCH {
                return Err("proposals_recorded: 1 to 64 proposals");
            }
            let mut proposals: Vec<RecordedProposal> = Vec::with_capacity(a.len());
            for p in a.iter() {
                let p = proposal_from(p)?;
                if p.document != document {
                    return Err("proposals_recorded: a proposal of another document");
                }
                if proposals.iter().any(|q| q.id == p.id) {
                    return Err("proposals_recorded: a repeated proposal id");
                }
                if proposals.iter().any(|q| q.text.id() == p.text.id()) {
                    return Err("proposals_recorded: a repeated text id");
                }
                proposals.push(p);
            }
            Ok(ImportRecord::ProposalsRecorded {
                document,
                proposals,
            })
        }
        "proposal_resolved" => {
            let o = exact(
                v,
                &["by", "proposal", "record", "resolution"],
                "proposal_resolved: members",
            )?;
            let resolution = o
                .get("resolution")
                .and_then(Value::as_str)
                .and_then(ImportResolution::from_name)
                .ok_or("proposal_resolved: resolution")?;
            Ok(ImportRecord::ProposalResolved {
                proposal: ImportProposalId::from_raw(id_from(
                    o.get("proposal"),
                    "proposal_resolved: proposal",
                )?),
                resolution,
                by: AccountRef::from_raw(id_from(o.get("by"), "proposal_resolved: by")?),
            })
        }
        _ => Err("record: unknown tag"),
    }
}

/// The stored JSON form of a record, for the engine envelope.
impl ToJson for ImportRecord {
    fn to_json(&self) -> Value {
        record_json(self)
    }
}

/// Decodes the stored JSON form of a record. Errors name schema members
/// only, never input content (R-NF-02).
impl FromJson for ImportRecord {
    fn from_json(value: &Value) -> Result<ImportRecord, FromJsonError> {
        record_from(value).map_err(FromJsonError::invalid)
    }
}

/// The parse limits of one stored record.
fn record_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(1 << 18)
        .with_max_depth(8)
        .with_max_string_bytes(256)
        .with_max_container_len(128)
        .with_max_nodes(16_384)
}

/// The RFC 8785 text of a record, which [`decode_record`] reads back to
/// the same record. Every number in a record is below 2^32, so the
/// canonical form always exists. The compact form is a total fallback only.
pub fn encode_record(record: &ImportRecord) -> String {
    let v = record_json(record);
    to_canonical(&v).unwrap_or_else(|_| to_compact(&v))
}

/// Decodes a stored import record. Fuzzed (`import_record_decode`).
pub fn decode_record(bytes: &[u8]) -> Result<ImportRecord, ImportError> {
    let v = fstp_json::parse_with(bytes, &record_limits()).map_err(|_| ImportError::NotJson)?;
    record_from(&v).map_err(ImportError::Malformed)
}

// ---------------------------------------------------------------------------
// Proposer output and fixtures
// ---------------------------------------------------------------------------

/// The parse limits of proposer output and fixtures: room for one batch of
/// values at their own bounds.
fn output_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(4 << 20)
        .with_max_depth(MAX_VALUE_DEPTH.saturating_add(4))
        .with_max_string_bytes(MAX_VALUE_BYTES)
        .with_max_container_len(MAX_VALUE_NODES)
        .with_max_nodes(MAX_BATCH.saturating_mul(MAX_VALUE_NODES.saturating_add(32)))
}

fn raw_json(p: &RawProposal) -> Value {
    let mut o = Object::with_capacity(3);
    o.insert("evidence", spans_json(&p.evidence));
    o.insert("field", field_json(p.field));
    o.insert("value", p.value.data_value());
    Value::Object(o)
}

fn raw_from(v: &Value) -> R<RawProposal> {
    let o = exact(v, &["evidence", "field", "value"], "proposal: members")?;
    let value = o.get("value").ok_or("proposal: value")?;
    Ok(RawProposal {
        field: field_from(o.get("field"))?,
        value: UntrustedValue::new(value).map_err(|_| "proposal: value out of bounds")?,
        evidence: spans_from(o.get("evidence"))?,
    })
}

/// The JSON text of one proposer output entry, which [`decode_proposal`]
/// reads back to the same proposal. Members are in sorted order and every
/// number lexeme is kept, so the value survives byte for byte.
pub fn encode_proposal(p: &RawProposal) -> String {
    to_compact(&raw_json(p))
}

/// Decodes one proposer output entry: an object with exactly `evidence`,
/// `field` and `value`. The value is kept unchanged except for the order of
/// object members. Fuzzed (`proposal_decode`).
pub fn decode_proposal(bytes: &[u8]) -> Result<RawProposal, ImportError> {
    let v = fstp_json::parse_with(bytes, &output_limits()).map_err(|_| ImportError::NotJson)?;
    raw_from(&v).map_err(ImportError::Malformed)
}

/// Decodes a [`FakeProposer`] fixture: an object with exactly `proposals`,
/// an array of at most `MAX_BATCH` objects with exactly `evidence` (a
/// non-empty string), `field` and `value`.
pub fn decode_fixture(bytes: &[u8]) -> Result<FakeProposer, ImportError> {
    let v = fstp_json::parse_with(bytes, &output_limits()).map_err(|_| ImportError::NotJson)?;
    fixture_from(&v)
        .map(FakeProposer::new)
        .map_err(ImportError::Malformed)
}

fn fixture_from(v: &Value) -> R<Vec<FixtureEntry>> {
    let o = exact(v, &["proposals"], "fixture: members")?;
    let a = array(o.get("proposals"), "fixture: proposals")?;
    if a.len() > MAX_BATCH {
        return Err("fixture: at most 64 proposals");
    }
    let mut out = Vec::with_capacity(a.len());
    for e in a.iter() {
        let o = exact(e, &["evidence", "field", "value"], "fixture: entry members")?;
        let evidence = o
            .get("evidence")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("fixture: evidence")?;
        let value = o.get("value").ok_or("fixture: value")?;
        out.push(FixtureEntry {
            field: field_from(o.get("field"))?,
            value: UntrustedValue::new(value).map_err(|_| "fixture: value out of bounds")?,
            evidence: evidence.to_owned(),
        });
    }
    Ok(out)
}

/// The JSON text of a fixture, which [`decode_fixture`] reads back to the
/// same proposer.
pub fn encode_fixture(p: &FakeProposer) -> String {
    let mut a = Array::with_capacity(p.entries().len());
    for e in p.entries() {
        let mut o = Object::with_capacity(3);
        o.insert("evidence", Value::String(e.evidence.clone()));
        o.insert("field", field_json(e.field));
        o.insert("value", e.value.data_value());
        a.push(Value::Object(o));
    }
    let mut o = Object::with_capacity(1);
    o.insert("proposals", Value::Array(a));
    to_compact(&Value::Object(o))
}
