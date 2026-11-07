//! The cell envelope codec (ADR-007, I-23, design sections 5.1, 5.3 and
//! 15). Each decoder is fuzzed.
//!
//! # Stored form
//!
//! A cell record or command is the RFC 8785 text of an object with exactly
//! one member, named for its side of the envelope:
//!
//! - `core` and `finding` hold an M2 record in the form of
//!   `fstp_engine::Record`, so every M2 record keeps its exact bytes. A
//!   command under `core` is an M2 command in the form of
//!   `fstp_domain::Command`. A command under `finding` is a finding
//!   command in the form below.
//! - `auth`, `tenant`, `text`, `key`, `release` and `ops` hold an object
//!   whose member `type` names the variant. The variant's fields sit beside
//!   it, under their own names.
//! - The `auth` object is the one `fstp_auth::codec` writes, and it is
//!   read back through `decode_auth_record` or `decode_auth_command`. So
//!   an auth record or command has one spelling inside the envelope and
//!   alone, and the auth codec's limits apply to it.
//!
//! Field spellings follow the M2 codec. Account and proposal ids and
//! 64-bit integers are decimal strings. Ids and digests are lowercase
//! hexadecimal strings. A write kind or a cause code is a JSON integer.
//! An opaque canonical value is a string holding its RFC 8785 text.
//!
//! # One spelling
//!
//! The decoders accept only the stored form. They parse the input, decode
//! it, encode the result again and refuse the input unless the two byte
//! strings are equal. So an accepted input re-encodes byte for byte, and
//! the step-up action digest names one command (I-78, design section 8.4).
//!
//! Decode errors name schema members and static reasons only, never input
//! content (R-NF-02).

use fstp_domain::id::{AccountId, CallId, LlmConfigId};
use fstp_domain::policy::ModelRef;
use fstp_findings::{Finding, FindingCommand, FindingId, Mark};
use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{
    Array, FromJson, FromJsonError, FromJsonErrorKind, Number, Object, ToJson, Value, parse,
    to_canonical,
};
use fstp_ledger::{Canonical, SCHEMA_V1};

use crate::ops::{OpsCommand, OpsRecord};
use crate::release::{ReleaseCommand, ReleaseRecord};
use crate::tenant::{TenantCommand, TenantRecord};
use crate::text::{TextCommand, TextRecord};
use crate::timeline::{
    FiredMessage, MAX_MESSAGES, MAX_OFFSET_MINUTES, MAX_SOURCE_LEN, TimelineRecord,
};
use crate::{CellCommand, CellRecord, KeyCommand, KeyRecord};

/// The schema versions of cell records that this build decodes. Version 1
/// is the only published version, for the M2 members and the cell members
/// alike. A later version adds an upcast here, and stored bytes are never
/// rewritten (ADR-007).
pub const CELL_SCHEMAS: [u16; 1] = [SCHEMA_V1];

/// The largest input the decoders read: 4 MiB. A larger input is refused
/// before it is parsed, so allocation stays bounded.
pub const MAX_INPUT: usize = 4 * 1024 * 1024;

/// The largest opaque canonical value inside a cell record or command,
/// such as a login policy or a key operation: 4 KiB.
pub const MAX_OPAQUE: usize = 4 * 1024;

/// The largest credential id: 1023 bytes, the WebAuthn bound on credential
/// ids, as the auth codec holds it.
pub const MAX_CREDENTIAL: usize = fstp_auth::codec::MAX_CREDENTIAL_LEN;

/// The most text ids one erasure names.
pub const MAX_TEXT_IDS: usize = 1024;

/// Why a cell record or command did not decode. It names schema members
/// and static reasons only, never input content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input is larger than [`MAX_INPUT`].
    TooLarge,
    /// The input is not one JSON text.
    NotJson,
    /// The input is not the one stored spelling of what it decodes to.
    NotCanonical,
    /// The input is not an object with exactly one known member.
    NotAnEnvelope,
    /// The schema version is not in [`CELL_SCHEMAS`].
    UnpublishedSchema,
    /// The member's value does not decode.
    Body {
        /// The envelope member.
        member: &'static str,
        /// What is wrong, as a static reason.
        reason: &'static str,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::TooLarge => f.write_str("cell value too large"),
            DecodeError::NotJson => f.write_str("cell value is not JSON"),
            DecodeError::NotCanonical => f.write_str("cell value is not in its stored spelling"),
            DecodeError::NotAnEnvelope => f.write_str("cell value is not an envelope"),
            DecodeError::UnpublishedSchema => f.write_str("unpublished cell schema version"),
            DecodeError::Body { member, reason } => write!(f, "cell member {member}: {reason}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ---------------------------------------------------------------------------
// The public entry points.

/// Decodes a cell record from its stored bytes. Fuzzed
/// (`cell_record_decode`).
pub fn decode_cell_record(bytes: &[u8]) -> Result<CellRecord, DecodeError> {
    let value = read_canonical(bytes)?;
    let record = record_from_value(&value)?;
    same_bytes(&record.to_json(), bytes)?;
    Ok(record)
}

/// Decodes a cell command from its canonical bytes. Fuzzed
/// (`cell_command_decode`).
pub fn decode_cell_command(bytes: &[u8]) -> Result<CellCommand, DecodeError> {
    let value = read_canonical(bytes)?;
    let command = command_from_value(&value)?;
    same_bytes(&command.to_json(), bytes)?;
    Ok(command)
}

/// Decodes a record from its canonical text at a schema version. This is
/// the decode function `fstp-cell` passes to `PgRecordStore` (design
/// section 5.3). A version outside [`CELL_SCHEMAS`] is refused before the
/// body is read.
pub fn record_from_canonical_at(canonical: &[u8], schema: u16) -> Result<CellRecord, DecodeError> {
    if !CELL_SCHEMAS.contains(&schema) {
        return Err(DecodeError::UnpublishedSchema);
    }
    decode_cell_record(canonical)
}

/// The stored bytes of a cell record: the RFC 8785 text of its JSON form.
pub fn encode_cell_record(r: &CellRecord) -> Vec<u8> {
    canonical_bytes(&r.to_json())
}

/// The canonical bytes of a cell command, which [`decode_cell_command`]
/// reads back. The step-up action digest is taken over them (design
/// section 8.4).
pub fn encode_cell_command(c: &CellCommand) -> Vec<u8> {
    canonical_bytes(&c.to_json())
}

/// The canonical bytes of `c`, but only when they name `c` alone: they
/// decode back to `c` exactly. `None` otherwise, for example for opaque
/// bytes that are not canonical UTF-8 JSON, which the encoder cannot carry
/// as they are. The step-up digests take this form, so no two commands
/// share one (I-78, design section 8.4).
pub fn try_encode_cell_command(c: &CellCommand) -> Option<Vec<u8>> {
    let bytes = encode_cell_command(c);
    match decode_cell_command(&bytes) {
        Ok(back) if back == *c => Some(bytes),
        _ => None,
    }
}

impl Canonical for CellRecord {
    fn canonical(&self) -> Vec<u8> {
        encode_cell_record(self)
    }
}

impl Canonical for CellCommand {
    fn canonical(&self) -> Vec<u8> {
        encode_cell_command(self)
    }
}

/// The RFC 8785 text of `v`. Every number the cell encoders write is a
/// 16-bit integer, and the M2 encoders write large values as strings, so
/// the canonical form always exists. An encoder that broke this would give
/// empty bytes, which no decoder accepts.
fn canonical_bytes(v: &Value) -> Vec<u8> {
    to_canonical(v).map(String::into_bytes).unwrap_or_default()
}

/// Parses `bytes` and checks that they are RFC 8785 text.
fn read_canonical(bytes: &[u8]) -> Result<Value, DecodeError> {
    if bytes.len() > MAX_INPUT {
        return Err(DecodeError::TooLarge);
    }
    let value = parse(bytes).map_err(|_| DecodeError::NotJson)?;
    let text = to_canonical(&value).map_err(|_| DecodeError::NotCanonical)?;
    if text.as_bytes() != bytes {
        return Err(DecodeError::NotCanonical);
    }
    Ok(value)
}

/// Refuses unless `v` encodes to exactly `bytes`.
fn same_bytes(v: &Value, bytes: &[u8]) -> Result<(), DecodeError> {
    let again = to_canonical(v).map_err(|_| DecodeError::NotCanonical)?;
    if again.as_bytes() == bytes {
        Ok(())
    } else {
        Err(DecodeError::NotCanonical)
    }
}

/// The single member of an envelope.
fn envelope(value: &Value) -> Result<(&str, &Value), DecodeError> {
    let o = value.as_object().ok_or(DecodeError::NotAnEnvelope)?;
    let mut members = o.iter();
    match (members.next(), members.next()) {
        (Some((k, v)), None) => Ok((k, v)),
        _ => Err(DecodeError::NotAnEnvelope),
    }
}

/// Maps a JSON decode error of `member` to a static reason.
fn body(member: &'static str) -> impl Fn(FromJsonError) -> DecodeError {
    move |e| DecodeError::Body {
        member,
        reason: reason_of(&e),
    }
}

/// A static reason for a JSON decode error. It holds no input content.
fn reason_of(e: &FromJsonError) -> &'static str {
    match e.kind() {
        FromJsonErrorKind::WrongType { expected, .. } => expected,
        FromJsonErrorKind::NotAnInteger => "not an integer",
        FromJsonErrorKind::OutOfRange { .. } => "out of range",
        FromJsonErrorKind::MissingField => "a member is missing",
        FromJsonErrorKind::UnknownField => "an unknown member",
        FromJsonErrorKind::Invalid(why) => why,
        _ => "invalid value",
    }
}

// ---------------------------------------------------------------------------
// Records.

fn record_from_value(value: &Value) -> Result<CellRecord, DecodeError> {
    let (member, inner) = envelope(value)?;
    match member {
        "core" | "finding" => fstp_engine::Record::from_json(value)
            .map(CellRecord::Engine)
            .map_err(body(if member == "core" { "core" } else { "finding" })),
        // The engine's tenant side (lane m4tenant). M3's own tenant
        // records keep the member `tenant`.
        "onboarding" => fstp_engine::Record::from_json(value)
            .map(CellRecord::Engine)
            .map_err(body("onboarding")),
        // The engine's creator and import sides (M4 design sections 3.2
        // to 3.4). The encoder writes them through `fstp_engine::Record`,
        // so the decoder reads them back the same way. Without them no
        // creator batch is storable, and since D2e no programme activates
        // on the cell (M4 design section 15.0).
        "creator" => fstp_engine::Record::from_json(value)
            .map(CellRecord::Engine)
            .map_err(body("creator")),
        "import" => fstp_engine::Record::from_json(value)
            .map(CellRecord::Engine)
            .map_err(body("import")),
        // The engine's contract side (M5 lane L-CON).
        "contract" => fstp_engine::Record::from_json(value)
            .map(CellRecord::Engine)
            .map_err(body("contract")),
        "auth" => auth_record(inner).map(CellRecord::Auth),
        "tenant" => tenant_record(inner)
            .map(CellRecord::Tenant)
            .map_err(body("tenant")),
        "text" => text_record(inner)
            .map(CellRecord::Text)
            .map_err(body("text")),
        "key" => key_record(inner).map(CellRecord::Key).map_err(body("key")),
        "release" => release_record(inner)
            .map(CellRecord::Release)
            .map_err(body("release")),
        "ops" => ops_record(inner).map(CellRecord::Ops).map_err(body("ops")),
        "timeline" => timeline_record(inner)
            .map(CellRecord::Timeline)
            .map_err(body("timeline")),
        _ => Err(DecodeError::NotAnEnvelope),
    }
}

impl ToJson for CellRecord {
    fn to_json(&self) -> Value {
        match self {
            CellRecord::Engine(r) => r.to_json(),
            CellRecord::Auth(r) => wrap("auth", auth_record_json(r)),
            CellRecord::Tenant(r) => wrap("tenant", tenant_record_json(r)),
            CellRecord::Text(r) => wrap("text", text_record_json(r)),
            CellRecord::Key(r) => wrap("key", key_record_json(r)),
            CellRecord::Release(r) => wrap("release", release_record_json(r)),
            CellRecord::Ops(r) => wrap("ops", ops_record_json(r)),
            CellRecord::Timeline(r) => wrap("timeline", timeline_record_json(r)),
        }
    }
}

// ---------------------------------------------------------------------------
// The auth member: fstp-auth's codec (design sections 5.1 and 15).
//
// The value under `auth` is the object whose RFC 8785 text
// `fstp_auth::codec::encode_auth_record` or `encode_auth_command` gives.
// So each auth record and command has one spelling, alone or inside the
// cell envelope. The decoders pass the member's canonical text to
// `decode_auth_record` or `decode_auth_command`, so the limits and the
// checks of the auth codec apply here too.

/// The JSON form of an auth record, as fstp-auth's codec encodes it.
fn auth_record_json(r: &fstp_auth::AuthRecord) -> Value {
    r.to_json()
}

/// An auth record through `fstp_auth::codec::decode_auth_record`.
fn auth_record(v: &Value) -> Result<fstp_auth::AuthRecord, DecodeError> {
    fstp_auth::codec::decode_auth_record(&canonical_bytes(v)).map_err(auth_body)
}

/// The JSON form of an auth command, as fstp-auth's codec encodes it.
fn auth_command_json(c: &fstp_auth::AuthCommand) -> Value {
    c.to_json()
}

/// An auth command through `fstp_auth::codec::decode_auth_command`.
fn auth_command(v: &Value) -> Result<fstp_auth::AuthCommand, DecodeError> {
    fstp_auth::codec::decode_auth_command(&canonical_bytes(v)).map_err(auth_body)
}

/// A static reason for an auth codec error. It holds no input content.
fn auth_body(e: fstp_auth::codec::CodecError) -> DecodeError {
    use fstp_auth::codec::CodecError as E;
    let reason = match e {
        E::Length => "wrong length",
        E::Size => "empty or too large for the auth codec",
        E::Json => "outside the auth codec limits",
        E::NotCanonical => "not canonical",
        E::Schema(_) => "outside the auth schema",
        E::OtherCell => "names another cell",
    };
    DecodeError::Body {
        member: "auth",
        reason,
    }
}

fn tenant_record_json(r: &TenantRecord) -> Value {
    match r {
        TenantRecord::TenantAdminGranted { account } => tagged(
            "TenantAdminGranted",
            vec![("account", account_json(*account))],
        ),
        TenantRecord::TenantAdminEnded { account } => tagged(
            "TenantAdminEnded",
            vec![("account", account_json(*account))],
        ),
        TenantRecord::SelfGrantApproved {
            approver,
            grant_digest,
            expires_at,
        } => tagged(
            "SelfGrantApproved",
            vec![
                ("approver", account_json(*approver)),
                ("expires_at", Value::String(expires_at.to_string())),
                ("grant_digest", hex(grant_digest)),
            ],
        ),
        TenantRecord::SelfGrantApprovalUsed { grant_digest } => tagged(
            "SelfGrantApprovalUsed",
            vec![("grant_digest", hex(grant_digest))],
        ),
        TenantRecord::LoginPolicySet { policy } => {
            tagged("LoginPolicySet", vec![("policy", opaque_json(policy))])
        }
    }
}

fn tenant_record(v: &Value) -> Result<TenantRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "TenantAdminGranted" => {
            fields(o, &["account"])?;
            Ok(TenantRecord::TenantAdminGranted {
                account: account_from(o, "account")?,
            })
        }
        "TenantAdminEnded" => {
            fields(o, &["account"])?;
            Ok(TenantRecord::TenantAdminEnded {
                account: account_from(o, "account")?,
            })
        }
        "SelfGrantApproved" => {
            fields(o, &["approver", "expires_at", "grant_digest"])?;
            Ok(TenantRecord::SelfGrantApproved {
                approver: account_from(o, "approver")?,
                grant_digest: array_from(o, "grant_digest")?,
                expires_at: i64_from(o, "expires_at")?,
            })
        }
        "SelfGrantApprovalUsed" => {
            fields(o, &["grant_digest"])?;
            Ok(TenantRecord::SelfGrantApprovalUsed {
                grant_digest: array_from(o, "grant_digest")?,
            })
        }
        "LoginPolicySet" => {
            fields(o, &["policy"])?;
            Ok(TenantRecord::LoginPolicySet {
                policy: opaque_from(o, "policy")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn text_record_json(r: &TextRecord) -> Value {
    match r {
        TextRecord::TextPut { id } => tagged("TextPut", vec![("id", hex(id))]),
        TextRecord::TextsErased { ids } => tagged("TextsErased", vec![("ids", id_list(ids))]),
        TextRecord::ErasureRequested { ids, cause, by } => tagged(
            "ErasureRequested",
            vec![
                ("by", account_json(*by)),
                ("cause", Value::Number(Number::from(*cause))),
                ("ids", id_list(ids)),
            ],
        ),
    }
}

fn text_record(v: &Value) -> Result<TextRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "TextPut" => {
            fields(o, &["id"])?;
            Ok(TextRecord::TextPut {
                id: array_from(o, "id")?,
            })
        }
        "TextsErased" => {
            fields(o, &["ids"])?;
            Ok(TextRecord::TextsErased {
                ids: id_list_from(o, "ids")?,
            })
        }
        "ErasureRequested" => {
            fields(o, &["by", "cause", "ids"])?;
            Ok(TextRecord::ErasureRequested {
                ids: id_list_from(o, "ids")?,
                cause: u16_from(o, "cause")?,
                by: account_from(o, "by")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn key_record_json(r: &KeyRecord) -> Value {
    match r {
        KeyRecord::KeyOpRecorded { op } => tagged("KeyOpRecorded", vec![("op", opaque_json(op))]),
        KeyRecord::EpochDestroyed { epoch, receipt } => tagged(
            "EpochDestroyed",
            vec![
                ("epoch", Value::String(epoch.to_string())),
                ("receipt", hex(receipt)),
            ],
        ),
    }
}

fn key_record(v: &Value) -> Result<KeyRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "KeyOpRecorded" => {
            fields(o, &["op"])?;
            Ok(KeyRecord::KeyOpRecorded {
                op: opaque_from(o, "op")?,
            })
        }
        "EpochDestroyed" => {
            fields(o, &["epoch", "receipt"])?;
            Ok(KeyRecord::EpochDestroyed {
                epoch: u64_from(o, "epoch")?,
                receipt: array_from(o, "receipt")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn release_record_json(r: &ReleaseRecord) -> Value {
    match r {
        ReleaseRecord::TicketIssued {
            id,
            kind,
            proposal,
            holder,
        } => tagged(
            "TicketIssued",
            vec![
                ("holder", account_json(*holder)),
                ("id", hex(id)),
                ("kind", Value::Number(Number::from(*kind))),
                ("proposal", dec_u128(*proposal)),
            ],
        ),
        ReleaseRecord::IdentityReleaseIssued { id, proposal, by } => tagged(
            "IdentityReleaseIssued",
            vec![
                ("by", account_json(*by)),
                ("id", hex(id)),
                ("proposal", dec_u128(*proposal)),
            ],
        ),
    }
}

fn release_record(v: &Value) -> Result<ReleaseRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "TicketIssued" => {
            fields(o, &["holder", "id", "kind", "proposal"])?;
            Ok(ReleaseRecord::TicketIssued {
                id: array_from(o, "id")?,
                kind: u16_from(o, "kind")?,
                proposal: u128_from(o, "proposal")?,
                holder: account_from(o, "holder")?,
            })
        }
        "IdentityReleaseIssued" => {
            fields(o, &["by", "id", "proposal"])?;
            Ok(ReleaseRecord::IdentityReleaseIssued {
                id: array_from(o, "id")?,
                proposal: u128_from(o, "proposal")?,
                by: account_from(o, "by")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn ops_record_json(r: &OpsRecord) -> Value {
    match r {
        OpsRecord::BreakGlassApproved { grant } => {
            tagged("BreakGlassApproved", vec![("grant", hex(grant))])
        }
        OpsRecord::BreakGlassEnded { grant } => {
            tagged("BreakGlassEnded", vec![("grant", hex(grant))])
        }
    }
}

fn ops_record(v: &Value) -> Result<OpsRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "BreakGlassApproved" => {
            fields(o, &["grant"])?;
            Ok(OpsRecord::BreakGlassApproved {
                grant: array_from(o, "grant")?,
            })
        }
        "BreakGlassEnded" => {
            fields(o, &["grant"])?;
            Ok(OpsRecord::BreakGlassEnded {
                grant: array_from(o, "grant")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

// ---------------------------------------------------------------------------
// The timeline member (M6 design section 3.1). Template ids, versions and
// kinds are JSON integers. Times, leads, offsets and source versions are
// decimal strings. Ids, digests and source references are hexadecimal.

fn timeline_record_json(r: &TimelineRecord) -> Value {
    match r {
        TimelineRecord::TemplateVersionRecorded {
            template,
            version,
            locale,
            digest,
        } => tagged(
            "TemplateVersionRecorded",
            vec![
                ("digest", hex(digest)),
                ("locale", Value::String(locale.clone())),
                ("template", Value::Number(Number::from(*template))),
                ("version", Value::Number(Number::from(*version))),
            ],
        ),
        TimelineRecord::EventScheduled {
            event,
            kind,
            lead,
            source,
            source_version,
            due,
            offset_minutes,
        } => tagged(
            "EventScheduled",
            vec![
                ("due", Value::String(due.to_string())),
                ("event", hex(event)),
                ("kind", Value::Number(Number::from(*kind))),
                ("lead", Value::String(lead.to_string())),
                ("offset_minutes", Value::String(offset_minutes.to_string())),
                ("source", hex(source)),
                ("source_version", Value::String(source_version.to_string())),
            ],
        ),
        TimelineRecord::EventCancelled {
            event,
            superseded_by,
        } => tagged(
            "EventCancelled",
            vec![
                ("event", hex(event)),
                (
                    "superseded_by",
                    superseded_by.as_ref().map_or(Value::Null, |e| hex(e)),
                ),
            ],
        ),
        TimelineRecord::EventFired { event, messages } => tagged(
            "EventFired",
            vec![
                ("event", hex(event)),
                (
                    "messages",
                    Value::Array(messages.iter().map(fired_message_json).collect::<Array>()),
                ),
            ],
        ),
    }
}

fn fired_message_json(m: &FiredMessage) -> Value {
    let mut o = Object::with_capacity(4);
    o.insert("idem", hex(&m.idem));
    o.insert("outbox", hex(&m.outbox));
    o.insert("template", Value::Number(Number::from(m.template)));
    o.insert("version", Value::Number(Number::from(m.version)));
    Value::Object(o)
}

fn timeline_record(v: &Value) -> Result<TimelineRecord, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "TemplateVersionRecorded" => {
            fields(o, &["digest", "locale", "template", "version"])?;
            let locale = str_of(o, "locale")?;
            if !crate::timeline::is_locale(locale) {
                return Err(FromJsonError::invalid("not a locale tag").at_field("locale"));
            }
            Ok(TimelineRecord::TemplateVersionRecorded {
                template: u16_from(o, "template")?,
                version: u16_from(o, "version")?,
                locale: locale.to_owned(),
                digest: array_from(o, "digest")?,
            })
        }
        "EventScheduled" => {
            fields(
                o,
                &[
                    "due",
                    "event",
                    "kind",
                    "lead",
                    "offset_minutes",
                    "source",
                    "source_version",
                ],
            )?;
            let offset = i64_from(o, "offset_minutes")?;
            let offset_minutes = i16::try_from(offset)
                .ok()
                .filter(|m| m.unsigned_abs() <= MAX_OFFSET_MINUTES.unsigned_abs())
                .ok_or_else(|| {
                    FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "offset" })
                        .at_field("offset_minutes")
                })?;
            Ok(TimelineRecord::EventScheduled {
                event: array_from(o, "event")?,
                kind: u16_from(o, "kind")?,
                lead: i64_from(o, "lead")?,
                source: bytes_from(o, "source", MAX_SOURCE_LEN)?,
                source_version: u64_from(o, "source_version")?,
                due: i64_from(o, "due")?,
                offset_minutes,
            })
        }
        "EventCancelled" => {
            fields(o, &["event", "superseded_by"])?;
            let superseded_by = match member(o, "superseded_by")? {
                Value::Null => None,
                _ => Some(array_from(o, "superseded_by")?),
            };
            Ok(TimelineRecord::EventCancelled {
                event: array_from(o, "event")?,
                superseded_by,
            })
        }
        "EventFired" => {
            fields(o, &["event", "messages"])?;
            let list = member(o, "messages")?
                .as_array()
                .ok_or_else(|| FromJsonError::invalid("not a list").at_field("messages"))?;
            if list.len() > MAX_MESSAGES {
                return Err(FromJsonError::invalid("too many messages").at_field("messages"));
            }
            let mut messages = Vec::with_capacity(list.len());
            for (i, m) in list.iter().enumerate() {
                messages.push(fired_message(m).map_err(|e| e.at_index(i).at_field("messages"))?);
            }
            Ok(TimelineRecord::EventFired {
                event: array_from(o, "event")?,
                messages,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn fired_message(v: &Value) -> Result<FiredMessage, FromJsonError> {
    let o = expect_object(v)?;
    reject_unknown(o, &["idem", "outbox", "template", "version"])?;
    Ok(FiredMessage {
        outbox: array_from(o, "outbox")?,
        idem: array_from(o, "idem")?,
        template: u16_from(o, "template")?,
        version: u16_from(o, "version")?,
    })
}

// ---------------------------------------------------------------------------
// Commands.

fn command_from_value(value: &Value) -> Result<CellCommand, DecodeError> {
    let (member, inner) = envelope(value)?;
    match member {
        "core" => fstp_domain::Command::from_json(inner)
            .map(|c| CellCommand::Engine(fstp_engine::Command::Core(c)))
            .map_err(body("core")),
        "finding" => finding_command(inner)
            .map(|c| CellCommand::Engine(fstp_engine::Command::Finding(c)))
            .map_err(body("finding")),
        "onboarding" => fstp_engine::tenant::request_from_json(inner)
            .map(|c| CellCommand::Engine(fstp_engine::Command::Tenant(c)))
            .map_err(body("onboarding")),
        "auth" => auth_command(inner).map(CellCommand::Auth),
        "tenant" => tenant_command(inner)
            .map(CellCommand::Tenant)
            .map_err(body("tenant")),
        "text" => text_command(inner)
            .map(CellCommand::Text)
            .map_err(body("text")),
        "key" => key_command(inner)
            .map(CellCommand::Key)
            .map_err(body("key")),
        "release" => release_command(inner)
            .map(CellCommand::Release)
            .map_err(body("release")),
        "ops" => ops_command(inner)
            .map(CellCommand::Ops)
            .map_err(body("ops")),
        _ => Err(DecodeError::NotAnEnvelope),
    }
}

impl ToJson for CellCommand {
    fn to_json(&self) -> Value {
        match self {
            CellCommand::Engine(fstp_engine::Command::Core(c)) => wrap("core", c.to_json()),
            CellCommand::Engine(fstp_engine::Command::Finding(c)) => {
                wrap("finding", finding_command_json(c))
            }
            // M4 forms (lane m4eng). The decoder does not read them back yet;
            // the lead adds them with the cell routes of M4.
            CellCommand::Engine(fstp_engine::Command::Creator(c)) => wrap("creator", c.to_json()),
            CellCommand::Engine(fstp_engine::Command::Bridge(c)) => wrap("bridge", c.to_json()),
            CellCommand::Engine(fstp_engine::Command::Import(c)) => {
                wrap("import", fstp_engine::bridge::import_command_json(c))
            }
            // Lane m4tenant. The cell's own tenant commands hold the
            // member `tenant`, so the engine's tenant request goes under
            // `onboarding`, as its records do. The decoder reads it back.
            CellCommand::Engine(fstp_engine::Command::Tenant(c)) => {
                wrap("onboarding", fstp_engine::tenant::request_json(c))
            }
            // Lane mapp (R-EV-05): the plan the revision records, under
            // its own member. The decoder does not read it back yet; the
            // lead adds it with the cell route of `stage2.revise`.
            CellCommand::Engine(fstp_engine::Command::Stage2Revision(r)) => {
                let [plan, _] = r.commands();
                wrap("stage2_revision", plan.to_json())
            }
            // M5 lane L-CON. The decoder does not read it back yet; the
            // L-API lane adds it with the contract routes.
            CellCommand::Engine(fstp_engine::Command::Contract(c)) => wrap("contract", c.to_json()),
            CellCommand::Auth(c) => wrap("auth", auth_command_json(c)),
            CellCommand::Tenant(c) => wrap("tenant", tenant_command_json(c)),
            CellCommand::Text(c) => wrap("text", text_command_json(c)),
            CellCommand::Key(c) => wrap("key", key_command_json(c)),
            CellCommand::Release(c) => wrap("release", release_command_json(c)),
            CellCommand::Ops(c) => wrap("ops", ops_command_json(c)),
        }
    }
}

/// The finding command form: `type` is `Record`, `Mark` or `Regenerate`.
/// A `Record` holds the finding in the form of the finding codec. A
/// `Mark` holds the finding id and `agreed` or `disputed`. A `Regenerate`
/// holds the call, the configuration, the model and the findings.
fn finding_command_json(c: &FindingCommand) -> Value {
    match c {
        FindingCommand::Record(f) => tagged("Record", vec![("finding", f.to_json())]),
        FindingCommand::Mark { finding, mark } => tagged(
            "Mark",
            vec![
                ("finding", dec_u128(finding.raw())),
                (
                    "mark",
                    Value::String(
                        match mark {
                            Mark::Agreed => "agreed",
                            Mark::Disputed => "disputed",
                        }
                        .to_owned(),
                    ),
                ),
            ],
        ),
        FindingCommand::Regenerate {
            call,
            config,
            config_model,
            findings,
        } => tagged(
            "Regenerate",
            vec![
                ("call", dec_u128(call.raw())),
                ("config", dec_u128(config.raw())),
                ("config_model", Value::String(config_model.0.clone())),
                (
                    "findings",
                    Value::Array(findings.iter().map(ToJson::to_json).collect::<Array>()),
                ),
            ],
        ),
    }
}

fn finding_command(v: &Value) -> Result<FindingCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "Record" => {
            fields(o, &["finding"])?;
            Ok(FindingCommand::Record(Finding::from_json(member(
                o, "finding",
            )?)?))
        }
        "Mark" => {
            fields(o, &["finding", "mark"])?;
            let mark = match member(o, "mark")?.as_str() {
                Some("agreed") => Mark::Agreed,
                Some("disputed") => Mark::Disputed,
                _ => return Err(FromJsonError::invalid("not a mark").at_field("mark")),
            };
            Ok(FindingCommand::Mark {
                finding: FindingId::from_raw(u128_from(o, "finding")?),
                mark,
            })
        }
        "Regenerate" => {
            fields(o, &["call", "config", "config_model", "findings"])?;
            let model = member(o, "config_model")?
                .as_str()
                .ok_or_else(|| FromJsonError::invalid("not a model name").at_field("config_model"))?
                .to_owned();
            let list = member(o, "findings")?
                .as_array()
                .ok_or_else(|| FromJsonError::invalid("not a list").at_field("findings"))?;
            let mut findings = Vec::with_capacity(list.len());
            for (i, f) in list.iter().enumerate() {
                findings
                    .push(Finding::from_json(f).map_err(|e| e.at_index(i).at_field("findings"))?);
            }
            Ok(FindingCommand::Regenerate {
                call: CallId::from_raw(u128_from(o, "call")?),
                config: LlmConfigId::from_raw(u128_from(o, "config")?),
                config_model: ModelRef(model),
                findings,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn tenant_command_json(c: &TenantCommand) -> Value {
    match c {
        TenantCommand::GrantTenantAdmin { account } => tagged(
            "GrantTenantAdmin",
            vec![("account", account_json(*account))],
        ),
        TenantCommand::EndTenantAdmin { account } => {
            tagged("EndTenantAdmin", vec![("account", account_json(*account))])
        }
        TenantCommand::ApproveSelfGrant { grant_digest } => tagged(
            "ApproveSelfGrant",
            vec![("grant_digest", hex(grant_digest))],
        ),
        TenantCommand::SetLoginPolicy { policy } => {
            tagged("SetLoginPolicy", vec![("policy", opaque_json(policy))])
        }
        TenantCommand::IssueFirstAdminInvitation {
            invitation,
            account,
            token_digest,
        } => tagged(
            "IssueFirstAdminInvitation",
            vec![
                ("account", account_json(*account)),
                ("invitation", hex(invitation)),
                ("token_digest", hex(token_digest)),
            ],
        ),
        TenantCommand::EnrolByInvitation {
            invitation,
            credential,
        } => tagged(
            "EnrolByInvitation",
            vec![
                ("credential", hex(credential)),
                ("invitation", hex(invitation)),
            ],
        ),
    }
}

fn tenant_command(v: &Value) -> Result<TenantCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "GrantTenantAdmin" => {
            fields(o, &["account"])?;
            Ok(TenantCommand::GrantTenantAdmin {
                account: account_from(o, "account")?,
            })
        }
        "EndTenantAdmin" => {
            fields(o, &["account"])?;
            Ok(TenantCommand::EndTenantAdmin {
                account: account_from(o, "account")?,
            })
        }
        "ApproveSelfGrant" => {
            fields(o, &["grant_digest"])?;
            Ok(TenantCommand::ApproveSelfGrant {
                grant_digest: array_from(o, "grant_digest")?,
            })
        }
        "SetLoginPolicy" => {
            fields(o, &["policy"])?;
            Ok(TenantCommand::SetLoginPolicy {
                policy: opaque_from(o, "policy")?,
            })
        }
        "IssueFirstAdminInvitation" => {
            fields(o, &["account", "invitation", "token_digest"])?;
            Ok(TenantCommand::IssueFirstAdminInvitation {
                invitation: array_from(o, "invitation")?,
                account: account_from(o, "account")?,
                token_digest: array_from(o, "token_digest")?,
            })
        }
        "EnrolByInvitation" => {
            fields(o, &["credential", "invitation"])?;
            Ok(TenantCommand::EnrolByInvitation {
                invitation: array_from(o, "invitation")?,
                credential: bytes_from(o, "credential", MAX_CREDENTIAL)?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn text_command_json(c: &TextCommand) -> Value {
    match c {
        TextCommand::PutText { id } => tagged("PutText", vec![("id", hex(id))]),
        TextCommand::EraseTexts { ids, cause } => tagged(
            "EraseTexts",
            vec![
                ("cause", Value::Number(Number::from(*cause))),
                ("ids", id_list(ids)),
            ],
        ),
    }
}

fn text_command(v: &Value) -> Result<TextCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "PutText" => {
            fields(o, &["id"])?;
            Ok(TextCommand::PutText {
                id: array_from(o, "id")?,
            })
        }
        "EraseTexts" => {
            fields(o, &["cause", "ids"])?;
            Ok(TextCommand::EraseTexts {
                ids: id_list_from(o, "ids")?,
                cause: u16_from(o, "cause")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn key_command_json(c: &KeyCommand) -> Value {
    match c {
        KeyCommand::RecordKeyOp { op } => tagged("RecordKeyOp", vec![("op", opaque_json(op))]),
        KeyCommand::RecordEpochDestroyed { epoch, receipt } => tagged(
            "RecordEpochDestroyed",
            vec![
                ("epoch", Value::String(epoch.to_string())),
                ("receipt", hex(receipt)),
            ],
        ),
    }
}

fn key_command(v: &Value) -> Result<KeyCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "RecordKeyOp" => {
            fields(o, &["op"])?;
            Ok(KeyCommand::RecordKeyOp {
                op: opaque_from(o, "op")?,
            })
        }
        "RecordEpochDestroyed" => {
            fields(o, &["epoch", "receipt"])?;
            Ok(KeyCommand::RecordEpochDestroyed {
                epoch: u64_from(o, "epoch")?,
                receipt: array_from(o, "receipt")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn release_command_json(c: &ReleaseCommand) -> Value {
    match c {
        ReleaseCommand::IssueReleaseTicket { proposal } => tagged(
            "IssueReleaseTicket",
            vec![("proposal", dec_u128(*proposal))],
        ),
        ReleaseCommand::IssueWriteTicket { kind } => tagged(
            "IssueWriteTicket",
            vec![("kind", Value::Number(Number::from(*kind)))],
        ),
        ReleaseCommand::RecordRelationship { relationship } => tagged(
            "RecordRelationship",
            vec![("relationship", opaque_json(relationship))],
        ),
    }
}

fn release_command(v: &Value) -> Result<ReleaseCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "IssueReleaseTicket" => {
            fields(o, &["proposal"])?;
            Ok(ReleaseCommand::IssueReleaseTicket {
                proposal: u128_from(o, "proposal")?,
            })
        }
        "IssueWriteTicket" => {
            fields(o, &["kind"])?;
            Ok(ReleaseCommand::IssueWriteTicket {
                kind: u16_from(o, "kind")?,
            })
        }
        "RecordRelationship" => {
            fields(o, &["relationship"])?;
            Ok(ReleaseCommand::RecordRelationship {
                relationship: opaque_from(o, "relationship")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

fn ops_command_json(c: &OpsCommand) -> Value {
    match c {
        OpsCommand::ApproveBreakGlass { request } => {
            tagged("ApproveBreakGlass", vec![("request", hex(request))])
        }
        OpsCommand::EndBreakGlass { grant } => tagged("EndBreakGlass", vec![("grant", hex(grant))]),
        OpsCommand::ApplyOperatorTicket { ticket } => {
            tagged("ApplyOperatorTicket", vec![("ticket", opaque_json(ticket))])
        }
        OpsCommand::EndSessionsAtBindingEnd { account } => tagged(
            "EndSessionsAtBindingEnd",
            vec![("account", account_json(*account))],
        ),
    }
}

fn ops_command(v: &Value) -> Result<OpsCommand, FromJsonError> {
    let (tag, o) = variant(v)?;
    match tag {
        "ApproveBreakGlass" => {
            fields(o, &["request"])?;
            Ok(OpsCommand::ApproveBreakGlass {
                request: array_from(o, "request")?,
            })
        }
        "EndBreakGlass" => {
            fields(o, &["grant"])?;
            Ok(OpsCommand::EndBreakGlass {
                grant: array_from(o, "grant")?,
            })
        }
        "ApplyOperatorTicket" => {
            fields(o, &["ticket"])?;
            Ok(OpsCommand::ApplyOperatorTicket {
                ticket: opaque_from(o, "ticket")?,
            })
        }
        "EndSessionsAtBindingEnd" => {
            fields(o, &["account"])?;
            Ok(OpsCommand::EndSessionsAtBindingEnd {
                account: account_from(o, "account")?,
            })
        }
        _ => Err(unknown_variant()),
    }
}

// ---------------------------------------------------------------------------
// The canonical JSON text of `GrantRole` without `second_admin`.

/// The canonical text of an M2 command with its `second_admin` member
/// removed, as the SoD-07 grant digest takes it (design section 5.1).
/// `None` for a command that is not a `GrantRole`.
pub(crate) fn grant_without_second_admin(c: &fstp_domain::Command) -> Option<Vec<u8>> {
    if !matches!(c, fstp_domain::Command::GrantRole { .. }) {
        return None;
    }
    let mut v = c.to_json();
    let o = v.as_object_mut()?;
    o.remove("second_admin")?;
    // Fail closed: empty bytes would mean the canonical form failed.
    Some(canonical_bytes(&v)).filter(|b| !b.is_empty())
}

// ---------------------------------------------------------------------------
// Field helpers.

/// An object of one member.
fn wrap(member: &'static str, inner: Value) -> Value {
    let mut o = Object::with_capacity(1);
    o.insert(member, inner);
    Value::Object(o)
}

/// A variant object: `type` and the variant's members.
fn tagged(tag: &'static str, members: Vec<(&'static str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len().saturating_add(1));
    o.insert("type", Value::String(tag.to_owned()));
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// The variant tag and object of a variant value.
fn variant(v: &Value) -> Result<(&str, &Object), FromJsonError> {
    let o = expect_object(v)?;
    let tag = o
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| FromJsonError::invalid("no variant type").at_field("type"))?;
    Ok((tag, o))
}

/// Refuses an object whose members are not exactly `type` and `names`.
fn fields(o: &Object, names: &[&'static str]) -> Result<(), FromJsonError> {
    let mut all: Vec<&str> = Vec::with_capacity(names.len().saturating_add(1));
    all.push("type");
    all.extend_from_slice(names);
    reject_unknown(o, &all)?;
    for n in names {
        if !o.contains_key(n) {
            return Err(FromJsonError::new(FromJsonErrorKind::MissingField).at_field(n));
        }
    }
    Ok(())
}

fn member<'a>(o: &'a Object, name: &'static str) -> Result<&'a Value, FromJsonError> {
    o.get(name)
        .ok_or_else(|| FromJsonError::new(FromJsonErrorKind::MissingField).at_field(name))
}

fn unknown_variant() -> FromJsonError {
    FromJsonError::invalid("unknown variant").at_field("type")
}

fn str_of<'a>(o: &'a Object, name: &'static str) -> Result<&'a str, FromJsonError> {
    member(o, name)?
        .as_str()
        .ok_or_else(|| FromJsonError::invalid("not a string").at_field(name))
}

/// Lowercase hexadecimal of `bytes`.
fn hex(bytes: &[u8]) -> Value {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    Value::String(s)
}

/// The lowercase hexadecimal digit of a nibble.
fn hex_digit(n: u8) -> char {
    char::from_digit(u32::from(n), 16).unwrap_or('0')
}

/// The value of one lowercase hexadecimal digit.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|x| x.checked_add(10)),
        _ => None,
    }
}

/// Bytes from lowercase hexadecimal, at most `max` bytes.
fn unhex(s: &str, max: usize) -> Option<Vec<u8>> {
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) || raw.len() / 2 > max {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let (hi, lo) = match pair {
            [h, l] => (nibble(*h)?, nibble(*l)?),
            _ => return None,
        };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn bytes_from(o: &Object, name: &'static str, max: usize) -> Result<Vec<u8>, FromJsonError> {
    unhex(str_of(o, name)?, max)
        .ok_or_else(|| FromJsonError::invalid("not lowercase hexadecimal").at_field(name))
}

fn array_from<const N: usize>(o: &Object, name: &'static str) -> Result<[u8; N], FromJsonError> {
    let bytes = bytes_from(o, name, N)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| FromJsonError::invalid("wrong length").at_field(name))
}

fn id_list(ids: &[[u8; 16]]) -> Value {
    Value::Array(ids.iter().map(|id| hex(id)).collect::<Array>())
}

fn id_list_from(o: &Object, name: &'static str) -> Result<Vec<[u8; 16]>, FromJsonError> {
    let list = member(o, name)?
        .as_array()
        .ok_or_else(|| FromJsonError::invalid("not a list").at_field(name))?;
    if list.len() > MAX_TEXT_IDS {
        return Err(FromJsonError::invalid("too many ids").at_field(name));
    }
    let mut out = Vec::with_capacity(list.len());
    for (i, v) in list.iter().enumerate() {
        let bad = || {
            FromJsonError::invalid("not a 16-byte id")
                .at_index(i)
                .at_field(name)
        };
        let s = v.as_str().ok_or_else(bad)?;
        let bytes = unhex(s, 16).ok_or_else(bad)?;
        out.push(<[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| bad())?);
    }
    Ok(out)
}

fn dec_u128(n: u128) -> Value {
    Value::String(n.to_string())
}

fn account_json(a: AccountId) -> Value {
    dec_u128(a.raw())
}

/// Whether `s` is a canonical unsigned decimal: digits only, no leading
/// zero unless it is `0`.
fn canonical_unsigned(s: &str) -> bool {
    match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [b'0', ..] => false,
        b => b.iter().all(u8::is_ascii_digit),
    }
}

fn u128_from(o: &Object, name: &'static str) -> Result<u128, FromJsonError> {
    let s = str_of(o, name)?;
    if !canonical_unsigned(s) {
        return Err(FromJsonError::invalid("not a canonical decimal").at_field(name));
    }
    s.parse::<u128>().map_err(|_| {
        FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "u128" }).at_field(name)
    })
}

fn u64_from(o: &Object, name: &'static str) -> Result<u64, FromJsonError> {
    u64::try_from(u128_from(o, name)?).map_err(|_| {
        FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "u64" }).at_field(name)
    })
}

fn account_from(o: &Object, name: &'static str) -> Result<AccountId, FromJsonError> {
    u128_from(o, name).map(AccountId::from_raw)
}

/// A signed 64-bit decimal: an optional `-` before a canonical unsigned
/// decimal, never `-0`.
fn i64_from(o: &Object, name: &'static str) -> Result<i64, FromJsonError> {
    let s = str_of(o, name)?;
    let digits = s.strip_prefix('-').unwrap_or(s);
    if !canonical_unsigned(digits) || s == "-0" {
        return Err(FromJsonError::invalid("not a canonical decimal").at_field(name));
    }
    s.parse::<i64>().map_err(|_| {
        FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "i64" }).at_field(name)
    })
}

fn u16_from(o: &Object, name: &'static str) -> Result<u16, FromJsonError> {
    let n = member(o, name)?
        .as_number()
        .ok_or_else(|| FromJsonError::invalid("not a number").at_field(name))?;
    n.as_u64()
        .and_then(|x| u16::try_from(x).ok())
        .ok_or_else(|| {
            FromJsonError::new(FromJsonErrorKind::OutOfRange { target: "u16" }).at_field(name)
        })
}

/// An opaque canonical value as a string holding its text. The bytes are
/// carried as they are. The decoder checks that they are RFC 8785 text.
fn opaque_json(bytes: &[u8]) -> Value {
    Value::String(String::from_utf8_lossy(bytes).into_owned())
}

fn opaque_from(o: &Object, name: &'static str) -> Result<Vec<u8>, FromJsonError> {
    let s = str_of(o, name)?;
    if s.len() > MAX_OPAQUE {
        return Err(FromJsonError::invalid("opaque value too large").at_field(name));
    }
    let v = parse(s.as_bytes())
        .map_err(|_| FromJsonError::invalid("opaque value is not JSON").at_field(name))?;
    let text = to_canonical(&v)
        .map_err(|_| FromJsonError::invalid("opaque value is not canonical").at_field(name))?;
    if text != s {
        return Err(FromJsonError::invalid("opaque value is not canonical").at_field(name));
    }
    Ok(s.as_bytes().to_vec())
}
