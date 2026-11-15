//! The audit read models of a programme (R-AU-01, I-24, ADR-007,
//! `overview.md` NOTE 5): the ledger entries of the programme and the
//! vault answers its decisions used.
//!
//! Neither model holds a text. An entry names each text it references by
//! the text's id (ADR-007). An account appears by its id and its role in
//! the programme, never by a name or contact. A vault answer appears by
//! its query kind, query digest, answer bit and epoch only.

use fstp_domain::id::ProgrammeId;
use fstp_json::{Array, Object, ToJson, Value};

/// One audit read model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditModel {
    /// `audit.entries`.
    Entries(AuditLog),
    /// `audit.vault_outcomes`.
    VaultOutcomes(VaultOutcomes),
}

/// The ledger entries of one programme, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditLog {
    /// The programme.
    pub programme: ProgrammeId,
    /// The entries, newest first.
    pub entries: Vec<AuditRow>,
}

/// One ledger entry of the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// The sequence number.
    pub seq: u64,
    /// The instant, in UTC microseconds.
    pub at: i64,
    /// The side of the ledger envelope, such as `core` or `creator`.
    pub side: &'static str,
    /// The record kind, such as `BindingGranted`.
    pub kind: String,
    /// The acting account, if the record names one.
    pub actor: Option<u128>,
    /// The actor's role in the programme, `system` or `account`.
    pub actor_role: &'static str,
    /// What the record acts on: a kind and an id.
    pub object: Option<(&'static str, u128)>,
    /// The ids of the texts the record references (ADR-007).
    pub texts: Vec<u128>,
    /// The SHA-256 of the entry's stored RFC 8785 text, in lower-case
    /// hex (I-24).
    pub hash: String,
}

/// The vault answers the decisions of one programme used, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultOutcomes {
    /// The programme.
    pub programme: ProgrammeId,
    /// The answers.
    pub outcomes: Vec<VaultOutcomeRow>,
}

/// One recorded vault answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultOutcomeRow {
    /// The sequence number of its entry.
    pub seq: u64,
    /// The instant, in UTC microseconds.
    pub at: i64,
    /// The query kind.
    pub query: String,
    /// The query digest, in lower-case hex.
    pub digest: String,
    /// The answer bit.
    pub holds: bool,
    /// The vault epoch.
    pub epoch: u64,
}

fn dec(x: impl ToString) -> Value {
    Value::String(x.to_string())
}

impl ToJson for AuditRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("seq", dec(self.seq));
        let _ = o.insert("at", dec(self.at));
        let _ = o.insert("side", Value::from(self.side));
        let _ = o.insert("kind", Value::from(self.kind.as_str()));
        let _ = o.insert("actor", self.actor.map_or(Value::Null, dec));
        let _ = o.insert("actor_role", Value::from(self.actor_role));
        let (object_type, object) = match self.object {
            Some((t, id)) => (Value::from(t), dec(id)),
            None => (Value::Null, Value::Null),
        };
        let _ = o.insert("object_type", object_type);
        let _ = o.insert("object", object);
        let texts: Array = self.texts.iter().map(|t| dec(*t)).collect();
        let _ = o.insert("texts", Value::Array(texts));
        let _ = o.insert("hash", Value::from(self.hash.as_str()));
        Value::Object(o)
    }
}

impl ToJson for VaultOutcomeRow {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("seq", dec(self.seq));
        let _ = o.insert("at", dec(self.at));
        let _ = o.insert("query", Value::from(self.query.as_str()));
        let _ = o.insert("digest", Value::from(self.digest.as_str()));
        let _ = o.insert("holds", Value::Bool(self.holds));
        let _ = o.insert("epoch", dec(self.epoch));
        Value::Object(o)
    }
}

impl ToJson for AuditModel {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        match self {
            AuditModel::Entries(log) => {
                let _ = o.insert("programme", dec(log.programme.raw()));
                let rows: Array = log.entries.iter().map(ToJson::to_json).collect();
                let _ = o.insert("entries", Value::Array(rows));
            }
            AuditModel::VaultOutcomes(v) => {
                let _ = o.insert("programme", dec(v.programme.raw()));
                let rows: Array = v.outcomes.iter().map(ToJson::to_json).collect();
                let _ = o.insert("outcomes", Value::Array(rows));
            }
        }
        Value::Object(o)
    }
}

/// One sample of each model, with every member set and each nullable
/// member null once, for the shape tests.
#[cfg(test)]
pub(crate) fn samples() -> Vec<AuditModel> {
    vec![
        AuditModel::Entries(AuditLog {
            programme: ProgrammeId::from_raw(1),
            entries: vec![
                AuditRow {
                    seq: 9,
                    at: 2,
                    side: "core",
                    kind: "PartyUnmasked".to_owned(),
                    actor: Some(3),
                    actor_role: "fstp_coordinator",
                    object: Some(("programme", 1)),
                    texts: vec![4],
                    hash: "ab".repeat(32),
                },
                AuditRow {
                    seq: 8,
                    at: 1,
                    side: "creator",
                    kind: "ProbeRecorded".to_owned(),
                    actor: None,
                    actor_role: "system",
                    object: None,
                    texts: Vec::new(),
                    hash: "cd".repeat(32),
                },
            ],
        }),
        AuditModel::VaultOutcomes(VaultOutcomes {
            programme: ProgrammeId::from_raw(1),
            outcomes: vec![VaultOutcomeRow {
                seq: 5,
                at: 6,
                query: "SameIdentityAsAny".to_owned(),
                digest: "ef".repeat(32),
                holds: false,
                epoch: 7,
            }],
        }),
    ]
}
