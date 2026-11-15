//! The audit reads of a programme (R-AU-01, I-24, ADR-007, `overview.md`
//! NOTE 5). `authorize_read` cleared the caller as the auditor of the
//! programme first (`roles-and-sod.md`, roles table).
//!
//! - `audit.entries` lists the ledger entries of the programme, newest
//!   first. An entry belongs to the programme when its record names the
//!   programme, or names a call, proposal, assignment or binding of it, at
//!   its top level or one level down. So the admin acts on the programme
//!   show (role grants, the activation and an I-67 override, ADR-022), and
//!   so does every unmask (ADR-023).
//! - Each row names its side, record kind, acting account and that
//!   account's role in the programme, the object it acts on, and the ids
//!   of the texts it references. ADR-007: a text is never read here, only
//!   its id is named. The hash is the SHA-256 of the entry's stored text
//!   (I-24), so a row checks against the ledger.
//! - `audit.vault_outcomes` lists the `VaultOutcome` records whose command
//!   also appended an entry of the programme: the query kind, its digest,
//!   the answer bit and the epoch, never the query (NOTE 5).
//!
//! Interim readings, pending Daniel:
//!
//! - Tenant records, such as onboarding steps and tenant settings, name
//!   no programme, so no programme's log lists them.
//! - The vault answers of a dry run go to the vault audit port, which has
//!   no read. Only the answers a committed decision recorded are listed.
//! - The actor's role is a role the account holds or held in the
//!   programme, else `tenant_admin` for a tenant admin, else `account`.
//!   A record that names no account is the system's.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, AssignmentId, BindingId, CallId, ProgrammeId, ProposalId};
use fstp_engine::{EngineState, EnvelopeKind, Record};
use fstp_json::{ToJson, Value};

use super::{Call, Seams};
use crate::audit::{AuditLog, AuditModel, AuditRow, VaultOutcomeRow, VaultOutcomes};
use crate::port::{AsyncEngine as _, TenantConfig as _};
use crate::{ApiError, ErrorCode, ReadModel};

/// The members that name the acting account, in the order a row picks.
const ACTOR_KEYS: [&str; 7] = [
    "by",
    "granted_by",
    "author",
    "approver",
    "actor",
    "requested_by",
    "uploaded_by",
];

/// The members that name what a record acts on, in the order a row
/// picks. Each is an object type of the reply shape.
const OBJECT_KEYS: [&str; 7] = [
    "proposal",
    "call",
    "assignment",
    "binding",
    "request",
    "decision",
    "programme",
];

/// The reads of this module: which one `entries` names.
pub(super) fn read<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    entries: bool,
) -> Result<ReadModel, ApiError> {
    let ledger = call
        .ports
        .engine()
        .ledger()
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::Unavailable, "audit")))?;
    let state: &EngineState = &call.state;
    let model = if entries {
        let is_admin = |a: AccountId| call.ports.tenant().is_tenant_admin(a);
        AuditModel::Entries(log(state, &ledger, programme, &is_admin))
    } else {
        AuditModel::VaultOutcomes(outcomes(state, &ledger, programme))
    };
    Ok(ReadModel::Audit(model))
}

/// The inner JSON of a record: the value of its one envelope member.
fn inner(record: &Record) -> Value {
    match record.to_json() {
        Value::Object(o) => o
            .iter()
            .next()
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// The id a member holds: a canonical decimal string.
fn id_of(v: &Value) -> Option<u128> {
    let s = v.as_str()?;
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The programme of a binding, held or ended.
fn binding_programme(state: &EngineState, id: BindingId) -> Option<ProgrammeId> {
    let roster = state.core.roster();
    roster
        .bindings()
        .find(|(b, _)| *b == id)
        .map(|(_, b)| b.programme)
        .or_else(|| {
            roster
                .ended()
                .find(|(b, _)| *b == id)
                .map(|(_, e)| e.binding.programme)
        })
}

/// The programme that member `name` with value `v` names, if any.
fn programme_named(state: &EngineState, name: &str, v: &Value) -> Option<ProgrammeId> {
    let id = id_of(v)?;
    match name {
        "programme" => Some(ProgrammeId::from_raw(id)),
        "call" => crate::forms::programme_of_call(state, CallId::from_raw(id)),
        "proposal" => super::grant::programme_of(state, ProposalId::from_raw(id)),
        "assignment" => state
            .core
            .review()
            .get(AssignmentId::from_raw(id))
            .and_then(|a| super::grant::programme_of(state, a.proposal)),
        "binding" => binding_programme(state, BindingId::from_raw(id)),
        _ => None,
    }
}

/// The programmes the record JSON `v` names at its top level and one
/// level down.
fn programmes_of(state: &EngineState, v: &Value) -> BTreeSet<ProgrammeId> {
    let mut out = BTreeSet::new();
    let Some(o) = v.as_object() else {
        return out;
    };
    for (name, member) in o.iter() {
        if let Some(p) = programme_named(state, name, member) {
            out.insert(p);
        }
        if let Some(inner) = member.as_object() {
            for (n, m) in inner.iter() {
                if let Some(p) = programme_named(state, n, m) {
                    out.insert(p);
                }
            }
        }
    }
    out
}

/// The text ids a record JSON references: every object of exactly the
/// members `id` and `digest`, as a `TextRef` is written (ADR-007).
fn text_ids(v: &Value, depth: u8, out: &mut BTreeSet<u128>) {
    if depth > 4 {
        return;
    }
    match v {
        Value::Object(o) => {
            let is_ref = o.len() == 2 && o.contains_key("digest");
            match (is_ref, o.get("id").and_then(id_of)) {
                (true, Some(id)) => {
                    out.insert(id);
                }
                _ => {
                    for (_, m) in o.iter() {
                        text_ids(m, depth.saturating_add(1), out);
                    }
                }
            }
        }
        Value::Array(a) => {
            for m in a.iter() {
                text_ids(m, depth.saturating_add(1), out);
            }
        }
        _ => {}
    }
}

/// The record kind: the `type` or `kind` tag of the inner record.
fn kind_of(v: &Value) -> String {
    let o = v.as_object();
    o.and_then(|o| o.get("type"))
        .or_else(|| o.and_then(|o| o.get("kind")))
        .and_then(Value::as_str)
        .unwrap_or("record")
        .to_owned()
}

/// The role a row names for `actor` in `programme`.
fn role_of(
    state: &EngineState,
    programme: ProgrammeId,
    actor: AccountId,
    is_admin: &dyn Fn(AccountId) -> bool,
) -> &'static str {
    let roster = state.core.roster();
    let held = roster
        .bindings()
        .map(|(_, b)| b)
        .chain(roster.ended().map(|(_, e)| &e.binding))
        .filter(|b| b.account == actor && b.programme == programme)
        .map(|b| b.role)
        .min();
    match held {
        Some(role) => fstp_access::role_wire_name(role),
        None if is_admin(actor) => "tenant_admin",
        None => "account",
    }
}

/// The audit log of `programme` over `ledger`, newest first.
fn log(
    state: &EngineState,
    ledger: &[fstp_ledger::Entry<Record>],
    programme: ProgrammeId,
    is_admin: &dyn Fn(AccountId) -> bool,
) -> AuditLog {
    let mut entries = Vec::new();
    for e in ledger.iter().rev() {
        let v = inner(&e.record);
        if !programmes_of(state, &v).contains(&programme) {
            continue;
        }
        let o = v.as_object();
        let actor = o.and_then(|o| ACTOR_KEYS.iter().find_map(|k| o.get(k).and_then(id_of)));
        let object = o.and_then(|o| {
            OBJECT_KEYS
                .iter()
                .find_map(|k| o.get(k).and_then(id_of).map(|id| (*k, id)))
        });
        let mut texts = BTreeSet::new();
        text_ids(&v, 0, &mut texts);
        let hash = e
            .canonical_text()
            .map(|t| crate::action::hex(&fstp_crypto::sha256(t.as_bytes())))
            .unwrap_or_default();
        entries.push(AuditRow {
            seq: e.seq.raw(),
            at: e.at,
            side: EnvelopeKind::of(&e.record).member(),
            kind: kind_of(&v),
            actor,
            actor_role: actor.map_or("system", |a| {
                role_of(state, programme, AccountId::from_raw(a), is_admin)
            }),
            object,
            texts: texts.into_iter().collect(),
            hash,
        });
    }
    AuditLog { programme, entries }
}

/// The vault answers the decisions of `programme` used, newest first.
fn outcomes(
    state: &EngineState,
    ledger: &[fstp_ledger::Entry<Record>],
    programme: ProgrammeId,
) -> VaultOutcomes {
    let mut of_command: BTreeMap<[u8; 16], bool> = BTreeMap::new();
    for e in ledger {
        if is_outcome(&e.record) {
            continue;
        }
        if programmes_of(state, &inner(&e.record)).contains(&programme) {
            of_command.insert(e.command, true);
        }
    }
    let mut out = Vec::new();
    for e in ledger.iter().rev() {
        let Record::Core(fstp_domain::record::Record::VaultOutcome {
            digest,
            holds,
            epoch,
            ..
        }) = &e.record
        else {
            continue;
        };
        if !of_command.contains_key(&e.command) {
            continue;
        }
        out.push(VaultOutcomeRow {
            seq: e.seq.raw(),
            at: e.at,
            query: kind_of_query(&inner(&e.record)),
            digest: crate::action::hex(&digest.bytes()),
            holds: *holds,
            epoch: epoch.raw(),
        });
    }
    VaultOutcomes {
        programme,
        outcomes: out,
    }
}

fn is_outcome(r: &Record) -> bool {
    matches!(
        r,
        Record::Core(fstp_domain::record::Record::VaultOutcome { .. })
    )
}

/// The query kind of a `VaultOutcome`, as the record codec writes it.
fn kind_of_query(v: &Value) -> String {
    v.as_object()
        .and_then(|o| o.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("query")
        .to_owned()
}
