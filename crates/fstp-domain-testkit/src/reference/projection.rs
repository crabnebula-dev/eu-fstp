//! Independent reference for the journey projector (I-92, I-97, I-27,
//! R-JV-11).
//!
//! Written from `SPEC/12-journey-ui.md` sections 3, 7.1, 7.3 and 11 and
//! ADR-015 "Read model only", lane j2 test author. It reads ledger entries
//! only, through the domain and engine record types and the codec's
//! stored form, never through the projector.
//!
//! - [`generated_ledger`] drives the I-23 ledger machine of
//!   [`crate::mc::ledger_model`] over the full engine from genesis, so the
//!   projector tests fold real ledgers: policy versions, calls, roles,
//!   submissions, the stage 1 and stage 2 paths with questions and
//!   answers, scores, corrections, the cut-off, negotiation and payments.
//! - [`stored_copy`] decodes each entry from its stored bytes, as a
//!   rebuild from the database reads it.
//! - [`legs`] and [`positions`] are the route of each proposal: one leg
//!   per `Transitioned` record, and the state of its last leg, or DRAFT
//!   from its `ProposalCreated` record.
//! - [`text_refs`] lists every `TextRef` a record holds, read from the
//!   codec's stored form, so nested references count too.
//! - [`seed_canary`] writes [`CANARY`] into every free-text field a
//!   ledger record can hold: the opaque policy values, the pinned model
//!   names and the deadline zones. No journey row or reply may hold it.
//!
//! Readings taken here, interim, pending Daniel:
//!
//! - A leg's time is the `at` of its ledger entry, and its sequence
//!   number the entry's own.
//! - A proposal with no transition yet stands at DRAFT since its
//!   `ProposalCreated` entry.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::id::{ContentDigest, ProposalId, TextId, TextRef};
use fstp_domain::policy::{
    FunderProfileRef, IrcExemptions, ModelRef, OpaqueValue, PolicyVersion, TieBreakRule,
    VotingRules,
};
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::time::ZoneName;
use fstp_engine::{EnvelopeKind, Record, envelope_from_json};
use fstp_json::{FromJson, Value};
use fstp_ledger::Entry;
use fstp_prop::{Gen, StateMachine};

use crate::mc::ledger_model::{Canon, LedgerMachine, stored_json, witness_run};

/// The canary text. It holds spaces, as free text does.
pub const CANARY: &str = "CANARY free text JOURNEYx7f3a9c";

/// The part of the canary every seeded field carries, the zone included.
pub const CANARY_MARK: &str = "JOURNEYx7f3a9c";

/// The canary as a zone name, which allows no spaces.
pub const CANARY_ZONE: &str = "Canary/JOURNEYx7f3a9c";

// ---------------------------------------------------------------------------
// Ledgers

/// A ledger of the I-23 machine: genesis, then up to `max_commands`
/// commands drawn by `g`. A machine step that fails its own batch
/// checks ends the case as a failure with the machine's message.
pub fn generated_ledger(g: &mut Gen, max_commands: usize) -> Result<Vec<Entry<Record>>, String> {
    let m = LedgerMachine::new(max_commands);
    let mut model = m.init_model();
    let mut sut = m.init_sut();
    for _ in 0..max_commands.saturating_add(1) {
        let cmd = m.command(g, &model);
        if !m.precondition(&model, &cmd) {
            continue;
        }
        let out = m.run(&mut sut, &cmd);
        m.next_state(&mut model, &cmd);
        if let Err(e) = out.applied {
            return Err(format!("ledger machine step {}: {e}", out.context));
        }
    }
    sut.run
        .map(|r| r.ledger)
        .ok_or_else(|| "the ledger machine ran no setup".to_owned())
}

/// The ledger of the scripted I-23 witness run, which reaches NEGOTIATION
/// with stage 2 questions, answers, a revision and corrections.
pub fn witness_ledger() -> Result<Vec<Entry<Record>>, String> {
    witness_run().map(|r| r.ledger)
}

/// Decodes a stored record of schema version `schema`.
fn decode_record(schema: u16, value: &Value) -> Result<Record, String> {
    let (kind, inner) =
        envelope_from_json(value).map_err(|e| format!("the envelope does not decode: {e:?}"))?;
    match kind {
        EnvelopeKind::Core => fstp_domain::codec::record_from_json_at(schema, inner)
            .map(Record::Core)
            .map_err(|e| format!("the core record does not decode: {e:?}")),
        EnvelopeKind::Finding => Err("the testkit has no finding decoder".to_owned()),
        EnvelopeKind::Creator | EnvelopeKind::Import | EnvelopeKind::Tenant => {
            fstp_engine::record_from_json_at(schema, value)
                .map_err(|e| format!("the engine record does not decode: {e:?}"))
        }
    }
}

/// Each entry decoded again from its stored bytes (ADR-007), as a rebuild
/// from the database reads it. Finding entries, which have no codec in
/// the testkit, are kept as they are.
pub fn stored_copy(entries: &[Entry<Record>]) -> Result<Vec<Entry<Record>>, String> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if matches!(e.record, Record::Finding(_)) {
            out.push(e.clone());
            continue;
        }
        let n = e.seq.raw();
        let text = e
            .clone()
            .map_record(Canon)
            .canonical_text()
            .map_err(|err| format!("entry {n} has no stored form: {err}"))?;
        let value = fstp_json::parse(text.as_bytes())
            .map_err(|err| format!("the stored text of entry {n} does not parse: {err:?}"))?;
        let raw = Entry::<Value>::from_json(&value)
            .map_err(|err| format!("the stored entry {n} does not decode: {err:?}"))?;
        let decoded = raw
            .try_map_record(|schema, v| decode_record(schema, &v))
            .map_err(|err| format!("stored entry {n}: {err}"))?;
        out.push(decoded);
    }
    Ok(out)
}

/// The core record of an entry, if it holds one.
pub fn core(e: &Entry<Record>) -> Option<&CoreRecord> {
    match &e.record {
        Record::Core(r) => Some(r),
        Record::Finding(_) | Record::Creator(_) | Record::Import(_) | Record::Tenant(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Routes

/// One completed leg of a proposal's route, as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Leg {
    /// The state left.
    pub from: StateTag,
    /// The state reached.
    pub to: StateTag,
    /// The time of the ledger entry.
    pub at: i64,
    /// The sequence number of the ledger entry.
    pub seq: u64,
}

/// A proposal's current position, as the reference sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Place {
    /// The current state.
    pub node: StateTag,
    /// When the proposal reached it.
    pub since: i64,
    /// The sequence number of the record that put it there.
    pub seq: u64,
}

/// Every proposal's legs, in ledger order.
pub fn legs(entries: &[Entry<Record>]) -> BTreeMap<ProposalId, Vec<Leg>> {
    let mut out: BTreeMap<ProposalId, Vec<Leg>> = BTreeMap::new();
    for e in entries {
        if let Some(CoreRecord::Transitioned(t)) = core(e) {
            out.entry(t.proposal).or_default().push(Leg {
                from: t.from,
                to: t.to,
                at: e.at,
                seq: e.seq.raw(),
            });
        }
    }
    out
}

/// Every proposal's current position.
pub fn positions(entries: &[Entry<Record>]) -> BTreeMap<ProposalId, Place> {
    let mut out: BTreeMap<ProposalId, Place> = BTreeMap::new();
    for e in entries {
        match core(e) {
            Some(CoreRecord::ProposalCreated { proposal, .. }) => {
                out.entry(*proposal).or_insert(Place {
                    node: StateTag::Draft,
                    since: e.at,
                    seq: e.seq.raw(),
                });
            }
            Some(CoreRecord::Transitioned(t)) => {
                out.insert(
                    t.proposal,
                    Place {
                        node: t.to,
                        since: e.at,
                        seq: e.seq.raw(),
                    },
                );
            }
            _ => {}
        }
    }
    out
}

/// The sequence numbers of the `Transitioned` entries, with their proposal.
pub fn transition_seqs(entries: &[Entry<Record>]) -> BTreeMap<u64, ProposalId> {
    entries
        .iter()
        .filter_map(|e| match core(e) {
            Some(CoreRecord::Transitioned(t)) => Some((e.seq.raw(), t.proposal)),
            _ => None,
        })
        .collect()
}

/// The sequence numbers of the stage 2 question and answer entries, with
/// the text each one references (section 7.2 "Clarification").
pub fn clarification_texts(entries: &[Entry<Record>]) -> BTreeMap<u64, (ProposalId, TextRef)> {
    entries
        .iter()
        .filter_map(|e| match core(e) {
            Some(CoreRecord::QuestionAsked { proposal, text, .. })
            | Some(CoreRecord::AnswersRecorded { proposal, text }) => {
                Some((e.seq.raw(), (*proposal, *text)))
            }
            _ => None,
        })
        .collect()
}

/// The sequence numbers of the entries that hold a message record: an
/// outbox event, which is the seam of every notification (I-27, I-29).
pub fn message_seqs(entries: &[Entry<Record>]) -> Vec<u64> {
    entries
        .iter()
        .filter(|e| matches!(core(e), Some(CoreRecord::OutboxEnqueued(_))))
        .map(|e| e.seq.raw())
        .collect()
}

// ---------------------------------------------------------------------------
// Text references

/// The digit value of one hexadecimal character.
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// The 32 bytes of a lowercase hexadecimal digest.
fn digest_of(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        let v = hex_digit(*hi)?
            .checked_mul(16)?
            .checked_add(hex_digit(*lo)?)?;
        *slot = v;
    }
    Some(out)
}

/// Collects the text references of a stored value: every object with
/// exactly the members `id` (a decimal string) and `digest` (64 lowercase
/// hexadecimal digits), which is the codec's form of a `TextRef`.
fn collect_refs(v: &Value, out: &mut Vec<TextRef>) {
    match v {
        Value::Object(o) => {
            if o.len() == 2
                && let (Some(id), Some(d)) = (
                    o.get("id").and_then(Value::as_str),
                    o.get("digest").and_then(Value::as_str),
                )
                && let (Ok(id), Some(d)) = (id.parse::<u128>(), digest_of(d))
            {
                out.push(TextRef::new(
                    TextId::from_raw(id),
                    ContentDigest::from_bytes(d),
                ));
                return;
            }
            for (_, member) in o.iter() {
                collect_refs(member, out);
            }
        }
        Value::Array(a) => {
            for item in a {
                collect_refs(item, out);
            }
        }
        _ => {}
    }
}

/// Every text reference `record` holds, nested ones included.
pub fn text_refs(record: &Record) -> Vec<TextRef> {
    let mut out = Vec::new();
    if let Some(v) = stored_json(record) {
        collect_refs(&v, &mut out);
    }
    out
}

/// The text references of every entry, by sequence number.
pub fn text_refs_by_seq(entries: &[Entry<Record>]) -> BTreeMap<u64, Vec<TextRef>> {
    entries
        .iter()
        .map(|e| (e.seq.raw(), text_refs(&e.record)))
        .filter(|(_, refs)| !refs.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// The canary

/// The opaque value of the canary text.
fn canary_value() -> Result<OpaqueValue, String> {
    OpaqueValue::from_value(&Value::String(CANARY.to_owned()))
        .map_err(|e| format!("canary value: {e:?}"))
}

/// Writes the canary into every free-text field of a policy version.
fn seed_version(v: &mut PolicyVersion) -> Result<usize, String> {
    let canary = canary_value()?;
    let mut n: usize = 0;
    for value in v.frozen.opaque.values_mut() {
        *value = canary.clone();
        n = n.saturating_add(1);
    }
    for value in v.live.opaque.values_mut() {
        *value = canary.clone();
        n = n.saturating_add(1);
    }
    v.frozen.p14 = IrcExemptions(canary.clone());
    v.frozen.p16 = VotingRules(canary.clone());
    v.frozen.p17 = TieBreakRule(canary.clone());
    v.frozen.p53 = FunderProfileRef(canary.clone());
    v.frozen.p21.provider = canary;
    v.frozen.p21.primary = ModelRef(CANARY.to_owned());
    for m in &mut v.frozen.p21.fallbacks {
        *m = ModelRef(CANARY.to_owned());
    }
    Ok(n.saturating_add(6))
}

/// The ledger with [`CANARY`] written into every free-text field its
/// records hold, and how many fields were seeded. The records need not
/// replay through the engine: the projector folds, it does not decide.
pub fn seed_canary(entries: &[Entry<Record>]) -> Result<(Vec<Entry<Record>>, usize), String> {
    let zone = ZoneName::new(CANARY_ZONE).ok_or("the canary zone is not a zone name")?;
    let mut seeded: usize = 0;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let mut e = e.clone();
        if let Record::Core(r) = &mut e.record {
            match r {
                CoreRecord::PolicyVersionRecorded { version, .. } => {
                    seeded = seeded.saturating_add(seed_version(version)?);
                }
                CoreRecord::CallDrafted { deadline_zone, .. }
                | CoreRecord::CallEdited { deadline_zone, .. } => {
                    *deadline_zone = zone.clone();
                    seeded = seeded.saturating_add(1);
                }
                _ => {}
            }
        }
        out.push(e);
    }
    Ok((out, seeded))
}

/// Whether `bytes` hold the canary mark anywhere.
pub fn holds_canary(bytes: &[u8]) -> bool {
    let mark = CANARY_MARK.as_bytes();
    bytes.windows(mark.len()).any(|w| w == mark)
}
