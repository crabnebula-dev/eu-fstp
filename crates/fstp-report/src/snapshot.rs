//! The data snapshot a funder document is generated from (R-RP-01).
//!
//! A snapshot is a prefix of the core ledger: its entries in ledger order,
//! each with its sequence number, its time and its record. Its digest is
//! the SHA-256 over one canonical JSON line per entry, so equal ledgers
//! give equal digests whatever store they came from.

use fstp_domain::Record;
use fstp_domain::id::ContentDigest;
use fstp_domain::time::Timestamp;
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::Seq;

use crate::ReportError;

/// One ledger entry of a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its position in the ledger.
    pub seq: Seq,
    /// Its time.
    pub at: Timestamp,
    /// Its core record.
    pub record: Record,
}

/// A snapshot of the core ledger (module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    entries: Vec<Entry>,
}

impl Snapshot {
    /// The snapshot of `entries`. Sequence numbers must rise strictly and
    /// times must not fall.
    pub fn new(entries: Vec<Entry>) -> Result<Snapshot, ReportError> {
        for w in entries.windows(2) {
            if let [a, b] = w {
                if b.seq <= a.seq {
                    return Err(ReportError::Snapshot("sequence numbers do not rise"));
                }
                if b.at < a.at {
                    return Err(ReportError::Snapshot("times fall"));
                }
            }
        }
        Ok(Snapshot { entries })
    }

    /// The entries in ledger order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The sequence number of the last entry, or zero when empty.
    pub fn head(&self) -> Seq {
        self.entries.last().map_or(Seq::ZERO, |e| e.seq)
    }

    /// The SHA-256 over one canonical line per entry (module
    /// documentation).
    pub fn digest(&self) -> Result<ContentDigest, ReportError> {
        let mut h = fstp_crypto::Sha256::new();
        for e in &self.entries {
            h.update(entry_line(e)?.as_bytes());
            h.update(b"\n");
        }
        Ok(ContentDigest::from_bytes(h.finish()))
    }
}

/// The canonical JSON line of one entry.
fn entry_line(e: &Entry) -> Result<String, ReportError> {
    let mut o = Object::new();
    o.insert("seq", Value::String(e.seq.raw().to_string()));
    o.insert("at", Value::String(e.at.micros().to_string()));
    o.insert("record", e.record.to_json());
    Value::Object(o)
        .to_canonical()
        .map_err(|_| ReportError::Encoding)
}

/// The SHA-256 of the canonical JSON of `record`, as the audit file lists
/// it.
pub(crate) fn record_digest(record: &Record) -> Result<[u8; 32], ReportError> {
    let text = record
        .to_json()
        .to_canonical()
        .map_err(|_| ReportError::Encoding)?;
    Ok(fstp_crypto::sha256(text.as_bytes()))
}
