//! The report of a serving custody simulator (lane m3/custody-decisions).
//!
//! A world in process mode runs each cell's custody as its own
//! `fstp-custody-sim` process ([`super::serve`]). The test that started it
//! must know the root bytes and the seal keys custody saw, so the I-80
//! scans can look for them, and no byte of them may pass through the cell.
//! The simulator therefore appends one fixed-size record to a report file
//! that only the test reads:
//!
//! ```text
//! record = kind u8 | chain u8 | epoch u64 | bytes 32          42 bytes
//! kind   = 1 root created (bytes: the root)
//!        | 2 seal key wrapped (bytes: the seal key S(e))
//!        | 3 root destroyed (bytes: 32 zero bytes)
//! ```
//!
//! Integers are big-endian. [`decode`] accepts exactly one spelling: a
//! whole number of records, known kinds and chains, and zero bytes in a
//! destroy record. It is fuzzed (`custody_sim_report_decode`).

use fstp_custody::Chain;

use crate::NotImplemented;

/// The length of one record.
pub const RECORD_LEN: usize = 42;

/// What a record reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A root was created. The bytes are the root.
    Root,
    /// A seal key was wrapped under the root of the chain and epoch. The
    /// bytes are the seal key.
    Seal,
    /// The root of the chain and epoch was destroyed.
    Destroyed,
}

impl Kind {
    const fn code(self) -> u8 {
        match self {
            Kind::Root => 1,
            Kind::Seal => 2,
            Kind::Destroyed => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Root),
            2 => Some(Kind::Seal),
            3 => Some(Kind::Destroyed),
            _ => None,
        }
    }
}

/// One record. Its `Debug` form never shows the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// What it reports.
    pub kind: Kind,
    /// The chain of the root.
    pub chain: Chain,
    /// The epoch of the root.
    pub epoch: u64,
    /// The root or seal key, or zero bytes for a destroy.
    pub bytes: [u8; 32],
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.kind)
            .field("chain", &self.chain)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Record {
    /// The record's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        let (head, rest) = out.split_at_mut(2);
        head.copy_from_slice(&[self.kind.code(), self.chain.code()]);
        let (epoch, bytes) = rest.split_at_mut(8);
        epoch.copy_from_slice(&self.epoch.to_be_bytes());
        bytes.copy_from_slice(&self.bytes);
        out
    }
}

/// The refusal of a report that breaks the format.
const MALFORMED: &str = "fstp_celltest::custody_sim::report: the report breaks its format";

/// Decodes a whole report.
///
/// # Errors
///
/// Refuses a partial record, an unknown kind or chain, and a destroy
/// record whose bytes are not zero.
pub fn decode(bytes: &[u8]) -> Result<Vec<Record>, NotImplemented> {
    let (records, rest) = bytes.as_chunks::<RECORD_LEN>();
    if !rest.is_empty() {
        return Err(NotImplemented::new(MALFORMED));
    }
    records
        .iter()
        .map(|r| {
            let (&[kind, chain], rest) = r
                .split_first_chunk::<2>()
                .ok_or(NotImplemented::new(MALFORMED))?;
            let (epoch, body) = rest
                .split_first_chunk::<8>()
                .ok_or(NotImplemented::new(MALFORMED))?;
            let kind = Kind::from_code(kind).ok_or(NotImplemented::new(MALFORMED))?;
            let chain = Chain::from_code(chain).ok_or(NotImplemented::new(MALFORMED))?;
            let bytes: [u8; 32] = body
                .try_into()
                .map_err(|_| NotImplemented::new(MALFORMED))?;
            if kind == Kind::Destroyed && bytes != [0; 32] {
                return Err(NotImplemented::new(MALFORMED));
            }
            Ok(Record {
                kind,
                chain,
                epoch: u64::from_be_bytes(*epoch),
                bytes,
            })
        })
        .collect()
}

/// The roots of `records`, in order of creation, with their chain and
/// epoch.
#[must_use]
pub fn roots(records: &[Record]) -> Vec<&Record> {
    records.iter().filter(|r| r.kind == Kind::Root).collect()
}

/// The seal keys of `records`, each with whether the root it was wrapped
/// under has been destroyed since.
#[must_use]
pub fn seal_keys(records: &[Record]) -> Vec<(&Record, bool)> {
    records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == Kind::Seal)
        .map(|(i, r)| {
            let destroyed = records
                .iter()
                .skip(i)
                .any(|d| d.kind == Kind::Destroyed && d.chain == r.chain && d.epoch == r.epoch);
            (r, destroyed)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn rec(kind: Kind, chain: Chain, epoch: u64, b: u8) -> Record {
        Record {
            kind,
            chain,
            epoch,
            bytes: [b; 32],
        }
    }

    /// I-80 harness: a report decodes to the records written, and a seal
    /// key counts as destroyed only after its root's destroy record.
    #[test]
    fn i80_harness_custody_report_round_trips() {
        let records = vec![
            rec(Kind::Root, Chain::App, 0, 1),
            rec(Kind::Seal, Chain::App, 0, 2),
            rec(Kind::Destroyed, Chain::App, 0, 0),
            rec(Kind::Root, Chain::App, 1, 3),
            rec(Kind::Seal, Chain::App, 1, 4),
            rec(Kind::Seal, Chain::Vault, 0, 5),
        ];
        let bytes: Vec<u8> = records.iter().flat_map(Record::encode).collect();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, records);
        assert_eq!(roots(&back).len(), 2);
        let seals: Vec<(u8, bool)> = seal_keys(&back)
            .into_iter()
            .map(|(r, d)| (r.bytes[0], d))
            .collect();
        assert_eq!(seals, vec![(2, true), (4, false), (5, false)]);
    }

    /// I-80 harness: a partial record, an unknown kind or chain, and a
    /// destroy record with bytes are refused.
    #[test]
    fn i80_harness_custody_report_refuses_other_spellings() {
        let good = rec(Kind::Root, Chain::App, 7, 9).encode();
        assert!(decode(&good[..RECORD_LEN - 1]).is_err());
        let mut kind = good;
        kind[0] = 4;
        assert!(decode(&kind).is_err());
        let mut chain = good;
        chain[1] = 9;
        assert!(decode(&chain).is_err());
        let mut destroyed = good;
        destroyed[0] = Kind::Destroyed.code();
        assert!(decode(&destroyed).is_err());
        assert_eq!(decode(&[]).unwrap(), Vec::new());
    }
}
