//! The usage record of a custody backend and the reconciliation of a
//! usage log with a chain's `KeyOp` records (ADR-004 "Reconciliation").
//!
//! Every custody call carries a [`RequestId`]. A backend that keeps a
//! usage log writes one record per call with that id. `fstp-keyd` wrote
//! this layout first (lane W2f), and the test simulator of `fstp-celltest`
//! writes the same one. A [`crate::UsagePage`] carries these records, or
//! a damage marker ([`crate::keyd::USAGE_DAMAGED_TAG`]) in place of a
//! record that failed its check.
//!
//! ```text
//! record = id 16 | tag u8 = 0xf1 | op u8 | chain u8 | epoch u64
//!        | time u64 (Unix seconds) | outcome u8 | client u8 | check 4    41 bytes
//! check  = the first 4 bytes of SHA-256 over the 37 bytes before it
//! ```
//!
//! [`reconcile`] matches the backend's entries with the request ids and
//! calls of the `KeyOp` records read from the owning chain. Each record
//! covers one usage entry, so a call replayed under an id that already
//! has its record is reported. The fuzz target of [`decode_entry`] is
//! `usage_record_decode`.
//!
//! Interim, pending Daniel: a `usage_since` read is not a use of a root
//! key, and no keystore writes a `KeyOp` record for it. [`reconcile`]
//! therefore skips [`UsageOp::Usage`] entries.

use fstp_keys::Epoch;
use fstp_keys::keyop::{KeyCall, KeyOp};

use crate::{CustodyError, RequestId};

/// Length of one usage record.
pub const USAGE_RECORD_LEN: usize = 41;
/// The tag byte of every usage record, after the request id.
pub const USAGE_RECORD_TAG: u8 = 0xf1;
/// The outcome code of a served call. Any other outcome is the refusal
/// code ([`crate::Refusal::code`]).
pub const OUTCOME_SERVED: u8 = 0;
/// The offset of the tag, after the request id.
const TAG_AT: usize = 16;
/// Length of a record before its check.
const CHECKED_LEN: usize = USAGE_RECORD_LEN - CHECK_LEN;
/// Length of the check.
const CHECK_LEN: usize = 4;

/// A custody operation, as a usage record names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsageOp {
    /// `create_root`.
    Create,
    /// `wrap`.
    Wrap,
    /// `unwrap`.
    Unwrap,
    /// `destroy`.
    Destroy,
    /// `sign`.
    Sign,
    /// `usage_since`.
    Usage,
}

impl UsageOp {
    /// Every operation, in code order.
    pub const ALL: [UsageOp; 6] = [
        UsageOp::Create,
        UsageOp::Wrap,
        UsageOp::Unwrap,
        UsageOp::Destroy,
        UsageOp::Sign,
        UsageOp::Usage,
    ];

    /// The one-byte code in a usage record.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            UsageOp::Create => 1,
            UsageOp::Wrap => 2,
            UsageOp::Unwrap => 3,
            UsageOp::Destroy => 4,
            UsageOp::Sign => 5,
            UsageOp::Usage => 6,
        }
    }

    /// The operation of a record code, if the code is known.
    #[must_use]
    pub fn from_code(code: u8) -> Option<UsageOp> {
        UsageOp::ALL.into_iter().find(|o| o.code() == code)
    }

    /// A short lower-case name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            UsageOp::Create => "create",
            UsageOp::Wrap => "wrap",
            UsageOp::Unwrap => "unwrap",
            UsageOp::Destroy => "destroy",
            UsageOp::Sign => "sign",
            UsageOp::Usage => "usage",
        }
    }

    /// The operation of a name of [`UsageOp::name`], if it is one.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<UsageOp> {
        UsageOp::ALL
            .into_iter()
            .find(|o| o.name().as_bytes() == name)
    }

    /// The operation a keystore's custody call makes.
    #[must_use]
    pub const fn of_call(call: KeyCall) -> UsageOp {
        match call {
            KeyCall::CreateRoot => UsageOp::Create,
            KeyCall::Wrap => UsageOp::Wrap,
            KeyCall::Unwrap => UsageOp::Unwrap,
            KeyCall::Destroy => UsageOp::Destroy,
            KeyCall::Sign => UsageOp::Sign,
        }
    }
}

/// One usage record of a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsageRecord {
    /// The request id the call carried.
    pub request: RequestId,
    /// The operation.
    pub op: UsageOp,
    /// The ADR-004 chain code of the root, or 0 for a call that names no
    /// root.
    pub chain: u8,
    /// The root epoch, or 0 for a call that names no root.
    pub epoch: Epoch,
    /// When the backend served it, in Unix seconds.
    pub time: u64,
    /// [`OUTCOME_SERVED`], or the refusal code.
    pub outcome: u8,
    /// The client code of the backend, 0 when it has none.
    pub client: u8,
}

/// One entry of a usage page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsageEntry {
    /// A record that passed its check.
    Record(UsageRecord),
    /// The damage marker of the record at this log index.
    Damaged {
        /// The log index.
        index: u64,
    },
}

/// The check of the first [`CHECKED_LEN`] bytes of a record.
fn check_of(head: &[u8]) -> [u8; CHECK_LEN] {
    let digest = fstp_crypto::sha256(head);
    let mut out = [0u8; CHECK_LEN];
    if let Some(d) = digest.get(..CHECK_LEN) {
        out.copy_from_slice(d);
    }
    out
}

/// The record bytes of `r`, with its check.
#[must_use]
pub fn encode_record(r: &UsageRecord) -> [u8; USAGE_RECORD_LEN] {
    let mut rec = Vec::with_capacity(USAGE_RECORD_LEN);
    rec.extend_from_slice(&r.request.0);
    rec.push(USAGE_RECORD_TAG);
    rec.push(r.op.code());
    rec.push(r.chain);
    rec.extend_from_slice(&r.epoch.0.to_be_bytes());
    rec.extend_from_slice(&r.time.to_be_bytes());
    rec.push(r.outcome);
    rec.push(r.client);
    let check = check_of(&rec);
    rec.extend_from_slice(&check);
    let mut out = [0u8; USAGE_RECORD_LEN];
    for (d, s) in out.iter_mut().zip(rec) {
        *d = s;
    }
    out
}

/// Whether `rec` has the record tag and a matching check.
#[must_use]
pub fn record_intact(rec: &[u8; USAGE_RECORD_LEN]) -> bool {
    let (head, check) = rec.split_at(CHECKED_LEN);
    rec.get(TAG_AT) == Some(&USAGE_RECORD_TAG) && check == check_of(head)
}

/// The entry of one opaque record of a usage page.
///
/// # Errors
///
/// [`CustodyError::Protocol`] for a record of another length, a wrong tag
/// or check, or an unknown operation code. A damage marker decodes as
/// [`UsageEntry::Damaged`].
pub fn decode_entry(bytes: &[u8]) -> Result<UsageEntry, CustodyError> {
    if let Some(index) = crate::keyd::usage_damaged_index(bytes) {
        return Ok(UsageEntry::Damaged { index });
    }
    let rec: &[u8; USAGE_RECORD_LEN] = bytes
        .try_into()
        .map_err(|_| CustodyError::Protocol("a usage record has the wrong length"))?;
    if !record_intact(rec) {
        return Err(CustodyError::Protocol(
            "a usage record fails its tag or check",
        ));
    }
    let (id, rest) = rec.split_at(TAG_AT);
    let request = RequestId(
        id.try_into()
            .map_err(|_| CustodyError::Protocol("a usage record request id"))?,
    );
    let byte = |i: usize| {
        rest.get(i)
            .copied()
            .ok_or(CustodyError::Protocol("a usage record is short"))
    };
    let u64_at = |i: usize| -> Result<u64, CustodyError> {
        let b: [u8; 8] = rest
            .get(i..i.saturating_add(8))
            .and_then(|s| s.try_into().ok())
            .ok_or(CustodyError::Protocol("a usage record is short"))?;
        Ok(u64::from_be_bytes(b))
    };
    let op = UsageOp::from_code(byte(1)?).ok_or(CustodyError::Protocol(
        "a usage record names an unknown operation",
    ))?;
    Ok(UsageEntry::Record(UsageRecord {
        request,
        op,
        chain: byte(2)?,
        epoch: Epoch(u64_at(3)?),
        time: u64_at(11)?,
        outcome: byte(19)?,
        client: byte(20)?,
    }))
}

/// What reconciliation matches: a request id and its operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyUse {
    /// The request id.
    pub request: RequestId,
    /// The operation.
    pub op: UsageOp,
}

impl KeyUse {
    /// The use a usage record reports.
    #[must_use]
    pub const fn of_record(r: &UsageRecord) -> KeyUse {
        KeyUse {
            request: r.request,
            op: r.op,
        }
    }

    /// The use a `KeyOp` record announces.
    #[must_use]
    pub const fn of_key_op(k: &KeyOp) -> KeyUse {
        KeyUse {
            request: RequestId(k.request),
            op: UsageOp::of_call(k.call),
        }
    }
}

/// The backend uses with no matching `KeyOp` record, in usage order.
/// Each one raises `CustodyAnomaly` (ADR-004 "Reconciliation").
///
/// Matching counts: each record covers one usage entry. `usage_since`
/// reads are skipped (module documentation).
#[must_use]
pub fn reconcile(usage: &[KeyUse], recorded: &[KeyUse]) -> Vec<KeyUse> {
    let mut unused: std::collections::BTreeMap<KeyUse, usize> = std::collections::BTreeMap::new();
    for k in recorded {
        let c = unused.entry(*k).or_insert(0);
        *c = c.saturating_add(1);
    }
    let mut out = Vec::new();
    for u in usage.iter().filter(|u| u.op != UsageOp::Usage) {
        match unused.get_mut(u) {
            Some(c) if *c > 0 => *c = c.saturating_sub(1),
            _ => out.push(*u),
        }
    }
    out
}

/// One finding of [`reconcile_page`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CustodyAnomaly {
    /// A backend use with no `KeyOp` record.
    Unrecorded(UsageRecord),
    /// A damaged usage record, by log index.
    Damaged {
        /// The log index.
        index: u64,
    },
}

/// Reconciles the decoded entries of a usage log with `KeyOp` records:
/// every damaged record, then every use without its record.
#[must_use]
pub fn reconcile_page(entries: &[UsageEntry], key_ops: &[KeyOp]) -> Vec<CustodyAnomaly> {
    let mut out: Vec<CustodyAnomaly> = entries
        .iter()
        .filter_map(|e| match e {
            UsageEntry::Damaged { index } => Some(CustodyAnomaly::Damaged { index: *index }),
            UsageEntry::Record(_) => None,
        })
        .collect();
    let records: Vec<&UsageRecord> = entries
        .iter()
        .filter_map(|e| match e {
            UsageEntry::Record(r) => Some(r),
            UsageEntry::Damaged { .. } => None,
        })
        .collect();
    let usage: Vec<KeyUse> = records.iter().map(|r| KeyUse::of_record(r)).collect();
    let recorded: Vec<KeyUse> = key_ops.iter().map(KeyUse::of_key_op).collect();
    let missing = reconcile(&usage, &recorded);
    let mut left = missing.as_slice();
    for r in records {
        if let Some((first, rest)) = left.split_first()
            && *first == KeyUse::of_record(r)
        {
            out.push(CustodyAnomaly::Unrecorded(*r));
            left = rest;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fstp_keys::Chain;

    fn rec(id: u8, op: UsageOp) -> UsageRecord {
        UsageRecord {
            request: RequestId([id; 16]),
            op,
            chain: 1,
            epoch: Epoch(3),
            time: 1_793_232_000,
            outcome: OUTCOME_SERVED,
            client: 1,
        }
    }

    fn key_op(id: u8, call: KeyCall) -> KeyOp {
        KeyOp {
            call,
            chain: Chain::App,
            epoch: Epoch(3),
            request: [id; 16],
        }
    }

    /// ADR-004 "Reconciliation": a usage record keeps its request id
    /// through its bytes, and a changed byte fails its check.
    #[test]
    fn adr004_usage_record_round_trips_with_its_request_id() {
        for op in UsageOp::ALL {
            let r = rec(9, op);
            let bytes = encode_record(&r);
            assert_eq!(decode_entry(&bytes), Ok(UsageEntry::Record(r)));
            for i in 0..USAGE_RECORD_LEN {
                let mut m = bytes;
                m[i] ^= 0x40;
                assert!(decode_entry(&m).is_err(), "byte {i} changed");
            }
        }
        let mut marker = vec![crate::keyd::USAGE_DAMAGED_TAG];
        marker.extend_from_slice(&5u64.to_be_bytes());
        assert_eq!(decode_entry(&marker), Ok(UsageEntry::Damaged { index: 5 }));
    }

    /// I-24, ADR-004 "Reconciliation": a use without its `KeyOp` record
    /// is reported, a replayed call is reported, a usage read is not, and
    /// a damaged record is.
    #[test]
    fn i24_reconcile_reports_unrecorded_uses_and_damage() {
        let entries = vec![
            UsageEntry::Record(rec(1, UsageOp::Create)),
            UsageEntry::Record(rec(2, UsageOp::Wrap)),
            UsageEntry::Record(rec(3, UsageOp::Usage)),
            UsageEntry::Damaged { index: 7 },
            UsageEntry::Record(rec(1, UsageOp::Create)),
            UsageEntry::Record(rec(4, UsageOp::Unwrap)),
        ];
        let ops = vec![
            key_op(1, KeyCall::CreateRoot),
            key_op(2, KeyCall::Wrap),
            key_op(4, KeyCall::Destroy),
        ];
        assert_eq!(
            reconcile_page(&entries, &ops),
            vec![
                CustodyAnomaly::Damaged { index: 7 },
                CustodyAnomaly::Unrecorded(rec(1, UsageOp::Create)),
                CustodyAnomaly::Unrecorded(rec(4, UsageOp::Unwrap)),
            ]
        );
    }
}
