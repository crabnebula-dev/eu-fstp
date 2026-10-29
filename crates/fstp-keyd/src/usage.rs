//! The append-only usage log of `fstp-keyd` (ADR-004 part 2
//! "Reconciliation").
//!
//! One fixed-length record per operation. It holds no key bytes. No ADR
//! fixed these bytes before this lane; their record in ADR-004 is with
//! the lead.
//!
//! ```text
//! record = id 16 | tag u8 = 0xf1 | op u8 | chain u8 | epoch u64
//!        | time u64 (Unix seconds) | outcome u8 | client u8 | check 4    41 bytes
//! check  = the first 4 bytes of SHA-256 over the 37 bytes before it
//! ```
//!
//! The client is the role of the socket the request came in on
//! ([`crate::ClientRole::code`]). Each socket serves one OS user, so the
//! role names that user. Client 0 is a request served outside a socket.
//!
//! A crash or a full key volume part way through an append leaves a
//! partial record at the end. Every append, and every start, first cuts
//! the file back to a whole number of records, so no later record is
//! read at the wrong offset. A record whose tag or check fails hides no
//! other. [`UsageLog::since`] reports it in its page as a damage marker
//! ([`fstp_custody::keyd::USAGE_DAMAGED_TAG`] and the record's log
//! index), whatever root it named. So the daily reconciliation sees the
//! gap and can raise `CustodyAnomaly` (ADR-004 part 2 "Reconciliation").

use std::io::{BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use fstp_custody::keyd::{RequestId, RootHandle};

use crate::KeydError;

/// The name of the usage log on the key volume.
pub(crate) const USAGE_FILE: &str = "usage.log";
/// Length of one record.
pub(crate) const RECORD_LEN: usize = 41;
/// The offset of the record tag, after the request id.
const TAG_AT: usize = 16;
/// The tag byte of every record.
pub(crate) const RECORD_TAG: u8 = 0xf1;
/// Length of a record before its check.
const CHECKED_LEN: usize = RECORD_LEN - CHECK_LEN;
/// Length of the check.
const CHECK_LEN: usize = 4;

/// Operation codes.
pub(crate) const OP_CREATE: u8 = 1;
pub(crate) const OP_WRAP: u8 = 2;
pub(crate) const OP_UNWRAP: u8 = 3;
pub(crate) const OP_DESTROY: u8 = 4;
pub(crate) const OP_SIGN: u8 = 5;
pub(crate) const OP_USAGE: u8 = 6;

/// Outcome codes: 0 served, otherwise the refusal code.
pub(crate) const OUTCOME_SERVED: u8 = 0;

/// The client code of a request served outside a socket, as the unit
/// tests serve them.
#[cfg(test)]
pub(crate) const CLIENT_NONE: u8 = 0;

/// The usage log of one key volume.
pub(crate) struct UsageLog {
    path: PathBuf,
}

/// The record length as a file offset step.
fn record_len_u64() -> u64 {
    u64::try_from(RECORD_LEN).unwrap_or(u64::MAX)
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

/// The damage marker that stands in a usage page for the record at log
/// index `index`: the tag and the index.
fn damage_marker(index: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(fstp_custody::keyd::USAGE_DAMAGED_LEN);
    out.push(fstp_custody::keyd::USAGE_DAMAGED_TAG);
    out.extend_from_slice(&index.to_be_bytes());
    out
}

/// Whether `rec` has the record tag and a matching check.
fn intact(rec: &[u8; RECORD_LEN]) -> bool {
    let (head, check) = rec.split_at(CHECKED_LEN);
    rec.get(TAG_AT) == Some(&RECORD_TAG) && check == check_of(head)
}

impl UsageLog {
    /// The usage log of `volume`, without touching the file.
    pub(crate) fn new(volume: &Path) -> UsageLog {
        UsageLog {
            path: volume.join(USAGE_FILE),
        }
    }

    /// The usage log of `volume`, with a partial last record cut away.
    pub(crate) fn open(volume: &Path) -> Result<UsageLog, KeydError> {
        let log = UsageLog::new(volume);
        match std::fs::OpenOptions::new().write(true).open(&log.path) {
            Ok(file) => cut_partial(&file)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(KeydError::Io("open the usage log")),
        }
        Ok(log)
    }

    /// Appends one record served outside a socket, and syncs it.
    #[cfg(test)]
    pub(crate) fn append(
        &self,
        id: RequestId,
        op: u8,
        root: Option<RootHandle>,
        outcome: u8,
    ) -> Result<(), KeydError> {
        self.append_from(CLIENT_NONE, id, op, root, outcome)
    }

    /// Appends one record of a request from `client`, and syncs it. A
    /// partial record at the end is cut away first.
    pub(crate) fn append_from(
        &self,
        client: u8,
        id: RequestId,
        op: u8,
        root: Option<RootHandle>,
        outcome: u8,
    ) -> Result<(), KeydError> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut rec = Vec::with_capacity(RECORD_LEN);
        rec.extend_from_slice(&id.0);
        rec.push(RECORD_TAG);
        rec.push(op);
        rec.push(root.map_or(0, |r| r.chain.code()));
        rec.extend_from_slice(&root.map_or(0, |r| r.epoch.0).to_be_bytes());
        rec.extend_from_slice(&time.to_be_bytes());
        rec.push(outcome);
        rec.push(client);
        let check = check_of(&rec);
        rec.extend_from_slice(&check);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .map_err(|_| KeydError::Io("open the usage log"))?;
        cut_partial(&file)?;
        file.write_all(&rec)
            .map_err(|_| KeydError::Io("append to the usage log"))?;
        file.sync_data()
            .map_err(|_| KeydError::Io("sync the usage log"))
    }

    /// The records of `root` from record index `cursor` on, at most
    /// `max`, and the cursor after them. It reads from the cursor's
    /// offset on, not the whole file. A record that fails its check
    /// cannot be trusted to name its root, so every page that spans it
    /// carries a damage marker in its place.
    pub(crate) fn since(
        &self,
        root: RootHandle,
        cursor: u64,
        max: usize,
    ) -> Result<(Vec<Vec<u8>>, u64), KeydError> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), cursor)),
            Err(_) => return Err(KeydError::Io("read the usage log")),
        };
        let offset = cursor
            .checked_mul(record_len_u64())
            .ok_or(KeydError::Io("the usage cursor is out of range"))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| KeydError::Io("read the usage log"))?;
        let mut reader = BufReader::new(file);
        let chain = root.chain.code();
        let epoch = root.epoch.0.to_be_bytes();
        let mut out = Vec::new();
        let mut next = cursor;
        let mut rec = [0u8; RECORD_LEN];
        while out.len() < max {
            match reader.read_exact(&mut rec) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => return Err(KeydError::Io("read the usage log")),
            }
            let index = next;
            next = next.saturating_add(1);
            if !intact(&rec) {
                out.push(damage_marker(index));
                continue;
            }
            let same_chain = rec.get(18) == Some(&chain);
            let same_epoch = rec.get(19..27) == Some(&epoch[..]);
            if same_chain && same_epoch {
                out.push(rec.to_vec());
            }
        }
        Ok((out, next))
    }
}

/// Cuts `file` back to a whole number of records and syncs it, so a
/// partial record a crash or a full volume left is never read as the
/// start of the next one.
fn cut_partial(file: &std::fs::File) -> Result<(), KeydError> {
    let len = file
        .metadata()
        .map_err(|_| KeydError::Io("read the usage log length"))?
        .len();
    let whole = len
        .checked_rem(record_len_u64())
        .and_then(|rem| len.checked_sub(rem))
        .unwrap_or(len);
    if whole != len {
        file.set_len(whole)
            .and_then(|()| file.sync_all())
            .map_err(|_| KeydError::Io("cut a partial usage record"))?;
    }
    Ok(())
}

/// Review reproducer (independent review of lane W2f). It fails on the
/// current code and passes once the defect is fixed.
#[cfg(test)]
mod review {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use fstp_custody::{Chain, Epoch};

    /// ADR-004 part 2 "Reconciliation": a partial append, as a full key
    /// volume or a crash leaves it, must not hide the records after it.
    /// The log has no framing, so every later record is read at the
    /// wrong offset and `usage_since` stops returning it.
    #[test]
    fn review_keyd_usage_log_torn_append_hides_later_records() {
        let dir =
            std::env::temp_dir().join(format!("fstp-keyd-rob-review-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = UsageLog::new(&dir);
        let root = RootHandle {
            chain: Chain::App,
            epoch: Epoch(1),
        };
        log.append(RequestId([1; 16]), OP_WRAP, Some(root), OUTCOME_SERVED)
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(USAGE_FILE))
            .unwrap();
        file.write_all(&[0xaa; 10]).unwrap();
        drop(file);
        log.append(RequestId([2; 16]), OP_UNWRAP, Some(root), OUTCOME_SERVED)
            .unwrap();
        let (records, _) = log.since(root, 0, 512).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            records.iter().any(|r| r.get(..16) == Some(&[2u8; 16][..])),
            "the record after a torn append is lost: {} record(s) read",
            records.len()
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;
    use fstp_custody::{Chain, Epoch};

    /// ADR-004 part 2 "Reconciliation": a record whose bytes changed
    /// fails its check. The page reports it as a damage marker with its
    /// log index, so reconciliation sees the gap, and the records around
    /// it are still read. A page that starts at a cursor reads from there
    /// on.
    #[test]
    fn adr004_keyd_usage_log_reports_a_damaged_record() {
        let dir = std::env::temp_dir().join(format!("fstp-keyd-unit-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = UsageLog::open(&dir).unwrap();
        let root = RootHandle {
            chain: Chain::Vault,
            epoch: Epoch(4),
        };
        for n in 1..=3u8 {
            log.append_from(2, RequestId([n; 16]), OP_UNWRAP, Some(root), OUTCOME_SERVED)
                .unwrap();
        }
        let path = dir.join(USAGE_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[RECORD_LEN + 30] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let other = RootHandle {
            chain: Chain::App,
            epoch: Epoch(1),
        };
        let (all, next) = log.since(root, 0, 512).unwrap();
        let (tail, _) = log.since(root, 2, 512).unwrap();
        let (elsewhere, _) = log.since(other, 0, 512).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let markers = |page: &[Vec<u8>]| -> Vec<u64> {
            page.iter()
                .filter_map(|r| fstp_custody::keyd::usage_damaged_index(r))
                .collect()
        };
        let records: Vec<&Vec<u8>> = all.iter().filter(|r| r.len() == RECORD_LEN).collect();
        let ids: Vec<u8> = records.iter().map(|r| r[0]).collect();
        assert_eq!(ids, [1, 3], "the damaged record was read or hid another");
        assert_eq!(markers(&all), [1], "the damaged record is not reported");
        assert_eq!(all.len(), 3, "a page holds more than records and markers");
        assert_eq!(
            markers(&elsewhere),
            [1],
            "another root's page hides the gap"
        );
        assert_eq!(next, 3);
        assert_eq!(tail.iter().map(|r| r[0]).collect::<Vec<_>>(), [3]);
        assert!(
            records.iter().all(|r| r[36] == 2),
            "the client role is lost"
        );
    }
}
