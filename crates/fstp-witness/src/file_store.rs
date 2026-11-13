//! The append-only file store of a self-hosted witness (ADR-010 "Self-
//! hosted witness", design section 15 `file_store_decode`).
//!
//! ```text
//! file   = record*
//! record = be64(witness_seq) || be32(len) || bytes
//! ```
//!
//! Records are appended and never rewritten, so the encoding of a prefix
//! of the records is a prefix of the file. A file cut inside a record is
//! refused. A file cut at a record boundary, as after a crash between two
//! appends, holds exactly the records before the cut.
//!
//! Two layers read the file:
//!
//! - [`decode_file_store`] reads the framing. It needs only strictly
//!   rising sequences, so it also reads a segment of a longer store.
//! - [`load_file_store`] reads a whole store. One file holds the witness
//!   chain of exactly one cell and chain, because witness sequences
//!   count per cell and chain (reading of lane W2g). Its sequences are
//!   therefore 1, 2, 3 with no gap, and a deleted middle record is
//!   refused.
//!
//! [`FileStore`] is the store of a running local witness (lane F-SELF).
//! Its record content is the interim layout of ADR-010 "Self-hosted
//! witness": a prepare record is the witness message and its encoded
//! receipt, and an abort or in-doubt record is the witness message,
//! `be64(received_at)` and the witness link. Loading a chain replays its
//! records from [`fstp_audit::witness::witness_genesis`] and refuses any
//! break, as the database store does.
//!
//! Scope (ADR-010 open point 7, Daniel, 2026-11-13): the local witness
//! detects a change by any database role and by the database owner. A
//! root user on the cell node can change both the database and this
//! store, which only the optional external bucket would detect.

use std::path::{Path, PathBuf};

use fstp_audit::anchor::{AnchorRow, RECEIPT_ENCODED_LEN, decode_receipt, encode_receipt};
use fstp_audit::codec::Reader;
use fstp_audit::witness::{Prepare, RecordKind};
use fstp_audit::{CellId, ChainId, DecodeError, Invalid, Link};

use crate::WitnessError;
use crate::chain_witness::Withdrawal;
use crate::message::{
    MAX_MESSAGE_LEN, TAG_PREPARE, WitnessMessage, decode_witness_message, encode_witness_message,
};
use crate::store::{LoadedChain, RegisteredCell, StoreError, Stored, replay};

/// The longest record the store holds: the longest witness message and
/// the receipt the witness gave for it. Derived, so that every message
/// the core accepts fits in one record.
pub const MAX_FILE_RECORD_LEN: usize = MAX_MESSAGE_LEN + RECEIPT_ENCODED_LEN;

/// One record of the append-only file store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    /// The witness sequence, from 1.
    pub witness_seq: u64,
    /// The record bytes.
    pub bytes: Vec<u8>,
}

/// The bytes that append `record` after a last record of sequence
/// `last_seq` (0 for an empty store).
///
/// # Errors
///
/// [`Invalid::SequenceNotRising`] unless the sequence rises, and
/// [`Invalid::BodyTooLong`] above [`MAX_FILE_RECORD_LEN`].
pub fn encode_file_record(last_seq: u64, record: &FileRecord) -> Result<Vec<u8>, WitnessError> {
    if record.witness_seq <= last_seq {
        return Err(Invalid::SequenceNotRising.into());
    }
    if record.bytes.len() > MAX_FILE_RECORD_LEN {
        return Err(Invalid::BodyTooLong.into());
    }
    let len = u32::try_from(record.bytes.len()).map_err(|_| Invalid::BodyTooLong)?;
    let mut out = Vec::with_capacity(record.bytes.len().saturating_add(12));
    out.extend_from_slice(&record.witness_seq.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&record.bytes);
    Ok(out)
}

/// Encodes a whole store.
///
/// # Errors
///
/// As [`encode_file_record`], for the first record that fails.
pub fn encode_file_store(records: &[FileRecord]) -> Result<Vec<u8>, WitnessError> {
    let mut out = Vec::new();
    let mut last = 0;
    for r in records {
        out.extend_from_slice(&encode_file_record(last, r)?);
        last = r.witness_seq;
    }
    Ok(out)
}

/// Decodes the framing of the file store. An empty file holds no record.
/// A truncated record is detected. Fuzzed (`file_store_decode`).
///
/// # Errors
///
/// [`WitnessError::Decode`] for a cut inside a record or a record over
/// its limit, and [`WitnessError::Invalid`] for a sequence that does not
/// rise.
pub fn decode_file_store(bytes: &[u8]) -> Result<Vec<FileRecord>, WitnessError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    let mut last = 0u64;
    while !r.is_empty() {
        let witness_seq = r.be64()?;
        if witness_seq <= last {
            return Err(DecodeError::Invalid(Invalid::SequenceNotRising).into());
        }
        let bytes = r.bytes32(MAX_FILE_RECORD_LEN)?;
        last = witness_seq;
        out.push(FileRecord { witness_seq, bytes });
    }
    Ok(out)
}

/// Loads the whole store of one cell and chain: [`decode_file_store`],
/// then sequences 1, 2, 3 with no gap. Fuzzed (`file_store_decode`).
///
/// # Errors
///
/// As [`decode_file_store`], and [`Invalid::SequenceGap`] for a store that
/// does not start at 1 or misses a record inside it.
pub fn load_file_store(bytes: &[u8]) -> Result<Vec<FileRecord>, WitnessError> {
    let records = decode_file_store(bytes)?;
    let mut expected = 0u64;
    for r in &records {
        expected = expected.checked_add(1).ok_or(Invalid::SequenceGap)?;
        if r.witness_seq != expected {
            return Err(Invalid::SequenceGap.into());
        }
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// The store of a running local witness (lane F-SELF).

/// The name of the registry file in a store directory.
pub const REGISTRY_FILE: &str = "registry";

/// The file name of `cell`'s `chain` in a store directory:
/// `chain-<32 hex digits of the cell>-<chain byte>`.
#[must_use]
pub fn chain_file_name(cell: CellId, chain: ChainId) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("chain-");
    for b in cell.0 {
        // Writing to a String does not fail.
        let _ = write!(s, "{b:02x}");
    }
    let _ = write!(s, "-{}", chain.byte());
    s
}

/// The tag of a registry record that pins a cell CA certificate.
const REG_CA: u8 = 1;
/// The tag of a registry record that adds an anchor key.
const REG_KEY: u8 = 2;
/// The suffix of an abort or in-doubt record: `be64(received_at)` and the
/// witness link.
const WITHDRAWAL_SUFFIX_LEN: usize = 8 + 32;

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what)
}

/// The bytes of one chain record: the witness message, then for a prepare
/// its encoded receipt, and for an abort or in-doubt record
/// `be64(received_at)` and the witness link (ADR-010 "Self-hosted
/// witness", interim layout).
fn prepare_record(p: &Prepare, row: &AnchorRow) -> Result<Vec<u8>, StoreError> {
    let mut bytes = encode_witness_message(&WitnessMessage::Prepare(p.clone()))
        .map_err(|_| corrupt("prepare message"))?;
    bytes.extend_from_slice(&encode_receipt(&row.receipt).map_err(|_| corrupt("receipt"))?);
    Ok(bytes)
}

/// Reads one chain record of `cell`'s `chain` at witness sequence `seq`.
fn read_chain_record(
    cell: CellId,
    chain: ChainId,
    record: &FileRecord,
) -> Result<Stored, StoreError> {
    let tag = record.bytes.get(1).copied();
    let seq = record.witness_seq;
    if tag == Some(TAG_PREPARE) {
        let cut = record
            .bytes
            .len()
            .checked_sub(RECEIPT_ENCODED_LEN)
            .ok_or(corrupt("prepare record"))?;
        let (message, receipt) = record.bytes.split_at(cut);
        let Ok(WitnessMessage::Prepare(p)) = decode_witness_message(message) else {
            return Err(corrupt("prepare record"));
        };
        let receipt = decode_receipt(receipt).map_err(|_| corrupt("receipt"))?;
        let a = &p.anchor;
        let f = &receipt.fields;
        if (a.cell, a.chain, receipt.cell, receipt.chain) != (cell, chain, cell, chain)
            || (f.n, f.link) != (a.n, a.link)
            || f.witness_seq != seq
        {
            return Err(corrupt("prepare record"));
        }
        return Ok(Stored::Prepare {
            seq,
            row: AnchorRow {
                anchor: p.anchor,
                receipt,
            },
        });
    }
    let cut = record
        .bytes
        .len()
        .checked_sub(WITHDRAWAL_SUFFIX_LEN)
        .ok_or(corrupt("withdrawal record"))?;
    let (message, suffix) = record.bytes.split_at(cut);
    let (kind, c, ch, n, link) = match decode_witness_message(message) {
        Ok(WitnessMessage::Abort {
            cell,
            chain,
            n,
            link,
        }) => (RecordKind::Abort, cell, chain, n, link),
        Ok(WitnessMessage::InDoubtAbsent {
            cell,
            chain,
            n,
            link,
        }) => (RecordKind::InDoubtAbsent, cell, chain, n, link),
        _ => return Err(corrupt("withdrawal record")),
    };
    if (c, ch) != (cell, chain) {
        return Err(corrupt("withdrawal record"));
    }
    let witness_link = suffix
        .get(8..)
        .and_then(|l| <[u8; 32]>::try_from(l).ok())
        .ok_or(corrupt("withdrawal record"))?;
    Ok(Stored::Withdrawn {
        seq,
        kind,
        n,
        link,
        witness_link: Link(witness_link),
    })
}

/// The append-only file store of a local witness (ADR-010 "Self-hosted
/// witness"): one file per cell and chain ([`chain_file_name`]) and one
/// registry file ([`REGISTRY_FILE`]), each in the framing above, in one
/// directory that only the witness's OS user may read and write.
///
/// Each append writes one whole record, then syncs the file, before the
/// witness answers. A crash inside an append leaves a cut record, which
/// [`FileStore::open`] refuses. Every chain file loads through
/// [`load_file_store`], and [`crate::store`]'s replay recomputes every
/// witness link, so a missing, changed or cut record stops the witness
/// from starting.
///
/// Scope (ADR-010 open point 7): a root user on the node can rewrite the
/// directory and the cell's database together. The local witness does
/// not detect that; only the optional external bucket would.
#[derive(Debug)]
pub struct FileStore {
    dir: PathBuf,
    /// The witness sequence of the registry's last record.
    registry_seq: u64,
}

impl FileStore {
    /// Opens the store in `dir`, creating the directory with mode 0700 if
    /// it does not exist. It loads the registry and every chain file, so
    /// a store that does not load never serves.
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] when the directory cannot be read or
    /// created, and [`StoreError::Corrupt`] for any file that does not
    /// load.
    pub fn open(dir: &Path) -> Result<FileStore, StoreError> {
        create_private_dir(dir)?;
        let registry = read_file(&dir.join(REGISTRY_FILE))?;
        let registry = load_file_store(&registry).map_err(|_| corrupt("registry"))?;
        let store = FileStore {
            dir: dir.to_path_buf(),
            registry_seq: registry.last().map_or(0, |r| r.witness_seq),
        };
        let cells = store.load_registry()?;
        let entries = std::fs::read_dir(dir).map_err(|_| StoreError::Unavailable("store"))?;
        for entry in entries {
            let entry = entry.map_err(|_| StoreError::Unavailable("store"))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(corrupt("a file name"))?;
            if name == REGISTRY_FILE {
                continue;
            }
            let found = cells.iter().find_map(|c| {
                [ChainId::App, ChainId::Vault]
                    .into_iter()
                    .find(|ch| chain_file_name(c.cell, *ch) == name)
                    .map(|ch| (c.cell, ch))
            });
            let Some((cell, chain)) = found else {
                return Err(corrupt("a file of no registered chain"));
            };
            store.load_chain(cell, chain)?;
        }
        Ok(store)
    }

    /// The store directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every registered cell, in registration order.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the registry does not load.
    pub fn load_registry(&self) -> Result<Vec<RegisteredCell>, StoreError> {
        load_registry_file(&read_file(&self.dir.join(REGISTRY_FILE))?)
    }

    /// Registers `cell` with its CA certificate `ca_cert` (DER) at `at`. A
    /// second registration with the same certificate changes nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Conflict`] when the cell is registered with another
    /// CA, and [`StoreError::Unavailable`] when the record cannot be
    /// written.
    pub fn register_cell(
        &mut self,
        cell: CellId,
        ca_cert: &[u8],
        at: i64,
    ) -> Result<(), StoreError> {
        if let Some(c) = self.load_registry()?.into_iter().find(|c| c.cell == cell) {
            return if c.ca_cert == ca_cert {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        let mut bytes = vec![REG_CA];
        bytes.extend_from_slice(&cell.0);
        bytes.extend_from_slice(&at.to_be_bytes());
        bytes.extend_from_slice(ca_cert);
        self.append_registry(bytes)
    }

    /// Adds `key` to the anchor key history of `cell`'s `chain` at `at`.
    /// A key in the history already changes nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] for a cell that is not registered, and
    /// [`StoreError::Unavailable`] when the record cannot be written.
    pub fn register_anchor_key(
        &mut self,
        cell: CellId,
        chain: ChainId,
        key: &[u8],
        at: i64,
    ) -> Result<(), StoreError> {
        let registry = self.load_registry()?;
        let c = registry
            .iter()
            .find(|c| c.cell == cell)
            .ok_or(corrupt("anchor key of an unknown cell"))?;
        let have = match chain {
            ChainId::App => &c.app_keys,
            ChainId::Vault => &c.vault_keys,
        };
        if have.iter().any(|k| k == key) {
            return Ok(());
        }
        let mut bytes = vec![REG_KEY];
        bytes.extend_from_slice(&cell.0);
        bytes.push(chain.byte());
        bytes.extend_from_slice(&at.to_be_bytes());
        bytes.extend_from_slice(key);
        self.append_registry(bytes)
    }

    fn append_registry(&mut self, bytes: Vec<u8>) -> Result<(), StoreError> {
        let seq = self
            .registry_seq
            .checked_add(1)
            .ok_or(corrupt("registry sequence"))?;
        let framed = encode_file_record(
            self.registry_seq,
            &FileRecord {
                witness_seq: seq,
                bytes,
            },
        )
        .map_err(|_| corrupt("registry record"))?;
        append(&self.dir, REGISTRY_FILE, &framed)?;
        self.registry_seq = seq;
        Ok(())
    }

    /// Rebuilds `cell`'s `chain` from its file, recomputing every witness
    /// link. A chain with no file is empty.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] for a cut, missing or changed record.
    pub fn load_chain(&self, cell: CellId, chain: ChainId) -> Result<LoadedChain, StoreError> {
        load_chain_file(
            cell,
            chain,
            &read_file(&self.dir.join(chain_file_name(cell, chain)))?,
        )
    }

    /// Appends a receipted prepare `p` with its anchor row `row`, after the
    /// chain's last record.
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] when the record cannot be written and
    /// synced. The record may then be cut, which the next start refuses.
    pub fn append_prepare(&self, p: &Prepare, row: &AnchorRow) -> Result<(), StoreError> {
        let seq = row.receipt.fields.witness_seq;
        let bytes = prepare_record(p, row)?;
        self.append_chain(row.anchor.cell, row.anchor.chain, seq, bytes)
    }

    /// Appends an abort or an in-doubt record `message`, received at
    /// `received_at`, with the witness fields `w`.
    ///
    /// # Errors
    ///
    /// As [`FileStore::append_prepare`].
    pub fn append_withdrawal(
        &self,
        message: &WitnessMessage,
        received_at: i64,
        w: &Withdrawal,
    ) -> Result<(), StoreError> {
        let (cell, chain) = match message {
            WitnessMessage::Abort { cell, chain, .. }
            | WitnessMessage::InDoubtAbsent { cell, chain, .. } => (*cell, *chain),
            WitnessMessage::Prepare(_) => return Err(corrupt("withdrawal record")),
        };
        let mut bytes =
            encode_witness_message(message).map_err(|_| corrupt("withdrawal message"))?;
        bytes.extend_from_slice(&received_at.to_be_bytes());
        bytes.extend_from_slice(&w.witness_link.0);
        self.append_chain(cell, chain, w.witness_seq, bytes)
    }

    fn append_chain(
        &self,
        cell: CellId,
        chain: ChainId,
        seq: u64,
        bytes: Vec<u8>,
    ) -> Result<(), StoreError> {
        let last = seq.checked_sub(1).ok_or(corrupt("witness sequence"))?;
        let framed = encode_file_record(
            last,
            &FileRecord {
                witness_seq: seq,
                bytes,
            },
        )
        .map_err(|_| corrupt("chain record"))?;
        append(&self.dir, &chain_file_name(cell, chain), &framed)
    }
}

/// Loads a registry file: each record pins one cell CA certificate or
/// adds one anchor key to a registered cell. Fuzzed
/// (`file_store_records_decode`).
///
/// # Errors
///
/// [`StoreError::Corrupt`] for a file that does not load, a record that
/// does not read, a second CA for one cell, or a key of an unknown cell.
pub fn load_registry_file(bytes: &[u8]) -> Result<Vec<RegisteredCell>, StoreError> {
    let records = load_file_store(bytes).map_err(|_| corrupt("registry"))?;
    let mut out: Vec<RegisteredCell> = Vec::new();
    for r in &records {
        let bad = corrupt("registry record");
        let (Some(&tag), Some(cell)) = (r.bytes.first(), r.bytes.get(1..17)) else {
            return Err(bad);
        };
        let cell = CellId(<[u8; 16]>::try_from(cell).map_err(|_| bad)?);
        match tag {
            REG_CA => {
                // The registration time (8 bytes), then the certificate.
                let ca_cert = r.bytes.get(25..).ok_or(bad)?.to_vec();
                if out.iter().any(|c| c.cell == cell) {
                    return Err(corrupt("registry record"));
                }
                out.push(RegisteredCell {
                    cell,
                    ca_cert,
                    app_keys: Vec::new(),
                    vault_keys: Vec::new(),
                });
            }
            REG_KEY => {
                // The chain, the registration time (8 bytes), the key.
                let chain = r
                    .bytes
                    .get(17)
                    .and_then(|b| ChainId::from_byte(*b))
                    .ok_or(bad)?;
                let key = r.bytes.get(26..).ok_or(bad)?.to_vec();
                let entry = out
                    .iter_mut()
                    .find(|c| c.cell == cell)
                    .ok_or(corrupt("anchor key of an unknown cell"))?;
                match chain {
                    ChainId::App => entry.app_keys.push(key),
                    ChainId::Vault => entry.vault_keys.push(key),
                }
            }
            _ => return Err(corrupt("registry record")),
        }
    }
    Ok(out)
}

/// Loads the chain file of `cell`'s `chain` and replays it, recomputing
/// every witness link from the chain's witness genesis. Fuzzed
/// (`file_store_records_decode`).
///
/// # Errors
///
/// [`StoreError::Corrupt`] for a cut, missing or changed record.
pub fn load_chain_file(
    cell: CellId,
    chain: ChainId,
    bytes: &[u8],
) -> Result<LoadedChain, StoreError> {
    let records = load_file_store(bytes).map_err(|_| corrupt("chain file"))?;
    let stored = records
        .iter()
        .map(|r| read_chain_record(cell, chain, r))
        .collect::<Result<Vec<_>, _>>()?;
    replay(cell, chain, stored)
}

/// The bytes of `path`, or none for a file that does not exist.
fn read_file(path: &Path) -> Result<Vec<u8>, StoreError> {
    match std::fs::read(path) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(StoreError::Unavailable("store file")),
    }
}

/// Creates `dir` if it does not exist, readable and writable by its owner
/// only.
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|_| StoreError::Unavailable("store directory"))
}

/// Appends `framed` to `name` in `dir` and syncs it. A new file is also
/// made durable in its directory.
fn append(dir: &Path, name: &str, framed: &[u8]) -> Result<(), StoreError> {
    use std::io::Write as _;
    let path = dir.join(name);
    let new = !path.exists();
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let fail = |_| StoreError::Unavailable("store append");
    let mut f = opts.open(&path).map_err(fail)?;
    f.write_all(framed).map_err(fail)?;
    f.sync_data().map_err(fail)?;
    if new {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(fail)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use fstp_audit::anchor::{Anchor, Receipt, ReceiptFields, encode_receipt};
    use fstp_audit::chain::{genesis, link_of};
    use fstp_audit::witness::{MAX_PREPARE_ROWS, Prepare};
    use fstp_audit::{CellId, ChainId, Link, SIGNATURE_LEN};

    use super::*;
    use crate::message::{WitnessMessage, decode_witness_message, encode_witness_message};

    fn rec(witness_seq: u64) -> FileRecord {
        FileRecord {
            witness_seq,
            bytes: vec![u8::try_from(witness_seq % 256).unwrap()],
        }
    }

    /// I-24, ADR-010 "Self-hosted witness": the loader of a whole store
    /// takes sequences 1, 2, 3 and refuses a deleted middle record, a
    /// deleted first record and a store that starts above 1.
    #[test]
    fn i24_file_store_loader_refuses_a_missing_record() {
        let whole = encode_file_store(&[rec(1), rec(2), rec(3)]).unwrap();
        assert_eq!(load_file_store(&whole).unwrap().len(), 3);
        assert_eq!(load_file_store(&[]).unwrap(), Vec::new());
        for gap in [vec![rec(1), rec(3)], vec![rec(2), rec(3)], vec![rec(5)]] {
            let bytes = encode_file_store(&gap).unwrap();
            assert!(decode_file_store(&bytes).is_ok(), "framing is sound");
            assert_eq!(
                load_file_store(&bytes),
                Err(WitnessError::Invalid(Invalid::SequenceGap)),
                "{gap:?}"
            );
        }
    }

    /// I-24, design section 15: the largest prepare the witness accepts,
    /// with its receipt, fits in one file record and decodes back.
    #[test]
    fn i24_file_store_holds_the_largest_prepare_and_its_receipt() {
        let cell = CellId([9; 16]);
        let chain = ChainId::App;
        let prev = (0, genesis(cell, chain));
        let stored_hashes = vec![[0x5A; 32]; MAX_PREPARE_ROWS];
        let mut head = prev;
        for sh in &stored_hashes {
            head = (head.0 + 1, link_of(&head.1, cell, chain, head.0 + 1, sh));
        }
        let p = Prepare {
            prev,
            stored_hashes,
            anchor: Anchor {
                cell,
                chain,
                n: head.0,
                link: head.1,
                at: 0,
                signature: vec![0; SIGNATURE_LEN],
            },
        };
        let message = encode_witness_message(&WitnessMessage::Prepare(p.clone())).unwrap();
        assert_eq!(message.len(), MAX_MESSAGE_LEN);
        let receipt = encode_receipt(&Receipt {
            cell,
            chain,
            fields: ReceiptFields {
                n: head.0,
                link: head.1,
                witness_seq: 1,
                witness_link: Link([1; 32]),
                received_at: 0,
            },
            signature: vec![0; SIGNATURE_LEN],
        })
        .unwrap();
        assert_eq!(receipt.len(), RECEIPT_ENCODED_LEN);
        let mut bytes = message;
        bytes.extend_from_slice(&receipt);
        assert_eq!(bytes.len(), MAX_FILE_RECORD_LEN);
        let file = encode_file_store(&[FileRecord {
            witness_seq: 1,
            bytes,
        }])
        .unwrap();
        let back = load_file_store(&file).unwrap();
        assert_eq!(back.len(), 1);
        let (m, _) = back[0].bytes.split_at(MAX_MESSAGE_LEN);
        assert_eq!(decode_witness_message(m), Ok(WitnessMessage::Prepare(p)));
        let over = FileRecord {
            witness_seq: 1,
            bytes: vec![0; MAX_FILE_RECORD_LEN + 1],
        };
        assert!(encode_file_store(&[over]).is_err(), "over the limit");
    }
}
