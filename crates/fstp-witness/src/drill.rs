//! The restore drill's offline check of a restored chain against fetched
//! witness copies (ADR-012 record of lane m10/drill-chain).
//!
//! `fstp-cell check-chain` and `fstp-vault check-chain` read the restored
//! chain from a scratch cluster, then call [`load_copy`] on the copies
//! that `fstp-backup witness-fetch` wrote, and [`check_restored`] on both.
//! The copy loads with the file store reader, which recomputes every
//! witness link, so a changed, cut or missing record refuses it. The
//! anchor key history is the one the copy's registry holds for the cell
//! and chain, the keys the witness checked each prepare under. Nothing
//! here writes a file or reaches a witness.

use std::path::Path;

use fstp_audit::verify::{ChainView, RestoredCopy, verify_restored};
use fstp_audit::{AnchorRow, AuditError, CellId, ChainId, StoredEntry, StoredRow, WitnessRecord};
use fstp_obs::drill_status::{ChainCheck, instant_of_micros};

use crate::file_store::FileStore;
use crate::store::StoreError;

/// One chain of a fetched witness copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopiedChain {
    /// The witness log of the chain, in witness order.
    pub log: Vec<WitnessRecord>,
    /// The chain's anchor key history in the copy's registry.
    pub anchor_keys: Vec<Vec<u8>>,
}

/// Loads `cell`'s `chain` from the fetched witness copy in `dir`. Every
/// file of the copy loads first, as at a witness start. A missing
/// directory is refused, never created.
///
/// # Errors
///
/// [`StoreError::Unavailable`] for a missing directory or a file that
/// does not read, and [`StoreError::Corrupt`] for a file that does not
/// load or a cell that the copy does not register.
pub fn load_copy(dir: &Path, cell: CellId, chain: ChainId) -> Result<CopiedChain, StoreError> {
    if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Err(StoreError::Unavailable("witness copy directory"));
    }
    let store = FileStore::open(dir)?;
    let registered = store
        .load_registry()?
        .into_iter()
        .find(|c| c.cell == cell)
        .ok_or(StoreError::Corrupt("a cell the witness copy does not hold"))?;
    let anchor_keys = match chain {
        ChainId::App => registered.app_keys,
        ChainId::Vault => registered.vault_keys,
    };
    let log = store.load_chain(cell, chain)?.log;
    Ok(CopiedChain { log, anchor_keys })
}

/// The check line of a verified restored chain (ADR-012 record of lane
/// m10/drill-chain, row "Check line").
#[must_use]
pub fn check_line(r: &RestoredCopy) -> ChainCheck {
    let n = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
    ChainCheck {
        rows: r.verified.rows,
        checked: r.checked,
        later: r.later,
        oldest_later: r.oldest_later.map(instant_of_micros),
        oldest_newer: r.oldest_newer.map(instant_of_micros),
        lost: n(r.verified.lost_in_restore.len()),
        doubt: n(r.verified.possible_deletions.len()),
    }
}

/// The restored rows, ledger entries and anchor rows of a chain.
#[derive(Clone, Copy, Debug)]
pub struct Restored<'a> {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The chain rows with their links, by row number.
    pub rows: &'a [StoredRow],
    /// The stored entries the kind 1 rows name.
    pub ledger: &'a [StoredEntry],
    /// The anchor rows with their receipts, by row number.
    pub anchors: &'a [AnchorRow],
}

/// Checks a restored chain against its copy with
/// `fstp_audit::verify::verify_restored`, under the pinned witness
/// receipt keys `witness_keys`.
///
/// # Errors
///
/// [`AuditError::Tamper`] with the first finding.
pub fn check_restored(
    restored: &Restored<'_>,
    copy: &CopiedChain,
    witness_keys: &[Vec<u8>],
) -> Result<ChainCheck, AuditError> {
    verify_restored(&ChainView {
        cell: restored.cell,
        chain: restored.chain,
        rows: restored.rows,
        ledger: restored.ledger,
        anchors: restored.anchors,
        witness: &copy.log,
        anchor_keys: &copy.anchor_keys,
        witness_keys,
    })
    .map(|r| check_line(&r))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use fstp_audit::{Link, LostInRestore, Verified};

    fn dir(tag: &str) -> std::path::PathBuf {
        let r = fstp_crypto::random_array::<6>().unwrap();
        std::env::temp_dir().join(format!(
            "fstp-witness-drill-{tag}-{}",
            r.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }

    /// ADR-012 record of lane m10/drill-chain, row "Keys": a copy gives
    /// the chain's anchor key history from its registry, and refuses a
    /// missing directory, never creating it, and a cell it does not hold.
    #[test]
    fn adr012_dc_copy_gives_the_registered_anchor_keys() {
        let d = dir("keys");
        assert_eq!(
            load_copy(&d, CellId([1; 16]), ChainId::App),
            Err(StoreError::Unavailable("witness copy directory"))
        );
        assert!(!d.exists(), "a missing copy is never created");
        let mut fs = FileStore::open(&d).unwrap();
        let cell = CellId([4; 16]);
        fs.register_cell(cell, b"synthetic ca", 1).unwrap();
        fs.register_anchor_key(cell, ChainId::App, &[0xA1; 8], 2)
            .unwrap();
        fs.register_anchor_key(cell, ChainId::Vault, &[0xB1; 8], 3)
            .unwrap();
        fs.register_anchor_key(cell, ChainId::App, &[0xA2; 8], 4)
            .unwrap();
        let app = load_copy(&d, cell, ChainId::App).unwrap();
        assert_eq!(app.anchor_keys, vec![vec![0xA1; 8], vec![0xA2; 8]]);
        assert!(app.log.is_empty());
        let vault = load_copy(&d, cell, ChainId::Vault).unwrap();
        assert_eq!(vault.anchor_keys, vec![vec![0xB1; 8]]);
        assert!(matches!(
            load_copy(&d, CellId([5; 16]), ChainId::App),
            Err(StoreError::Corrupt(_))
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// ADR-012 record of lane m10/drill-chain, row "Check line": the
    /// verdict maps to the line, with witness times in Unix seconds and
    /// the findings counted.
    #[test]
    fn adr012_dc_restored_copy_maps_to_the_check_line() {
        let r = RestoredCopy {
            verified: Verified {
                rows: 9,
                possible_deletions: vec![(3, Link([1; 32]))],
                lost_in_restore: vec![
                    LostInRestore {
                        from: 2,
                        to: 4,
                        job: [7; 16],
                    },
                    LostInRestore {
                        from: 6,
                        to: 6,
                        job: [8; 16],
                    },
                ],
            },
            checked: 7,
            later: 1,
            oldest_later: Some(1_795_000_100_500_000),
            oldest_newer: Some(1_795_000_050_000_001),
        };
        assert_eq!(
            check_line(&r),
            ChainCheck {
                rows: 9,
                checked: 7,
                later: 1,
                oldest_later: Some(1_795_000_100),
                oldest_newer: Some(1_795_000_050),
                lost: 2,
                doubt: 1,
            }
        );
    }
}
