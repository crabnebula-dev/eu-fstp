//! The restore rule of the App keystore (ADR-012 record of lane L27, row
//! "App restore"), the same rule as the vault's (record of lane L17).
//!
//! [`restore_order`] ranks the copies a restore may take: the copy at the
//! higher chain epoch first, and at an equal epoch the restored backup
//! before the snapshot, since the only snapshot of an epoch older than a
//! day is the one step 5 took before the backup's rows. [`choose`] takes
//! the first copy whose rows all open through custody ([`check_rows`]),
//! whole, and gives the changes that make the restored tables that copy.
//! It never mixes rows of two copies: a mix could bring back a key that a
//! later rotation dropped (I-81).

use fstp_custody::{Custody, SealKey};
use fstp_keys::envelope;
use fstp_pgstore::{Change, KeystoreChanges, KeystoreRows};

use super::{Keystore, NoSink, ctx_for, keys_err, open_group, open_signers, seal_aad};
use crate::CellError;

/// Where a kept copy came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The restored backup's own rows.
    Backup,
    /// The keystore snapshot.
    Snapshot,
}

fn epoch_of(rows: &KeystoreRows) -> Option<u64> {
    rows.chain.as_ref().map(|c| c.epoch)
}

/// Ranks the copies (module documentation). A copy with no chain row is
/// left out.
#[must_use]
pub fn restore_order<'a>(
    backup: Option<&'a KeystoreRows>,
    snapshot: Option<&'a KeystoreRows>,
) -> Vec<(Source, &'a KeystoreRows)> {
    let mut out: Vec<(Source, &KeystoreRows)> = [
        backup.map(|b| (Source::Backup, b)),
        snapshot.map(|s| (Source::Snapshot, s)),
    ]
    .into_iter()
    .flatten()
    .filter(|(_, r)| epoch_of(r).is_some())
    .collect();
    out.sort_by(|a, b| epoch_of(b.1).cmp(&epoch_of(a.1)).then(a.0.cmp(&b.0)));
    out
}

/// Opens every current key of a keystore loaded from rows, under the seal
/// key `s` of its epoch: the sealed chain state, every current group
/// secret, every current signing key, and one data key.
pub(super) fn open_loaded(ks: &mut Keystore, s: &SealKey) -> Result<(), CellError> {
    let groups = ks.open_groups(s)?;
    open_signers(s, ks)?;
    if let Some((dek, (g, generation, sealed))) = ks.keys.iter().next() {
        let sk = match groups.0.get(&(*g, *generation)) {
            Some(sk) => sk,
            None => {
                let row = ks
                    .groups
                    .get(&(*g, *generation))
                    .ok_or(keys_err("snapshot group"))?;
                &open_group(s, ks.cell, *g, *generation, row)?
            }
        };
        envelope::open_key(sk, sealed, &ctx_for(ks.cell, *g, *generation, dek.0))
            .map_err(|_| keys_err("snapshot sample"))?;
    }
    Ok(())
}

/// Checks that `rows` of `cell` open whole through `custody`: custody
/// unwraps the seal key of the chain row's epoch from its own root row,
/// and [`open_loaded`] opens every current key under it.
///
/// # Errors
///
/// [`CellError::Keys`] for rows that do not load or open, and
/// [`CellError::Custody`] for a refused unwrap.
pub async fn check_rows<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    rows: KeystoreRows,
) -> Result<(), CellError> {
    let mut ks = Keystore::from_rows(cell, rows, std::sync::Arc::new(NoSink))?;
    let e = ks.epoch();
    let row = ks
        .roots
        .get(&e)
        .cloned()
        .ok_or(keys_err("no root of the chain epoch"))?;
    let s = custody
        .unwrap(&row.root, &row.wrapped, &seal_aad(ks.cell, e))
        .await
        .map_err(CellError::Custody)?;
    open_loaded(&mut ks, &s)
}

fn diff<K: Ord + Clone, R: Clone>(
    from: &[R],
    to: &[R],
    key: impl Fn(&R) -> K,
) -> Vec<Change<K, R>> {
    let keep: std::collections::BTreeSet<K> = to.iter().map(&key).collect();
    let mut out: Vec<Change<K, R>> = from
        .iter()
        .map(&key)
        .filter(|k| !keep.contains(k))
        .map(Change::Delete)
        .collect();
    out.extend(to.iter().cloned().map(Change::Put));
    out
}

/// The changes that make the stored rows `from` into `to`, whole: every
/// row of `to` is put, and every row of `from` that `to` lacks is deleted.
#[must_use]
pub fn changes_to(from: Option<&KeystoreRows>, to: &KeystoreRows) -> KeystoreChanges {
    let empty = KeystoreRows::default();
    let f = from.unwrap_or(&empty);
    KeystoreChanges {
        chain: to.chain.clone(),
        roots: diff(&f.roots, &to.roots, |r| r.epoch),
        groups: diff(&f.groups, &to.groups, |g| (g.group, g.generation)),
        keys: diff(&f.keys, &to.keys, |k| k.id),
        texts: diff(&f.texts, &to.texts, |t| t.id),
        signers: diff(&f.signers, &to.signers, |s| (s.purpose, s.generation)),
        digests: diff(&f.digests, &to.digests, |d| d.digest),
        logins: diff(&f.logins, &to.logins, |l| l.account),
        requested: diff(&f.requested, &to.requested, |r| *r),
        displays: diff(&f.displays, &to.displays, |d| d.account),
    }
}

/// Applies the rule (module documentation) to the restored rows `backup`
/// and the snapshot rows `snapshot`. Returns where the kept copy came
/// from, and the changes to write when it is not the backup's own rows.
///
/// # Errors
///
/// [`CellError::Keys`] when no copy opens.
pub async fn choose<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    backup: Option<&KeystoreRows>,
    snapshot: Option<&KeystoreRows>,
) -> Result<(Source, Option<KeystoreChanges>), CellError> {
    for (source, rows) in restore_order(backup, snapshot) {
        if check_rows(custody, cell, rows.clone()).await.is_err() {
            continue;
        }
        let changes = match source {
            Source::Backup => None,
            Source::Snapshot => Some(changes_to(backup, rows)),
        };
        return Ok((source, changes));
    }
    Err(keys_err("no keystore copy opens"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use fstp_pgstore::ChainRow;

    fn at(epoch: u64) -> KeystoreRows {
        KeystoreRows {
            chain: Some(ChainRow {
                epoch,
                state: Vec::new(),
                lookup_group: None,
                login_group: None,
                startup_unwrap: None,
            }),
            ..KeystoreRows::default()
        }
    }

    /// ADR-012 record of lane L27, row "App restore": the copy at the
    /// higher epoch first; at an equal epoch the backup first; a copy with
    /// no chain row never.
    #[test]
    fn adr012_app_restore_order_ranks_epoch_then_backup() {
        let s = |v: Vec<(Source, &KeystoreRows)>| v.into_iter().map(|x| x.0).collect::<Vec<_>>();
        let (e2, e3) = (at(2), at(3));
        assert_eq!(
            s(restore_order(Some(&e2), Some(&e3))),
            vec![Source::Snapshot, Source::Backup]
        );
        assert_eq!(
            s(restore_order(Some(&e3), Some(&e2))),
            vec![Source::Backup, Source::Snapshot]
        );
        assert_eq!(
            s(restore_order(Some(&e3), Some(&at(3)))),
            vec![Source::Backup, Source::Snapshot]
        );
        let none = KeystoreRows::default();
        assert_eq!(
            s(restore_order(Some(&none), Some(&e2))),
            vec![Source::Snapshot]
        );
        assert!(restore_order(None, None).is_empty());
    }
}
