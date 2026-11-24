//! Keystore snapshots of the Vault chain (ADR-012 and ADR-004 records of
//! lane L17, I-81, R-KY-02, R-NF-08).
//!
//! # The image
//!
//! A snapshot holds the vault keystore image `"FVK1"`: every root row,
//! every live group, data key and tuple row, and the intent row, as
//! [`crate::keystore::read_rows`] reads them. Every key in it is sealed:
//! the seal keys under their roots, the group secrets under a seal key,
//! the data keys to their group keys and the tuples under their data keys.
//! So an image opens only through custody, and only while a root of its
//! rows lives (I-80, I-81).
//!
//! ```text
//! image  = "FVK1" | version u8 = 1 | cell 16
//!          | n u32 | root* | n u32 | group* | n u32 | key* | n u32 | tuple*
//!          | has_intent u8 | intent?
//! root   = epoch u64 | backend u8 | state u8 | created_at i64
//!          | len u16 | handle | len u16 | wrapped | len u16 | receipt
//! group  = group 16 | generation u32 | purpose u8 | epoch u64
//!          | len u32 | public | len u32 | sealed
//! key    = id 16 | group 16 | generation u32 | sealed 1210
//! tuple  = identity 16 | group 16 | len u32 | envelope
//! intent = id 16 | phase i16 | len u32 | plan
//! ```
//!
//! Integers are big-endian. An empty receipt is none. Rows are strictly
//! increasing by epoch, by group and generation, by id and by identity, so
//! the decoder admits one spelling only. It bounds every length and
//! refuses trailing bytes. Fuzzed (`vault_keystore_image_decode`).
//!
//! # The restore rule
//!
//! [`restore_order`] ranks the copies a restore may take, and
//! [`restore_with`] takes the first that opens, whole (ADR-012 record of
//! lane L17, row "Restore rule, vault").

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use fstp_backup::Snapshots;
use fstp_custody::Custody;
use fstp_keys::envelope::SEALED_KEY_LEN;
use fstp_obs::{SnapshotChain, SnapshotFailure, SnapshotTrigger, snapshot_status};
use fstp_pgwire::Client;
use fstp_rt::Runtime;

use crate::VaultError;
use crate::keystore::{
    self, Change, DataKeyRow, GroupRow, IntentRow, KeystoreRows, RootRow, STATE_DESTROYED,
    STATE_LIVE, STATE_PENDING, TupleRow,
};

/// The magic of a vault keystore image.
pub const IMAGE_MAGIC: [u8; 4] = *b"FVK1";
/// The only image version.
pub const IMAGE_VERSION: u8 = 1;
/// The longest custody handle, wrapped seal key or receipt.
pub const MAX_SHORT: usize = 4096;
/// The longest group public key or sealed group secret.
pub const MAX_GROUP_FIELD: usize = 64 * 1024;
/// The longest sealed tuple.
pub const MAX_ENVELOPE: usize = 64 * 1024;
/// The longest sealed chain state.
pub const MAX_PLAN: usize = 64 * 1024 * 1024;

fn bad(rule: &'static str) -> VaultError {
    VaultError::Malformed(rule)
}

/// Encodes the image of `rows` of `cell`.
///
/// # Errors
///
/// [`VaultError::Malformed`] for rows out of order, a field too long, a
/// code out of range, or an empty receipt.
pub fn encode_image(cell: &[u8; 16], rows: &KeystoreRows) -> Result<Vec<u8>, VaultError> {
    let mut out = IMAGE_MAGIC.to_vec();
    out.push(IMAGE_VERSION);
    out.extend_from_slice(cell);
    let mut roots: Vec<&RootRow> = rows.all_roots().collect();
    roots.sort_by_key(|r| r.epoch);
    put_count(&mut out, roots.len())?;
    let mut last = None;
    for r in roots {
        if last.is_some_and(|e| e >= r.epoch) {
            return Err(bad("the image root order"));
        }
        last = Some(r.epoch);
        out.extend_from_slice(&r.epoch.to_be_bytes());
        out.push(code(r.backend, 1, 3, "the image root backend")?);
        out.push(code(
            r.state,
            STATE_LIVE,
            STATE_PENDING,
            "the image root state",
        )?);
        out.extend_from_slice(&r.created_at.to_be_bytes());
        put16(&mut out, &r.handle)?;
        put16(&mut out, &r.wrapped)?;
        match &r.receipt {
            Some(x) if x.is_empty() => return Err(bad("the image receipt")),
            Some(x) => put16(&mut out, x)?,
            None => put16(&mut out, &[])?,
        }
    }
    put_count(&mut out, rows.groups.len())?;
    let mut last = None;
    for g in &rows.groups {
        let k = (g.group, g.generation);
        if last.is_some_and(|l| l >= k) {
            return Err(bad("the image group order"));
        }
        last = Some(k);
        out.extend_from_slice(&g.group);
        out.extend_from_slice(&g.generation.to_be_bytes());
        out.push(g.purpose);
        out.extend_from_slice(&g.epoch.to_be_bytes());
        put32(&mut out, &g.public_key, MAX_GROUP_FIELD)?;
        put32(&mut out, &g.sealed_secret, MAX_GROUP_FIELD)?;
    }
    put_count(&mut out, rows.data_keys.len())?;
    let mut last = None;
    for d in &rows.data_keys {
        if last.is_some_and(|l| l >= d.id) {
            return Err(bad("the image data key order"));
        }
        last = Some(d.id);
        if d.sealed.len() != SEALED_KEY_LEN {
            return Err(bad("the image sealed key"));
        }
        out.extend_from_slice(&d.id);
        out.extend_from_slice(&d.group);
        out.extend_from_slice(&d.generation.to_be_bytes());
        out.extend_from_slice(&d.sealed);
    }
    put_count(&mut out, rows.tuples.len())?;
    let mut last = None;
    for t in &rows.tuples {
        if last.is_some_and(|l| l >= t.identity) {
            return Err(bad("the image tuple order"));
        }
        last = Some(t.identity);
        out.extend_from_slice(&t.identity);
        out.extend_from_slice(&t.group);
        put32(&mut out, &t.envelope, MAX_ENVELOPE)?;
    }
    match &rows.intent {
        None => out.push(0),
        Some(i) => {
            out.push(1);
            out.extend_from_slice(&i.id);
            if !(0..=5).contains(&i.phase) {
                return Err(bad("the image intent phase"));
            }
            out.extend_from_slice(&i.phase.to_be_bytes());
            put32(&mut out, &i.plan, MAX_PLAN)?;
        }
    }
    Ok(out)
}

fn code(v: i16, lo: i16, hi: i16, rule: &'static str) -> Result<u8, VaultError> {
    if (lo..=hi).contains(&v) {
        u8::try_from(v).map_err(|_| bad(rule))
    } else {
        Err(bad(rule))
    }
}

fn put_count(out: &mut Vec<u8>, n: usize) -> Result<(), VaultError> {
    let n = u32::try_from(n).map_err(|_| bad("the image row count"))?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), VaultError> {
    if field.len() > MAX_SHORT {
        return Err(bad("the image field length"));
    }
    let n = u16::try_from(field.len()).map_err(|_| bad("the image field length"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn put32(out: &mut Vec<u8>, field: &[u8], max: usize) -> Result<(), VaultError> {
    if field.len() > max {
        return Err(bad("the image field length"));
    }
    let n = u32::try_from(field.len()).map_err(|_| bad("the image field length"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(bad("a truncated keystore image"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, VaultError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32, VaultError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, VaultError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, VaultError> {
        usize::try_from(self.u32()?).map_err(|_| bad("the image row count"))
    }

    fn field16(&mut self) -> Result<Vec<u8>, VaultError> {
        let n = usize::from(u16::from_be_bytes(self.array()?));
        if n > MAX_SHORT {
            return Err(bad("the image field length"));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn field32(&mut self, max: usize) -> Result<Vec<u8>, VaultError> {
        let n = usize::try_from(self.u32()?).map_err(|_| bad("the image field length"))?;
        if n > max {
            return Err(bad("the image field length"));
        }
        Ok(self.take(n)?.to_vec())
    }
}

/// Decodes an image into its cell and rows. Fuzzed
/// (`vault_keystore_image_decode`).
///
/// # Errors
///
/// [`VaultError::Malformed`] naming the rule broken: the magic, the
/// version, a length, a code, the row order, a keystore with no live
/// root, or trailing bytes. It never quotes the input (R-NF-02).
pub fn decode_image(bytes: &[u8]) -> Result<([u8; 16], KeystoreRows), VaultError> {
    let mut r = Reader { rest: bytes };
    if r.array::<4>()? != IMAGE_MAGIC {
        return Err(bad("the image magic"));
    }
    if r.u8()? != IMAGE_VERSION {
        return Err(bad("the image version"));
    }
    let cell = r.array::<16>()?;
    let n = r.count()?;
    let mut roots: Vec<RootRow> = Vec::new();
    for _ in 0..n {
        let epoch = r.u64()?;
        if roots.last().is_some_and(|l| l.epoch >= epoch) {
            return Err(bad("the image root order"));
        }
        let backend = i16::from(r.u8()?);
        if !(1..=3).contains(&backend) {
            return Err(bad("the image root backend"));
        }
        let state = i16::from(r.u8()?);
        if ![STATE_LIVE, STATE_DESTROYED, STATE_PENDING].contains(&state) {
            return Err(bad("the image root state"));
        }
        let created_at = i64::from_be_bytes(r.array()?);
        let handle = r.field16()?;
        let wrapped = r.field16()?;
        let receipt = r.field16()?;
        roots.push(RootRow {
            epoch,
            backend,
            handle,
            wrapped,
            created_at,
            state,
            receipt: (!receipt.is_empty()).then_some(receipt),
        });
    }
    let n = r.count()?;
    let mut groups: Vec<GroupRow> = Vec::new();
    for _ in 0..n {
        let group = r.array::<16>()?;
        let generation = r.u32()?;
        if groups
            .last()
            .is_some_and(|l| (l.group, l.generation) >= (group, generation))
        {
            return Err(bad("the image group order"));
        }
        let purpose = r.u8()?;
        let epoch = r.u64()?;
        let public_key = r.field32(MAX_GROUP_FIELD)?;
        let sealed_secret = r.field32(MAX_GROUP_FIELD)?;
        groups.push(GroupRow {
            purpose,
            group,
            generation,
            public_key,
            sealed_secret,
            epoch,
        });
    }
    let n = r.count()?;
    let mut data_keys: Vec<DataKeyRow> = Vec::new();
    for _ in 0..n {
        let id = r.array::<16>()?;
        if data_keys.last().is_some_and(|l| l.id >= id) {
            return Err(bad("the image data key order"));
        }
        let group = r.array::<16>()?;
        let generation = r.u32()?;
        let sealed = r.take(SEALED_KEY_LEN)?.to_vec();
        data_keys.push(DataKeyRow {
            id,
            group,
            generation,
            sealed,
        });
    }
    let n = r.count()?;
    let mut tuples: Vec<TupleRow> = Vec::new();
    for _ in 0..n {
        let identity = r.array::<16>()?;
        if tuples.last().is_some_and(|l| l.identity >= identity) {
            return Err(bad("the image tuple order"));
        }
        let group = r.array::<16>()?;
        let envelope = r.field32(MAX_ENVELOPE)?;
        tuples.push(TupleRow {
            identity,
            group,
            envelope,
        });
    }
    let intent = match r.u8()? {
        0 => None,
        1 => {
            let id = r.array::<16>()?;
            let phase = i16::from_be_bytes(r.array()?);
            if !(0..=5).contains(&phase) {
                return Err(bad("the image intent phase"));
            }
            let plan = r.field32(MAX_PLAN)?;
            Some(IntentRow { id, plan, phase })
        }
        _ => return Err(bad("the image intent flag")),
    };
    if !r.rest.is_empty() {
        return Err(bad("trailing bytes after the keystore image"));
    }
    let current = roots
        .iter()
        .rposition(|x| x.state == STATE_LIVE)
        .ok_or(bad("a keystore image with no live root"))?;
    let root = roots.remove(current);
    Ok((
        cell,
        KeystoreRows {
            root,
            others: roots,
            groups,
            data_keys,
            tuples,
            intent,
        },
    ))
}

// ---------------------------------------------------------------------
// The restore rule.
// ---------------------------------------------------------------------

/// Where a copy of the keystore rows comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// A keystore that still lives.
    Live,
    /// The restored backup's own rows.
    Backup,
    /// A keystore snapshot.
    Snapshot,
}

/// Ranks the copies a restore may take (ADR-012 record of lane L17, row
/// "Restore rule, vault"): a live keystore first, then by the epoch of the
/// copy's current root, higher first. At an equal epoch the restored
/// backup ranks above the snapshot, since the only snapshot of an epoch is
/// the one step 5 took before the backup's rows.
#[must_use]
pub fn restore_order<'a>(
    live: Option<&'a KeystoreRows>,
    snapshot: Option<&'a KeystoreRows>,
    backup: Option<&'a KeystoreRows>,
) -> Vec<(Source, &'a KeystoreRows)> {
    let mut out: Vec<(Source, &KeystoreRows)> = Vec::new();
    if let Some(l) = live {
        out.push((Source::Live, l));
    }
    let mut rest: Vec<(Source, &KeystoreRows)> = [
        backup.map(|b| (Source::Backup, b)),
        snapshot.map(|s| (Source::Snapshot, s)),
    ]
    .into_iter()
    .flatten()
    .collect();
    rest.sort_by(|a, b| b.1.root.epoch.cmp(&a.1.root.epoch).then(a.0.cmp(&b.0)));
    out.extend(rest);
    out
}

/// The changes that make the stored rows `from` into `to`, whole.
fn changes_to(from: Option<&KeystoreRows>, to: &KeystoreRows) -> Vec<Change> {
    let mut out = Vec::new();
    for r in to.all_roots() {
        out.push(Change::PutRoot(r.clone()));
    }
    if let Some(f) = from {
        for g in &f.groups {
            if !to
                .groups
                .iter()
                .any(|x| (x.group, x.generation) == (g.group, g.generation))
            {
                out.push(Change::DropGroup(g.group, g.generation));
            }
        }
        for d in &f.data_keys {
            if !to.data_keys.iter().any(|x| x.id == d.id) {
                out.push(Change::DropDataKey(d.id));
            }
        }
        for t in &f.tuples {
            if !to.tuples.iter().any(|x| x.identity == t.identity) {
                out.push(Change::DropTuple(t.identity));
            }
        }
        if let Some(i) = &f.intent
            && to.intent.as_ref().is_none_or(|x| x.id != i.id)
        {
            out.push(Change::DropIntent(i.id));
        }
    }
    out.extend(to.groups.iter().cloned().map(Change::PutGroup));
    out.extend(to.data_keys.iter().cloned().map(Change::PutDataKey));
    out.extend(to.tuples.iter().cloned().map(Change::PutTuple));
    if let Some(i) = &to.intent {
        out.push(Change::PutIntent(i.clone()));
    }
    out
}

/// Writes `rows` over the stored keystore of `client` in one transaction,
/// whole: every row of `rows` is put, and every group, data key, tuple and
/// intent row that `rows` lacks is deleted. Root rows are only put, so a
/// destroyed root keeps its row and receipt.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when the read or the write fails.
pub async fn write_copy<R: Runtime>(
    client: &mut Client<R>,
    rows: &KeystoreRows,
    now: i64,
) -> Result<(), VaultError> {
    let stored = keystore::read_rows(client).await?;
    keystore::apply_changes(client, &changes_to(stored.as_ref(), rows), now).await
}

/// `fstp-vault restore-keystore` over the keys login `client`, which
/// holds the keystore lock: reads the restored rows, fetches snapshot
/// `id` (or the newest one `snapshots` names), takes the first copy of
/// [`restore_order`] whose rows all open through `custody`
/// ([`crate::erasure::check_rows`]), and writes it whole in one
/// transaction. Returns where the copy came from.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when no copy opens, or a read, fetch or
/// write fails.
pub async fn restore_with<R: Runtime, C: Custody>(
    client: &mut Client<R>,
    custody: &C,
    cell: [u8; 16],
    snapshots: Option<&Snapshots>,
    id: Option<[u8; 16]>,
    now: i64,
) -> Result<Source, VaultError> {
    let backup = keystore::read_rows(client).await?;
    let id = match (snapshots, id) {
        (Some(_), Some(id)) => Some(id),
        (Some(s), None) => s
            .latest()
            .await
            .map_err(|_| VaultError::Unavailable("the snapshot pointer"))?,
        (None, _) => None,
    };
    let snapshot = match (snapshots, id) {
        (Some(s), Some(id)) => {
            let image = s
                .fetch(custody, id)
                .await
                .map_err(|_| VaultError::Unavailable("the keystore snapshot"))?;
            let (c, rows) = decode_image(&image)?;
            if c != cell {
                return Err(bad("the snapshot cell"));
            }
            Some(rows)
        }
        _ => None,
    };
    for (source, rows) in restore_order(None, snapshot.as_ref(), backup.as_ref()) {
        if crate::erasure::check_rows(custody, &cell, rows)
            .await
            .is_err()
        {
            continue;
        }
        if source != Source::Backup {
            write_copy(client, rows, now).await?;
        }
        return Ok(source);
    }
    Err(VaultError::Unavailable("a keystore copy that opens"))
}

// ---------------------------------------------------------------------
// The snapshot without a rotation, and the daily snapshot.
// ---------------------------------------------------------------------

/// A failed snapshot step and its error (ADR-012 record of lane
/// m10/backup-followups, row "Failure reason").
pub type Failed = (SnapshotFailure, VaultError);

/// The step of a failed upload of the snapshot writer.
#[must_use]
pub fn upload_failure(e: &fstp_backup::BackupError) -> SnapshotFailure {
    use fstp_backup::BackupError as B;
    match e {
        B::Custody(_) | B::KeyFile(_) => SnapshotFailure::Custody,
        B::Seal(_) => SnapshotFailure::Image,
        _ => SnapshotFailure::Upload,
    }
}

/// The step of a failed fetch of the snapshot reader: custody, the store,
/// or a copy that did not verify or open.
#[must_use]
pub fn fetch_failure(e: &fstp_backup::BackupError) -> SnapshotFailure {
    use fstp_backup::BackupError as B;
    match e {
        B::Custody(_) | B::KeyFile(_) => SnapshotFailure::Custody,
        B::NotFound | B::S3Status(_) | B::S3Refused(_) | B::Transport(_) | B::Xml(_) | B::Io(_) => {
            SnapshotFailure::Fetch
        }
        _ => SnapshotFailure::Open,
    }
}

/// The step of a failed pointer write.
#[must_use]
pub fn pointer_failure(e: &fstp_backup::BackupError) -> SnapshotFailure {
    use fstp_backup::BackupError as B;
    match e {
        B::Custody(_) | B::KeyFile(_) => SnapshotFailure::Custody,
        _ => SnapshotFailure::Pointer,
    }
}

/// Takes a snapshot of `rows` and checks it, with no rotation (ADR-012
/// record of lane L27, row "Daily snapshot"): seals and uploads their
/// image, fetches it back, opens it with the vault's snapshot key through
/// `custody`, and checks that its rows all open under their own current
/// root ([`crate::erasure::check_rows`]). Only then is the pointer
/// written. Nothing is rotated or destroyed.
///
/// # Errors
///
/// The failed step (ADR-012 record of lane m10/backup-followups) with
/// [`VaultError::Unavailable`] for a failed upload, fetch or pointer
/// write, and [`VaultError::Malformed`] for a snapshot that does not
/// open.
pub async fn snapshot_once<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    snapshots: &Snapshots,
    rows: &KeystoreRows,
) -> Result<(), Failed> {
    let check = |e: VaultError| (SnapshotFailure::Check, e);
    let image = encode_image(&cell, rows).map_err(|e| (SnapshotFailure::Image, e))?;
    let id = snapshots.upload(custody, &image).await.map_err(|e| {
        (
            upload_failure(&e),
            VaultError::Unavailable("the keystore snapshot upload"),
        )
    })?;
    let fetched = snapshots.fetch(custody, id).await.map_err(|e| {
        (
            fetch_failure(&e),
            VaultError::Unavailable("the keystore snapshot fetch"),
        )
    })?;
    let (c, back) = decode_image(&fetched).map_err(check)?;
    if c != cell || back.root.epoch != rows.root.epoch {
        return Err(check(bad("the snapshot root")));
    }
    crate::erasure::check_rows(custody, &cell, &back)
        .await
        .map_err(check)?;
    snapshots.publish(custody, id).await.map_err(|e| {
        (
            pointer_failure(&e),
            VaultError::Unavailable("the keystore snapshot pointer"),
        )
    })
}

/// Records one snapshot try: the status file in `dir`, if any, and one
/// typed event, each naming the failed step, if any (ADR-012 records of
/// lanes L27 and m10/backup-followups, rows "Event", "Status file" and
/// "Failure reason"). A status file that does not write is skipped: the
/// event still says what happened.
pub fn note(dir: Option<&Path>, trigger: SnapshotTrigger, failure: Option<SnapshotFailure>) {
    if let Some(d) = dir {
        let _ = snapshot_status::record(d, failure, snapshot_status::now());
    }
    let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::KeystoreSnapshot {
        chain: SnapshotChain::Vault,
        trigger,
        failure,
    });
}

/// A boxed future of a daily snapshot.
pub type DailyFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// The daily snapshot of a serving vault: what the task beside the
/// keystore watch runs once a day with the rows it read
/// (`crate::service::RegistrarParts::daily`).
pub trait DailySnapshot: Send + Sync {
    /// Takes, checks and records one snapshot of `rows`. Whether it
    /// verified.
    fn run(&self, rows: KeystoreRows) -> DailyFuture<'_>;
    /// Records a try that failed before it had rows to snapshot: the
    /// keystore rows did not read from the vault's database.
    fn failed(&self);
    /// Whether a request file asks for a snapshot now, which this takes
    /// (ADR-012 record of lane m10/store-reconnect, row "Snapshot
    /// request"). None by default.
    fn requested(&self) -> bool {
        false
    }
}

/// The daily snapshot over `custody`, writing the status file in
/// `status_dir`.
pub struct Daily<C> {
    /// The cell.
    pub cell: [u8; 16],
    /// The snapshot writer.
    pub snapshots: Snapshots,
    /// The vault's own custody entry.
    pub custody: C,
    /// The directory of the status file: the credentials directory.
    pub status_dir: Option<PathBuf>,
}

impl<C: Custody + Send + Sync> DailySnapshot for Daily<C> {
    fn run(&self, rows: KeystoreRows) -> DailyFuture<'_> {
        Box::pin(async move {
            let failure = snapshot_once(&self.custody, self.cell, &self.snapshots, &rows)
                .await
                .err()
                .map(|(step, _)| step);
            note(self.status_dir.as_deref(), SnapshotTrigger::Daily, failure);
            failure.is_none()
        })
    }

    fn failed(&self) {
        note(
            self.status_dir.as_deref(),
            SnapshotTrigger::Daily,
            Some(SnapshotFailure::Database),
        );
    }

    fn requested(&self) -> bool {
        self.status_dir
            .as_deref()
            .is_some_and(fstp_obs::snapshot_status::take_request)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn root(epoch: u64, state: i16) -> RootRow {
        RootRow {
            epoch,
            backend: 2,
            handle: vec![epoch as u8; 9],
            wrapped: vec![0x60; 60],
            created_at: 7,
            state,
            receipt: (state == STATE_DESTROYED).then(|| b"gone".to_vec()),
        }
    }

    fn rows(epoch: u64) -> KeystoreRows {
        KeystoreRows {
            root: root(epoch, STATE_LIVE),
            others: (1..epoch).map(|e| root(e, STATE_DESTROYED)).collect(),
            groups: vec![
                GroupRow {
                    purpose: 12,
                    group: [1; 16],
                    generation: 1,
                    public_key: vec![2; 1216],
                    sealed_secret: vec![3; 2460],
                    epoch,
                },
                GroupRow {
                    purpose: 10,
                    group: [1; 16],
                    generation: 2,
                    public_key: vec![4; 1216],
                    sealed_secret: vec![5; 2460],
                    epoch,
                },
            ],
            data_keys: vec![DataKeyRow {
                id: [6; 16],
                group: [1; 16],
                generation: 2,
                sealed: vec![7; SEALED_KEY_LEN],
            }],
            tuples: vec![TupleRow {
                identity: [6; 16],
                group: [1; 16],
                envelope: vec![8; 90],
            }],
            intent: Some(IntentRow {
                id: [9; 16],
                plan: vec![10; 40],
                phase: 0,
            }),
        }
    }

    /// ADR-012 record of lane L17: the vault keystore image round trips,
    /// re-encodes byte for byte, and refuses a cut, a trailing byte, rows
    /// out of order, a bad code and an image with no live root.
    #[test]
    fn adr012_vault_keystore_image_round_trips_in_one_spelling() {
        let cell = [0x42; 16];
        let r = rows(3);
        let bytes = encode_image(&cell, &r).unwrap();
        let (c, back) = decode_image(&bytes).unwrap();
        assert_eq!(c, cell);
        assert!(back == r, "the rows changed in the round trip");
        assert_eq!(encode_image(&c, &back).unwrap(), bytes);
        for cut in [0, 4, 20, bytes.len() - 1] {
            assert!(decode_image(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_image(&long).is_err());
        let mut swapped = r.clone();
        swapped.groups.swap(0, 1);
        assert!(encode_image(&cell, &swapped).is_err());
        let mut no_live = r.clone();
        no_live.root.state = STATE_DESTROYED;
        no_live.root.receipt = Some(b"x".to_vec());
        let b = encode_image(&cell, &no_live).unwrap();
        assert!(decode_image(&b).is_err());
        let mut bad_state = bytes.clone();
        // The state byte of the first root: magic, version, cell, count,
        // epoch, backend.
        bad_state[4 + 1 + 16 + 4 + 8 + 1] = 9;
        assert!(decode_image(&bad_state).is_err());
        let mut empty_receipt = r;
        empty_receipt.others[0].receipt = Some(Vec::new());
        assert!(encode_image(&cell, &empty_receipt).is_err());
    }

    /// ADR-012 record of lane L17, row "Restore rule, vault": a live
    /// keystore ranks first; otherwise the copy at the higher epoch; at an
    /// equal epoch the restored backup before the snapshot.
    #[test]
    fn adr012_vault_restore_order_ranks_live_then_epoch_then_backup() {
        let (e2, e3, e3b) = (rows(2), rows(3), rows(3));
        let srcs = |v: Vec<(Source, &KeystoreRows)>| v.into_iter().map(|x| x.0).collect::<Vec<_>>();
        assert_eq!(
            srcs(restore_order(Some(&e2), Some(&e3), Some(&e3b))),
            vec![Source::Live, Source::Backup, Source::Snapshot]
        );
        assert_eq!(
            srcs(restore_order(None, Some(&e3), Some(&e2))),
            vec![Source::Snapshot, Source::Backup]
        );
        assert_eq!(
            srcs(restore_order(None, Some(&e2), Some(&e3))),
            vec![Source::Backup, Source::Snapshot]
        );
        assert_eq!(
            srcs(restore_order(None, Some(&e3), Some(&e3b))),
            vec![Source::Backup, Source::Snapshot]
        );
        assert_eq!(
            srcs(restore_order(None, Some(&e3), None)),
            vec![Source::Snapshot]
        );
        assert!(restore_order(None, None, None).is_empty());
    }
}
