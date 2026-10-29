//! I-81: destroying a root or data key makes the protected data
//! unrecoverable, including from backups (design section 14.4,
//! T-ID-SHRED). The real-stack and file custody tests.
//!
//! Lane W1d wrote these tests before the production code. They are red
//! until the cell runtime (lane W3a), the backup agent (lane W2k), and
//! `fstp-keyd` with `KeydCustody` (lane W2f) land. Each harness part a
//! test needs and the harness lacks is a named seam below, so no test
//! passes on a missing part.
//!
//! The file custody tests make their key volumes under the directory that
//! `FSTP_KEY_VOLUME_DIR` names, which must be on ext4 or XFS. Without it
//! they fail with a named seam.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::reference::keys::{ACCEPTED_VOLUMES, REFUSED_VOLUMES, key_volume_accepted};
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_custody::{Aad, Custody, DestroyReceipt, KeydCustody, RootLabel, SealKey};
use fstp_keys::{CellId, Chain, Epoch};
use fstp_rt::future::block_on;

// ---------------------------------------------------------------------------
// Worlds.

fn world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

fn run(world: &World, steps: &[&str]) {
    let script = CycleScript {
        steps: steps.iter().map(|s| (*s).to_owned()).collect(),
    };
    if let Err(e) = world.run_cycle(0, &script).result {
        panic!("{e} (NotImplemented)");
    }
}

/// What trying every wrapped key of every copy found. The counts show
/// that the helper tried something, so an empty failure list means
/// something.
#[derive(Debug, Default)]
struct OpenReport {
    /// How many (copy, erased object) pairs it tried.
    erased_tried: usize,
    /// How many (copy, live object) pairs it tried.
    live_tried: usize,
    /// Erased objects that opened, by copy.
    erased_opened: Vec<String>,
    /// Live objects that did not open, by copy.
    live_failed: Vec<String>,
}

/// The seam of [`backup_copies`]: the world takes `pg_basebackup` copies
/// and WAL archives through `fstp-backup` and restores each into a fresh
/// server, but exposes no call for it. Lanes W2k and W3b add it.
const BACKUP_SEAM: &str = "fstp_celltest::world::World takes and restores no backups through fstp-backup (lanes W2k and W3b)";

/// Every backup copy of the world, each restored into a fresh server, and
/// the live store last.
fn backup_copies(world: &World) -> Result<Vec<StoreSet>, String> {
    let _ = world;
    Err(BACKUP_SEAM.to_owned())
}

/// The seam of [`open_every_key`]: no harness call reads the keystore
/// rows of a restored copy and tries them against every live custody
/// key. It needs the keystore schema (lane W2e) and the simulator's
/// unwrap (lane W1a, waiting for `fstp_crypto::aead`).
const OPEN_SEAM: &str = "no harness call tries every keystore row of a copy against every live custody key (lanes W2e and W1a)";

/// Tries every wrapped key in every copy against every live custody key,
/// and opens every text it reaches. It counts each erased and each live
/// text it tried, by copy.
fn open_every_key(world: &World, copies: &[StoreSet]) -> Result<OpenReport, String> {
    let _ = (world, copies);
    Err(OPEN_SEAM.to_owned())
}

/// Whose canaries a test asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subject {
    /// The subject the script erased: an account, an identity or a text.
    Erased,
    /// Subjects the script left alive.
    Live,
}

/// The seam of [`world_canaries`]: the world seeds canaries into its
/// cells but does not say which, nor whose subject each belongs to. Lane
/// W3b adds the accessor.
const CANARY_SEAM: &str = "fstp_celltest::world::World does not expose the canaries it seeded, by kind and by erased or live subject (lane W3b)";

/// The canaries of `kind` the world seeded for the erased subject, or for
/// the live subjects.
fn world_canaries(
    world: &World,
    kind: CanaryKind,
    subject: Subject,
) -> Result<Vec<Canary>, String> {
    let _ = (world, kind, subject);
    Err(CANARY_SEAM.to_owned())
}

/// The seam of [`recomputed_digests`]: no harness call recomputes a
/// keyed digest of a guessed value under every key a live root opens,
/// and matches it against the index rows of every copy.
const DIGEST_SEAM: &str = "no harness call recomputes keyed digests under every live-openable Lookup or Match key (lanes W2e and W1a)";

/// The index rows of every copy that a live key's digest of `guess`
/// matches.
fn recomputed_digests(
    world: &World,
    copies: &[StoreSet],
    chain: Chain,
    guess: &[u8],
) -> Result<Vec<String>, String> {
    let _ = (world, copies, chain, guess);
    Err(DIGEST_SEAM.to_owned())
}

/// The script of the text tests: backups before and between two text
/// erasures.
const TEXT_SCRIPT: [&str; 8] = [
    "call-cycle",
    "base-backup",
    "wal-archive",
    "erase-text",
    "base-backup",
    "wal-archive",
    "erase-text",
    "wal-archive",
];

/// I-81, design section 14.4: `pg_basebackup` copies and WAL archives are
/// taken through `fstp-backup` before and between two erasures, and each
/// is restored into a fresh server. Every wrapped key in every copy and
/// the live store is tried against every live custody key. The erased
/// texts never open, and every live text still does. The helper must
/// have tried at least one erased and one live text.
#[test]
fn i81_erased_text_unrecoverable_from_every_backup() {
    let world = world();
    run(&world, &TEXT_SCRIPT);
    let copies = backup_copies(&world).unwrap_or_else(|e| panic!("{e}"));
    let report = open_every_key(&world, &copies).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        report.erased_tried > 0 && report.live_tried > 0,
        "the helper tried nothing: {report:?}"
    );
    assert!(
        report.erased_opened.is_empty() && report.live_failed.is_empty(),
        "{report:?}"
    );
}

/// I-81, design section 14.1: no text salt canary is in any database,
/// dump, log, backup or egress capture, in any encoding.
#[test]
fn i81_text_salt_never_stored_in_clear() {
    let world = world();
    run(
        &world,
        &["call-cycle", "base-backup", "wal-archive", "erase-text"],
    );
    let mut canaries = world_canaries(&world, CanaryKind::TextSalt, Subject::Erased)
        .unwrap_or_else(|e| panic!("{e}"));
    canaries.extend(
        world_canaries(&world, CanaryKind::TextSalt, Subject::Live)
            .unwrap_or_else(|e| panic!("{e}")),
    );
    assert!(!canaries.is_empty(), "the world seeded no text salt");
    let stores = world.stores().unwrap_or_else(|e| panic!("{e}"));
    let report = scan(&stores, &canaries).unwrap();
    assert!(report.is_clean(), "{report:?}");
}

/// The script of the email digest tests.
const ACCOUNT_SCRIPT: [&str; 5] = [
    "call-cycle",
    "base-backup",
    "wal-archive",
    "erase-account",
    "wal-archive",
];

/// The script of the identity match key tests.
const IDENTITY_SCRIPT: [&str; 5] = [
    "call-cycle",
    "base-backup",
    "wal-archive",
    "erase-identity",
    "wal-archive",
];

/// The index rows a live key's digest of each guess matches, by guess.
fn digest_hits(world: &World, chain: Chain, guesses: &[Vec<u8>]) -> Vec<(String, Vec<String>)> {
    let copies = backup_copies(world).unwrap_or_else(|e| panic!("{e}"));
    guesses
        .iter()
        .map(|g| {
            let hits =
                recomputed_digests(world, &copies, chain, g).unwrap_or_else(|e| panic!("{e}"));
            (String::from_utf8_lossy(g).into_owned(), hits)
        })
        .collect()
}

fn emails(world: &World, subject: Subject) -> Vec<Vec<u8>> {
    let c = world_canaries(world, CanaryKind::Email, subject).unwrap_or_else(|e| panic!("{e}"));
    assert!(!c.is_empty(), "the world seeded no {subject:?} login email");
    c.iter().map(|e| e.email_address().into_bytes()).collect()
}

fn names(world: &World, subject: Subject) -> Vec<Vec<u8>> {
    let c = world_canaries(world, CanaryKind::Name, subject).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !c.is_empty(),
        "the world seeded no {subject:?} identity name"
    );
    c.iter().map(|n| n.text().into_bytes()).collect()
}

/// I-81, design section 3.5 (G24): after an account whose login email is
/// a canary is erased, no key a live root opens recomputes that email's
/// lookup digest to match an index row of any backup.
#[test]
fn i81_erased_email_digest_cannot_be_recomputed_from_backups() {
    let world = world();
    run(&world, &ACCOUNT_SCRIPT);
    let hits = digest_hits(&world, Chain::App, &emails(&world, Subject::Erased));
    assert!(hits.iter().all(|(_, h)| h.is_empty()), "{hits:?}");
}

/// I-81 teeth for the email digest test: the login email of a live
/// account still recomputes to its index row, so the helper finds
/// digests where they exist.
#[test]
fn i81_teeth_live_email_digest_is_recomputed() {
    let world = world();
    run(&world, &ACCOUNT_SCRIPT);
    let hits = digest_hits(&world, Chain::App, &emails(&world, Subject::Live));
    assert!(hits.iter().all(|(_, h)| !h.is_empty()), "{hits:?}");
}

/// I-81, design section 3.5 (G24): after an identity is erased, no key a
/// live root opens recomputes its match digest from its attribute tuple
/// to match an index row of any backup.
#[test]
fn i81_erased_identity_match_key_cannot_be_recomputed_from_backups() {
    let world = world();
    run(&world, &IDENTITY_SCRIPT);
    let hits = digest_hits(&world, Chain::Vault, &names(&world, Subject::Erased));
    assert!(hits.iter().all(|(_, h)| h.is_empty()), "{hits:?}");
}

/// I-81 teeth for the identity match test: a live identity's attribute
/// tuple still recomputes to its match row.
#[test]
fn i81_teeth_live_identity_match_digest_is_recomputed() {
    let world = world();
    run(&world, &IDENTITY_SCRIPT);
    let hits = digest_hits(&world, Chain::Vault, &names(&world, Subject::Live));
    assert!(hits.iter().all(|(_, h)| !h.is_empty()), "{hits:?}");
}

// ---------------------------------------------------------------------------
// File custody (design section 3.3, Q32 A).

/// The environment variable that names a directory on an ext4 or XFS
/// filesystem, for the key volumes of the file custody tests.
const KEY_VOLUME_ENV: &str = "FSTP_KEY_VOLUME_DIR";

/// The seam of [`key_volume_root`]: `fstp-keyd` accepts only an ext4 or
/// XFS key volume. `std::env::temp_dir()` is APFS on macOS and often
/// tmpfs on Linux, so a correct `fstp-keyd` refuses it. The CI isolation
/// job (lane W4) sets the variable to an ext4 or XFS mount.
const KEY_VOLUME_SEAM: &str = "FSTP_KEY_VOLUME_DIR is unset: the file custody tests need a directory on an ext4 or XFS mount, which the CI isolation job provides (design section 3.3, lane W4)";

/// The directory under which the file custody tests make key volumes.
fn key_volume_root() -> Result<PathBuf, String> {
    match std::env::var_os(KEY_VOLUME_ENV) {
        Some(dir) if !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => Err(KEY_VOLUME_SEAM.to_owned()),
    }
}

/// The socket and key volume of one test, both fresh and removed when
/// dropped. The socket lives in the temporary directory. The volume
/// lives under [`key_volume_root`].
struct Scratch {
    socket_dir: PathBuf,
    socket: PathBuf,
    volume: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let leaf = format!("fstp-w1d-{name}-{}", std::process::id());
        let root = key_volume_root().unwrap_or_else(|e| panic!("{e}"));
        let socket_dir = std::env::temp_dir().join(&leaf);
        let volume = root.join(&leaf);
        for dir in [&socket_dir, &volume] {
            let _ = fs::remove_dir_all(dir);
            fs::create_dir_all(dir).unwrap();
        }
        Scratch {
            socket: socket_dir.join("keyd.sock"),
            socket_dir,
            volume,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.socket_dir);
        let _ = fs::remove_dir_all(&self.volume);
    }
}

/// A running `fstp-keyd` that a test started with [`keyd_start`].
struct KeydRun {
    socket: PathBuf,
}

/// Starts `fstp-keyd` on `socket` and `volume` and returns its client
/// once the socket is bound. It reports a server that exits first.
fn keyd_start(socket: &Path, volume: &Path) -> Result<(KeydCustody, KeydRun), String> {
    let (done, exited) = std::sync::mpsc::channel();
    {
        let (socket, volume) = (socket.to_path_buf(), volume.to_path_buf());
        std::thread::spawn(move || {
            let _ = done.send(fstp_keyd::serve(&socket, &volume));
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !socket.exists() {
        match exited.try_recv() {
            Ok(Err(e)) => return Err(format!("fstp_keyd::serve: {e}")),
            Ok(Ok(())) => return Err("fstp_keyd::serve returned before binding".to_owned()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("fstp_keyd::serve panicked".to_owned());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("fstp-keyd bound no socket at {}", socket.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let client = KeydCustody::new(socket).map_err(|e| format!("KeydCustody::new: {e}"))?;
    Ok((
        client,
        KeydRun {
            socket: socket.to_path_buf(),
        },
    ))
}

/// The seam of [`keyd_stop`]: `fstp_keyd::serve` runs until shutdown and
/// takes no stop handle. `fstp-celltest` cannot spawn the `fstp-keyd`
/// binary to kill it, since the binary is in another package. Joining the
/// server thread would block forever. Lane W2f adds a serve with a stop
/// handle, or a way to run the binary as a child, and this helper then
/// stops through it.
const KEYD_STOP_SEAM: &str = "fstp-keyd has no serve with a stop handle, and fstp-celltest cannot run the fstp-keyd binary as a child to kill it, so no test can restart it (lane W2f)";

/// Stops the server of `run`.
fn keyd_stop_server(run: &KeydRun) -> Result<(), String> {
    let _ = run;
    Err(KEYD_STOP_SEAM.to_owned())
}

/// Stops `fstp-keyd`, waits until it has stopped, and removes its socket
/// file, so the next [`keyd_start`] binds afresh and reloads the volume
/// from disk.
fn keyd_stop(run: KeydRun) -> Result<(), String> {
    keyd_stop_server(&run)?;
    match fs::remove_file(&run.socket) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("removing {}: {e}", run.socket.display())),
    }
}

fn label(epoch: u64) -> RootLabel {
    RootLabel {
        cell: Some(CellId([9; 16])),
        chain: Chain::App,
        epoch: Epoch(epoch),
    }
}

/// The epoch files of epoch `e` on `volume`, with their bytes.
fn epoch_files(volume: &Path, e: u64) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(volume).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("epoch-") && name.ends_with(&format!("-{e}.key")) {
            out.push((name, fs::read(entry.path()).unwrap()));
        }
    }
    out
}

/// Writes saved epoch files back onto `volume`: a remnant of each, such
/// as its freed blocks or a copy the install does not know about.
fn restore_files(volume: &Path, files: &[(String, Vec<u8>)]) {
    for (name, bytes) in files {
        fs::write(volume.join(name), bytes).unwrap();
    }
}

/// The inode of every regular file on `volume` that is not an epoch file:
/// the key table, and anything else `fstp-keyd` keeps beside it.
fn table_inodes(volume: &Path) -> BTreeMap<String, u64> {
    use std::os::unix::fs::MetadataExt as _;
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(volume).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = entry.metadata().unwrap();
        if meta.is_file() && !name.starts_with("epoch-") {
            out.insert(name, meta.ino());
        }
    }
    out
}

/// One entry of the `fstp-keyd` key table, as an offline decoder reads
/// it from the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyTableEntry {
    /// The chain of the epoch.
    chain: Chain,
    /// The epoch.
    epoch: u64,
    /// Whether the entry still holds the bytes of `K(e)`.
    holds_key: bool,
}

/// The seam of [`key_table_entries`]: the key table is sealed under a
/// passphrase-derived key (ADR-004 part 2). `fstp-keyd` exposes no
/// offline decoder of it under that passphrase, and `serve` takes no
/// passphrase a test can give it. Lane W2f adds both, and this helper
/// then calls the decoder. A keyd that only marks an epoch destroyed but
/// keeps `K(e)` passes every other check here, so this one is needed.
const KEY_TABLE_SEAM: &str = "fstp-keyd exposes no offline decoder of its key table under the passphrase, and serve takes no test passphrase (ADR-004 part 2, lane W2f)";

/// Every entry of the key table on `volume`, decoded offline.
fn key_table_entries(volume: &Path) -> Result<Vec<KeyTableEntry>, String> {
    let _ = volume;
    Err(KEY_TABLE_SEAM.to_owned())
}

/// Whether the key table entries hold `K(epoch)` of the App chain.
fn holds_app_key(entries: &[KeyTableEntry], epoch: u64) -> bool {
    entries
        .iter()
        .any(|e| e.chain == Chain::App && e.epoch == epoch && e.holds_key)
}

/// One step of an `fstp-keyd` destroy, as ADR-004 part 2 lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeydDestroyStep {
    /// `K(e)` overwritten in the key table in place.
    OverwriteKey,
    /// The key table fsynced.
    FsyncTable,
    /// The epoch file unlinked.
    UnlinkEpochFile,
    /// The key directory fsynced.
    FsyncDirectory,
    /// The key table and the directory read back.
    ReadBack,
}

/// The seam of [`keyd_receipt_steps`]: no ADR fixes the bytes of an
/// `fstp-keyd` `DestroyReceipt`, and `fstp-keyd` exposes no decoder of
/// them. Lane W2f records the receipt in ADR-004 and exposes the decoder,
/// and this helper then calls it.
const RECEIPT_SEAM: &str = "fstp-keyd exposes no decoder of its DestroyReceipt steps, and no ADR fixes its bytes (ADR-004 part 2, lane W2f)";

/// The destroy steps an `fstp-keyd` receipt records, in order.
fn keyd_receipt_steps(receipt: &DestroyReceipt) -> Result<Vec<KeydDestroyStep>, String> {
    let _ = receipt;
    Err(RECEIPT_SEAM.to_owned())
}

/// I-81, design section 3.3 and ADR-004 part 2 (G23, Q32 A): `fstp-keyd`
/// destroys epoch 1 by overwriting `K(1)` in the key table in place.
/// Every key table file keeps its inode, so no old table is left in freed
/// blocks. The table decoded offline holds `K(1)` before and not after,
/// so a tombstone that keeps `K(1)` fails. No epoch 1 file is left. The
/// pre-destroy epoch 1 files are then written back, as a remnant would
/// be, and a restarted `fstp-keyd` still cannot unwrap the seal key. The
/// receipt records each step, and epoch 2 still unwraps. The claim is
/// scoped to a key volume excluded from host backups and snapshots.
#[test]
fn i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume() {
    let scratch = Scratch::new("i81-keyd");
    let (socket, volume) = (&scratch.socket, &scratch.volume);
    let aad = Aad(b"i81 file custody".to_vec());
    let (client, run) = keyd_start(socket, volume).unwrap_or_else(|e| panic!("{e}"));
    let r1 = block_on(client.create_root(label(1))).unwrap();
    let r2 = block_on(client.create_root(label(2))).unwrap();
    let w1 = block_on(client.wrap(&r1, &SealKey::from_bytes([1; 32]), &aad)).unwrap();
    let w2 = block_on(client.wrap(&r2, &SealKey::from_bytes([2; 32]), &aad)).unwrap();
    let remnant = epoch_files(volume, 1);
    assert!(!remnant.is_empty(), "no epoch-*-1.key file on the volume");
    let tables = table_inodes(volume);
    assert!(
        !tables.is_empty(),
        "no key table file beside the epoch files on the key volume"
    );
    let before = key_table_entries(volume).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        holds_app_key(&before, 1) && holds_app_key(&before, 2),
        "the decoder found no K(1) or K(2) before the destroy: {before:?}"
    );
    let receipt = block_on(client.destroy(&r1)).unwrap();
    let after = table_inodes(volume);
    let moved: Vec<&String> = tables
        .iter()
        .filter(|(name, ino)| after.get(*name) != Some(*ino))
        .map(|(name, _)| name)
        .collect();
    assert!(
        moved.is_empty(),
        "destroy replaced or removed key table files {moved:?} instead of overwriting K(1) in place"
    );
    let entries = key_table_entries(volume).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !holds_app_key(&entries, 1),
        "the key table still holds K(1) after destroy: {entries:?}"
    );
    assert!(holds_app_key(&entries, 2), "destroy lost K(2): {entries:?}");
    drop(client);
    keyd_stop(run).unwrap_or_else(|e| panic!("{e}"));
    let left: Vec<String> = epoch_files(volume, 1).into_iter().map(|(n, _)| n).collect();
    assert!(left.is_empty(), "epoch 1 files left: {left:?}");
    assert_eq!(
        keyd_receipt_steps(&receipt).unwrap_or_else(|e| panic!("{e}")),
        vec![
            KeydDestroyStep::OverwriteKey,
            KeydDestroyStep::FsyncTable,
            KeydDestroyStep::UnlinkEpochFile,
            KeydDestroyStep::FsyncDirectory,
            KeydDestroyStep::ReadBack,
        ],
        "the receipt does not record the destroy steps of ADR-004"
    );
    restore_files(volume, &remnant);
    let (client, run) = keyd_start(socket, volume).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        block_on(client.unwrap(&r1, &w1, &aad)).is_err(),
        "a remnant of the destroyed epoch file opened: K(1) was not overwritten"
    );
    let s2 = block_on(client.unwrap(&r2, &w2, &aad)).unwrap();
    assert_eq!(s2.expose(), &[2; 32], "the live epoch lost its seal key");
    drop(client);
    keyd_stop(run).unwrap_or_else(|e| panic!("{e}"));
}

/// I-81 teeth for the file custody test: with no destroy, an epoch file
/// that is unlinked and then written back from its saved bytes opens
/// again after a restart. So the remnant check above tests the `K(e)`
/// overwrite, not the restore.
#[test]
fn i81_teeth_restored_epoch_file_opens_without_destroy() {
    let scratch = Scratch::new("i81-keyd-teeth");
    let (socket, volume) = (&scratch.socket, &scratch.volume);
    let aad = Aad(b"i81 file custody teeth".to_vec());
    let (client, run) = keyd_start(socket, volume).unwrap_or_else(|e| panic!("{e}"));
    let r1 = block_on(client.create_root(label(1))).unwrap();
    let w1 = block_on(client.wrap(&r1, &SealKey::from_bytes([1; 32]), &aad)).unwrap();
    let saved = epoch_files(volume, 1);
    assert!(!saved.is_empty(), "no epoch-*-1.key file on the volume");
    drop(client);
    keyd_stop(run).unwrap_or_else(|e| panic!("{e}"));
    for (name, _) in &saved {
        fs::remove_file(volume.join(name)).unwrap();
    }
    restore_files(volume, &saved);
    let (client, run) = keyd_start(socket, volume).unwrap_or_else(|e| panic!("{e}"));
    let s1 = block_on(client.unwrap(&r1, &w1, &aad)).unwrap();
    assert_eq!(
        s1.expose(),
        &[1; 32],
        "the restored epoch file did not open"
    );
    drop(client);
    keyd_stop(run).unwrap_or_else(|e| panic!("{e}"));
}

/// The seam of [`keyd_volume_check`]: `fstp-keyd` checks the key volume
/// only inside `serve`, through `statfs`. No test can mount btrfs, ZFS,
/// overlayfs or NFS. Lane W2f exposes the pure decision over the
/// filesystem type, and this helper then calls it.
const VOLUME_SEAM: &str =
    "fstp-keyd exposes no pure key volume check over the statfs filesystem type (lane W2f)";

/// Whether `fstp-keyd` accepts a key volume of filesystem type `magic`.
fn keyd_volume_check(magic: u64) -> Result<bool, String> {
    let _ = magic;
    Err(VOLUME_SEAM.to_owned())
}

/// Magic numbers that name no filesystem `fstp-keyd` knows, for the
/// allowlist checks.
const UNKNOWN_VOLUMES: [u64; 3] = [0, 0x1234_5678, u64::MAX];

/// I-81, design section 3.3 (Q32 A): `fstp-keyd` refuses a key volume on
/// btrfs, ZFS, overlayfs or a network filesystem, and accepts ext4 and
/// XFS. It decides by allowlist, so a FUSE, bcachefs or unknown
/// filesystem is refused too.
#[test]
fn i81_keyd_refuses_copy_on_write_key_volume() {
    let mut wrong = Vec::new();
    for (name, magic) in REFUSED_VOLUMES {
        if keyd_volume_check(magic).unwrap_or_else(|e| panic!("{e}")) {
            wrong.push(format!("{name} accepted"));
        }
    }
    for magic in UNKNOWN_VOLUMES {
        if keyd_volume_check(magic).unwrap_or_else(|e| panic!("{e}")) {
            wrong.push(format!("unknown filesystem {magic:#x} accepted"));
        }
    }
    for (name, magic) in ACCEPTED_VOLUMES {
        if !keyd_volume_check(magic).unwrap_or_else(|e| panic!("{e}")) {
            wrong.push(format!("{name} refused"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

/// I-81, design section 3.3: the reference key volume rule is an
/// allowlist. It accepts ext4 and XFS only, and refuses every listed
/// filesystem, FUSE and bcachefs among them, and every unknown value. A
/// self-check of the reference.
#[test]
fn i81_reference_key_volume_rule_is_an_allowlist() {
    let mut wrong = Vec::new();
    for (name, magic) in REFUSED_VOLUMES {
        if key_volume_accepted(magic) {
            wrong.push(format!("{name} accepted"));
        }
        if ACCEPTED_VOLUMES.iter().any(|(_, m)| *m == magic) {
            wrong.push(format!("{name} is on both lists"));
        }
    }
    for magic in UNKNOWN_VOLUMES {
        if key_volume_accepted(magic) {
            wrong.push(format!("unknown filesystem {magic:#x} accepted"));
        }
    }
    for (name, magic) in ACCEPTED_VOLUMES {
        if !key_volume_accepted(magic) {
            wrong.push(format!("{name} refused"));
        }
    }
    for name in ["fuse", "bcachefs", "smb", "afs"] {
        if !REFUSED_VOLUMES.iter().any(|(n, _)| *n == name) {
            wrong.push(format!("{name} is not among the refused examples"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}
