//! The off-host sealed copy of a `fstp-keyd` volume (ADR-004 record of
//! lane L16, ADR-012 record of lane L16, I-80, I-81).
//!
//! Decided by Daniel on 2026-11-21: the key that opens every backup must
//! survive the loss of the host, and a destroyed root epoch must never
//! come back from an old copy. Each test runs `fstp-keyd` on a scratch
//! volume, makes a copy, loses the volume, and imports the copy onto a
//! fresh one. The passphrase is the ephemeral one of development mode,
//! which the server also uses when no credential is set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Scratch, classify};
use fstp_custody::{
    Aad, Chain, Custody, CustodyError, Epoch, KeydCustody, Refusal, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_keyd::export::{
    self, ExportId, HOLD_FILE, export_volume, import_volume, release_import, retire_export,
};
use fstp_keyd::{ClientRole, ClientSocket, KeydError, Passphrase, PassphraseSource};
use fstp_obs::assurance::ReducedReason;
use fstp_rt::future::block_on;

fn pass() -> Passphrase {
    Passphrase::development().expect("development mode in a debug test build")
}

fn label(chain: Chain, epoch: u64) -> RootLabel {
    RootLabel {
        cell: None,
        chain,
        epoch: Epoch(epoch),
    }
}

fn seal(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A key volume with a console socket and a cell socket.
struct Host {
    scratch: Scratch,
    console: PathBuf,
    cell: PathBuf,
}

impl Host {
    fn new(name: &str) -> Host {
        let scratch = Scratch::new(name).unwrap_or_else(|e| panic!("{e}"));
        let console = scratch.socket_dir.join("console.sock");
        let cell = scratch.socket_dir.join("cell.sock");
        Host {
            scratch,
            console,
            cell,
        }
    }

    fn volume(&self) -> &Path {
        &self.scratch.volume
    }

    /// Starts the server and returns a console and a cell client.
    fn start(&self) -> (KeydCustody, KeydCustody) {
        let (done, exited) = std::sync::mpsc::channel();
        {
            let sockets = vec![
                ClientSocket::owner_only(&self.console, ClientRole::Console),
                ClientSocket::owner_only(&self.cell, ClientRole::Cell),
            ];
            let volume = self.volume().to_path_buf();
            std::thread::spawn(move || {
                let r = fstp_keyd::serve_sockets(&sockets, &volume, PassphraseSource::Credential);
                let _ = done.send(r.map_err(classify));
            });
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while !(self.console.exists() && self.cell.exists()) {
            if let Ok(r) = exited.try_recv() {
                panic!("fstp-keyd stopped before binding: {r:?}");
            }
            assert!(Instant::now() < deadline, "fstp-keyd bound no socket");
            std::thread::sleep(Duration::from_millis(10));
        }
        (
            KeydCustody::new(&self.console).unwrap(),
            KeydCustody::new(&self.cell).unwrap(),
        )
    }

    fn stop(&self) {
        fstp_keyd::stop(&self.console).unwrap();
    }

    /// The loss of the host: the key volume is gone.
    fn lose_volume(&self) {
        std::fs::remove_dir_all(self.volume()).unwrap();
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = fstp_keyd::stop(&self.console);
    }
}

fn create(c: &KeydCustody, chain: Chain, epoch: u64) -> RootRef {
    block_on(c.create_root(label(chain, epoch))).unwrap()
}

fn wrap(c: &KeydCustody, root: &RootRef, n: u8) -> WrappedSealKey {
    block_on(c.wrap(root, &SealKey::from_bytes(seal(n)), &Aad(vec![n]))).unwrap()
}

fn unwrap(c: &KeydCustody, root: &RootRef, w: &WrappedSealKey, n: u8) -> Result<[u8; 32], Refusal> {
    match block_on(c.unwrap(root, w, &Aad(vec![n]))) {
        Ok(k) => Ok(*k.expose()),
        Err(CustodyError::Refused(r)) => Err(r),
        Err(e) => panic!("unexpected custody error: {e:?}"),
    }
}

fn live(volume: &Path, chain: Chain, epoch: u64) -> bool {
    fstp_keyd::open_key_table(volume, &pass())
        .unwrap()
        .get(chain, Epoch(epoch))
        .is_some_and(fstp_keyd::KeyTableEntry::is_live)
}

/// I-80, I-81, ADR-004 and ADR-012 records of lane L16: after the loss of
/// the host, a copy imported onto a fresh volume opens the ClusterBackup
/// root that seals every backup, at once and while held. The App root
/// opens once release names its current epoch.
#[test]
fn i80_i81_host_loss_restore_from_offhost_copy() {
    let a = Host::new("l16-loss-a");
    let (console, cell) = a.start();
    let cb = create(&console, Chain::ClusterBackup, 1);
    let w_cb = wrap(&console, &cb, 0x41);
    let app = create(&cell, Chain::App, 1);
    let w_app = wrap(&cell, &app, 0x42);
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();
    a.lose_volume();

    let b = Host::new("l16-loss-b");
    import_volume(&copy, b.volume(), &pass()).unwrap();
    assert!(b.volume().join(HOLD_FILE).exists());
    let (console, cell) = b.start();
    assert_eq!(unwrap(&console, &cb, &w_cb, 0x41), Ok(seal(0x41)));
    assert_eq!(
        unwrap(&cell, &app, &w_app, 0x42),
        Err(Refusal::NotPermitted),
        "a held volume serves the App chain"
    );
    b.stop();
    release_import(b.volume(), &pass(), &[(Chain::App, Epoch(1))]).unwrap();
    assert!(!b.volume().join(HOLD_FILE).exists());
    let (_console, cell) = b.start();
    assert_eq!(unwrap(&cell, &app, &w_app, 0x42), Ok(seal(0x42)));
}

/// I-81, ADR-004 record of lane L16 rule 2: a held volume answers only
/// unwrap and usage reads on the backup chains. Create, wrap and destroy
/// are refused on every chain, and the App chain is refused on the cell
/// socket.
#[test]
fn i81_held_import_serves_backup_chains_only() {
    let a = Host::new("l16-held-a");
    let (console, cell) = a.start();
    let cb = create(&console, Chain::ClusterBackup, 1);
    let w_cb = wrap(&console, &cb, 0x51);
    let app = create(&cell, Chain::App, 1);
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();

    let b = Host::new("l16-held-b");
    import_volume(&copy, b.volume(), &pass()).unwrap();
    let (console, cell) = b.start();
    assert_eq!(unwrap(&console, &cb, &w_cb, 0x51), Ok(seal(0x51)));
    let refused = |r: Result<(), CustodyError>| {
        assert_eq!(r, Err(CustodyError::Refused(Refusal::NotPermitted)));
    };
    refused(block_on(console.wrap(&cb, &SealKey::from_bytes(seal(1)), &Aad(vec![1]))).map(|_| ()));
    refused(block_on(console.create_root(label(Chain::ClusterBackup, 2))).map(|_| ()));
    refused(block_on(console.destroy(&cb)).map(|_| ()));
    refused(block_on(cell.create_root(label(Chain::App, 2))).map(|_| ()));
    refused(block_on(cell.destroy(&app)).map(|_| ()));
    assert!(live(b.volume(), Chain::App, 1));
}

/// I-81, ADR-004 record of lane L16 rule 1: an epoch destroyed by erasure
/// is never in a later copy. The imported table holds it as destroyed,
/// and it never opens again.
#[test]
fn i81_destroyed_epoch_never_in_a_later_copy() {
    let a = Host::new("l16-later-a");
    let (_console, cell) = a.start();
    let r1 = create(&cell, Chain::App, 1);
    let w1 = wrap(&cell, &r1, 0x61);
    let r2 = create(&cell, Chain::App, 2);
    let w2 = wrap(&cell, &r2, 0x62);
    block_on(cell.destroy(&r1)).unwrap();
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();
    a.lose_volume();

    let b = Host::new("l16-later-b");
    import_volume(&copy, b.volume(), &pass()).unwrap();
    assert!(!live(b.volume(), Chain::App, 1));
    assert!(
        !b.volume()
            .join(fstp_keyd::epoch::file_name(Chain::App, Epoch(1)))
            .exists()
    );
    release_import(b.volume(), &pass(), &[(Chain::App, Epoch(2))]).unwrap();
    let (_console, cell) = b.start();
    assert_eq!(unwrap(&cell, &r1, &w1, 0x61), Err(Refusal::Destroyed));
    assert_eq!(unwrap(&cell, &r2, &w2, 0x62), Ok(seal(0x62)));
    // The chain keeps its numbering: epoch 1 is never created again.
    assert!(block_on(cell.create_root(label(Chain::App, 1))).is_err());
}

/// I-81, ADR-004 record of lane L16 rule 3: a copy made before an
/// erasure and imported after it is re-erased before anything serves.
/// Release with the restored keystore's current epoch destroys the older
/// epoch, refuses because the current one is missing, and keeps the
/// hold. The erased epoch never opens on the new host.
#[test]
fn i81_older_copy_restored_after_erasure_is_re_erased_before_serving() {
    let a = Host::new("l16-older-a");
    let (_console, cell) = a.start();
    let r1 = create(&cell, Chain::App, 1);
    let w1 = wrap(&cell, &r1, 0x71);
    a.stop();
    let (old_id, old) = export_volume(a.volume(), &pass()).unwrap();
    // The erasure: a rotation to epoch 2 destroys epoch 1.
    let (_console, cell) = a.start();
    create(&cell, Chain::App, 2);
    block_on(cell.destroy(&r1)).unwrap();
    a.stop();
    a.lose_volume();

    let c = Host::new("l16-older-c");
    import_volume(&old, c.volume(), &pass()).unwrap();
    {
        let (_console, cell) = c.start();
        assert_eq!(unwrap(&cell, &r1, &w1, 0x71), Err(Refusal::NotPermitted));
        c.stop();
    }
    let r = release_import(c.volume(), &pass(), &[(Chain::App, Epoch(2))]);
    assert_eq!(r.unwrap_err(), KeydError::StaleCopy);
    assert!(c.volume().join(HOLD_FILE).exists(), "the hold was lifted");
    assert!(
        !live(c.volume(), Chain::App, 1),
        "the erased epoch survived"
    );
    let (_console, cell) = c.start();
    assert_ne!(unwrap(&cell, &r1, &w1, 0x71), Ok(seal(0x71)));
    let _ = old_id;
}

/// I-81, ADR-004 record of lane L16 rule 3: a copy made while a rotation
/// ran holds the old and the new epoch. Release keeps the current one
/// and every epoch above it, and destroys the older one.
#[test]
fn i81_release_destroys_only_epochs_below_the_current_one() {
    let a = Host::new("l16-mid-a");
    let (_console, cell) = a.start();
    let r1 = create(&cell, Chain::App, 1);
    let w1 = wrap(&cell, &r1, 0x81);
    let r2 = create(&cell, Chain::App, 2);
    let w2 = wrap(&cell, &r2, 0x82);
    create(&cell, Chain::App, 3);
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();

    let b = Host::new("l16-mid-b");
    import_volume(&copy, b.volume(), &pass()).unwrap();
    // Every erasable chain the volume holds must be named.
    assert!(release_import(b.volume(), &pass(), &[]).is_err());
    release_import(b.volume(), &pass(), &[(Chain::App, Epoch(2))]).unwrap();
    assert!(!live(b.volume(), Chain::App, 1));
    assert!(live(b.volume(), Chain::App, 2));
    assert!(live(b.volume(), Chain::App, 3));
    let (_console, cell) = b.start();
    assert_eq!(unwrap(&cell, &r1, &w1, 0x81), Err(Refusal::Destroyed));
    assert_eq!(unwrap(&cell, &r2, &w2, 0x82), Ok(seal(0x82)));
}

/// I-81, ADR-004 record of lane L16 rule 4: the source volume records
/// each copy. Once an epoch a copy holds is destroyed, the volume
/// reports reduced assurance until the operator retires that copy.
#[test]
fn i81_copy_register_reports_reduced_assurance_after_erasure() {
    let a = Host::new("l16-register");
    let (_console, cell) = a.start();
    let r1 = create(&cell, Chain::App, 1);
    a.stop();
    let (id, _copy) = export_volume(a.volume(), &pass()).unwrap();
    assert_eq!(export::export_reason(a.volume(), &pass()).unwrap(), None);
    let (_console, cell) = a.start();
    create(&cell, Chain::App, 2);
    block_on(cell.destroy(&r1)).unwrap();
    a.stop();
    assert_eq!(
        export::export_reason(a.volume(), &pass()).unwrap(),
        Some(ReducedReason::ExportHoldsErasedEpoch)
    );
    // A copy made after the erasure holds no destroyed epoch.
    let (later, _) = export_volume(a.volume(), &pass()).unwrap();
    assert_ne!(later, id);
    retire_export(a.volume(), id).unwrap();
    assert_eq!(export::export_reason(a.volume(), &pass()).unwrap(), None);
    // Retiring an id the register does not hold is refused.
    assert!(retire_export(a.volume(), ExportId([0xee; 16])).is_err());
}

/// I-80, ADR-004 record of lane L16: a copy does not open under another
/// passphrase, and a refused import writes nothing to the volume.
#[test]
fn i80_import_refuses_a_wrong_passphrase() {
    let a = Host::new("l16-pass-a");
    let (console, _cell) = a.start();
    create(&console, Chain::ClusterBackup, 1);
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();
    let b = Host::new("l16-pass-b");
    let wrong = Passphrase::from_bytes(b"not the passphrase of the volume").unwrap();
    assert_eq!(
        import_volume(&copy, b.volume(), &wrong).unwrap_err(),
        KeydError::WrongPassphrase
    );
    assert_eq!(std::fs::read_dir(b.volume()).unwrap().count(), 0);
}

/// I-80, ADR-004 record of lane L16: a copy with any changed byte is
/// refused, and an import never writes over a volume that holds a key
/// table.
#[test]
fn i80_import_refuses_a_tampered_copy_or_a_used_volume() {
    let a = Host::new("l16-tamper-a");
    let (console, _cell) = a.start();
    create(&console, Chain::ClusterBackup, 1);
    a.stop();
    let (_, copy) = export_volume(a.volume(), &pass()).unwrap();
    for at in [5usize, 30, 50, copy.len() / 2, copy.len() - 1] {
        let mut bad = copy.clone();
        bad[at] ^= 0x01;
        let b = Host::new(&format!("l16-tamper-{at}"));
        assert!(import_volume(&bad, b.volume(), &pass()).is_err(), "{at}");
        assert_eq!(std::fs::read_dir(b.volume()).unwrap().count(), 0, "{at}");
    }
    assert!(matches!(
        import_volume(&copy, a.volume(), &pass()),
        Err(KeydError::Volume(_))
    ));
}

/// ADR-004 record of lane L16 "Lock": a copy is never made while the
/// entry serves, so no destroy can run part way through it.
#[test]
fn adr004_keyd_volume_lock_excludes_a_second_holder() {
    let a = Host::new("l16-lock");
    let (console, _cell) = a.start();
    create(&console, Chain::ClusterBackup, 1);
    assert_eq!(
        export_volume(a.volume(), &pass()).unwrap_err(),
        KeydError::AlreadyRunning
    );
    a.stop();
    assert!(export_volume(a.volume(), &pass()).is_ok());
}
