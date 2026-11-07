//! Independent adversarial review of lane W1d, round 2. I-81, file
//! custody (design section 3.3, ADR-004 part 2, G23, Q32 A).
//!
//! ADR-004 part 2: "Destroy overwrites `K(e)` in the key table in place,
//! fsyncs, unlinks the epoch file, fsyncs the directory and reads back."
//! The lane's remnant check writes the old epoch file back and restarts
//! `fstp-keyd`. A keyd that writes a fresh key table and renames it over
//! the old one passes that check, yet the old table's freed blocks on the
//! key volume still hold `K(1)`. Those blocks plus a remnant of the epoch
//! file reopen the destroyed root. An in-place overwrite keeps the key
//! table's inode, and a rewrite by rename does not. This check is red on
//! `NotImplemented` now, and it is the check the lane test lacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fstp_custody::{Aad, Custody, KeydCustody, RootLabel, SealKey};
use fstp_keys::{CellId, Chain, Epoch};
use fstp_rt::future::block_on;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("fstp-review-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Waits until `fstp-keyd` has bound `socket`: it opens the key table
/// before it binds, so a client that connects earlier is refused.
fn wait_for_socket(socket: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fstp-keyd bound no socket at {}",
            socket.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn label(epoch: u64) -> RootLabel {
    RootLabel {
        cell: Some(CellId([9; 16])),
        chain: Chain::App,
        epoch: Epoch(epoch),
    }
}

/// The inode of every regular file on `volume` that is not an epoch file:
/// the key table, and anything else `fstp-keyd` keeps beside it.
#[cfg(unix)]
fn table_inodes(volume: &Path) -> BTreeMap<String, u64> {
    use std::os::unix::fs::MetadataExt;
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

/// I-81 review (G23, Q32 A): `fstp-keyd` destroys epoch 1 by overwriting
/// `K(1)` in the key table in place. Every key table file on the volume
/// before the destroy is still there afterwards, with the same inode, so
/// no old copy of the table is left in freed blocks of the volume.
#[cfg(unix)]
#[test]
fn review_keyd_destroy_overwrites_the_key_table_in_place() {
    let scratch = Scratch::new("keyd-inplace");
    let socket = scratch.0.join("keyd.sock");
    let volume = scratch.0.join("keys");
    fs::create_dir_all(&volume).unwrap();
    let _server = {
        let (socket, volume) = (socket.clone(), volume.clone());
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve(&socket, &volume);
        })
    };
    wait_for_socket(&socket);
    let client = KeydCustody::new(&socket)
        .unwrap_or_else(|e| panic!("KeydCustody::new: {e} (NotImplemented)"));
    let aad = Aad(b"review in place".to_vec());
    let r1 = block_on(client.create_root(label(1))).unwrap();
    let r2 = block_on(client.create_root(label(2))).unwrap();
    let _w1 = block_on(client.wrap(&r1, &SealKey::from_bytes([1; 32]), &aad)).unwrap();
    let _w2 = block_on(client.wrap(&r2, &SealKey::from_bytes([2; 32]), &aad)).unwrap();
    let before = table_inodes(&volume);
    assert!(
        !before.is_empty(),
        "no key table file beside the epoch files on the key volume"
    );
    block_on(client.destroy(&r1)).unwrap();
    let after = table_inodes(&volume);
    let moved: Vec<String> = before
        .iter()
        .filter(|(name, ino)| after.get(*name) != Some(*ino))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(
        moved.is_empty(),
        "destroy replaced or removed key table files {moved:?} instead of overwriting K(1) in place"
    );
}
