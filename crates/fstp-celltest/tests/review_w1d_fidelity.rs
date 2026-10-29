//! Independent review of lane W1d (reference fidelity). I-81, file
//! custody (design section 3.3, ADR-004 part 2, Q32 A).
//!
//! Each `review_` test states a rule of the design that the lane's tests
//! do not check. It fails against the current tree and passes once file
//! custody meets the rule and the lane's test checks it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::path::{Path, PathBuf};

use fstp_custody::{Aad, Custody, KeydCustody, RootLabel, SealKey};
use fstp_keys::{CellId, Chain, Epoch};
use fstp_rt::future::block_on;

/// A fresh scratch directory for one test, removed when dropped.
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

fn keyd(socket: &Path, volume: &Path) -> (KeydCustody, std::thread::JoinHandle<()>) {
    let server = {
        let (socket, volume) = (socket.to_path_buf(), volume.to_path_buf());
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve(&socket, &volume);
        })
    };
    let client = KeydCustody::new(socket)
        .unwrap_or_else(|e| panic!("KeydCustody::new: {e} (NotImplemented)"));
    (client, server)
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

/// I-81 review, design section 3.3: "Destroy overwrites `K(e)` in the key
/// table in place, fsyncs, unlinks the epoch file". The per-epoch key
/// exists so that a remnant of the epoch file, such as its freed blocks
/// on the key volume, no longer opens. The lane's
/// `i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume`
/// only checks that the file is gone, so an `fstp-keyd` that unlinks the
/// file and keeps `K(e)` passes it. This test puts the pre-destroy bytes
/// of the epoch file back and expects the restarted `fstp-keyd` to refuse.
#[test]
fn review_file_custody_remnant_epoch_file_does_not_open_after_destroy() {
    let scratch = Scratch::new("keyd-remnant");
    let socket = scratch.0.join("keyd.sock");
    let volume = scratch.0.join("keys");
    fs::create_dir_all(&volume).unwrap();
    let aad = Aad(b"review file custody".to_vec());
    let (r1, w1, remnant) = {
        let (client, server) = keyd(&socket, &volume);
        let r1 = block_on(client.create_root(label(1))).unwrap();
        let _r2 = block_on(client.create_root(label(2))).unwrap();
        let w1 = block_on(client.wrap(&r1, &SealKey::from_bytes([1; 32]), &aad)).unwrap();
        let remnant = epoch_files(&volume, 1);
        assert!(!remnant.is_empty(), "no epoch-*-1.key file on the volume");
        block_on(client.destroy(&r1)).unwrap();
        drop(client);
        let _ = server.join();
        (r1, w1, remnant)
    };
    for (name, bytes) in &remnant {
        fs::write(volume.join(name), bytes).unwrap();
    }
    let (client, _server) = keyd(&socket, &volume);
    assert!(
        block_on(client.unwrap(&r1, &w1, &aad)).is_err(),
        "a remnant of the destroyed epoch file still opens: K(1) was not overwritten"
    );
}
