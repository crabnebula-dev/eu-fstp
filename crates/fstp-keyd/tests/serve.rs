//! `fstp-keyd` and its `KeydCustody` client end to end (ADR-004 part 2
//! "File custody" and "Custody interface", design section 3.3, Q32 A,
//! I-80, I-81).
//!
//! Each test starts `fstp_keyd::serve` on a fresh socket and a key volume
//! under `FSTP_KEY_VOLUME_DIR`, which the Linux CI test job mounts as ext4. The
//! cross-crate file custody tests (`i81_file_custody_*`, the restart and
//! remnant checks) live in `fstp-celltest`. These are the crate's own
//! tests of each custody operation over the socket.
//!
//! Without `FSTP_KEY_VOLUME_DIR`, as on macOS, the key volume is a
//! temporary directory. `fstp-keyd` serves it at reduced assurance (I-81
//! NOTE of 2026-11-01), so every test still runs (Q-F, interim pending
//! Daniel).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use common::{Scratch, contains, files_under, running, start_cell_and_vault};
use fstp_custody::{Aad, CellId, Chain, Custody, Epoch, RootLabel, SealKey, UsageCursor};
use fstp_rt::future::block_on;

fn label(chain: Chain, epoch: u64) -> RootLabel {
    RootLabel {
        cell: Some(CellId([0x3c; 16])),
        chain,
        epoch: Epoch(epoch),
    }
}

/// A seal key canary for test `n`: 32 bytes no other test uses.
fn canary(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = n ^ (0x5a_u8.wrapping_add((i as u8).wrapping_mul(37)));
    }
    out
}

/// I-80, ADR-004 part 2: a seal key wrapped under a root unwraps under the
/// same root and AAD to the same 32 bytes. The root itself never crosses
/// the socket: the client holds a reference and a wrapped key only.
#[test]
fn i80_keyd_wraps_and_unwraps_a_seal_key() {
    let (_scratch, client) = running("wrap-unwrap");
    let aad = Aad(b"keyd crate round trip".to_vec());
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    assert_eq!(root.chain, Chain::App);
    assert_eq!(root.epoch, Epoch(1));
    let w = block_on(client.wrap(&root, &SealKey::from_bytes(canary(1)), &aad)).unwrap();
    let back = block_on(client.unwrap(&root, &w, &aad)).unwrap();
    assert_eq!(back.expose(), &canary(1));
}

/// ADR-004 part 2: a wrapped seal key is bound to its AAD. Under any other
/// AAD it does not unwrap.
#[test]
fn adr004_keyd_unwrap_refuses_another_aad() {
    let (_scratch, client) = running("other-aad");
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let w = block_on(client.wrap(
        &root,
        &SealKey::from_bytes(canary(2)),
        &Aad(b"owner A".to_vec()),
    ))
    .unwrap();
    let r = block_on(client.unwrap(&root, &w, &Aad(b"owner B".to_vec())));
    assert!(r.is_err(), "unwrapped under another AAD");
}

/// ADR-004 part 2: a seal key wrapped under one root does not unwrap
/// under another, of the same chain or of another chain. The Vault root
/// lives behind the `fstp-vault` socket ("Access to `fstp-keyd`"), so
/// the test asks both sockets.
#[test]
fn adr004_keyd_unwrap_refuses_another_root() {
    let scratch = Scratch::new("other-root").unwrap_or_else(|e| panic!("{e}"));
    let vault_socket = scratch.socket_dir.join("vault.sock");
    let (client, vault) = start_cell_and_vault(&scratch.socket, &vault_socket, &scratch.volume)
        .unwrap_or_else(|e| panic!("{e}"));
    let aad = Aad(b"keyd crate other root".to_vec());
    let r1 = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let r2 = block_on(client.create_root(label(Chain::App, 2))).unwrap();
    let rv = block_on(vault.create_root(label(Chain::Vault, 1))).unwrap();
    let w = block_on(client.wrap(&r1, &SealKey::from_bytes(canary(3)), &aad)).unwrap();
    assert!(
        block_on(client.unwrap(&r2, &w, &aad)).is_err(),
        "unwrapped under the next epoch"
    );
    assert!(
        block_on(vault.unwrap(&rv, &w, &aad)).is_err(),
        "unwrapped under the Vault chain"
    );
    assert!(
        block_on(client.unwrap(&rv, &w, &aad)).is_err(),
        "unwrapped under the Vault chain through the cell socket"
    );
}

/// R-NF-08, ADR-004 part 2 "Access to `fstp-keyd`": the `fstp-cell`
/// socket reaches the App and CellBackup chains and never the Vault
/// chain, and the `fstp-vault` socket reaches the Vault chain only. Each
/// refusal is `NotPermitted`.
#[test]
fn r_nf_08_keyd_sockets_keep_cell_and_vault_chains_apart() {
    use fstp_custody::{CustodyError, Refusal};
    let scratch = Scratch::new("chain-sets").unwrap_or_else(|e| panic!("{e}"));
    let vault_socket = scratch.socket_dir.join("vault.sock");
    let (cell, vault) = start_cell_and_vault(&scratch.socket, &vault_socket, &scratch.volume)
        .unwrap_or_else(|e| panic!("{e}"));
    let refused = Err(CustodyError::Refused(Refusal::NotPermitted));
    let mut wrong = Vec::new();
    for chain in [Chain::App, Chain::CellBackup] {
        if block_on(cell.create_root(label(chain, 1))).is_err() {
            wrong.push(format!("the cell socket refused {chain:?}"));
        }
        if block_on(vault.create_root(label(chain, 1))).map(|_| ()) != refused {
            wrong.push(format!("the vault socket served {chain:?}"));
        }
    }
    if block_on(vault.create_root(label(Chain::Vault, 1))).is_err() {
        wrong.push("the vault socket refused Vault".to_owned());
    }
    for chain in [Chain::Vault, Chain::ClusterBackup, Chain::ControlPlane] {
        if block_on(cell.create_root(label(chain, 1))).map(|_| ()) != refused {
            wrong.push(format!("the cell socket served {chain:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

/// I-81, ADR-004 part 2: after destroy, the root unwraps nothing, while
/// a live root of the same chain still unwraps its own key.
#[test]
fn i81_keyd_destroyed_root_never_unwraps() {
    let (_scratch, client) = running("destroyed");
    let aad = Aad(b"keyd crate destroy".to_vec());
    let r1 = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let r2 = block_on(client.create_root(label(Chain::App, 2))).unwrap();
    let w1 = block_on(client.wrap(&r1, &SealKey::from_bytes(canary(4)), &aad)).unwrap();
    let w2 = block_on(client.wrap(&r2, &SealKey::from_bytes(canary(5)), &aad)).unwrap();
    block_on(client.destroy(&r1)).unwrap();
    assert!(
        block_on(client.unwrap(&r1, &w1, &aad)).is_err(),
        "a destroyed root unwrapped"
    );
    assert!(
        block_on(client.wrap(&r1, &SealKey::from_bytes(canary(6)), &aad)).is_err(),
        "a destroyed root wrapped"
    );
    let s2 = block_on(client.unwrap(&r2, &w2, &aad)).unwrap();
    assert_eq!(s2.expose(), &canary(5), "the live root lost its key");
}

/// I-81, M-SHRED environment semantics: "A destroy of a root already
/// destroyed returns its receipt again." A retried destroy after a lost
/// reply gives the same receipt, not an error.
#[test]
fn i81_keyd_second_destroy_returns_the_same_receipt() {
    let (_scratch, client) = running("destroy-twice");
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let first = block_on(client.destroy(&root)).unwrap();
    let again = block_on(client.destroy(&root)).unwrap();
    assert!(!first.0.is_empty(), "an empty receipt");
    assert_eq!(first, again, "a second destroy gave another receipt");
}

/// ADR-004 part 2: "Each root epoch is 32 random bytes in its own file
/// `epoch-<chain>-<e>.key`." After a create, the key volume holds one
/// epoch file for that epoch, and after the destroy it holds none.
#[test]
fn adr004_keyd_keeps_one_epoch_file_per_root_epoch() {
    let (scratch, client) = running("epoch-file");
    let epoch_files = |e: u64| -> Vec<String> {
        std::fs::read_dir(&scratch.volume)
            .unwrap()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("epoch-") && n.ends_with(&format!("-{e}.key")))
            .collect()
    };
    // A chain's epochs are created from 1 on with no gap (ADR-004 part 2
    // "Epochs"), so epochs 1 to 6 come first.
    for e in 1..7 {
        block_on(client.create_root(label(Chain::App, e))).unwrap();
    }
    let root = block_on(client.create_root(label(Chain::App, 7))).unwrap();
    assert_eq!(epoch_files(7).len(), 1, "epoch files: {:?}", epoch_files(7));
    block_on(client.destroy(&root)).unwrap();
    assert!(epoch_files(7).is_empty(), "left: {:?}", epoch_files(7));
}

/// I-80: a seal key never lands on disk in clear. After a wrap and an
/// unwrap, no file on the key volume or in the socket directory holds
/// the seal key bytes, and neither does the wrapped key the client got.
#[test]
fn i80_keyd_never_stores_or_returns_a_seal_key_in_clear() {
    let (scratch, client) = running("no-clear");
    let aad = Aad(b"keyd crate no clear".to_vec());
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let w = block_on(client.wrap(&root, &SealKey::from_bytes(canary(7)), &aad)).unwrap();
    let _ = block_on(client.unwrap(&root, &w, &aad)).unwrap();
    assert!(
        !contains(&w.0, &canary(7)),
        "the wrapped key holds the seal key"
    );
    let mut found = Vec::new();
    for dir in [&scratch.volume, &scratch.socket_dir] {
        for (path, bytes) in files_under(dir) {
            if contains(&bytes, &canary(7)) {
                found.push(path.display().to_string());
            }
        }
    }
    assert!(found.is_empty(), "the seal key in clear in {found:?}");
}

/// ADR-004 part 2 "Reconciliation": `fstp-keyd` keeps a usage log of its
/// operations, which `usage_since` reads. After a create, a wrap and an
/// unwrap the log holds at least those three, and no entry holds the
/// seal key bytes.
#[test]
fn adr004_keyd_usage_log_records_operations_without_key_bytes() {
    let (_scratch, client) = running("usage");
    let aad = Aad(b"keyd crate usage".to_vec());
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let w = block_on(client.wrap(&root, &SealKey::from_bytes(canary(8)), &aad)).unwrap();
    let _ = block_on(client.unwrap(&root, &w, &aad)).unwrap();
    let page = block_on(client.usage_since(&root, UsageCursor::default())).unwrap();
    assert!(
        page.operations.len() >= 3,
        "the usage log holds {} operations",
        page.operations.len()
    );
    for op in &page.operations {
        assert!(
            !contains(op, &canary(8)),
            "a usage entry holds the seal key"
        );
    }
}

/// ADR-004 part 2 "Access to `fstp-keyd`": "Directory and socket
/// permissions let only that user connect." The socket grants nothing to
/// its group or to other users.
#[cfg(unix)]
#[test]
fn adr004_keyd_socket_admits_only_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let (scratch, _client) = running("socket-mode");
    let mode = std::fs::metadata(&scratch.socket)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "socket mode {mode:o} grants group or other access"
    );
}

/// I-81 NOTE (2026-11-01), Q-F: the full path is never skipped in Linux
/// CI. There `FSTP_KEY_VOLUME_DIR` must name a directory, and a volume
/// under it must report full assurance. Elsewhere a volume reports
/// `Full` only on Linux, and `Reduced` with a reason otherwise.
#[test]
fn i81_note_linux_ci_key_volume_reports_full() {
    use fstp_obs::assurance::Assurance;
    let in_ci = std::env::var_os("CI").is_some_and(|v| !v.is_empty());
    if cfg!(target_os = "linux") && in_ci {
        assert!(
            common::key_volume_named(),
            "FSTP_KEY_VOLUME_DIR is unset in Linux CI, so the full I-81 path would be skipped"
        );
    }
    let scratch = Scratch::new("assurance-guard").unwrap_or_else(|e| panic!("{e}"));
    let a = fstp_keyd::check_key_volume(&scratch.volume);
    if cfg!(target_os = "linux") && common::key_volume_named() {
        assert_eq!(a, Assurance::Full, "the named key volume is not full");
    }
    if !cfg!(target_os = "linux") {
        let Assurance::Reduced(r) = a else {
            panic!("full assurance off Linux");
        };
        assert!(!r.as_str().is_empty());
    }
}

/// I-81 NOTE (2026-11-01): `fstp-keyd` starts on a key volume of reduced
/// assurance instead of refusing it, and custody works there. Off Linux
/// the volume reports `Reduced` with a reason, never `Full`.
#[test]
fn i81_note_keyd_serves_a_volume_of_any_assurance() {
    use fstp_obs::assurance::Assurance;
    let (scratch, client) = running("any-assurance");
    let a = common::check_volume_assurance(&scratch.volume).unwrap_or_else(|e| panic!("{e}"));
    if !cfg!(target_os = "linux") {
        assert!(matches!(a, Assurance::Reduced(_)), "{a:?}");
    }
    let aad = Aad(b"keyd crate any assurance".to_vec());
    let root = block_on(client.create_root(label(Chain::App, 1))).unwrap();
    let w = block_on(client.wrap(&root, &SealKey::from_bytes(canary(9)), &aad)).unwrap();
    let back = block_on(client.unwrap(&root, &w, &aad)).unwrap();
    assert_eq!(back.expose(), &canary(9));
}
