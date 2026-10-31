//! Review reproducers for lane W2f that need the private socket loop.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fstp_custody::{CellId, Chain, Custody as _, Epoch, RootLabel};
use fstp_rt::future::block_on;

use crate::Passphrase;
use crate::server::{Server, run, stop};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fstp-keyd-review-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// R-NF-08, ADR-004 part 2 "Access to fstp-keyd": each socket serves a
/// fixed set of chains. `fstp-cell` reaches App and CellBackup, and
/// `fstp-vault` reaches Vault only, so a compromise of application keys
/// does not expose the vault. `fstp-keyd` serves every chain on its one
/// socket. A client that holds the App socket creates, unwraps and
/// destroys Vault roots too.
#[cfg(unix)]
#[test]
fn review_keyd_one_socket_serves_app_and_vault_chains() {
    let dir = scratch("chains");
    let socket = dir.join("keyd.sock");
    let volume = dir.join("keys");
    std::fs::create_dir_all(&volume).unwrap();
    let pass = Passphrase::from_bytes(b"synthetic review passphrase").unwrap();
    let server = Server::open(&volume, &pass).unwrap();
    let handle = {
        let socket = socket.clone();
        std::thread::spawn(move || run(&socket, server))
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "no socket");
        std::thread::sleep(Duration::from_millis(5));
    }
    let client = fstp_custody::KeydCustody::new(&socket).unwrap();
    let label = |chain| RootLabel {
        cell: Some(CellId([3; 16])),
        chain,
        epoch: Epoch(1),
    };
    let app = block_on(client.create_root(label(Chain::App)));
    let vault = block_on(client.create_root(label(Chain::Vault)));
    stop(&socket).unwrap();
    handle.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(app.is_ok(), "the App create failed: {app:?}");
    assert!(
        vault.is_err(),
        "the socket that serves the App chain also served a Vault root"
    );
}

// ---------------------------------------------------------------------------
// Adversarial review of the fixes (independent review of lane W2f, round
// 2). Each test fails on the current code and passes once its defect is
// fixed.

mod adversarial {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use std::io::Write as _;
    use std::path::Path;

    use fstp_custody::keyd::{Request, RequestId, Response, RootHandle};
    use fstp_custody::{Chain, Custody as _, Epoch, RootLabel};
    use fstp_rt::future::block_on;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    use super::scratch;
    use crate::Passphrase;
    use crate::access::{ClientRole, ClientSocket};
    use crate::server::{Server, run_sockets, stop};
    use crate::table::{EpochKey, TABLE_FILE, TableStore};

    const ID: RequestId = RequestId([0x5a; 16]);

    fn pass() -> Passphrase {
        Passphrase::from_bytes(b"synthetic adversarial review passphrase").unwrap()
    }

    fn create(s: &mut Server, chain: Chain, e: u64) -> RootHandle {
        match s.handle(&Request::CreateRoot {
            id: ID,
            cell: None,
            chain,
            epoch: Epoch(e),
        }) {
            Response::Root(h) => h,
            other => panic!("create {e}: {other:?}"),
        }
    }

    fn wait_for(paths: &[&Path]) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !paths.iter().all(|p| p.exists()) {
            assert!(Instant::now() < deadline, "no sockets");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// R-NF-08, ADR-004 part 2 "Access to `fstp-keyd`": each socket
    /// serves its own client, so a compromise of the `fstp-cell` OS user
    /// must not reach the vault. The accept loop serves one connection
    /// at a time, and the 5 s read timeout applies to each `read` call,
    /// not to the request. A cell client that sends its header one byte
    /// a second holds the loop for as long as it likes, and the
    /// `fstp-vault` client waits behind it. Here a vault create takes
    /// about 13 s instead of a few milliseconds.
    #[cfg(unix)]
    #[test]
    fn review_keyd_slow_cell_client_stalls_the_vault_socket() {
        use std::os::unix::net::UnixStream;

        let dir = scratch("adv-slow");
        let volume = dir.join("keys");
        std::fs::create_dir_all(&volume).unwrap();
        let sockets = vec![
            ClientSocket::owner_only(&dir.join("cell.sock"), ClientRole::Cell),
            ClientSocket::owner_only(&dir.join("vault.sock"), ClientRole::Vault),
        ];
        let server = Server::open(&volume, &pass()).unwrap();
        let handle = {
            let sockets = sockets.clone();
            std::thread::spawn(move || run_sockets(&sockets, server))
        };
        wait_for(&[&sockets[0].path, &sockets[1].path]);
        let mut slow = UnixStream::connect(&sockets[0].path).unwrap();
        let trickle = std::thread::spawn(move || {
            // Eight of the nine header bytes, one a second.
            for b in &fstp_custody::keyd::FRAME_MAGIC {
                let _ = slow.write_all(&[*b]);
                std::thread::sleep(Duration::from_secs(1));
            }
            for _ in 0..4 {
                let _ = slow.write_all(&[0]);
                std::thread::sleep(Duration::from_secs(1));
            }
            slow
        });
        std::thread::sleep(Duration::from_millis(300));
        let vault = fstp_custody::KeydCustody::new(&sockets[1].path).unwrap();
        let started = Instant::now();
        let created = block_on(vault.create_root(RootLabel {
            cell: None,
            chain: Chain::Vault,
            epoch: Epoch(1),
        }));
        let waited = started.elapsed();
        drop(trickle.join());
        stop(&sockets[1].path).unwrap();
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(created.is_ok(), "{created:?}");
        assert!(
            waited < Duration::from_secs(3),
            "a slow fstp-cell connection held the fstp-vault socket for {waited:?}"
        );
    }

    /// ADR-004 part 2 "A crash at any step loses nothing", and the FKT2
    /// claim that a torn write damages one slot at most. A create that
    /// appends a new slot and stops part way, as a full key volume
    /// leaves it (a short `write`), leaves a file that holds no whole
    /// number of slots. `SealedTable::decode` then refuses the whole
    /// table, so the next start loses every root of every chain.
    #[test]
    fn review_keyd_torn_slot_append_loses_every_root() {
        let dir = scratch("adv-append");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r1 = create(&mut s, Chain::App, 1);
        let wrapped = match s.handle(&Request::Wrap {
            id: ID,
            root: r1,
            aad: b"aad".to_vec(),
            key: Zeroizing::new([3; 32]),
        }) {
            Response::Wrapped(w) => w,
            other => panic!("wrap: {other:?}"),
        };
        let table = dir.join(TABLE_FILE);
        let before = std::fs::metadata(&table).unwrap().len();
        create(&mut s, Chain::App, 2);
        drop(s);
        // The state a short write of the new slot leaves: 30 of its 70
        // bytes.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&table)
            .unwrap();
        file.set_len(before + 30).unwrap();
        drop(file);
        let reopened = Server::open(&dir, &pass());
        let unwrapped = reopened.map(|mut s| {
            s.handle(&Request::Unwrap {
                id: ID,
                root: r1,
                aad: b"aad".to_vec(),
                wrapped,
            })
        });
        let _ = std::fs::remove_dir_all(&dir);
        match unwrapped {
            Ok(r) => assert_eq!(r, Response::Unwrapped(Zeroizing::new([3; 32]))),
            Err(e) => panic!("a torn slot append lost every root: {e:?}"),
        }
    }

    /// ADR-004 part 2 "A crash at any step loses nothing". A create whose
    /// slot write lands but whose fsync fails marks the slot `Blocked`
    /// and answers `Internal`. The cell retries the create (step 3), and
    /// `insert` seals a second slot for the same chain and epoch. Once
    /// the first write reaches the disk too, the next start finds two
    /// slots of one epoch, and `decode_key_table_body` refuses the whole
    /// table. The test leaves the first slot in place of the failed one
    /// by dropping its entry, as the failed insert does.
    #[test]
    fn review_keyd_retried_create_after_a_failed_fsync_loses_every_root() {
        let dir = scratch("adv-dup");
        let mut store = TableStore::open_or_create(&dir, &pass()).unwrap();
        store
            .insert(Chain::App, Epoch(1), EpochKey::from_bytes([1; 32]))
            .unwrap();
        store
            .insert(Chain::App, Epoch(2), EpochKey::from_bytes([2; 32]))
            .unwrap();
        // The failed insert: its slot holds the bytes, its entry is not
        // in the table, and its slot is not free.
        store.table.entries.retain(|e| e.epoch != Epoch(2));
        store
            .insert(Chain::App, Epoch(2), EpochKey::from_bytes([4; 32]))
            .unwrap();
        drop(store);
        let reopened = TableStore::open_or_create(&dir, &pass());
        let live = reopened.as_ref().map(|s| {
            s.table
                .get(Chain::App, Epoch(1))
                .is_some_and(|e| e.is_live())
        });
        let _ = std::fs::remove_dir_all(&dir);
        match live {
            Ok(l) => assert!(l, "the live R(1) is gone after a retried create"),
            Err(e) => panic!("a retried create after a failed fsync lost every root: {e:?}"),
        }
    }
}
