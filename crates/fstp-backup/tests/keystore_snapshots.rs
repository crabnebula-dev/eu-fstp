//! Keystore snapshots through the S3 subset (ADR-012 record of lane L17,
//! ADR-004 record of lane L17, R-NF-08, I-81, I-80).
//!
//! A snapshot of each process is sealed to its own snapshot group, uploaded
//! to `<cell>/keystore/<snapshot id>` on the in-process fake S3 of lane L10,
//! and fetched back. Opening needs the snapshot root in custody. The two
//! snapshot keys never open each other's containers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::sync::Arc;

use fstp_backup::keyfile::{self, FileKind};
use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::snapshot::{self, SnapshotKey, SnapshotOwner, Snapshots};
use fstp_backup::{BackupError, ContainerKind, open_container};
use fstp_custody::{Chain, Custody};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "TESTACCESSKEY17";
const SK: &str = "test/secret+key=lane-l17";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-snapshots";
const CELL: [u8; 16] = [0x17; 16];

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(2).unwrap()
}

fn client(rt: &TokioRuntime, fake: &FakeS3) -> S3Client<TokioRuntime> {
    S3Client::with_tls(
        rt.clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, SK).unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    )
}

struct World {
    rt: TokioRuntime,
    fake: FakeS3,
    custody: MemCustody,
    app: Snapshots,
    vault: Snapshots,
}

fn world() -> World {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let store = Arc::new(client(&rt, &fake));
    let key = |owner| {
        let bytes = rt
            .block_on(SnapshotKey::create(&custody, CELL, owner))
            .unwrap();
        SnapshotKey::decode(&bytes, CELL, owner).unwrap()
    };
    let app = Snapshots::new(store.clone(), key(SnapshotOwner::App));
    let vault = Snapshots::new(store, key(SnapshotOwner::Vault));
    World {
        rt,
        fake,
        custody,
        app,
        vault,
    }
}

/// ADR-012 record of lane L17: a snapshot uploads to `<cell>/keystore/<id>`
/// and fetches back to its plaintext through the snapshot root. The
/// pointer names it once published. A missing object is `NotFound`, and a
/// changed byte fails to open.
#[test]
fn adr012_snapshot_upload_and_fetch_round_trip() {
    let w = world();
    let body = b"synthetic keystore image, lane L17".to_vec();
    let id = w.rt.block_on(w.vault.upload(&body)).unwrap();
    let name = snapshot::object_name(CELL, id);
    assert_eq!(
        name,
        format!(
            "{}/keystore/{}",
            "17".repeat(16),
            fstp_backup::sigv4::hex(&id)
        )
    );
    assert!(w.fake.state.objects.lock().unwrap().contains_key(&name));
    let back = w.rt.block_on(w.vault.fetch(&w.custody, id)).unwrap();
    assert_eq!(back, body);
    assert_eq!(w.rt.block_on(w.vault.latest()).unwrap(), None);
    w.rt.block_on(w.vault.publish(id)).unwrap();
    assert_eq!(w.rt.block_on(w.vault.latest()).unwrap(), Some(id));
    assert_eq!(w.rt.block_on(w.app.latest()).unwrap(), None);
    // A missing snapshot.
    assert_eq!(
        w.rt.block_on(w.vault.fetch(&w.custody, [9; 16])),
        Err(BackupError::NotFound)
    );
    // A changed byte.
    {
        let mut objects = w.fake.state.objects.lock().unwrap();
        let o = objects.get_mut(&name).unwrap();
        let last = o.len() - 3;
        o[last] ^= 1;
    }
    assert!(w.rt.block_on(w.vault.fetch(&w.custody, id)).is_err());
    w.fake.stop(&w.rt);
}

/// R-NF-08, ADR-004 record of lane L17: the vault's snapshot key and the
/// App chain's snapshot key never open each other's containers. A vault
/// snapshot is kind 5 on VaultBackup, an App snapshot kind 3 on
/// CellBackup, each root is labelled with the cell, and no fetch through
/// the other key returns the plaintext.
#[test]
fn r_nf_08_snapshot_keys_never_open_each_other() {
    let w = world();
    let v = w.rt.block_on(w.vault.upload(b"vault rows")).unwrap();
    let a = w.rt.block_on(w.app.upload(b"app rows")).unwrap();
    let objects = w.fake.state.objects.lock().unwrap().clone();
    let vb = &objects[&snapshot::object_name(CELL, v)];
    let ab = &objects[&snapshot::object_name(CELL, a)];
    assert_eq!(vb[7], ContainerKind::VaultKeystoreSnapshot.code());
    assert_eq!(vb[8], Chain::VaultBackup.code());
    assert_eq!(ab[7], ContainerKind::KeystoreSnapshot.code());
    assert_eq!(ab[8], Chain::CellBackup.code());
    let vs =
        w.rt.block_on(w.vault.key().open_secret(&w.custody))
            .unwrap();
    let as_ = w.rt.block_on(w.app.key().open_secret(&w.custody)).unwrap();
    assert!(
        open_container(&vs, ab).is_err(),
        "the vault key opened App rows"
    );
    assert!(
        open_container(&as_, vb).is_err(),
        "the App key opened vault rows"
    );
    assert!(w.rt.block_on(w.app.fetch(&w.custody, v)).is_err());
    assert!(w.rt.block_on(w.vault.fetch(&w.custody, a)).is_err());
    let labels = w.custody.labels();
    assert_eq!(labels.len(), 2);
    assert!(labels.iter().all(|l| l.cell.map(|c| c.0) == Some(CELL)));
    let chains: Vec<Chain> = labels.iter().map(|l| l.chain).collect();
    assert!(chains.contains(&Chain::VaultBackup) && chains.contains(&Chain::CellBackup));
    w.fake.stop(&w.rt);
}

/// I-81, I-80: a snapshot opens only while its snapshot root lives. Once
/// the root is destroyed, as a cell erasure does, the fetched container
/// no longer opens. The key file holds no open key.
#[test]
fn i81_snapshot_dies_with_its_snapshot_root() {
    let w = world();
    let id = w.rt.block_on(w.vault.upload(b"rows")).unwrap();
    let secret =
        w.rt.block_on(w.vault.key().open_secret(&w.custody))
            .unwrap();
    let file = keyfile::encode(w.vault.key().file()).unwrap();
    let sb = secret.to_bytes();
    assert!(
        !file.windows(32).any(|x| x == &sb[..32]),
        "I-80: the key file holds the open secret"
    );
    w.rt.block_on(w.custody.destroy(&w.vault.key().file().root()))
        .unwrap();
    assert!(w.rt.block_on(w.vault.fetch(&w.custody, id)).is_err());
    w.fake.stop(&w.rt);
}

/// ADR-004 record of lane L17: each key file decodes only under its own
/// magic, so no process reads another's file as its own.
#[test]
fn adr004_snapshot_key_files_decode_only_under_their_magic() {
    let rt = rt();
    let custody = MemCustody::default();
    for kind in FileKind::ALL {
        let bytes = rt
            .block_on(keyfile::create_kind(&custody, CELL, kind))
            .unwrap();
        for other in FileKind::ALL {
            assert_eq!(
                keyfile::decode_kind(&bytes, other).is_ok(),
                kind == other,
                "{kind:?} as {other:?}"
            );
        }
        let f = keyfile::decode_kind(&bytes, kind).unwrap();
        assert_eq!(keyfile::encode(&f).unwrap(), bytes);
        assert_eq!(f.root().chain, kind.chain());
    }
    for owner in [SnapshotOwner::App, SnapshotOwner::Vault] {
        let bytes = rt
            .block_on(SnapshotKey::create(&custody, CELL, owner))
            .unwrap();
        assert!(SnapshotKey::decode(&bytes, [0x18; 16], owner).is_err());
    }
}

/// ADR-012 record of lane L17 "Newest snapshot": the pointer is exactly
/// sixteen bytes. Any other length is refused.
#[test]
fn adr012_snapshot_pointer_is_exactly_sixteen_bytes() {
    assert_eq!(snapshot::decode_pointer(&[7; 16]), Ok([7; 16]));
    for len in [0, 15, 17, 32] {
        assert!(snapshot::decode_pointer(&vec![7; len]).is_err(), "{len}");
    }
    assert_eq!(
        snapshot::pointer_name(CELL, SnapshotOwner::Vault),
        format!("{}/keystore/latest-vault", "17".repeat(16))
    );
    assert_eq!(
        snapshot::pointer_name(CELL, SnapshotOwner::App),
        format!("{}/keystore/latest-app", "17".repeat(16))
    );
}
