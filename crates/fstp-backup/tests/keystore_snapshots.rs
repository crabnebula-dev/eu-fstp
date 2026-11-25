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
use fstp_backup::snapshot::{self, ObjectStore, SnapshotKey, SnapshotOwner, Snapshots};
use fstp_backup::writer::WriterKey;
use fstp_backup::{
    BackupError, ContainerKind, ObjectIdent, open_container, open_object, seal_object,
};
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
    client_for(rt, fake, BUCKET)
}

fn client_for(rt: &TokioRuntime, fake: &FakeS3, bucket: &str) -> S3Client<TokioRuntime> {
    S3Client::with_tls(
        rt.clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: bucket.to_owned(),
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
    let id = w.rt.block_on(w.vault.upload(&w.custody, &body)).unwrap();
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
    w.rt.block_on(w.vault.publish(&w.custody, id)).unwrap();
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
    let v =
        w.rt.block_on(w.vault.upload(&w.custody, b"vault rows"))
            .unwrap();
    let a =
        w.rt.block_on(w.app.upload(&w.custody, b"app rows"))
            .unwrap();
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
    // ADR-012 record of lane m10/backup-followups: the same holds for the
    // `FBC2` opener, under either writer key.
    for wp in [w.vault.key().file(), w.app.key().file()] {
        let wp = &wp.writer_public().unwrap()[..];
        assert!(open_object(&vs, wp, ab).is_err());
        assert!(open_object(&as_, wp, vb).is_err());
    }
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
    let id = w.rt.block_on(w.vault.upload(&w.custody, b"rows")).unwrap();
    let secret =
        w.rt.block_on(w.vault.key().open_secret(&w.custody))
            .unwrap();
    let file = keyfile::encode(w.vault.key().file()).unwrap();
    let sb = secret.to_bytes();
    assert!(
        !file.windows(32).any(|x| x == &sb[..32]),
        "I-80: the key file holds the open secret"
    );
    // Nor the writer key sealed beside it (ADR-012 record of lane
    // m10/backup-followups).
    let writer =
        w.rt.block_on(keyfile::open_writer(&w.custody, w.vault.key().file()))
            .unwrap();
    let wb = writer.encode().unwrap();
    assert!(
        !file.windows(32).any(|x| x == &wb[21..53]),
        "I-80: the key file holds the open writer key"
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
        // The version 2 group key file comes with its writer key, from
        // `create` (record of lane m10/backup-format).
        let bytes = if kind == FileKind::ClusterBackup {
            rt.block_on(keyfile::create(&custody, CELL))
                .unwrap()
                .key_file
        } else {
            rt.block_on(keyfile::create_kind(&custody, CELL, kind))
                .unwrap()
        };
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

/// ADR-012 record of lane m10/backup-followups, row "Old pointers": a
/// 16-byte version 1 pointer names no snapshot, since nothing
/// authenticates it, and the decoder refuses it as a version 2 pointer.
/// The pointer objects keep their names.
#[test]
fn adr012_version_1_pointer_names_no_snapshot() {
    let w = world();
    let name = snapshot::pointer_name(CELL, SnapshotOwner::Vault);
    w.fake
        .state
        .objects
        .lock()
        .unwrap()
        .insert(name.clone(), vec![7; 16]);
    assert_eq!(w.rt.block_on(w.vault.latest()).unwrap(), None);
    for len in [0, 15, 16, 17, 32, snapshot::POINTER_LEN - 1] {
        assert!(snapshot::decode_pointer(&vec![7; len]).is_err(), "{len}");
    }
    assert_eq!(name, format!("{}/keystore/latest-vault", "17".repeat(16)));
    assert_eq!(
        snapshot::pointer_name(CELL, SnapshotOwner::App),
        format!("{}/keystore/latest-app", "17".repeat(16))
    );
    w.fake.stop(&w.rt);
}

/// F-043, TH-51, ADR-012 record of lane m10/backup-followups: a holder of
/// the snapshot group's public key alone cannot plant a snapshot. A
/// container sealed to that key but signed by another writer key is
/// refused before anything opens, and so is an `FBC1` container, which
/// carries no signature.
#[test]
fn f043_th51_snapshot_from_a_public_key_holder_is_refused() {
    let w = world();
    let id = [0x31; 16];
    let file = w.vault.key().file();
    let forger = WriterKey::generate(CELL).unwrap();
    let forged = seal_object(
        &file.public_key().unwrap(),
        &forger,
        &file.group_ref(),
        &ObjectIdent::VaultSnapshot(id),
        b"planted rows",
    )
    .unwrap();
    let old = fstp_backup::seal_container(
        &file.public_key().unwrap(),
        ContainerKind::VaultKeystoreSnapshot,
        &file.group_ref(),
        0,
        b"planted rows",
    )
    .unwrap();
    for (bytes, rule) in [(forged, "writer signature"), (old, "magic")] {
        w.fake
            .state
            .objects
            .lock()
            .unwrap()
            .insert(snapshot::object_name(CELL, id), bytes);
        assert_eq!(
            w.rt.block_on(w.vault.fetch(&w.custody, id)),
            Err(BackupError::Malformed(rule))
        );
    }
    w.fake.stop(&w.rt);
}

/// F-043, ADR-012 record of lane m10/backup-followups: a snapshot names
/// its id and its process. A genuine snapshot copied under another id, or
/// the App snapshot under the vault's name, is refused.
#[test]
fn f043_snapshot_under_another_id_is_refused() {
    let w = world();
    let a =
        w.rt.block_on(w.vault.upload(&w.custody, b"rows a"))
            .unwrap();
    let app =
        w.rt.block_on(w.app.upload(&w.custody, b"app rows"))
            .unwrap();
    let b = [0x42; 16];
    {
        let mut o = w.fake.state.objects.lock().unwrap();
        let bytes = o[&snapshot::object_name(CELL, a)].clone();
        o.insert(snapshot::object_name(CELL, b), bytes);
    }
    assert_eq!(
        w.rt.block_on(w.vault.fetch(&w.custody, b)),
        Err(BackupError::Malformed("snapshot name"))
    );
    {
        let mut o = w.fake.state.objects.lock().unwrap();
        let bytes = o[&snapshot::object_name(CELL, app)].clone();
        o.insert(snapshot::object_name(CELL, b), bytes);
    }
    assert!(w.rt.block_on(w.vault.fetch(&w.custody, b)).is_err());
    assert_eq!(
        w.rt.block_on(w.vault.fetch(&w.custody, a)).unwrap(),
        b"rows a"
    );
    w.fake.stop(&w.rt);
}

/// F-043, ADR-012 record of lane m10/backup-followups, row "Pointer,
/// version 2": a pointer is signed by its process and names its process
/// and cell. A changed byte, a pointer of the other process and a
/// pointer of the right process signed by another key are refused.
#[test]
fn f043_snapshot_pointer_is_signed_and_names_its_object() {
    let w = world();
    let id = w.rt.block_on(w.vault.upload(&w.custody, b"rows")).unwrap();
    w.rt.block_on(w.vault.publish(&w.custody, id)).unwrap();
    let vname = snapshot::pointer_name(CELL, SnapshotOwner::Vault);
    let aname = snapshot::pointer_name(CELL, SnapshotOwner::App);
    let good = w.fake.state.objects.lock().unwrap()[&vname].clone();
    assert_eq!(good.len(), snapshot::POINTER_LEN);
    let p = snapshot::decode_pointer(&good).unwrap();
    assert_eq!((p.owner, p.cell, p.id), (SnapshotOwner::Vault, CELL, id));
    assert_eq!(&good[..4], b"FKP1");
    assert_eq!(w.rt.block_on(w.vault.latest()).unwrap(), Some(id));
    let put = |name: &str, bytes: Vec<u8>| {
        w.fake
            .state
            .objects
            .lock()
            .unwrap()
            .insert(name.to_owned(), bytes);
    };
    for i in [4, 5, 6, 7, 30, 40, snapshot::POINTER_LEN - 1] {
        let mut b = good.clone();
        b[i] ^= 1;
        put(&vname, b);
        assert!(w.rt.block_on(w.vault.latest()).is_err(), "{i}");
    }
    // The vault's pointer under the App name: another process.
    put(&aname, good.clone());
    assert!(w.rt.block_on(w.app.latest()).is_err());
    // The right body signed by another key.
    let mut forged = snapshot::pointer_body(SnapshotOwner::Vault, CELL, [9; 16]);
    let sig = WriterKey::generate(CELL)
        .unwrap()
        .sign_pointer(&forged)
        .unwrap();
    forged.extend_from_slice(&sig);
    put(&vname, forged);
    assert_eq!(
        w.rt.block_on(w.vault.latest()),
        Err(BackupError::Malformed("pointer signature"))
    );
    w.fake.stop(&w.rt);
}

/// Q25, ADR-012 record of lane m10/backup-followups, row "Every store": a
/// snapshot and its pointer go to every store with the same bytes. A
/// fetch takes the first store whose copy verifies, and falls through a
/// changed or a missing copy. When no store has a good copy, the answer is
/// the first refusal.
#[test]
fn q25_snapshot_goes_to_every_store_and_falls_through() {
    let w = world();
    let second = FakeS3::start(&w.rt, AK, SK, REGION, "fstp-test-snapshots-2");
    let stores: Vec<Arc<dyn ObjectStore>> = vec![
        Arc::new(client(&w.rt, &w.fake)),
        Arc::new(client_for(&w.rt, &second, "fstp-test-snapshots-2")),
    ];
    let both = Snapshots::with_stores(stores, w.vault.key().clone()).unwrap();
    let id = w.rt.block_on(both.upload(&w.custody, b"rows")).unwrap();
    w.rt.block_on(both.publish(&w.custody, id)).unwrap();
    let name = snapshot::object_name(CELL, id);
    let pname = snapshot::pointer_name(CELL, SnapshotOwner::Vault);
    for n in [&name, &pname] {
        assert_eq!(
            w.fake.state.objects.lock().unwrap()[n],
            second.state.objects.lock().unwrap()[n],
        );
    }
    // A changed copy in the first store falls through to the second.
    {
        let mut o = w.fake.state.objects.lock().unwrap();
        let b = o.get_mut(&name).unwrap();
        let i = b.len() - 9;
        b[i] ^= 1;
        let p = o.get_mut(&pname).unwrap();
        p[40] ^= 1;
    }
    assert_eq!(w.rt.block_on(both.fetch(&w.custody, id)).unwrap(), b"rows");
    assert_eq!(w.rt.block_on(both.latest()).unwrap(), Some(id));
    // A missing copy in the first store falls through too.
    w.fake.state.objects.lock().unwrap().remove(&name);
    assert_eq!(w.rt.block_on(both.fetch(&w.custody, id)).unwrap(), b"rows");
    // No good copy anywhere: the refusal, never a silent absence.
    {
        let mut o = second.state.objects.lock().unwrap();
        let b = o.get_mut(&name).unwrap();
        let i = b.len() - 9;
        b[i] ^= 1;
    }
    assert!(matches!(
        w.rt.block_on(both.fetch(&w.custody, id)),
        Err(BackupError::Malformed(_))
    ));
    // Neither store holds it: absent.
    assert_eq!(
        w.rt.block_on(both.fetch(&w.custody, [3; 16])),
        Err(BackupError::NotFound)
    );
    // A store that refuses the upload fails the upload.
    second.stop(&w.rt);
    assert!(w.rt.block_on(both.upload(&w.custody, b"rows")).is_err());
    assert!(Snapshots::with_stores(Vec::new(), w.vault.key().clone()).is_err());
    w.fake.stop(&w.rt);
}

/// F-044, ADR-012 record of lane m10/backup-followups, row "Upgrade": a
/// version 1 snapshot key file upgrades in place through its own custody
/// root. The group, generation, group key and root stay, a writer key is
/// bound, and the version 1 file no longer decodes as version 2. A file
/// of another cell or one already upgraded is refused.
#[test]
fn f044_snapshot_key_file_upgrades_in_place() {
    let rt = rt();
    let custody = MemCustody::default();
    for (owner, v1) in [
        (SnapshotOwner::App, FileKind::CellSnapshotV1),
        (SnapshotOwner::Vault, FileKind::VaultSnapshotV1),
    ] {
        let old = rt
            .block_on(keyfile::create_kind(&custody, CELL, v1))
            .unwrap();
        assert!(SnapshotKey::is_version_1(&old, owner));
        assert!(SnapshotKey::decode(&old, CELL, owner).is_err());
        let new = rt
            .block_on(SnapshotKey::upgrade(&custody, &old, CELL, owner))
            .unwrap();
        assert!(!SnapshotKey::is_version_1(&new, owner));
        let o = keyfile::decode_kind(&old, v1).unwrap();
        let k = SnapshotKey::decode(&new, CELL, owner).unwrap();
        let n = k.file();
        assert_eq!(
            (n.cluster, n.group, n.generation, n.public, &n.handle),
            (o.cluster, o.group, o.generation, o.public, &o.handle)
        );
        assert_eq!(n.root(), o.root());
        let s = rt.block_on(k.open_secret(&custody)).unwrap();
        assert_eq!(s.public().to_bytes(), o.public);
        let w = rt.block_on(keyfile::open_writer(&custody, n)).unwrap();
        assert_eq!(Some(&w.public()), n.writer_public());
        assert!(
            rt.block_on(SnapshotKey::upgrade(&custody, &new, CELL, owner))
                .is_err()
        );
        assert!(
            rt.block_on(SnapshotKey::upgrade(&custody, &old, [0x18; 16], owner))
                .is_err()
        );
        // A snapshot written under the upgraded file opens.
        let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
        let s = Snapshots::new(Arc::new(client(&rt, &fake)), k);
        let id = rt.block_on(s.upload(&custody, b"rows")).unwrap();
        assert_eq!(rt.block_on(s.fetch(&custody, id)).unwrap(), b"rows");
        fake.stop(&rt);
    }
}

/// ADR-012 record of lane m10/backup-format, row "Custody AAD", and of
/// lane m10/backup-followups: a version 2 snapshot key file's header is
/// longer than `fstp-keyd` takes as AAD, so custody sees its short form.
/// The test custody refuses a longer AAD, as `fstp-keyd` does, and the
/// whole create, open and upgrade path runs through it.
#[test]
fn adr012_snapshot_key_custody_aad_fits_keyd() {
    let w = world();
    for s in [&w.app, &w.vault] {
        let f = s.key().file();
        assert!(f.aad().len() > fstp_custody::keyd::MAX_AAD_LEN);
        assert!(f.custody_aad().len() <= fstp_custody::keyd::MAX_AAD_LEN);
        assert!(w.rt.block_on(s.key().open_secret(&w.custody)).is_ok());
    }
    let long = fstp_custody::Aad(vec![0; fstp_custody::keyd::MAX_AAD_LEN + 1]);
    let root = w.vault.key().file().root();
    let seal = fstp_custody::SealKey::generate().unwrap();
    assert!(w.rt.block_on(w.custody.wrap(&root, &seal, &long)).is_err());
    w.fake.stop(&w.rt);
}

/// ADR-004 record of lane L17, row "Genesis", and ADR-012 record of lane
/// m10/backup-followups, row "Upgrade": at a process start, a missing
/// snapshot key file is created and a version 1 file is replaced on disk
/// by version 2 under the same root, with mode 0600 and no temporary file
/// left. A version 2 file is read as it is.
#[test]
fn f044_snapshot_key_file_upgrades_at_load() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = rt();
    let custody = MemCustody::default();
    let dir = std::env::temp_dir().join(format!(
        "fstp-bf-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(SnapshotOwner::Vault.key_file_name());
    let made = rt
        .block_on(snapshot::load_key(
            &custody,
            &path,
            CELL,
            SnapshotOwner::Vault,
        ))
        .unwrap();
    assert_eq!(made.file().kind, FileKind::VaultSnapshot);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let again = rt
        .block_on(snapshot::load_key(
            &custody,
            &path,
            CELL,
            SnapshotOwner::Vault,
        ))
        .unwrap();
    assert_eq!(again.file(), made.file());
    let v1 = rt
        .block_on(keyfile::create_kind(
            &custody,
            CELL,
            FileKind::VaultSnapshotV1,
        ))
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, &v1).unwrap();
    let up = rt
        .block_on(snapshot::load_key(
            &custody,
            &path,
            CELL,
            SnapshotOwner::Vault,
        ))
        .unwrap();
    let on_disk = std::fs::read(&path).unwrap();
    assert!(!SnapshotKey::is_version_1(&on_disk, SnapshotOwner::Vault));
    assert_eq!(keyfile::encode(up.file()).unwrap(), on_disk);
    assert_eq!(
        up.file().root(),
        keyfile::decode_kind(&v1, FileKind::VaultSnapshotV1)
            .unwrap()
            .root()
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    // Another cell's file is refused, and left as it was.
    assert!(
        rt.block_on(snapshot::load_key(
            &custody,
            &path,
            [0x18; 16],
            SnapshotOwner::Vault
        ))
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), on_disk);
    std::fs::remove_dir_all(&dir).unwrap();
}
