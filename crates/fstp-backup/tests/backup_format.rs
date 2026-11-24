//! The backup write side of lane m10/backup-format (ADR-012 record of
//! lane m10/backup-format, F-043, F-044, Q25, TH-51, R-CR-01, I-81),
//! against the in-process fake S3 of lane L10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::path::PathBuf;

use fstp_backup::BackupError;
use fstp_backup::agent::{Agent, Limits};
use fstp_backup::keyfile::{self, FileKind};
use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::writer::WriterKey;
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "TESTACCESSKEY01";
const SK: &str = "test/secret+key=0123456789";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-backups";
const CLUSTER: [u8; 16] = [0x5a; 16];

/// Small sizes, so a few MiB make several parts.
const SMALL: Limits = Limits {
    base_part: 3 * 1024 * 1024 + 7,
    single_put_max: 1024 * 1024,
    upload_part: 700 * 1024,
};

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(2).unwrap()
}

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-backup-fmt-{what}-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
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

struct Setup {
    rt: TokioRuntime,
    fake: FakeS3,
    custody: MemCustody,
    agent: Agent<TokioRuntime>,
    state: PathBuf,
    key_file: Vec<u8>,
    writer_key: Vec<u8>,
}

fn setup() -> Setup {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let created = rt.block_on(keyfile::create(&custody, CLUSTER)).unwrap();
    let state = temp_dir("state");
    let agent = Agent::new(
        client(&rt, &fake),
        CLUSTER,
        &created.key_file,
        Some(&created.writer_key),
        &state,
    )
    .unwrap()
    .with_limits(SMALL);
    Setup {
        rt,
        fake,
        custody,
        agent,
        state,
        key_file: created.key_file.clone(),
        writer_key: created.writer_key.to_vec(),
    }
}

/// The key file `bytes` with its group public key replaced by `public`.
/// The binding signature stays as it was.
fn with_public(bytes: &[u8], public: [u8; 1216]) -> Vec<u8> {
    let mut f = keyfile::decode(bytes).unwrap();
    f.public = public;
    keyfile::encode(&f).unwrap()
}

/// F-044, TH-51: a party that can write `cluster-backup.key` replaces its
/// group public key. The agent refuses the file before any seal, and an
/// agent built on the good file refuses to seal once its copy changes.
/// Re-signing the binding with another writer key does not help, since
/// the agent compares the writer key it holds.
#[test]
fn f044_th51_agent_refuses_a_key_file_with_a_replaced_public_key() {
    let s = setup();
    let attacker = fstp_crypto::hybrid_kem::generate().unwrap();
    let replaced = with_public(&s.key_file, attacker.public().to_bytes());
    let got = Agent::new(
        client(&s.rt, &s.fake),
        CLUSTER,
        &replaced,
        Some(&s.writer_key),
        &s.state,
    );
    assert_eq!(got.err(), Some(BackupError::KeyFile("binding")));

    // The attacker also replaces the writer public key and signs the
    // binding with a writer key of its own.
    let theirs = WriterKey::generate(CLUSTER).unwrap();
    let mut f = keyfile::decode(&replaced).unwrap();
    let b = f.binding.as_mut().unwrap();
    *b.writer = theirs.public();
    let aad = f.aad();
    *f.binding.as_mut().unwrap().signature = theirs.sign_binding(&aad).unwrap();
    let resigned = keyfile::encode(&f).unwrap();
    let got = Agent::new(
        client(&s.rt, &s.fake),
        CLUSTER,
        &resigned,
        Some(&s.writer_key),
        &s.state,
    );
    assert_eq!(
        got.err(),
        Some(BackupError::KeyFile("writer key of another key file"))
    );
    // Custody binds both public keys too: the re-signed file does not
    // open, so a restore or a drill would also refuse it.
    assert!(s.rt.block_on(keyfile::open(&s.custody, &f)).is_err());

    // The good agent seals and uploads, and nothing went to the store
    // under the attacker's key.
    let dir = temp_dir("wal");
    std::fs::write(dir.join("s"), b"segment").unwrap();
    s.rt.block_on(s.agent.archive(&dir.join("s"), "000000010000000000000001"))
        .unwrap();
    assert_eq!(s.fake.state.objects.lock().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// F-044: the writer key of another key file, or of another cluster, is
/// refused, and an agent without a writer key restores but never seals.
#[test]
fn f044_th51_agent_refuses_a_writer_key_of_another_key_file() {
    let s = setup();
    let other = s.rt.block_on(keyfile::create(&s.custody, CLUSTER)).unwrap();
    let got = Agent::new(
        client(&s.rt, &s.fake),
        CLUSTER,
        &s.key_file,
        Some(&other.writer_key),
        &s.state,
    );
    assert_eq!(
        got.err(),
        Some(BackupError::KeyFile("writer key of another key file"))
    );
    let elsewhere = WriterKey::generate([1; 16]).unwrap().encode().unwrap();
    let got = Agent::new(
        client(&s.rt, &s.fake),
        CLUSTER,
        &s.key_file,
        Some(&elsewhere),
        &s.state,
    );
    assert_eq!(
        got.err(),
        Some(BackupError::KeyFile("writer key of another cluster"))
    );
    let reader = Agent::new(client(&s.rt, &s.fake), CLUSTER, &s.key_file, None, &s.state).unwrap();
    let dir = temp_dir("wal");
    std::fs::write(dir.join("s"), b"segment").unwrap();
    assert_eq!(
        s.rt.block_on(reader.archive(&dir.join("s"), "000000010000000000000001"))
            .unwrap_err(),
        BackupError::Config("cluster-backup-writer.key")
    );
    assert!(s.fake.state.objects.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// F-043, F-044, ADR-012 record of lane m10/backup-format "Upgrade": a
/// version 1 key file is refused by the agent, and `upgrade` turns it
/// into a version 2 file for the same group key, root and group, bound
/// to a writer key, whose secret opens through the same custody root.
/// A given writer key is kept.
#[test]
fn f043_upgrade_keeps_the_group_key_and_binds_a_writer() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let v1 = rt
        .block_on(keyfile::create_kind(
            &custody,
            CLUSTER,
            FileKind::ClusterBackupV1,
        ))
        .unwrap();
    let old = keyfile::decode_kind(&v1, FileKind::ClusterBackupV1).unwrap();
    let old_secret = rt.block_on(keyfile::open(&custody, &old)).unwrap();
    assert_eq!(
        keyfile::decode(&v1).err(),
        Some(BackupError::KeyFile("magic"))
    );
    let w = WriterKey::generate(CLUSTER).unwrap();
    assert!(
        Agent::new(
            client(&rt, &fake),
            CLUSTER,
            &v1,
            Some(&w.encode().unwrap()),
            &temp_dir("v1"),
        )
        .is_err()
    );

    let up = rt.block_on(keyfile::upgrade(&custody, &v1, None)).unwrap();
    let new = keyfile::decode(&up.key_file).unwrap();
    assert_eq!(
        (new.cluster, new.group, new.generation, new.epoch),
        (old.cluster, old.group, old.generation, old.epoch)
    );
    assert_eq!((new.public, &new.handle), (old.public, &old.handle));
    let writer = WriterKey::decode(&up.writer_key).unwrap();
    new.check_writer(&writer).unwrap();
    let secret = rt.block_on(keyfile::open(&custody, &new)).unwrap();
    assert_eq!(secret.to_bytes()[..], old_secret.to_bytes()[..]);
    assert_eq!(custody.live(), 1, "the same root, no new one");

    let kept = rt
        .block_on(keyfile::upgrade(&custody, &v1, Some(w)))
        .unwrap();
    let kept_writer = WriterKey::decode(&kept.writer_key).unwrap();
    keyfile::decode(&kept.key_file)
        .unwrap()
        .check_writer(&kept_writer)
        .unwrap();
    // A version 2 file is not upgraded again.
    assert!(
        rt.block_on(keyfile::upgrade(&custody, &up.key_file, None))
            .is_err()
    );
    fake.stop(&rt);
}

/// F-043, TH-51, R-CR-01: a bucket writer moves part 0 of base backup B
/// under the name of part 0 of base backup A. The container names its
/// backup and part, so the restore of A refuses it and never returns B's
/// bytes.
#[test]
fn f043_th51_base_part_of_another_backup_is_refused() {
    let s = setup();
    let a = vec![0xaau8; 4 * 1024 * 1024];
    let b = vec![0xbbu8; 4 * 1024 * 1024];
    let ea =
        s.rt.block_on(s.agent.base_backup_from(&mut &a[..]))
            .unwrap();
    let eb =
        s.rt.block_on(s.agent.base_backup_from(&mut &b[..]))
            .unwrap();
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    let from = s.agent.base_object(eb.backup, 0);
    let to = s.agent.base_object(ea.backup, 0);
    {
        let mut objects = s.fake.state.objects.lock().unwrap();
        let moved = objects[&from].clone();
        objects.insert(to, moved);
    }
    let mut out = Vec::new();
    let got = s.rt.block_on(s.agent.restore_base(&secret, &ea, &mut out));
    assert_eq!(got, Err(BackupError::Malformed("restored container")));
    assert!(out.is_empty(), "no byte of backup B was written");
    // Backup B itself still restores.
    let mut out = Vec::new();
    assert_eq!(
        s.rt.block_on(s.agent.restore_base(&secret, &eb, &mut out)),
        Ok(2)
    );
    assert_eq!(out, b);
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// F-043, TH-51: a bucket writer stores the container of WAL segment 4
/// under the name of segment 3. `restore_command` for segment 3 refuses
/// it and writes nothing.
#[test]
fn f043_th51_wal_container_under_another_segment_name_is_refused() {
    let s = setup();
    let dir = s.state.join("wal");
    std::fs::create_dir_all(&dir).unwrap();
    let (n3, n4) = ("000000010000000000000003", "000000010000000000000004");
    std::fs::write(dir.join("s3"), vec![3u8; 4096]).unwrap();
    std::fs::write(dir.join("s4"), vec![4u8; 4096]).unwrap();
    s.rt.block_on(async {
        s.agent.archive(&dir.join("s3"), n3).await.unwrap();
        s.agent.archive(&dir.join("s4"), n4).await.unwrap();
    });
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    {
        let mut objects = s.fake.state.objects.lock().unwrap();
        let moved = objects[&s.agent.wal_object(n4)].clone();
        objects.insert(s.agent.wal_object(n3), moved);
    }
    let dest = s.state.join("restored");
    let got = s.rt.block_on(s.agent.restore_wal(&secret, n3, &dest));
    assert_eq!(got, Err(BackupError::Malformed("restored container")));
    assert!(std::fs::metadata(&dest).is_err());
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// F-043, TH-51: a party that holds the key file (public keys only, I-80)
/// and bucket write access seals a container of its own: an `FBC1`
/// container, and an `FBC2` container signed with a writer key of its
/// own. A restore refuses both, before it opens any key.
#[test]
fn f043_th51_container_from_a_public_key_holder_is_refused() {
    let s = setup();
    let key = keyfile::decode(&s.key_file).unwrap();
    let name = "000000010000000000000007";
    let old = fstp_backup::seal_container(
        &key.public_key().unwrap(),
        fstp_backup::ContainerKind::WalSegment,
        &key.group_ref(),
        0,
        b"forged WAL bytes, synthetic",
    )
    .unwrap();
    let theirs = WriterKey::generate(CLUSTER).unwrap();
    let forged = fstp_backup::seal_object(
        &key.public_key().unwrap(),
        &theirs,
        &key.group_ref(),
        &fstp_backup::ObjectIdent::Wal(name.to_owned()),
        b"forged WAL bytes, synthetic",
    )
    .unwrap();
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    let dest = s.state.join("restored");
    for (bytes, want) in [
        (old, BackupError::Malformed("magic")),
        (forged, BackupError::Malformed("writer signature")),
    ] {
        s.fake
            .state
            .objects
            .lock()
            .unwrap()
            .insert(s.agent.wal_object(name), bytes);
        let got = s.rt.block_on(s.agent.restore_wal(&secret, name, &dest));
        assert_eq!(got, Err(want));
        assert!(std::fs::metadata(&dest).is_err());
    }
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// F-043: the last flag stands on the last part, also when the stream is
/// a whole number of parts long, and a dropped last part is refused.
#[test]
fn f043_last_part_is_flagged_for_every_stream_length() {
    let s = setup();
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    let part = SMALL.base_part;
    for (len, parts) in [(0, 1), (1, 1), (part, 1), (part + 1, 2), (2 * part, 2)] {
        let base: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let e =
            s.rt.block_on(s.agent.base_backup_from(&mut &base[..]))
                .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            s.rt.block_on(s.agent.restore_base(&secret, &e, &mut out)),
            Ok(parts),
            "{len}"
        );
        assert_eq!(out, base, "{len}");
        for p in 0..parts {
            let (_, last) =
                s.rt.block_on(s.agent.fetch_base_part(&secret, e.backup, p))
                    .unwrap()
                    .unwrap();
            assert_eq!(last, p + 1 == parts, "{len} part {p}");
        }
        if parts == 2 {
            // Without its last part the backup does not restore, even when
            // the index claims the size of the first part alone.
            s.fake
                .state
                .objects
                .lock()
                .unwrap()
                .remove(&s.agent.base_object(e.backup, 1));
            let short = fstp_backup::index::IndexEntry {
                size: part as u64,
                ..e
            };
            assert!(
                s.rt.block_on(s.agent.restore_base(&secret, &short, &mut Vec::new()))
                    .is_err()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// A client of `fake` that signs with a wrong secret, so every request
/// fails: a store that is down or refuses.
fn broken_client(rt: &TokioRuntime, fake: &FakeS3) -> S3Client<TokioRuntime> {
    S3Client::with_tls(
        rt.clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, "wrong/secret").unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    )
}

/// An agent of `s` over the stores `stores`, in order.
fn agent_over(s: &Setup, mut stores: Vec<S3Client<TokioRuntime>>) -> Agent<TokioRuntime> {
    let first = stores.remove(0);
    Agent::new(first, CLUSTER, &s.key_file, Some(&s.writer_key), &s.state)
        .unwrap()
        .with_limits(SMALL)
        .with_stores(stores)
}

/// Q25, ADR-012 "Copies and the second provider": with two stores, every
/// WAL file and every base backup part goes to both with the same bytes,
/// and the index line is written once both hold every part.
#[test]
fn q25_every_store_gets_the_same_bytes() {
    let s = setup();
    let second = FakeS3::start(&s.rt, AK, SK, REGION, BUCKET);
    let agent = agent_over(&s, vec![client(&s.rt, &s.fake), client(&s.rt, &second)]);
    let dir = temp_dir("wal");
    std::fs::write(dir.join("s"), vec![5u8; 70_000]).unwrap();
    let base = vec![6u8; 7 * 1024 * 1024];
    let entry = s.rt.block_on(async {
        agent
            .archive(&dir.join("s"), "000000010000000000000009")
            .await
            .unwrap();
        agent.base_backup_from(&mut &base[..]).await.unwrap()
    });
    let a = s.fake.state.objects.lock().unwrap().clone();
    let b = second.state.objects.lock().unwrap().clone();
    assert_eq!(a.len(), 1 + 3);
    assert_eq!(a, b, "the same objects with the same bytes");
    assert_eq!(
        fstp_backup::index::newest(&s.state, CLUSTER).unwrap(),
        entry
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    second.stop(&s.rt);
    s.fake.stop(&s.rt);
}

/// Q25, ADR-012 record of lane m10/backup-format "Fetch from the
/// stores": a restore takes the first copy that verifies. A missing,
/// refused or unreachable first store falls through to the second. A
/// file missing everywhere is absent, and a refused copy with no good
/// one is an error, never the end of the archive.
#[test]
fn q25_fetch_falls_through_to_the_next_store() {
    let s = setup();
    let second = FakeS3::start(&s.rt, AK, SK, REGION, BUCKET);
    let agent = agent_over(&s, vec![client(&s.rt, &s.fake), client(&s.rt, &second)]);
    let dir = temp_dir("wal");
    let (n1, n2) = ("000000010000000000000001", "000000010000000000000002");
    std::fs::write(dir.join("s1"), vec![1u8; 5000]).unwrap();
    std::fs::write(dir.join("s2"), vec![2u8; 5000]).unwrap();
    let secret = s.rt.block_on(async {
        agent.archive(&dir.join("s1"), n1).await.unwrap();
        agent.archive(&dir.join("s2"), n2).await.unwrap();
        agent.open_secret(&s.custody).await.unwrap()
    });
    let fetch = |a: &Agent<TokioRuntime>, n: &str| s.rt.block_on(a.fetch_wal(&secret, n));
    // Missing in the first store.
    s.fake
        .state
        .objects
        .lock()
        .unwrap()
        .remove(&agent.wal_object(n1));
    assert_eq!(fetch(&agent, n1).unwrap().unwrap(), vec![1u8; 5000]);
    // A copy in the first store that names another segment.
    {
        let mut objects = s.fake.state.objects.lock().unwrap();
        let moved = objects[&agent.wal_object(n2)].clone();
        objects.insert(agent.wal_object(n1), moved);
    }
    assert_eq!(fetch(&agent, n1).unwrap().unwrap(), vec![1u8; 5000]);
    // The first store refuses every request.
    let down = agent_over(
        &s,
        vec![broken_client(&s.rt, &s.fake), client(&s.rt, &second)],
    );
    assert_eq!(fetch(&down, n2).unwrap().unwrap(), vec![2u8; 5000]);
    // Missing everywhere: absent, also with one store down.
    assert_eq!(fetch(&agent, "000000010000000000000003").unwrap(), None);
    assert_eq!(fetch(&down, "000000010000000000000003").unwrap(), None);
    // A refused copy and no good one: an error.
    second
        .state
        .objects
        .lock()
        .unwrap()
        .remove(&agent.wal_object(n1));
    assert_eq!(
        fetch(&agent, n1),
        Err(BackupError::Malformed("restored container"))
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    second.stop(&s.rt);
    s.fake.stop(&s.rt);
}

/// Q25, ADR-012 "A container counts as backed up only when every
/// configured copy is complete": a WAL file that one store refuses is not
/// archived, so PostgreSQL keeps it and retries. The retry uploads only
/// to the store that lacks it. A base backup that one store refuses
/// writes no index line.
#[test]
fn q25_archive_succeeds_only_when_every_store_holds_it() {
    let s = setup();
    let second = FakeS3::start(&s.rt, AK, SK, REGION, BUCKET);
    let failing = agent_over(
        &s,
        vec![client(&s.rt, &s.fake), broken_client(&s.rt, &second)],
    );
    let dir = temp_dir("wal");
    let name = "00000001000000000000000A";
    std::fs::write(dir.join("s"), vec![7u8; 5000]).unwrap();
    assert!(
        s.rt.block_on(failing.archive(&dir.join("s"), name))
            .is_err()
    );
    assert!(
        s.rt.block_on(failing.base_backup_from(&mut &[1u8; 10][..]))
            .is_err()
    );
    assert!(fstp_backup::index::newest(&s.state, CLUSTER).is_err());
    let healthy = agent_over(&s, vec![client(&s.rt, &s.fake), client(&s.rt, &second)]);
    let first_copy = s.fake.state.objects.lock().unwrap()[&healthy.wal_object(name)].clone();
    assert_eq!(
        s.rt.block_on(healthy.archive(&dir.join("s"), name))
            .unwrap(),
        fstp_backup::agent::Archived::Uploaded
    );
    assert_eq!(
        s.fake.state.objects.lock().unwrap()[&healthy.wal_object(name)],
        first_copy,
        "the store that held it is not written again"
    );
    assert!(
        second
            .state
            .objects
            .lock()
            .unwrap()
            .contains_key(&healthy.wal_object(name))
    );
    assert_eq!(
        s.rt.block_on(healthy.archive(&dir.join("s"), name))
            .unwrap(),
        fstp_backup::agent::Archived::Present
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    second.stop(&s.rt);
    s.fake.stop(&s.rt);
}

/// A synthetic base backup tar stream whose first member is a
/// `backup_label` naming the start segment `start`, then `len` bytes.
fn tar_stream(start: &str, len: usize) -> Vec<u8> {
    let label =
        format!("START WAL LOCATION: 0/1000028 (file {start})\nCHECKPOINT LOCATION: 0/1000060\n");
    let mut out = fstp_backup::tar::header("backup_label", label.len()).to_vec();
    out.extend_from_slice(label.as_bytes());
    out.resize(out.len().div_ceil(512) * 512, 0);
    out.extend((0..len).map(|i| (i % 253) as u8));
    out
}

/// Sets the time of every index line to `at[i]`, in order.
fn set_times(state: &std::path::Path, at: &[u64]) {
    let mut lines = fstp_backup::index::read_lines(state).unwrap();
    for (l, t) in lines.iter_mut().zip(at) {
        l.entry.at = *t;
    }
    fstp_backup::index::rewrite(state, &lines).unwrap();
}

const DAY: u64 = 86_400;
const T0: u64 = 1_800_000_000;

/// ADR-012 record of lane m10/backup-format "Prune rule": with 35 days
/// and at least 5 backups, nothing younger than 35 days goes, the newest
/// 5 always stay, and the newest one stays whatever the values. Pruned
/// lines leave the index, and their parts leave the store.
#[test]
fn adr012_prune_keeps_the_newest_and_the_minimum() {
    let s = setup();
    let mut entries = Vec::new();
    for i in 0..7u8 {
        let e =
            s.rt.block_on(s.agent.base_backup_from(&mut &vec![i; 4 * 1024 * 1024][..]))
                .unwrap();
        entries.push(e);
    }
    let at: Vec<u64> = (0..7).map(|i| T0 + i * DAY).collect();
    set_times(&s.state, &at);
    let keep = fstp_backup::config::Retention {
        keep_days: 35,
        keep_min: 5,
    };
    // Day 30 after the first: everything is younger than 35 days.
    let p = s.rt.block_on(s.agent.prune(&keep, T0 + 30 * DAY)).unwrap();
    assert_eq!((p.removed, p.held, p.kept), (0, 0, 7));
    // Day 100: all are old, so the newest 5 stay.
    let p = s.rt.block_on(s.agent.prune(&keep, T0 + 100 * DAY)).unwrap();
    assert_eq!((p.removed, p.held, p.kept), (2, 0, 5));
    let left: Vec<[u8; 16]> = fstp_backup::index::read_lines(&s.state)
        .unwrap()
        .iter()
        .map(|l| l.entry.backup)
        .collect();
    let want: Vec<[u8; 16]> = entries[2..].iter().map(|e| e.backup).collect();
    assert_eq!(left, want);
    let objects = s.fake.state.objects.lock().unwrap().clone();
    for (i, e) in entries.iter().enumerate() {
        for p in 0..2 {
            assert_eq!(
                objects.contains_key(&s.agent.base_object(e.backup, p)),
                i >= 2,
                "backup {i} part {p}"
            );
        }
    }
    // keep_min 1 and keep_days 1: only the newest stays.
    let one = fstp_backup::config::Retention {
        keep_days: 1,
        keep_min: 1,
    };
    let p = s.rt.block_on(s.agent.prune(&one, T0 + 100 * DAY)).unwrap();
    assert_eq!((p.removed, p.kept), (4, 1));
    let newest = fstp_backup::index::newest(&s.state, CLUSTER).unwrap();
    assert_eq!(newest.backup, entries[6].backup);
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    assert_eq!(
        s.rt.block_on(s.agent.restore_base(&secret, &newest, &mut Vec::new())),
        Ok(2)
    );
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}

/// ADR-012 record of lane m10/backup-format "Prune rule": a pruned base
/// backup takes its WAL with it, from its start segment up to the next
/// backup's start segment, in every store. The kept backup's WAL and the
/// timeline history file stay, and a backup with no known start segment
/// leaves the WAL alone.
#[test]
fn adr012_prune_deletes_parts_and_wal_of_old_backups() {
    let s = setup();
    let second = FakeS3::start(&s.rt, AK, SK, REGION, BUCKET);
    let agent = agent_over(&s, vec![client(&s.rt, &s.fake), client(&s.rt, &second)]);
    let dir = temp_dir("wal");
    std::fs::write(dir.join("w"), vec![9u8; 4096]).unwrap();
    std::fs::write(dir.join("h"), b"1\t0/3000000\tno recovery target\n").unwrap();
    let names: Vec<String> = (1..=8u64)
        .map(|n| format!("0000000100000000{n:08X}"))
        .collect();
    s.rt.block_on(async {
        for n in &names {
            agent.archive(&dir.join("w"), n).await.unwrap();
        }
        agent
            .archive(&dir.join("h"), "00000002.history")
            .await
            .unwrap();
        // Backup A starts at segment 2, B at segment 5, C has no label.
        agent
            .base_backup_from(&mut &tar_stream(&names[1], 1000)[..])
            .await
            .unwrap();
        agent
            .base_backup_from(&mut &tar_stream(&names[4], 1000)[..])
            .await
            .unwrap();
        agent.base_backup_from(&mut &[7u8; 3000][..]).await.unwrap();
    });
    let lines = fstp_backup::index::read_lines(&s.state).unwrap();
    assert_eq!(lines[0].start.unwrap().file_name(), names[1]);
    assert_eq!(lines[1].start.unwrap().file_name(), names[4]);
    assert_eq!((lines[1].parts, lines[2].start), (Some(1), None));
    set_times(&s.state, &[T0, T0 + DAY, T0 + 2 * DAY]);
    let keep = fstp_backup::config::Retention {
        keep_days: 1,
        keep_min: 1,
    };
    let p = s.rt.block_on(agent.prune(&keep, T0 + 50 * DAY)).unwrap();
    assert_eq!((p.removed, p.held, p.kept), (2, 0, 1));
    for store in [&s.fake, &second] {
        let objects = store.state.objects.lock().unwrap().clone();
        for (i, n) in names.iter().enumerate() {
            // Segments 2 to 4 belonged to A only. Segment 1 is older than
            // every backup the index knows. B has no next start segment
            // that is known, since C has none, so its WAL stays.
            let gone = (1..4).contains(&i);
            assert_eq!(!objects.contains_key(&agent.wal_object(n)), gone, "{n}");
        }
        assert!(objects.contains_key(&agent.wal_object("00000002.history")));
        for l in &lines[..2] {
            assert!(!objects.contains_key(&agent.base_object(l.entry.backup, 0)));
        }
        assert!(objects.contains_key(&agent.base_object(lines[2].entry.backup, 0)));
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
    second.stop(&s.rt);
    s.fake.stop(&s.rt);
}

/// ADR-012 record of lane m10/backup-format "Index after pruning": an
/// object a store holds under an object lock is no failure. Its backup's
/// line stays, so the next prune tries again, and goes once the lock
/// ends. A prune never touches the newest backup.
#[test]
fn adr012_held_delete_keeps_the_index_line() {
    let s = setup();
    let a =
        s.rt.block_on(s.agent.base_backup_from(&mut &[1u8; 10][..]))
            .unwrap();
    let b =
        s.rt.block_on(s.agent.base_backup_from(&mut &[2u8; 10][..]))
            .unwrap();
    set_times(&s.state, &[T0, T0 + DAY]);
    let locked = s.agent.base_object(a.backup, 0);
    s.fake.state.locked.lock().unwrap().insert(locked.clone());
    let keep = fstp_backup::config::Retention {
        keep_days: 1,
        keep_min: 1,
    };
    let p = s.rt.block_on(s.agent.prune(&keep, T0 + 50 * DAY)).unwrap();
    assert_eq!((p.removed, p.held, p.kept), (0, 1, 1));
    assert_eq!(fstp_backup::index::read_lines(&s.state).unwrap().len(), 2);
    assert!(s.fake.state.objects.lock().unwrap().contains_key(&locked));
    s.fake.state.locked.lock().unwrap().clear();
    let p = s.rt.block_on(s.agent.prune(&keep, T0 + 50 * DAY)).unwrap();
    assert_eq!((p.removed, p.held, p.kept), (1, 0, 1));
    let lines = fstp_backup::index::read_lines(&s.state).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].entry.backup, b.backup);
    assert!(
        !s.fake
            .state
            .deletes
            .lock()
            .unwrap()
            .iter()
            .any(|k| k.contains(&fstp_backup::sigv4::hex(&b.backup)))
    );
    let _ = std::fs::remove_dir_all(&s.state);
    s.fake.stop(&s.rt);
}
