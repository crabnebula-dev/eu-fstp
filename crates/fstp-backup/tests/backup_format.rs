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
