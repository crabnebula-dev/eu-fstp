//! The S3 client and the agent against an in-process fake S3 that checks
//! every SigV4 signature on its own (ADR-012 record of lane L10, R-CR-01,
//! I-81, I-80, R-NF-02). AWS's published SigV4 vectors are not in the
//! repository, so the fake's own verifier is the reference
//! (`support/fake_s3.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::path::PathBuf;

use fstp_backup::agent::{Agent, Archived, Limits};
use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::xml::S3Code;
use fstp_backup::{BackupError, index, keyfile};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "TESTACCESSKEY01";
const SK: &str = "test/secret+key=0123456789";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-backups";
const CLUSTER: [u8; 16] = [0x5a; 16];

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(2).unwrap()
}

fn client(rt: &TokioRuntime, fake: &FakeS3, secret: &str) -> S3Client<TokioRuntime> {
    S3Client::with_tls(
        rt.clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, secret).unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    )
}

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-backup-{what}-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Small sizes, so the multipart path runs on small inputs.
const SMALL: Limits = Limits {
    base_part: 3 * 1024 * 1024 + 7,
    single_put_max: 1024 * 1024,
    upload_part: 700 * 1024,
};

struct Setup {
    rt: TokioRuntime,
    fake: FakeS3,
    custody: MemCustody,
    agent: Agent<TokioRuntime>,
    state: PathBuf,
    key_file: Vec<u8>,
}

fn setup() -> Setup {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let created = rt.block_on(keyfile::create(&custody, CLUSTER)).unwrap();
    let key_file = created.key_file.clone();
    let state = temp_dir("state");
    let agent = Agent::new(
        client(&rt, &fake, SK),
        CLUSTER,
        &key_file,
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
        key_file,
    }
}

/// A synthetic plaintext of `n` bytes in which `canary` recurs.
fn plaintext(n: usize, canary: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut i = 0u32;
    while v.len() < n {
        v.extend_from_slice(canary);
        v.extend_from_slice(&i.to_be_bytes());
        i += 1;
    }
    v.truncate(n);
    v
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// ADR-012 "S3 subset": every call of the subset is signed, the fake's
/// own verifier accepts each signature and payload hash, objects round
/// trip through `PutObject` and the multipart calls, and a missing
/// object is `None`.
#[test]
fn adr012_s3_client_signs_every_request_the_fake_verifies() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let c = client(&rt, &fake, SK);
    rt.block_on(async {
        c.put_object("c/wal/000000010000000000000001", b"one".to_vec())
            .await
            .unwrap();
        assert_eq!(
            c.get_object("c/wal/000000010000000000000001")
                .await
                .unwrap(),
            Some(b"one".to_vec())
        );
        assert!(
            c.head_object("c/wal/000000010000000000000001")
                .await
                .unwrap()
        );
        assert!(
            !c.head_object("c/wal/000000010000000000000002")
                .await
                .unwrap()
        );
        assert_eq!(
            c.get_object("c/wal/000000010000000000000002")
                .await
                .unwrap(),
            None
        );
        let big: Vec<u8> = (0..2_500_000u32).map(|i| i as u8).collect();
        c.store("c/base/ab/0", big.clone(), 1024 * 1024, 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(c.get_object("c/base/ab/0").await.unwrap(), Some(big));
    });
    let s = &fake.state;
    assert_eq!(*s.bad_signatures.lock().unwrap(), 0);
    let reqs = s.requests.lock().unwrap().clone();
    assert!(
        reqs.iter()
            .any(|(m, q)| m == "POST" && q.ends_with("?uploads="))
    );
    assert_eq!(
        reqs.iter()
            .filter(|(m, q)| m == "PUT" && q.contains("partNumber="))
            .count(),
        3
    );
    assert!(s.violations.lock().unwrap().is_empty());
    fake.stop(&rt);
}

/// ADR-012: the fake's verifier has teeth. A wrong secret and a wrong
/// region are refused as `SignatureDoesNotMatch`, so the passing test
/// above means the signatures verify.
#[test]
fn adr012_sigv4_wrong_secret_or_region_is_refused() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let wrong = client(&rt, &fake, "another-secret");
    let e = rt
        .block_on(wrong.put_object("c/wal/000000010000000000000001", b"x".to_vec()))
        .unwrap_err();
    assert_eq!(e, BackupError::S3Refused(S3Code::SignatureDoesNotMatch));
    let other_region = S3Client::with_tls(
        rt.clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: "sbg".to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, SK).unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    );
    assert!(rt.block_on(other_region.get_object("c/x")).is_err());
    assert_eq!(*fake.state.bad_signatures.lock().unwrap(), 2);
    assert!(fake.state.objects.lock().unwrap().is_empty());
    fake.stop(&rt);
}

/// ADR-012: an error document under status 200 fails the completion,
/// and the failed multipart upload is aborted. No object is deleted.
#[test]
fn adr012_failed_multipart_upload_is_aborted() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let c = client(&rt, &fake, SK);
    *fake.state.fail_next_complete.lock().unwrap() = true;
    let e = rt
        .block_on(c.store("c/base/ab/0", vec![1; 3_000_000], 1_000_000, 1_000_000))
        .unwrap_err();
    assert_eq!(e, BackupError::S3Refused(S3Code::InternalError));
    assert_eq!(fake.state.open_uploads(), 0);
    assert!(fake.state.objects.lock().unwrap().is_empty());
    assert!(fake.state.violations.lock().unwrap().is_empty());
    fake.stop(&rt);
}

/// R-CR-01, ADR-012: a WAL segment and a multipart base backup leave the
/// client sealed. No request body and no stored object holds the
/// plaintext canary, and each opens back to its plaintext under the
/// group secret, which custody opens.
#[test]
fn r_cr_01_backup_objects_hold_no_plaintext() {
    let s = setup();
    let canary = b"PLAINTEXT-CANARY-ROW-7c41e2";
    let wal_dir = temp_dir("wal");
    let wal = plaintext(1024 * 1024, canary);
    std::fs::write(wal_dir.join("seg"), &wal).unwrap();
    let base = plaintext(7 * 1024 * 1024 + 11, canary);
    let (archived, entry) = s.rt.block_on(async {
        let a = s
            .agent
            .archive(&wal_dir.join("seg"), "000000010000000000000003")
            .await
            .unwrap();
        let e = s.agent.base_backup_from(&mut &base[..]).await.unwrap();
        (a, e)
    });
    assert_eq!(archived, Archived::Uploaded);
    assert_eq!(entry.size, base.len() as u64);
    assert_eq!(index::newest(&s.state, CLUSTER).unwrap(), entry);
    let objects = s.fake.state.objects.lock().unwrap().clone();
    assert_eq!(objects.len(), 1 + 3, "one segment and three base parts");
    for (name, bytes) in &objects {
        assert!(!holds(bytes, canary), "{name}");
        assert!(fstp_backup::decode_container(bytes).is_ok(), "{name}");
    }
    for body in s.fake.state.bodies.lock().unwrap().iter() {
        assert!(!holds(body, canary));
    }
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    let mut out = Vec::new();
    let parts =
        s.rt.block_on(s.agent.restore_base(&secret, &entry, &mut out))
            .unwrap();
    assert_eq!((parts, out == base), (3, true));
    let dest = wal_dir.join("restored");
    s.rt.block_on(
        s.agent
            .restore_wal(&secret, "000000010000000000000003", &dest),
    )
    .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), wal);
    assert_eq!(*s.fake.state.bad_signatures.lock().unwrap(), 0);
    let _ = std::fs::remove_dir_all(&wal_dir);
    let _ = std::fs::remove_dir_all(&s.state);
}

/// ADR-012 record of lane L10: a file already archived is not uploaded
/// again, `.partial` and `.backup` files are skipped, a history file is
/// archived, an unknown name is refused, and a missing file restores as
/// `NotFound`.
#[test]
fn adr012_archive_dedups_skips_and_refuses() {
    let s = setup();
    let dir = temp_dir("arch");
    std::fs::write(dir.join("f"), b"segment").unwrap();
    std::fs::write(
        dir.join("h"),
        b"1\t0/3000000\tno recovery target specified\n",
    )
    .unwrap();
    s.rt.block_on(async {
        let a = &s.agent;
        let f = dir.join("f");
        assert_eq!(
            a.archive(&f, "000000010000000000000004").await.unwrap(),
            Archived::Uploaded
        );
        assert_eq!(
            a.archive(&f, "000000010000000000000004").await.unwrap(),
            Archived::Present
        );
        assert_eq!(
            a.archive(&f, "000000010000000000000004.partial")
                .await
                .unwrap(),
            Archived::Skipped
        );
        assert_eq!(
            a.archive(&f, "000000010000000000000004.00000028.backup")
                .await
                .unwrap(),
            Archived::Skipped
        );
        assert_eq!(
            a.archive(&dir.join("h"), "00000002.history").await.unwrap(),
            Archived::Uploaded
        );
        assert!(a.archive(&f, "../../etc/passwd").await.is_err());
        let secret = a.open_secret(&s.custody).await.unwrap();
        assert_eq!(
            a.restore_wal(&secret, "000000010000000000000005", &dir.join("x"))
                .await
                .unwrap_err(),
            BackupError::NotFound
        );
        a.restore_wal(&secret, "00000002.history", &dir.join("hist"))
            .await
            .unwrap();
    });
    assert_eq!(s.fake.state.objects.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&s.state);
}

/// ADR-012 "Finding the newest backup": a restore checks the parts add up
/// to the index's size, so a missing or extra part is refused.
#[test]
fn adr012_restore_checks_parts_and_size() {
    let s = setup();
    let base = vec![3u8; 4 * 1024 * 1024];
    let entry =
        s.rt.block_on(s.agent.base_backup_from(&mut &base[..]))
            .unwrap();
    let secret = s.rt.block_on(s.agent.open_secret(&s.custody)).unwrap();
    let longer = index::IndexEntry {
        size: entry.size + 1,
        ..entry
    };
    let shorter = index::IndexEntry {
        size: entry.size - 1,
        ..entry
    };
    let other = index::IndexEntry {
        backup: [9; 16],
        ..entry
    };
    for (e, want) in [
        // F-043: the last part says it is the last, so a size the parts
        // do not reach is refused without asking for another part.
        (longer, BackupError::Malformed("base backup size")),
        (shorter, BackupError::Malformed("base backup size")),
        (other, BackupError::NotFound),
    ] {
        let got =
            s.rt.block_on(s.agent.restore_base(&secret, &e, &mut Vec::new()))
                .unwrap_err();
        assert_eq!(got, want);
    }
    // A part moved under another backup's name fails the part check.
    let objects = s.fake.state.objects.lock().unwrap().clone();
    let first = s.agent.base_object(entry.backup, 0);
    let second = s.agent.base_object(entry.backup, 1);
    s.fake
        .state
        .objects
        .lock()
        .unwrap()
        .insert(second.clone(), objects[&first].clone());
    assert_eq!(
        s.rt.block_on(s.agent.restore_base(&secret, &entry, &mut Vec::new()))
            .unwrap_err(),
        BackupError::Malformed("restored container")
    );
    let _ = std::fs::remove_dir_all(&s.state);
}

/// I-81, ADR-012 "Writer": the writer holds the public key only, so the
/// key file alone opens nothing. Once the ClusterBackup root is destroyed
/// in custody, no object of any backup opens again.
#[test]
fn i81_destroyed_cluster_root_leaves_every_backup_unreadable() {
    let s = setup();
    let entry =
        s.rt.block_on(s.agent.base_backup_from(&mut &b"cluster files"[..]))
            .unwrap();
    let f = keyfile::decode(&s.key_file).unwrap();
    assert!(s.rt.block_on(keyfile::open(&s.custody, &f)).is_ok());
    s.rt.block_on(fstp_custody::Custody::destroy(&s.custody, &f.root()))
        .unwrap();
    assert_eq!(s.custody.live(), 0);
    assert_eq!(
        s.rt.block_on(s.agent.open_secret(&s.custody)).err(),
        Some(BackupError::Custody("unwrap"))
    );
    // Another group secret opens no object either.
    let other = fstp_crypto::hybrid_kem::generate().unwrap();
    let object =
        s.fake.state.objects.lock().unwrap()[&s.agent.base_object(entry.backup, 0)].clone();
    let writer = *f.writer_public().unwrap();
    assert_eq!(
        fstp_backup::open_object(&other, &writer, &object).unwrap_err(),
        BackupError::OpenFailed
    );
    let _ = std::fs::remove_dir_all(&s.state);
}

/// I-80, ADR-012 record of lane L10: the key file decodes to one
/// spelling, holds the public key and never the group secret's bytes,
/// and its secret opens only through the root.
#[test]
fn i80_key_file_holds_no_open_key() {
    let rt = rt();
    let custody = MemCustody::default();
    let created = rt.block_on(keyfile::create(&custody, CLUSTER)).unwrap();
    let bytes = created.key_file.clone();
    let f = keyfile::decode(&bytes).unwrap();
    assert_eq!(keyfile::encode(&f).unwrap(), bytes);
    assert_eq!((f.cluster, f.generation, f.epoch), (CLUSTER, 1, 1));
    let secret = rt.block_on(keyfile::open(&custody, &f)).unwrap();
    let raw = secret.to_bytes();
    assert!(!holds(&bytes, &raw[..32]));
    assert!(!holds(&bytes, &raw[raw.len() - 64..]));
    assert!(holds(&bytes, &f.public));
    let mut cut = bytes.clone();
    cut.pop();
    assert!(keyfile::decode(&cut).is_err());
    let mut long = bytes.clone();
    long.push(0);
    assert!(keyfile::decode(&long).is_err());
    let mut flipped = bytes.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let g = keyfile::decode(&flipped).unwrap();
    assert!(rt.block_on(keyfile::open(&custody, &g)).is_err());
    let err = format!("{:?}", keyfile::decode(&cut).unwrap_err());
    assert!(err.len() < 80);
    assert!(
        Agent::new(
            client(&rt, &FakeS3::start(&rt, AK, SK, REGION, BUCKET), SK),
            [1; 16],
            &bytes,
            Some(&created.writer_key),
            &std::env::temp_dir()
        )
        .is_err()
    );
}
