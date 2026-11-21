//! The second custodian of the ClusterBackup chain (ADR-012 record of
//! lane L16, I-80, I-81, R-CR-01).
//!
//! Decided by Daniel on 2026-11-21: a second `fstp-keyd` on another
//! machine holds its own custody of the ClusterBackup chain, so a restore
//! works after the first host is gone. Each custody here is an in-memory
//! stand-in for one host's console socket. The object store is the fake
//! S3 that verifies every signature (`support/fake_s3.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::path::PathBuf;

use fstp_backup::agent::Agent;
use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::{BackupError, custodian, keyfile};
use fstp_custody::{Aad, Chain, Custody, Epoch, RootLabel, SealKey};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "TESTACCESSKEY01";
const SK: &str = "test/secret+key=0123456789";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-backups";
const CLUSTER: [u8; 16] = [0x6b; 16];

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

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-backup-l16-{what}-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The ceremony between host A (the group key's custody) and host B
/// (the second custodian): the group key file, B's custodian key file
/// and request, and A's escrow.
struct Ceremony {
    key_file: Vec<u8>,
    custodian_key: Vec<u8>,
    request: Vec<u8>,
    escrow: Vec<u8>,
}

fn ceremony(rt: &TokioRuntime, a: &MemCustody, b: &MemCustody) -> Ceremony {
    rt.block_on(async {
        let key_file = keyfile::create(a, CLUSTER).await.unwrap();
        let (custodian_key, request) = custodian::init(b, CLUSTER).await.unwrap();
        let key = keyfile::decode(&key_file).unwrap();
        let escrow = custodian::escrow(a, &key, &request).await.unwrap();
        Ceremony {
            key_file,
            custodian_key,
            request,
            escrow,
        }
    })
}

/// I-80, ADR-012 record of lane L16: the ceremony moves no root between
/// custodies. Each custody creates one ClusterBackup root of its own, and
/// no file of the ceremony holds the bytes of either root.
#[test]
fn i80_second_custodian_never_receives_a_root() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let c = ceremony(&rt, &a, &b);
    let expect = RootLabel {
        cell: None,
        chain: Chain::ClusterBackup,
        epoch: Epoch(1),
    };
    assert_eq!(a.labels(), vec![expect.clone()]);
    assert_eq!(b.labels(), vec![expect]);
    let roots: Vec<[u8; 32]> = a.root_bytes().into_iter().chain(b.root_bytes()).collect();
    assert_eq!(roots.len(), 2);
    for file in [&c.key_file, &c.custodian_key, &c.request, &c.escrow] {
        for r in &roots {
            assert!(!holds(file, r), "a root is in a ceremony file");
        }
    }
}

/// I-81, ADR-012 record of lane L16: the second custodian never holds a
/// chain that erasure rotates. An App epoch destroyed on host A opens
/// under nothing host B holds.
#[test]
fn i81_second_custodian_holds_no_erasable_root() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let app = rt
        .block_on(a.create_root(RootLabel {
            cell: None,
            chain: Chain::App,
            epoch: Epoch(1),
        }))
        .unwrap();
    let aad = Aad(b"app seal key".to_vec());
    let w = rt
        .block_on(a.wrap(&app, &SealKey::from_bytes([0x33; 32]), &aad))
        .unwrap();
    rt.block_on(a.destroy(&app)).unwrap();
    let c = ceremony(&rt, &a, &b);
    assert!(b.labels().iter().all(|l| l.chain == Chain::ClusterBackup));
    // Host B's one root does not open the erased epoch's wrapped key.
    let b_root = keyfile::decode_custodian(&c.custodian_key).unwrap().root();
    assert!(rt.block_on(b.unwrap(&b_root, &w, &aad)).is_err());
    assert!(rt.block_on(a.unwrap(&app, &w, &aad)).is_err());
}

/// I-80, I-81, ADR-012 record of lane L16: after the loss of host A, host
/// B restores the base backup and the WAL segment that host A wrote,
/// through its own custody, the escrow and the copy of the key file.
#[test]
fn i80_i81_host_loss_restore_from_the_second_custodian() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let c = ceremony(&rt, &a, &b);
    let wal = temp_dir("wal").join("000000010000000000000007");
    let segment: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&wal, &segment).unwrap();
    let base = b"synthetic cluster files, lane L16".repeat(1000);
    let entry = {
        let agent_a = Agent::new(client(&rt, &fake), CLUSTER, &c.key_file, &temp_dir("a")).unwrap();
        rt.block_on(agent_a.archive(&wal, "000000010000000000000007"))
            .unwrap();
        rt.block_on(agent_a.base_backup_from(&mut &base[..]))
            .unwrap()
    };
    drop(a);

    let agent_b = Agent::new(client(&rt, &fake), CLUSTER, &c.key_file, &temp_dir("b")).unwrap();
    let secret = rt
        .block_on(agent_b.open_escrow(&b, &c.custodian_key, &c.escrow))
        .unwrap();
    let mut out = Vec::new();
    rt.block_on(agent_b.restore_base(&secret, &entry, &mut out))
        .unwrap();
    assert_eq!(out, base);
    let wal_back = rt
        .block_on(agent_b.fetch_wal(&secret, "000000010000000000000007"))
        .unwrap();
    assert_eq!(wal_back, Some(segment));
    // Without host B's root nothing opens: another custody refuses.
    let other = MemCustody::default();
    assert!(
        rt.block_on(agent_b.open_escrow(&other, &c.custodian_key, &c.escrow))
            .is_err()
    );
    fake.stop(&rt);
}

/// I-80, R-CR-01, ADR-012 record of lane L16: the escrow never holds the
/// group secret in the clear, and opens only under the custodian key.
#[test]
fn i80_escrow_never_holds_the_group_secret_in_the_clear() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let c = ceremony(&rt, &a, &b);
    let key = keyfile::decode(&c.key_file).unwrap();
    let secret = rt.block_on(keyfile::open(&a, &key)).unwrap();
    let bytes = secret.to_bytes();
    for window in bytes.chunks(32) {
        assert!(
            !holds(&c.escrow, window),
            "group secret bytes in the escrow"
        );
    }
    assert!(fstp_backup::open_container(&secret, &c.escrow).is_err());
    let opened = rt
        .block_on(custodian::open(&b, &c.custodian_key, &c.escrow, &key))
        .unwrap();
    assert_eq!(opened.public().to_bytes(), key.public);
}

/// ADR-012 record of lane L16: the request and the custodian key file
/// decode in one spelling, a custodian key is never read as a group key
/// file or the reverse, and an escrow for another cluster or group is
/// refused.
#[test]
fn adr012_custodian_files_round_trip() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let c = ceremony(&rt, &a, &b);
    let req = custodian::decode_request(&c.request).unwrap();
    assert_eq!(req.cluster, CLUSTER);
    assert_eq!(custodian::encode_request(&req), c.request);
    let mut long = c.request.clone();
    long.push(0);
    assert!(custodian::decode_request(&long).is_err());
    assert!(custodian::decode_request(&c.request[..c.request.len() - 1]).is_err());

    assert!(keyfile::decode(&c.custodian_key).is_err());
    assert!(keyfile::decode_custodian(&c.key_file).is_err());
    let ck = keyfile::decode_custodian(&c.custodian_key).unwrap();
    assert_eq!(keyfile::encode(&ck).unwrap(), c.custodian_key);
    assert_eq!(ck.group, req.custodian);

    // A request of another cluster is refused by the escrow step.
    let other = custodian::Request {
        cluster: [0x01; 16],
        ..req
    };
    let key = keyfile::decode(&c.key_file).unwrap();
    assert_eq!(
        rt.block_on(custodian::escrow(
            &a,
            &key,
            &custodian::encode_request(&other)
        ))
        .unwrap_err(),
        BackupError::KeyFile("another cluster")
    );
    // An escrow checked against another group key file is refused.
    let other_key = keyfile::decode(&rt.block_on(keyfile::create(&a, CLUSTER)).unwrap()).unwrap();
    assert!(
        rt.block_on(custodian::open(&b, &c.custodian_key, &c.escrow, &other_key))
            .is_err()
    );
    assert!(custodian::decode_escrow_plain(&[0u8; 10]).is_err());
}
