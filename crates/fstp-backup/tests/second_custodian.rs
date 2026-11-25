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
use fstp_backup::snapshot::ObjectStore;
use fstp_backup::writer::WriterKey;
use fstp_backup::{BackupError, ContainerKind, GroupRef, ObjectIdent, custodian, keyfile};
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
    writer_key: Vec<u8>,
    custodian_key: Vec<u8>,
    request: Vec<u8>,
    escrow: Vec<u8>,
}

fn ceremony(rt: &TokioRuntime, a: &MemCustody, b: &MemCustody) -> Ceremony {
    rt.block_on(async {
        let created = keyfile::create(a, CLUSTER).await.unwrap();
        let key_file = created.key_file.clone();
        let writer_key = created.writer_key.to_vec();
        let (custodian_key, request) = custodian::init(b, CLUSTER).await.unwrap();
        let key = keyfile::decode(&key_file).unwrap();
        let writer = WriterKey::decode(&writer_key).unwrap();
        let escrow = custodian::escrow(a, &key, &writer, &request).await.unwrap();
        Ceremony {
            key_file,
            writer_key,
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
        let agent_a = Agent::new(
            client(&rt, &fake),
            CLUSTER,
            &c.key_file,
            Some(&c.writer_key),
            &temp_dir("a"),
        )
        .unwrap();
        rt.block_on(agent_a.archive(&wal, "000000010000000000000007"))
            .unwrap();
        rt.block_on(agent_a.base_backup_from(&mut &base[..]))
            .unwrap()
    };
    drop(a);

    let agent_b = Agent::new(
        client(&rt, &fake),
        CLUSTER,
        &c.key_file,
        None,
        &temp_dir("b"),
    )
    .unwrap();
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
            &WriterKey::decode(&c.writer_key).unwrap(),
            &custodian::encode_request(&other)
        ))
        .unwrap_err(),
        BackupError::KeyFile("another cluster")
    );
    // An escrow checked against another group key file is refused.
    let other_key =
        keyfile::decode(&rt.block_on(keyfile::create(&a, CLUSTER)).unwrap().key_file).unwrap();
    assert!(
        rt.block_on(custodian::open(&b, &c.custodian_key, &c.escrow, &other_key))
            .is_err()
    );
    assert!(custodian::decode_escrow_plain(&[0u8; 10]).is_err());
}

/// The escrow of the record of lane L16, sealed by hand as an `FBC1`
/// container of kind 4: what a ceremony before lane m10/backup-followups
/// left on the second host.
fn legacy_escrow(rt: &TokioRuntime, a: &MemCustody, key_file: &[u8], request: &[u8]) -> Vec<u8> {
    let key = keyfile::decode_kind(key_file, keyfile::FileKind::ClusterBackupV1)
        .or_else(|_| keyfile::decode(key_file))
        .unwrap();
    let req = custodian::decode_request(request).unwrap();
    let secret = rt.block_on(keyfile::open(a, &key)).unwrap();
    let mut plain = key.group.to_vec();
    plain.extend_from_slice(&key.generation.to_be_bytes());
    plain.extend_from_slice(&key.public);
    plain.extend_from_slice(&secret.to_bytes()[..]);
    let to = fstp_crypto::hybrid_kem::HybridPublicKey::from_bytes(&req.public).unwrap();
    fstp_backup::seal_container(
        &to,
        ContainerKind::CustodianEscrow,
        &GroupRef {
            owner: key.cluster,
            group: fstp_keys::GroupId(req.custodian),
            generation: 1,
        },
        0,
        &plain,
    )
    .unwrap()
}

/// F-043, ADR-012 record of lane m10/backup-followups, row "Escrow,
/// version 2": the escrow is an `FBC2` container of kind 4 that names the
/// custodian id and carries the writer key's signature. An escrow signed
/// by another key, or one made for another custodian, is refused. An
/// `FBC1` escrow made before this lane still opens.
#[test]
fn f043_escrow_is_signed_by_the_writer() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let c = ceremony(&rt, &a, &b);
    let key = keyfile::decode(&c.key_file).unwrap();
    assert_eq!(&c.escrow[..4], b"FBC2");
    assert_eq!(c.escrow[7], ContainerKind::CustodianEscrow.code());
    let req = custodian::decode_request(&c.request).unwrap();
    assert_eq!(&c.escrow[46..62], &req.custodian);
    let opened = rt
        .block_on(custodian::open(&b, &c.custodian_key, &c.escrow, &key))
        .unwrap();
    assert_eq!(opened.public().to_bytes(), key.public);
    // Signed by another writer key: refused before anything opens.
    let forger = WriterKey::generate(CLUSTER).unwrap();
    assert_eq!(
        rt.block_on(custodian::escrow(&a, &key, &forger, &c.request))
            .unwrap_err(),
        BackupError::KeyFile("writer key of another key file")
    );
    let forged = {
        let secret = rt.block_on(keyfile::open(&a, &key)).unwrap();
        let mut plain = key.group.to_vec();
        plain.extend_from_slice(&key.generation.to_be_bytes());
        plain.extend_from_slice(&key.public);
        plain.extend_from_slice(&secret.to_bytes()[..]);
        fstp_backup::seal_object(
            &fstp_crypto::hybrid_kem::HybridPublicKey::from_bytes(&req.public).unwrap(),
            &forger,
            &GroupRef {
                owner: CLUSTER,
                group: fstp_keys::GroupId(req.custodian),
                generation: 1,
            },
            &ObjectIdent::Escrow(req.custodian),
            &plain,
        )
        .unwrap()
    };
    assert_eq!(
        rt.block_on(custodian::open(&b, &c.custodian_key, &forged, &key))
            .err(),
        Some(BackupError::Malformed("writer signature"))
    );
    // An escrow for another custodian of the same custody does not name
    // this one.
    let (_, request2) = rt.block_on(custodian::init(&b, CLUSTER)).unwrap();
    let writer = WriterKey::decode(&c.writer_key).unwrap();
    let escrow2 = rt
        .block_on(custodian::escrow(&a, &key, &writer, &request2))
        .unwrap();
    assert!(
        rt.block_on(custodian::open(&b, &c.custodian_key, &escrow2, &key))
            .is_err()
    );
    // The FBC1 escrow of an earlier ceremony still opens.
    let old = legacy_escrow(&rt, &a, &c.key_file, &c.request);
    assert_eq!(&old[..4], b"FBC1");
    assert!(
        rt.block_on(custodian::open(&b, &c.custodian_key, &old, &key))
            .is_ok()
    );
}

/// The world of a key file upgrade: host A held a version 1 key file
/// when the ceremony ran, so host B holds that file and an `FBC1` escrow.
/// A then upgraded its key file and published it.
struct Upgraded {
    v1: Vec<u8>,
    v2: Vec<u8>,
    writer: Vec<u8>,
    custodian_key: Vec<u8>,
    escrow: Vec<u8>,
}

fn upgraded(rt: &TokioRuntime, a: &MemCustody, b: &MemCustody) -> Upgraded {
    let v1 = rt
        .block_on(keyfile::create_kind(
            a,
            CLUSTER,
            keyfile::FileKind::ClusterBackupV1,
        ))
        .unwrap();
    let (custodian_key, request) = rt.block_on(custodian::init(b, CLUSTER)).unwrap();
    let escrow = legacy_escrow(rt, a, &v1, &request);
    let created = rt.block_on(keyfile::upgrade(a, &v1, None)).unwrap();
    Upgraded {
        v1,
        v2: created.key_file,
        writer: created.writer_key.to_vec(),
        custodian_key,
        escrow,
    }
}

fn store_refs(stores: &[S3Client<TokioRuntime>]) -> Vec<&dyn ObjectStore> {
    stores.iter().map(|s| s as &dyn ObjectStore).collect()
}

/// F-044, I-80, ADR-012 record of lane m10/backup-followups, row "On the
/// second host": after host A upgrades its key file and publishes it,
/// host B adopts the version 2 file from the store with no operator step,
/// through its escrow, and then restores a backup that A wrote in the new
/// format. B adopts it with no local file too, and with a second store
/// whose copy is changed it falls through to the good one.
#[test]
fn f044_second_custodian_adopts_the_published_key_file() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let u = upgraded(&rt, &a, &b);
    let body = rt.block_on(custodian::publish(&a, &u.v2)).unwrap();
    let name = custodian::published_name(CLUSTER);
    assert_eq!(name, format!("{}/keys/cluster-backup.key", "6b".repeat(16)));
    fake.state
        .objects
        .lock()
        .unwrap()
        .insert(name.clone(), body.clone());
    let stores = [client(&rt, &fake)];
    let refs = store_refs(&stores);
    let adopted = rt
        .block_on(custodian::adopt_published(
            &b,
            &refs,
            CLUSTER,
            Some(&u.v1),
            &u.custodian_key,
            &u.escrow,
        ))
        .unwrap();
    assert_eq!(adopted, u.v2);
    let none = rt
        .block_on(custodian::adopt_published(
            &b,
            &refs,
            CLUSTER,
            None,
            &u.custodian_key,
            &u.escrow,
        ))
        .unwrap();
    assert_eq!(none, u.v2);
    // A backup A writes in the new format restores on B.
    let base = b"synthetic cluster files, lane m10/backup-followups".repeat(500);
    let entry = {
        let agent_a = Agent::new(
            client(&rt, &fake),
            CLUSTER,
            &u.v2,
            Some(&u.writer),
            &temp_dir("bf-a"),
        )
        .unwrap();
        rt.block_on(agent_a.base_backup_from(&mut &base[..]))
            .unwrap()
    };
    let agent_b = Agent::new(
        client(&rt, &fake),
        CLUSTER,
        &adopted,
        None,
        &temp_dir("bf-b"),
    )
    .unwrap();
    let secret = rt
        .block_on(agent_b.open_escrow(&b, &u.custodian_key, &u.escrow))
        .unwrap();
    let mut out = Vec::new();
    rt.block_on(agent_b.restore_base(&secret, &entry, &mut out))
        .unwrap();
    assert_eq!(out, base);
    // Nothing published: absent.
    fake.state.objects.lock().unwrap().remove(&name);
    assert_eq!(
        rt.block_on(custodian::adopt_published(
            &b,
            &refs,
            CLUSTER,
            Some(&u.v1),
            &u.custodian_key,
            &u.escrow,
        )),
        Err(BackupError::NotFound)
    );
    fake.stop(&rt);
}

/// F-044, TH-51, ADR-012 record of lane m10/backup-followups, row
/// "Published key file": a writer of the store who holds only the public
/// keys cannot have the second custodian adopt a key file. A copy with the
/// group public key but another writer key and a fresh binding, a copy
/// whose tag was made under another group secret, a changed byte, and a
/// copy of another group key are each refused, and so is a forged copy
/// against a version 2 escrow.
#[test]
fn f044_th51_published_key_file_with_another_writer_is_refused() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let u = upgraded(&rt, &a, &b);
    let good = rt.block_on(custodian::publish(&a, &u.v2)).unwrap();
    let (_, good_tag) = custodian::decode_published(&good).unwrap();
    let name = custodian::published_name(CLUSTER);
    let stores = [client(&rt, &fake)];
    let refs = store_refs(&stores);
    let try_with = |body: Vec<u8>, escrow: &[u8]| {
        fake.state
            .objects
            .lock()
            .unwrap()
            .insert(name.clone(), body);
        rt.block_on(custodian::adopt_published(
            &b,
            &refs,
            CLUSTER,
            Some(&u.v1),
            &u.custodian_key,
            escrow,
        ))
    };
    // The real group key, another writer key, a binding that verifies
    // under it, and the real tag copied over.
    let forger = WriterKey::generate(CLUSTER).unwrap();
    let mut f = keyfile::decode(&u.v2).unwrap();
    f.binding = Some(keyfile::Binding {
        writer: Box::new(forger.public()),
        signature: Box::new([0; fstp_backup::writer::SIGNATURE_LEN]),
    });
    let sig = forger.sign_binding(&f.aad()).unwrap();
    *f.binding.as_mut().unwrap().signature = sig;
    assert!(f.check_binding().is_ok());
    let forged = keyfile::encode(&f).unwrap();
    assert_eq!(
        try_with(
            custodian::encode_published(&forged, &good_tag).unwrap(),
            &u.escrow
        ),
        Err(BackupError::KeyFile("published key file tag"))
    );
    // The same against a version 2 escrow: its signature names the real
    // writer key.
    let request = custodian::encode_request(&custodian::Request {
        cluster: CLUSTER,
        custodian: keyfile::decode_custodian(&u.custodian_key).unwrap().group,
        public: keyfile::decode_custodian(&u.custodian_key).unwrap().public,
    });
    let escrow2 = rt
        .block_on(custodian::escrow(
            &a,
            &keyfile::decode(&u.v2).unwrap(),
            &WriterKey::decode(&u.writer).unwrap(),
            &request,
        ))
        .unwrap();
    assert_eq!(
        try_with(
            custodian::encode_published(&forged, &good_tag).unwrap(),
            &escrow2
        ),
        Err(BackupError::Malformed("writer signature"))
    );
    // A tag under another group secret.
    let other = fstp_crypto::hybrid_kem::generate().unwrap();
    let bad_tag = custodian::key_file_tag(&other, CLUSTER, &forged).unwrap();
    assert!(
        try_with(
            custodian::encode_published(&forged, &bad_tag).unwrap(),
            &u.escrow
        )
        .is_err()
    );
    // A changed byte of the good copy.
    let mut changed = good.clone();
    let i = changed.len() - 40;
    changed[i] ^= 1;
    assert!(try_with(changed, &u.escrow).is_err());
    // Another group key altogether, tagged under its own secret.
    let fresh = rt.block_on(keyfile::create(&a, CLUSTER)).unwrap();
    let own = rt
        .block_on(custodian::publish(&a, &fresh.key_file))
        .unwrap();
    assert!(try_with(own, &u.escrow).is_err());
    // The good copy is adopted.
    assert_eq!(try_with(good, &u.escrow).unwrap(), u.v2);
    fake.stop(&rt);
}

/// ADR-012 record of lane m10/backup-followups, row "Publishing": the
/// published copy decodes in one spelling and carries the version 2 key
/// file and its tag under the group secret. A version 1 key file is not
/// published. The mark names the key file by its SHA-256.
#[test]
fn adr012_publish_key_marks_the_copy() {
    let rt = rt();
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let u = upgraded(&rt, &a, &b);
    let body = rt.block_on(custodian::publish(&a, &u.v2)).unwrap();
    assert_eq!(&body[..4], b"FBK1");
    let (file, tag) = custodian::decode_published(&body).unwrap();
    assert_eq!(file, &u.v2[..]);
    assert_eq!(custodian::encode_published(file, &tag).unwrap(), body);
    let key = keyfile::decode(&u.v2).unwrap();
    let secret = rt.block_on(keyfile::open(&a, &key)).unwrap();
    assert_eq!(
        custodian::key_file_tag(&secret, CLUSTER, &u.v2).unwrap(),
        tag
    );
    for cut in [0, 4, 7, body.len() - 1] {
        assert!(custodian::decode_published(&body[..cut]).is_err(), "{cut}");
    }
    let mut long = body.clone();
    long.push(0);
    assert!(custodian::decode_published(&long).is_err());
    assert!(rt.block_on(custodian::publish(&a, &u.v1)).is_err());
    let mark = fstp_backup::published_mark(&u.v2);
    assert_eq!(mark.len(), 65);
    assert_eq!(
        mark.trim_end(),
        fstp_backup::sigv4::hex(&fstp_crypto::sha256(&u.v2))
    );
    assert_eq!(fstp_backup::PUBLISHED_MARK, "key-published");
}

/// F-044, TH-51, ADR-012 record of lane m10/key-pin-reason, row
/// "Legitimate changes": the second custodian's adoption of the published
/// key file writes the pin in the same step, with no operator step, and
/// creates the state directory when it is missing. A host with a version
/// 2 key file adopts nothing and keeps its pin.
#[test]
fn f044_th51_adoption_writes_the_pin() {
    let rt = rt();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let (a, b) = (MemCustody::default(), MemCustody::default());
    let u = upgraded(&rt, &a, &b);
    let body = rt.block_on(custodian::publish(&a, &u.v2)).unwrap();
    fake.state
        .objects
        .lock()
        .unwrap()
        .insert(custodian::published_name(CLUSTER), body);

    let creds = temp_dir("pin-adopt-creds");
    std::fs::write(creds.join("s3-access-key-id"), AK).unwrap();
    std::fs::write(creds.join("s3-secret-access-key"), SK).unwrap();
    std::fs::write(creds.join("s3-ca.pem"), fake_s3::CA_PEM).unwrap();
    std::fs::write(creds.join(keyfile::KEY_FILE), &u.v1).unwrap();
    std::fs::write(creds.join(custodian::ESCROW_FILE), &u.escrow).unwrap();
    std::fs::write(creds.join(custodian::CUSTODIAN_KEY_FILE), &u.custodian_key).unwrap();
    let state = temp_dir("pin-adopt-state").join("not-yet");
    let cfg = fstp_backup::config::FileConfig {
        cluster: CLUSTER,
        credentials_dir: creds.clone(),
        state_dir: state.clone(),
        pg_bindir: PathBuf::from("/nonexistent/pg/bin"),
        database: fstp_backup::config::DatabaseConfig {
            host: std::net::IpAddr::from([127, 0, 0, 1]),
            port: 5432,
        },
        object_store: Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        more_stores: Vec::new(),
        keyd_socket: None,
        retention: None,
    };
    fstp_backup::adopt_key_file_with(&rt, Ok(&b), &cfg).unwrap();
    assert_eq!(std::fs::read(creds.join(keyfile::KEY_FILE)).unwrap(), u.v2);
    let pin_path = state.join(fstp_backup::keypin::PIN_FILE);
    assert_eq!(
        std::fs::read(&pin_path).unwrap(),
        fstp_backup::keypin::encode(&u.v2).into_bytes()
    );
    fstp_backup::keypin::check(&state, &u.v2).unwrap();
    // Adopted once: the next restore adopts nothing, and needs no custody.
    fstp_backup::adopt_key_file_with::<MemCustody>(
        &rt,
        Err(BackupError::Config("keyd_socket")),
        &cfg,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&pin_path).unwrap(),
        fstp_backup::keypin::encode(&u.v2).into_bytes()
    );
    let _ = std::fs::remove_dir_all(&creds);
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
    fake.stop(&rt);
}
