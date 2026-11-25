//! The copy of the local witness store (ADR-012 record of lane
//! m10/witness-copy, decided by Daniel on 2026-11-24: backup is mission
//! critical), against the in-process fake S3 of lane L10.
//!
//! The store files here are framed as `fstp_witness::file_store` frames
//! them, `be64(seq) || be32(len) || bytes`, with synthetic record bytes.
//! The archiver reads only that framing, so the record content does not
//! matter to it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fstp_backup::BackupError;
use fstp_backup::agent::{Agent, Limits};
use fstp_backup::keyfile;
use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::witness::{self, FileState, WitnessState};
use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "TESTACCESSKEY01";
const SK: &str = "test/secret+key=0123456789";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-backups";
const CLUSTER: [u8; 16] = [0x5b; 16];

/// A synthetic chain file name of the witness store.
const CHAIN: &str = "chain-0102030405060708090a0b0c0d0e0f10-1";
const REGISTRY: &str = "registry";

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(2).unwrap()
}

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-backup-wc-{what}-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
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

struct Setup {
    rt: TokioRuntime,
    stores: Vec<FakeS3>,
    custody: MemCustody,
    key_file: Vec<u8>,
    writer_key: Vec<u8>,
    state: PathBuf,
    store: PathBuf,
}

impl Setup {
    /// An agent over every store, with the state directory `state`.
    fn agent_at(&self, state: &Path) -> Agent<TokioRuntime> {
        let mut clients: Vec<_> = self
            .stores
            .iter()
            .map(|f| client(&self.rt, f, SK))
            .collect();
        let first = clients.remove(0);
        Agent::new(
            first,
            CLUSTER,
            &self.key_file,
            Some(&self.writer_key),
            state,
        )
        .unwrap()
        .with_limits(Limits::default())
        .with_stores(clients)
    }

    fn agent(&self) -> Agent<TokioRuntime> {
        self.agent_at(&self.state)
    }

    /// An agent whose last store refuses every request.
    fn agent_with_a_broken_store(&self) -> Agent<TokioRuntime> {
        let mut clients: Vec<_> = self
            .stores
            .iter()
            .map(|f| client(&self.rt, f, SK))
            .collect();
        let last = clients.len() - 1;
        clients[last] = client(&self.rt, &self.stores[last], "wrong/secret");
        let first = clients.remove(0);
        Agent::new(
            first,
            CLUSTER,
            &self.key_file,
            Some(&self.writer_key),
            &self.state,
        )
        .unwrap()
        .with_stores(clients)
    }

    fn secret(&self) -> HybridSecretKey {
        self.rt
            .block_on(self.agent().open_secret(&self.custody))
            .unwrap()
    }

    fn archive(&self) -> Result<u32, BackupError> {
        self.rt.block_on(self.agent().witness_archive(&self.store))
    }

    fn objects(&self, n: usize) -> BTreeMap<String, Vec<u8>> {
        self.stores[n]
            .state
            .objects
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.contains("/witness/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn state_file(&self) -> WitnessState {
        let bytes = std::fs::read(self.state.join(witness::STATE_FILE)).unwrap();
        witness::decode_state(&bytes).unwrap()
    }

    fn stop(self) {
        for f in &self.stores {
            f.stop(&self.rt);
        }
        let _ = std::fs::remove_dir_all(&self.state);
        let _ = std::fs::remove_dir_all(&self.store);
    }
}

fn setup(stores: usize) -> Setup {
    let rt = rt();
    let fakes: Vec<FakeS3> = (0..stores)
        .map(|_| FakeS3::start(&rt, AK, SK, REGION, BUCKET))
        .collect();
    let custody = MemCustody::default();
    let created = rt.block_on(keyfile::create(&custody, CLUSTER)).unwrap();
    Setup {
        rt,
        stores: fakes,
        custody,
        key_file: created.key_file.clone(),
        writer_key: created.writer_key.to_vec(),
        state: temp_dir("state"),
        store: temp_dir("store"),
    }
}

/// One framed record of the witness store: `be64(seq) || be32(len) ||
/// bytes`, with `len` synthetic bytes that name the sequence.
fn frame(seq: u64, len: usize) -> Vec<u8> {
    let mut out = seq.to_be_bytes().to_vec();
    out.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
    out.extend((0..len).map(|i| (seq as u8).wrapping_mul(31).wrapping_add(i as u8)));
    out
}

/// Records `from` to `to` (inclusive), each of `len` bytes.
fn records(from: u64, to: u64, len: usize) -> Vec<u8> {
    (from..=to).flat_map(|s| frame(s, len)).collect()
}

fn append(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
}

/// Writes a store of a registry with three records and one chain file
/// with two.
fn write_store(s: &Setup) {
    append(&s.store.join(REGISTRY), &records(1, 3, 90));
    append(&s.store.join(CHAIN), &records(1, 2, 300));
}

fn read_dir(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_str().unwrap().to_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

/// R-CR-01, F-043, ADR-012 record of lane m10/witness-copy, rows
/// "Container kind", "Identity" and "Object names": every copy is an
/// `FBC2` container of kind 6 whose plaintext does not show, stored under
/// `<cluster>/witness/<file>/<offset>`. A copy moved to another file or
/// another offset is refused, so a fetch never takes it.
#[test]
fn r_cr_01_f043_witness_copy_is_sealed_and_bound_to_its_file_and_offset() {
    let s = setup(1);
    write_store(&s);
    // A marker inside a record, which a sealed copy must hide.
    let marker = b"synthetic-witness-marker-0001";
    let mut rec = 4u64.to_be_bytes().to_vec();
    rec.extend_from_slice(&u32::try_from(marker.len()).unwrap().to_be_bytes());
    rec.extend_from_slice(marker);
    append(&s.store.join(REGISTRY), &rec);
    assert_eq!(s.archive().unwrap(), 2);
    let agent = s.agent();
    // Files are numbered in name order when first seen.
    let chain0 = agent.witness_object(0, 0);
    let reg0 = agent.witness_object(1, 0);
    assert_eq!(
        chain0,
        format!(
            "{}/witness/00000000/0000000000000000",
            fstp_backup::sigv4::hex(&CLUSTER)
        )
    );
    let objects = s.objects(0);
    assert_eq!(
        objects.keys().cloned().collect::<Vec<_>>(),
        vec![chain0.clone(), reg0.clone()]
    );
    for bytes in objects.values() {
        assert_eq!(&bytes[..4], b"FBC2");
        assert_eq!(bytes[7], 6, "kind 6");
        assert!(fstp_backup::decode_container(bytes).is_ok());
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "the plaintext shows"
        );
    }
    let secret = s.secret();
    let out = s.store.with_extension("fetched");
    let got = s.rt.block_on(agent.witness_fetch(&secret, &out)).unwrap();
    assert_eq!(
        got,
        vec![
            (CHAIN.to_owned(), 600 + 24),
            (REGISTRY.to_owned(), 270 + 36 + 12 + marker.len() as u64),
        ]
    );
    assert_eq!(read_dir(&out), read_dir(&s.store));
    std::fs::remove_dir_all(&out).unwrap();

    // The registry's copy under the chain file's name: refused.
    s.stores[0]
        .state
        .objects
        .lock()
        .unwrap()
        .insert(chain0.clone(), objects[&reg0].clone());
    assert!(matches!(
        s.rt.block_on(agent.witness_fetch(&secret, &out)),
        Err(BackupError::Malformed(_))
    ));
    let _ = std::fs::remove_dir_all(&out);
    // The chain file's first segment again at a later offset of the same
    // file: refused, not taken as the next segment.
    {
        let mut o = s.stores[0].state.objects.lock().unwrap();
        o.insert(chain0.clone(), objects[&chain0].clone());
        o.insert(agent.witness_object(0, 624), objects[&chain0].clone());
    }
    assert!(matches!(
        s.rt.block_on(agent.witness_fetch(&secret, &out)),
        Err(BackupError::Malformed(_))
    ));
    let _ = std::fs::remove_dir_all(&out);
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, rows "One run" and "Upload
/// to every store": each run seals the records after the copied offset
/// as one new segment per file and sends it to every store with the same
/// bytes. A run with nothing new sends nothing.
#[test]
fn adr012_wc_archive_copies_each_new_tail_once_to_every_store() {
    let s = setup(2);
    write_store(&s);
    assert_eq!(s.archive().unwrap(), 2);
    assert_eq!(s.objects(0), s.objects(1), "the same bytes in each store");
    assert_eq!(s.archive().unwrap(), 0, "nothing new");
    assert_eq!(s.objects(0).len(), 2);
    let st = s.state_file();
    assert_eq!(
        st.files,
        vec![
            FileState {
                file: 0,
                name: CHAIN.to_owned(),
                copied: 624,
                end: 624
            },
            FileState {
                file: 1,
                name: REGISTRY.to_owned(),
                copied: 306,
                end: 306
            },
        ]
    );
    append(&s.store.join(CHAIN), &records(3, 5, 300));
    assert_eq!(s.archive().unwrap(), 1);
    let agent = s.agent();
    let objects = s.objects(0);
    assert!(objects.contains_key(&agent.witness_object(0, 624)));
    assert_eq!(objects, s.objects(1));
    // A new file takes the next number.
    let other = "chain-0102030405060708090a0b0c0d0e0f10-2";
    append(&s.store.join(other), &records(1, 1, 40));
    assert_eq!(s.archive().unwrap(), 1);
    assert!(s.objects(0).contains_key(&agent.witness_object(2, 0)));
    // An empty file and a file of no valid name are not copied.
    append(
        &s.store.join("chain-0102030405060708090a0b0c0d0e0f11-1"),
        b"",
    );
    append(&s.store.join("Registry.tmp"), &records(1, 1, 5));
    assert_eq!(s.archive().unwrap(), 0);
    assert_eq!(s.state_file().files.len(), 3);
    let secret = s.secret();
    let out = s.store.with_extension("fetched");
    s.rt.block_on(agent.witness_fetch(&secret, &out)).unwrap();
    let mut want = read_dir(&s.store);
    want.retain(|k, v| witness::valid_name(k) && !v.is_empty());
    assert_eq!(read_dir(&out), want);
    let _ = std::fs::remove_dir_all(&out);
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, row "Segments": a record the
/// witness is still writing waits for the next run, so no copy ends
/// inside a record.
#[test]
fn adr012_wc_archive_copies_only_whole_records() {
    let s = setup(1);
    write_store(&s);
    let third = frame(3, 300);
    // A cut inside the third record's header, then inside its bytes.
    for cut in [5, 12, 200] {
        let path = s.store.join(CHAIN);
        let mut bytes = records(1, 2, 300);
        bytes.extend_from_slice(&third[..cut]);
        std::fs::write(&path, &bytes).unwrap();
        s.archive().unwrap();
        let st = s.state_file();
        assert_eq!(st.files[0].copied, 624, "cut at {cut}");
        assert_eq!(st.files[0].end, 624, "cut at {cut}");
    }
    append(&s.store.join(CHAIN), &third[200..]);
    assert_eq!(s.archive().unwrap(), 1);
    assert_eq!(s.state_file().files[0].copied, 936);
    s.stop();
}

/// I-24, ADR-010 open point 7, ADR-012 record of lane m10/witness-copy,
/// row "A file shorter than its copies": a store file cut below what was
/// copied stops the run with a named rule, and the copies keep the longer
/// history.
#[test]
fn i24_adr012_wc_archive_refuses_a_file_shorter_than_its_copies() {
    let s = setup(1);
    write_store(&s);
    s.archive().unwrap();
    let before = s.objects(0);
    std::fs::write(s.store.join(CHAIN), records(1, 1, 300)).unwrap();
    assert_eq!(
        s.archive(),
        Err(BackupError::Malformed(
            "witness file shorter than its copies"
        ))
    );
    assert_eq!(s.objects(0), before);
    std::fs::remove_file(s.store.join(CHAIN)).unwrap();
    assert_eq!(
        s.archive(),
        Err(BackupError::Malformed(
            "witness file shorter than its copies"
        ))
    );
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, row "Copies this host did
/// not write": without its state, the archiver refuses to number files
/// again over copies that exist, and writes nothing. On a new store it
/// writes an empty state before its first upload.
#[test]
fn adr012_wc_archive_refuses_copies_it_did_not_write() {
    let s = setup(2);
    write_store(&s);
    s.archive().unwrap();
    let before = s.objects(0);
    let other_state = temp_dir("other-state");
    let other_store = temp_dir("other-store");
    append(&other_store.join(REGISTRY), &records(1, 1, 17));
    let got =
        s.rt.block_on(s.agent_at(&other_state).witness_archive(&other_store));
    assert_eq!(got, Err(BackupError::WitnessForeign));
    assert!(!other_state.join(witness::STATE_FILE).exists());
    assert_eq!(s.objects(0), before);
    assert_eq!(s.objects(1), before);
    // The copies in the second store only are enough to refuse.
    s.stores[0].state.objects.lock().unwrap().clear();
    let got =
        s.rt.block_on(s.agent_at(&other_state).witness_archive(&other_store));
    assert_eq!(got, Err(BackupError::WitnessForeign));
    let _ = std::fs::remove_dir_all(&other_state);
    let _ = std::fs::remove_dir_all(&other_store);
    s.stop();

    let s = setup(1);
    assert_eq!(s.archive().unwrap(), 0);
    assert_eq!(
        std::fs::read(s.state.join(witness::STATE_FILE)).unwrap(),
        b"v1\n"
    );
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, rows "One run" and
/// "Overwrite": a segment whose upload failed in one store is sent again
/// with exactly its bounds, so every store ends with the same segment
/// boundaries, and the records written since go in the next segment.
#[test]
fn adr012_wc_segment_in_flight_is_sent_again_with_the_same_bounds() {
    let s = setup(2);
    write_store(&s);
    s.archive().unwrap();
    append(&s.store.join(CHAIN), &records(3, 4, 300));
    let broken = s.agent_with_a_broken_store();
    assert!(s.rt.block_on(broken.witness_archive(&s.store)).is_err());
    let st = s.state_file();
    assert_eq!((st.files[0].copied, st.files[0].end), (624, 1248));
    append(&s.store.join(CHAIN), &records(5, 5, 300));
    assert_eq!(s.archive().unwrap(), 2);
    let st = s.state_file();
    assert_eq!((st.files[0].copied, st.files[0].end), (1560, 1560));
    let agent = s.agent();
    for n in 0..2 {
        let o = s.objects(n);
        assert!(o.contains_key(&agent.witness_object(0, 624)), "{n}");
        assert!(o.contains_key(&agent.witness_object(0, 1248)), "{n}");
    }
    let secret = s.secret();
    let out = s.store.with_extension("fetched");
    let got = s.rt.block_on(agent.witness_fetch(&secret, &out)).unwrap();
    assert_eq!(got[0], (CHAIN.to_owned(), 1560));
    assert_eq!(read_dir(&out), read_dir(&s.store));
    let _ = std::fs::remove_dir_all(&out);
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, item 2 and row "Rebuild": a
/// missing store, a missing file and a file cut at a record boundary all
/// come back from the copies, and the archiver state follows the copies,
/// also on a host with no state at all.
#[test]
fn adr012_wc_restore_fills_a_missing_or_shorter_store() {
    let s = setup(1);
    write_store(&s);
    s.archive().unwrap();
    let want = read_dir(&s.store);
    let secret = s.secret();
    let agent = s.agent();

    std::fs::remove_file(s.store.join(REGISTRY)).unwrap();
    std::fs::write(s.store.join(CHAIN), records(1, 1, 300)).unwrap();
    let r =
        s.rt.block_on(agent.witness_restore(&secret, &s.store))
            .unwrap();
    assert_eq!(r.filled, vec![CHAIN.to_owned(), REGISTRY.to_owned()]);
    assert!(r.kept.is_empty());
    assert_eq!(read_dir(&s.store), want);
    assert_eq!(s.archive().unwrap(), 0, "nothing to copy again");

    // A new host: no store and no state.
    std::fs::remove_dir_all(&s.store).unwrap();
    std::fs::remove_dir_all(&s.state).unwrap();
    std::fs::create_dir_all(&s.state).unwrap();
    let r =
        s.rt.block_on(agent.witness_restore(&secret, &s.store))
            .unwrap();
    assert_eq!(r.filled.len(), 2);
    assert_eq!(read_dir(&s.store), want);
    let st = s.state_file();
    assert_eq!(
        st.files
            .iter()
            .map(|f| (f.copied, f.end))
            .collect::<Vec<_>>(),
        vec![(624, 624), (306, 306)]
    );
    assert!(!s.state.join("witness-fetch").exists(), "scratch removed");
    append(&s.store.join(REGISTRY), &records(4, 4, 90));
    assert_eq!(s.archive().unwrap(), 1, "the copy resumes");

    // No copies at all: nothing changes.
    let empty = setup(1);
    write_store(&empty);
    let before = read_dir(&empty.store);
    let secret = empty.secret();
    let r = empty
        .rt
        .block_on(empty.agent().witness_restore(&secret, &empty.store))
        .unwrap();
    assert!(r.filled.is_empty() && r.kept.is_empty());
    assert_eq!(read_dir(&empty.store), before);
    empty.stop();
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, item 2: a local file longer
/// than its copy stays as it is, and the archiver then copies its tail.
#[test]
fn adr012_wc_restore_never_shortens_a_longer_store() {
    let s = setup(1);
    write_store(&s);
    s.archive().unwrap();
    append(&s.store.join(CHAIN), &records(3, 6, 300));
    let longer = read_dir(&s.store);
    let secret = s.secret();
    let r =
        s.rt.block_on(s.agent().witness_restore(&secret, &s.store))
            .unwrap();
    assert!(r.filled.is_empty());
    assert_eq!(r.kept, vec![CHAIN.to_owned(), REGISTRY.to_owned()]);
    assert_eq!(read_dir(&s.store), longer);
    assert_eq!(s.state_file().files[0].copied, 624);
    assert_eq!(s.archive().unwrap(), 1);
    assert_eq!(s.state_file().files[0].copied, 624 + 4 * 312);
    s.stop();
}

/// ADR-012 record of lane m10/witness-copy, row "Rebuild": a local file
/// that neither extends nor is extended by its copy stops the rebuild
/// with nothing changed, the files, the state and the copies alike.
#[test]
fn adr012_wc_restore_refuses_a_diverged_store_and_changes_nothing() {
    let s = setup(1);
    write_store(&s);
    s.archive().unwrap();
    // A changed byte in the chain file, and a registry cut short, which
    // alone would be filled.
    let mut chain = std::fs::read(s.store.join(CHAIN)).unwrap();
    chain[40] ^= 1;
    std::fs::write(s.store.join(CHAIN), &chain).unwrap();
    std::fs::write(s.store.join(REGISTRY), records(1, 1, 90)).unwrap();
    let before = read_dir(&s.store);
    let state = std::fs::read(s.state.join(witness::STATE_FILE)).unwrap();
    let objects = s.objects(0);
    let secret = s.secret();
    let got = s.rt.block_on(s.agent().witness_restore(&secret, &s.store));
    assert_eq!(got.unwrap_err(), BackupError::WitnessDiverged);
    assert_eq!(read_dir(&s.store), before);
    assert_eq!(
        std::fs::read(s.state.join(witness::STATE_FILE)).unwrap(),
        state
    );
    assert_eq!(s.objects(0), objects);
    assert!(!s.state.join("witness-fetch").exists(), "scratch removed");
    s.stop();
}

/// Q25, ADR-012 record of lane m10/witness-copy, row "Fetch": a segment
/// missing or refused in the first store comes from the next one. When no
/// store holds the first segment of file 0, there are no copies.
#[test]
fn adr012_wc_fetch_falls_through_to_the_next_store() {
    let s = setup(2);
    write_store(&s);
    s.archive().unwrap();
    append(&s.store.join(CHAIN), &records(3, 3, 300));
    s.archive().unwrap();
    let agent = s.agent();
    let secret = s.secret();
    {
        let mut o = s.stores[0].state.objects.lock().unwrap();
        o.remove(&agent.witness_object(0, 624));
        let other = o[&agent.witness_object(1, 0)].clone();
        o.insert(agent.witness_object(0, 0), other);
    }
    let out = s.store.with_extension("fetched");
    s.rt.block_on(agent.witness_fetch(&secret, &out)).unwrap();
    assert_eq!(read_dir(&out), read_dir(&s.store));
    std::fs::remove_dir_all(&out).unwrap();
    for f in &s.stores {
        f.state
            .objects
            .lock()
            .unwrap()
            .remove(&agent.witness_object(0, 0));
    }
    let got = s.rt.block_on(agent.witness_fetch(&secret, &out)).unwrap();
    assert!(got.is_empty());
    assert!(read_dir(&out).is_empty());
    // The output directory must be new or empty.
    std::fs::write(out.join("left"), b"x").unwrap();
    assert!(s.rt.block_on(agent.witness_fetch(&secret, &out)).is_err());
    let _ = std::fs::remove_dir_all(&out);
    s.stop();
}

/// ADR-010 "Witnesses", ADR-012 record of lane m10/witness-copy, row
/// "Retention": pruning old base backups never deletes a witness copy.
#[test]
fn adr012_wc_prune_never_touches_witness_copies() {
    let s = setup(1);
    write_store(&s);
    s.archive().unwrap();
    let agent = s.agent();
    for i in 0..3u8 {
        s.rt.block_on(agent.base_backup_from(&mut &vec![i; 1024][..]))
            .unwrap();
    }
    let witness = s.objects(0);
    let keep = fstp_backup::config::Retention {
        keep_days: 1,
        keep_min: 1,
    };
    let p = s.rt.block_on(agent.prune(&keep, 4_000_000_000)).unwrap();
    assert_eq!(p.removed, 2);
    assert_eq!(s.objects(0), witness);
    s.stop();
}
