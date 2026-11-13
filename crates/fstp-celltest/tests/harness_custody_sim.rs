//! Self-tests of the custody simulator (M3 design sections 3.3 and 14.3,
//! lane W1a). Written by the W1a implementer. The simulator holds known
//! root bytes so the I-80 scans can look for them, so its needles must be
//! exactly the bytes it holds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::custody_sim::CustodySim;
use fstp_celltest::scan::{StoreSet, scan_bytes};
use fstp_custody::{
    Aad, Chain, Custody as _, CustodyError, Epoch, Refusal, RootLabel, SealKey, UsageCursor,
    WrappedSealKey,
};
use fstp_rt::future::block_on;

fn label(chain: Chain) -> RootLabel {
    RootLabel {
        cell: None,
        chain,
        epoch: Epoch(1),
    }
}

/// Design section 14.3: a root's bytes are the hex part of a fresh root
/// key canary, and its needle carries those bytes under the canary text.
#[test]
fn harness_custody_sim_root_bytes_are_the_root_canary_secret() {
    let sim = CustodySim::for_cell(4);
    let root = block_on(sim.create_root(label(Chain::App))).unwrap();
    let needles = sim.root_needles();
    assert_eq!(needles.len(), 1);
    let canary = Canary::parse(&needles[0].label).unwrap();
    assert_eq!((canary.cell, canary.kind), (4, CanaryKind::RootKey));
    let held = sim.with_material(&root, |m| m.expose().to_vec()).unwrap();
    assert_eq!(held, needles[0].bytes);
    assert_eq!(held, canary.secret_bytes().to_vec());
}

/// Design section 3.7: a destroyed root's material is gone, a second
/// destroy refuses, and the usage log shows both operations.
#[test]
fn harness_custody_sim_destroy_drops_the_material() {
    let sim = CustodySim::new().unwrap();
    let root = block_on(sim.create_root(label(Chain::Vault))).unwrap();
    assert_eq!(sim.roots(), 1);
    block_on(sim.destroy(&root)).unwrap();
    assert_eq!(sim.roots(), 0);
    assert!(sim.with_material(&root, |_| ()).is_none());
    assert!(block_on(sim.destroy(&root)).is_err());
    let page = block_on(sim.usage_since(&root, fstp_custody::UsageCursor::default())).unwrap();
    assert_eq!(page.operations.len(), 2, "{page:?}");
}

/// I-80 and ADR-004 part 2: the simulator wraps a seal key under a root
/// with `fstp_crypto::aead` and unwraps it back. It refuses a tampered
/// wrap, a wrap under another AAD or root, and a destroyed root. Each
/// served wrap and unwrap is in the usage log. This replaces the pin
/// `harness_custody_sim_wrap_refuses_until_the_aead_lands`, retired by
/// Daniel's decision of 2026-11-13 (m3-exit-audit section 7, item 2).
#[test]
fn harness_custody_sim_wrap_round_trips_and_refuses_a_tampered_wrap() {
    let sim = CustodySim::new().unwrap();
    let root = block_on(sim.create_root(label(Chain::App))).unwrap();
    let other = block_on(sim.create_root(label(Chain::Vault))).unwrap();
    let aad = Aad(b"cell 0 app epoch 1".to_vec());
    let key = SealKey::from_bytes([7; 32]);
    let wrapped = block_on(sim.wrap(&root, &key, &aad)).unwrap();
    assert_eq!(wrapped.0.len(), 12 + 32 + 16);
    assert!(
        !wrapped.0.windows(32).any(|w| w == [7; 32]),
        "the wrap holds the key in clear"
    );
    let back = block_on(sim.unwrap(&root, &wrapped, &aad)).unwrap();
    assert_eq!(back.expose(), &[7; 32]);

    let refused = |w: &WrappedSealKey, r: &fstp_custody::RootRef, a: &Aad| match block_on(
        sim.unwrap(r, w, a),
    ) {
        Ok(_) => panic!("a tampered or misbound wrap unwrapped"),
        Err(e) => e,
    };
    let unwrap_failed = CustodyError::Refused(Refusal::UnwrapFailed);
    for at in [0, 12, wrapped.0.len() - 1] {
        let mut tampered = wrapped.0.clone();
        tampered[at] ^= 1;
        assert_eq!(
            refused(&WrappedSealKey(tampered), &root, &aad),
            unwrap_failed
        );
    }
    let short = WrappedSealKey(wrapped.0[..wrapped.0.len() - 1].to_vec());
    assert_eq!(refused(&short, &root, &aad), unwrap_failed);
    assert_eq!(refused(&wrapped, &root, &Aad(Vec::new())), unwrap_failed);
    assert_eq!(refused(&wrapped, &other, &aad), unwrap_failed);

    // Two wraps of one key differ, since each has a fresh nonce.
    let again = block_on(sim.wrap(&root, &key, &aad)).unwrap();
    assert_ne!(again.0, wrapped.0);

    // Create, two wraps and one unwrap were served and logged. Refused
    // unwraps are not.
    let page = block_on(sim.usage_since(&root, UsageCursor::default())).unwrap();
    assert_eq!(page.operations.len(), 4, "{page:?}");

    block_on(sim.destroy(&root)).unwrap();
    assert_eq!(
        refused(&wrapped, &root, &aad),
        CustodyError::Refused(Refusal::Destroyed)
    );
    let Err(err) = block_on(sim.wrap(&root, &key, &aad)) else {
        panic!("a destroyed root wrapped");
    };
    assert_eq!(err, CustodyError::Refused(Refusal::Destroyed));
}

/// Design section 3.3: `fstp-custody-sim` runs as its own process, holds
/// one App and one Vault root, and reports their needles and the address
/// of each root's material. On Linux the I-80 memory reader returns the
/// root bytes at exactly that address, and the scan finds them in the
/// region that holds it. The process also holds the hex text of each
/// root in other places, such as the canary text, so a hit anywhere else
/// would not show that the reader sees what custody holds.
#[test]
fn harness_custody_sim_process_holds_its_roots() {
    let dir = std::env::temp_dir().join(format!("fstp-custody-sim-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let needles_path = dir.join("needles");
    let mut child = Command::new(env!("CARGO_BIN_EXE_fstp-custody-sim"))
        .args(["--cell-index", "3", "--needles-out"])
        .arg(&needles_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut addresses = Vec::new();
    loop {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        if line == "ready\n" {
            break;
        }
        let hex = line.strip_prefix("root ").unwrap().trim_end();
        addresses.push(u64::from_str_radix(hex, 16).unwrap());
    }
    assert_eq!(addresses.len(), 2);
    assert!(addresses.iter().all(|a| *a != 0) && addresses[0] != addresses[1]);
    let text = std::fs::read_to_string(&needles_path).unwrap();
    let needles: Vec<fstp_celltest::scan::Needle> = text
        .lines()
        .map(|l| {
            let (label, hex) = l.split_once('\t').unwrap();
            let canary = Canary::parse(label).unwrap();
            assert_eq!((canary.cell, canary.kind), (3, CanaryKind::RootKey));
            assert_eq!(hex.len(), 64);
            fstp_celltest::scan::Needle {
                label: label.to_owned(),
                bytes: canary.secret_bytes().to_vec(),
            }
        })
        .collect();
    assert_eq!(needles.len(), 2);
    memory_holds(child.id(), &needles, &addresses);
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "linux")]
fn memory_holds(pid: u32, needles: &[fstp_celltest::scan::Needle], addresses: &[u64]) {
    let regions = fstp_celltest::procmem::read_memory(pid).unwrap();
    for (n, address) in needles.iter().zip(addresses) {
        let region = regions
            .iter()
            .find(|r| r.region.start <= *address && *address < r.region.end)
            .unwrap_or_else(|| panic!("no region read holds root {} at {address:x}", n.label));
        let offset = usize::try_from(address - region.region.start).unwrap();
        assert_eq!(
            region.bytes.get(offset..offset + n.bytes.len()),
            Some(n.bytes.as_slice()),
            "the reader does not show root {} where custody holds it",
            n.label
        );
        let mut stores = StoreSet::default();
        stores.push(format!("{:x}", region.region.start), region.bytes.clone());
        let report = scan_bytes(&stores, std::slice::from_ref(n)).unwrap();
        assert!(
            !report.is_clean(),
            "the scan misses root {} in the region that holds it",
            n.label
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn memory_holds(pid: u32, needles: &[fstp_celltest::scan::Needle], addresses: &[u64]) {
    // `/proc/<pid>/mem` is Linux only. The reader says so rather than
    // report clean memory.
    let _ = (needles, addresses, StoreSet::default(), scan_bytes);
    assert_eq!(
        fstp_celltest::procmem::read_memory(pid).unwrap_err(),
        fstp_celltest::procmem::ProcMemError::Unsupported
    );
}

/// I-80, ADR-004 part 2, lane m3/custody-decisions: `fstp-custody-sim
/// --serve` is a custody process that the production client
/// `KeydCustody` reaches over the `fstp-keyd` wire form. It creates,
/// wraps, unwraps, logs and destroys under each call's request id, and
/// refuses a tampered wrap and a destroyed root. Its report gives the
/// test the root and the seal key, which never cross the socket in a
/// response.
#[test]
fn harness_custody_sim_serves_custody_over_the_keyd_wire_form() {
    use fstp_celltest::custody_sim::report::Kind;
    use fstp_celltest::world_host::SimProcess;
    use fstp_custody::keyd::KeydCustody;
    use fstp_custody::{CellId, RequestId, with_request};

    let dir = std::env::temp_dir().join(format!("fstp-cs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let sim = SimProcess::spawn(2, &dir).unwrap();
    assert_ne!(sim.pid(), std::process::id());
    let client = KeydCustody::new(sim.socket()).unwrap();
    let label = RootLabel {
        cell: Some(CellId([0x5A; 16])),
        chain: Chain::App,
        epoch: Epoch(0),
    };
    let created = RequestId([1; 16]);
    let root = block_on(with_request(created, || client.create_root(label.clone()))).unwrap();
    // A second create of the same chain and epoch finds the root.
    let again = block_on(client.create_root(label)).unwrap();
    assert_eq!(again, root);

    let aad = Aad(b"synthetic aad".to_vec());
    let key = SealKey::from_bytes([0x3C; 32]);
    let wrapped = block_on(with_request(RequestId([2; 16]), || {
        client.wrap(&root, &key, &aad)
    }))
    .unwrap();
    let back = block_on(with_request(RequestId([3; 16]), || {
        client.unwrap(&root, &wrapped, &aad)
    }))
    .unwrap();
    assert_eq!(back.expose(), &[0x3C; 32]);
    let mut tampered = wrapped.0.clone();
    tampered[20] ^= 1;
    let Err(err) = block_on(client.unwrap(&root, &WrappedSealKey(tampered), &aad)) else {
        panic!("a tampered wrap unwrapped");
    };
    assert_eq!(err, CustodyError::Refused(Refusal::UnwrapFailed));

    // The usage log names each served call under its request id.
    let page = block_on(client.usage_since(&root, UsageCursor::default())).unwrap();
    let ids: Vec<[u8; 16]> = page
        .operations
        .iter()
        .map(|r| match fstp_custody::usage::decode_entry(r).unwrap() {
            fstp_custody::usage::UsageEntry::Record(u) => u.request.0,
            fstp_custody::usage::UsageEntry::Damaged { .. } => panic!("a damaged record"),
        })
        .collect();
    assert_eq!(ids, vec![[1; 16], [2; 16], [3; 16]]);

    block_on(with_request(RequestId([4; 16]), || client.destroy(&root))).unwrap();
    let Err(err) = block_on(client.wrap(&root, &key, &aad)) else {
        panic!("a destroyed root wrapped");
    };
    assert_eq!(err, CustodyError::Refused(Refusal::Destroyed));

    // The report: the root, the seal key it wrapped, then the destroy.
    let records = sim.records().unwrap();
    let kinds: Vec<Kind> = records.iter().map(|r| r.kind).collect();
    assert_eq!(kinds, vec![Kind::Root, Kind::Seal, Kind::Destroyed]);
    assert_eq!(records[1].bytes, [0x3C; 32]);
    let root_bytes = records[0].bytes;
    let canary = Canary::parse(&format!(
        "CNRY-2-rootkey-{}",
        String::from_utf8(root_bytes.to_vec()).unwrap()
    ));
    assert!(canary.is_some(), "the root is not a root key canary");
    assert!(
        !wrapped.0.windows(32).any(|w| w == root_bytes),
        "the root crossed the socket"
    );
    drop(sim);
    let _ = std::fs::remove_dir_all(&dir);
}
