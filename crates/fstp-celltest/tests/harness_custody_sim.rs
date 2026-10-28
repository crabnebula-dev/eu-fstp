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
use fstp_custody::{Aad, Chain, Custody as _, Epoch, RootLabel, SealKey, WrappedSealKey};
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

/// Wrapping needs `fstp_crypto::aead` (lane W1h), so it refuses with a
/// typed `NotImplemented` and never returns a made-up wrap.
#[test]
fn harness_custody_sim_wrap_refuses_until_the_aead_lands() {
    let sim = CustodySim::new().unwrap();
    let root = block_on(sim.create_root(label(Chain::App))).unwrap();
    let key = SealKey::from_bytes([7; 32]);
    let err = block_on(sim.wrap(&root, &key, &Aad(Vec::new()))).unwrap_err();
    assert!(format!("{err:?}").contains("NotImplemented"), "{err:?}");
    let Err(err) = block_on(sim.unwrap(&root, &WrappedSealKey(vec![1]), &Aad(Vec::new()))) else {
        panic!("unwrap returned a key");
    };
    assert!(format!("{err:?}").contains("NotImplemented"), "{err:?}");
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
