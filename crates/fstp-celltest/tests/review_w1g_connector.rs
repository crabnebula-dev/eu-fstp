//! Review reproducer for lane W1g (I-38), round 2: test strength.
//!
//! Design section 14.4 defines `i38_only_egress_reaches_crabnebula_hosts`
//! as "the cell's outbound connector refuses those hosts for any other
//! caller". The lane test checks source text only. It is green now,
//! while `fstp_cell::egress::connect` is a W0 stub, so the section 20
//! checklist row reads green with its behavioural claim unchecked.
//!
//! The predicate below copies the lane test's judgment, since that test
//! is private to its binary. The reproducer fails while the copied
//! verdict is green on a stub connector. It passes once the lane test
//! also drives the connector, and so stays red on the stub or a seam.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use fstp_cell::CellError;
use fstp_cell::egress::{Destination, connect};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `shipped_sources` of `i38_egress.rs`.
fn shipped_sources() -> Vec<(String, PathBuf, String)> {
    const TEST_ONLY: [&str; 5] = [
        "fstp-celltest",
        "fstp-domain-testkit",
        "fstp-pgtest",
        "fstp-prop",
        "fstp-mc",
    ];
    let crates = workspace_root().join("crates");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&crates).unwrap() {
        let dir = e.unwrap().path();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if TEST_ONLY.contains(&name.as_str()) {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir.join("src"), &mut files);
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            out.push((name.clone(), f, text));
        }
    }
    out
}

/// The verdict of `i38_only_egress_reaches_crabnebula_hosts`: `Ok` when
/// the lane test is green.
fn only_egress_verdict() -> Result<(), String> {
    let sources = shipped_sources();
    if !sources
        .iter()
        .any(|(c, _, t)| c == "fstp-release" && t.contains("pub enum CnCall"))
    {
        return Err("the scan did not read fstp_release::egress".to_owned());
    }
    let mut offenders = Vec::new();
    for (krate, file, text) in &sources {
        for needle in ["/v1/updates", "/v1/licences"] {
            if text.contains(needle)
                && !["fstp-release", "fstp-release-svc"].contains(&krate.as_str())
            {
                offenders.push(format!("{} names {needle}", file.display()));
            }
        }
        if text.contains("CnCall") && !["fstp-release", "fstp-cell"].contains(&krate.as_str()) {
            offenders.push(format!("{} names CnCall", file.display()));
        }
    }
    if !offenders.is_empty() {
        return Err(format!("{offenders:?}"));
    }
    connector_refusals()
}

/// `CONNECTOR_SEAM` of `i38_egress.rs`.
const CONNECTOR_SEAM: &str = "fstp_cell::egress::connect takes no host and shows no resolved host, so the refusal of a CrabNebula host for any destination but Destination::CrabNebula(CnCall) cannot be driven (design section 14.4; lane W3a)";

/// `connector_refusals` of `i38_egress.rs`: the behavioural half, which
/// drives the connector for every destination other than
/// `Destination::CrabNebula` and stays red on the seam.
fn connector_refusals() -> Result<(), String> {
    let others = [
        Destination::AppDatabase,
        Destination::Vault,
        Destination::Custody,
        Destination::ControlPlane,
        Destination::Witness,
        Destination::KeystoreSnapshots,
    ];
    for d in others {
        if let Err(CellError::NotImplemented(op)) = connect(&d) {
            return Err(format!("{op} is NotImplemented ({d:?}): {CONNECTOR_SEAM}"));
        }
    }
    Err(CONNECTOR_SEAM.to_owned())
}

/// I-38, design section 14.4: `i38_only_egress_reaches_crabnebula_hosts`
/// must not be green while the cell's outbound connector is a stub, since
/// its design claim is that the connector refuses CrabNebula hosts for
/// any caller but `fstp_release::egress`.
#[test]
fn review_i38_only_egress_test_is_red_while_the_connector_is_a_stub() {
    let connector_is_stub = matches!(
        connect(&Destination::Witness),
        Err(CellError::NotImplemented(_))
    );
    let verdict = only_egress_verdict();
    assert!(
        !(connector_is_stub && verdict.is_ok()),
        "I-38: i38_only_egress_reaches_crabnebula_hosts is green although \
         fstp_cell::egress::connect is NotImplemented, so no connector refusal was checked"
    );
}
