//! I-20: the platform stores no link between tenant accounts in different
//! tenants (design section 14.4).
//!
//! The whole-world identifier comparison is `t_iso_i20_*` in
//! `t_iso_i20.rs`. Layering rule 4 is also checked by `tools/deps-check`
//! (`i19_i20_layering_m3_rule4_control_plane_reaches_no_tenant_crate`,
//! lane W0). The test here reads the manifests on its own.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until `RelyingParty::new` (lane W2a) and the cell runtime (lane W3a)
//! land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::egress::Peer;
use fstp_celltest::mc::place_model::db;
use fstp_celltest::scan::{
    CellDump, Needle, PublicConstants, StoreSet, scan_bytes, shared_identifiers,
};
use fstp_celltest::world::{ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_prop::{Gen, prop_assert_eq};
use fstp_webauthn::{RelyingParty, WebAuthnError};

// ---------------------------------------------------------------------------
// Relying party (B11, ADR-008).

fn label(g: &mut Gen) -> String {
    let n = g.usize_in(1..=16);
    (0..n)
        .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz0123456789")))
        .collect()
}

/// I-20, B11: the relying party id of a cell is its exact host, and its
/// origin is `https://` and that host. No parent domain stands in for it.
#[test]
fn i20_rp_id_is_the_exact_cell_host() {
    fstp_prop::check("i20_rp_id_is_the_exact_cell_host", |g: &mut Gen| {
        let host = format!(
            "{}.{}.{}",
            label(g),
            label(g),
            g.pick(&["eu", "de", "fr", "test"])
        );
        #[allow(unreachable_patterns, reason = "lane W2a adds refusal variants")]
        match RelyingParty::new(&host) {
            Err(WebAuthnError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
            Err(e) => Err(format!("{host} was refused: {e:?}")),
            Ok(rp) => {
                let origin = format!("https://{host}");
                prop_assert_eq!(rp.parts(), (host.as_str(), origin.as_str()));
                Ok(())
            }
        }
    });
}

/// I-20, B11: a host with a scheme, a port, a path, a wildcard, a leading
/// or trailing dot, or no dot at all is refused, so no relying party spans
/// two cells.
#[test]
fn i20_rp_id_refuses_anything_but_a_host() {
    let mut refused = 0usize;
    let hosts = [
        "",
        "eu",
        "https://a.cell.eu",
        "a.cell.eu:443",
        "a.cell.eu/",
        "*.cell.eu",
        ".cell.eu",
        "a.cell.eu.",
    ];
    for host in hosts {
        #[allow(unreachable_patterns, reason = "lane W2a adds refusal variants")]
        match RelyingParty::new(host) {
            Ok(rp) => panic!("{host:?} gave the relying party {:?}", rp.parts()),
            Err(WebAuthnError::NotImplemented(op)) => panic!("{op} is NotImplemented"),
            Err(_) => refused += 1,
        }
    }
    assert_eq!(refused, hosts.len());
}

// ---------------------------------------------------------------------------
// Layering rule 4 (design section 2.4).

/// The control-plane crates of rule 4.
const CONTROL_PLANE: [&str; 6] = [
    "fstp-control",
    "fstp-cp-proto",
    "fstp-witness",
    "fstp-edge",
    "fstp-release",
    "fstp-release-svc",
];

/// The crates that define tenant records, account types or vault data.
const TENANT: [&str; 11] = [
    "fstp-domain",
    "fstp-engine",
    "fstp-findings",
    "fstp-auth",
    "fstp-cell-core",
    "fstp-cell",
    "fstp-pgstore",
    "fstp-vault",
    "fstp-vault-core",
    "fstp-vault-proto",
    "fstp-domain-testkit",
];

/// The `fstp-*` crates of the `[dependencies]` and `[build-dependencies]`
/// tables of a manifest.
fn deps_of(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut on = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            on = line == "[dependencies]" || line == "[build-dependencies]";
            continue;
        }
        if on
            && line.starts_with("fstp-")
            && let Some(name) = line.split(['.', ' ', '=']).next()
        {
            out.insert(name.to_owned());
        }
    }
    out
}

/// The tenant crates each control-plane crate reaches, as `crate -> path`.
fn rule4_breaches(manifests: &BTreeMap<String, String>) -> Vec<String> {
    let deps: BTreeMap<&str, BTreeSet<String>> = manifests
        .iter()
        .map(|(k, v)| (k.as_str(), deps_of(v)))
        .collect();
    let mut out = Vec::new();
    for start in CONTROL_PLANE {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut todo = vec![(start.to_owned(), start.to_owned())];
        while let Some((n, path)) = todo.pop() {
            if seen.contains_key(&n) {
                continue;
            }
            seen.insert(n.clone(), path.clone());
            for d in deps.get(n.as_str()).into_iter().flatten() {
                todo.push((d.clone(), format!("{path} -> {d}")));
            }
        }
        for (n, path) in seen {
            if TENANT.contains(&n.as_str()) {
                out.push(path);
            }
        }
    }
    out
}

fn workspace_manifests() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(db::workspace_root().join("crates")).unwrap() {
        let p = e.unwrap().path().join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&p) {
            let name = p
                .parent()
                .and_then(|d| d.file_name())
                .unwrap()
                .to_string_lossy()
                .into_owned();
            out.insert(name, text);
        }
    }
    out
}

/// I-20, I-19, layering rule 4: no control-plane crate reaches a crate
/// that defines tenant records, account types or vault data, directly or
/// through another crate. Their sources do not name `AccountId`.
#[test]
fn i20_control_plane_crates_cannot_name_account_types() {
    let manifests = workspace_manifests();
    for c in CONTROL_PLANE {
        assert!(manifests.contains_key(c), "no manifest for {c}");
    }
    let breaches = rule4_breaches(&manifests);
    assert!(breaches.is_empty(), "{breaches:#?}");
    for c in CONTROL_PLANE {
        let mut files = Vec::new();
        let mut todo = vec![db::workspace_root().join("crates").join(c).join("src")];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    todo.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            assert!(
                !text.contains("AccountId"),
                "{} names AccountId",
                f.display()
            );
        }
    }
}

/// I-20 teeth: a control-plane crate that reaches `fstp-domain` through
/// another crate is caught, with its path.
#[test]
fn i20_teeth_control_plane_reaching_account_types_is_caught() {
    let mut m = BTreeMap::new();
    m.insert(
        "fstp-control".to_owned(),
        "[dependencies]\nfstp-cp-proto.workspace = true\n\n[dev-dependencies]\nfstp-domain.workspace = true\n"
            .to_owned(),
    );
    m.insert(
        "fstp-cp-proto".to_owned(),
        "[dependencies]\nfstp-helper = { path = \"../fstp-helper\" }\n".to_owned(),
    );
    m.insert(
        "fstp-helper".to_owned(),
        "[dependencies]\nfstp-domain.workspace = true\n".to_owned(),
    );
    let breaches = rule4_breaches(&m);
    assert!(
        breaches
            .contains(&"fstp-control -> fstp-cp-proto -> fstp-helper -> fstp-domain".to_owned()),
        "{breaches:#?}"
    );
    // The dev-dependency of fstp-control alone is no breach.
    assert!(
        breaches.iter().all(|b| b.contains("fstp-helper")),
        "{breaches:#?}"
    );
}

// ---------------------------------------------------------------------------
// Worlds.

fn world() -> World {
    World::start(WorldSpec {
        cells: 2,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn same_person_cycles(w: &World) {
    let script = CycleScript {
        steps: ["signup", "verify-identity", "submit-proposal"]
            .map(str::to_owned)
            .to_vec(),
    };
    for i in 0..2 {
        w.run_cycle(i, &script)
            .result
            .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
    }
}

/// The hex values of `sql` in every cell database of `w` whose name starts
/// with `prefix`.
fn values(w: &World, prefix: &str, sql: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for d in w.databases().unwrap() {
        let Some(cell) = db::cell_of(&d.name) else {
            continue;
        };
        if !d.name.starts_with(prefix) {
            continue;
        }
        let c = w.clusters().iter().find(|c| c.name() == d.cluster).unwrap();
        let rows = c.server().psql(&d.name, sql).unwrap();
        out.entry(cell.to_owned())
            .or_default()
            .extend(rows.lines().filter(|l| !l.is_empty()).map(str::to_owned));
    }
    out
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// I-20, B6: after the same person joins two cells, no account id of
/// either cell is in any store of the control plane or the witness, or in
/// any capture sent to them. Each id is sought as raw bytes, as hex in
/// both cases and in its 8-4-4-4-12 text form in both cases, each in every
/// encoding the scanner derives.
#[test]
fn i20_control_plane_and_witness_hold_no_account_id() {
    let w = world();
    same_person_cycles(&w);
    let ids = values(
        &w,
        "c_",
        "SELECT encode(uuid_send(account_id), 'hex') FROM auth.session \
         UNION SELECT encode(uuid_send(account_id), 'hex') FROM auth.token \
         WHERE account_id IS NOT NULL",
    );
    let needles: Vec<Needle> = ids
        .values()
        .flatten()
        .enumerate()
        .flat_map(|(i, hex)| {
            // The 8-4-4-4-12 text form, in which JSON, text columns and
            // dumps write a uuid. The scanner derives no such form.
            let text = format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            );
            [
                Needle {
                    label: format!("account {i} raw"),
                    bytes: hex_bytes(hex),
                },
                Needle {
                    label: format!("account {i} hex"),
                    bytes: hex.clone().into_bytes(),
                },
                Needle {
                    label: format!("account {i} hex, uppercase"),
                    bytes: hex.to_ascii_uppercase().into_bytes(),
                },
                Needle {
                    label: format!("account {i} uuid text"),
                    bytes: text.clone().into_bytes(),
                },
                Needle {
                    label: format!("account {i} uuid text, uppercase"),
                    bytes: text.to_ascii_uppercase().into_bytes(),
                },
            ]
        })
        .collect();
    assert!(
        !needles.is_empty(),
        "no account id was found in either cell"
    );
    let stores = w.stores().unwrap();
    let shared: Vec<String> = [ClusterKind::Control, ClusterKind::Witness]
        .iter()
        .map(|k| format!("{}/", w.cluster(*k).unwrap().name()))
        .collect();
    let mut outside = StoreSet::default();
    for (name, bytes) in &stores.stores {
        if shared.iter().any(|p| name.starts_with(p)) {
            outside.push(name.clone(), bytes.clone());
        }
    }
    let to_shared = w
        .egress()
        .store_set_where(|r| matches!(r.to, Peer::ControlPlane | Peer::Witness));
    outside.stores.extend(to_shared.stores);
    let report = scan_bytes(&outside, &needles).unwrap();
    assert!(report.is_clean(), "{:?}", report.hits);
}

/// I-20, Q17, design section 3.5: the same person verified in two cells
/// gets a different identity match key in each cell's vault.
#[test]
fn i20_vault_match_keys_differ_across_cells() {
    let w = world();
    same_person_cycles(&w);
    let keys = values(
        &w,
        "v_",
        "SELECT encode(match_key, 'hex') FROM vault.identity",
    );
    assert_eq!(keys.len(), 2, "{keys:?}");
    let mut it = keys.values();
    let (a, b) = (it.next().unwrap(), it.next().unwrap());
    assert!(
        !a.is_empty() && !b.is_empty(),
        "no match key in a vault: {keys:?}"
    );
    assert!(
        a.is_disjoint(b),
        "a match key is shared: {:?}",
        a.intersection(b)
    );
}

/// I-20 teeth: two cells' stores that hold one lookup digest, in hex in
/// one and base64 in the other, share an identifier beyond the public
/// constants, so `shared_identifiers` reports it.
#[test]
fn i20_teeth_shared_lookup_key_is_caught() {
    let digest: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let mut a = StoreSet::default();
    a.push(
        "cell-a/dump/c_a",
        format!("lookup\t\\\\x{hex}\n").into_bytes(),
    );
    let mut b = StoreSet::default();
    b.push(
        "cell-b/dump/c_b",
        format!("lookup {}\n", fstp_celltest::soft_authn::base64url(&digest)).into_bytes(),
    );
    let (da, dbm) = (CellDump::from_stores(&a), CellDump::from_stores(&b));
    let shared = shared_identifiers(&da, &dbm, &PublicConstants::default()).unwrap();
    assert!(shared.contains(&digest), "{shared:?}");
}
