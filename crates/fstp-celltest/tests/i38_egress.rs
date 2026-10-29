//! I-38: calls from a self-hosted cell to CrabNebula-hosted services
//! carry no tenant data, only product version, channel and licence id
//! (design sections 10.1 and 14.4, `self-hosted-services.md`).
//!
//! Lane W1g wrote these tests before the production code. Each compares
//! production against `fstp_celltest::reference::licence`. They are red
//! until `fstp_release::egress` and `fstp_release::licence` (lane W2j),
//! `fstp_control::install` (lane W2h) and the self-hosted cell runtime
//! (lanes W3a and W3b) land. The teeth tests run on the reference, so each
//! seeded defect is shown to fail its property now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use fstp_cell::CellError;
use fstp_cell::egress::Destination;
use fstp_celltest::canary::{self, Canary, CanaryKind};
use fstp_celltest::egress::{Component, Direction, EgressLog, Endpoint, Peer, Route};
use fstp_celltest::mc::licence_model::release_stub;
use fstp_celltest::reference::licence::{
    self as r, RefCall, RefChannel, RefHosts, RefKind, RefLicenceId, RefToken, RefVersion,
};
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert_eq};
use fstp_release::egress::{self, Channel, CnCall, LicenceRefresh, ProductVersion, UpdateCheck};
use fstp_release::licence::LicenceId;

// ---------------------------------------------------------------------------
// Helpers.

/// The production call of a reference call.
fn prod_call(c: &RefCall) -> CnCall {
    let v = |v: RefVersion| ProductVersion(v.major, v.minor, v.patch);
    match *c {
        RefCall::Update { version, channel } => CnCall::Update(UpdateCheck {
            version: v(version),
            channel: match channel {
                RefChannel::Stable => Channel::Stable,
            },
        }),
        RefCall::Licence { licence, version } => CnCall::Licence(LicenceRefresh {
            licence: LicenceId(licence.0),
            version: v(version),
        }),
    }
}

/// `fstp_release::egress::encode`, with a stub refusal named.
fn encode(c: &RefCall) -> Result<Vec<u8>, String> {
    egress::encode(&prod_call(c)).map_err(|e| match release_stub(&e) {
        Some(op) => format!("{op} is NotImplemented"),
        None => format!("encode refused {c:?}: {e:?}"),
    })
}

fn gen_version(g: &mut Gen) -> RefVersion {
    RefVersion {
        major: g.u16(),
        minor: g.u16(),
        patch: g.u16(),
    }
}

fn gen_licence(g: &mut Gen) -> RefLicenceId {
    let mut id = [0u8; 16];
    for b in &mut id {
        *b = g.u8();
    }
    RefLicenceId(id)
}

fn gen_update(g: &mut Gen) -> RefCall {
    RefCall::Update {
        version: gen_version(g),
        channel: *g.pick(&RefChannel::ALL),
    }
}

fn gen_refresh(g: &mut Gen) -> RefCall {
    RefCall::Licence {
        licence: gen_licence(g),
        version: gen_version(g),
    }
}

fn gen_call(g: &mut Gen) -> RefCall {
    if g.bool() {
        gen_update(g)
    } else {
        gen_refresh(g)
    }
}

/// One canonical call of each kind.
const CANONICAL_VERSION: RefVersion = RefVersion {
    major: 1,
    minor: 2,
    patch: 3,
};

/// The two production hosts, read from one production request of each
/// call. Each must be a DNS host name. The template tests then require
/// the same host on every other request, so the host never varies.
///
/// Gap: design section 10.1 names no host constant, and the stub exports
/// none. Lane W2j may export `UPDATE_HOST` and `LICENCE_HOST`; the tests
/// would then compare against them.
fn production_hosts() -> RefHosts {
    let host = |call: RefCall| -> String {
        let bytes = encode(&call).unwrap_or_else(|e| panic!("{e}"));
        let host = r::host_of(&bytes)
            .unwrap_or_else(|| panic!("I-38: the second line of {call:?} is not a Host header"));
        assert!(
            r::host_ok(&host),
            "I-38: the Host of {call:?} is not a plain DNS host name: {host:?}"
        );
        host
    };
    RefHosts {
        update: host(RefCall::Update {
            version: CANONICAL_VERSION,
            channel: RefChannel::Stable,
        }),
        licence: host(RefCall::Licence {
            licence: RefLicenceId([0; 16]),
            version: CANONICAL_VERSION,
        }),
    }
}

/// Hosts for tests that run on the reference only.
fn test_hosts() -> RefHosts {
    RefHosts {
        update: "updates.example.test".to_owned(),
        licence: "licences.example.test".to_owned(),
    }
}

/// The request with `line` inserted after the `Host` header.
fn with_header(bytes: &[u8], line: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let (first, rest) = text.split_once("\r\n").unwrap();
    let (host, rest) = rest.split_once("\r\n").unwrap();
    format!("{first}\r\n{host}\r\n{line}\r\n{rest}").into_bytes()
}

/// The captures of `log` to CrabNebula hosts, one outbound stream per
/// connection.
fn crabnebula_streams(log: &EgressLog) -> StoreSet {
    let all = log.store_set_where(|route| route.to == Peer::CrabNebula);
    StoreSet {
        stores: all
            .stores
            .into_iter()
            .filter(|(name, _)| name.ends_with("/out"))
            .collect(),
    }
}

fn self_hosted_world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Dedicated,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: true,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("a self-hosted world with one cell: {e}"))
}

/// The steps of one full cycle, from programme to export.
const CYCLE: [&str; 13] = [
    "create-programme",
    "publish-call",
    "submit",
    "stage1",
    "stage2",
    "rank",
    "irc-review",
    "negotiate",
    "grant",
    "request-payment",
    "release-payment",
    "notify",
    "export",
];

/// The steps that may run between cycle steps: a restart, each refresh
/// outcome and an update check.
const BETWEEN: [&str; 5] = [
    "restart",
    "licence-refresh:success",
    "licence-refresh:refused",
    "licence-refresh:garbage",
    "update-check",
];

/// The most steps of [`BETWEEN`] run after one cycle step.
const MAX_BETWEEN: usize = 3;

/// The number of random scripts each self-hosted test runs. Each starts a
/// full cycle on PostgreSQL, so the bound is small.
const SELF_HOSTED_CASES: u32 = 12;

/// The shrink budget of a failing self-hosted run.
const SELF_HOSTED_SHRINK_STEPS: u32 = 24;

/// One random cycle script of the self-hosted runs (design section 14.4).
/// It seeds every canary of cell 0 as the synthetic personal values of
/// the cycle. After each cycle step it runs zero to [`MAX_BETWEEN`] steps
/// of [`BETWEEN`], so a refresh right after a restart and an update check
/// after a garbage refresh both occur. It ends with an update check and a
/// successful refresh, so every script sends to a CrabNebula host.
///
/// Gap: `CycleScript` names steps by text, and lane W3b defines the step
/// vocabulary. The step names here are the W1g proposal.
fn gen_self_hosted_script(g: &mut Gen, canaries: &[Canary]) -> CycleScript {
    let mut steps: Vec<String> = canaries
        .iter()
        .map(|c| format!("seed:{}:{}", c.kind.label(), c.text()))
        .collect();
    for step in CYCLE {
        steps.push(step.to_owned());
        for _ in 0..g.usize_in(0..=MAX_BETWEEN) {
            steps.push((*g.pick(&BETWEEN)).to_owned());
        }
    }
    steps.push("update-check".to_owned());
    steps.push("licence-refresh:success".to_owned());
    CycleScript { steps }
}

/// Runs random self-hosted scripts on cell 0 of `world`, one per case of
/// the property `name`. After each script, `judge` reads the world's
/// egress so far. A script that does not complete fails the case.
fn check_self_hosted(
    name: &str,
    world: &World,
    canaries: &[Canary],
    judge: impl Fn(&World) -> Result<(), String>,
) {
    let cfg = fstp_prop::Config::default()
        .with_cases(SELF_HOSTED_CASES)
        .with_max_shrink_steps(SELF_HOSTED_SHRINK_STEPS);
    fstp_prop::check_with(name, cfg, |g: &mut Gen| {
        let script = gen_self_hosted_script(g, canaries);
        if let Err(e) = world.run_cycle(0, &script).result {
            return Err(format!(
                "the self-hosted cycle {:?} did not complete: {e}",
                script.steps
            ));
        }
        judge(world).map_err(|e| format!("{e} after {:?}", script.steps))
    });
}

// ---------------------------------------------------------------------------
// Byte-exact captures.

/// I-38, design section 10.1: the update check is byte for byte
/// `GET /v1/updates/{channel}/{version}` with the Host header only. Only
/// the version and channel vary.
#[test]
fn i38_update_check_bytes_match_the_template() {
    let hosts = production_hosts();
    fstp_prop::check(
        "i38_update_check_bytes_match_the_template",
        |g: &mut Gen| {
            let call = gen_update(g);
            let got = encode(&call)?;
            prop_assert_eq!(got, r::request(&call, &hosts), "{call:?}");
            Ok(())
        },
    );
}

/// I-38, design section 10.1: the licence refresh is byte for byte
/// `POST /v1/licences/{licence}/refresh` with Host, Content-Type and
/// Content-Length, and the body `{"version":"x.y.z"}`. Only the licence id
/// and the version vary.
#[test]
fn i38_licence_refresh_bytes_match_the_template() {
    let hosts = production_hosts();
    fstp_prop::check(
        "i38_licence_refresh_bytes_match_the_template",
        |g: &mut Gen| {
            let call = gen_refresh(g);
            let got = encode(&call)?;
            prop_assert_eq!(got, r::request(&call, &hosts), "{call:?}");
            Ok(())
        },
    );
}

/// I-38, Q41: the first token is imported from a file, so no registration
/// data ever leaves the cell. `decode_licence_file` returns exactly the
/// token bytes of a well-formed file, and refuses every file the
/// reference refuses: a changed line ending, a missing final line feed,
/// an extra byte, a wrong armour line or a token of the wrong length.
#[test]
fn i38_licence_file_import_matches_reference() {
    let key = Ed25519SigningKey::from_seed(&[0x11; 32]).unwrap();
    fstp_prop::check(
        "i38_licence_file_import_matches_reference",
        |g: &mut Gen| {
            let issued_at = g.i64_in(0..=4_000_000_000);
            let t = RefToken {
                licence: gen_licence(g),
                kind: *g.pick(&RefKind::ALL),
                issued_at,
                refresh_after: issued_at + g.i64_in(0..=30 * r::DAY_S),
                not_after: issued_at + g.i64_in(30 * r::DAY_S..=60 * r::DAY_S),
            };
            let token = r::sign_token(&t, &key).map_err(|e| e.to_string())?;
            let mut file = r::licence_file(&token);
            match g.u8_in(0..=5) {
                0 => {}
                1 => {
                    let text = String::from_utf8(file.clone()).unwrap();
                    file = text.replace('\n', "\r\n").into_bytes();
                }
                2 => {
                    file.pop();
                }
                3 => file.push(b'\n'),
                4 => file[5] = b'X',
                _ => {
                    let short = token.get(..token.len() - 1).unwrap_or_default();
                    file = r::licence_file(short);
                }
            }
            let want = r::decode_licence_file(&file);
            let got = match fstp_release::licence::decode_licence_file(&file) {
                Ok(bytes) => Some(bytes),
                Err(e) => match release_stub(&e) {
                    Some(op) => return Err(format!("{op} is NotImplemented")),
                    None => None,
                },
            };
            prop_assert_eq!(got, want, "{:?}", String::from_utf8_lossy(&file));
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Self-hosted worlds.

/// I-38, design section 14.4: a self-hosted cell runs random full cycles
/// with restarts, every refresh outcome and update checks between steps,
/// with every canary kind of cell 0 seeded. No byte it sends to a
/// CrabNebula host holds a canary in any encoding.
///
/// The cell must have sent something to a CrabNebula host, so the scan
/// never passes on an empty run. The scanner's own reach is shown by
/// `i38_teeth_canary_in_crabnebula_capture_is_caught`.
///
/// The cell's stores are no positive control for the seeding. Bodies are
/// sealed at rest (design section 4.2, Q5 A), identity attributes go to
/// the vault origin (Q7 A), and a root key canary must never appear
/// (I-80). So a correct cell holds no plaintext canary to find.
#[test]
fn i38_self_hosted_cell_sends_no_canary_to_crabnebula_hosts() {
    let world = self_hosted_world();
    let canaries = canary::generate_set(0).unwrap();
    check_self_hosted(
        "i38_self_hosted_cell_sends_no_canary_to_crabnebula_hosts",
        &world,
        &canaries,
        |world| {
            let report =
                scan(&crabnebula_streams(world.egress()), &canaries).map_err(|e| e.to_string())?;
            if report.is_clean() {
                Ok(())
            } else {
                Err(format!(
                    "I-38: a self-hosted cell sent a canary to a CrabNebula host: {:?}",
                    report.hits
                ))
            }
        },
    );
    assert!(
        !crabnebula_streams(world.egress()).stores.is_empty(),
        "the cycles made no update check or refresh, so nothing was scanned"
    );
}

/// I-38, test-plan row: every request a self-hosted cell sends to a
/// CrabNebula host in random full cycles is exactly one of the two
/// templates, so it holds only the permitted fields.
#[test]
fn i38_self_hosted_captures_match_the_templates() {
    let world = self_hosted_world();
    let canaries = canary::generate_set(0).unwrap();
    let hosts = production_hosts();
    check_self_hosted(
        "i38_self_hosted_captures_match_the_templates",
        &world,
        &canaries,
        |world| {
            let breaches: Vec<(String, String)> = crabnebula_streams(world.egress())
                .stores
                .iter()
                .filter_map(|(name, bytes)| {
                    r::split_requests(bytes, &hosts)
                        .err()
                        .map(|e| (name.clone(), e))
                })
                .collect();
            if breaches.is_empty() {
                Ok(())
            } else {
                Err(format!("I-38: {breaches:?}"))
            }
        },
    );
    assert!(
        !crabnebula_streams(world.egress()).stores.is_empty(),
        "the cycles made no update check or refresh, so nothing was checked"
    );
}

/// The streams to CrabNebula hosts that do not hold only templates: any
/// stream from a component other than the cell, and any outbound cell
/// stream that is not templates back to back. Each stream joins every
/// write of one connection, so a request written in parts is judged
/// whole.
fn off_template_streams(log: &EgressLog, hosts: &RefHosts) -> Vec<String> {
    let foreign = log.store_set_where(|route| {
        route.to == Peer::CrabNebula && route.from.component != Component::Cell
    });
    let mut out: Vec<String> = foreign.stores.into_iter().map(|(name, _)| name).collect();
    out.extend(
        crabnebula_streams(log)
            .stores
            .into_iter()
            .filter(|(_, bytes)| r::split_requests(bytes, hosts).is_err())
            .map(|(name, _)| name),
    );
    out
}

/// I-38, design section 7.2 (Q9): a self-hosted cell anchors at its local
/// witness. Through random full cycles, every connection to a CrabNebula
/// host comes from the cell itself and carries only the templates, so no
/// anchor, receipt or audit entry goes there.
#[test]
fn i38_self_hosted_witness_never_targets_crabnebula() {
    let world = self_hosted_world();
    let canaries = canary::generate_set(0).unwrap();
    let hosts = production_hosts();
    check_self_hosted(
        "i38_self_hosted_witness_never_targets_crabnebula",
        &world,
        &canaries,
        |world| {
            let off_template = off_template_streams(world.egress(), &hosts);
            if off_template.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "I-38: an anchor or another payload went to a CrabNebula host: {off_template:?}"
                ))
            }
        },
    );
    assert!(
        world.egress().peers_contacted().contains(&Peer::Witness),
        "the cycles anchored nothing, so the witness route was not exercised"
    );
}

/// I-38: the witness judgment reads joined streams. A refresh written in
/// two writes, headers then body, is one template and passes. A second
/// connection to a CrabNebula host from the witness is flagged, as is a
/// cell stream with one extra header.
#[test]
fn i38_reference_witness_judgment_reads_joined_streams() {
    let hosts = test_hosts();
    let call = RefCall::Licence {
        licence: RefLicenceId([0x4c; 16]),
        version: CANONICAL_VERSION,
    };
    let bytes = r::request(&call, &hosts);
    let cut = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let split = EgressLog::new();
    let cell = Route::new(Endpoint::cell(0), Peer::CrabNebula, None);
    split.record(cell, Direction::Outbound, 1, &bytes[..cut]);
    split.record(cell, Direction::Outbound, 1, &bytes[cut..]);
    let witness = EgressLog::new();
    witness.record(
        Route::new(Endpoint::shared(Component::Witness), Peer::CrabNebula, None),
        Direction::Outbound,
        1,
        &bytes,
    );
    let extra = EgressLog::new();
    extra.record(
        cell,
        Direction::Outbound,
        1,
        &with_header(&bytes, "X-Tenant: tenant-1"),
    );
    assert_eq!(
        [
            off_template_streams(&split, &hosts).len(),
            off_template_streams(&witness, &hosts).len(),
            off_template_streams(&extra, &hosts).len(),
        ],
        [0, 1, 1]
    );
}

// ---------------------------------------------------------------------------
// Structure.

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

/// Every `(crate, file, text)` of the shipped crates' `src` trees. The
/// test-only crates are left out: `fstp-celltest` builds requests to test
/// the egress, and `fstp-domain-testkit` and `fstp-pgtest` never ship.
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

/// The source half of `i38_only_egress_reaches_crabnebula_hosts`: no
/// shipped crate other than `fstp-release` (the client) and
/// `fstp-release-svc` (the services) names the two request paths, and no
/// shipped crate other than `fstp-release` and `fstp-cell` (whose
/// connector carries a `CnCall`) names `CnCall`.
fn source_offenders() -> Vec<String> {
    let sources = shipped_sources();
    if !sources
        .iter()
        .any(|(c, _, t)| c == "fstp-release" && t.contains("pub enum CnCall"))
    {
        return vec!["the scan did not read fstp_release::egress".to_owned()];
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
    offenders
}

/// Every destination of the cell's connector other than
/// `Destination::CrabNebula`. The match has no wildcard, so a new variant
/// of ADR-009 stops this file from building until it is placed here.
fn other_destinations() -> Vec<Destination> {
    let is_other = |d: &Destination| match d {
        Destination::AppDatabase
        | Destination::Vault
        | Destination::Custody
        | Destination::ControlPlane
        | Destination::Witness
        | Destination::KeystoreSnapshots => true,
        Destination::CrabNebula(_) => false,
    };
    [
        Destination::AppDatabase,
        Destination::Vault,
        Destination::Custody,
        Destination::ControlPlane,
        Destination::Witness,
        Destination::KeystoreSnapshots,
    ]
    .into_iter()
    .filter(is_other)
    .collect()
}

/// The connector's API gap. `fstp_cell::egress::connect` takes a
/// `Destination` and no host, and shows no host it resolves. So no test
/// can ask it to reach a CrabNebula host for another destination.
const CONNECTOR_SEAM: &str = "fstp_cell::egress::connect takes no host and shows no resolved host, so the refusal of a CrabNebula host for any destination but Destination::CrabNebula(CnCall) cannot be driven (design section 14.4; lane W3a)";

#[allow(
    unreachable_patterns,
    reason = "lane W3a adds typed refusals to CellError; until then NotImplemented is its only variant"
)]
fn cell_stub(e: &CellError) -> Option<&'static str> {
    match e {
        CellError::NotImplemented(op) => Some(op),
        _ => None,
    }
}

/// The behavioural half of `i38_only_egress_reaches_crabnebula_hosts`:
/// the cell's connector refuses a CrabNebula host for every destination
/// other than `Destination::CrabNebula(CnCall)`.
///
/// Gap ([`CONNECTOR_SEAM`]): the stub connector refuses everything with
/// NotImplemented, and its API takes no host. Lane W3a gives it a way to
/// name a host, and this half then drives each destination of
/// [`other_destinations`] against both production hosts.
fn connector_refusals() -> Result<(), String> {
    for d in other_destinations() {
        if let Err(e) = fstp_cell::egress::connect(&d)
            && let Some(op) = cell_stub(&e)
        {
            return Err(format!("{op} is NotImplemented ({d:?}): {CONNECTOR_SEAM}"));
        }
    }
    Err(CONNECTOR_SEAM.to_owned())
}

/// I-38, design sections 10.1 and 14.4: only `fstp_release::egress`
/// builds requests to CrabNebula hosts, and the cell's outbound connector
/// refuses those hosts for any other caller.
///
/// Two halves. The source half requires that no other shipped crate names
/// the request paths or `CnCall`. A text scan alone is easy to get past,
/// for example with a path built by `concat!`. So the behavioural half
/// drives the connector, and it stays red on [`CONNECTOR_SEAM`] until lane
/// W3a lands.
#[test]
fn i38_only_egress_reaches_crabnebula_hosts() {
    let offenders = source_offenders();
    let connector = connector_refusals();
    assert!(
        offenders.is_empty() && connector.is_ok(),
        "I-38: a caller other than fstp_release::egress can reach a CrabNebula host. \
         Source half: {offenders:?}. Connector half: {connector:?}"
    );
}

/// The proposed install configuration of a self-hosted cell with an EUDI
/// relying party mode (P-45).
///
/// Gap: design section 9.5 fixes no install configuration grammar, and
/// the stub `InstallConfig` holds `host` only. The member
/// `eudi_relying_party` with the values `tenant_registration` and
/// `intermediary` is the W1g proposal for lane W2h.
fn install_config(mode: &str) -> Vec<u8> {
    format!("{{\"host\":\"cell.example.test\",\"eudi_relying_party\":\"{mode}\"}}").into_bytes()
}

#[allow(
    unreachable_patterns,
    reason = "lane W2h adds typed refusals to ControlError; until then NotImplemented is its only variant"
)]
fn control_stub(e: &fstp_control::ControlError) -> Option<&'static str> {
    match e {
        fstp_control::ControlError::NotImplemented(op) => Some(op),
        _ => None,
    }
}

/// I-38, design section 10.3, `eudi-wallet.md`: a self-hosted build
/// refuses P-45 intermediary mode at configuration decode, since that
/// mode would send identity data to a CrabNebula service.
#[test]
fn i38_self_hosted_refuses_intermediary_mode() {
    let got = fstp_control::install::decode_install_config(&install_config("intermediary"));
    match got {
        Ok(c) => panic!("I-38: a self-hosted install decoded P-45 intermediary mode: {c:?}"),
        Err(e) => assert_eq!(
            control_stub(&e),
            None,
            "decode_install_config is NotImplemented, so nothing refused intermediary mode"
        ),
    }
}

/// I-38, the twin of `i38_self_hosted_refuses_intermediary_mode`: the same
/// configuration with tenant registration decodes, so the refusal is
/// about the mode and not a decoder that refuses everything.
#[test]
fn i38_self_hosted_accepts_tenant_registration_mode() {
    let got = fstp_control::install::decode_install_config(&install_config("tenant_registration"));
    match got {
        Ok(c) => assert_eq!(c.host, "cell.example.test"),
        Err(e) => panic!(
            "a self-hosted install refused tenant registration: {e:?}{}",
            if control_stub(&e).is_some() {
                " (NotImplemented)"
            } else {
                ""
            }
        ),
    }
}

// ---------------------------------------------------------------------------
// The reference and teeth.

/// I-38: the template parser reads back every call from its template
/// bytes. A self-test of the permitted-fields predicate.
#[test]
fn i38_reference_template_round_trips() {
    let hosts = test_hosts();
    fstp_prop::check("i38_reference_template_round_trips", |g: &mut Gen| {
        let call = gen_call(g);
        let got = r::parse_request(&r::request(&call, &hosts), &hosts);
        prop_assert_eq!(got, Ok(call));
        Ok(())
    });
}

/// The permitted-fields property over an encoder.
fn template_holds(bytes: &[u8], hosts: &RefHosts) -> Result<(), String> {
    r::parse_request(bytes, hosts).map(|_| ()).map_err(|b| {
        format!(
            "I-38: a request outside the templates ({b:?}): {:?}",
            String::from_utf8_lossy(bytes)
        )
    })
}

/// I-38 teeth (design section 20): an encoder that adds one header, such
/// as a `User-Agent` naming the tenant's host, fails the permitted-fields
/// property.
#[test]
fn i38_teeth_extra_header_is_caught() {
    let hosts = test_hosts();
    let outcome = fstp_prop::run(
        "i38_teeth_extra_header_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            let call = gen_call(g);
            let header = *g.pick(&[
                "User-Agent: fstp-cell/1.2.3 (grants.tenant.example)",
                "Cookie: session=1",
                "X-Tenant: tenant-1",
            ]);
            template_holds(&with_header(&r::request(&call, &hosts), header), &hosts)
        },
    );
    expect_prop_failure(&outcome, "I-38").unwrap();
}

/// I-38 teeth: a refresh body with one more member, such as a holder
/// contact, fails the permitted-fields property.
#[test]
fn i38_teeth_extra_body_member_is_caught() {
    let hosts = test_hosts();
    let outcome = fstp_prop::run(
        "i38_teeth_extra_body_member_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            let RefCall::Licence { licence, version } = gen_refresh(g) else {
                return Ok(());
            };
            let body = format!(
                "{{\"version\":\"{}\",\"contact\":\"admin@tenant.example\"}}",
                version.render()
            );
            let bytes = format!(
                "POST /v1/licences/{}/refresh HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                licence.hex(),
                hosts.licence,
                body.len()
            );
            template_holds(bytes.as_bytes(), &hosts)
        },
    );
    expect_prop_failure(&outcome, "I-38").unwrap();
}

/// I-38 scanner teeth (design section 14.1): a request to a CrabNebula
/// host that carries one canary in a header is found by the scan of the
/// recorded egress, in each canary kind.
#[test]
fn i38_teeth_canary_in_crabnebula_capture_is_caught() {
    let hosts = test_hosts();
    let missed: Vec<CanaryKind> = CanaryKind::ALL
        .into_iter()
        .filter(|kind| {
            let canary = Canary::generate(0, *kind).unwrap();
            let log = EgressLog::new();
            let call = RefCall::Update {
                version: CANONICAL_VERSION,
                channel: RefChannel::Stable,
            };
            let leaked = with_header(
                &r::request(&call, &hosts),
                &format!("X-Tenant: {}", canary.text()),
            );
            log.record(
                Route::new(Endpoint::cell(0), Peer::CrabNebula, None),
                Direction::Outbound,
                1,
                &leaked,
            );
            let report = scan(&crabnebula_streams(&log), std::slice::from_ref(&canary)).unwrap();
            report.is_clean()
        })
        .collect();
    assert!(
        missed.is_empty(),
        "teeth: the scan missed canaries of kinds {missed:?}"
    );
}
