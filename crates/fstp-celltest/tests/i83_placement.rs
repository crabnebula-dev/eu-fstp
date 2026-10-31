//! I-83: identity vault databases never share a cluster with application
//! databases (design section 14.4, T-DB-ISO, B8).
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until `fstp_control::placement` and `cell_role_plan` (lane W2h), the cp
//! migrations (lane W2h), the vault and cell start checks (lanes W2d and
//! W3a), the cell runtime (lane W3a) and the M-PLACE tripwire count (lane
//! W4) land.
//!
//! Lane m3i83 runs the start checks over real clusters. Each target of
//! the start-check comparison becomes a live database on a server whose
//! certificate OU is the target's. The cell and the vault derive the OU
//! and the SPKI from their own `fstp_pgwire` connection. The cell's whole
//! start path is run over such databases too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::place_model::db::{self, MigrationSet};
use fstp_celltest::mc::place_model::{
    Mode, Mutant, PlaceAction, PlaceBackend, PlaceDefect, PlaceModel, Production, Reference,
    cluster, cluster_id, ids, properties, reference_places,
};
use fstp_celltest::mc::tripwires::{M_PLACE, NOT_MEASURED, tripwire};
use fstp_celltest::world::{ClusterHandle, DbMode, VaultLayout, World, WorldSpec, kind_label};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement, PlacementError};
use fstp_domain_testkit::harness::teeth::{expect_unreachable, expect_violation};
use fstp_mc::{Config, check, explore};
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

fn bound() -> Config {
    assert_ne!(
        M_PLACE, NOT_MEASURED,
        "the M-PLACE tripwire is not recorded yet (lane W4); \
         i83_m_place_tripwire_records_the_measured_count gives the count"
    );
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(tripwire(M_PLACE))
}

fn outcome_of<B: PlaceBackend>(
    backend: B,
) -> fstp_mc::Outcome<
    fstp_celltest::mc::place_model::PlaceState,
    fstp_celltest::mc::place_model::PlaceAction,
> {
    let model = PlaceModel::new(backend);
    let props = properties(&model);
    check(&model, &props, &bound())
}

fn passes<B: PlaceBackend>(backend: B) {
    let outcome = outcome_of(backend);
    assert!(
        outcome.exhaustive,
        "M-PLACE did not finish under its tripwire:\n{outcome}"
    );
    if let Err(e) = outcome.require_all_passed() {
        panic!("{e}\n{outcome}");
    }
}

fn caught<B: PlaceBackend>(backend: B, id: &str) {
    let outcome = outcome_of(backend);
    if let Err(e) = expect_violation(&outcome, id) {
        panic!("{e}\n{outcome}");
    }
}

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-PLACE production backend: {e}"))
}

const ALL_KINDS: [ClusterKind; 4] = [
    ClusterKind::Application,
    ClusterKind::Vault,
    ClusterKind::Control,
    ClusterKind::Witness,
];

fn spec(cells: u8, mode: DbMode, self_hosted: bool) -> WorldSpec {
    WorldSpec {
        cells,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted,
        process_mode: false,
    }
}

fn world(cells: u8, mode: DbMode, self_hosted: bool) -> World {
    World::start(spec(cells, mode, self_hosted))
        .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn cp_set() -> MigrationSet {
    db::migration_sets()
        .into_iter()
        .find(|s| s.set == "cp")
        .unwrap()
}

/// A fresh control-plane database with the cp migrations applied.
fn cp_database() -> (ClusterHandle, String) {
    let control = ClusterHandle::start(ClusterKind::Control).unwrap();
    let name = db::migrated(control.server(), &cp_set()).unwrap_or_else(|e| panic!("{e}"));
    (control, name)
}

// ---------------------------------------------------------------------------
// Production against the reference.

/// I-83, design section 9.2: `Placement::new` accepts exactly an
/// application cluster and a different vault cluster, for every pair of
/// kinds, and the placement names the clusters it was given.
#[test]
fn i83_placement_never_mixes_kinds() {
    fstp_prop::check("i83_placement_never_mixes_kinds", |g: &mut Gen| {
        let app = Cluster {
            id: ClusterId([g.u8_in(0..=3); 16]),
            kind: *g.pick(&ALL_KINDS),
        };
        let vault = Cluster {
            id: ClusterId([g.u8_in(0..=3); 16]),
            kind: *g.pick(&ALL_KINDS),
        };
        let want = reference_places(&app, &vault);
        match Placement::new(&app, &vault) {
            Err(PlacementError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
            Ok(p) => {
                prop_assert_eq!(want, true, "placed {app:?} and {vault:?}");
                prop_assert_eq!(p.clusters(), (app.id, vault.id));
                Ok(())
            }
            Err(e) => {
                prop_assert_eq!(want, false, "refused {app:?} and {vault:?} with {e:?}");
                Ok(())
            }
        }
    });
}

/// I-83, design section 9.2: each refusal names its reason: a wrong
/// application kind, a wrong vault kind, or one cluster for both.
///
/// Design section 9.2 does not order the three checks, so each case
/// breaks exactly one rule. The wrong-kind cases use two distinct
/// clusters, and the one-cluster case uses the right kinds.
#[test]
fn i83_placement_refusals_name_their_reason() {
    let app = cluster(0).unwrap();
    let vault = cluster(1).unwrap();
    let control = cluster(2).unwrap();
    let other = |kind| Cluster {
        id: ClusterId([0xE7; 16]),
        kind,
    };
    let cases = [
        (
            other(ClusterKind::Vault),
            vault,
            PlacementError::NotAnApplicationCluster,
        ),
        (control, vault, PlacementError::NotAnApplicationCluster),
        (
            app,
            other(ClusterKind::Application),
            PlacementError::NotAVaultCluster,
        ),
        (app, control, PlacementError::NotAVaultCluster),
        (
            app,
            Cluster {
                id: app.id,
                kind: ClusterKind::Vault,
            },
            PlacementError::SameCluster,
        ),
    ];
    for (a, v, want) in cases {
        match Placement::new(&a, &v) {
            Err(PlacementError::NotImplemented(op)) => panic!("{op} is NotImplemented"),
            got => assert_eq!(got, Err(want), "{a:?} and {v:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// M-PLACE.

/// I-83 and I-82, M-PLACE over production: every placement keeps the
/// kinds apart, no plan reaches two cells' databases, and every witness is
/// reachable.
#[test]
fn i83_m_place() {
    passes(production());
}

/// I-83 and I-82, M-PLACE over the reference: every property and witness
/// holds.
#[test]
fn i83_m_place_on_the_reference() {
    passes(Reference);
}

/// I-83, design section 14.1: the recorded tripwire count is the measured
/// state count of M-PLACE over the reference.
#[test]
fn i83_m_place_tripwire_records_the_measured_count() {
    let space = explore(&PlaceModel::new(Reference), &Config::default());
    assert!(
        space.exhaustive,
        "M-PLACE over the reference did not finish"
    );
    assert_eq!(
        M_PLACE,
        space.len(),
        "record the measured M-PLACE count {} in fstp_celltest::mc::tripwires (lane W4)",
        space.len()
    );
}

/// I-83 teeth, design section 14.2: a placement that takes the first free
/// cluster without a kind check breaks I-83.
#[test]
fn i83_teeth_first_free_cluster_is_caught() {
    caught(
        Mutant::new(production(), PlaceDefect::FirstFreeCluster),
        ids::I83,
    );
}

/// I-83 teeth: the same defect is caught on the reference.
#[test]
fn i83_teeth_first_free_cluster_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, PlaceDefect::FirstFreeCluster),
        ids::I83,
    );
}

/// I-82 teeth, M-PLACE `I-82-plan`: a plan that names another cell is
/// caught.
#[test]
fn i82_teeth_m_place_plan_for_another_cell_is_caught() {
    caught(
        Mutant::new(production(), PlaceDefect::PlanForFirstCell),
        ids::I82_PLAN,
    );
}

/// I-82 teeth: the same defect is caught on the reference.
#[test]
fn i82_teeth_m_place_plan_for_another_cell_is_caught_on_the_reference() {
    caught(
        Mutant::new(Reference, PlaceDefect::PlanForFirstCell),
        ids::I82_PLAN,
    );
}

/// An over-denial mutant: it refuses every placement.
#[derive(Clone, Copy, Debug)]
struct RefusesAll<B>(B);

impl<B: PlaceBackend> PlaceBackend for RefusesAll<B> {
    fn place(
        &self,
        registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, fstp_celltest::NotImplemented> {
        self.0.place(registry, app, vault)?;
        Ok(None)
    }

    fn plan(
        &self,
        cell: fstp_cp_proto::CellId,
    ) -> Result<fstp_celltest::mc::place_model::PlanView, fstp_celltest::NotImplemented> {
        self.0.plan(cell)
    }
}

/// I-83 teeth, design section 14.1 two-way postconditions: a placement that
/// refuses everything keeps I-83 but loses the shared-cell witness.
#[test]
fn i83_teeth_refusing_every_placement_loses_the_witness() {
    let outcome = outcome_of(RefusesAll(Reference));
    if let Err(e) = expect_unreachable(&outcome, ids::W_SHARED) {
        panic!("{e}\n{outcome}");
    }
}

/// I-83: the model offers the mixed requests that the witnesses need: a
/// vault cluster asked for as the application cluster.
#[test]
fn i83_m_place_offers_mixed_requests() {
    let model = PlaceModel::new(Reference);
    let mut out = Vec::new();
    fstp_mc::Model::actions(
        &model,
        &fstp_celltest::mc::place_model::PlaceState::genesis(),
        &mut out,
    );
    assert!(out.contains(&PlaceAction::Provision {
        cell: 0,
        app: 1,
        vault: 0,
        mode: Mode::Shared,
    }));
    assert_eq!(cluster(1).map(|c| c.id), Some(cluster_id(1)));
}

// ---------------------------------------------------------------------------
// The control-plane database (design section 4.4).

/// I-83, design section 4.4: `cp.cluster.kind` cannot change once
/// registered. The trigger refuses an UPDATE of the kind, even by the
/// superuser.
#[test]
fn i83_cluster_kind_is_immutable() {
    let (control, name) = cp_database();
    let s = control.server();
    s.psql(
        &name,
        "INSERT INTO cp.cluster (cluster_id, kind, region, endpoint, server_spki, created_at) \
         VALUES ('\\x000102030405060708090a0b0c0d0e0f', 1, 1, 'app1.example:5432', '\\x00', 1)",
    )
    .unwrap();
    let err = s
        .psql(
            &name,
            "UPDATE cp.cluster SET kind = 2 WHERE cluster_id = '\\x000102030405060708090a0b0c0d0e0f'",
        )
        .expect_err("the kind of a registered cluster changed");
    assert!(err.to_string().contains("ERROR"), "{err}");
    let kind = s.psql(&name, "SELECT kind FROM cp.cluster").unwrap();
    assert_eq!(kind, "1");
}

/// I-83, design section 4.4: a database CHECK refuses one cluster for both
/// the application and the vault database of a cell.
#[test]
fn i83_cp_cell_refuses_one_cluster_for_both_databases() {
    let (control, name) = cp_database();
    let s = control.server();
    s.psql(
        &name,
        "INSERT INTO cp.cluster (cluster_id, kind, region, endpoint, server_spki, created_at) \
         VALUES ('\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', 1, 1, 'app1.example:5432', '\\x00', 1)",
    )
    .unwrap();
    let err = s
        .psql(
            &name,
            "INSERT INTO cp.cell (cell_id, status, mode, app_cluster, vault_cluster, \
             app_backend, vault_backend, org_ref, created_at) VALUES \
             ('\\x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 1, 1, \
              '\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', '\\x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', \
              1, 1, '\\x00', 1)",
        )
        .expect_err("one cluster took both databases of a cell");
    assert!(err.to_string().contains("check"), "{err}");
}

// ---------------------------------------------------------------------------
// Start checks (design section 9.2).

/// What a database looks like to a process at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    /// `fstp_meta.placement.kind` of the database: 1 application, 2 vault.
    marker: u8,
    /// The kind in the server certificate's subject OU.
    ou: ClusterKind,
    /// The kind the server SPKI is registered for.
    spki: ClusterKind,
}

/// The reference start rule of design section 9.2: a process accepts a
/// database only when the marker, the OU and the registered SPKI all name
/// its own kind.
fn reference_accepts(own: ClusterKind, t: Target) -> bool {
    let marker = match own {
        ClusterKind::Application => 1,
        ClusterKind::Vault => 2,
        ClusterKind::Control | ClusterKind::Witness => 0,
    };
    t.marker == marker && t.ou == own && t.spki == own
}

fn targets() -> Vec<Target> {
    let mut out = Vec::new();
    for marker in [1, 2] {
        for ou in [ClusterKind::Application, ClusterKind::Vault] {
            for spki in [ClusterKind::Application, ClusterKind::Vault] {
                out.push(Target { marker, ou, spki });
            }
        }
    }
    out
}

/// A start-check verdict: whether the process accepts the database, or
/// why the check could not run.
type StartVerdict = Result<bool, fstp_celltest::NotImplemented>;

/// The vault start check of design section 9.2 for one target, over a
/// real cluster (lane m3i83).
///
/// The target becomes a live database ([`live_target`]): a server whose
/// certificate OU is the target's, a database of the target's marker,
/// and a registration that gives the server's SPKI the target's kind. The
/// verdict is that of `fstp_vault::service::check_database`, the check
/// `fstp_vault::service::serve` runs, over a `fstp_pgwire` connection to
/// that database. Any refusal other than the I-83 one fails the test, so
/// no target is refused for an unrelated reason.
fn vault_start_check(t: Target) -> StartVerdict {
    let live = live_target(t, "vault");
    let registered = live.vault_registration();
    let mut client = live.connect(0);
    match block_on(fstp_vault::service::check_database(
        &mut client,
        &registered,
    )) {
        Ok(_) => Ok(true),
        Err(fstp_vault::VaultError::Malformed("not a vault database (I-83)")) => Ok(false),
        Err(e) => panic!("{t:?}: the vault check failed for another reason: {e}"),
    }
}

/// The cell start check of design section 9.2 for one target, the mirror
/// of [`vault_start_check`]: `fstp_cell::process::check_database`, the
/// check `fstp_cell::process::start` runs first, over a real cluster.
fn cell_start_check(t: Target) -> StartVerdict {
    let live = live_target(t, "app");
    let registered = live.cell_registration();
    let mut client = live.connect(0);
    match block_on(fstp_cell::process::check_database(&mut client, &registered)) {
        Ok(_) => Ok(true),
        Err(e) if e == placement_refusal() => Ok(false),
        Err(e) => panic!("{t:?}: the cell check failed for another reason: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Live databases for the start checks (lane m3i83).

/// The refusal `fstp_cell::process` gives a database that fails I-83.
fn placement_refusal() -> fstp_cell::CellError {
    fstp_cell::CellError::Config(fstp_cell::config::ConfigError::Invalid("placement"))
}

fn rt() -> &'static fstp_rt::tokio::TokioRuntime {
    static RT: std::sync::OnceLock<fstp_rt::tokio::TokioRuntime> = std::sync::OnceLock::new();
    RT.get_or_init(|| fstp_rt::tokio::TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

/// The named server of `kind` for the live start checks. Each starts with
/// its own cluster CA and carries `kind` as its certificate OU. They are
/// not the world's clusters, whose `pg_hba.conf` the world installs.
fn live_server(kind: ClusterKind) -> &'static fstp_pgtest::PgServer {
    let name = match kind {
        ClusterKind::Application => "i83live_application",
        ClusterKind::Vault => "i83live_vault",
        ClusterKind::Control | ClusterKind::Witness => panic!("no live server of kind {kind:?}"),
    };
    ClusterHandle::start_named(kind, name)
        .unwrap_or_else(|e| panic!("{e}"))
        .server()
}

/// The certificate `server` holds, as `fstp-pgtest` wrote it to the
/// server's TLS directory. This is what a control plane registers.
fn held_leaf(server: &fstp_pgtest::PgServer) -> Vec<u8> {
    let pem = std::fs::read(server.dir().join("tls").join("server.pem")).unwrap();
    let text = String::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    fstp_pgwire::base64::decode(body.as_bytes()).unwrap()
}

/// The SHA-256 digest of the SPKI of the certificate `server` holds.
fn held_spki_digest(server: &fstp_pgtest::PgServer) -> [u8; 32] {
    let der = held_leaf(server);
    fstp_crypto::sha256(fstp_witness::peer::read_cert(&der).unwrap().spki)
}

/// A database of one target on a live server, with its login roles.
struct Live {
    target: Target,
    server: &'static fstp_pgtest::PgServer,
    cell: [u8; 16],
    dbname: String,
    logins: Vec<fstp_pgtest::RoleLogin>,
}

impl Live {
    /// The registration of both live servers: the target's server under
    /// the target's SPKI kind, the other server under its own kind.
    fn registration(&self) -> Vec<([u8; 32], ClusterKind)> {
        let other = match self.target.ou {
            ClusterKind::Application => ClusterKind::Vault,
            _ => ClusterKind::Application,
        };
        vec![
            (held_spki_digest(self.server), self.target.spki),
            (held_spki_digest(live_server(other)), other),
        ]
    }

    fn vault_registration(&self) -> Vec<fstp_vault::service::RegisteredSpki> {
        use fstp_vault::start::ClusterRole;
        self.registration()
            .into_iter()
            .map(|(digest, kind)| fstp_vault::service::RegisteredSpki {
                digest,
                role: match kind {
                    ClusterKind::Application => ClusterRole::Application,
                    ClusterKind::Vault => ClusterRole::Vault,
                    ClusterKind::Control | ClusterKind::Witness => ClusterRole::Other,
                },
            })
            .collect()
    }

    fn cell_registration(&self) -> Vec<fstp_cell::process::RegisteredSpki> {
        use fstp_cell::engine::startup::ClusterRole;
        self.registration()
            .into_iter()
            .map(|(digest, kind)| fstp_cell::process::RegisteredSpki {
                digest,
                role: match kind {
                    ClusterKind::Application => ClusterRole::Application,
                    ClusterKind::Vault => ClusterRole::Vault,
                    ClusterKind::Control | ClusterKind::Witness => ClusterRole::Other,
                },
            })
            .collect()
    }

    /// The `fstp_pgwire` configuration of login `i`.
    fn config(&self, i: usize) -> fstp_pgwire::Config {
        let p = self.logins[i].conn_params(self.server, &self.dbname);
        let tls = fstp_pgwire::ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem)
            .unwrap();
        fstp_pgwire::Config::new(
            p.host.clone(),
            p.port,
            p.user.as_str(),
            fstp_pgwire::Password::new(p.password.as_str()).unwrap(),
            p.dbname.clone(),
            tls,
        )
        .unwrap()
        .connect_timeout(Some(std::time::Duration::from_secs(20)))
    }

    /// A connection as login `i`.
    fn connect(&self, i: usize) -> fstp_pgwire::Client<fstp_rt::tokio::TokioRuntime> {
        block_on(fstp_pgwire::Client::connect(rt(), &self.config(i)))
            .unwrap_or_else(|e| panic!("{:?}: connect: {e}", self.target))
    }
}

/// Target `t` as a live database on the live server whose OU is `t.ou`
/// ([`live_database`]), with the one login role suffix `suffix`.
fn live_target(t: Target, suffix: &str) -> Live {
    let cell = fstp_crypto::random_array::<16>().unwrap();
    live_database(live_server(t.ou), t, cell, &[suffix])
}

/// Target `t` as a live database of `cell` on `server`: the app
/// migration set and placement marker 1, or the vault set and marker 2,
/// under the name grammar of the set. Each of `suffixes` becomes a login
/// role `<prefix>_<cell>_<suffix>` that may connect and read the
/// placement marker. `t.ou` is not read here: the server's certificate
/// carries it.
fn live_database(
    server: &'static fstp_pgtest::PgServer,
    t: Target,
    cell: [u8; 16],
    suffixes: &[&str],
) -> Live {
    let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
    let (prefix, set) = match t.marker {
        1 => ("c", "app"),
        2 => ("v", "vault"),
        m => panic!("no migration set has placement marker {m}"),
    };
    let dbname = format!("{prefix}_{hex}");
    let roles: Vec<String> = suffixes
        .iter()
        .map(|s| format!("{prefix}_{hex}_{s}"))
        .collect();
    let logins: Vec<_> = roles
        .iter()
        .map(|r| server.create_login_role(r).unwrap())
        .collect();
    let role_refs: Vec<&str> = roles.iter().map(String::as_str).collect();
    server.create_database_for(&dbname, &role_refs).unwrap();
    let set = db::migration_sets()
        .into_iter()
        .find(|s| s.set == set)
        .unwrap();
    db::apply_set(server, &dbname, &set).unwrap_or_else(|e| panic!("{e}"));
    let mut sql = format!(
        "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) \
         VALUES ('\\x{hex}', '\\x{}', {});\n",
        "5a".repeat(16),
        t.marker
    );
    for r in &roles {
        sql.push_str(&format!(
            "GRANT USAGE ON SCHEMA fstp_meta TO {r};\nGRANT SELECT ON fstp_meta.placement TO {r};\n"
        ));
    }
    server.psql(&dbname, &sql).unwrap();
    // The marker check reads exactly one row, so a refusal is never the
    // refusal of an empty or doubled placement table.
    let rows = server
        .psql(&dbname, "SELECT count(*) FROM fstp_meta.placement")
        .unwrap();
    assert_eq!(rows, "1", "{t:?}");
    Live {
        target: t,
        server,
        cell,
        dbname,
        logins,
    }
}

/// Every target where `check` disagrees with the reference rule for a
/// process of kind `own`, or could not run, one line each.
fn start_check_mismatches(own: ClusterKind, check: fn(Target) -> StartVerdict) -> Vec<String> {
    let mut out = Vec::new();
    for t in targets() {
        let want = reference_accepts(own, t);
        match check(t) {
            Ok(got) if got == want => {}
            Ok(got) => out.push(format!(
                "{t:?}: the {own:?} start check accepted: {got}, the reference: {want}"
            )),
            Err(e) => out.push(format!("{t:?}: {e}")),
        }
    }
    out
}

/// I-83, design section 9.2: `fstp-vault` refuses a database whose
/// placement marker is not vault, whose server certificate OU is not
/// `vault`, or whose SPKI is registered for an application cluster. It
/// accepts the one target where all three name the vault kind. Every
/// target is compared with the reference rule.
#[test]
fn i83_vault_refuses_an_application_cluster() {
    let found = start_check_mismatches(ClusterKind::Vault, vault_start_check);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-83, design section 9.2: `fstp-cell` makes the mirror checks, refuses
/// a vault cluster and accepts only an application target. Every target
/// is compared with the reference rule.
#[test]
fn i83_cell_refuses_a_vault_cluster() {
    let found = start_check_mismatches(ClusterKind::Application, cell_start_check);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-83 teeth: the start-check comparison reports a check that accepts
/// every target, and one that ignores the SPKI. The reference rule itself
/// gives no mismatch.
#[test]
fn i83_teeth_start_check_comparison_catches_a_lax_check() {
    let all = start_check_mismatches(ClusterKind::Vault, |_| Ok(true));
    assert_eq!(all.len(), targets().len() - 1, "{all:#?}");
    let no_spki = start_check_mismatches(ClusterKind::Vault, |t| {
        Ok(t.marker == 2 && t.ou == ClusterKind::Vault)
    });
    assert_eq!(no_spki.len(), 1, "{no_spki:#?}");
    let exact = start_check_mismatches(ClusterKind::Application, |t| {
        Ok(reference_accepts(ClusterKind::Application, t))
    });
    assert!(exact.is_empty(), "{exact:#?}");
}

/// I-83: the reference start rule accepts one target per kind, and never
/// the other kind's.
#[test]
fn i83_reference_start_rule_accepts_only_its_own_kind() {
    let accepted = |own| {
        targets()
            .into_iter()
            .filter(|t| reference_accepts(own, *t))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        accepted(ClusterKind::Vault),
        vec![Target {
            marker: 2,
            ou: ClusterKind::Vault,
            spki: ClusterKind::Vault
        }]
    );
    assert_eq!(
        accepted(ClusterKind::Application),
        vec![Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Application
        }]
    );
}

// ---------------------------------------------------------------------------
// The server certificate readings (lane m3i83).

/// The DER of a server certificate with OU `ou`, issued by a fresh
/// cluster CA of `fstp-pgtest`.
fn minted_server_leaf(ou: &str) -> Vec<u8> {
    let ca = fstp_pgtest::certs::ClusterCa::generate("i83 test cluster CA").unwrap();
    let pem = String::from_utf8(ca.issue_server(ou).unwrap().cert_pem).unwrap();
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    fstp_pgwire::base64::decode(body.as_bytes()).unwrap()
}

/// The DER of a certificate whose subject has the OU `ou`, or none. It is
/// a client certificate, since `fstp-pki` issues a server certificate
/// only with a cluster kind marker as its OU.
fn minted_leaf_with_any_ou(ou: Option<&str>) -> Vec<u8> {
    use fstp_pgtest::certs::{Name, Profile, Usage, signer::KeyPair, to_spec};
    let issuer = KeyPair::generate().unwrap();
    let subject = KeyPair::generate().unwrap();
    let mut serial = fstp_crypto::random_array::<16>().unwrap().to_vec();
    serial[0] = (serial[0] & 0x7f) | 0x01;
    let profile = Profile {
        serial,
        issuer: Name {
            cn: "i83 test CA".to_owned(),
            ou: None,
        },
        subject: Name {
            cn: "127.0.0.1".to_owned(),
            ou: ou.map(str::to_owned),
        },
        not_before: 1_700_000_000,
        not_after: 1_700_000_000 + 86_400,
        spki_der: subject.spki_der().unwrap(),
        usage: Usage::Client,
        dns_names: Vec::new(),
        ip_addrs: Vec::new(),
    };
    let spec = to_spec(&profile, &issuer.spki_der().unwrap()).unwrap();
    let tbs = fstp_pki::cert::tbs(&spec).unwrap();
    let signature = issuer.sign(tbs.as_der()).unwrap();
    fstp_pki::cert::assemble(&tbs, &signature).unwrap()
}

/// I-83, design sections 1.3 and 9.2: the OU spellings the cell and the
/// vault compare with are the cluster kind markers `fstp-pki` issues.
#[test]
fn i83_start_check_ou_spellings_are_the_pki_markers() {
    use fstp_pki::cert::ClusterKindOu;
    assert_eq!(
        fstp_cell::process::APPLICATION_OU,
        ClusterKindOu::Application.as_str()
    );
    assert_eq!(fstp_cell::process::VAULT_OU, ClusterKindOu::Vault.as_str());
    assert_eq!(
        fstp_vault::service::APPLICATION_OU,
        ClusterKindOu::Application.as_str()
    );
    assert_eq!(fstp_vault::service::VAULT_OU, ClusterKindOu::Vault.as_str());
}

/// I-83, design section 9.2: the cell reads the cluster kind from the
/// server certificate's OU. Only the exact markers name a kind. Another
/// cluster kind, another spelling and bytes that are no certificate name
/// none.
#[test]
fn i83_cell_reads_the_cluster_kind_from_the_server_certificate_ou() {
    use fstp_cell::engine::startup::ClusterRole;
    use fstp_cell::process::server_ou_role;
    let cases = [
        ("application", ClusterRole::Application),
        ("vault", ClusterRole::Vault),
        ("control", ClusterRole::Other),
        ("witness", ClusterRole::Other),
    ];
    for (ou, want) in cases {
        assert_eq!(server_ou_role(&minted_server_leaf(ou)), want, "OU {ou:?}");
    }
    for ou in [Some("vaults"), Some("Vault"), Some("applicatio"), None] {
        assert_eq!(
            server_ou_role(&minted_leaf_with_any_ou(ou)),
            ClusterRole::Other,
            "OU {ou:?}"
        );
    }
    assert_eq!(
        server_ou_role(&minted_leaf_with_any_ou(Some("application"))),
        ClusterRole::Application,
        "the OU reading itself"
    );
    let leaf = minted_server_leaf("vault");
    assert_eq!(server_ou_role(&leaf[..leaf.len() - 1]), ClusterRole::Other);
    assert_eq!(server_ou_role(b"vault"), ClusterRole::Other);
}

/// I-83, design section 9.2: a server key names a kind only when it is
/// registered, and every registration of it names that one kind. A key
/// registered for an application and a vault cluster names none.
#[test]
fn i83_cell_registered_kind_needs_one_agreeing_registration() {
    use fstp_cell::engine::startup::ClusterRole;
    use fstp_cell::process::{RegisteredSpki, registered_role, server_spki_digest};
    let leaf = minted_server_leaf("application");
    let other = minted_server_leaf("application");
    let digest = server_spki_digest(&leaf).unwrap();
    assert_ne!(Some(digest), server_spki_digest(&other));
    let reg = |role| RegisteredSpki { digest, role };
    let elsewhere = RegisteredSpki {
        digest: server_spki_digest(&other).unwrap(),
        role: ClusterRole::Application,
    };
    assert_eq!(registered_role(&leaf, &[]), ClusterRole::Other);
    assert_eq!(registered_role(&leaf, &[elsewhere]), ClusterRole::Other);
    assert_eq!(
        registered_role(&leaf, &[elsewhere, reg(ClusterRole::Application)]),
        ClusterRole::Application
    );
    assert_eq!(
        registered_role(&leaf, &[reg(ClusterRole::Vault)]),
        ClusterRole::Vault
    );
    assert_eq!(
        registered_role(
            &leaf,
            &[reg(ClusterRole::Application), reg(ClusterRole::Application)]
        ),
        ClusterRole::Application
    );
    assert_eq!(
        registered_role(
            &leaf,
            &[reg(ClusterRole::Application), reg(ClusterRole::Vault)]
        ),
        ClusterRole::Other
    );
    assert_eq!(
        registered_role(b"not a certificate", &[reg(ClusterRole::Application)]),
        ClusterRole::Other
    );
}

// ---------------------------------------------------------------------------
// The cell's start path over real clusters (lane m3i83).

/// A custody backend that counts its calls and refuses each one.
#[derive(Clone, Default)]
struct CountingCustody(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl CountingCustody {
    fn refuse<T>(&self) -> std::future::Ready<Result<T, fstp_custody::CustodyError>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Err(fstp_custody::CustodyError::Transport(
            "the I-83 test custody",
        )))
    }

    fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl fstp_custody::Custody for CountingCustody {
    fn create_root(
        &self,
        _label: fstp_custody::RootLabel,
    ) -> impl Future<Output = Result<fstp_custody::RootRef, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }

    fn wrap(
        &self,
        _root: &fstp_custody::RootRef,
        _key: &fstp_custody::SealKey,
        _aad: &fstp_custody::Aad,
    ) -> impl Future<Output = Result<fstp_custody::WrappedSealKey, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }

    fn unwrap(
        &self,
        _root: &fstp_custody::RootRef,
        _w: &fstp_custody::WrappedSealKey,
        _aad: &fstp_custody::Aad,
    ) -> impl Future<Output = Result<fstp_custody::SealKey, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }

    fn destroy(
        &self,
        _root: &fstp_custody::RootRef,
    ) -> impl Future<Output = Result<fstp_custody::DestroyReceipt, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }

    fn sign(
        &self,
        _key: &fstp_custody::SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<fstp_custody::EcdsaSignature, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }

    fn usage_since(
        &self,
        _root: &fstp_custody::RootRef,
        _cursor: fstp_custody::UsageCursor,
    ) -> impl Future<Output = Result<fstp_custody::UsagePage, fstp_custody::CustodyError>> + Send
    {
        self.refuse()
    }
}

/// A vault client that counts its calls and answers each one as
/// unavailable.
#[derive(Clone, Default)]
struct CountingVault(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl CountingVault {
    fn refuse<T>(&self) -> std::future::Ready<Result<T, fstp_cell_core::driver::VaultFault>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Err(fstp_cell_core::driver::VaultFault::Unavailable))
    }

    fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl fstp_cell::engine::VaultClient for CountingVault {
    fn epoch(
        &self,
    ) -> impl Future<
        Output = Result<fstp_domain::id::VaultEpoch, fstp_cell_core::driver::VaultFault>,
    > + Send {
        self.refuse()
    }

    fn ask(
        &self,
        _queries: &[fstp_domain::oracle::Query],
        _reaction_for: Option<fstp_domain::id::VaultEpoch>,
        _at: fstp_domain::time::Timestamp,
    ) -> impl Future<
        Output = Result<fstp_domain::oracle::Answers, fstp_cell_core::driver::VaultFault>,
    > + Send {
        self.refuse()
    }

    fn ack(
        &self,
        _epoch: fstp_domain::id::VaultEpoch,
        _seq: fstp_ledger::Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), fstp_cell_core::driver::VaultFault>> + Send {
        self.refuse()
    }
}

/// A TLS server configuration from the `fstp-tls` fixtures. The start
/// refusals stop before any listener exists.
fn fixture_server_tls() -> fstp_tls::ServerConfig {
    fstp_tls::ServerConfig::builder(
        fstp_pgtest::tls::SERVER_CERT_PEM,
        fstp_pgtest::tls::SERVER_KEY_PEM,
    )
    .build()
    .unwrap()
}

/// What happened when [`start_cell_over`] ran `fstp_cell::process::start`.
struct CellStart {
    result: Result<(), fstp_cell::CellError>,
    custody_calls: usize,
    vault_calls: usize,
}

/// The cell database of `cell` for target `t` on `server`, with the
/// `writer` and `app` logins, which may use every table. A start that
/// passes the I-83 check thus reaches the steps after it instead of a
/// permission error.
fn granted_cell_database(
    server: &'static fstp_pgtest::PgServer,
    t: Target,
    cell: [u8; 16],
) -> Live {
    let live = live_database(server, t, cell, &["writer", "app"]);
    let grants = format!(
        "DO $g$ DECLARE s text; BEGIN \
           FOR s IN SELECT nspname FROM pg_namespace \
             WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema' LOOP \
             EXECUTE format('GRANT USAGE ON SCHEMA %I TO {w}, {a}', s); \
             EXECUTE format('GRANT ALL ON ALL TABLES IN SCHEMA %I TO {w}, {a}', s); \
             EXECUTE format('GRANT ALL ON ALL SEQUENCES IN SCHEMA %I TO {w}, {a}', s); \
           END LOOP; END $g$",
        w = live.logins[0].role,
        a = live.logins[1].role,
    );
    live.server.psql(&live.dbname, &grants).unwrap();
    live
}

/// Runs `fstp_cell::process::start` over the cell database of target
/// `t`, made on the live server whose OU is `t.ou`. The writer login
/// connects to the same database on the live server of `writer_on`: the
/// target's server, or the other one with a database of the same cell.
fn start_cell_over(t: Target, registered: RegisteredBy, writer_on: ClusterKind) -> CellStart {
    use std::sync::Arc;
    let cell = fstp_crypto::random_array::<16>().unwrap();
    let live = granted_cell_database(live_server(t.ou), t, cell);
    let writer = if writer_on == t.ou {
        live.config(0)
    } else {
        granted_cell_database(live_server(writer_on), t, cell).config(0)
    };
    let registered_servers = match registered {
        RegisteredBy::Target => live.cell_registration(),
        RegisteredBy::Nobody => Vec::new(),
    };
    let custody = CountingCustody::default();
    let vault = CountingVault::default();
    let ledger_key = fstp_pgstore::LedgerKey::new(
        1,
        fstp_keys::DekId(fstp_crypto::random_array::<16>().unwrap()),
        fstp_crypto::aead::Key::generate().unwrap(),
    );
    let loopback = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
    let parts = fstp_cell::process::CellProcessParts {
        cell: live.cell,
        mode: fstp_cell::config::Mode::Saas,
        host: "i83.cell.fstp.localhost".to_owned(),
        writer,
        app: live.config(1),
        registered_servers,
        custody: custody.clone(),
        keystore: None,
        keys: fstp_cell::process::CellKeys {
            anchor: fstp_crypto::composite::generate().unwrap(),
            ledger: Arc::new(fstp_pgstore::LedgerKeys::new(ledger_key)),
            cred_lookup: fstp_crypto::random_array::<32>().unwrap(),
        },
        witness: fstp_cell::witness::link::WitnessEndpoint {
            addr: loopback,
            server_name: "witness.fstp.localhost".to_owned(),
            tls: fstp_tls::ClientConfig::mutual(
                fstp_pgtest::tls::CA_PEM,
                fstp_pgtest::tls::CLIENT_CERT_PEM,
                fstp_pgtest::tls::CLIENT_KEY_PEM,
            )
            .unwrap(),
            ca_digest: [0; 32],
        },
        witness_keys: vec![
            fstp_crypto::composite::generate()
                .unwrap()
                .public_key()
                .to_bytes()
                .to_vec(),
        ],
        vault: vault.clone(),
        tunnel_tls: fstp_cell::http::tunnel::TunnelTls {
            tunnel: Arc::new(fixture_server_tls()),
            origin: Arc::new(fixture_server_tls()),
        },
        internal_tls: Arc::new(fixture_server_tls()),
        pages: None,
        listen: fstp_cell::process::Listen {
            tunnel: loopback,
            internal: loopback,
            health: loopback,
        },
    };
    let result = match block_on(fstp_cell::process::start(rt(), parts)) {
        Ok(running) => block_on(running.shutdown(std::time::Duration::from_secs(10))),
        Err(e) => Err(e),
    };
    CellStart {
        result,
        custody_calls: custody.calls(),
        vault_calls: vault.calls(),
    }
}

/// Which registration a live cell start gets.
#[derive(Clone, Copy, Debug)]
enum RegisteredBy {
    /// Both live servers, the target's under the target's SPKI kind.
    Target,
    /// No server key at all.
    Nobody,
}

/// I-83, design section 9.2: `fstp_cell::process::start` refuses an
/// application database on a vault cluster, whose certificate OU is
/// `vault` and whose key is registered for a vault cluster. The refusal
/// comes before custody or the vault is called, so nothing is created
/// for the misplaced database.
#[test]
fn i83_cell_start_refuses_a_vault_cluster_before_custody_or_the_vault() {
    let s = start_cell_over(
        Target {
            marker: 1,
            ou: ClusterKind::Vault,
            spki: ClusterKind::Vault,
        },
        RegisteredBy::Target,
        ClusterKind::Vault,
    );
    assert_eq!(s.result, Err(placement_refusal()));
    assert_eq!((s.custody_calls, s.vault_calls), (0, 0));
}

/// I-83, design section 9.2: the cell refuses a server whose OU names an
/// application cluster when the control plane registered its key for a
/// vault cluster.
#[test]
fn i83_cell_start_refuses_an_application_ou_whose_key_is_registered_for_a_vault_cluster() {
    let s = start_cell_over(
        Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Vault,
        },
        RegisteredBy::Target,
        ClusterKind::Application,
    );
    assert_eq!(s.result, Err(placement_refusal()));
    assert_eq!((s.custody_calls, s.vault_calls), (0, 0));
}

/// I-83, design section 9.2: the cell refuses a server whose key the
/// control plane never registered, though its OU and marker are right.
#[test]
fn i83_cell_start_refuses_an_unregistered_server_key() {
    let s = start_cell_over(
        Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Application,
        },
        RegisteredBy::Nobody,
        ClusterKind::Application,
    );
    assert_eq!(s.result, Err(placement_refusal()));
    assert_eq!((s.custody_calls, s.vault_calls), (0, 0));
}

/// I-83, design section 9.2: the cell checks the server behind its
/// writer pool too. The app login reaches an application cluster, but the
/// writer login reaches a database of the same cell on a vault cluster,
/// so the start refuses before custody or the vault is called.
#[test]
fn i83_cell_start_refuses_a_writer_pool_on_a_vault_cluster() {
    let s = start_cell_over(
        Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Application,
        },
        RegisteredBy::Target,
        ClusterKind::Vault,
    );
    assert_eq!(s.result, Err(placement_refusal()));
    assert_eq!((s.custody_calls, s.vault_calls), (0, 0));
}

/// I-83 control for the refusals above: on an application cluster whose
/// key is registered for an application cluster, the start passes the
/// I-83 check and goes on to the genesis of the key chain, which calls
/// the vault or custody. This test's vault and custody refuse, so the
/// start then fails, but never with the placement refusal.
#[test]
fn i83_cell_start_passes_the_check_on_an_application_cluster() {
    let s = start_cell_over(
        Target {
            marker: 1,
            ou: ClusterKind::Application,
            spki: ClusterKind::Application,
        },
        RegisteredBy::Target,
        ClusterKind::Application,
    );
    assert_ne!(s.result, Err(placement_refusal()));
    assert!(
        s.custody_calls + s.vault_calls > 0,
        "the start stopped before genesis: {:?}",
        s.result
    );
}

/// Synthetic certificates whose subjects hold two OUs, from the
/// `fstp-pgwire` fuzz seeds: `OU=application, OU=vault`,
/// `OU=vault, OU=application`, and one multi-valued RDN
/// `OU=vault + CN=127.0.0.1 + OU=application`.
const TWO_OU_LEAVES: [&[u8]; 3] = [
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/two-ous-application-first"),
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/two-ous"),
    include_bytes!("../../fstp-pgwire/fuzz/seeds/pg_cert_subject_ou/multi-valued-rdn"),
];

/// I-83, design section 9.2: a server certificate whose subject holds
/// two OUs names no cluster kind, whichever OU comes first. So it is no
/// application server even with its key registered for an application
/// cluster only, and the cell's server check refuses it. A certificate
/// with the one OU `application` is one.
#[test]
fn i83_cell_refuses_a_server_certificate_with_two_ous() {
    use fstp_cell::engine::startup::ClusterRole;
    use fstp_cell::process::{
        RegisteredSpki, application_server_check, is_application_server, registered_role,
        server_ou_role, server_spki_digest,
    };
    let one = minted_server_leaf("application");
    let reg = |leaf: &[u8]| {
        [RegisteredSpki {
            digest: server_spki_digest(leaf).unwrap(),
            role: ClusterRole::Application,
        }]
    };
    assert!(is_application_server(&one, &reg(&one)));
    assert!(application_server_check(&reg(&one)).accepts(&one));
    for leaf in TWO_OU_LEAVES {
        let reg = reg(leaf);
        assert_eq!(server_ou_role(leaf), ClusterRole::Other);
        assert_eq!(registered_role(leaf, &reg), ClusterRole::Application);
        assert!(!is_application_server(leaf, &reg));
        assert!(!application_server_check(&reg).accepts(leaf));
    }
}

/// I-83, design section 9.2: a cell pool over a configuration with the
/// cell's server check runs it on every connection, not only on the one
/// `Pool::open` makes. Each new connection of a pool on an application
/// cluster passes it. A pool over the same cell's roles on a vault
/// cluster cannot open, and no connection of it starts a session.
#[test]
fn i83_cell_server_check_holds_every_pool_connection() {
    use fstp_cell::process::application_server_check;
    use fstp_pgstore::{DbFault, Pool, PoolError, Role};
    let app = Target {
        marker: 1,
        ou: ClusterKind::Application,
        spki: ClusterKind::Application,
    };
    let live = live_target(app, "app");
    let check = application_server_check(&live.cell_registration());
    let pool = block_on(Pool::open(
        rt().clone(),
        live.cell,
        Role::App,
        live.config(0).server_check(check.clone()),
        2,
    ))
    .unwrap();
    let held: Vec<_> = (0..2).map(|_| block_on(pool.get()).unwrap()).collect();
    for c in &held {
        assert_eq!(
            c.server_certificate_der(),
            held_leaf(live_server(ClusterKind::Application)).as_slice()
        );
    }
    drop(held);
    let misplaced = live_database(
        live_server(ClusterKind::Vault),
        Target {
            marker: 1,
            ou: ClusterKind::Vault,
            spki: ClusterKind::Vault,
        },
        live.cell,
        &["app"],
    );
    let config = misplaced.config(0).server_check(check);
    let refused = block_on(Pool::open(rt().clone(), live.cell, Role::App, config, 1));
    match refused {
        Err(PoolError::Connect(DbFault {
            kind: fstp_pgwire::ErrorKind::ServerRefused,
            ..
        })) => {}
        other => panic!("the vault cluster pool opened: {:?}", other.err()),
    }
}

// ---------------------------------------------------------------------------
// Worlds.

/// I-83, R-NF-01, design section 1.4: a self-hosted cell runs two
/// PostgreSQL instances with separate data directories, ports and cluster
/// CAs. Its application database lives only on the application instance
/// and its vault database only on the vault instance.
#[test]
fn i83_self_hosted_layout_runs_two_instances() {
    let w = world(1, DbMode::Shared, true);
    let clusters = w.clusters();
    assert_eq!(clusters.len(), 2, "{clusters:?}");
    let (a, v) = (&clusters[0], &clusters[1]);
    assert_eq!(
        (a.kind(), v.kind()),
        (ClusterKind::Application, ClusterKind::Vault)
    );
    assert_ne!(a.server().port(), v.server().port());
    assert_ne!(a.server().dir(), v.server().dir());
    assert_ne!(
        a.server().cluster_ca().map(|c| c.cert_pem().to_vec()),
        v.server().cluster_ca().map(|c| c.cert_pem().to_vec())
    );
    let dbs = w.databases().unwrap();
    let on = |prefix: &str| {
        dbs.iter()
            .filter(|d| db::cell_of(&d.name).is_some() && d.name.starts_with(prefix))
            .map(|d| d.kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(on("c_"), vec![ClusterKind::Application], "{dbs:?}");
    assert_eq!(on("v_"), vec![ClusterKind::Vault], "{dbs:?}");
}

/// I-83, B8: in a SaaS world in shared and in dedicated mode, every vault
/// database sits on a vault cluster and every application database on an
/// application cluster.
#[test]
fn t_db_iso_i83_cell_databases_sit_on_clusters_of_their_kind() {
    for mode in [DbMode::Shared, DbMode::Dedicated] {
        let w = world(3, mode, false);
        let dbs = w.databases().unwrap();
        let cells: Vec<_> = dbs
            .iter()
            .filter(|d| db::cell_of(&d.name).is_some())
            .collect();
        assert_eq!(cells.len(), 6, "{mode:?}: {dbs:?}");
        for d in cells {
            let want = if d.name.starts_with("v_") {
                ClusterKind::Vault
            } else {
                ClusterKind::Application
            };
            assert_eq!(
                d.kind,
                want,
                "{mode:?}: {} on {} ({})",
                d.name,
                d.cluster,
                kind_label(d.kind)
            );
        }
    }
}
