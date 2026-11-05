//! M-PLACE (design section 14.2, I-82, I-83). Lane W1f owns this file.
//!
//! The universe: three clusters of kinds application, vault and control,
//! and two cells. Cluster registration, provisioning in shared and
//! dedicated mode, cell erasure and cluster decommission. Moves between
//! modes are M9 work through export and import (ADR-005), so the model has
//! no move action.
//!
//! The model runs over a [`PlaceBackend`]: [`Reference`], [`Production`]
//! (`fstp_control::placement::Placement::new` and
//! `fstp_control::pg::cell_role_plan`) or a [`Mutant`] with one seeded
//! defect. Every placement and every role plan the model records comes from
//! the backend. The properties judge them by the rules of design sections
//! 4.1 and 9.2, written here on their own.
//!
//! The provisioning environment offers every pair of registered clusters,
//! in either order and the same cluster twice. The mode rule is the
//! environment's: a dedicated cell takes clusters that hold no other cell,
//! and a shared cell takes clusters that hold no dedicated cell.
//!
//! Gap, reported by lane W1f: the stub API has no provisioning planner
//! that takes the mode, so the mode rule is not production code here.
//! Only `Placement::new` and `cell_role_plan` are.
//!
//! The module also holds the reference names and the reference role plan
//! of design section 4.1, which the I-82 tests share.

use std::collections::BTreeSet;

use fstp_control::ControlError;
use fstp_control::pg::{CellDatabase, Privilege, RolePlan};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement, PlacementError};
use fstp_cp_proto::{CellId, RoleName};
use fstp_mc::{Model, Property};

use crate::NotImplemented;

// ---------------------------------------------------------------------------
// Reference names and the reference role plan (design section 4.1).

/// The 32 lowercase hex digits of `cell` (design section 4.1).
pub fn cell_hex(cell: CellId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in cell.0 {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*d));
            }
        }
    }
    out
}

/// The database name of `db` for `cell`: `c_<cell>` or `v_<cell>`.
pub fn database_name(db: CellDatabase, cell: CellId) -> String {
    let prefix = match db {
        CellDatabase::App => "c",
        CellDatabase::Vault => "v",
    };
    format!("{prefix}_{}", cell_hex(cell))
}

/// The login role name of `role` in `db` for `cell`: `<db>_<suffix>`.
pub fn role_name(db: CellDatabase, cell: CellId, role: RoleName) -> String {
    format!("{}_{}", database_name(db, cell), role.suffix())
}

/// Whether `name` is a DDL identifier of the closed grammar
/// `^[cv]_[0-9a-f]{32}$` (design section 4.1, ADR-011).
pub fn is_ddl_identifier(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 34
        && matches!(b.first(), Some(b'c' | b'v'))
        && b.get(1) == Some(&b'_')
        && b.get(2..)
            .is_some_and(|hex| hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

/// The login roles of the application database (design section 4.1).
pub const APP_ROLES: [RoleName; 5] = [
    RoleName::Migrator,
    RoleName::Writer,
    RoleName::App,
    RoleName::Keys,
    RoleName::Auditor,
];

/// The login roles of the vault database (design section 4.1).
pub const VAULT_ROLES: [RoleName; 3] = [RoleName::Migrator, RoleName::Vault, RoleName::Keys];

/// The login roles of `db`.
pub fn roles_of(db: CellDatabase) -> &'static [RoleName] {
    match db {
        CellDatabase::App => &APP_ROLES,
        CellDatabase::Vault => &VAULT_ROLES,
    }
}

/// The tables of the application database, from design section 4.2, and
/// the journey read model of ADR-015 "Storage and roles".
pub const APP_TABLES: [&str; 24] = [
    "ledger.command",
    "ledger.entry",
    "audit.chain",
    "audit.anchor",
    "blob.text",
    "keystore.root",
    "keystore.group_key",
    "keystore.data_key",
    "keystore.erasure_intent",
    "auth.session",
    "auth.challenge",
    "auth.sign_count",
    "auth.token",
    "auth_log.stepup_consumed",
    "auth_log.session_end",
    "ops.outbox",
    "ops.checkpoint",
    "ops.licence_state",
    "journey.entry",
    "journey.entry_text",
    "journey.projection_cursor",
    "journey.leg",
    "journey.route_start",
    "journey.assignment",
];

const SI: &[Privilege] = &[Privilege::Select, Privilege::Insert];
const S: &[Privilege] = &[Privilege::Select];
const FULL: &[Privilege] = &[
    Privilege::Select,
    Privilege::Insert,
    Privilege::Update,
    Privilege::Delete,
];
const SD: &[Privilege] = &[Privilege::Select, Privilege::Delete];

/// The schema part of `schema.table`.
pub fn schema_of(object: &str) -> &str {
    object.split_once('.').map_or(object, |(s, _)| s)
}

/// The privileges design section 4.1 gives `role` on the application
/// table `object`, or an empty slice for none.
///
/// Reading, reported to Daniel by lane W1f: "full rights" are SELECT,
/// INSERT, UPDATE and DELETE, the four privileges of the `apply_grant`
/// grammar. "The stored ledger rows" for the auditor are `ledger.command`
/// and `ledger.entry`. The `keys` role's DELETE on `blob` rows of completed
/// erasures is a table grant on `blob.text`, since row conditions are not
/// in the grammar. It comes with SELECT on `blob.text`: PostgreSQL needs
/// SELECT on the columns a DELETE reads in its WHERE clause, so DELETE
/// alone cannot remove one row by id (I-81). The grammar has no column
/// grants, so the SELECT covers the whole table, sealed envelopes
/// included. The migrator owns every schema and needs no grant.
pub fn app_privileges(role: RoleName, object: &str) -> &'static [Privilege] {
    let schema = schema_of(object);
    match role {
        RoleName::Writer => match schema {
            "ledger" | "auth_log" => SI,
            "audit" if matches!(object, "audit.chain" | "audit.anchor") => SI,
            "ops" if object == "ops.outbox" => SI,
            _ => &[],
        },
        RoleName::App => match schema {
            "ledger" | "audit" | "auth_log" => S,
            "auth" => FULL,
            "ops" if object == "ops.outbox" => S,
            "ops" => FULL,
            "blob" => SI,
            // ADR-015 "Storage and roles": the projector writes
            // append-only journey rows as `app`, INSERT and SELECT only.
            "journey" => SI,
            _ => &[],
        },
        RoleName::Keys => match schema {
            "keystore" => FULL,
            "blob" => SD,
            _ => &[],
        },
        RoleName::Auditor => match schema {
            "audit" | "ledger" => S,
            _ => &[],
        },
        RoleName::Migrator | RoleName::Vault => &[],
    }
}

/// The reference grant rows of the application database: `(role, object,
/// privileges)` for every table of [`APP_TABLES`] a role gets a right on,
/// in table order, then role order.
pub fn app_grants() -> Vec<(RoleName, &'static str, Vec<Privilege>)> {
    let mut out = Vec::new();
    for object in APP_TABLES {
        for role in APP_ROLES {
            let privs = app_privileges(role, object);
            if !privs.is_empty() {
                out.push((role, object, privs.to_vec()));
            }
        }
    }
    out
}

/// The tables of the vault database, from design section 4.3, with the
/// keystore tables of section 4.2. `vault.country_condition` holds the
/// P-17 country conditions, named by Daniel on 2026-10-30 (design 21.0).
pub const VAULT_TABLES: [&str; 15] = [
    "vault.epoch",
    "vault.fact",
    "vault.identity",
    "vault.account",
    "vault.document",
    "vault.negotiation",
    "vault.ticket_used",
    "vault.query_log",
    "vault.country_condition",
    "keystore.root",
    "keystore.group_key",
    "keystore.data_key",
    "keystore.erasure_intent",
    "vault_audit.chain",
    "vault_audit.anchor",
];

/// What the reference pins for `role` on the vault table `object`.
///
/// Reading, reported to Daniel by lane W1f: design section 4.1 gives the
/// vault database "the same pattern" and pins only that `vault_audit.*` is
/// INSERT and SELECT only. Read with the application rows, that pins three
/// things. The `keys` role holds full rights on each keystore table and
/// nothing else. The `vault` role holds exactly INSERT and SELECT on each
/// `vault_audit` table, and at least SELECT and INSERT on each `vault`
/// table. The migrator owns every schema and holds no grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultPin {
    /// Exactly these privileges, and none when the slice is empty.
    Exactly(&'static [Privilege]),
    /// At least these privileges. The rest is open until Daniel pins it.
    AtLeast(&'static [Privilege]),
}

/// The reference pin for `role` on the vault table `object`. A country
/// condition is fixed once set (NOTE 6), so the `vault` role holds exactly
/// SELECT and INSERT on `vault.country_condition`, and no other role holds
/// anything on it.
pub fn vault_pin(role: RoleName, object: &str) -> VaultPin {
    if object == "vault.country_condition" {
        return match role {
            RoleName::Vault => VaultPin::Exactly(SI),
            _ => VaultPin::Exactly(&[]),
        };
    }
    match (role, schema_of(object)) {
        (RoleName::Keys, "keystore") => VaultPin::Exactly(FULL),
        (RoleName::Vault, "vault_audit") => VaultPin::Exactly(SI),
        (RoleName::Vault, "vault") => VaultPin::AtLeast(SI),
        _ => VaultPin::Exactly(&[]),
    }
}

/// A role plan as the model sees it: the cell it names and every database
/// and role name its rows render to (design section 4.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanView {
    /// The cell the plan names.
    pub cell: CellId,
    /// Every rendered database and role name of its role, grant and
    /// `pg_hba` rows.
    pub names: BTreeSet<String>,
    /// The number of rows.
    pub rows: usize,
}

/// The view of a production plan, rendered by the reference names.
pub fn plan_view(plan: &RolePlan) -> PlanView {
    let mut names = BTreeSet::new();
    let cell = plan.cell;
    for r in &plan.roles {
        names.insert(database_name(r.database, cell));
        names.insert(role_name(r.database, cell, r.role));
    }
    for g in &plan.grants {
        names.insert(database_name(g.database, cell));
        names.insert(role_name(g.database, cell, g.role));
    }
    for h in &plan.hba {
        names.insert(database_name(h.database, cell));
        names.insert(role_name(h.database, cell, h.role));
    }
    let rows = plan
        .roles
        .len()
        .saturating_add(plan.grants.len())
        .saturating_add(plan.hba.len());
    PlanView { cell, names, rows }
}

/// The reference view of `cell`'s plan: both databases and every role of
/// [`APP_ROLES`] and [`VAULT_ROLES`].
pub fn reference_plan_view(cell: CellId) -> PlanView {
    let mut names = BTreeSet::new();
    let mut rows = 0usize;
    for db in [CellDatabase::App, CellDatabase::Vault] {
        names.insert(database_name(db, cell));
        for role in roles_of(db) {
            names.insert(role_name(db, cell, *role));
            // One role row and one pg_hba line per role.
            rows = rows.saturating_add(2);
        }
    }
    rows = rows.saturating_add(app_grants().len());
    PlanView { cell, names, rows }
}

// ---------------------------------------------------------------------------
// The universe.

/// The clusters of the universe, by index: their kinds.
pub const KINDS: [ClusterKind; 3] = [
    ClusterKind::Application,
    ClusterKind::Vault,
    ClusterKind::Control,
];

/// The number of clusters.
pub const N_CLUSTERS: u8 = 3;

/// The number of cells.
pub const N_CELLS: u8 = 2;

/// The id of cluster `i`.
pub const fn cluster_id(i: u8) -> ClusterId {
    ClusterId([0xC0 ^ i; 16])
}

/// The id of cell `i`.
pub const fn cell_id(i: u8) -> CellId {
    CellId([0xA0 ^ i; 16])
}

/// Cluster `i` with its kind, or `None` outside the universe.
pub fn cluster(i: u8) -> Option<Cluster> {
    KINDS.get(usize::from(i)).map(|kind| Cluster {
        id: cluster_id(i),
        kind: *kind,
    })
}

/// The index of the cluster with id `id`, if it is in the universe.
pub fn index_of(id: ClusterId) -> Option<u8> {
    (0..N_CLUSTERS).find(|i| cluster_id(*i) == id)
}

/// How a cell is provisioned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// The cell shares clusters with other shared cells.
    Shared,
    /// The cell's clusters hold no other cell.
    Dedicated,
}

/// The registration state of a cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reg {
    /// Not registered yet.
    Unregistered,
    /// Registered: its kind is fixed (I-83).
    Registered,
    /// Decommissioned. A cluster id is never registered again.
    Decommissioned,
}

// ---------------------------------------------------------------------------
// Backends.

/// What M-PLACE asks of the code under test.
pub trait PlaceBackend {
    /// The placement of a cell on `app` and `vault`: the application and
    /// vault cluster ids, or `None` when the placement is refused.
    /// `registry` is every registered cluster, in registration order.
    fn place(
        &self,
        registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, NotImplemented>;

    /// The role plan of `cell`.
    fn plan(&self, cell: CellId) -> Result<PlanView, NotImplemented>;
}

/// The reference rule of design section 9.2: the application cluster is of
/// kind application, the vault cluster of kind vault, and they differ.
pub fn reference_places(app: &Cluster, vault: &Cluster) -> bool {
    app.kind == ClusterKind::Application && vault.kind == ClusterKind::Vault && app.id != vault.id
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl PlaceBackend for Reference {
    fn place(
        &self,
        _registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, NotImplemented> {
        Ok(reference_places(app, vault).then_some((app.id, vault.id)))
    }

    fn plan(&self, cell: CellId) -> Result<PlanView, NotImplemented> {
        Ok(reference_plan_view(cell))
    }
}

/// The production backend: `Placement::new` and `cell_role_plan`. No
/// reference logic stands in for production.
#[derive(Clone, Copy, Debug)]
pub struct Production {
    _probe: (),
}

fn control_ni(e: ControlError) -> NotImplemented {
    #[allow(unreachable_patterns, reason = "lane W2h may add refusal variants")]
    match e {
        ControlError::NotImplemented(op) => NotImplemented::new(op),
        // A refusal of a plan is no plan: the run halts and
        // `backend-answers` fails.
        _ => NotImplemented::new("fstp_control::pg::cell_role_plan refused"),
    }
}

impl Production {
    /// The production backend, once both production calls answer.
    pub fn new() -> Result<Production, NotImplemented> {
        let p = Production { _probe: () };
        let (Some(app), Some(vault)) = (cluster(0), cluster(1)) else {
            return Err(NotImplemented::new("M-PLACE universe has no clusters"));
        };
        p.place(&[app, vault], &app, &vault)?;
        p.plan(cell_id(0))?;
        Ok(p)
    }
}

impl PlaceBackend for Production {
    fn place(
        &self,
        _registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, NotImplemented> {
        match Placement::new(app, vault) {
            Ok(p) => Ok(Some(p.clusters())),
            Err(PlacementError::NotImplemented(op)) => Err(NotImplemented::new(op)),
            // Every other error is a refusal, so a new refusal variant
            // needs no change here.
            Err(_) => Ok(None),
        }
    }

    fn plan(&self, cell: CellId) -> Result<PlanView, NotImplemented> {
        fstp_control::pg::cell_role_plan(cell)
            .map(|p| plan_view(&p))
            .map_err(control_ni)
    }
}

/// A seeded defect of a [`Mutant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceDefect {
    /// The placement takes the first registered cluster other than the
    /// application cluster as the vault cluster, and checks no kind
    /// (design section 14.2 teeth).
    FirstFreeCluster,
    /// Every plan names cell 0, so a second cell's plan reaches the first
    /// cell's databases (`I-82-plan` teeth).
    PlanForFirstCell,
    /// Every plan lacks the rows of the application `keys` role, so the
    /// plan misses a role of design section 4.1 (`I-82-plan` teeth).
    PlanWithoutKeysRole,
}

/// A backend with one seeded defect over an inner backend.
#[derive(Clone, Copy, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: PlaceDefect,
}

impl<B> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: PlaceDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }
}

impl<B: PlaceBackend> PlaceBackend for Mutant<B> {
    fn place(
        &self,
        registry: &[Cluster],
        app: &Cluster,
        vault: &Cluster,
    ) -> Result<Option<(ClusterId, ClusterId)>, NotImplemented> {
        // The inner backend is asked once, so a stub still halts the run.
        let got = self.inner.place(registry, app, vault)?;
        match self.defect {
            PlaceDefect::FirstFreeCluster => Ok(registry
                .iter()
                .find(|c| c.id != app.id)
                .map(|free| (app.id, free.id))),
            PlaceDefect::PlanForFirstCell | PlaceDefect::PlanWithoutKeysRole => Ok(got),
        }
    }

    fn plan(&self, cell: CellId) -> Result<PlanView, NotImplemented> {
        match self.defect {
            PlaceDefect::PlanForFirstCell => {
                self.inner.plan(cell)?;
                self.inner.plan(cell_id(0))
            }
            PlaceDefect::PlanWithoutKeysRole => {
                let mut view = self.inner.plan(cell)?;
                view.names
                    .remove(&role_name(CellDatabase::App, cell, RoleName::Keys));
                Ok(view)
            }
            PlaceDefect::FirstFreeCluster => self.inner.plan(cell),
        }
    }
}

// ---------------------------------------------------------------------------
// The model.

/// A provisioned cell.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Placed {
    /// The application cluster's index, or `None` when the backend named a
    /// cluster outside the universe.
    pub app: Option<u8>,
    /// The vault cluster's index, or `None` as for `app`.
    pub vault: Option<u8>,
    /// The mode.
    pub mode: Mode,
    /// The role plan the backend gave.
    pub plan: PlanView,
}

/// The state of M-PLACE.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlaceState {
    /// Each cluster's registration state, by index.
    pub clusters: [Reg; 3],
    /// Each cell's placement, by index.
    pub cells: [Option<Placed>; 2],
    /// Whether a provisioning that asked for clusters of the wrong kinds,
    /// or one cluster twice, was refused.
    pub refused_mixed: bool,
    /// Whether each cluster, by index, ever held a cell.
    pub hosted: [bool; 3],
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

impl PlaceState {
    /// The state before any registration.
    pub const fn genesis() -> PlaceState {
        PlaceState {
            clusters: [Reg::Unregistered; 3],
            cells: [None, None],
            refused_mixed: false,
            hosted: [false; 3],
            halt: None,
        }
    }

    /// The registration state of cluster `i`.
    pub fn reg(&self, i: u8) -> Option<Reg> {
        self.clusters.get(usize::from(i)).copied()
    }

    /// The placement of cell `c`.
    pub fn placed(&self, c: u8) -> Option<&Placed> {
        self.cells.get(usize::from(c)).and_then(Option::as_ref)
    }

    /// Every registered cluster, in index order.
    pub fn registry(&self) -> Vec<Cluster> {
        (0..N_CLUSTERS)
            .filter(|i| self.reg(*i) == Some(Reg::Registered))
            .filter_map(cluster)
            .collect()
    }

    /// The modes of the cells other than `c` placed on cluster `i`.
    pub fn others_on(&self, i: u8, c: u8) -> Vec<Mode> {
        (0..N_CELLS)
            .filter(|o| *o != c)
            .filter_map(|o| self.placed(o))
            .filter(|p| p.app == Some(i) || p.vault == Some(i))
            .map(|p| p.mode)
            .collect()
    }

    /// Whether any cell is placed on cluster `i`.
    pub fn in_use(&self, i: u8) -> bool {
        (0..N_CELLS)
            .filter_map(|c| self.placed(c))
            .any(|p| p.app == Some(i) || p.vault == Some(i))
    }
}

/// An action of M-PLACE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlaceAction {
    /// Register cluster `i`.
    Register(u8),
    /// Provision cell `cell` on application cluster `app` and vault
    /// cluster `vault` in `mode`.
    Provision {
        /// The cell.
        cell: u8,
        /// The requested application cluster.
        app: u8,
        /// The requested vault cluster.
        vault: u8,
        /// The mode.
        mode: Mode,
    },
    /// Erase cell `c`: its databases go, its clusters stay.
    Erase(u8),
    /// Decommission cluster `i`, which holds no cell.
    Decommission(u8),
}

/// M-PLACE over a backend.
#[derive(Debug)]
pub struct PlaceModel<B> {
    backend: B,
}

impl<B: PlaceBackend> PlaceModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> PlaceModel<B> {
        PlaceModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn provision(
        &self,
        s: &PlaceState,
        cell: u8,
        app: u8,
        vault: u8,
        mode: Mode,
    ) -> Option<PlaceState> {
        if s.placed(cell).is_some() || s.halt.is_some() {
            return None;
        }
        if s.reg(app) != Some(Reg::Registered) || s.reg(vault) != Some(Reg::Registered) {
            return None;
        }
        // The environment's mode rule.
        let fits = |i: u8| {
            let others = s.others_on(i, cell);
            match mode {
                Mode::Dedicated => others.is_empty(),
                Mode::Shared => !others.contains(&Mode::Dedicated),
            }
        };
        if !fits(app) || !fits(vault) {
            return None;
        }
        let (app_c, vault_c) = (cluster(app)?, cluster(vault)?);
        let mut next = s.clone();
        match self.backend.place(&s.registry(), &app_c, &vault_c) {
            Err(e) => next.halt = Some(e.operation),
            Ok(None) => {
                if !reference_places(&app_c, &vault_c) {
                    next.refused_mixed = true;
                }
            }
            Ok(Some((a, v))) => match self.backend.plan(cell_id(cell)) {
                Err(e) => next.halt = Some(e.operation),
                Ok(plan) => {
                    for i in [index_of(a), index_of(v)].into_iter().flatten() {
                        if let Some(h) = next.hosted.get_mut(usize::from(i)) {
                            *h = true;
                        }
                    }
                    let slot = next.cells.get_mut(usize::from(cell))?;
                    *slot = Some(Placed {
                        app: index_of(a),
                        vault: index_of(v),
                        mode,
                        plan,
                    });
                }
            },
        }
        Some(next)
    }
}

impl<B: PlaceBackend> Model for PlaceModel<B> {
    type State = PlaceState;
    type Action = PlaceAction;

    fn init(&self) -> Vec<PlaceState> {
        vec![PlaceState::genesis()]
    }

    fn actions(&self, s: &PlaceState, out: &mut Vec<PlaceAction>) {
        if s.halt.is_some() {
            return;
        }
        for i in 0..N_CLUSTERS {
            out.push(PlaceAction::Register(i));
            out.push(PlaceAction::Decommission(i));
        }
        for cell in 0..N_CELLS {
            for app in 0..N_CLUSTERS {
                for vault in 0..N_CLUSTERS {
                    for mode in [Mode::Shared, Mode::Dedicated] {
                        out.push(PlaceAction::Provision {
                            cell,
                            app,
                            vault,
                            mode,
                        });
                    }
                }
            }
            out.push(PlaceAction::Erase(cell));
        }
    }

    fn step(&self, s: &PlaceState, a: &PlaceAction) -> Option<PlaceState> {
        match *a {
            PlaceAction::Register(i) => {
                if s.reg(i) != Some(Reg::Unregistered) {
                    return None;
                }
                let mut next = s.clone();
                *next.clusters.get_mut(usize::from(i))? = Reg::Registered;
                Some(next)
            }
            PlaceAction::Decommission(i) => {
                if s.reg(i) != Some(Reg::Registered) || s.in_use(i) {
                    return None;
                }
                let mut next = s.clone();
                *next.clusters.get_mut(usize::from(i))? = Reg::Decommissioned;
                Some(next)
            }
            PlaceAction::Provision {
                cell,
                app,
                vault,
                mode,
            } => self.provision(s, cell, app, vault, mode),
            PlaceAction::Erase(c) => {
                s.placed(c)?;
                let mut next = s.clone();
                *next.cells.get_mut(usize::from(c))? = None;
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &PlaceState) -> bool {
        // Every state is a legitimate end: the operator may stop anywhere.
        let _ = s;
        true
    }
}

/// The property ids of M-PLACE.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-83 over every placement.
    pub const I83: &str = "I-83";
    /// I-82 over every role plan.
    pub const I82_PLAN: &str = "I-82-plan";
    /// The backend's verdict equals the reference verdict, both ways.
    pub const TWO_WAY: &str = "two-way";
    /// Two shared cells on one application cluster.
    pub const W_SHARED: &str = "witness-two-shared-cells-on-one-cluster";
    /// A dedicated cell is placed.
    pub const W_DEDICATED: &str = "witness-dedicated-cell-placed";
    /// A provisioning with the wrong kinds or one cluster twice is refused.
    pub const W_REFUSED: &str = "witness-mixed-placement-refused";
    /// A cluster that held a cell is decommissioned once the cell is erased.
    pub const W_DECOMMISSION: &str = "witness-decommission-after-erase";
}

/// Why placement `p` breaks I-83 in `s`, if it does.
pub fn i83_breach(s: &PlaceState, p: &Placed) -> Option<String> {
    let (Some(app), Some(vault)) = (p.app, p.vault) else {
        return Some(format!(
            "I-83: a placement names a cluster outside the universe: {p:?}"
        ));
    };
    if app == vault {
        return Some(format!(
            "I-83: one cluster {app} holds both databases of a cell"
        ));
    }
    let kind = |i: u8| KINDS.get(usize::from(i)).copied();
    if kind(app) != Some(ClusterKind::Application) {
        return Some(format!(
            "I-83: the application database is on cluster {app} of kind {:?}",
            kind(app)
        ));
    }
    if kind(vault) != Some(ClusterKind::Vault) {
        return Some(format!(
            "I-83: the vault database is on cluster {vault} of kind {:?}",
            kind(vault)
        ));
    }
    for i in [app, vault] {
        if s.reg(i) != Some(Reg::Registered) {
            return Some(format!(
                "I-83: cluster {i} holds a cell but is {:?}",
                s.reg(i)
            ));
        }
    }
    None
}

/// Why the plans of `s` break I-82, if they do: a plan names another cell,
/// is empty, renders another set of names than [`reference_plan_view`] of
/// its cell, or shares a name with another cell's plan.
///
/// [`plan_view`] renders every name from the plan's cell, so a plan with
/// the right cell renders only names of that cell. The name set still
/// shows a plan that lacks a role or a database. The row count is not
/// compared: the reference counts no vault grant rows, since design
/// section 4.1 does not pin them. The shape of the rows is checked by
/// `i82_role_plan_matches_design_section_4_1`.
pub fn i82_plan_breach(s: &PlaceState) -> Option<String> {
    let placed: Vec<(u8, &Placed)> = (0..N_CELLS)
        .filter_map(|c| s.placed(c).map(|p| (c, p)))
        .collect();
    for (c, p) in &placed {
        let want = cell_id(*c);
        if p.plan.cell != want {
            return Some(format!(
                "I-82-plan: the plan of cell {c} names cell {:?}",
                p.plan.cell
            ));
        }
        if p.plan.rows == 0 || p.plan.names.is_empty() {
            return Some(format!("I-82-plan: the plan of cell {c} is empty"));
        }
        let reference = reference_plan_view(want);
        if let Some(n) = p.plan.names.difference(&reference.names).next() {
            return Some(format!(
                "I-82-plan: the plan of cell {c} renders {n}, which is not its own"
            ));
        }
        if let Some(n) = reference.names.difference(&p.plan.names).next() {
            return Some(format!(
                "I-82-plan: the plan of cell {c} has no row for {n}"
            ));
        }
    }
    for (i, (c, p)) in placed.iter().enumerate() {
        for (d, q) in placed.iter().skip(i.saturating_add(1)) {
            if let Some(n) = p.plan.names.intersection(&q.plan.names).next() {
                return Some(format!(
                    "I-82-plan: the plans of cells {c} and {d} both reach {n}"
                ));
            }
        }
    }
    None
}

fn two_way(s: &PlaceState, a: &PlaceAction, t: &PlaceState) -> Result<(), String> {
    let PlaceAction::Provision {
        cell, app, vault, ..
    } = *a
    else {
        return Ok(());
    };
    if t.halt.is_some() {
        return Ok(());
    }
    let (Some(app_c), Some(vault_c)) = (cluster(app), cluster(vault)) else {
        return Ok(());
    };
    let want = reference_places(&app_c, &vault_c);
    let got = s.placed(cell).is_none() && t.placed(cell).is_some();
    if got == want {
        return Ok(());
    }
    Err(format!(
        "two-way: provisioning cell {cell} on clusters {app} ({:?}) and {vault} ({:?}): \
         the backend placed it: {got}, the reference: {want}",
        app_c.kind, vault_c.kind
    ))
}

/// The properties of M-PLACE.
pub fn properties<'a, B: PlaceBackend>(_m: &'a PlaceModel<B>) -> Vec<Property<'a, PlaceModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &PlaceState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::always_with(ids::I83, |s: &PlaceState| {
            match (0..N_CELLS)
                .filter_map(|c| s.placed(c))
                .find_map(|p| i83_breach(s, p))
            {
                None => Ok(()),
                Some(why) => Err(why),
            }
        }),
        Property::always_with(ids::I82_PLAN, |s: &PlaceState| match i82_plan_breach(s) {
            None => Ok(()),
            Some(why) => Err(why),
        }),
        Property::transition_with(ids::TWO_WAY, two_way),
        Property::reachable(ids::W_SHARED, |s: &PlaceState| {
            match (s.placed(0), s.placed(1)) {
                (Some(a), Some(b)) => {
                    a.mode == Mode::Shared && b.mode == Mode::Shared && a.app == b.app
                }
                _ => false,
            }
        }),
        Property::reachable(ids::W_DEDICATED, |s: &PlaceState| {
            (0..N_CELLS)
                .filter_map(|c| s.placed(c))
                .any(|p| p.mode == Mode::Dedicated)
        }),
        Property::reachable(ids::W_REFUSED, |s: &PlaceState| s.refused_mixed),
        Property::reachable(ids::W_DECOMMISSION, |s: &PlaceState| {
            s.clusters
                .iter()
                .zip(s.hosted)
                .any(|(r, h)| *r == Reg::Decommissioned && h)
        }),
    ]
}

// ---------------------------------------------------------------------------
// Database support for the W1f tests over real clusters.

/// Support for the I-16, I-19, I-82, I-83 and R-NF tests that run over
/// real `fstp-pgtest` clusters: migration sets, catalogue reads, the
/// isolation auditor's scalar rows, logins as a cell role, and the
/// reference cross-cell path check.
///
/// Every query expands arrays on the server, so each row is scalar text.
/// Every helper returns an error string and never panics.
pub mod db {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};

    use fstp_control::isolation_audit::{
        CatalogueRows, DatabaseGrant, HbaRule, Membership, PrivilegeGraph, RoleAttrs,
    };
    use fstp_control::placement::ClusterKind;
    use fstp_migrate::catalogue::TableSpec;
    use fstp_pgtest::PgServer;

    /// One migration set and the catalogue its owner exports (design
    /// sections 4.5 and 4.6).
    #[derive(Clone, Copy, Debug)]
    pub struct MigrationSet {
        /// The owning crate's directory under `crates/`.
        pub krate: &'static str,
        /// The set's directory under `migrations/`.
        pub set: &'static str,
        /// The kind of cluster the set runs on.
        pub kind: ClusterKind,
        /// The owner's catalogue.
        pub catalogue: &'static [TableSpec],
    }

    /// Every migration set of M3, in the order of design section 4.6.
    pub fn migration_sets() -> [MigrationSet; 5] {
        [
            MigrationSet {
                krate: "fstp-pgstore",
                set: "app",
                kind: ClusterKind::Application,
                catalogue: fstp_pgstore::CATALOGUE,
            },
            MigrationSet {
                krate: "fstp-vault",
                set: "vault",
                kind: ClusterKind::Vault,
                catalogue: fstp_vault::CATALOGUE,
            },
            MigrationSet {
                krate: "fstp-control",
                set: "cp",
                kind: ClusterKind::Control,
                catalogue: fstp_control::CATALOGUE,
            },
            MigrationSet {
                krate: "fstp-witness",
                set: "witness",
                kind: ClusterKind::Witness,
                catalogue: fstp_witness::CATALOGUE,
            },
            MigrationSet {
                krate: "fstp-release-svc",
                set: "licence",
                kind: ClusterKind::Control,
                catalogue: fstp_release_svc::CATALOGUE,
            },
        ]
    }

    /// The workspace root.
    pub fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The `.sql` files of `set`, sorted by name.
    ///
    /// # Errors
    ///
    /// Fails when the directory is missing, unreadable or empty, so a test
    /// over a missing set is red and never vacuous.
    pub fn migration_files(set: &MigrationSet) -> Result<Vec<PathBuf>, String> {
        let dir = workspace_root()
            .join("crates")
            .join(set.krate)
            .join("migrations")
            .join(set.set);
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            format!(
                "the migration set crates/{}/migrations/{} is missing: {e}",
                set.krate, set.set
            )
        })?;
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!(
                "the migration set crates/{}/migrations/{} holds no .sql file",
                set.krate, set.set
            ));
        }
        Ok(files)
    }

    fn unique(prefix: &str) -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{}_{n}", std::process::id())
    }

    /// Creates a fresh database on `server` and returns its name. The name
    /// never matches the cell database grammar.
    ///
    /// # Errors
    ///
    /// Returns psql's error.
    pub fn fresh_database(server: &PgServer, prefix: &str) -> Result<String, String> {
        let name = unique(prefix);
        server
            .psql("postgres", &format!("CREATE DATABASE {name}"))
            .map_err(|e| e.to_string())?;
        Ok(name)
    }

    /// Applies every file of `set` to `dbname` as the superuser, in order.
    ///
    /// # Errors
    ///
    /// Fails for a missing set or a failing statement.
    pub fn apply_set(server: &PgServer, dbname: &str, set: &MigrationSet) -> Result<(), String> {
        for file in migration_files(set)? {
            let sql =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            server
                .psql(dbname, &sql)
                .map_err(|e| format!("{}: {e}", file.display()))?;
        }
        Ok(())
    }

    /// A fresh database on `server` with `set` applied.
    ///
    /// # Errors
    ///
    /// As [`fresh_database`] and [`apply_set`].
    pub fn migrated(server: &PgServer, set: &MigrationSet) -> Result<String, String> {
        let db = fresh_database(server, &format!("w1f_{}", set.set))?;
        apply_set(server, &db, set)?;
        Ok(db)
    }

    /// The schemas of the server that no catalogue lists.
    pub const SYSTEM_SCHEMAS: [&str; 3] = ["pg_catalog", "information_schema", "pg_toast"];

    /// Every user table of `dbname` with its columns in order, keyed by
    /// `(schema, table)`. Views count as tables.
    ///
    /// # Errors
    ///
    /// Returns psql's error.
    pub fn table_columns(
        server: &PgServer,
        dbname: &str,
    ) -> Result<BTreeMap<(String, String), Vec<String>>, String> {
        let rows = server
            .psql(
                dbname,
                "SELECT table_schema || '|' || table_name || '|' || column_name \
                 FROM information_schema.columns \
                 WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
                 ORDER BY table_schema, table_name, ordinal_position",
            )
            .map_err(|e| e.to_string())?;
        let mut out: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for line in rows.lines().filter(|l| !l.is_empty()) {
            let mut parts = line.splitn(3, '|');
            let (Some(s), Some(t), Some(c)) = (parts.next(), parts.next(), parts.next()) else {
                return Err(format!("bad column row {line:?}"));
            };
            out.entry((s.to_owned(), t.to_owned()))
                .or_default()
                .push(c.to_owned());
        }
        Ok(out)
    }

    /// The tables and columns of `catalogue`, keyed as [`table_columns`]
    /// keys them.
    pub fn catalogue_columns(catalogue: &[TableSpec]) -> BTreeMap<(String, String), Vec<String>> {
        catalogue
            .iter()
            .map(|t| {
                (
                    (t.schema.to_owned(), t.name.to_owned()),
                    t.columns.iter().map(|c| c.name.to_owned()).collect(),
                )
            })
            .collect()
    }

    /// The differences between a database's tables and a catalogue, one
    /// line each. Empty when they are equal, column for column.
    pub fn catalogue_diff(
        db: &BTreeMap<(String, String), Vec<String>>,
        cat: &BTreeMap<(String, String), Vec<String>>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (k, cols) in db {
            match cat.get(k) {
                None => out.push(format!("{}.{} is not catalogued", k.0, k.1)),
                Some(want) if want != cols => out.push(format!(
                    "{}.{} has columns {cols:?}, the catalogue lists {want:?}",
                    k.0, k.1
                )),
                Some(_) => {}
            }
        }
        for k in cat.keys() {
            if !db.contains_key(k) {
                out.push(format!(
                    "{}.{} is catalogued but no migration creates it",
                    k.0, k.1
                ));
            }
        }
        out
    }

    fn rows(text: &str, fields: usize) -> Result<Vec<Vec<&str>>, String> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let parts: Vec<&str> = l.split('|').collect();
                if parts.len() == fields {
                    Ok(parts)
                } else {
                    Err(format!("bad catalogue row {l:?}"))
                }
            })
            .collect()
    }

    fn field<'a>(row: &[&'a str], i: usize) -> &'a str {
        row.get(i).copied().unwrap_or_default()
    }

    fn flag(row: &[&str], i: usize) -> bool {
        field(row, i) == "t"
    }

    /// One `pg_hba_file_rules` row with each array member on its own row,
    /// with the options the auditor's [`HbaRule`] leaves out.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct HbaRow {
        /// The rule as the auditor takes it.
        pub rule: HbaRule,
        /// The netmask, empty when the address carries its own.
        pub netmask: String,
        /// The options joined by commas, such as `clientcert=verify-full`.
        pub options: String,
    }

    /// The `pg_hba_file_rules` of `server`, unnested on the server.
    ///
    /// # Errors
    ///
    /// Fails for a rule with an error, or psql's error.
    pub fn hba_rows(server: &PgServer) -> Result<Vec<HbaRow>, String> {
        let errors = server
            .psql(
                "postgres",
                "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
            )
            .map_err(|e| e.to_string())?;
        if errors != "0" {
            return Err(format!("pg_hba.conf has {errors} rules with errors"));
        }
        let text = server
            .psql(
                "postgres",
                "SELECT r.line_number::text, r.type, d, u, coalesce(r.address, ''), \
                 coalesce(r.netmask, ''), coalesce(r.auth_method, ''), \
                 coalesce(array_to_string(r.options, ','), '') \
                 FROM pg_hba_file_rules r \
                 CROSS JOIN LATERAL unnest(coalesce(r.database, ARRAY['']::text[])) d \
                 CROSS JOIN LATERAL unnest(coalesce(r.user_name, ARRAY['']::text[])) u \
                 ORDER BY r.line_number, d, u",
            )
            .map_err(|e| e.to_string())?;
        rows(&text, 8)?
            .into_iter()
            .map(|r| {
                Ok(HbaRow {
                    rule: HbaRule {
                        line: field(&r, 0)
                            .parse()
                            .map_err(|_| format!("bad line number in {r:?}"))?,
                        kind: field(&r, 1).to_owned(),
                        database: field(&r, 2).to_owned(),
                        user: field(&r, 3).to_owned(),
                        address: field(&r, 4).to_owned(),
                        method: field(&r, 6).to_owned(),
                    },
                    netmask: field(&r, 5).to_owned(),
                    options: field(&r, 7).to_owned(),
                })
            })
            .collect()
    }

    /// The names of every database of `server` that takes connections.
    ///
    /// # Errors
    ///
    /// Returns psql's error.
    pub fn databases(server: &PgServer) -> Result<Vec<String>, String> {
        Ok(server
            .psql(
                "postgres",
                "SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname",
            )
            .map_err(|e| e.to_string())?
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// The scalar catalogue rows of `server` that the isolation auditor
    /// reads (design section 9.3). A NULL `datacl` reads as the default
    /// ACL, so PUBLIC's default CONNECT is not missed.
    ///
    /// Gap, reported by lane W1f: the reading job is `fstp-pgagent`'s and
    /// has no stub, so these queries stand in for it. `pg_extension` is per
    /// database, and the rows hold every database's extension names.
    ///
    /// # Errors
    ///
    /// Returns psql's error or a malformed row.
    pub fn catalogue_rows(server: &PgServer) -> Result<CatalogueRows, String> {
        let q = |sql: &str| server.psql("postgres", sql).map_err(|e| e.to_string());
        let roles = rows(
            &q(
                "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, \
                rolbypassrls, rolcanlogin FROM pg_roles ORDER BY rolname",
            )?,
            7,
        )?
        .into_iter()
        .map(|r| RoleAttrs {
            name: field(&r, 0).to_owned(),
            superuser: flag(&r, 1),
            createrole: flag(&r, 2),
            createdb: flag(&r, 3),
            replication: flag(&r, 4),
            bypassrls: flag(&r, 5),
            login: flag(&r, 6),
        })
        .collect();
        let memberships = rows(
            &q("SELECT m.rolname, r.rolname FROM pg_auth_members a \
                JOIN pg_roles m ON m.oid = a.member JOIN pg_roles r ON r.oid = a.roleid \
                ORDER BY 1, 2")?,
            2,
        )?
        .into_iter()
        .map(|r| Membership {
            member: field(&r, 0).to_owned(),
            role: field(&r, 1).to_owned(),
        })
        .collect();
        let database_grants = rows(
            &q(
                "SELECT d.datname, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE g.rolname END, \
                a.privilege_type FROM pg_database d \
                CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a \
                LEFT JOIN pg_roles g ON g.oid = a.grantee ORDER BY 1, 2, 3",
            )?,
            3,
        )?
        .into_iter()
        .map(|r| DatabaseGrant {
            database: field(&r, 0).to_owned(),
            grantee: field(&r, 1).to_owned(),
            privilege: field(&r, 2).to_owned(),
        })
        .collect();
        let mut extensions = BTreeSet::new();
        for db in databases(server)? {
            let names = server
                .psql(&db, "SELECT extname FROM pg_extension ORDER BY 1")
                .map_err(|e| e.to_string())?;
            extensions.extend(names.lines().filter(|l| !l.is_empty()).map(str::to_owned));
        }
        let hba = hba_rows(server)?.into_iter().map(|h| h.rule).collect();
        Ok(CatalogueRows {
            roles,
            memberships,
            database_grants,
            extensions: extensions.into_iter().collect(),
            hba,
        })
    }

    /// Each cycle's home cell, from the cell hexes whose databases changed
    /// during each cycle, keyed by the cycle's index.
    ///
    /// `CellHandle` names no cell id, so the T-ISO sweeps learn each home
    /// from its cycle. A background task of another cell, such as the
    /// licence refresh, the erasure runner or a keystore snapshot (design
    /// sections 2.5 and 9.6), may write during a cycle. So a cycle may
    /// change more than its own cell. Rule: while some cycle without a home
    /// has exactly one changed cell that is no other cycle's home, that
    /// cell becomes its home. Two cycles never share a home. A cycle that
    /// is left without one is not in the map.
    pub fn match_homes(changes: &[BTreeSet<String>]) -> BTreeMap<usize, String> {
        let mut homes: BTreeMap<usize, String> = BTreeMap::new();
        loop {
            let taken: BTreeSet<&String> = homes.values().collect();
            let mut next = None;
            for (i, mine) in changes.iter().enumerate() {
                if homes.contains_key(&i) {
                    continue;
                }
                let left: Vec<&String> = mine.iter().filter(|h| !taken.contains(h)).collect();
                if let [hex] = left.as_slice() {
                    next = Some((i, (*hex).clone()));
                    break;
                }
            }
            let Some((i, hex)) = next else {
                return homes;
            };
            homes.insert(i, hex);
        }
    }

    /// The cell hex of a cell database or role name: the 32 hex digits
    /// after `c_` or `v_`.
    pub fn cell_of(name: &str) -> Option<&str> {
        let rest = name
            .strip_prefix("c_")
            .or_else(|| name.strip_prefix("v_"))?;
        let hex = rest.get(..32)?;
        let tail = rest.get(32..)?;
        let ok = hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && (tail.is_empty() || tail.starts_with('_'));
        ok.then_some(hex)
    }

    /// The node a SUPERUSER role reaches in the privilege graph. A
    /// superuser needs no CONNECT grant and reads every file of the
    /// cluster, so it reaches every database.
    ///
    /// Reading, reported by lane W1f: design section 9.3 has the auditor
    /// read `pg_roles`, so its graph carries the attribute. The reference
    /// names it with this node, as `role -> attribute:superuser`. A
    /// production graph must hold that edge too (two-way check).
    pub const SUPERUSER_NODE: &str = "attribute:superuser";

    /// The edges the rows imply on their own: each membership as
    /// `member -> role`, each CONNECT grant as `grantee -> database`, and
    /// each SUPERUSER role as `role ->` [`SUPERUSER_NODE`]. A production
    /// graph must hold each of them (two-way check).
    ///
    /// A member of a role can `SET ROLE` to it, since PostgreSQL 16 gives
    /// a grant the SET option by default. So a membership chain that ends
    /// in a SUPERUSER role is a path to every database.
    pub fn reference_edges(rows: &CatalogueRows) -> BTreeSet<(String, String)> {
        let mut out = BTreeSet::new();
        for m in &rows.memberships {
            out.insert((m.member.clone(), m.role.clone()));
        }
        for g in &rows.database_grants {
            if g.privilege == "CONNECT" {
                out.insert((g.grantee.clone(), g.database.clone()));
            }
        }
        for r in rows.roles.iter().filter(|r| r.superuser) {
            out.insert((r.name.clone(), SUPERUSER_NODE.to_owned()));
        }
        out
    }

    /// The predefined roles that read, write or signal across databases, or
    /// reach the server's files (design section 4.1).
    pub const CROSS_DATABASE_ROLES: [&str; 8] = [
        "pg_read_all_data",
        "pg_write_all_data",
        "pg_read_all_stats",
        "pg_monitor",
        "pg_signal_backend",
        "pg_read_server_files",
        "pg_write_server_files",
        "pg_execute_server_program",
    ];

    /// Every path in `graph` from a cell's role to another cell's database
    /// or role, one line each.
    ///
    /// Reading, reported by lane W1f: an edge from `PUBLIC` is an edge from
    /// every role, as PostgreSQL grants it. Edges are followed
    /// transitively, so a membership chain is a path. A predefined role of
    /// [`CROSS_DATABASE_ROLES`] and the [`SUPERUSER_NODE`] reach every
    /// database of the cluster, so a path to one is a cross-cell path too.
    pub fn cross_cell_paths(graph: &PrivilegeGraph) -> Vec<String> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for e in &graph.edges {
            adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
        }
        let mut starts: BTreeSet<&str> = BTreeSet::new();
        for e in &graph.edges {
            for n in [e.from.as_str(), e.to.as_str()] {
                if cell_of(n).is_some() && n.len() > 34 {
                    starts.insert(n);
                }
            }
        }
        let mut out = Vec::new();
        for start in starts {
            let Some(own) = cell_of(start) else { continue };
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut todo: Vec<&str> = vec![start, "PUBLIC"];
            while let Some(n) = todo.pop() {
                if !seen.insert(n) {
                    continue;
                }
                if let Some(next) = adj.get(n) {
                    todo.extend(next.iter().copied());
                }
            }
            for n in seen {
                if CROSS_DATABASE_ROLES.contains(&n) || n == SUPERUSER_NODE {
                    out.push(format!("{start} reaches {n}, which crosses every database"));
                }
                if let Some(other) = cell_of(n)
                    && other != own
                {
                    out.push(format!("{start} reaches {n}"));
                }
            }
        }
        out
    }

    fn private_dir() -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join(unique("fstp-w1f-login"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| e.to_string())?;
        Ok(dir)
    }

    fn write_private(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf, String> {
        let path = dir.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        f.write_all(data).map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// A client credential: a password and a PEM certificate and key.
    #[derive(Clone)]
    pub struct Credential {
        /// The role name.
        pub role: String,
        /// The password.
        pub password: String,
        /// The client certificate (PEM).
        pub cert_pem: Vec<u8>,
        /// Its key (PEM).
        pub key_pem: Vec<u8>,
    }

    impl std::fmt::Debug for Credential {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Credential")
                .field("role", &self.role)
                .finish_non_exhaustive()
        }
    }

    /// Runs `sql` in `dbname` on `server` as `who`, over TLS verify-full
    /// against `root_ca_pem`, and returns the output or psql's error.
    /// `who` set to `None` connects with no client certificate.
    ///
    /// # Errors
    ///
    /// Returns psql's standard error when the login or the statement fails.
    pub fn run_as(
        server: &PgServer,
        root_ca_pem: &[u8],
        who: &Credential,
        with_cert: bool,
        dbname: &str,
        sql: &str,
    ) -> Result<String, String> {
        let home = private_dir()?;
        let result = (|| {
            let root = write_private(&home, "root.pem", root_ca_pem)?;
            let mut cmd = Command::new(server.bindir().join("psql"));
            cmd.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .env("HOME", &home)
                .env("PGPASSWORD", &who.password)
                .env("PGSSLMODE", "verify-full")
                .env("PGSSLROOTCERT", &root)
                .env("PGCONNECT_TIMEOUT", "10");
            if with_cert {
                cmd.env(
                    "PGSSLCERT",
                    write_private(&home, "client.pem", &who.cert_pem)?,
                )
                .env(
                    "PGSSLKEY",
                    write_private(&home, "client-key.pem", &who.key_pem)?,
                );
            } else {
                cmd.env("PGSSLCERT", home.join("none.pem"))
                    .env("PGSSLKEY", home.join("none-key.pem"));
            }
            let out = cmd
                .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
                .args(["-h", server.host(), "-p", &server.port().to_string()])
                .args(["-U", &who.role, "-d", dbname, "-c", sql])
                .stdin(Stdio::null())
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
            }
        })();
        let _ = std::fs::remove_dir_all(&home);
        result
    }

    /// Takes over the login role `role` of `server` as an attacker who
    /// holds its credentials would: a new random password set by the
    /// superuser, and a client certificate for `role` from the server's
    /// own cluster CA. No privilege of the role changes.
    ///
    /// # Errors
    ///
    /// Fails for a server without a cluster CA, a name outside the role
    /// grammar, or psql's error.
    pub fn take_over(server: &PgServer, role: &str) -> Result<Credential, String> {
        if !role
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!("not a role name: {role:?}"));
        }
        let ca = server.cluster_ca().ok_or("the server has no cluster CA")?;
        let issued = ca.issue_role(role).map_err(|e| e.to_string())?;
        let mut raw = [0u8; 16];
        fstp_crypto::random_bytes(&mut raw).map_err(|_| "random source failed".to_owned())?;
        let password = super::cell_hex(fstp_cp_proto::CellId(raw));
        server
            .psql(
                "postgres",
                &format!("ALTER ROLE {role} PASSWORD '{password}'"),
            )
            .map_err(|e| e.to_string())?;
        Ok(Credential {
            role: role.to_owned(),
            password,
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
        })
    }

    /// Who a store of a world belongs to (I-19, I-20).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum StoreOwner {
        /// A store of one cell database alone: its relation files or its
        /// dump. The value is the cell's 32 hex digits.
        Database(String),
        /// An egress capture inside cell `i`: from the cell or its vault to
        /// that cell's own vault.
        CellInternal(u8),
        /// Everything else: other egress captures, shared cluster files
        /// such as WAL and the server log, the control plane, the witness
        /// and every shared log sink.
        Outside,
    }

    fn egress_cell(label: &str, kind: &str) -> Option<u8> {
        label.strip_prefix(kind)?.strip_prefix('-')?.parse().ok()
    }

    /// The owner of the store named `store`, given the world's databases.
    pub fn store_owner(store: &str, dbs: &[crate::world::WorldDatabase]) -> StoreOwner {
        if let Some(rest) = store.strip_prefix("egress/") {
            let mut parts = rest.split('/');
            let (from, to) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let from_cell = egress_cell(from, "cell").or_else(|| egress_cell(from, "vault"));
            return match (from_cell, egress_cell(to, "vault")) {
                (Some(a), Some(b)) if a == b => StoreOwner::CellInternal(a),
                _ => StoreOwner::Outside,
            };
        }
        dbs.iter()
            .filter(|d| d.owns(store))
            .find_map(|d| cell_of(&d.name).map(|h| StoreOwner::Database(h.to_owned())))
            .unwrap_or(StoreOwner::Outside)
    }

    /// The stores of each cell's databases, keyed by the cell's hex.
    pub fn stores_by_cell(
        stores: &crate::scan::StoreSet,
        dbs: &[crate::world::WorldDatabase],
    ) -> BTreeMap<String, crate::scan::StoreSet> {
        let mut out: BTreeMap<String, crate::scan::StoreSet> = BTreeMap::new();
        for (name, bytes) in &stores.stores {
            if let StoreOwner::Database(hex) = store_owner(name, dbs) {
                out.entry(hex)
                    .or_default()
                    .push(name.clone(), bytes.clone());
            }
        }
        out
    }

    /// The stores outside every cell: [`StoreOwner::Outside`].
    pub fn outside_stores(
        stores: &crate::scan::StoreSet,
        dbs: &[crate::world::WorldDatabase],
    ) -> crate::scan::StoreSet {
        let mut out = crate::scan::StoreSet::default();
        for (name, bytes) in &stores.stores {
            if store_owner(name, dbs) == StoreOwner::Outside {
                out.push(name.clone(), bytes.clone());
            }
        }
        out
    }

    /// The login roles of `server` whose names follow the cell role
    /// grammar, sorted.
    ///
    /// # Errors
    ///
    /// Returns psql's error.
    pub fn cell_login_roles(server: &PgServer) -> Result<Vec<String>, String> {
        Ok(server
            .psql(
                "postgres",
                "SELECT rolname FROM pg_roles WHERE rolcanlogin \
                 AND rolname ~ '^[cv]_[0-9a-f]{32}_[a-z]+$' ORDER BY 1",
            )
            .map_err(|e| e.to_string())?
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-82, design section 4.1: the reference names follow the DDL
    /// grammar and name only the cell.
    #[test]
    fn i82_reference_names_follow_the_ddl_grammar() {
        let cell = CellId([0x5a; 16]);
        assert_eq!(cell_hex(cell), "5a".repeat(16));
        assert!(is_ddl_identifier(&database_name(CellDatabase::App, cell)));
        assert!(is_ddl_identifier(&database_name(CellDatabase::Vault, cell)));
        assert!(!is_ddl_identifier("c_ACME"));
        assert!(!is_ddl_identifier(&format!("x_{}", "0".repeat(32))));
        assert!(!is_ddl_identifier(&format!("c_{}", "0".repeat(31))));
        assert_eq!(
            role_name(CellDatabase::Vault, cell, RoleName::Keys),
            format!("v_{}_keys", "5a".repeat(16))
        );
    }

    /// A self-test bound well above the measured count. The model runs in
    /// the lane's tests bind it at twice the measured count instead.
    fn self_test_bound() -> fstp_mc::Config {
        fstp_mc::Config::default()
            .with_stop_when_decided(false)
            .with_max_states(1_000_000)
    }

    fn self_test<B: PlaceBackend>(backend: B) -> fstp_mc::Outcome<PlaceState, PlaceAction> {
        let model = PlaceModel::new(backend);
        let props = properties(&model);
        fstp_mc::check(&model, &props, &self_test_bound())
    }

    /// I-83, I-82, design section 14.1: M-PLACE over the reference is
    /// exhaustive, every property holds and every witness is reachable.
    #[test]
    fn i83_m_place_self_test_reference_passes() {
        let outcome = self_test(Reference);
        assert!(outcome.exhaustive, "{outcome}");
        assert!(outcome.require_all_passed().is_ok(), "{outcome}");
    }

    /// I-83 teeth self-test: the first-free-cluster mutant breaks I-83 on
    /// the reference.
    #[test]
    fn i83_m_place_self_test_first_free_cluster_is_caught() {
        let outcome = self_test(Mutant::new(Reference, PlaceDefect::FirstFreeCluster));
        assert!(
            matches!(
                outcome.verdict(ids::I83),
                Some(fstp_mc::Verdict::Violated(_))
            ),
            "{outcome}"
        );
    }

    /// I-82 teeth self-test: the plan-for-the-first-cell mutant breaks
    /// `I-82-plan` on the reference.
    #[test]
    fn i82_m_place_self_test_plan_for_first_cell_is_caught() {
        let outcome = self_test(Mutant::new(Reference, PlaceDefect::PlanForFirstCell));
        assert!(
            matches!(
                outcome.verdict(ids::I82_PLAN),
                Some(fstp_mc::Verdict::Violated(_))
            ),
            "{outcome}"
        );
    }

    /// I-82 teeth self-test: a plan that lacks the `keys` role of the
    /// application database breaks `I-82-plan` on the reference.
    #[test]
    fn i82_m_place_self_test_plan_without_a_role_is_caught() {
        let outcome = self_test(Mutant::new(Reference, PlaceDefect::PlanWithoutKeysRole));
        assert!(
            matches!(
                outcome.verdict(ids::I82_PLAN),
                Some(fstp_mc::Verdict::Violated(_))
            ),
            "{outcome}"
        );
    }

    /// The state count of M-PLACE over the reference, measured by lane W1f.
    /// The lead records it as `M_PLACE` in `mc::tripwires`.
    const MEASURED: usize = 107;

    fn tripwire_bound() -> fstp_mc::Config {
        fstp_mc::Config::default()
            .with_stop_when_decided(false)
            .with_max_states(crate::mc::tripwires::tripwire(MEASURED))
    }

    fn at_tripwire<B: PlaceBackend>(backend: B) -> fstp_mc::Outcome<PlaceState, PlaceAction> {
        let model = PlaceModel::new(backend);
        let props = properties(&model);
        fstp_mc::check(&model, &props, &tripwire_bound())
    }

    /// An over-denial backend: it refuses every placement.
    struct RefusesAll;

    impl PlaceBackend for RefusesAll {
        fn place(
            &self,
            _registry: &[Cluster],
            _app: &Cluster,
            _vault: &Cluster,
        ) -> Result<Option<(ClusterId, ClusterId)>, NotImplemented> {
            Ok(None)
        }

        fn plan(&self, cell: CellId) -> Result<PlanView, NotImplemented> {
            Reference.plan(cell)
        }
    }

    /// I-83, design section 14.1: the measured count is the size of the
    /// reference state space, and the reference passes at its tripwire.
    #[test]
    fn i83_m_place_self_test_measured_count_and_tripwire() {
        let space = fstp_mc::explore(&PlaceModel::new(Reference), &fstp_mc::Config::default());
        assert!(space.exhaustive);
        assert_eq!(space.len(), MEASURED);
        let outcome = at_tripwire(Reference);
        assert!(outcome.exhaustive, "{outcome}");
        assert!(outcome.require_all_passed().is_ok(), "{outcome}");
    }

    /// I-83 and I-82 teeth self-test: under the tripwire bound each seeded
    /// defect still fails its property, and over-denial loses the witness.
    /// The first-free-cluster mutant reaches 591 states, so the bound stops
    /// it, but only after its depth-3 counterexample.
    #[test]
    fn i83_m_place_self_test_teeth_hold_at_the_tripwire() {
        let first_free = at_tripwire(Mutant::new(Reference, PlaceDefect::FirstFreeCluster));
        assert!(
            matches!(
                first_free.verdict(ids::I83),
                Some(fstp_mc::Verdict::Violated(_))
            ),
            "{first_free}"
        );
        let plan_first = at_tripwire(Mutant::new(Reference, PlaceDefect::PlanForFirstCell));
        assert!(
            matches!(
                plan_first.verdict(ids::I82_PLAN),
                Some(fstp_mc::Verdict::Violated(_))
            ),
            "{plan_first}"
        );
        let refuses = at_tripwire(RefusesAll);
        assert!(refuses.exhaustive, "{refuses}");
        assert!(
            matches!(
                refuses.verdict(ids::W_SHARED),
                Some(fstp_mc::Verdict::Unreachable)
            ),
            "{refuses}"
        );
    }

    /// I-82, ADR-007, design section 4.1: the reference writer holds INSERT
    /// and SELECT only, and only the keys role reaches the keystore.
    #[test]
    fn i82_reference_writer_holds_insert_and_select_only() {
        for (role, object, privs) in app_grants() {
            if role == RoleName::Writer {
                assert_eq!(privs, SI, "{object}");
            }
            if schema_of(object) == "keystore" {
                assert_eq!(role, RoleName::Keys, "{object}");
            }
        }
    }

    /// I-82, I-81, design section 4.1: the reference keys role holds SELECT
    /// and DELETE on `blob.text`, so it can delete one erased row by id,
    /// and nothing else on `blob`.
    #[test]
    fn i82_reference_keys_role_can_delete_a_blob_row_by_id() {
        let blob: Vec<(&str, Vec<Privilege>)> = app_grants()
            .into_iter()
            .filter(|(r, o, _)| *r == RoleName::Keys && schema_of(o) == "blob")
            .map(|(_, o, p)| (o, p))
            .collect();
        assert_eq!(
            blob,
            vec![("blob.text", vec![Privilege::Select, Privilege::Delete])]
        );
    }
}
