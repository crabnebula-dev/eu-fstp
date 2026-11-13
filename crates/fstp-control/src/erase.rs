//! `fstp-control erase-cell`: the cell's erasure after the P-46 retrieval
//! period (R-SW-02, design section 3.7, ADR-004 "CA keys in custody",
//! I-81). Lanes m3/erase-cell and m3/erase-cell-2.
//!
//! The job runs only as an [`ApprovedJob`] of two operators
//! ([`crate::approval`]). [`erase_cell_steps`] then runs the steps of
//! design section 3.7 in order, and reports each one as it finishes
//! ([`ErasureEvent`]):
//!
//! 1. destroys every live root of the cell's App, Vault and CellBackup
//!    chains, and the cell CA sign key, in custody, keeping each receipt;
//! 2. has `fstp-pgagent` drop both cell databases and their roles, each
//!    drop approved by two operators and checked again by the agent, and
//!    rewrite `pg_hba.conf` on both clusters ([`CellDatabases`]);
//! 3. removes every route of the cell at the edge ([`EdgeRoutes`]);
//! 4. issues the erasure confirmation, composite-signed by the control
//!    plane, which lists every destroyed key with its receipt.
//!
//! [`erase_cell`] runs steps 1 and 4 only.
//!
//! Every copy of the cell's keys, in any backup, WAL archive or replica,
//! is sealed under a chain whose roots are then gone, so no copy restores
//! the cell (I-81). Each custody call is announced to the caller with its
//! request id before it is made (ADR-004 "Reconciliation").
//!
//! Interim, pending Daniel (ADR-004 records of lanes m3/erase-cell and
//! m3/erase-cell-2):
//!
//! - Destroying a CA sign key is [`SignKeyCustody`], outside the six
//!   operations of the `Custody` trait (I-80). The test custody and the
//!   file custody client implement it. `fstp-keyd` holds no sign key
//!   yet, so it answers `NoSignKey`.
//! - The key list is input. In production it comes from
//!   `cp.custody_entry` and the backend's listing, which is not built.
//! - Step 2 does not delete the cell's object storage prefix or its
//!   witness credentials, which are not built. Step 3 reaches an edge in
//!   the same process only, since the route feed to `fstp-edge` is not
//!   designed.

use std::collections::BTreeSet;
use std::future::Future;

use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_custody::{
    Chain, Custody, CustodyError, DestroyReceipt, RequestId, RootRef, SignKeyRef, with_request,
};

use crate::ControlError;
use crate::agent::JobOutcome;
use crate::approval::{ApprovedJob, DestructiveJob, JobDigest};
use crate::pg::CellDatabase;
use crate::pgagent::{DbIdent, PgagentJob};
use crate::placement::{ClusterId, Placement};

/// The composite signature context of an erasure confirmation.
pub const CONFIRMATION_CONTEXT: &[u8] = b"fstp-cell-erasure-v1";

/// The magic that opens the signed body of a confirmation.
const CONFIRMATION_MAGIC: &[u8; 4] = b"FCE1";

/// The chains a cell erasure destroys (design section 3.7 step 1).
pub const CELL_CHAINS: [Chain; 3] = [Chain::App, Chain::Vault, Chain::CellBackup];

/// A finished step of a cell erasure, as the approval log records it
/// (design section 3.7). It holds ids and counts only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureStep {
    /// Step 1: every listed root and CA key of the cell is destroyed in
    /// custody.
    KeysDestroyed {
        /// The number of keys destroyed.
        count: u16,
    },
    /// Step 2: `fstp-pgagent` dropped one of the cell's databases.
    DatabaseDropped {
        /// The cluster.
        cluster: ClusterId,
        /// The database.
        database: CellDatabase,
    },
    /// Step 2: `fstp-pgagent` dropped the roles of one of the cell's
    /// databases.
    RolesDropped {
        /// The cluster.
        cluster: ClusterId,
        /// The database.
        database: CellDatabase,
    },
    /// Step 2: `fstp-pgagent` rewrote the cluster's `pg_hba.conf`, which
    /// no longer holds a line of the cell.
    HbaRewritten {
        /// The cluster.
        cluster: ClusterId,
    },
    /// Step 3: the edge removed every route of the cell.
    RoutesRemoved {
        /// The number of routes removed.
        count: u16,
    },
}

/// Destroys a CA sign key in custody (ADR-004 "CA keys in custody").
/// Kept apart from the six operations of the `Custody` trait (I-80).
pub trait SignKeyCustody: Send + Sync + 'static {
    /// Destroys the sign key and returns the backend's receipt.
    fn destroy_sign_key(
        &self,
        key: &SignKeyRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send;
}

/// The file custody client destroys a sign key through its own request
/// (`fstp_custody::KeydCustody::destroy_sign_key`). Interim, pending
/// Daniel: `fstp-keyd` holds no sign key yet, since no request creates
/// one, so it answers `NoSignKey`.
impl SignKeyCustody for fstp_custody::KeydCustody {
    fn destroy_sign_key(
        &self,
        key: &SignKeyRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        fstp_custody::KeydCustody::destroy_sign_key(self, key)
    }
}

/// The custody keys of one cell that its erasure destroys.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellKeys {
    /// Every live root of the cell's App, Vault and CellBackup chains.
    pub roots: Vec<RootRef>,
    /// The cell CA sign keys, the next one of a rollover included.
    pub ca: Vec<SignKeyRef>,
}

/// One destroyed key in a confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasedKey {
    /// The chain of a root, or `None` for a CA sign key.
    pub chain: Option<Chain>,
    /// The custody handle.
    pub handle: Vec<u8>,
    /// The backend's destroy receipt.
    pub receipt: DestroyReceipt,
}

/// The erasure confirmation the tenant receives (R-SW-02, design section
/// 3.7 step 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureConfirmation {
    /// The erased cell.
    pub cell: CellId,
    /// When the last key was destroyed, in seconds.
    pub erased_at: i64,
    /// The digest of the approved job.
    pub job: JobDigest,
    /// The requester, then the second approver.
    pub approvers: [StaffRef; 2],
    /// Every destroyed key, in the order destroyed.
    pub keys: Vec<ErasedKey>,
    /// The control plane's composite signature over [`Self::body`].
    pub signature: Vec<u8>,
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), ControlError> {
    let len = u16::try_from(b.len()).map_err(|_| ControlError::Job("erasure field length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

impl ErasureConfirmation {
    /// The signed body: the magic, the cell, the time, the job digest,
    /// both approvers, then a count and each key as its chain code (0 for
    /// a CA key), its handle and its receipt, each with a 16-bit length.
    /// One spelling per confirmation.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] when a handle, a receipt or the key count
    /// exceeds 65 535.
    pub fn body(&self) -> Result<Vec<u8>, ControlError> {
        let mut out = CONFIRMATION_MAGIC.to_vec();
        out.extend_from_slice(&self.cell.0);
        out.extend_from_slice(&self.erased_at.to_be_bytes());
        out.extend_from_slice(&self.job.0);
        for s in self.approvers {
            out.extend_from_slice(&s.0);
        }
        let n = u16::try_from(self.keys.len()).map_err(|_| ControlError::Job("erasure keys"))?;
        out.extend_from_slice(&n.to_be_bytes());
        for k in &self.keys {
            out.push(k.chain.map_or(0, Chain::code));
            push_bytes(&mut out, &k.handle)?;
            push_bytes(&mut out, &k.receipt.0)?;
        }
        Ok(out)
    }
}

/// Whether `c` carries a composite signature of the control-plane key
/// `public_key` over its body. Both halves must verify (I-90).
pub fn verify_erasure_confirmation(public_key: &[u8], c: &ErasureConfirmation) -> bool {
    c.body().is_ok_and(|body| {
        composite::verify_with_context(public_key, &body, CONFIRMATION_CONTEXT, &c.signature)
            .is_ok()
    })
}

/// Checks that `keys` are the cell's own: every root names `cell` and one
/// of [`CELL_CHAINS`], each of those chains has a root, a CA key is
/// there, and no handle repeats.
///
/// # Errors
///
/// [`ControlError::Job`] naming the rule broken.
pub fn check_cell_keys(cell: CellId, keys: &CellKeys) -> Result<(), ControlError> {
    let mut seen = BTreeSet::new();
    for r in &keys.roots {
        if r.cell.map(|c| c.0) != Some(cell.0) {
            return Err(ControlError::Job("a root of another cell"));
        }
        if !CELL_CHAINS.contains(&r.chain) {
            return Err(ControlError::Job("a root outside the cell chains"));
        }
        if !seen.insert(r.handle.0.clone()) {
            return Err(ControlError::Job("a key listed twice"));
        }
    }
    for k in &keys.ca {
        if !seen.insert(k.handle.0.clone()) {
            return Err(ControlError::Job("a key listed twice"));
        }
    }
    if CELL_CHAINS
        .iter()
        .any(|c| !keys.roots.iter().any(|r| r.chain == *c))
    {
        return Err(ControlError::Job("a cell chain without a root"));
    }
    if keys.ca.is_empty() {
        return Err(ControlError::Job("no cell CA key"));
    }
    Ok(())
}

/// The cell of the approved `erase-cell` job.
fn erased_cell(approved: &ApprovedJob) -> Result<CellId, ControlError> {
    match approved.job() {
        DestructiveJob::EraseCell { cell } => Ok(*cell),
        DestructiveJob::Pgagent(_) => Err(ControlError::ApprovalRequired),
    }
}

/// Design section 3.7 step 1: destroys `keys` in `custody`, roots first,
/// then CA keys. `announce` receives each call's request id before the
/// call.
async fn destroy_keys<C: Custody + SignKeyCustody>(
    custody: &C,
    keys: &CellKeys,
    mut announce: impl FnMut([u8; 16]),
) -> Result<Vec<ErasedKey>, ControlError> {
    let mut erased = Vec::new();
    for root in &keys.roots {
        let id = RequestId::generate().map_err(ControlError::Custody)?;
        announce(id.0);
        let receipt = with_request(id, || custody.destroy(root))
            .await
            .map_err(ControlError::Custody)?;
        erased.push(ErasedKey {
            chain: Some(root.chain),
            handle: root.handle.0.clone(),
            receipt,
        });
    }
    for key in &keys.ca {
        let id = RequestId::generate().map_err(ControlError::Custody)?;
        announce(id.0);
        let receipt = with_request(id, || custody.destroy_sign_key(key))
            .await
            .map_err(ControlError::Custody)?;
        erased.push(ErasedKey {
            chain: None,
            handle: key.handle.0.clone(),
            receipt,
        });
    }
    Ok(erased)
}

/// Design section 3.7 step 4: the confirmation of the destroyed keys,
/// signed by the control-plane key `signer` at `now`.
fn confirm(
    cell: CellId,
    approved: &ApprovedJob,
    erased: Vec<ErasedKey>,
    signer: &CompositeSigningKey,
    now: i64,
) -> Result<ErasureConfirmation, ControlError> {
    let mut confirmation = ErasureConfirmation {
        cell,
        erased_at: now,
        job: approved.digest(),
        approvers: approved.approvers(),
        keys: erased,
        signature: Vec::new(),
    };
    let body = confirmation.body()?;
    confirmation.signature = signer
        .sign_with_context(&body, CONFIRMATION_CONTEXT)
        .map_err(|_| ControlError::Job("the confirmation signature"))?
        .to_bytes()
        .to_vec();
    Ok(confirmation)
}

/// Runs the approved erasure of the cell: destroys `keys` in `custody`,
/// then signs the confirmation with the control-plane key `signer` at
/// `now`. `announce` receives each custody call's request id before the
/// call is made. Design steps 1 and 4 only: [`erase_cell_steps`] runs
/// steps 2 and 3 between them.
///
/// A key already gone stops the job with its refusal and no
/// confirmation. Interim: such a retry needs the backend's receipt of the
/// earlier destroy, which no backend reads back yet.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] when `approved` is not this cell's
/// erasure. [`ControlError::Job`] from [`check_cell_keys`].
/// [`ControlError::Custody`] when custody refuses a destroy.
pub async fn erase_cell<C: Custody + SignKeyCustody>(
    custody: &C,
    approved: &ApprovedJob,
    keys: &CellKeys,
    signer: &CompositeSigningKey,
    now: i64,
    announce: impl FnMut([u8; 16]),
) -> Result<ErasureConfirmation, ControlError> {
    let cell = erased_cell(approved)?;
    check_cell_keys(cell, keys)?;
    let erased = destroy_keys(custody, keys, announce).await?;
    confirm(cell, approved, erased, signer, now)
}

// ---------------------------------------------------------------------------
// Design section 3.7 steps 2 and 3 (lane m3/erase-cell-2).

/// The `fstp-pgagent` of each self-operated cluster, as `fstp-control`
/// reaches it (design section 3.7 step 2).
pub trait CellDatabases {
    /// Sends the approved destructive agent job `job` to the agent of its
    /// cluster, with the evidence of both approvals, and returns the
    /// agent's outcome.
    fn run_approved(
        &self,
        job: &ApprovedJob,
    ) -> impl Future<Output = Result<JobOutcome, ControlError>>;

    /// Sends the non-destructive job `job` to the agent of `cluster`.
    fn run(
        &self,
        cluster: ClusterId,
        job: &PgagentJob,
    ) -> impl Future<Output = Result<JobOutcome, ControlError>>;
}

/// The edge's route feed (design section 3.7 step 3). Interim, pending
/// Daniel: the feed from `fstp-control` to a remote `fstp-edge` is not
/// designed, and `fstp_edge::run` refuses to start without it. An edge in
/// the same process removes routes through `fstp_edge::LiveRoutes`.
pub trait EdgeRoutes {
    /// Removes every route of `cell`, including `id.<cell host>`, and
    /// returns the number removed. A cell without routes removes none.
    fn remove_cell(&self, cell: CellId) -> impl Future<Output = Result<u16, ControlError>>;
}

/// What a cell erasure reports while it runs: a custody call before it is
/// made, and each step after it finished. The caller logs both, as
/// `OperatorLogin::log_custody_call` and `OperatorLogin::log_step` do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureEvent {
    /// The request id of a custody call about to be made.
    CustodyCall([u8; 16]),
    /// A finished step.
    Step(ErasureStep),
}

/// The destructive agent jobs that design section 3.7 step 2 runs for
/// `cell` on `placement`, in order: on the application cluster, then on
/// the vault cluster, the database drop and then its roles.
pub fn database_drop_jobs(cell: CellId, placement: &Placement) -> [(ClusterId, PgagentJob); 4] {
    let (app, vault) = placement.clusters();
    let a = DbIdent::new(CellDatabase::App, cell);
    let v = DbIdent::new(CellDatabase::Vault, cell);
    [
        (app, PgagentJob::DropCellDatabase(a)),
        (app, PgagentJob::DropRoles(a)),
        (vault, PgagentJob::DropCellDatabase(v)),
        (vault, PgagentJob::DropRoles(v)),
    ]
}

/// The approved jobs of [`database_drop_jobs`], in its order, from
/// `agent_jobs`. Each must be there exactly once, carry the evidence the
/// agent checks, and no other job may be there.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] naming no job: a missing, extra,
/// repeated or evidence-less approved job.
fn ordered_drop_jobs<'a>(
    cell: CellId,
    placement: &Placement,
    agent_jobs: &'a [ApprovedJob],
) -> Result<Vec<&'a ApprovedJob>, ControlError> {
    let want = database_drop_jobs(cell, placement);
    if agent_jobs.len() != want.len() {
        return Err(ControlError::ApprovalRequired);
    }
    let mut out = Vec::with_capacity(want.len());
    for (cluster, job) in want {
        let digest = crate::approval::job_digest(&DestructiveJob::pgagent(cluster, job)?);
        let mut found = agent_jobs.iter().filter(|j| j.digest() == digest);
        let (Some(j), None) = (found.next(), found.next()) else {
            return Err(ControlError::ApprovalRequired);
        };
        crate::agent::approved_frame(j)?;
        out.push(j);
    }
    Ok(out)
}

fn agent_done(outcome: JobOutcome) -> Result<(), ControlError> {
    match outcome {
        JobOutcome::Done => Ok(()),
        JobOutcome::Refused(_) | JobOutcome::Failed => {
            Err(ControlError::Job("a cell database job did not run"))
        }
    }
}

fn count16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Runs the approved erasure of the cell in the order of design section
/// 3.7, and reports each step through `report`:
///
/// 1. destroys `keys` in `custody`, every custody call announced first;
/// 2. on each cluster of `placement`, application first, has
///    `fstp-pgagent` drop the cell's database, then its roles, then
///    rewrite `pg_hba.conf`, through `databases`. Each drop is one of
///    `agent_jobs`, approved by two operators, which the agent checks
///    again itself;
/// 3. removes every route of the cell through `edge`;
/// 4. signs the confirmation with `signer` at `now`.
///
/// Every check runs before step 1: the erasure job, the keys, and the
/// four approved drops of [`database_drop_jobs`] with their evidence. So
/// a job that would stop at step 2 for want of an approval destroys
/// nothing. Step 2 deletes neither the object storage prefix nor the
/// witness credentials, which are not built. Interim, pending Daniel: a
/// failure after step 1 stops the job with no confirmation, and the log
/// shows the last finished step. Resuming it needs the job state in
/// `cp.job`.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] for an erasure of another kind and
/// for agent jobs that are not exactly the four drops, each with its
/// evidence. The errors of [`check_cell_keys`]. [`ControlError::Custody`]
/// when custody refuses a destroy. [`ControlError::Job`] when an agent job
/// does not finish, and the errors of `databases` and `edge`.
#[allow(clippy::too_many_arguments)]
pub async fn erase_cell_steps<C, D, E>(
    custody: &C,
    databases: &D,
    edge: &E,
    approved: &ApprovedJob,
    agent_jobs: &[ApprovedJob],
    placement: &Placement,
    keys: &CellKeys,
    signer: &CompositeSigningKey,
    now: i64,
    mut report: impl FnMut(ErasureEvent),
) -> Result<ErasureConfirmation, ControlError>
where
    C: Custody + SignKeyCustody,
    D: CellDatabases,
    E: EdgeRoutes,
{
    let cell = erased_cell(approved)?;
    check_cell_keys(cell, keys)?;
    let drops = ordered_drop_jobs(cell, placement, agent_jobs)?;

    let erased = destroy_keys(custody, keys, |id| {
        report(ErasureEvent::CustodyCall(id));
    })
    .await?;
    report(ErasureEvent::Step(ErasureStep::KeysDestroyed {
        count: count16(erased.len()),
    }));

    let (app, vault) = placement.clusters();
    for (cluster, pair) in [(app, drops.get(0..2)), (vault, drops.get(2..4))] {
        let [db_job, roles_job] = pair.unwrap_or_default() else {
            return Err(ControlError::ApprovalRequired);
        };
        let database = match db_job.job() {
            DestructiveJob::Pgagent(a) => match a.job() {
                PgagentJob::DropCellDatabase(d) => d.database(),
                _ => return Err(ControlError::ApprovalRequired),
            },
            DestructiveJob::EraseCell { .. } => return Err(ControlError::ApprovalRequired),
        };
        agent_done(databases.run_approved(db_job).await?)?;
        report(ErasureEvent::Step(ErasureStep::DatabaseDropped {
            cluster,
            database,
        }));
        agent_done(databases.run_approved(roles_job).await?)?;
        report(ErasureEvent::Step(ErasureStep::RolesDropped {
            cluster,
            database,
        }));
        agent_done(databases.run(cluster, &PgagentJob::WriteHba).await?)?;
        report(ErasureEvent::Step(ErasureStep::HbaRewritten { cluster }));
    }

    let removed = edge.remove_cell(cell).await?;
    report(ErasureEvent::Step(ErasureStep::RoutesRemoved {
        count: removed,
    }));

    confirm(cell, approved, erased, signer, now)
}
