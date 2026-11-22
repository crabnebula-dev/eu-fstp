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
//!    rewrite `pg_hba.conf` on both clusters ([`CellDatabases`]). Then it
//!    revokes the cell at the witness ([`WitnessCredentials`],
//!    [`WitnessRegistry`]). It deletes no object of the cell's object
//!    storage prefix (ADR-004, Daniel's night decision of 2026-11-15):
//!    step 1 made every backup unreadable (I-81), and bucket lifecycle
//!    rules remove the objects later (ADR-005, ADR-012);
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
//!   file custody client implement it. `fstp-keyd` holds sign keys in
//!   sign-key slots of its key table, and a destroy overwrites the key
//!   in place (lane m3/erase-prod). `OkmsCustody` does not implement it.
//! - The key list is input. In production it comes from
//!   `cp.custody_entry` and the backend's listing, which is not built.
//! - Step 3 reaches remote edges through [`crate::routes::RemoteEdges`],
//!   or an edge in the same process.

use std::collections::BTreeSet;
use std::future::Future;

use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_custody::{
    Chain, Custody, CustodyError, DestroyReceipt, RequestId, RootRef, SignKeyRef, with_request,
};

use crate::ControlError;
use crate::agent::JobOutcome;
use crate::approval::{ApprovalBatch, ApprovedJob, DestructiveJob, JobDigest};
use crate::pg::CellDatabase;
use crate::pgagent::{DbIdent, PgagentJob};
use crate::placement::{ClusterId, Placement};

/// The composite signature context of an erasure confirmation.
pub const CONFIRMATION_CONTEXT: &[u8] = b"fstp-cell-erasure-v1";

/// The magic that opens the signed body of a confirmation.
const CONFIRMATION_MAGIC: &[u8; 4] = b"FCE1";

/// The chains a cell erasure destroys (design section 3.7 step 1).
pub const CELL_CHAINS: [Chain; 3] = [Chain::App, Chain::Vault, Chain::CellBackup];

/// The chain a cell erasure also destroys when the cell has a root on it:
/// the vault's snapshot key (ADR-004 record of lane L17). A pilot with no
/// bucket has none, so it is not required as [`CELL_CHAINS`] are.
pub const OPTIONAL_CELL_CHAINS: [Chain; 1] = [Chain::VaultBackup];

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
    /// Step 2: the witness revoked the cell (ADR-004, 2026-11-15 late).
    WitnessCellRevoked,
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
/// (`fstp_custody::KeydCustody::destroy_sign_key`). `fstp-keyd` keeps each
/// sign key in a sign-key slot of its key table and overwrites it in place
/// (ADR-004 "Decided by Daniel, 2026-11-15 (late)").
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
/// of [`CELL_CHAINS`] or [`OPTIONAL_CELL_CHAINS`], each of the first has a root, a CA key is
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
        if !CELL_CHAINS.contains(&r.chain) && !OPTIONAL_CELL_CHAINS.contains(&r.chain) {
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

/// The edge's route feed (design section 3.7 step 3). Remote edges poll
/// a signed, versioned route table, and [`crate::routes::RemoteEdges`]
/// finishes removal once every edge reports a version without the cell
/// (ADR-004 "Decided by Daniel, 2026-11-15 (late)"). An edge in the same
/// process removes routes through `fstp_edge::LiveRoutes`, as the test
/// world does.
pub trait EdgeRoutes {
    /// Removes every route of `cell`, including `id.<cell host>`, and
    /// returns the number removed. A cell without routes removes none.
    fn remove_cell(&self, cell: CellId) -> impl Future<Output = Result<u16, ControlError>>;
}

/// The cell's credentials at the witness (design section 3.7 step 2,
/// ADR-004 "Decided by Daniel, 2026-11-15 (late)"). The witness appends a
/// revocation record beside `witness.cell_ca` and refuses the revoked
/// cell from then on. `witness.cell_ca` stays append-only, and the anchor
/// rows keep their references. The cell's secret key material, its CA
/// key and the anchor keys sealed under its App and Vault chains, is
/// destroyed through custody in step 1.
pub trait WitnessCredentials {
    /// Revokes `cell` at the witness, so the witness no longer accepts
    /// the cell's client certificates or any request of the cell. A
    /// second revocation changes nothing.
    fn revoke_cell(&self, cell: CellId) -> impl Future<Output = Result<(), ControlError>>;
}

/// The SaaS witness database, as `fstp-control` reaches it to revoke a
/// cell (R-SW-02). It logs in as `witness_migrator`, as provisioning does
/// to register a cell, since `witness_service` only reads the registry.
/// The witness refuses the cell from its next request on
/// (`fstp_witness::store::revoke_cell`).
pub struct WitnessRegistry<R: fstp_rt::Runtime> {
    rt: R,
    login: fstp_pgwire::Config,
}

impl<R: fstp_rt::Runtime> WitnessRegistry<R> {
    /// The registry of the witness database that `login` reaches, as
    /// `witness_migrator`, on `rt`.
    pub fn new(rt: R, login: fstp_pgwire::Config) -> WitnessRegistry<R> {
        WitnessRegistry { rt, login }
    }
}

impl<R: fstp_rt::Runtime> std::fmt::Debug for WitnessRegistry<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessRegistry").finish_non_exhaustive()
    }
}

/// UTC microseconds now, the time unit of the witness registry.
fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

impl<R: fstp_rt::Runtime> WitnessCredentials for WitnessRegistry<R> {
    async fn revoke_cell(&self, cell: CellId) -> Result<(), ControlError> {
        let mut client = fstp_pgwire::Client::connect(&self.rt, &self.login)
            .await
            .map_err(|_| ControlError::Job("the witness database"))?;
        let revoked =
            fstp_witness::store::revoke_cell(&mut client, fstp_audit::CellId(cell.0), now_us())
                .await;
        let _ = client.close().await;
        revoked.map_err(|_| ControlError::Job("the witness revocation"))
    }
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

/// Every destructive job of the erasure of `cell` on `placement`: the
/// `erase-cell` job, then the four drops of [`database_drop_jobs`] in
/// their order (ADR-004 "Decided by Daniel, 2026-11-15 (late)").
///
/// # Errors
///
/// The errors of [`DestructiveJob::pgagent`].
pub fn erasure_jobs(
    cell: CellId,
    placement: &Placement,
) -> Result<Vec<DestructiveJob>, ControlError> {
    let mut jobs = vec![DestructiveJob::EraseCell { cell }];
    for (cluster, job) in database_drop_jobs(cell, placement) {
        jobs.push(DestructiveJob::pgagent(cluster, job)?);
    }
    Ok(jobs)
}

/// The batch that each of the two operators approves once for the
/// erasure of `cell` on `placement`: the digests of [`erasure_jobs`].
///
/// # Errors
///
/// The errors of [`erasure_jobs`] and [`ApprovalBatch::of`].
pub fn erasure_batch(cell: CellId, placement: &Placement) -> Result<ApprovalBatch, ControlError> {
    ApprovalBatch::of(&erasure_jobs(cell, placement)?)
}

/// Checks the approvals of an erasure before step 1 (ADR-004, 2026-11-15
/// late): the `erase-cell` job and each drop carry the same two
/// approvals, and each is a batch approval over exactly the jobs of
/// [`erasure_batch`]. So every job digest of the erasure is in an
/// approved batch, and each operator approved the erasure once.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] for a job without evidence, an
/// approval of one job, a batch of other jobs, or a job approved apart
/// from the others.
fn check_erasure_batch(
    cell: CellId,
    placement: &Placement,
    approved: &ApprovedJob,
    drops: &[&ApprovedJob],
) -> Result<(), ControlError> {
    let want = erasure_batch(cell, placement)?;
    let pair = approved.evidence().ok_or(ControlError::ApprovalRequired)?;
    for e in pair {
        let batch = e.batch.as_ref().ok_or(ControlError::ApprovalRequired)?;
        if !batch.same_jobs(&want) || !batch.contains(approved.digest()) {
            return Err(ControlError::ApprovalRequired);
        }
    }
    let [p0, p1] = pair;
    for j in drops {
        let [d0, d1] = j.evidence().ok_or(ControlError::ApprovalRequired)?;
        let same = (d0 == p0 && d1 == p1) || (d0 == p1 && d1 == p0);
        if !same {
            return Err(ControlError::ApprovalRequired);
        }
    }
    Ok(())
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
///    again itself. Then it revokes the cell at the witness through
///    `witness`. It deletes no object storage (ADR-004, 2026-11-15
///    night): bucket lifecycle rules remove the cell's objects;
/// 3. removes every route of the cell through `edge`;
/// 4. signs the confirmation with `signer` at `now`.
///
/// Every check runs before step 1: the erasure job, the keys, and the
/// four approved drops of [`database_drop_jobs`] with their evidence, and
/// that the erasure job and every drop carry the same two batch approvals
/// over exactly the jobs of [`erasure_batch`] (ADR-004, 2026-11-15 late).
/// So a job that would stop at step 2 for want of an approval destroys
/// nothing. Interim, pending Daniel: a
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
pub async fn erase_cell_steps<C, D, W, E>(
    custody: &C,
    databases: &D,
    witness: &W,
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
    W: WitnessCredentials,
    E: EdgeRoutes,
{
    let cell = erased_cell(approved)?;
    check_cell_keys(cell, keys)?;
    let drops = ordered_drop_jobs(cell, placement, agent_jobs)?;
    check_erasure_batch(cell, placement, approved, &drops)?;

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

    witness.revoke_cell(cell).await?;
    report(ErasureEvent::Step(ErasureStep::WitnessCellRevoked));

    let removed = edge.remove_cell(cell).await?;
    report(ErasureEvent::Step(ErasureStep::RoutesRemoved {
        count: removed,
    }));

    confirm(cell, approved, erased, signer, now)
}
