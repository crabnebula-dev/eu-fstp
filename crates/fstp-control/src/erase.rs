//! `fstp-control erase-cell`: the cell's erasure after the P-46 retrieval
//! period (R-SW-02, design section 3.7, ADR-004 "CA keys in custody",
//! I-81). Lane m3/erase-cell.
//!
//! The job runs only as an [`ApprovedJob`] of two operators
//! ([`crate::approval`]). It then:
//!
//! 1. destroys every live root of the cell's App, Vault and CellBackup
//!    chains, and the cell CA sign key, in custody, keeping each receipt;
//! 2. issues the erasure confirmation, composite-signed by the control
//!    plane, which lists every destroyed key with its receipt.
//!
//! Every copy of the cell's keys, in any backup, WAL archive or replica,
//! is sealed under a chain whose roots are then gone, so no copy restores
//! the cell (I-81). Each custody call is announced to the caller with its
//! request id before it is made (ADR-004 "Reconciliation").
//!
//! Interim, pending Daniel (ADR-004 record of lane m3/erase-cell):
//!
//! - Destroying a CA sign key is [`SignKeyCustody`], outside the six
//!   operations of the `Custody` trait (I-80). Only the test custody
//!   implements it yet.
//! - The key list is input. In production it comes from
//!   `cp.custody_entry` and the backend's listing, which is not built.
//! - Design steps 2 and 3, dropping the databases and removing the
//!   routes, are not run: the destructive `fstp-pgagent` jobs and the edge
//!   route removal are not built.

use std::collections::BTreeSet;
use std::future::Future;

use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_custody::{
    Chain, Custody, CustodyError, DestroyReceipt, RequestId, RootRef, SignKeyRef, with_request,
};

use crate::ControlError;
use crate::approval::{ApprovedJob, DestructiveJob, JobDigest};

/// The composite signature context of an erasure confirmation.
pub const CONFIRMATION_CONTEXT: &[u8] = b"fstp-cell-erasure-v1";

/// The magic that opens the signed body of a confirmation.
const CONFIRMATION_MAGIC: &[u8; 4] = b"FCE1";

/// The chains a cell erasure destroys (design section 3.7 step 1).
pub const CELL_CHAINS: [Chain; 3] = [Chain::App, Chain::Vault, Chain::CellBackup];

/// Destroys a CA sign key in custody (ADR-004 "CA keys in custody").
/// Kept apart from the six operations of the `Custody` trait (I-80).
pub trait SignKeyCustody: Send + Sync + 'static {
    /// Destroys the sign key and returns the backend's receipt.
    fn destroy_sign_key(
        &self,
        key: &SignKeyRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send;
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

/// Runs the approved erasure of the cell: destroys `keys` in `custody`,
/// then signs the confirmation with the control-plane key `signer` at
/// `now`. `announce` receives each custody call's request id before the
/// call is made.
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
    mut announce: impl FnMut([u8; 16]),
) -> Result<ErasureConfirmation, ControlError> {
    let cell = match approved.job() {
        DestructiveJob::EraseCell { cell } => *cell,
        DestructiveJob::Pgagent(_) => return Err(ControlError::ApprovalRequired),
    };
    check_cell_keys(cell, keys)?;
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
