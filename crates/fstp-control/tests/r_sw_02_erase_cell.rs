//! R-SW-02, design section 3.7, ADR-004 "CA keys in custody", ADR-011:
//! the `erase-cell` job of `fstp-control` over a recording custody.
//! Lane m3/erase-cell.
//!
//! The job runs only as a two-operator approved erasure of its own cell.
//! It destroys exactly the cell's listed roots and CA keys, announces
//! each custody call's request id before the call, and signs a
//! confirmation that lists every receipt.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fstp_control::ControlError;
use fstp_control::approval::{ApprovalBook, ApprovedJob, DestructiveJob};
use fstp_control::erase::{
    CONFIRMATION_CONTEXT, CellKeys, ErasureConfirmation, SignKeyCustody, check_cell_keys,
    erase_cell, verify_erasure_confirmation,
};
use fstp_control::pgagent::{DbIdent, PgagentJob};
use fstp_control::placement::ClusterId;
use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_custody::{
    Aad, BackendId, Chain, Custody, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature,
    Epoch, Refusal, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage,
    WrappedSealKey, current_request,
};
use fstp_rt::future::block_on;

const T0: i64 = 1_800_000_000;
const CELL: CellId = CellId([0x0c; 16]);

/// One destroy call: the handle and the request id it ran under.
type Call = (Vec<u8>, Option<[u8; 16]>);

/// A custody that holds handles only, and records each destroy with the
/// request id it ran under.
#[derive(Clone, Default)]
struct Recorder {
    live: Arc<Mutex<BTreeSet<Vec<u8>>>>,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl Recorder {
    fn destroy_handle(&self, h: &[u8]) -> Result<DestroyReceipt, CustodyError> {
        self.calls
            .lock()
            .unwrap()
            .push((h.to_vec(), current_request().map(|r| r.0)));
        if self.live.lock().unwrap().remove(h) {
            let mut receipt = b"gone:".to_vec();
            receipt.extend_from_slice(h);
            Ok(DestroyReceipt(receipt))
        } else {
            Err(CustodyError::Refused(Refusal::UnknownRoot))
        }
    }
}

impl Custody for Recorder {
    fn create_root(
        &self,
        _label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("create_root")))
    }
    fn wrap(
        &self,
        _root: &RootRef,
        _key: &SealKey,
        _aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("wrap")))
    }
    fn unwrap(
        &self,
        _root: &RootRef,
        _w: &WrappedSealKey,
        _aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("unwrap")))
    }
    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        std::future::ready(self.destroy_handle(&root.handle.0))
    }
    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("sign")))
    }
    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Ok(UsagePage::default()))
    }
}

impl SignKeyCustody for Recorder {
    fn destroy_sign_key(
        &self,
        key: &SignKeyRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        std::future::ready(self.destroy_handle(&key.handle.0))
    }
}

fn root(cell: CellId, chain: Chain, epoch: u64, handle: u8) -> RootRef {
    RootRef {
        backend: BackendId::Simulator,
        cell: Some(fstp_custody::CellId(cell.0)),
        chain,
        epoch: Epoch(epoch),
        handle: CustodyHandle(vec![handle; 16]),
    }
}

fn ca(handle: u8) -> SignKeyRef {
    SignKeyRef {
        backend: BackendId::Simulator,
        handle: CustodyHandle(vec![handle; 16]),
    }
}

/// The cell's keys: the Vault chain mid-rotation with two live epochs.
fn cell_keys() -> CellKeys {
    CellKeys {
        roots: vec![
            root(CELL, Chain::App, 3, 1),
            root(CELL, Chain::Vault, 1, 2),
            root(CELL, Chain::Vault, 2, 3),
            root(CELL, Chain::CellBackup, 0, 4),
        ],
        ca: vec![ca(5)],
    }
}

fn custody_holding(keys: &CellKeys, extra: &[u8]) -> Recorder {
    let c = Recorder::default();
    let mut live = c.live.lock().unwrap();
    for r in &keys.roots {
        live.insert(r.handle.0.clone());
    }
    for k in &keys.ca {
        live.insert(k.handle.0.clone());
    }
    for h in extra {
        live.insert(vec![*h; 16]);
    }
    drop(live);
    c
}

fn approved(job: DestructiveJob) -> ApprovedJob {
    let mut book = ApprovalBook::default();
    book.approve(StaffRef([1; 16]), &job, T0).unwrap();
    book.approve(StaffRef([2; 16]), &job, T0).unwrap();
    book.take(StaffRef([1; 16]), &job, T0 + 1).unwrap()
}

fn erase_job(cell: CellId) -> DestructiveJob {
    DestructiveJob::EraseCell { cell }
}

fn run(
    custody: &Recorder,
    job: &ApprovedJob,
    keys: &CellKeys,
    signer: &CompositeSigningKey,
) -> (Result<ErasureConfirmation, ControlError>, Vec<[u8; 16]>) {
    let mut announced = Vec::new();
    let r = block_on(erase_cell(custody, job, keys, signer, T0 + 2, |id| {
        announced.push(id);
    }));
    (r, announced)
}

/// R-SW-02, design section 3.7 steps 1 and 4, ADR-004 "CA keys in
/// custody": an approved erasure destroys every listed root of the cell's
/// three chains, both epochs of a chain mid-rotation included, and the
/// cell CA key, and nothing else. The confirmation lists one receipt per
/// key, names both approvers and the job, and verifies under the control
/// plane's key.
#[test]
fn r_sw_02_erase_cell_destroys_every_cell_key_and_signs_the_receipts() {
    let keys = cell_keys();
    let custody = custody_holding(&keys, &[0x77]);
    let signer = composite::generate().unwrap();
    let job = approved(erase_job(CELL));
    let (confirmation, _) = run(&custody, &job, &keys, &signer);
    let c = confirmation.unwrap();
    assert_eq!(c.cell, CELL);
    assert_eq!(c.job, job.digest());
    assert_eq!(c.approvers, [StaffRef([1; 16]), StaffRef([2; 16])]);
    let handles: Vec<Vec<u8>> = c.keys.iter().map(|k| k.handle.clone()).collect();
    let want: Vec<Vec<u8>> = (1..=5).map(|h| vec![h; 16]).collect();
    assert_eq!(handles, want);
    assert_eq!(c.keys[4].chain, None);
    assert_eq!(c.keys[2].chain, Some(Chain::Vault));
    for k in &c.keys {
        let mut receipt = b"gone:".to_vec();
        receipt.extend_from_slice(&k.handle);
        assert_eq!(k.receipt.0, receipt);
    }
    assert_eq!(
        *custody.live.lock().unwrap(),
        BTreeSet::from([vec![0x77; 16]]),
        "the erasure touched a key it was not given, or left one"
    );
    let pk = signer.public_key().to_bytes();
    assert!(verify_erasure_confirmation(&pk, &c));
    assert!(
        composite::verify_with_context(&pk, &c.body().unwrap(), CONFIRMATION_CONTEXT, &c.signature)
            .is_ok()
    );
}

/// ADR-004 "Reconciliation": each custody call's request id reaches the
/// caller before the call, and the call runs under that id.
#[test]
fn r_sw_02_erase_cell_announces_each_custody_call_first() {
    let keys = cell_keys();
    let custody = custody_holding(&keys, &[]);
    let signer = composite::generate().unwrap();
    let (r, announced) = run(&custody, &approved(erase_job(CELL)), &keys, &signer);
    r.unwrap();
    let calls = custody.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 5);
    let ran: Vec<[u8; 16]> = calls.iter().map(|(_, id)| id.unwrap()).collect();
    assert_eq!(ran, announced);
    assert_eq!(announced.iter().collect::<BTreeSet<_>>().len(), 5);
}

/// R-SW-02 teeth: the confirmation does not verify after any change to
/// its body, under another key, or with either signature half alone
/// broken.
#[test]
fn r_sw_02_teeth_a_changed_confirmation_does_not_verify() {
    let keys = cell_keys();
    let custody = custody_holding(&keys, &[]);
    let signer = composite::generate().unwrap();
    let (r, _) = run(&custody, &approved(erase_job(CELL)), &keys, &signer);
    let c = r.unwrap();
    let pk = signer.public_key().to_bytes();
    let mut changes: Vec<ErasureConfirmation> = Vec::new();
    let mut x = c.clone();
    x.keys.pop();
    changes.push(x);
    let mut x = c.clone();
    x.cell = CellId([0x0d; 16]);
    changes.push(x);
    let mut x = c.clone();
    x.erased_at += 1;
    changes.push(x);
    let mut x = c.clone();
    x.approvers.swap(0, 1);
    changes.push(x);
    let mut x = c.clone();
    x.keys[0].receipt.0.push(0);
    changes.push(x);
    let mut x = c.clone();
    x.keys[4].chain = Some(Chain::App);
    changes.push(x);
    let mut x = c.clone();
    x.signature[0] ^= 1;
    changes.push(x);
    let mut x = c.clone();
    let last = x.signature.len() - 1;
    x.signature[last] ^= 1;
    changes.push(x);
    for (i, changed) in changes.iter().enumerate() {
        assert!(!verify_erasure_confirmation(&pk, changed), "change {i}");
    }
    let other = composite::generate().unwrap().public_key().to_bytes();
    assert!(!verify_erasure_confirmation(&other, &c));
}

/// R-SW-02, ADR-011: the job runs only as the approved erasure of its own
/// cell. An approved erasure of another cell, or an approved agent job,
/// destroys nothing.
#[test]
fn r_sw_02_erase_cell_runs_only_its_own_approved_erasure() {
    let keys = cell_keys();
    let custody = custody_holding(&keys, &[]);
    let signer = composite::generate().unwrap();
    let (r, _) = run(
        &custody,
        &approved(erase_job(CellId([0x0d; 16]))),
        &keys,
        &signer,
    );
    assert_eq!(r, Err(ControlError::Job("a root of another cell")));
    let db = DbIdent::parse("c_00112233445566778899aabbccddeeff").unwrap();
    let agent = DestructiveJob::pgagent(ClusterId([3; 16]), PgagentJob::DropRoles(db)).unwrap();
    let (r, _) = run(&custody, &approved(agent), &keys, &signer);
    assert_eq!(r, Err(ControlError::ApprovalRequired));
    assert!(custody.calls.lock().unwrap().is_empty());
}

/// R-SW-02, design section 3.7 step 1: the job refuses a key list that is
/// not exactly a cell's own. A root of another cell, of the ClusterBackup
/// or ControlPlane chain, a missing chain, no CA key and a repeated
/// handle are each refused before any custody call.
#[test]
fn r_sw_02_erase_cell_refuses_keys_that_are_not_the_cells_own() {
    let mut cases: Vec<(&str, CellKeys)> = Vec::new();
    let mut k = cell_keys();
    k.roots.push(root(CellId([0x0d; 16]), Chain::App, 1, 9));
    cases.push(("another cell", k));
    let mut k = cell_keys();
    k.roots.push(root(CELL, Chain::ClusterBackup, 1, 9));
    cases.push(("cluster backup", k));
    let mut k = cell_keys();
    k.roots.push(root(CELL, Chain::ControlPlane, 1, 9));
    cases.push(("control plane", k));
    let mut k = cell_keys();
    k.roots.retain(|r| r.chain != Chain::CellBackup);
    cases.push(("missing chain", k));
    let mut k = cell_keys();
    k.ca.clear();
    cases.push(("no CA", k));
    let mut k = cell_keys();
    k.ca.push(ca(1));
    cases.push(("repeat", k));
    let mut k = cell_keys();
    k.roots[0].cell = None;
    cases.push(("no cell", k));
    for (what, keys) in cases {
        assert!(
            matches!(check_cell_keys(CELL, &keys), Err(ControlError::Job(_))),
            "{what}"
        );
        let custody = custody_holding(&keys, &[]);
        let signer = composite::generate().unwrap();
        let (r, _) = run(&custody, &approved(erase_job(CELL)), &keys, &signer);
        assert!(r.is_err(), "{what}");
        assert!(custody.calls.lock().unwrap().is_empty(), "{what}");
    }
    assert_eq!(check_cell_keys(CELL, &cell_keys()), Ok(()));
}

/// I-81 under failure: a destroy custody refuses ends the job with the
/// refusal and issues no confirmation.
#[test]
fn r_sw_02_erase_cell_issues_no_confirmation_after_a_refused_destroy() {
    let keys = cell_keys();
    let custody = custody_holding(&keys, &[]);
    custody.live.lock().unwrap().remove(&vec![3; 16]);
    let signer = composite::generate().unwrap();
    let (r, _) = run(&custody, &approved(erase_job(CELL)), &keys, &signer);
    assert_eq!(
        r,
        Err(ControlError::Custody(CustodyError::Refused(
            Refusal::UnknownRoot
        )))
    );
}
