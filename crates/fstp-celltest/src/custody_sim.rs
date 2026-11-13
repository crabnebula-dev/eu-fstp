//! The custody simulator behind `fstp-custody-sim`. It holds known root
//! bytes so the scanners can look for them (design section 14.3). Lane W1a.
//!
//! Each root's material is the hex part of a fresh [`CanaryKind::RootKey`]
//! canary, as 32 ASCII bytes ([`Canary::secret_bytes`]). The simulator
//! hands out [`Needle`]s for its roots, so an I-80 scan can look for the
//! exact root bytes in every encoding. The simulator runs as its own
//! process (design section 3.3, `SimCustody`), so a memory scan of a cell
//! or vault process shows whether root bytes ever entered it.
//!
//! Its usage log holds one record per served create, wrap, unwrap and
//! destroy, in the layout of `fstp_custody::usage` that `fstp-keyd`
//! writes, with the caller's request id (`fstp_custody::with_request`,
//! ADR-004 "Reconciliation").
//!
//! Wrap and unwrap seal a key under its root with AES-256-GCM from
//! `fstp_crypto::aead`, in the layout `fstp-keyd` uses: the nonce, then
//! the sealed key and its tag. The AAD binds a label, the root's handle
//! and the caller's AAD. Daniel decided on 2026-11-13 that the simulator
//! wraps and unwraps (m3-exit-audit section 7, item 2, Q-SIM).
//!
//! # Seams
//!
//! - CA signing needs ECDSA from `fstp_crypto::sig` (lane W1h). Until
//!   then `sign` refuses with [`CustodyError::NotImplemented`].
//! - A create or destroy that fails still refuses with
//!   [`CustodyError::NotImplemented`] and names the reason. Wrap and
//!   unwrap refuse with [`CustodyError::Refused`], as `fstp-keyd` does.
//! - The process serves no custody protocol yet. The frame codec of
//!   `fstp-custody` is lane W2f. [`run`] creates the roots, writes their
//!   needles for the test that started it, and holds them until its
//!   standard input closes.

use std::fmt;
use std::future::{Future, ready};
use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_crypto::aead;
use fstp_custody::usage::{OUTCOME_SERVED, UsageOp, UsageRecord, encode_record};
use fstp_custody::{
    Aad, BackendId, CellId, Chain, Custody, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Epoch, Refusal, RequestId, RootLabel, RootRef, SealKey, SignKeyRef,
    UsageCursor, UsagePage, WrappedSealKey,
};

use crate::NotImplemented;
use crate::canary::{Canary, CanaryKind};
use crate::scan::Needle;

/// The bytes of one simulated root. No `Clone`, no `Debug`, and the bytes
/// are overwritten on drop. The identifier is allowed only in `fstp-keyd`
/// and `fstp-celltest` (layering rule 7).
pub struct RootMaterial([u8; 32]);

impl RootMaterial {
    /// The root bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for RootMaterial {
    fn drop(&mut self) {
        // A plain overwrite. zeroize waits for ADR-001 A1 (lane W2f); this
        // is a test simulator, and the canary bytes are synthetic.
        self.0 = [0u8; 32];
    }
}

struct SimRoot {
    root: RootRef,
    canary: Canary,
    material: Option<RootMaterial>,
    /// The wraps sealed under this root, so the AEAD seal limit holds
    /// across calls (ADR-004 "Seal-count limit").
    seals: u64,
}

#[derive(Default)]
struct SimState {
    roots: Vec<SimRoot>,
    /// The usage log: the handle of the root each record names, and the
    /// record in the layout of `fstp_custody::usage`.
    usage: Vec<(CustodyHandle, Vec<u8>)>,
}

/// The custody simulator.
pub struct CustodySim {
    cell_index: u8,
    state: Arc<Mutex<SimState>>,
}

impl fmt::Debug for CustodySim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodySim")
            .field("cell_index", &self.cell_index)
            .field("roots", &self.roots())
            .finish_non_exhaustive()
    }
}

/// The refusal of `sign` while `fstp_crypto` has no signing module.
const WAITS_FOR_CRYPTO: &str = "fstp_celltest::custody_sim: sign needs fstp_crypto sig (lane W1h)";

/// The label that opens the AAD of every wrap, as in `fstp-keyd`.
const WRAP_LABEL: &[u8] = b"fstp-custody-sim-wrap-v1";

/// The length of a wrapped seal key: nonce, sealed key, tag.
const WRAPPED_LEN: usize = aead::NONCE_LEN + 32 + aead::TAG_LEN;

impl CustodySim {
    /// A new simulator whose root canaries name cell index 0.
    ///
    /// # Errors
    ///
    /// Never fails. The `Result` keeps the W0 signature.
    pub fn new() -> Result<CustodySim, NotImplemented> {
        Ok(CustodySim::for_cell(0))
    }

    /// A new simulator whose root canaries name cell index `cell_index`.
    #[must_use]
    pub fn for_cell(cell_index: u8) -> CustodySim {
        CustodySim {
            cell_index,
            state: Arc::new(Mutex::new(SimState::default())),
        }
    }

    /// A second handle on the same simulator: the same roots and the same
    /// usage log. A keystore that owns its custody client takes one.
    #[must_use]
    pub fn handle(&self) -> CustodySim {
        CustodySim {
            cell_index: self.cell_index,
            state: Arc::clone(&self.state),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SimState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The number of live roots it holds.
    pub fn roots(&self) -> usize {
        self.lock()
            .roots
            .iter()
            .filter(|r| r.material.is_some())
            .count()
    }

    /// Creates a root for `label` with fresh canary bytes, under the
    /// caller's request id or a fresh one.
    ///
    /// # Errors
    ///
    /// Refuses when the random source fails.
    pub fn create(&self, label: RootLabel) -> Result<RootRef, NotImplemented> {
        self.create_with_id(fresh_id()?, label)
    }

    /// Creates a root for `label` with fresh canary bytes, and logs the
    /// call under `request` (ADR-004 "Reconciliation").
    ///
    /// # Errors
    ///
    /// Refuses when the random source fails.
    pub fn create_with_id(
        &self,
        request: RequestId,
        label: RootLabel,
    ) -> Result<RootRef, NotImplemented> {
        let canary = Canary::generate(self.cell_index, CanaryKind::RootKey)?;
        let mut state = self.lock();
        let number = u64::try_from(state.roots.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let root = RootRef {
            backend: BackendId::Simulator,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(format!("sim-root-{number}").into_bytes()),
        };
        let record = usage_record(request, UsageOp::Create, &root);
        state.usage.push((root.handle.clone(), record));
        state.roots.push(SimRoot {
            root: root.clone(),
            material: Some(RootMaterial(canary.secret_bytes())),
            canary,
            seals: 0,
        });
        Ok(root)
    }

    /// Destroys the root `root` refers to under the caller's request
    /// id or a fresh one, and returns the receipt.
    ///
    /// # Errors
    ///
    /// Refuses a root this simulator does not hold, or one already
    /// destroyed.
    pub fn destroy_root(&self, root: &RootRef) -> Result<DestroyReceipt, NotImplemented> {
        self.destroy_root_with_id(fresh_id()?, root)
    }

    /// Destroys the root `root` refers to, logs the call under `request`
    /// and returns the receipt.
    ///
    /// # Errors
    ///
    /// Refuses a root this simulator does not hold, or one already
    /// destroyed.
    pub fn destroy_root_with_id(
        &self,
        request: RequestId,
        root: &RootRef,
    ) -> Result<DestroyReceipt, NotImplemented> {
        let mut state = self.lock();
        let Some(entry) = state
            .roots
            .iter_mut()
            .find(|r| r.root.handle == root.handle && r.material.is_some())
        else {
            return Err(NotImplemented::new(
                "fstp_celltest::custody_sim: no live root with this handle",
            ));
        };
        entry.material = None;
        let mut receipt = b"fstp-custody-sim destroyed ".to_vec();
        receipt.extend_from_slice(&root.handle.0);
        let record = usage_record(request, UsageOp::Destroy, root);
        state.usage.push((root.handle.clone(), record));
        Ok(DestroyReceipt(receipt))
    }

    /// Wraps `key` under the live root `root` with `aad`, and logs the
    /// call under `request` (ADR-004 part 2 and "Reconciliation").
    ///
    /// # Errors
    ///
    /// Refuses a root this simulator does not hold, a destroyed root, and
    /// a root that reached the AEAD seal limit.
    pub fn wrap_with_id(
        &self,
        request: RequestId,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> Result<WrappedSealKey, CustodyError> {
        let mut state = self.lock();
        let entry = live_root(&mut state.roots, root)?;
        let material = entry
            .material
            .as_ref()
            .ok_or(CustodyError::Refused(Refusal::Destroyed))?;
        let aead_key = aead::Key::from_bytes_with_count(material.expose(), entry.seals)
            .map_err(CustodyError::Crypto)?;
        let sealed =
            aead::seal(&aead_key, &wrap_aad(root, aad), key.expose()).map_err(|e| match e {
                fstp_crypto::CryptoError::SealLimitReached => {
                    CustodyError::Refused(Refusal::LimitReached)
                }
                other => CustodyError::Crypto(other),
            })?;
        entry.seals = aead_key.seal_count();
        drop(aead_key);
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.body);
        let record = usage_record(request, UsageOp::Wrap, root);
        state.usage.push((root.handle.clone(), record));
        Ok(WrappedSealKey(out))
    }

    /// Unwraps `w` under the live root `root` with `aad`, and logs the
    /// call under `request`.
    ///
    /// # Errors
    ///
    /// Refuses a root this simulator does not hold, a destroyed root, and
    /// a wrapped key that does not open under this root and AAD. A
    /// refused unwrap is not logged, since the log holds served calls.
    pub fn unwrap_with_id(
        &self,
        request: RequestId,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> Result<SealKey, CustodyError> {
        let mut state = self.lock();
        let entry = live_root(&mut state.roots, root)?;
        let material = entry
            .material
            .as_ref()
            .ok_or(CustodyError::Refused(Refusal::Destroyed))?;
        if w.0.len() != WRAPPED_LEN {
            return Err(CustodyError::Refused(Refusal::UnwrapFailed));
        }
        let (nonce, body) =
            w.0.split_first_chunk::<{ aead::NONCE_LEN }>()
                .ok_or(CustodyError::Refused(Refusal::UnwrapFailed))?;
        let aead_key = aead::Key::from_bytes_with_count(material.expose(), entry.seals)
            .map_err(CustodyError::Crypto)?;
        let opened = aead::open(&aead_key, nonce, &wrap_aad(root, aad), body)
            .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
        drop(aead_key);
        let bytes: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
        let record = usage_record(request, UsageOp::Unwrap, root);
        state.usage.push((root.handle.clone(), record));
        Ok(SealKey::from_bytes(bytes))
    }

    /// The material of a live root, for the test that checks where it may
    /// appear.
    pub fn with_material<T>(
        &self,
        root: &RootRef,
        f: impl FnOnce(&RootMaterial) -> T,
    ) -> Option<T> {
        let state = self.lock();
        state
            .roots
            .iter()
            .find(|r| r.root.handle == root.handle)
            .and_then(|r| r.material.as_ref())
            .map(f)
    }

    /// One needle per root ever created, destroyed ones included, labelled
    /// with the root's canary text. A scan for them finds root bytes in
    /// every encoding of design section 14.1.
    #[must_use]
    pub fn root_needles(&self) -> Vec<Needle> {
        self.lock()
            .roots
            .iter()
            .map(|r| Needle {
                label: r.canary.text(),
                bytes: r.canary.secret_bytes().to_vec(),
            })
            .collect()
    }

    /// The canaries behind the roots ever created.
    #[must_use]
    pub fn root_canaries(&self) -> Vec<Canary> {
        self.lock().roots.iter().map(|r| r.canary.clone()).collect()
    }
}

/// The entry of the live root `root` refers to.
fn live_root<'a>(
    roots: &'a mut [SimRoot],
    root: &RootRef,
) -> Result<&'a mut SimRoot, CustodyError> {
    let entry = roots
        .iter_mut()
        .find(|r| r.root.handle == root.handle)
        .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
    if entry.material.is_none() {
        return Err(CustodyError::Refused(Refusal::Destroyed));
    }
    Ok(entry)
}

/// The AAD of a wrap: the label, the root's chain, epoch and handle, and
/// the caller's AAD. The handle is length-prefixed, so no two roots and
/// AADs give the same bytes.
fn wrap_aad(root: &RootRef, aad: &Aad) -> Vec<u8> {
    let handle = &root.handle.0;
    let mut out = Vec::with_capacity(
        WRAP_LABEL
            .len()
            .saturating_add(13)
            .saturating_add(handle.len())
            .saturating_add(aad.0.len()),
    );
    out.extend_from_slice(WRAP_LABEL);
    out.push(root.chain.code());
    out.extend_from_slice(&root.epoch.0.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(handle.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(handle);
    out.extend_from_slice(&aad.0);
    out
}

/// The caller's request id (`fstp_custody::with_request`), or a fresh
/// one.
fn fresh_id() -> Result<RequestId, NotImplemented> {
    fstp_custody::request_or_fresh()
        .map_err(|_| NotImplemented::new("fstp_celltest::custody_sim: no random request id"))
}

/// The caller's request id, or a fresh one, for a call that refuses with
/// a [`CustodyError`].
fn fresh_custody_id() -> Result<RequestId, CustodyError> {
    fstp_custody::request_or_fresh()
}

/// The usage record of a served call on `root`, in the layout of
/// `fstp_custody::usage` that `fstp-keyd` writes too. The simulator is
/// client 0, and it logs only the calls it served.
fn usage_record(request: RequestId, op: UsageOp, root: &RootRef) -> Vec<u8> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    encode_record(&UsageRecord {
        request,
        op,
        chain: root.chain.code(),
        epoch: root.epoch,
        time,
        outcome: OUTCOME_SERVED,
        client: 0,
    })
    .to_vec()
}

fn cursor_index(cursor: &UsageCursor) -> usize {
    let mut bytes = [0u8; 8];
    for (dst, src) in bytes.iter_mut().rev().zip(cursor.0.iter().rev()) {
        *dst = *src;
    }
    usize::try_from(u64::from_be_bytes(bytes)).unwrap_or(usize::MAX)
}

impl Custody for CustodySim {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        ready(
            self.create(label)
                .map_err(|e| CustodyError::NotImplemented(e.operation)),
        )
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        ready(fresh_custody_id().and_then(|id| self.wrap_with_id(id, root, key, aad)))
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        ready(fresh_custody_id().and_then(|id| self.unwrap_with_id(id, root, w, aad)))
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        ready(
            self.destroy_root(root)
                .map_err(|e| CustodyError::NotImplemented(e.operation)),
        )
    }

    fn sign(
        &self,
        key: &SignKeyRef,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        let _ = (key, digest);
        ready(Err(CustodyError::NotImplemented(WAITS_FOR_CRYPTO)))
    }

    fn usage_since(
        &self,
        root: &RootRef,
        cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        let state = self.lock();
        let from = cursor_index(&cursor);
        let operations: Vec<Vec<u8>> = state
            .usage
            .iter()
            .skip(from)
            .filter(|(h, _)| *h == root.handle)
            .map(|(_, r)| r.clone())
            .collect();
        let next = u64::try_from(state.usage.len()).unwrap_or(u64::MAX);
        ready(Ok(UsagePage {
            operations,
            next: UsageCursor(next.to_be_bytes().to_vec()),
        }))
    }
}

/// What the `fstp-custody-sim` process is asked to do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimArgs {
    /// The cell index the root canaries name.
    pub cell_index: u8,
    /// The cell id the roots belong to, as 32 lowercase hex digits.
    pub cell: Option<[u8; 16]>,
    /// Where to write one line per root: canary text, a tab, and the root
    /// bytes in lowercase hex. The file is created with mode 0600.
    pub needles_out: Option<std::path::PathBuf>,
}

/// Parses `--cell-index <n>`, `--cell <32 hex>` and `--needles-out <path>`.
///
/// # Errors
///
/// Refuses an unknown flag, a missing value or a malformed value.
pub fn parse_args(args: &[String]) -> Result<SimArgs, NotImplemented> {
    let mut out = SimArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(NotImplemented::new(
            "fstp-custody-sim: a flag lacks its value",
        ))?;
        match flag.as_str() {
            "--cell-index" => {
                out.cell_index = value
                    .parse()
                    .map_err(|_| NotImplemented::new("fstp-custody-sim: bad --cell-index"))?;
            }
            "--cell" => {
                let cell = crate::canary::parse_lower_hex_16(value)
                    .ok_or(NotImplemented::new("fstp-custody-sim: bad --cell"))?;
                out.cell = Some(cell);
            }
            "--needles-out" => out.needles_out = Some(value.into()),
            _ => return Err(NotImplemented::new("fstp-custody-sim: unknown flag")),
        }
    }
    Ok(out)
}

/// Runs the simulator as a process until its standard input closes.
///
/// It creates one root for the App chain and one for the Vault chain at
/// epoch 1, and writes their needles if asked. On standard output it then
/// prints one line `root <address>` per root, in needle order, and then
/// `ready`. The address is where the root's [`RootMaterial`] bytes sit
/// in the process, in lowercase hex. A memory test can then check that
/// its reader sees the root bytes at the place custody holds them, not a
/// stray copy of the hex text. It then holds the roots in memory.
///
/// # Errors
///
/// Refuses bad arguments, and fails when the needle file cannot be written.
pub fn run() -> Result<(), NotImplemented> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&args)?;
    let sim = CustodySim::for_cell(args.cell_index);
    let mut roots = Vec::new();
    for chain in [Chain::App, Chain::Vault] {
        roots.push(sim.create(RootLabel {
            cell: args.cell.map(CellId),
            chain,
            epoch: Epoch(1),
        })?);
    }
    // The addresses are read once every root exists, since a later create
    // may move the earlier roots. Nothing creates a root after this.
    let mut report = String::new();
    for root in &roots {
        let address = sim
            .with_material(root, |m| m.expose().as_ptr().addr())
            .ok_or(NotImplemented::new("fstp-custody-sim: lost a new root"))?;
        report.push_str(&format!("root {address:x}\n"));
    }
    report.push_str("ready\n");
    if let Some(path) = &args.needles_out {
        write_needles(path, &sim.root_needles())?;
    }
    let mut stdout = std::io::stdout();
    stdout
        .write_all(report.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|_| NotImplemented::new("fstp-custody-sim: cannot write to stdout"))?;
    // Hold the roots until the parent closes the pipe, in any way.
    let mut sink = [0u8; 256];
    let mut stdin = std::io::stdin();
    while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    // The roots stay live until here, so a memory scan sees them.
    let held = sim.roots();
    drop(sim);
    if held == 2 {
        Ok(())
    } else {
        Err(NotImplemented::new("fstp-custody-sim: lost a root"))
    }
}

fn write_needles(path: &std::path::Path, needles: &[Needle]) -> Result<(), NotImplemented> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut text = String::new();
    for n in needles {
        text.push_str(&n.label);
        text.push('\t');
        text.push_str(&crate::canary::lower_hex(&n.bytes));
        text.push('\n');
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|_| NotImplemented::new("fstp-custody-sim: cannot write the needle file"))
}
