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
//! # Seams
//!
//! - Wrapping and unwrapping seal keys need AES-256-GCM from
//!   `fstp_crypto::aead`, and CA signing needs ECDSA from
//!   `fstp_crypto::sig`. Both are lane W1h. Until then those operations
//!   refuse with [`CustodyError::NotImplemented`].
//! - [`CustodyError`] has only the `NotImplemented` variant in the W0
//!   stub. A destroy of an unknown root refuses with it too, and names the
//!   reason. Lane W2f gives the error its real variants.
//! - The process serves no custody protocol yet. The frame codec of
//!   `fstp-custody` is lane W2f. [`run`] creates the roots, writes their
//!   needles for the test that started it, and holds them until its
//!   standard input closes.

use std::fmt;
use std::future::{Future, ready};
use std::io::{Read as _, Write as _};
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_custody::{
    Aad, BackendId, CellId, Chain, Custody, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Epoch, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage,
    WrappedSealKey,
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
}

#[derive(Default)]
struct SimState {
    roots: Vec<SimRoot>,
    usage: Vec<Vec<u8>>,
}

/// The custody simulator.
pub struct CustodySim {
    cell_index: u8,
    state: Mutex<SimState>,
}

impl fmt::Debug for CustodySim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodySim")
            .field("cell_index", &self.cell_index)
            .field("roots", &self.roots())
            .finish_non_exhaustive()
    }
}

/// The refusal while `fstp_crypto` has no AEAD or signing module.
const WAITS_FOR_CRYPTO: &str =
    "fstp_celltest::custody_sim: wrap, unwrap and sign need fstp_crypto aead and sig (lane W1h)";

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
            state: Mutex::new(SimState::default()),
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

    /// Creates a root for `label` with fresh canary bytes.
    ///
    /// # Errors
    ///
    /// Refuses when the random source fails.
    pub fn create(&self, label: RootLabel) -> Result<RootRef, NotImplemented> {
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
        state.usage.push(usage_record("create", &root.handle));
        state.roots.push(SimRoot {
            root: root.clone(),
            material: Some(RootMaterial(canary.secret_bytes())),
            canary,
        });
        Ok(root)
    }

    /// Destroys the root `root` refers to and returns the receipt.
    ///
    /// # Errors
    ///
    /// Refuses a root this simulator does not hold, or one already
    /// destroyed.
    pub fn destroy_root(&self, root: &RootRef) -> Result<DestroyReceipt, NotImplemented> {
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
        state.usage.push(usage_record("destroy", &root.handle));
        Ok(DestroyReceipt(receipt))
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

fn usage_record(op: &str, handle: &CustodyHandle) -> Vec<u8> {
    let mut out = op.as_bytes().to_vec();
    out.push(b' ');
    out.extend_from_slice(&handle.0);
    out
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
        let _ = (root, key, aad);
        ready(Err(CustodyError::NotImplemented(WAITS_FOR_CRYPTO)))
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let _ = (root, w, aad);
        ready(Err(CustodyError::NotImplemented(WAITS_FOR_CRYPTO)))
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
            .filter(|r| r.ends_with(&root.handle.0))
            .cloned()
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
