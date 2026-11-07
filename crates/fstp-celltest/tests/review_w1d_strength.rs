//! Independent review of lane W1d (test strength). I-81, M-SHRED.
//!
//! Each `review_` test seeds a planner defect into M-SHRED through the
//! public `ShredBackend` seam and asserts that some property of the model
//! reports it. They fail against the current model, which lets the defect
//! pass, and pass once the model gains the missing check.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::shred_model::{Reference, ShredBackend, ShredModel, properties};
use fstp_celltest::reference::keys::{KeyIx, Layout, RefPlan, RefStep};
use fstp_mc::{Config, check};

/// A bound well above any measured M-SHRED count, so every run here is
/// exhaustive and its verdicts are final.
fn bound() -> Config {
    Config::default()
        .with_stop_when_decided(false)
        .with_max_states(200_000)
}

/// The names of the properties that failed over `backend`, after an
/// exhaustive run.
fn failed<B: ShredBackend>(backend: B) -> Vec<String> {
    let model = ShredModel::new(backend);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(outcome.exhaustive, "not exhaustive:\n{outcome}");
    match outcome.require_all_passed() {
        Ok(()) => Vec::new(),
        Err(e) => vec![format!("{e}")],
    }
}

// ---------------------------------------------------------------------------
// Defect 1: a request that arrives while a run is in flight is dropped.

/// The reference planner, except that a request recorded while a run is
/// in flight is ignored. That key is never erased, although its request
/// is recorded (ADR-004 part 2: "Requests that arrive while a batch runs
/// join the next batch").
struct DropsMidRunRequests;

impl ShredBackend for DropsMidRunRequests {
    type Plan = RefPlan;
    fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
        Reference.genesis(layout)
    }
    fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
        if plan.run.is_some() {
            return Ok(plan.clone());
        }
        Reference.request(plan, dek)
    }
    fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
        Reference.next(plan)
    }
    fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
        Reference.apply(plan, done)
    }
    fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
        Reference.restart(stored)
    }
}

/// I-81 review: M-SHRED has no progress property. A planner that drops
/// every erasure request arriving during a run leaves those keys
/// readable forever, and yet every M-SHRED property and witness holds.
#[test]
fn review_m_shred_dropped_mid_run_request_is_caught() {
    let found = failed(DropsMidRunRequests);
    assert!(
        !found.is_empty(),
        "a planner that drops mid-run erasure requests passes M-SHRED"
    );
}

/// The same planner, except that a crash forgets the queued requests.
struct ForgetsQueueOnRestart;

impl ShredBackend for ForgetsQueueOnRestart {
    type Plan = RefPlan;
    fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
        Reference.genesis(layout)
    }
    fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
        Reference.request(plan, dek)
    }
    fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
        Reference.next(plan)
    }
    fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
        Reference.apply(plan, done)
    }
    fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
        let mut p = Reference.restart(stored)?;
        p.queued.clear();
        Ok(p)
    }
}

/// I-81 review, ADR-004 "A crash at any step loses nothing": a planner
/// whose restart forgets the queued erasure requests passes M-SHRED and
/// the scripted crash runs, which use one request only.
#[test]
fn review_m_shred_queue_lost_on_restart_is_caught() {
    let found = failed(ForgetsQueueOnRestart);
    assert!(
        !found.is_empty(),
        "a planner that loses queued erasure requests on restart passes M-SHRED"
    );
}

// ---------------------------------------------------------------------------
// Defect 2: a batch with two keys of one group re-seals one of them.

/// The keys of the running batch in group `g`, before the commit.
fn batch_in_group(plan: &RefPlan, g: u8) -> Vec<KeyIx> {
    let Some(run) = plan.run.as_ref() else {
        return Vec::new();
    };
    let Some(members) = plan.members.get(usize::from(g)) else {
        return Vec::new();
    };
    run.batch
        .iter()
        .copied()
        .filter(|k| members.contains(k))
        .collect()
}

/// The reference planner, except that `Reseal` drops only the smallest
/// erased key of its group. Every other erased key of that group is
/// re-sealed to the new generation, which then stays live.
struct ResealsAllButOneErased;

impl ResealsAllButOneErased {
    fn mutate(plan: &RefPlan, step: RefStep) -> RefStep {
        match step {
            RefStep::Reseal { group, mut keep } => {
                let erased = batch_in_group(plan, group);
                for k in erased.iter().skip(1) {
                    keep.push(*k);
                }
                keep.sort_unstable();
                RefStep::Reseal { group, keep }
            }
            other => other,
        }
    }
}

impl ShredBackend for ResealsAllButOneErased {
    type Plan = RefPlan;
    fn genesis(&self, layout: &Layout) -> Result<RefPlan, String> {
        Reference.genesis(layout)
    }
    fn request(&self, plan: &RefPlan, dek: KeyIx) -> Result<RefPlan, String> {
        Reference.request(plan, dek)
    }
    fn next(&self, plan: &RefPlan) -> Result<Option<RefStep>, String> {
        Ok(Reference.next(plan)?.map(|s| Self::mutate(plan, s)))
    }
    fn apply(&self, plan: &RefPlan, done: &RefStep) -> Result<RefPlan, String> {
        let original = Reference.next(plan)?.ok_or("no step")?;
        if Self::mutate(plan, original.clone()) == *done {
            Reference.apply(plan, &original)
        } else {
            Reference.apply(plan, done)
        }
    }
    fn restart(&self, stored: &RefPlan) -> Result<RefPlan, String> {
        Reference.restart(stored)
    }
}

/// I-81 review: the M-SHRED universe requests `k0`, `k2`, `k1`, and `k0`
/// always runs alone, so no batch ever holds two keys of one group. A
/// planner that re-seals every erased key of a group but the first one
/// keeps erased keys openable, and still passes M-SHRED.
#[test]
fn review_m_shred_two_erased_keys_of_one_group_is_caught() {
    let found = failed(ResealsAllButOneErased);
    assert!(
        !found.is_empty(),
        "a planner that re-seals all but one erased key of a group passes M-SHRED"
    );
}

/// The control twin: on a universe whose second and third requests share
/// group `g1`, the same defect breaks I-81. So the gap is the universe,
/// not the predicate.
#[test]
fn review_control_same_group_universe_catches_the_reseal_defect() {
    let model = ShredModel::with(ResealsAllButOneErased, Layout::m_shred(), vec![0, 2, 3]);
    let props = properties(&model);
    let outcome = check(&model, &props, &bound());
    assert!(
        outcome.require_all_passed().is_err(),
        "the defect also passes the same-group universe"
    );
}

// ---------------------------------------------------------------------------
// Defect 3: the file custody destroy test does not check the K(e) wipe.

/// A fresh scratch directory for one test, removed when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("fstp-review-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A server started by [`keyd`]. `serve` runs until it is stopped, so
/// [`KeydServer::join`] stops it through `fstp_keyd::stop` and then joins
/// its thread. The next start then reloads the volume from disk.
struct KeydServer {
    socket: std::path::PathBuf,
    thread: std::thread::JoinHandle<()>,
}

impl KeydServer {
    fn join(self) -> std::thread::Result<()> {
        fstp_keyd::stop(&self.socket).unwrap_or_else(|e| panic!("fstp_keyd::stop: {e}"));
        self.thread.join()
    }
}

/// Waits until `fstp-keyd` has bound `socket`: it opens the key table
/// before it binds, so a client that connects earlier is refused.
fn wait_for_socket(socket: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fstp-keyd bound no socket at {}",
            socket.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn keyd(
    socket: &std::path::Path,
    volume: &std::path::Path,
) -> (fstp_custody::KeydCustody, KeydServer) {
    let thread = {
        let (socket, volume) = (socket.to_path_buf(), volume.to_path_buf());
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve(&socket, &volume);
        })
    };
    wait_for_socket(socket);
    let server = KeydServer {
        socket: socket.to_path_buf(),
        thread,
    };
    let client = fstp_custody::KeydCustody::new(socket)
        .unwrap_or_else(|e| panic!("KeydCustody::new: {e} (NotImplemented)"));
    (client, server)
}

/// I-81 review, design section 3.3 (G23, Q32 A): the protection against
/// a leftover copy of an epoch file is the in-place overwrite of `K(e)`
/// in the key table. The lane's
/// `i81_file_custody_destroy_leaves_no_openable_epoch_on_the_key_volume`
/// checks only that the epoch file is unlinked, so a keyd that unlinks
/// the file and keeps `K(e)` passes it. This check puts a pre-destroy
/// copy of the epoch file back and requires that it still never opens.
/// It is red on `NotImplemented` now, and it is the check that test
/// lacks.
#[test]
fn review_keyd_pre_destroy_epoch_file_copy_never_opens() {
    use fstp_custody::{Aad, Custody, RootLabel, SealKey};
    use fstp_keys::{CellId, Chain, Epoch};
    use fstp_rt::future::block_on;

    let scratch = Scratch::new("keyd-copy");
    let socket = scratch.0.join("keyd.sock");
    let volume = scratch.0.join("keys");
    std::fs::create_dir_all(&volume).unwrap();
    let aad = Aad(b"review file custody".to_vec());
    let label = RootLabel {
        cell: Some(CellId([9; 16])),
        chain: Chain::App,
        epoch: Epoch(1),
    };
    let (r1, w1, copies) = {
        let (client, server) = keyd(&socket, &volume);
        let r1 = block_on(client.create_root(label)).unwrap();
        let w1 = block_on(client.wrap(&r1, &SealKey::from_bytes([1; 32]), &aad)).unwrap();
        let mut copies = Vec::new();
        for entry in std::fs::read_dir(&volume).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("epoch-") {
                copies.push((entry.path(), std::fs::read(entry.path()).unwrap()));
            }
        }
        assert!(!copies.is_empty(), "no epoch file on the key volume");
        block_on(client.destroy(&r1)).unwrap();
        drop(client);
        let _ = server.join();
        (r1, w1, copies)
    };
    for (path, bytes) in &copies {
        std::fs::write(path, bytes).unwrap();
    }
    let (client, _server) = keyd(&socket, &volume);
    assert!(
        block_on(client.unwrap(&r1, &w1, &aad)).is_err(),
        "a pre-destroy copy of the epoch file opened after the destroy"
    );
}
