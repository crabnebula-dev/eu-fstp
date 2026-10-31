//! Regression tests of the lane w3ae review, fix round 1, for the parts
//! that run without composite anchor signing (lane w2gs):
//!
//! - the step-up freshness check at the commit instant of each store
//!   (design section 8.4, ADR-008, I-78);
//! - the peer check of the witness client before every message
//!   (R-NF-09);
//! - the abort owed after a receipt for another cell (I-24, design
//!   section 7.2);
//! - the bounded read of the configuration file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod stepup_common;

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_audit::anchor::{Anchor, Receipt, ReceiptFields};
use fstp_audit::anchorer::{PrepareWitness, WitnessFault};
use fstp_audit::witness::{Prepare, WitnessRecord};
use fstp_audit::{CellId, ChainId, Link};
use fstp_auth::{Method, SessionView};
use fstp_cell::engine::{
    AppendRequest, CellAppendError, CellEngine, CellStore, EngineError, Unanchored, VaultClient,
    stepup_refusal,
};
use fstp_cell::tasks::system_now;
use fstp_cell::witness::store::{AnchoredStore, MemDatabase, OpenPrepare, StoreKeys};
use fstp_cell::witness::{WitnessClient, WitnessLink, WitnessMessage, WitnessReply};
use fstp_cell_core::driver::{SideEffects, VaultFault};
use fstp_cell_core::gate::{self, Action, Admitted, HighRiskAction, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellRecord, KeyRecord, action_digest};
use fstp_crypto::composite;
use fstp_domain::id::{AccountId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_keys::envelope::DataKey;
use fstp_ledger::{AsyncRecordStore, MemStore, RecordStore, Seq};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;

const CELL: [u8; 16] = [0xC7; 16];
const ADMIN: AccountId = AccountId::from_raw(1);
const MINUTE_US: i64 = 60_000_000;
const PINNED_CA: [u8; 32] = [0x12; 32];
const FOREIGN_CA: [u8; 32] = [0x13; 32];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A vault at the genesis epoch. Tenant commands ask no query.
struct GenesisVault;

impl VaultClient for GenesisVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(VaultEpoch::GENESIS))
    }

    fn ask(
        &self,
        _queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        std::future::ready(Err(VaultFault::Unavailable))
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(Ok(()))
    }
}

/// The session of the first admin.
const SESSION: [u8; 16] = [0x5E; 16];
/// The command id of the first admin grant.
const GRANT_ID: [u8; 16] = [0xA0; 16];

fn first_admin_grant() -> CellCommand {
    CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN })
}

/// `GrantTenantAdmin` of the first admin, admitted at `now` with the
/// fresh strong step-up `stepup` that the ledger granted at `now`, and
/// P-71 of five minutes.
fn grant_first_admin(engine: &CellEngine, now: Timestamp, stepup: [u8; 16]) -> Admitted {
    let cmd = first_admin_grant();
    let session = SessionView {
        id: SESSION,
        account: ADMIN,
        method: Method::Passkey,
        started: now,
        last_used: now,
    };
    let command_id = GRANT_ID;
    let action = Action::Command(cmd.clone());
    let high = HighRiskAction::of(&action).unwrap();
    assert!(high.is_some(), "GrantTenantAdmin is high risk");
    let stepup = StepUpView {
        id: stepup,
        session: session.id,
        action_digest: action_digest(&cmd, command_id),
        asserted_at: now,
        strong: true,
        consumed: false,
    };
    let policy = LoginPolicy {
        stepup_freshness_us: 5 * MINUTE_US,
    };
    gate::admit_command(
        &engine.state(),
        &session,
        action,
        command_id,
        Some(&stepup),
        now,
        &policy,
    )
    .unwrap()
}

/// Runs the first admin grant over an unanchored store whose commit
/// clock reads `commit_at - admitted_at` after the admission instant.
/// The ledger grants the step-up first (`stepup_common`). Returns the
/// grant's result and the number of entries the grant appended.
fn grant_over_unanchored(commit_after: i64) -> (Result<(), EngineError>, u64) {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let now = system_now();
        let mut mem = MemStore::new();
        let stepup = stepup_common::grant_stepup(
            &mut mem,
            SESSION,
            ADMIN,
            &first_admin_grant(),
            GRANT_ID,
            now,
        )
        .unwrap();
        let seeded = RecordStore::head(&mem).raw();
        let store = Unanchored::open(mem, CELL)
            .await
            .unwrap()
            .with_commit_clock(Arc::new(move || now + commit_after));
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .unwrap();
        let admitted = grant_first_admin(&engine, Timestamp::from_micros(now), stepup);
        let r = engine.execute(admitted).await.map(|_| ());
        drop(engine);
        let store = task.await.unwrap();
        let head = AsyncRecordStore::head(&store).await.unwrap().raw();
        (r, head - seeded)
    })
}

/// I-78, design section 8.4, ADR-008: a step-up fresh at admission but
/// past P-71 at the commit instant is refused at commit. The engine
/// reports the I-78 refusal, never a store outage, and nothing is
/// committed. The same command committed within P-71 commits.
#[test]
fn i78_cell_unanchored_store_refuses_a_step_up_stale_at_commit() {
    let (stale, appended) = grant_over_unanchored(6 * MINUTE_US);
    assert_eq!(stale, Err(EngineError::Exec(stepup_refusal())));
    assert_eq!(appended, 0, "a stale step-up committed nothing");
    let (fresh, appended) = grant_over_unanchored(4 * MINUTE_US);
    assert_eq!(fresh, Ok(()));
    assert!(appended > 0, "a step-up fresh at commit commits");
}

/// A witness that answers nothing: the anchored store refuses a stale
/// step-up before any prepare, so it is never reached.
struct NoWitness(AtomicUsize);

impl PrepareWitness for NoWitness {
    fn prepare(&self, _p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err(WitnessFault::Unreachable))
    }

    fn abort(&self, _head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        std::future::ready(Ok(()))
    }

    fn in_doubt_absent(
        &self,
        _head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        std::future::ready(Ok(()))
    }
}

impl OpenPrepare for NoWitness {
    fn open_prepare(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(None))
    }
}

/// I-78, design section 8.4, ADR-008: the anchored store checks the
/// step-up against its own commit clock, not the admission instant
/// `req.at`. A batch admitted ten minutes ago whose step-up expired five
/// minutes ago is refused with the typed `StepUpStale`, not as an
/// outage, and no prepare reaches the witness.
#[test]
fn i78_anchored_store_refuses_a_step_up_stale_at_its_commit_instant() {
    let keys = StoreKeys {
        anchor: composite::generate().unwrap(),
        ledger: DataKey::generate().unwrap(),
        // No prepare reaches the witness. The pin only satisfies the
        // store, which refuses an empty pin set (ADR-010 "Keys").
        witness: vec![
            composite::generate()
                .unwrap()
                .public_key()
                .to_bytes()
                .to_vec(),
        ],
    };
    let now = system_now();
    let mut store = AnchoredStore::new(
        MemDatabase::new(),
        NoWitness(AtomicUsize::new(0)),
        CELL,
        keys,
    )
    .unwrap()
    .with_commit_clock(Arc::new(move || now));
    let req = AppendRequest {
        expected: Seq::ZERO,
        at: now - 10 * MINUTE_US,
        command: [0x02; 16],
        batch: vec![CellRecord::Key(KeyRecord::KeyOpRecorded {
            op: b"{\"n\":2}".to_vec(),
        })],
        side: SideEffects {
            stepup_consumed: Some([0x02; 16]),
            stepup_fresh_until: Some(now - 5 * MINUTE_US),
            sessions_ended: Vec::new(),
        },
    };
    let r = fstp_rt::future::block_on(async {
        store.start().await.unwrap();
        store.append_cell(req).await
    });
    assert_eq!(r.map(|_| ()), Err(CellAppendError::StepUpStale));
    assert_eq!(store.witness().0.load(Ordering::SeqCst), 0);
}

/// A witness link whose peer CA can change between connections, and
/// that records what it sent and what it answers to a prepare.
struct ScriptedLink {
    issuer: Mutex<[u8; 32]>,
    issuer_checks: AtomicUsize,
    sent: Mutex<Vec<WitnessMessage>>,
    receipt_cell: CellId,
}

impl ScriptedLink {
    fn new(receipt_cell: CellId) -> ScriptedLink {
        ScriptedLink {
            issuer: Mutex::new(PINNED_CA),
            issuer_checks: AtomicUsize::new(0),
            sent: Mutex::new(Vec::new()),
            receipt_cell,
        }
    }
}

/// A shared handle on a [`ScriptedLink`].
#[derive(Clone)]
struct Shared(Arc<ScriptedLink>);

impl WitnessLink for Shared {
    fn peer_issuer(&self) -> impl Future<Output = Result<[u8; 32], WitnessFault>> + Send {
        self.0.issuer_checks.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(*lock(&self.0.issuer)))
    }

    fn send(
        &self,
        message: WitnessMessage,
    ) -> impl Future<Output = Result<WitnessReply, WitnessFault>> + Send {
        lock(&self.0.sent).push(message.clone());
        let reply = match message {
            WitnessMessage::Prepare(p) => WitnessReply::Receipt(Receipt {
                cell: self.0.receipt_cell,
                chain: ChainId::App,
                fields: ReceiptFields {
                    n: p.anchor.n,
                    link: p.anchor.link,
                    witness_seq: 1,
                    witness_link: p.anchor.link,
                    received_at: p.anchor.at,
                },
                signature: Vec::new(),
            }),
            WitnessMessage::Abort { .. } | WitnessMessage::InDoubtAbsent { .. } => {
                WitnessReply::Recorded
            }
        };
        std::future::ready(Ok(reply))
    }

    fn outstanding(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(None))
    }

    fn log(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Vec<WitnessRecord>, WitnessFault>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
}

fn prepare_of_row_one() -> Prepare {
    Prepare {
        prev: (0, Link([0; 32])),
        stored_hashes: vec![[0x44; 32]],
        anchor: Anchor {
            cell: CellId(CELL),
            chain: ChainId::App,
            n: 1,
            link: Link([0x45; 32]),
            at: 1,
            signature: Vec::new(),
        },
    }
}

/// R-NF-09: the witness client checks the peer's issuing CA before every
/// message, not once per client. After a reconnect to a peer of another
/// CA, nothing more is sent.
#[test]
fn r_nf_09_cell_witness_client_checks_the_peer_before_every_message() {
    let link = Shared(Arc::new(ScriptedLink::new(CellId(CELL))));
    let client = WitnessClient::new(link.clone(), CellId(CELL), ChainId::App, PINNED_CA);
    fstp_rt::future::block_on(async {
        assert_eq!(client.abort((1, Link([0x45; 32]))).await, Ok(()));
        *lock(&link.0.issuer) = FOREIGN_CA;
        assert_eq!(
            client.abort((1, Link([0x45; 32]))).await,
            Err(WitnessFault::Unreachable)
        );
        assert_eq!(
            client.prepare(&prepare_of_row_one()).await.map(|_| ()),
            Err(WitnessFault::Unreachable)
        );
    });
    assert_eq!(link.0.issuer_checks.load(Ordering::SeqCst), 3);
    assert_eq!(
        lock(&link.0.sent).len(),
        1,
        "a foreign peer received a message"
    );
}

/// I-24, design section 7.2: a receipt for another cell is not a
/// refusal. The witness answered, so it may hold the prepare outstanding.
/// The client reports a fault that leads the anchorer to send Abort
/// before the same row is prepared again, never `Refused`, after which
/// no abort would follow.
#[test]
fn i24_cell_witness_client_treats_a_receipt_for_another_cell_as_owing_an_abort() {
    let link = Shared(Arc::new(ScriptedLink::new(CellId([0xEE; 16]))));
    let client = WitnessClient::new(link.clone(), CellId(CELL), ChainId::App, PINNED_CA);
    let r = fstp_rt::future::block_on(client.prepare(&prepare_of_row_one()));
    assert_eq!(r.map(|_| ()), Err(WitnessFault::Unreachable));
}

/// The configuration file is read with a bound: a path that never ends,
/// such as `/dev/zero`, is refused one byte past `MAX_CONFIG_LEN` and is
/// never read whole.
#[test]
fn cell_config_read_stops_one_byte_past_the_limit() {
    let r = fstp_cell::read_config(std::path::Path::new("/dev/zero"));
    assert_eq!(
        r,
        Err(fstp_cell::CellError::Config(
            fstp_cell::config::ConfigError::Invalid("length")
        ))
    );
}
