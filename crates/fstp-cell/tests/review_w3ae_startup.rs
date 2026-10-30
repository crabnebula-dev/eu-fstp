//! Reproducer of the independent review of lane w3ae: the start-up path
//! starts no timeline. The harness is a trimmed copy of the in-memory
//! parts of `main_startup.rs`. Starting a cell needs composite anchor
//! signing (lane w2gs), so this test is also red until w2gs merges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_audit::anchor::AnchorRow;
use fstp_audit::anchorer::WitnessFault;
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_cell::egress::{CnFault, CnTransport};
use fstp_cell::engine::startup::{ListenerKind, StartParts};
use fstp_cell::engine::{CellEngine, VaultClient};
use fstp_cell::tasks::erasure::ErasureRunner;
use fstp_cell::witness::store::{AnchoredStore, MemDatabase, StoreKeys};
use fstp_cell::witness::{WitnessClient, WitnessLink, WitnessMessage, WitnessReply};
use fstp_cell_core::driver::VaultFault;
use fstp_crypto::{aead, composite};
use fstp_custody::{
    Aad, BackendId, Custody, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature, Refusal,
    RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_keys::envelope::DataKey;
use fstp_ledger::Seq;
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;
use fstp_witness::{ChainWitness, Sender, sign_receipt};

const CELL: [u8; 16] = [0x3D; 16];
const WITNESS_CA: [u8; 32] = [0x12; 32];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

type Roots = (BTreeMap<Vec<u8>, [u8; 32]>, u64);

#[derive(Clone, Default)]
struct Custodian(Arc<Mutex<Roots>>);

impl Custodian {
    fn root(&self, root: &RootRef) -> Result<aead::Key, CustodyError> {
        let rk = *lock(&self.0)
            .0
            .get(&root.handle.0)
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
        aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)
    }
}

impl Custody for Custodian {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let mut key = [0u8; 32];
        let r = fstp_crypto::random_bytes(&mut key).map_err(CustodyError::Crypto);
        let handle = {
            let mut g = lock(&self.0);
            g.1 += 1;
            let h = g.1.to_be_bytes().to_vec();
            g.0.insert(h.clone(), key);
            h
        };
        std::future::ready(r.map(|()| RootRef {
            backend: BackendId::Simulator,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(handle),
        }))
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let r = (|| {
            let k = self.root(root)?;
            let s = aead::seal(&k, &aad.0, key.expose()).map_err(CustodyError::Crypto)?;
            let mut out = s.nonce.to_vec();
            out.extend_from_slice(&s.body);
            Ok(WrappedSealKey(out))
        })();
        std::future::ready(r)
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let r = (|| {
            let k = self.root(root)?;
            let (nonce, body) = w.0.split_at(aead::NONCE_LEN);
            let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().unwrap();
            let pt = aead::open(&k, &nonce, &aad.0, body)
                .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
            Ok(SealKey::from_bytes(pt.as_slice().try_into().unwrap()))
        })();
        std::future::ready(r)
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let gone = lock(&self.0).0.remove(&root.handle.0).is_some();
        std::future::ready(if gone {
            Ok(DestroyReceipt(root.handle.0.clone()))
        } else {
            Err(CustodyError::Refused(Refusal::UnknownRoot))
        })
    }

    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::Refused(Refusal::NoSignKey)))
    }

    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Ok(UsagePage::default()))
    }
}

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

struct WitnessPeer {
    core: Mutex<ChainWitness>,
    key: CompositeSigningKey,
    log: Mutex<Vec<WitnessRecord>>,
}

#[derive(Clone)]
struct Peer(Arc<WitnessPeer>);

impl WitnessLink for Peer {
    fn peer_issuer(&self) -> impl Future<Output = Result<[u8; 32], WitnessFault>> + Send {
        std::future::ready(Ok(WITNESS_CA))
    }

    fn send(
        &self,
        message: WitnessMessage,
    ) -> impl Future<Output = Result<WitnessReply, WitnessFault>> + Send {
        let sender = Sender::writer(CellId(CELL), ChainId::App);
        let mut core = lock(&self.0.core);
        let reply = match message {
            WitnessMessage::Prepare(p) => match core.prepare(sender, &p, p.anchor.at) {
                Err(_) => WitnessReply::Refused,
                Ok(fields) => {
                    match sign_receipt(&self.0.key, CellId(CELL), ChainId::App, &fields) {
                        Err(_) => WitnessReply::Refused,
                        Ok(receipt) => {
                            lock(&self.0.log).push(WitnessRecord::Prepare(AnchorRow {
                                anchor: p.anchor.clone(),
                                receipt: receipt.clone(),
                            }));
                            WitnessReply::Receipt(receipt)
                        }
                    }
                }
            },
            WitnessMessage::Abort { .. } | WitnessMessage::InDoubtAbsent { .. } => {
                WitnessReply::UnknownPrepare
            }
        };
        std::future::ready(Ok(reply))
    }

    fn outstanding(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(lock(&self.0.core).state().outstanding))
    }

    fn log(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Vec<WitnessRecord>, WitnessFault>> + Send {
        std::future::ready(Ok(lock(&self.0.log).clone()))
    }
}

struct NoCrabNebula;

impl CnTransport for NoCrabNebula {
    fn exchange(
        &self,
        _host: &'static str,
        _request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send {
        std::future::ready(Err(CnFault::Unreachable))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Design sections 5.1 and 8.2, M3 design section 19 row W3a, lane scope
/// ("the system tasks (scheduled role ends ...)"): a started cell runs the
/// timeline that issues `EndScheduledRole`, `EndSessionsAtBindingEnd`,
/// `ExpireStage2` and `ReEnter`. `startup::start` documents "7. The system
/// tasks start", but it spawns only the release task of a self-hosted
/// cell. A SaaS cell starts with the engine as the only participant of
/// its shutdown, so no due system command is ever issued. Every system
/// task joins the drain (ADR-002), so a running timeline is a second
/// participant.
#[test]
fn review_started_saas_cell_runs_the_timeline() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let peer = Peer(Arc::new(WitnessPeer {
            core: Mutex::new(ChainWitness::genesis(CellId(CELL), ChainId::App)),
            key: composite::generate().unwrap(),
            log: Mutex::new(Vec::new()),
        }));
        let witness_keys = vec![peer.0.key.public_key().to_bytes().to_vec()];
        let client =
            |p: &Peer| WitnessClient::new(p.clone(), CellId(CELL), ChainId::App, WITNESS_CA);
        let custody = Custodian::default();
        let keys = StoreKeys {
            anchor: composite::generate().unwrap(),
            ledger: DataKey::generate().unwrap(),
            witness: witness_keys,
        };
        let mut store = AnchoredStore::new(MemDatabase::new(), client(&peer), CELL, keys).unwrap();
        store.start().await.unwrap();
        let setup = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &setup, 8)
            .await
            .unwrap();
        let runner = ErasureRunner::genesis(custody.clone(), engine.clone(), CELL)
            .await
            .expect("the key chain starts (needs anchor signing, lane w2gs)");
        let keystore = runner.keystore().clone();
        drop(runner);
        drop(engine);
        let store = task.await.unwrap();
        let (db, _, keys) = store.into_parts();
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let parts = StartParts {
            config: format!(
                "{{\"cell\":\"{}\",\"version\":\"0.3.0\",\"mode\":\"saas\"}}",
                hex(&CELL)
            )
            .into_bytes(),
            custody,
            keystore,
            db,
            witness: client(&peer),
            keys,
            vault: GenesisVault,
            crabnebula: None::<NoCrabNebula>,
            licence: None,
            listen: [
                (ListenerKind::Tunnel, loopback),
                (ListenerKind::Internal, loopback),
                (ListenerKind::Health, loopback),
            ],
        };
        let mut report = |_| {};
        let cell = fstp_cell::engine::startup::start(&rt2, parts, &mut report)
            .await
            .expect("the cell starts");
        let participants = cell.shutdown.active();
        cell.shutdown.trigger();
        assert!(
            participants >= 2,
            "a started SaaS cell runs only its engine ({participants} participant): no timeline \
             issues the due system commands"
        );
    });
}
