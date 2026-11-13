//! The keyed login email index of the App chain (design sections 3.1, 3.5
//! and 4.2, decision 27 "Keyed digests die with erasure", I-81, G24,
//! Q22). Lane m3/login-m2http.
//!
//! The keystore owner (`fstp_cell::tasks::erasure`) holds the `Lookup`
//! keyed digest group and the index. These tests drive it over an
//! in-memory engine and an in-memory custody backend: an address joins
//! the index sealed as a text, a lookup finds its account under any
//! letter case, and an erasure batch that erases a login email replaces
//! the `Lookup` key, so the erased address has no digest and every live
//! address has a new one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod stepup_common;

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_auth::{Method, SessionView};
use fstp_cell::engine::{CellEngine, Unanchored, VaultClient};
use fstp_cell::tasks::erasure::{ErasureRunner, LoginEmailSet};
use fstp_cell_core::driver::VaultFault;
use fstp_cell_core::gate::{self, Action, HighRiskAction, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::text::TextCommand;
use fstp_cell_core::{CellCommand, CellRecord, action_digest};
use fstp_crypto::aead;
use fstp_custody::{
    Aad, BackendId, Custody as CustodyBackend, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Refusal, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage,
    WrappedSealKey,
};
use fstp_domain::id::{AccountId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{MemStore, Seq};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;

const CELL: [u8; 16] = [0xE6; 16];
const ADMIN: AccountId = AccountId::from_raw(1);
const ERASED: AccountId = AccountId::from_raw(0x51);
const LIVE: AccountId = AccountId::from_raw(0x52);
/// Synthetic addresses under the reserved `.test` name.
const ERASED_EMAIL: &str = "erased.person@login-index.test";
const LIVE_EMAIL: &str = "live.person@login-index.test";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The roots by handle, and the last handle drawn, of [`Custodian`].
type Roots = (BTreeMap<Vec<u8>, [u8; 32]>, u64);

#[derive(Clone, Default)]
/// An in-memory custody backend.
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

impl CustodyBackend for Custodian {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let r = (|| {
            let mut key = [0u8; 32];
            fstp_crypto::random_bytes(&mut key).map_err(CustodyError::Crypto)?;
            let mut g = lock(&self.0);
            g.1 += 1;
            let handle = g.1.to_be_bytes().to_vec();
            g.0.insert(handle.clone(), key);
            Ok(RootRef {
                backend: BackendId::Simulator,
                cell: label.cell,
                chain: label.chain,
                epoch: label.epoch,
                handle: CustodyHandle(handle),
            })
        })();
        std::future::ready(r)
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
        let r = if lock(&self.0).0.remove(&root.handle.0).is_some() {
            Ok(DestroyReceipt(root.handle.0.clone()))
        } else {
            Err(CustodyError::Refused(Refusal::UnknownRoot))
        };
        std::future::ready(r)
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

/// A vault at the genesis epoch: these commands ask no query.
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

const SESSION: [u8; 16] = [0x5E; 16];
const GRANT_ADMIN: u8 = 0xA0;

/// Runs `cmd` as the tenant admin through the gate, with the step-up
/// `stepup` when it is high risk.
async fn as_admin(
    engine: &CellEngine,
    cmd: CellCommand,
    id: u8,
    stepup: Option<[u8; 16]>,
) -> Result<(), &'static str> {
    let now = Timestamp::from_micros(fstp_cell::tasks::system_now());
    let session = SessionView {
        id: SESSION,
        account: ADMIN,
        method: Method::Passkey,
        started: now,
        last_used: now,
    };
    let command_id = [id; 16];
    let action = Action::Command(cmd.clone());
    let high = HighRiskAction::of(&action).map_err(|_| "no risk class")?;
    let stepup = high.zip(stepup).map(|(_, stepup)| StepUpView {
        id: stepup,
        session: session.id,
        action_digest: action_digest(&cmd, command_id),
        asserted_at: now,
        strong: true,
        consumed: false,
    });
    let policy = LoginPolicy {
        stepup_freshness_us: 5 * 60 * 1_000_000,
    };
    let admitted = gate::admit_command(
        &engine.state(),
        &session,
        action,
        command_id,
        stepup.as_ref(),
        now,
        &policy,
    )
    .map_err(|_| "the gate refused the tenant admin")?;
    engine
        .execute(admitted)
        .await
        .map(|_| ())
        .map_err(|_| "the tenant admin command failed")
}

/// What one run of the index saw.
#[derive(Debug, Default)]
struct IndexRun {
    taken: Option<LoginEmailSet>,
    found_any_case: Option<AccountId>,
    digests_before: Vec<[u8; 32]>,
    digests_after: Vec<[u8; 32]>,
    erased_after: Option<AccountId>,
    live_after: Option<AccountId>,
    erased_email_after: Option<String>,
    live_email_after: Option<String>,
    live_after_restart: Option<AccountId>,
}

/// Indexes two addresses, then erases the first one's text through the
/// ledger and runs the batch to its end, then restarts the runner from
/// its durable keystore.
fn run_index() -> IndexRun {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let mut mem: MemStore<CellRecord> = MemStore::new();
        let stepup = stepup_common::grant_stepup(
            &mut mem,
            SESSION,
            ADMIN,
            &CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            [GRANT_ADMIN; 16],
            fstp_cell::tasks::system_now(),
        )
        .unwrap();
        let store = Unanchored::open(mem, CELL).await.unwrap();
        let shutdown = Shutdown::new();
        let (engine, _task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .unwrap();
        as_admin(
            &engine,
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            GRANT_ADMIN,
            Some(stepup),
        )
        .await
        .unwrap();
        let sim = Custodian::default();
        let mut runner = ErasureRunner::genesis(sim.clone(), engine.clone(), CELL)
            .await
            .unwrap();
        let mut run = IndexRun::default();
        assert_eq!(
            runner.set_login_email(ERASED, ERASED_EMAIL).unwrap(),
            LoginEmailSet::Set
        );
        assert_eq!(
            runner.set_login_email(LIVE, LIVE_EMAIL).unwrap(),
            LoginEmailSet::Set
        );
        run.taken = Some(runner.set_login_email(LIVE, ERASED_EMAIL).unwrap());
        run.found_any_case = runner
            .login_account(&ERASED_EMAIL.to_ascii_uppercase())
            .unwrap();
        run.digests_before = runner.keystore().login_digests();
        let text = runner.keystore().login_text(ERASED).unwrap();
        // The account erasure names the login email's text (ADR-007).
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::PutText { id: text }),
            0xB0,
            None,
        )
        .await
        .unwrap();
        as_admin(
            &engine,
            CellCommand::Text(TextCommand::EraseTexts {
                ids: vec![text],
                cause: 2,
            }),
            0xB1,
            None,
        )
        .await
        .unwrap();
        runner.run_until_idle().await.unwrap();
        run.digests_after = runner.keystore().login_digests();
        run.erased_after = runner.login_account(ERASED_EMAIL).unwrap();
        run.live_after = runner.login_account(LIVE_EMAIL).unwrap();
        let state = engine.state();
        run.erased_email_after = runner.login_email(&state, ERASED).unwrap();
        run.live_email_after = runner.login_email(&state, LIVE).unwrap();
        let store = runner.keystore().clone();
        drop(runner);
        let again = ErasureRunner::resume(sim, engine.clone(), store)
            .await
            .unwrap();
        run.live_after_restart = again.login_account(LIVE_EMAIL).unwrap();
        run
    })
}

/// Design section 4.2, Q22: an address is the login email of one
/// account only, and the keyed lookup reads it in any letter case.
#[test]
fn i81_login_email_index_maps_one_address_to_one_account() {
    let run = run_index();
    assert_eq!(run.taken, Some(LoginEmailSet::Taken));
    assert_eq!(run.found_any_case, Some(ERASED));
    assert_eq!(run.digests_before.len(), 2);
}

/// I-81, design section 3.5 (G24), decision 27: a batch that erases a
/// login email replaces the `Lookup` key. The erased address finds no
/// account and opens no more, the live address is found under the new
/// key, and no digest of the old key survives in the index.
#[test]
fn i81_erasing_a_login_email_rotates_the_lookup_key() {
    let run = run_index();
    assert_eq!(run.erased_after, None, "the erased address is still found");
    assert_eq!(run.erased_email_after, None, "the erased address opens");
    assert_eq!(run.live_after, Some(LIVE), "the live address is lost");
    assert_eq!(run.live_email_after.as_deref(), Some(LIVE_EMAIL));
    assert_eq!(run.digests_after.len(), 1);
    for d in &run.digests_after {
        assert!(
            !run.digests_before.contains(d),
            "a digest under the old Lookup key survived the batch"
        );
    }
}

/// I-81, design section 3.4: the index survives a restart from the
/// durable keystore, whose `Lookup` group opens again under custody.
#[test]
fn i81_login_email_index_survives_a_restart() {
    let run = run_index();
    assert_eq!(run.live_after_restart, Some(LIVE));
}
