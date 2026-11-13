//! The system tasks of a cell: the timeline that ends sessions at a
//! scheduled binding end, and the licence refresh and update check of a
//! self-hosted cell (M3 design sections 5.1, 8.2, 10.1 to 10.3; I-23,
//! I-38, I-39, I-77).
//!
//! Lane W3a (agent two, test author) wrote these tests before the tasks.
//! Each test runs `fstp_cell::tasks` through one seam below, on a
//! scripted clock. Each seam refuses with `NotImplemented` until the
//! tasks exist, so each test is red for that reason only. The production
//! agent replaces the seam bodies and leaves the assertions alone.
//!
//! The expected request bytes come from `fstp_release::egress::encode`,
//! the only code that builds requests to CrabNebula hosts (I-38). The
//! tasks must send exactly those bytes through
//! `fstp_cell::egress::Destination::CrabNebula`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod stepup_common;

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_auth::{Method, SessionView};
use fstp_cell::config::Mode;
use fstp_cell::egress::{CnClient, CnFault, CnTransport};
use fstp_cell::engine::{CellEngine, Unanchored, VaultClient};
use fstp_cell::tasks::release::{self, LicenceHold, ReleaseSettings, ReleaseView};
use fstp_cell::tasks::{Clock, timeline};
use fstp_cell_core::action_digest;
use fstp_cell_core::driver::VaultFault;
use fstp_cell_core::gate::{self, Action, Admitted};
use fstp_cell_core::gate::{HighRiskAction, LoginPolicy, StepUpView};
use fstp_cell_core::ops::OpsCommand;
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{
    CellCommand, KeyCommand, SystemTask, is_system_command_id, system_command_id,
};
use fstp_domain::id::BindingId;
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, P1, SodSetup, grant, sod_truth};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_ledger::{MemStore, Seq};
use fstp_release::egress::{
    Channel, CnCall, LICENCE_HOST, LicenceRefresh, ProductVersion, UPDATE_HOST, UpdateCheck, encode,
};
use fstp_release::licence::{
    DAY_S, Ed25519Public, Ed25519SigningKey, KeySet, LicenceId, LicenceKind, VerifiedToken,
    refresh_response, sign_token,
};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;

/// One microsecond.
const US: i64 = 1;
/// One second in microseconds.
const SECOND_US: i64 = 1_000_000;
/// One hour in microseconds.
const HOUR_US: i64 = 3_600 * SECOND_US;
/// One day in microseconds.
const DAY_US: i64 = 24 * HOUR_US;
/// The licence refresh timeout (design section 10.2).
const REFRESH_TIMEOUT_US: i64 = 10 * SECOND_US;

/// The instant of the scheduled binding end in the timeline scenario.
const END_AT: i64 = 1_800_000_000_000_000;

/// The licence of the self-hosted cell.
const LICENCE: LicenceId = LicenceId([0x5A; 16]);
/// The running version.
const VERSION: ProductVersion = ProductVersion(0, 3, 0);

/// A command the timeline task issued.
#[derive(Clone, Debug)]
struct Issued {
    /// The tick at which the task issued it.
    at: i64,
    /// The command.
    command: CellCommand,
    /// Its command id.
    id: [u8; 16],
    /// Whether the store reported it as a duplicate of an earlier entry.
    duplicate: bool,
}

/// The ground-truth vault of the M2 generators, as the engine reaches it.
struct TruthVault(GroundTruth);

impl VaultClient for TruthVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(self.0.epoch()))
    }

    fn ask(
        &self,
        queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        let mut out = Answers::new();
        let mut ok = true;
        for q in queries {
            match self.0.try_answer(q) {
                Some(a) => out.insert(q.clone(), a),
                None => ok = false,
            }
        }
        std::future::ready(if ok {
            Ok(out)
        } else {
            Err(VaultFault::Unavailable)
        })
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

/// The instant of the setup: an hour before the scheduled end.
const SETUP_AT: i64 = END_AT - HOUR_US;

/// The binding of account A.
const BINDING_A: BindingId = BindingId::from_raw(500);

/// The tenant admin's session.
const SESSION: [u8; 16] = [0x5E; 16];

/// Runs `cmd` as the tenant admin through the gate at `SETUP_AT`, with
/// the fresh strong step-up `stepup` that the ledger granted, when it is
/// high risk.
async fn as_admin(
    engine: &CellEngine,
    cmd: CellCommand,
    id: u8,
    stepup: Option<[u8; 16]>,
) -> Result<(), String> {
    let now = Timestamp::from_micros(SETUP_AT);
    let session = SessionView {
        id: SESSION,
        account: ADMIN,
        method: Method::Passkey,
        started: now,
        last_used: now,
    };
    let command_id = [id; 16];
    let action = Action::Command(cmd.clone());
    let high = HighRiskAction::of(&action).map_err(|d| format!("{d:?}"))?;
    let stepup = high.zip(stepup).map(|(_, stepup)| StepUpView {
        id: stepup,
        session: session.id,
        action_digest: action_digest(&cmd, command_id),
        asserted_at: now,
        strong: true,
        consumed: false,
    });
    let policy = LoginPolicy {
        stepup_freshness_us: 5 * 60 * SECOND_US,
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
    .map_err(|d| format!("the gate refused the tenant admin: {d:?}"))?;
    engine
        .execute(admitted)
        .await
        .map(|_| ())
        .map_err(|e| format!("the setup command failed: {e:?}"))
}

/// The commands of the timeline scenario, each with its command id
/// byte: the tenant admin and A's Drafting binding with its end
/// scheduled for [`END_AT`]. The programme is written by
/// [`write_programme`] first.
fn setup_commands() -> Result<Vec<(CellCommand, u8)>, String> {
    let mut g = grant(
        BINDING_A,
        A,
        P1,
        Role::CallDrafter,
        Timestamp::from_micros(SETUP_AT),
    )
    .cmd;
    if let fstp_domain::Command::GrantRole { end, .. } = &mut g {
        *end = Some(Timestamp::from_micros(END_AT));
    }
    Ok(vec![
        (
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
            0xA0,
        ),
        (CellCommand::Engine(fstp_engine::Command::Core(g)), 0xA2),
    ])
}

/// The corpus vault answered at the state's epoch, for the composed
/// programme entries.
struct AtEpoch<'a> {
    truth: &'a GroundTruth,
    epoch: VaultEpoch,
}

impl fstp_engine::IdentityOracle for AtEpoch<'_> {
    fn ask(
        &self,
        q: &Query,
    ) -> Result<fstp_domain::oracle::Answer, fstp_domain::oracle::OracleDown> {
        let mut a = self.truth.answer(q);
        a.epoch = self.epoch;
        Ok(a)
    }

    fn epoch(&self) -> Result<VaultEpoch, fstp_domain::oracle::OracleDown> {
        Ok(self.epoch)
    }
}

/// Writes programme `P1` straight into `mem` at `SETUP_AT`: the entries
/// the creator path appends for the setup's `CreateProgramme` (by
/// `ADMIN`) and `ActivateProgramme` (by the second tenant admin). Strict
/// D2e refuses both as core commands (M4 design section 15.0), so they
/// are composed as `fstp_domain_testkit::activation::run_core` composes
/// them, as `52cdc5c` did.
fn write_programme(mem: &mut MemStore<fstp_cell_core::CellRecord>) -> Result<(), String> {
    use fstp_domain_testkit::activation::{activation_records, open_records};
    use fstp_ledger::RecordStore;
    let steps = SodSetup::one(1, &[]).steps()?;
    let truth = sod_truth();
    for (step, id) in steps.iter().take(2).zip([0xB1u8, 0xB2]) {
        let mut entries = Vec::new();
        mem.read(Seq::ZERO, usize::MAX, &mut entries)
            .map_err(|e| format!("the store did not read: {e:?}"))?;
        let state = fstp_cell_core::replay(&entries)
            .map_err(|e| format!("the stored ledger does not fold: {e:?}"))?;
        let engine = state.engine();
        let ctx = fstp_domain::command::Ctx {
            now: Timestamp::from_micros(SETUP_AT),
            actor: step.actor,
            command: fstp_domain::id::CommandId::from_bytes([id; 16]),
            via: fstp_domain::command::Via::Web,
            tenant_admin: true,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        let vault = AtEpoch {
            truth: &truth,
            epoch: engine.epoch(),
        };
        let records = match &step.cmd {
            fstp_domain::Command::CreateProgramme { policy } => {
                open_records(engine, &vault, policy, &ctx)
            }
            cmd => activation_records(engine, &vault, cmd, &ctx),
        }
        .map_err(|e| format!("the programme step was refused: {e:?}"))?;
        let batch = records
            .into_iter()
            .map(fstp_cell_core::CellRecord::Engine)
            .collect();
        let head = RecordStore::head(mem);
        RecordStore::append(mem, head, SETUP_AT, [id; 16], batch)
            .map_err(|e| format!("the programme step did not append: {e:?}"))?;
    }
    Ok(())
}

/// The setup commands, each with its command id byte and the step-up the
/// ledger granted for it.
type Setup = Vec<(CellCommand, u8, Option<[u8; 16]>)>;

/// A store that holds programme `P1` ([`write_programme`]) and, granted at
/// `SETUP_AT`, the step-up of each
/// high-risk setup command (`stepup_common`), and the setup commands with
/// their step-ups.
fn setup_store() -> Result<(MemStore<fstp_cell_core::CellRecord>, Setup), String> {
    let mut mem = MemStore::new();
    write_programme(&mut mem)?;
    let mut setup = Vec::new();
    for (cmd, id) in setup_commands()? {
        let high =
            HighRiskAction::of(&Action::Command(cmd.clone())).map_err(|d| format!("{d:?}"))?;
        let stepup = match high {
            None => None,
            Some(_) => Some(stepup_common::grant_stepup(
                &mut mem, SESSION, ADMIN, &cmd, [id; 16], SETUP_AT,
            )?),
        };
        setup.push((cmd, id, stepup));
    }
    Ok((mem, setup))
}

/// Runs the setup commands through the gate.
async fn timeline_setup(engine: &CellEngine, setup: Setup) -> Result<(), String> {
    for (cmd, id, stepup) in setup {
        as_admin(engine, cmd, id, stepup).await?;
    }
    Ok(())
}

/// A's open passkey session, started at `SETUP_AT`, before the scheduled
/// end: the one row of `auth.session` in the scenario.
struct ASession;

impl timeline::SessionSource for ASession {
    fn sessions_of(&self, account: fstp_domain::id::AccountId) -> timeline::RowsFuture<'_> {
        let at = Timestamp::from_micros(SETUP_AT);
        let live = if account == A {
            vec![SessionView {
                id: [0xA5; 16],
                account: A,
                method: Method::Passkey,
                started: at,
                last_used: at,
            }]
        } else {
            Vec::new()
        };
        Box::pin(std::future::ready(Some(fstp_cell_core::SessionRows::new(
            live,
            Vec::new(),
        ))))
    }
}

/// Seam: starts a cell over in-memory parts where account A holds a
/// Drafting binding whose end is scheduled for [`END_AT`]
/// (`BindingEndScheduled`), and holds an open passkey session from before
/// it. Runs the timeline task once at each tick, in order. With
/// `restart_after = Some(i)`, the cell restarts over the same store after
/// tick `i`. Returns every command the task issued.
///
/// Reading: a command counts as issued when the engine committed it or
/// reported it as a duplicate. A command the decider refuses is not in the
/// list, so a refusal can never pass for a commit. The session itself is
/// not a ledger record but a row of `auth.session` (design section 4.2,
/// int3), so the timeline reads it through [`ASession`], its session
/// source.
fn run_timeline(ticks: &[i64], restart_after: Option<usize>) -> Result<Vec<Issued>, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    let ticks = ticks.to_vec();
    rt.block_on(async move {
        let (mem, setup) =
            setup_store().map_err(|e| Box::leak(e.into_boxed_str()) as &'static str)?;
        let store = Unanchored::open(mem, CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let mut shutdown = Shutdown::new();
        let (mut engine, mut task) =
            CellEngine::start(&rt2, store, TruthVault(sod_truth()), &shutdown, 8)
                .await
                .map_err(|_| "the engine did not start")?;
        timeline_setup(&engine, setup)
            .await
            .map_err(|e| Box::leak(e.into_boxed_str()) as &'static str)?;
        let mut out = Vec::new();
        for (i, t) in ticks.iter().enumerate() {
            for item in timeline::tick(&engine, &ASession, Timestamp::from_micros(*t)).await {
                if let timeline::Issued::Ran(Ok(done)) = item.result {
                    out.push(Issued {
                        at: *t,
                        command: item.command,
                        id: item.id,
                        duplicate: done.duplicate.is_some(),
                    });
                }
            }
            if restart_after == Some(i) {
                drop(engine);
                let store = task.await.map_err(|_| "the engine task failed")?;
                let store = Unanchored::open(store.into_inner(), CELL)
                    .await
                    .map_err(|_| "the store did not open again")?;
                shutdown = Shutdown::new();
                (engine, task) =
                    CellEngine::start(&rt2, store, TruthVault(sod_truth()), &shutdown, 8)
                        .await
                        .map_err(|_| "the engine did not restart")?;
            }
        }
        drop(engine);
        let _ = task.await;
        Ok(out)
    })
}

/// How the scripted CrabNebula services behave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    /// Both answer at once with valid responses.
    Healthy,
    /// No connection can be opened.
    Unreachable,
    /// Connections open and nothing is ever answered.
    Hangs,
    /// Both answer `503 Service Unavailable`.
    Refuses,
}

/// How one call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The service answered with a valid response.
    Answered,
    /// The task gave up waiting.
    TimedOut,
    /// The connection failed or the service refused.
    #[allow(
        dead_code,
        reason = "only the seam builds it, once the production path exists"
    )]
    Failed,
}

/// One call to a CrabNebula host.
#[derive(Clone, Debug)]
struct Call {
    /// The host the connection went to (the TLS server name).
    host: String,
    /// The plaintext request bytes above TLS.
    bytes: Vec<u8>,
    /// When the call started, in microseconds of the scripted clock.
    started: i64,
    /// When the task stopped waiting for it.
    ended: i64,
    /// How it ended.
    outcome: Outcome,
}

/// What the release tasks did.
#[derive(Debug)]
struct ReleaseRun {
    /// Every call to a CrabNebula host, in start order.
    calls: Vec<Call>,
    /// Whether an erasure-runner key command submitted one hour into the
    /// run committed.
    command_committed: bool,
}

/// The first instant of the scripted clock: 2027-01-15, UTC.
const START: i64 = 1_800_000_000_000_000 - 10 * DAY_US;

/// The cell id of these tests.
const CELL: [u8; 16] = [0x5C; 16];

/// A vault at the genesis epoch that answers nothing else: key commands
/// ask no query.
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

/// The scripted clock. A sleep moves time to its end at once. A sleep
/// past `start + span` stops the run. The first sleep across the
/// one-hour mark first submits the pending command through the engine.
struct SimClock {
    now: Mutex<i64>,
    end: i64,
    stop: Shutdown,
    submit: Mutex<Option<(CellEngine, Admitted)>>,
    committed: Mutex<bool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
struct Sim(Arc<SimClock>);

impl Clock for Sim {
    fn now(&self) -> i64 {
        *lock(&self.0.now)
    }

    fn sleep_until(&self, at: i64) -> impl Future<Output = ()> + Send {
        let me = Arc::clone(&self.0);
        async move {
            let hour = START + HOUR_US;
            let now = *lock(&me.now);
            if now < hour && at >= hour {
                let pending = lock(&me.submit).take();
                if let Some((engine, admitted)) = pending {
                    *lock(&me.now) = hour;
                    let ok = engine.execute(admitted).await.is_ok();
                    *lock(&me.committed) = ok;
                }
            }
            if at > me.end {
                me.stop.trigger();
            }
            let mut n = lock(&me.now);
            *n = (*n).max(at);
        }
    }
}

/// The scripted CrabNebula services, recording every call above TLS.
struct Services {
    service: Service,
    clock: Sim,
    key: Ed25519SigningKey,
    calls: Mutex<Vec<(String, Vec<u8>, i64)>>,
}

#[derive(Clone)]
struct Recorder(Arc<Services>);

fn http(status: &str, ctype: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    if let Some(t) = ctype {
        out.push_str(&format!("Content-Type: {t}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

impl Services {
    fn answer(&self, host: &str) -> Vec<u8> {
        if host == UPDATE_HOST {
            return http("200 OK", None, b"");
        }
        let issued = self.clock.now().div_euclid(SECOND_US);
        let token = VerifiedToken {
            licence: LICENCE,
            kind: LicenceKind::Noncommercial,
            issued_at: issued,
            refresh_after: issued + DAY_S,
            not_after: issued + 30 * DAY_S,
        };
        let signed = sign_token(&token, &self.key).unwrap();
        http(
            "200 OK",
            Some("application/octet-stream"),
            &refresh_response(None, &signed),
        )
    }
}

impl CnTransport for Recorder {
    fn exchange(
        &self,
        host: &'static str,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send {
        let me = Arc::clone(&self.0);
        async move {
            let started = me.clock.now();
            lock(&me.calls).push((host.to_owned(), request, started));
            match me.service {
                Service::Healthy => Ok(me.answer(host)),
                Service::Unreachable => Err(CnFault::Unreachable),
                Service::Hangs => std::future::pending().await,
                Service::Refuses => Ok(http("503 Service Unavailable", None, b"")),
            }
        }
    }
}

/// Seam: starts a cell in `mode` over in-memory parts, with licence
/// [`LICENCE`], version [`VERSION`] and channel `Stable`. Runs it for
/// `span` microseconds of a scripted clock with the services under
/// `service`, and records every call above TLS through the cell's
/// `Destination::CrabNebula` connector. One hour in, it submits one
/// erasure-runner key command.
fn run_release_tasks(mode: Mode, service: Service, span: i64) -> Result<ReleaseRun, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        let state = engine.state();
        let admitted = gate::admit_system(
            &state,
            Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp {
                op: b"{\"n\":1}".to_vec(),
            })),
            SystemTask::ErasureRunner,
            system_command_id(*b"release1"),
            Timestamp::from_micros(START + HOUR_US),
        )
        .map_err(|_| "the key command was not admitted")?;
        let stop = Shutdown::new();
        let clock = Sim(Arc::new(SimClock {
            now: Mutex::new(START),
            end: START + span,
            stop: stop.clone(),
            submit: Mutex::new(Some((engine.clone(), admitted))),
            committed: Mutex::new(false),
        }));
        let key = Ed25519SigningKey::from_seed(&[0x4B; 32]).map_err(|_| "no signing key")?;
        let keys = KeySet::shipped(&[Ed25519Public(key.public_key())]).map_err(|_| "no key set")?;
        let first = VerifiedToken {
            licence: LICENCE,
            kind: LicenceKind::Noncommercial,
            issued_at: 0,
            refresh_after: 0,
            not_after: START.div_euclid(SECOND_US) + 30 * DAY_S,
        };
        let services = Recorder(Arc::new(Services {
            service,
            clock: clock.clone(),
            key,
            calls: Mutex::new(Vec::new()),
        }));
        let client = CnClient::new(mode, services.clone());
        let view = ReleaseView::default();
        let settings = ReleaseSettings {
            licence: Some(LICENCE),
            version: VERSION,
            channel: Channel::Stable,
        };
        let signal = stop.signal();
        let hold = LicenceHold { token: first, keys };
        release::run(&clock, &client, mode, settings, Some(hold), &view, &signal).await;
        drop(signal);
        // A SaaS run returns at once, so the clock never reaches the hour.
        clock.sleep_until(START + span).await;
        let attempts = view.attempts();
        let recorded = lock(&services.0.calls).clone();
        if attempts.len() != recorded.len() {
            return Err("an attempt has no recorded call, or the reverse");
        }
        let calls = attempts
            .iter()
            .zip(recorded)
            .map(|(a, (host, bytes, started))| Call {
                host,
                bytes,
                started,
                ended: a.ended,
                outcome: match a.outcome {
                    release::Outcome::Answered => Outcome::Answered,
                    release::Outcome::TimedOut => Outcome::TimedOut,
                    release::Outcome::Failed(_) => Outcome::Failed,
                },
            })
            .collect();
        let command_committed = *lock(&clock.0.committed);
        drop(engine);
        let _ = task.await;
        Ok(ReleaseRun {
            calls,
            command_committed,
        })
    })
}

fn release(mode: Mode, service: Service, span: i64) -> ReleaseRun {
    run_release_tasks(mode, service, span).unwrap_or_else(|e| panic!("{e}"))
}

fn licence_bytes() -> Vec<u8> {
    encode(&CnCall::Licence(LicenceRefresh {
        licence: LICENCE,
        version: VERSION,
    }))
    .unwrap()
}

fn update_bytes() -> Vec<u8> {
    encode(&CnCall::Update(UpdateCheck {
        version: VERSION,
        channel: Channel::Stable,
    }))
    .unwrap()
}

fn calls_to<'a>(r: &'a ReleaseRun, host: &str) -> Vec<&'a Call> {
    r.calls.iter().filter(|c| c.host == host).collect()
}

/// The gaps between successive call starts.
fn gaps(calls: &[&Call]) -> Vec<i64> {
    calls
        .windows(2)
        .map(|w| w[1].started - w[0].started)
        .collect()
}

fn is_end_sessions(c: &CellCommand) -> bool {
    matches!(
        c,
        CellCommand::Ops(OpsCommand::EndSessionsAtBindingEnd { .. })
    )
}

/// I-77, design sections 5.1 and 8.2: at the instant of a scheduled
/// binding end, the timeline issues `EndSessionsAtBindingEnd` once, and
/// never one microsecond before. It also issues the M2 command that
/// records the end. Every command runs under a system task id.
#[test]
fn i77_cell_timeline_ends_sessions_at_a_scheduled_binding_end() {
    let ticks = [END_AT - US, END_AT, END_AT + US];
    let issued = run_timeline(&ticks, None).unwrap_or_else(|e| panic!("{e}"));
    let before = issued.iter().any(|i| i.at < END_AT);
    let ends: Vec<&Issued> = issued
        .iter()
        .filter(|i| is_end_sessions(&i.command) && !i.duplicate)
        .collect();
    let engine_end = issued
        .iter()
        .any(|i| i.at == END_AT && matches!(i.command, CellCommand::Engine(_)) && !i.duplicate);
    let ok = !before
        && ends.len() == 1
        && ends.first().is_some_and(|i| i.at == END_AT)
        && engine_end
        && issued.iter().all(|i| is_system_command_id(i.id));
    assert!(ok, "{issued:?}");
}

/// I-23, I-77, ADR-007, design section 5.2: a restart between ticks
/// replays the store, so the timeline commits each scheduled end once. A
/// command it issues again is reported as a duplicate.
#[test]
fn i23_cell_timeline_commits_each_scheduled_end_once_across_restarts() {
    let ticks = [END_AT, END_AT + US, END_AT + HOUR_US];
    let issued = run_timeline(&ticks, Some(0)).unwrap_or_else(|e| panic!("{e}"));
    let committed = issued
        .iter()
        .filter(|i| is_end_sessions(&i.command) && !i.duplicate)
        .count();
    assert!(committed == 1, "{issued:?}");
}

/// I-38, design section 10.1: every licence refresh a self-hosted cell
/// sends is exactly the `fstp_release::egress` template for its licence
/// and version.
#[test]
fn i38_cell_licence_refresh_bytes_match_the_egress_template() {
    let r = release(Mode::SelfHosted, Service::Healthy, 2 * DAY_US);
    let calls = calls_to(&r, LICENCE_HOST);
    let want = licence_bytes();
    assert!(
        !calls.is_empty() && calls.iter().all(|c| c.bytes == want),
        "{r:?}"
    );
}

/// I-38, design sections 10.1 and 10.3: every update check a self-hosted
/// cell sends is exactly the `fstp_release::egress` template for its
/// version and channel.
#[test]
fn i38_cell_update_check_bytes_match_the_egress_template() {
    let r = release(Mode::SelfHosted, Service::Healthy, 2 * DAY_US);
    let calls = calls_to(&r, UPDATE_HOST);
    let want = update_bytes();
    assert!(
        !calls.is_empty() && calls.iter().all(|c| c.bytes == want),
        "{r:?}"
    );
}

/// I-38, design section 10.1: a self-hosted cell reaches CrabNebula only
/// through the two service hosts, and only with the two templates.
#[test]
fn i38_cell_release_tasks_reach_only_the_two_service_hosts() {
    let r = release(Mode::SelfHosted, Service::Healthy, 2 * DAY_US);
    let licence = licence_bytes();
    let update = update_bytes();
    let ok = r.calls.iter().all(|c| {
        (c.host == LICENCE_HOST && c.bytes == licence)
            || (c.host == UPDATE_HOST && c.bytes == update)
    });
    assert!(ok && !r.calls.is_empty(), "{r:?}");
}

/// I-38, B12, design section 10.1: a SaaS cell never builds a call to a
/// CrabNebula host.
#[test]
fn i38_saas_cell_sends_nothing_to_crabnebula_hosts() {
    let r = release(Mode::Saas, Service::Healthy, 2 * DAY_US);
    assert!(r.calls.is_empty(), "{r:?}");
}

/// I-39, design section 10.2: the licence refresh runs, and runs at most
/// once a day: successive answered refreshes are at least a day apart.
#[test]
fn i39_cell_licence_refresh_runs_at_most_once_a_day() {
    let r = release(Mode::SelfHosted, Service::Healthy, 3 * DAY_US);
    let answered: Vec<&Call> = calls_to(&r, LICENCE_HOST)
        .into_iter()
        .filter(|c| c.outcome == Outcome::Answered)
        .collect();
    let g = gaps(&answered);
    assert!(
        answered.len() >= 2 && g.iter().all(|d| *d >= DAY_US),
        "gaps {g:?}, run {r:?}"
    );
}

/// I-39, design section 10.2: a refresh that gets no answer is abandoned
/// after at most ten seconds, and the task tries again later.
#[test]
fn i39_cell_licence_refresh_gives_up_after_ten_seconds() {
    let r = release(Mode::SelfHosted, Service::Hangs, 2 * DAY_US);
    let calls = calls_to(&r, LICENCE_HOST);
    let ok = calls.len() >= 2
        && calls.iter().all(|c| {
            c.outcome == Outcome::TimedOut
                && c.ended > c.started
                && c.ended - c.started <= REFRESH_TIMEOUT_US
        });
    assert!(ok, "{r:?}");
}

/// I-39, design section 10.2: after failed refreshes the task backs off.
/// The gaps between attempts never shrink, and the last is longer than
/// the first.
#[test]
fn i39_cell_licence_refresh_backs_off_after_failures() {
    let r = release(Mode::SelfHosted, Service::Refuses, DAY_US);
    let calls = calls_to(&r, LICENCE_HOST);
    let g = gaps(&calls);
    let ok = calls.len() >= 3
        && g.windows(2).all(|w| w[1] >= w[0])
        && matches!((g.first(), g.last()), (Some(a), Some(b)) if b > a);
    assert!(ok, "gaps {g:?}, run {r:?}");
}

/// I-39, design section 10.2: commands commit while the CrabNebula
/// services cannot be reached. No command waits for the licence task.
#[test]
fn i39_cell_commands_commit_while_crabnebula_services_are_down() {
    let r = release(Mode::SelfHosted, Service::Unreachable, 2 * HOUR_US);
    assert!(r.command_committed, "{r:?}");
}

/// The templates themselves: the licence refresh and the update check
/// are distinct, so a test above cannot pass by comparing one to itself.
#[test]
fn i38_egress_templates_differ_by_call() {
    assert_ne!(licence_bytes(), update_bytes());
}
