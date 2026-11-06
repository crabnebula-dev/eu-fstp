//! Fakes of the M3 ports of `fstp_api_core::port` (design section 6.1). A
//! contract test runs each fake and each M3 implementation through the
//! same suite. Lane W3b owns this module, and its test author wrote it.
//!
//! Every fake is a cheap handle over shared state, so a test keeps a clone
//! after the ports move into an `ApiCore`, and reads what each port saw.
//! The fakes hold synthetic data only: the synthetic vault of
//! `fstp-domain-testkit`, generated sessions and fake digests.
//!
//! - [`FakePorts`] implements `CellPorts`. Two port types of `port.rs`
//!   are W0 placeholders with private fields, `TenantSettings` and
//!   `NoticePage`. No code outside `port.rs` can build them, so they reach
//!   the fakes through [`PortSeams`]. Until the lead gives them public
//!   constructors, [`cell::FakeCell::new`] refuses with [`NotImplemented`].
//! - [`tokens::FakeTokens`] holds MCP token grants. `port.rs` has no
//!   token port yet, so dispatch cannot resolve a bearer token (gap
//!   reported by the W3b test author).
//! - [`fixture`] builds the I-85 world from genesis through production
//!   commands.
//! - [`requests`] builds the operations of the I-85 tests through the
//!   adapter-facing decoders of `fstp_api_core::decode`.

pub mod audit;
pub mod cell;
pub mod clock;
#[cfg(test)]
mod creator_forged_tests;
pub mod creator_requests;
#[cfg(test)]
mod creator_wire_tests;
pub mod draft_cell;
pub mod engine;
pub mod fixture;
pub mod ids;
pub mod misc;
pub mod people_requests;
mod reads;
pub mod requests;
pub mod sessions;
pub mod shell;
pub mod step_up;
pub mod texts;
pub mod tokens;
pub mod vault;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_api_core::port::{CellPorts, NoticePage, Page, TenantSettings};
use fstp_domain::id::AccountId;

use crate::NotImplemented;

pub use audit::{FakeAudit, FakeVaultAudit, VaultAuditRecord};
pub use cell::FakeCell;
pub use clock::FakeClock;
pub use engine::{DryRun, Execution, FakeEngine};
pub use ids::FakeIds;
pub use misc::{
    FakeAccounts, FakeBreakGlass, FakeOutbox, FakePrecheck, FakeProber, FakeRecovery, FakeTenant,
};
pub use sessions::{FakeSessions, WebLogin};
pub use step_up::FakeStepUp;
pub use texts::{FakeBlobs, FakeSealer, FakeTexts};
pub use tokens::{FakeTokens, TokenGrant};
pub use vault::{CellOracle, FakeVault, fake_query_digest};

/// Locks `m`, taking the data of a poisoned lock. A fake never panics, so
/// a poisoned lock only means a test thread failed while holding it.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The values of the two W0 placeholder types of `port.rs` that only the
/// lead can build. See the module documentation.
#[derive(Clone)]
pub struct PortSeams {
    /// The tenant settings `TenantConfig::settings` returns.
    pub settings: Arc<TenantSettings>,
    /// Builds the notice page `Outbox::notices` returns.
    pub notices: Arc<dyn Fn(AccountId, Page) -> NoticePage + Send + Sync>,
}

impl std::fmt::Debug for PortSeams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortSeams(..)")
    }
}

/// The values of [`PortSeams`]: MCP enabled for every role (the P-74
/// SuperSAFE value), the inference record whose model is the fixture's
/// P-21 primary, and a synthetic tenant id.
pub fn port_seams() -> Result<PortSeams, NotImplemented> {
    let settings = TenantSettings {
        mcp: fstp_access::McpSettings::all_roles(),
        inference: Some(fstp_api_core::port::InferenceRecord {
            config: fstp_domain::id::LlmConfigId::from_raw(1),
            model: fstp_domain::policy::ModelRef(
                fstp_domain_testkit::r#gen::policy::MODEL_A.to_owned(),
            ),
        }),
        tenant: Some(fstp_api_core::port::TenantId::from_raw(0x7e7a_0001)),
    };
    Ok(PortSeams {
        settings: Arc::new(settings),
        notices: Arc::new(|_, _| NoticePage::default()),
    })
}

/// Every fake port of one cell. Cloning shares every port.
#[derive(Clone, Debug)]
pub struct FakePorts {
    /// The sessions port, which is also the sessions admin port.
    pub sessions: FakeSessions,
    /// The step-up port.
    pub step_up: FakeStepUp,
    /// The accounts port.
    pub accounts: FakeAccounts,
    /// The synthetic vault.
    pub vault: FakeVault,
    /// The engine port over the M2 engine.
    pub engine: FakeEngine,
    /// The audit sink.
    pub audit: FakeAudit,
    /// The text store.
    pub texts: FakeTexts,
    /// The blob store.
    pub blobs: FakeBlobs,
    /// The pre-check provider of the e2e cell.
    pub precheck: FakePrecheck,
    /// The sealer.
    pub sealer: FakeSealer,
    /// The recorder of vault answers that commit no command.
    pub vault_audit: FakeVaultAudit,
    /// The recovery approvals.
    pub recovery: FakeRecovery,
    /// The break-glass approvals.
    pub break_glass: FakeBreakGlass,
    /// The tenant configuration.
    pub tenant: FakeTenant,
    /// The outbox.
    pub outbox: FakeOutbox,
    /// The recording prober.
    pub prober: FakeProber,
    /// The controllable clock.
    pub clock: FakeClock,
    /// The deterministic id source.
    pub ids: FakeIds,
    /// The MCP token grants, held for the token port `port.rs` lacks.
    pub tokens: FakeTokens,
}

impl CellPorts for FakePorts {
    type Sessions = FakeSessions;
    type StepUp = FakeStepUp;
    type Accounts = FakeAccounts;
    type Vault = FakeVault;
    type Engine = FakeEngine;
    type Audit = FakeAudit;
    type Texts = FakeTexts;
    type Blobs = FakeBlobs;
    type Precheck = FakePrecheck;
    type Sealer = FakeSealer;
    type VaultAudit = FakeVaultAudit;
    type SessionsAdmin = FakeSessions;
    type Recovery = FakeRecovery;
    type BreakGlass = FakeBreakGlass;
    type Tenant = FakeTenant;
    type Outbox = FakeOutbox;
    type Prober = FakeProber;
    type Clock = FakeClock;
    type Ids = FakeIds;
    type Tokens = FakeTokens;

    fn sessions(&self) -> &FakeSessions {
        &self.sessions
    }
    fn step_up(&self) -> &FakeStepUp {
        &self.step_up
    }
    fn accounts(&self) -> &FakeAccounts {
        &self.accounts
    }
    fn vault(&self) -> &FakeVault {
        &self.vault
    }
    fn engine(&self) -> &FakeEngine {
        &self.engine
    }
    fn audit(&self) -> &FakeAudit {
        &self.audit
    }
    fn texts(&self) -> &FakeTexts {
        &self.texts
    }
    fn blobs(&self) -> &FakeBlobs {
        &self.blobs
    }
    fn precheck(&self) -> Option<&FakePrecheck> {
        Some(&self.precheck)
    }
    fn sealer(&self) -> &FakeSealer {
        &self.sealer
    }
    fn vault_audit(&self) -> &FakeVaultAudit {
        &self.vault_audit
    }
    fn sessions_admin(&self) -> &FakeSessions {
        &self.sessions
    }
    fn recovery(&self) -> &FakeRecovery {
        &self.recovery
    }
    fn break_glass(&self) -> &FakeBreakGlass {
        &self.break_glass
    }
    fn tenant(&self) -> &FakeTenant {
        &self.tenant
    }
    fn outbox(&self) -> &FakeOutbox {
        &self.outbox
    }
    fn prober(&self) -> &FakeProber {
        &self.prober
    }
    fn clock(&self) -> &FakeClock {
        &self.clock
    }
    fn ids(&self) -> &FakeIds {
        &self.ids
    }
    fn tokens(&self) -> &FakeTokens {
        &self.tokens
    }
}

/// Builds the `FakePorts` of the I-85 world.
///
/// It refuses until [`port_seams`] can build the two placeholder values.
pub fn fake_ports() -> Result<FakePorts, NotImplemented> {
    let world = fixture::pending_world().map_err(|_| {
        NotImplemented::new("fstp_api_testkit::fake::fake_ports: the I-85 world did not build")
    })?;
    let seams = port_seams()?;
    FakePorts::new(&world, seams)
}

impl FakePorts {
    /// The fake ports over `world`, with the placeholder values `seams`.
    pub fn new(world: &fixture::World, seams: PortSeams) -> Result<FakePorts, NotImplemented> {
        let clock = FakeClock::new(world.start);
        let vault = FakeVault::new(world.truth.clone());
        let tenant = FakeTenant::new(seams.settings, world.admins.clone());
        let prober = FakeProber::default();
        let vault_audit = FakeVaultAudit::default();
        let texts = FakeTexts::default();
        let blobs = FakeBlobs::default();
        let env = shell::CellEnvironment::new(
            &vault,
            prober.clone(),
            tenant.admin_set(),
            vault_audit.clone(),
        )
        .with_texts(texts.clone());
        let imports = shell::ImportShell::new(blobs.clone(), texts.clone());
        let engine = FakeEngine::open_with(world, vault.oracle(), env, Some(imports))
            .map_err(|_| NotImplemented::new("fstp_api_testkit::fake::FakePorts::new: engine"))?;
        let sessions = FakeSessions::new(clock.clone(), tenant.clone());
        Ok(FakePorts {
            sessions,
            step_up: FakeStepUp::new(clock.clone()),
            accounts: FakeAccounts::default(),
            vault,
            engine,
            audit: FakeAudit::default(),
            texts,
            blobs,
            precheck: FakePrecheck,
            sealer: FakeSealer::default(),
            vault_audit,
            recovery: FakeRecovery::default(),
            break_glass: FakeBreakGlass::default(),
            tenant,
            outbox: FakeOutbox::new(seams.notices),
            prober,
            clock,
            ids: FakeIds::default(),
            tokens: FakeTokens::default(),
        })
    }
}
