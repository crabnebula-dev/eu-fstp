//! `TenantConfig`, `Outbox`, `Clock` and `Ids` of the production cell
//! (ADR-026).
//!
//! Interim readings, pending Daniel:
//!
//! - The MCP settings are the P-74 default, MCP enabled for every role.
//!   The ledger's tenant part does not carry P-74 to this port yet.
//! - The tenant id bound into every action digest is the cell id: one
//!   tenant per cell on a SaaS pilot (ADR-026 "Deployment of the pilot").
//! - The cell has no inference record before onboarding records one, so a
//!   publication is refused (R-LA-05).
//! - The cell records no second tenant admin approval through this port.

use std::sync::Arc;

use fstp_api_core::port::{
    ApprovalId, Clock, Ids, NoticePage, Outbox, Page, PortError, SecondAdminApproval, TenantConfig,
    TenantId, TenantSettings,
};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_rt::Runtime;

use super::Inner;

/// The tenant configuration.
pub(crate) struct CellTenant<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> TenantConfig for CellTenant<R, V> {
    fn settings(&self) -> Arc<TenantSettings> {
        Arc::new(TenantSettings {
            mcp: fstp_access::McpSettings::all_roles(),
            inference: None,
            tenant: Some(TenantId::from_raw(u128::from_be_bytes(self.0.cell))),
        })
    }

    /// The ledger's tenant admin set (Q31 A).
    fn is_tenant_admin(&self, a: AccountId) -> bool {
        self.0.engine.state().tenant().is_admin(a)
    }

    /// ADR-021: the cell's organisation port, for a ledger with no tenant
    /// part.
    fn organisation_active(&self) -> bool {
        self.0
            .organisation
            .active_in(self.0.engine.state().engine())
    }

    async fn approval(&self, id: ApprovalId) -> Result<SecondAdminApproval, PortError> {
        let _ = id;
        Err(PortError::Refused)
    }
}

/// The outbox: no in-app notices, and the delivery log and timeline reads
/// fail closed until their ports are built over `ops.*`.
pub(crate) struct CellOutbox;

impl Outbox for CellOutbox {
    fn notices(&self, a: AccountId, page: Page) -> NoticePage {
        let _ = (a, page);
        NoticePage::default()
    }
}

/// The cell clock: the engine's, which a test world moves.
pub(crate) struct CellClock<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> Clock for CellClock<R, V> {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

/// Fresh ids from the cell's random source.
pub(crate) struct CellIds;

impl Ids for CellIds {
    fn fresh(&self) -> Result<u128, PortError> {
        fstp_crypto::random_array::<16>()
            .map(u128::from_be_bytes)
            .map_err(|_| PortError::Unavailable)
    }
}
