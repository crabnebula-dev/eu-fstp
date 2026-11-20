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

use std::collections::BTreeMap;
use std::sync::Arc;

use fstp_api_core::port::{
    ApprovalId, Clock, Ids, NoticePage, Outbox, Page, PortError, SecondAdminApproval, TenantConfig,
    TenantId, TenantSettings,
};
use fstp_api_core::views::{DeliveryPhase, DeliveryRow, EventState, TimelineRow};
use fstp_cell_core::timeline::EventStatus;
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_pgstore::{DeliveryLog, Phase};
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

/// The most delivery rows one page holds.
const MAX_DELIVERY_PAGE: u32 = 200;

/// The outbox (ADR-026 record of lane L5): no in-app notices yet, the
/// tenant's delivery log over `ops.delivery`, and a programme's timeline
/// from the ledger's timeline fold.
pub(crate) struct CellOutbox<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

/// Where an event stands, as the timeline read names it.
fn event_state(s: EventStatus) -> EventState {
    match s {
        EventStatus::Scheduled => EventState::Scheduled,
        EventStatus::Cancelled(_) => EventState::Cancelled,
        EventStatus::Fired => EventState::Fired,
    }
}

/// The phase of a delivery head row, as the delivery log read names it.
fn phase(p: Phase) -> DeliveryPhase {
    match p {
        Phase::Claimed => DeliveryPhase::Claimed,
        Phase::Committing => DeliveryPhase::Committing,
        Phase::Sent => DeliveryPhase::Sent,
        Phase::Transient => DeliveryPhase::Transient,
        Phase::Permanent => DeliveryPhase::Permanent,
        Phase::InDoubt => DeliveryPhase::InDoubt,
    }
}

impl<R: Runtime, V: Send + Sync> Outbox for CellOutbox<R, V> {
    fn notices(&self, a: AccountId, page: Page) -> NoticePage {
        let _ = (a, page);
        NoticePage::default()
    }

    /// One page of the head of each message with a delivery row, newest
    /// first (M6 design section 6). Each names its row, template, event,
    /// template version, phase, attempts and last reply code, never a body
    /// or an address (I-27). The event comes from the message's commit
    /// point, or from the fired message whose key gives its row. A message
    /// no fired event of the ledger names is left out.
    async fn deliveries(&self, page: Page) -> Result<Vec<DeliveryRow>, PortError> {
        let log = DeliveryLog::new(self.0.app.clone()).map_err(|_| PortError::Unavailable)?;
        let heads = log
            .heads(page.limit.min(MAX_DELIVERY_PAGE), page.offset)
            .await
            .map_err(|_| PortError::Unavailable)?;
        let state = self.0.engine.state();
        let events: BTreeMap<[u8; 16], [u8; 32]> = state
            .timeline()
            .fired_messages()
            .map(|(idem, event)| (fstp_timeline::outbox_id(idem), *event))
            .collect();
        let mut out = Vec::with_capacity(heads.len());
        for (head, commit) in heads {
            let Some(event) = commit
                .map(|c| c.event)
                .or_else(|| events.get(&head.outbox).copied())
            else {
                continue;
            };
            let Some(template) = fstp_timeline::event_template(&state, &event) else {
                continue;
            };
            let version = match commit {
                Some(c) => c.template_version,
                None => fstp_mail::Template::latest(template, fstp_mail::Locale::En)
                    .and_then(|t| u16::try_from(t.version()).ok())
                    .unwrap_or(0),
            };
            out.push(DeliveryRow {
                outbox: head.outbox,
                template: template.code(),
                event,
                template_version: version,
                phase: phase(head.phase),
                attempts: head.attempt,
                reply_code: head.reply_code,
            });
        }
        Ok(out)
    }

    /// The scheduled, cancelled and fired events of `programme`, by due
    /// instant then id (M6 design section 6, R-NT-01). The ledger's
    /// timeline fold holds them, so a restart reads the same events.
    async fn timeline(&self, programme: ProgrammeId) -> Result<Vec<TimelineRow>, PortError> {
        let state = self.0.engine.state();
        let mut rows: Vec<TimelineRow> = state
            .timeline()
            .events()
            .filter(|(_, e)| fstp_timeline::event_programme(&state, e) == Some(programme))
            .map(|(id, e)| TimelineRow {
                event: *id,
                kind: e.kind,
                due: e.due,
                state: event_state(e.status),
            })
            .collect();
        rows.sort_by_key(|r| (r.due, r.event));
        Ok(rows)
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
