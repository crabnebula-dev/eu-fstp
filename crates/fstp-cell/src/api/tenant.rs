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
    ApprovalId, Clock, Ids, NoticePage, Outbox, Page, PortError, ProbeKind, ProbeOutcome, Prober,
    SecondAdminApproval, TenantConfig, TenantId, TenantSettings,
};

use crate::shell::probe::TenantProbe;
use fstp_api_core::system::{MailState, SystemFacts};
use fstp_api_core::views::{DeliveryPhase, DeliveryRow, EventState, TimelineRow};
use fstp_cell_core::timeline::EventStatus;
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_pgstore::{DeliveryLog, Phase};
use fstp_rt::Runtime;

use super::Inner;

/// The tenant configuration.
pub(crate) struct CellTenant<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: crate::engine::VaultClient> TenantConfig for CellTenant<R, V> {
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
    /// part. The production cell takes no answer from its configuration
    /// (ADR-026 record of lane L18), so its port answers "not active". Only
    /// a test world from before the tenant part sets it.
    fn organisation_active(&self) -> bool {
        self.0
            .organisation
            .active_in(self.0.engine.state().engine())
    }

    async fn approval(&self, id: ApprovalId) -> Result<SecondAdminApproval, PortError> {
        let _ = id;
        Err(PortError::Refused)
    }

    /// ADR-028 record of lane L20: the vault answers `epoch`, the relay
    /// greets, and the host status file, each live check within
    /// [`super::system::CHECK_LIMIT`].
    async fn system(&self) -> SystemFacts {
        let i = &self.0;
        let limit = super::system::CHECK_LIMIT;
        let vault_answers = matches!(
            fstp_rt::timeout(&i.rt, limit, i.vault.epoch()).await,
            Ok(Ok(_))
        );
        let mail = match (&i.relay, &i.probe) {
            (None, _) => MailState::NotConfigured,
            (Some(_), None) => MailState::Fails,
            (Some(_), Some(p)) => match fstp_rt::timeout(&i.rt, limit, p.channel()).await {
                Ok(fstp_creator::ProbeOutcome::Pass) => MailState::Works,
                _ => MailState::Fails,
            },
        };
        SystemFacts {
            vault_answers,
            mail,
            host: super::system::read_host_file(i.host_status.as_deref()),
            findings: findings_now(i).await,
        }
    }

    /// ADR-012 record of lane m10/declared-restore: one anchored events
    /// transaction holds the event naming the finding and the account,
    /// and the acknowledgement row keyed by the finding. The finding stays.
    /// A second acknowledgement of the same finding writes nothing.
    async fn acknowledge_finding(
        &self,
        account: AccountId,
        finding: u128,
    ) -> Result<(), PortError> {
        let i = &self.0;
        let Some(f) = i.findings.iter().find(|f| f.wire_id() == finding) else {
            return Err(PortError::Refused);
        };
        let ack = fstp_pgstore::finding_ack_idem(&i.cell, &f.id);
        let done = fstp_pgstore::outbox_written(&i.app, &[ack])
            .await
            .map_err(|_| PortError::Unavailable)?;
        if done.first().is_some_and(Option::is_some) {
            return Ok(());
        }
        let event = acknowledgement_event(finding, account).ok_or(PortError::Refused)?;
        let row = fstp_pgstore::OwnRow::FindingAck {
            finding: f.id,
            actor: account.raw().to_be_bytes(),
        };
        i.engine
            .append_events_with(i.engine.now(), vec![event], vec![row])
            .await
            .map_err(|_| PortError::Unavailable)
    }
}

/// The findings of the start-up, each with the time of its acknowledgement
/// if a tenant admin gave one (ADR-012 record of lane m10/declared-restore).
/// A store that cannot be read shows every finding as unacknowledged.
async fn findings_now<R: Runtime, V>(i: &Inner<R, V>) -> Vec<fstp_api_core::system::Finding> {
    let acks: Vec<[u8; 32]> = i
        .findings
        .iter()
        .map(|f| fstp_pgstore::finding_ack_idem(&i.cell, &f.id))
        .collect();
    let written = fstp_pgstore::outbox_written(&i.app, &acks)
        .await
        .unwrap_or_default();
    i.findings
        .iter()
        .enumerate()
        .map(|(k, f)| fstp_api_core::system::Finding {
            acknowledged_at: written
                .get(k)
                .copied()
                .flatten()
                .map(Timestamp::from_micros),
            ..*f
        })
        .collect()
}

/// The event of an acknowledgement: the finding's wire id and the
/// account, as canonical JSON of ids only.
fn acknowledgement_event(finding: u128, account: AccountId) -> Option<Vec<u8>> {
    use fstp_json::{Object, Value};
    let mut o = Object::new();
    let _ = o.insert("kind", Value::from("finding_acknowledged"));
    let _ = o.insert("finding", Value::String(finding.to_string()));
    let _ = o.insert("actor", Value::String(account.raw().to_string()));
    fstp_json::to_canonical(&Value::Object(o))
        .ok()
        .map(String::into_bytes)
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

/// The `Prober` of onboarding (Q5, ADR-026 record of lane L18) over the
/// ADR-027 probes: the Channels step checks the platform relay's greeting,
/// and the Domains and email step checks SPF, DKIM and DMARC of the domain
/// the admin saved. A Channels save that names Matrix or WhatsApp fails,
/// since those adapters are out of scope (B-03, B-05). Without probes, and
/// for a probe that names no domain, every probe fails.
pub(crate) struct CellTenantProber(pub(super) Option<Arc<dyn TenantProbe>>);

/// The port's outcome of a shell probe: anything but a pass fails (Q5).
fn outcome(o: fstp_creator::ProbeOutcome) -> ProbeOutcome {
    match o {
        fstp_creator::ProbeOutcome::Pass => ProbeOutcome::Pass,
        _ => ProbeOutcome::Fail,
    }
}

impl Prober for CellTenantProber {
    async fn probe(&self, p: ProbeKind) -> ProbeOutcome {
        match (p, &self.0) {
            (ProbeKind::Channel, Some(t)) => outcome(t.channel().await),
            _ => ProbeOutcome::Fail,
        }
    }

    async fn sending_domain(&self, domain: &str) -> ProbeOutcome {
        match &self.0 {
            Some(t) => outcome(t.domain(domain).await),
            None => ProbeOutcome::Fail,
        }
    }

    async fn channels(&self, matrix: bool, whatsapp: bool) -> ProbeOutcome {
        if matrix || whatsapp {
            return ProbeOutcome::Fail;
        }
        self.probe(ProbeKind::Channel).await
    }
}
