//! The M6 timeline engine (M6 design section 4, lane L6-TL).
//!
//! - [`derive`] is a pure function of the cell state and the clock. It
//!   reads the core state and the timeline fold only (I-10).
//! - [`plan`] diffs it against the scheduled set: `EventScheduled` for a
//!   new event, `EventCancelled` for a scheduled event that is no longer
//!   derived. A source whose version changed cancels the old event,
//!   superseded by the new one (R-NT-01 AC).
//! - [`firing`] builds the one entry an event fires in: its first-use
//!   template versions, the records of its System command and
//!   `EventFired`, with the bodies of its outbox rows (I-25).
//!
//! Kinds in this build:
//!
//! - [`kind::IMMEDIATE`]: every `OutboxEnqueued` record, due at its entry
//!   time. `ProposalOutcome` and `IrcConcern` go to the lead,
//!   `NotifiableConflict` to the programme's FSTP coordinators, and
//!   `BindingEnded` has no email (group removal is M8). A
//!   `CopyRequested` goes to the given address (R-SB-04, lane L6-API).
//! - The four sweep kinds of `fstp_engine::sweep`, due when the domain
//!   lists the command. The event carries the command, and no email.
//! - [`kind::CORRIGENDUM`]: each numbered change of a call's effective
//!   limits, to every lead and team member bound to a proposal in the
//!   call, resolved when it fires (I-53).
//!
//! The other kinds of design section 4 have their codes reserved here,
//! but no source yet: milestone reminders need a milestone due date that
//! the plan does not hold, and the notice event needs the M5 notice record.
//! A copy request is an immediate event, so its reserved kind stays unused.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod message;

use std::collections::{BTreeMap, BTreeSet};

use fstp_cell_core::CellState;
use fstp_cell_core::timeline::{
    CHANNEL_EMAIL, EventId, EventStatus, FiredMessage, Idem, MessageBody, Recipient,
    TimelineCommand, TimelineRecord, TimelineState, event_id, immediate_source, message_idem,
};
use fstp_domain::id::{AccountId, CallId, ProposalId};
use fstp_domain::record::OutboxEvent;
use fstp_domain::roles::{BindingScope, Role};
use fstp_domain::time::Timestamp;
use fstp_engine::sweep::{self, SweepKind};
use fstp_mail::{Bindings, LinkTarget, Locale, Moment, Slot, Template, TemplateId, Value};

use crate::message::MessageSpec;

/// The event kinds, as the ledger records them (M6 design section 4).
pub mod kind {
    /// An `OutboxEnqueued` record.
    pub const IMMEDIATE: u16 = 1;
    /// The sweep's `ExpireStage2`.
    pub const STAGE2_EXPIRY: u16 = 2;
    /// The sweep's `ReEnter`.
    pub const RE_ENTER: u16 = 3;
    /// The sweep's `StartExecution`.
    pub const START_EXECUTION: u16 = 4;
    /// The sweep's `Complete`.
    pub const COMPLETE: u16 = 5;
    /// A milestone reminder (P-31). Reserved: no source yet.
    pub const MILESTONE_REMINDER: u16 = 6;
    /// A milestone is overdue (P-33). Reserved: no source yet.
    pub const MILESTONE_OVERDUE: u16 = 7;
    /// A corrigendum (I-53).
    pub const CORRIGENDUM: u16 = 8;
    /// A contractual notice (I-40). Reserved: no source yet.
    pub const NOTICE_ISSUED: u16 = 9;
    /// A copy of a submission record (R-SB-04). Reserved: no source yet.
    pub const COPY_REQUESTED: u16 = 10;
}

/// The event kind of a sweep kind.
pub const fn sweep_kind(k: SweepKind) -> u16 {
    match k {
        SweepKind::ExpireStage2 => kind::STAGE2_EXPIRY,
        SweepKind::ReEnter => kind::RE_ENTER,
        SweepKind::StartExecution => kind::START_EXECUTION,
        SweepKind::Complete => kind::COMPLETE,
    }
}

/// The ledger code of a template: its position in `TemplateId::ALL`,
/// from 1.
pub fn template_code(id: TemplateId) -> u16 {
    let at = TemplateId::ALL.iter().position(|t| *t == id).unwrap_or(0);
    u16::try_from(at).map_or(0, |n| n.saturating_add(1))
}

/// The `ops.outbox` row id of the message with key `idem`: the first 16
/// bytes of SHA-256 over `"fstp-outbox-v1"` and the key. One key has one
/// row id, so a retried firing names the same row.
pub fn outbox_id(idem: &Idem) -> [u8; 16] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-outbox-v1");
    h.update(idem);
    let d = h.finish();
    let mut out = [0u8; 16];
    for (o, b) in out.iter_mut().zip(d.iter()) {
        *o = *b;
    }
    out
}

/// One derived event (M6 design section 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    /// The kind.
    pub kind: u16,
    /// The offset from the source's due date, microseconds.
    pub lead: i64,
    /// The source reference.
    pub source: Vec<u8>,
    /// The source version.
    pub source_version: u64,
    /// When it is due, UTC microseconds.
    pub due: i64,
    /// The recorded UTC offset, minutes.
    pub offset_minutes: i16,
}

impl Derived {
    /// The event id.
    pub fn id(&self) -> EventId {
        event_id(self.kind, self.lead, &self.source, self.source_version)
    }

    /// The `EventScheduled` record of this event.
    pub fn scheduled(&self) -> TimelineRecord {
        TimelineRecord::EventScheduled {
            event: self.id(),
            kind: self.kind,
            lead: self.lead,
            source: self.source.clone(),
            source_version: self.source_version,
            due: self.due,
            offset_minutes: self.offset_minutes,
        }
    }
}

/// Every event the state derives at `now`, by id.
///
/// A sweep or corrigendum event is due at the first instant it is
/// derived, so its due instant is the one already scheduled, or `now`.
/// A sweep event's source version counts the earlier fired or cancelled
/// events of its command, so a command that comes due again for the same
/// subject gets a new event (state-machine NOTE 5 and NOTE 8).
pub fn derive(s: &CellState, now: Timestamp) -> BTreeMap<EventId, Derived> {
    let t = s.timeline();
    let mut out = BTreeMap::new();
    let mut put = |d: Derived| {
        out.insert(d.id(), d);
    };
    for (seq, at, _) in t.enqueued() {
        put(Derived {
            kind: kind::IMMEDIATE,
            lead: 0,
            source: immediate_source(seq, 0),
            source_version: 0,
            due: at,
            offset_minutes: 0,
        });
    }
    for cmd in sweep::due(s.engine(), now).unwrap_or_default() {
        let fstp_engine::Command::Core(core) = cmd else {
            continue;
        };
        let Some(k) = sweep::kind_of(&core) else {
            continue;
        };
        let kind = sweep_kind(k);
        let source = command_source(&core);
        let version = terminal(t, kind, &source);
        put(Derived {
            kind,
            lead: 0,
            due: scheduled_due(t, kind, &source, version).unwrap_or(now.micros()),
            source,
            source_version: version,
            offset_minutes: 0,
        });
    }
    let core = &s.engine().core;
    for (call, _) in core.calls().iter() {
        let Some(limits) = fstp_domain::programme::effective_limits(core, call) else {
            continue;
        };
        for tg in limits.tightenings() {
            let source = call.raw().to_be_bytes().to_vec();
            let version = u64::from(tg.corrigendum.get());
            put(Derived {
                kind: kind::CORRIGENDUM,
                lead: 0,
                due: scheduled_due(t, kind::CORRIGENDUM, &source, version).unwrap_or(now.micros()),
                source,
                source_version: version,
                offset_minutes: 0,
            });
        }
    }
    out
}

/// The source reference of a sweep event: SHA-256 of the canonical core
/// command, which names its subject.
fn command_source(core: &fstp_domain::Command) -> Vec<u8> {
    let bytes = fstp_cell_core::encode_cell_command(&fstp_cell_core::CellCommand::Engine(
        fstp_engine::Command::Core(core.clone()),
    ));
    fstp_crypto::sha256(&bytes).to_vec()
}

/// How many events of `kind` from `source` were fired or cancelled.
fn terminal(t: &TimelineState, kind: u16, source: &[u8]) -> u64 {
    let n = t
        .events()
        .filter(|(_, e)| e.kind == kind && e.source == source)
        .filter(|(_, e)| e.status != EventStatus::Scheduled)
        .count();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The due instant of the event already scheduled for this source and
/// version, if any.
fn scheduled_due(t: &TimelineState, kind: u16, source: &[u8], version: u64) -> Option<i64> {
    t.event(&event_id(kind, 0, source, version)).map(|e| e.due)
}

/// The records that bring the scheduled set of `t` to `derived`: an
/// `EventScheduled` for each derived event the timeline never held, then
/// an `EventCancelled` for each scheduled event no longer derived. A
/// cancelled event names the derived event of the same kind, lead and
/// source that supersedes it (R-NT-01 AC). A fired or cancelled event is
/// never scheduled again (I-25).
pub fn diff(t: &TimelineState, derived: &BTreeMap<EventId, Derived>) -> Vec<TimelineRecord> {
    let mut out: Vec<TimelineRecord> = derived
        .iter()
        .filter(|(id, _)| t.event(id).is_none())
        .map(|(_, d)| d.scheduled())
        .collect();
    for (id, e) in t.events() {
        if e.status != EventStatus::Scheduled || derived.contains_key(id) {
            continue;
        }
        let superseded_by = derived
            .iter()
            .find(|(new, d)| {
                t.event(new).is_none()
                    && d.kind == e.kind
                    && d.lead == e.lead
                    && d.source == e.source
            })
            .map(|(new, _)| *new);
        out.push(TimelineRecord::EventCancelled {
            event: *id,
            superseded_by,
        });
    }
    out
}

/// The schedule and cancel records due at `now` ([`derive`], [`diff`]).
pub fn plan(s: &CellState, now: Timestamp) -> Vec<TimelineRecord> {
    diff(s.timeline(), &derive(s, now))
}

/// The scheduled events due at `now`, by due instant and then id.
pub fn due_events(t: &TimelineState, now: Timestamp) -> Vec<EventId> {
    let mut due: Vec<(i64, EventId)> = t
        .events()
        .filter(|(_, e)| e.status == EventStatus::Scheduled && e.due <= now.micros())
        .map(|(id, e)| (e.due, *id))
        .collect();
    due.sort_unstable();
    due.into_iter().map(|(_, id)| id).collect()
}

/// One firing: the command and the bodies of its outbox rows, in message
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firing {
    /// The `Fire` command.
    pub command: TimelineCommand,
    /// The bodies.
    pub bodies: Vec<MessageBody>,
}

/// One message before it has a key: recipient, template and values.
struct Draft {
    to: Recipient,
    template: TemplateId,
    bindings: Bindings,
}

/// The firing of `event` at `now`, or `None` while it cannot fire: not
/// scheduled, not due, its System command no longer due (the next plan
/// cancels it), or a message that does not render.
pub fn firing(s: &CellState, event: &EventId, now: Timestamp) -> Option<Firing> {
    let t = s.timeline();
    let e = t.event(event)?;
    if e.status != EventStatus::Scheduled || e.due > now.micros() {
        return None;
    }
    let when = Value::Moment(Moment::new(Timestamp::from_micros(e.due), e.offset_minutes).ok()?);
    let mut then = None;
    let drafts = match e.kind {
        kind::IMMEDIATE => {
            let seq = immediate_seq(&e.source)?;
            let (_, _, ev) = t.enqueued().find(|(q, _, _)| *q == seq)?;
            immediate(s, ev, when, now)
        }
        kind::CORRIGENDUM => {
            let call = CallId::from_raw(u128::from_be_bytes(e.source.as_slice().try_into().ok()?));
            let n = u32::try_from(e.source_version).ok()?;
            receiving(s, call, now)
                .into_iter()
                .map(|to| Draft {
                    to: Recipient::Account(to),
                    template: TemplateId::Corrigendum,
                    bindings: Bindings::new()
                        .with(Slot::Call, Value::Call(call))
                        .with(Slot::Count, Value::Count(n))
                        .with(Slot::When, when)
                        .with(Slot::Link, Value::Link(LinkTarget::CallGuide(call))),
                })
                .collect()
        }
        k => {
            let cmd = sweep::due(s.engine(), now)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|c| match c {
                    fstp_engine::Command::Core(core) => Some(core),
                    _ => None,
                })
                .find(|core| {
                    sweep::kind_of(core).map(sweep_kind) == Some(k)
                        && command_source(core) == e.source
                })?;
            then = Some(Box::new(cmd));
            Vec::new()
        }
    };
    let mut templates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut messages = Vec::with_capacity(drafts.len());
    let mut bodies = Vec::with_capacity(drafts.len());
    for d in drafts {
        let template = Template::latest(d.template, Locale::En)?;
        if template.slots() != d.bindings.slots().collect::<BTreeSet<Slot>>() {
            return None;
        }
        let code = template_code(d.template);
        let version = u16::try_from(template.version()).ok()?;
        if t.template(code, version).is_none() && seen.insert((code, version)) {
            templates.push(TimelineRecord::TemplateVersionRecorded {
                template: code,
                version,
                locale: Locale::En.code().to_owned(),
                digest: template.digest(),
            });
        }
        let to = d.to;
        let idem = message_idem(event, to, CHANNEL_EMAIL);
        let outbox = outbox_id(&idem);
        let body = MessageSpec {
            template: d.template,
            version: template.version(),
            locale: Locale::En,
            event: *event,
            idem,
            to,
            date: now,
            bindings: d.bindings,
        }
        .encode()?;
        messages.push(FiredMessage {
            outbox,
            idem,
            template: code,
            version,
        });
        bodies.push(MessageBody { outbox, body });
    }
    Some(Firing {
        command: TimelineCommand::Fire {
            event: *event,
            templates,
            messages,
            then,
        },
        bodies,
    })
}

/// The ledger sequence of an immediate event's source.
fn immediate_seq(source: &[u8]) -> Option<u64> {
    let seq: [u8; 8] = source.get(..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(seq))
}

/// The messages of an outbox record (M6 design section 4, reading 3).
fn immediate(s: &CellState, ev: &OutboxEvent, when: Value, now: Timestamp) -> Vec<Draft> {
    let lead = |p: ProposalId| s.proposal(p).map(|(_, lead)| lead);
    match *ev {
        OutboxEvent::ProposalOutcome { proposal, state } => lead(proposal)
            .map(|to| Draft {
                to: Recipient::Account(to),
                template: TemplateId::ProposalOutcome,
                bindings: Bindings::new()
                    .with(Slot::Proposal, Value::Proposal(proposal))
                    .with(Slot::State, Value::State(state))
                    .with(Slot::When, when)
                    .with(Slot::Link, Value::Link(LinkTarget::Proposal(proposal))),
            })
            .into_iter()
            .collect(),
        // The concern text stays on the platform: the email says a notice
        // is waiting (reading 3, I-27).
        OutboxEvent::IrcConcern { proposal, .. } => lead(proposal)
            .map(|to| Draft {
                to: Recipient::Account(to),
                template: TemplateId::IrcConcern,
                bindings: Bindings::new()
                    .with(Slot::Proposal, Value::Proposal(proposal))
                    .with(Slot::Link, Value::Link(LinkTarget::Notices)),
            })
            .into_iter()
            .collect(),
        OutboxEvent::NotifiableConflict { proposal } => {
            let Some((call, _)) = s.proposal(proposal) else {
                return Vec::new();
            };
            coordinators(s, call, now)
                .into_iter()
                .map(|to| Draft {
                    to: Recipient::Account(to),
                    template: TemplateId::NotifiableConflict,
                    bindings: Bindings::new()
                        .with(Slot::Call, Value::Call(call))
                        .with(Slot::Proposal, Value::Proposal(proposal))
                        .with(
                            Slot::Link,
                            Value::Link(LinkTarget::NotifiableConflicts(call)),
                        ),
                })
                .collect()
        }
        // Group membership removal is M8. No email.
        OutboxEvent::BindingEnded { .. } => Vec::new(),
        // R-SB-04, reading 4: one copy to the given address, ids and times
        // only. The recipient is the digest of the sealed address text, which
        // the dispatcher resolves. The instant is the first submission, or
        // the request time before one.
        OutboxEvent::CopyRequested { proposal, address } => {
            let submitted = fstp_domain::proposal::copy::submitted_at(&s.engine().core, proposal)
                .and_then(|t| Moment::new(t, 0).ok())
                .map_or(when, Value::Moment);
            vec![Draft {
                to: Recipient::Address(address.digest().bytes()),
                template: TemplateId::SubmissionCopy,
                bindings: Bindings::new()
                    .with(Slot::Proposal, Value::Proposal(proposal))
                    .with(Slot::When, submitted)
                    .with(Slot::Link, Value::Link(LinkTarget::Proposal(proposal))),
            }]
        }
    }
}

/// The FSTP coordinators of the programme of `call`, active at `now`.
fn coordinators(s: &CellState, call: CallId, now: Timestamp) -> BTreeSet<AccountId> {
    let core = &s.engine().core;
    let Some(programme) = fstp_domain::programme::call(core, call).map(|c| c.programme()) else {
        return BTreeSet::new();
    };
    core.roster()
        .bindings()
        .filter(|(_, b)| {
            b.role == Role::FstpCoordinator
                && b.programme == programme
                && b.scope == BindingScope::Programme
                && b.active_at(now)
        })
        .map(|(_, b)| b.account)
        .collect()
}

/// Every lead and team member bound to a proposal in `call` at `now`
/// (reading 5).
fn receiving(s: &CellState, call: CallId, now: Timestamp) -> BTreeSet<AccountId> {
    s.engine()
        .core
        .roster()
        .bindings()
        .filter(|(_, b)| {
            matches!(b.role, Role::Applicant | Role::ApplicantTeamMember)
                && matches!(b.scope, BindingScope::Proposal { call: c, .. } if c == call)
                && b.active_at(now)
        })
        .map(|(_, b)| b.account)
        .collect()
}

/// The most records one `Plan` command carries.
pub const PLAN_CHUNK: usize = 256;

/// The system command id of a timeline command. A firing is bound to its
/// event, so every retry of one firing has one id and the store answers a
/// repeat as a duplicate (I-23, ADR-007). A plan is bound to its records,
/// which the state fixes, so a retried plan repeats its id too.
pub fn command_id(c: &TimelineCommand) -> [u8; 16] {
    let mut h = fstp_crypto::Sha256::new();
    match c {
        TimelineCommand::Fire { event, .. } => {
            h.update(b"fstp-timeline-fire-v1");
            h.update(event);
        }
        TimelineCommand::Plan { .. } => {
            h.update(b"fstp-timeline-plan-v1");
            h.update(&fstp_cell_core::encode_cell_command(
                &fstp_cell_core::CellCommand::Timeline(c.clone()),
            ));
        }
    }
    let d = h.finish();
    let mut suffix = [0u8; 8];
    for (o, b) in suffix.iter_mut().zip(d.iter()) {
        *o = *b;
    }
    fstp_cell_core::system_command_id(suffix)
}
