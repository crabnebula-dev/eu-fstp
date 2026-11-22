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
//! - [`kind::RETENTION_END`]: the end of a grant's funder retention
//!   period (P-41), due at the confirmation of its last payment request
//!   plus P-41 years (`fstp_domain::retention`). Its source is the grant.
//!   It carries no email and no command: the tenant admins' reminder is
//!   the platform mailbox message the API core derives from the same
//!   date (lane m5/retention, interim, pending Daniel: no email template
//!   exists for it). Its fire entry records that retention ended.
//! - [`kind::SIGNER_ROTATION_DUE`]: the notice companion key is a year old
//!   (ADR-004; Daniel, 2026-11-15 late). Sourced by the key, due 365 days
//!   after its latest `create_signer` or `rotate_signer` key record, and
//!   moved by a rotation. It fires once per generation, with no email and
//!   no command: it is the operator's reminder on the timeline.
//! - [`kind::REPORTING_PERIOD_END`] and [`kind::REPORT_DEADLINE`]: the end
//!   of each reporting period of an active programme and its report
//!   deadline, from P-57 (`fstp_domain::reporting`, Daniel, 2026-11-15
//!   late). Their source is the programme and the period number. They
//!   carry no email and no command: the programme managers' reminder is
//!   the mailbox message the API core derives from the same dates.
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
use fstp_domain::id::{AccountId, CallId, ProgrammeId, ProposalId};
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
    /// The end of a grant's funder retention period (P-41, Daniel,
    /// 2026-11-15 late): the confirmation of its last payment request plus
    /// P-41 years.
    pub const RETENTION_END: u16 = 11;
    /// The end of a programme's reporting period (P-57, Daniel,
    /// 2026-11-15 late): the midnight after its last day.
    pub const REPORTING_PERIOD_END: u16 = 12;
    /// The report deadline of a reporting period (P-57): the midnight
    /// after its last day.
    pub const REPORT_DEADLINE: u16 = 13;
    /// The notice companion key is a year old and due for rotation
    /// (ADR-004; Daniel, 2026-11-15 late: the operator rotates it by hand,
    /// and the platform reminds the operator when a year is up).
    pub const SIGNER_ROTATION_DUE: u16 = 14;
    /// A passkey was flagged suspect and is disabled (ADR-008, Daniel,
    /// 2026-11-19). Sourced by the flag's ordinal (big-endian `u64` from
    /// 1, the position of the `CredentialSuspect` record among them), due
    /// at the first tick that sees it. It fires once, with one email to the
    /// holder when the tenant has a mail relay and none otherwise.
    pub const PASSKEY_DISABLED: u16 = 15;
    /// The invitation of a person to a programme role by address (J2,
    /// ADR-026 record of lane L5). Sourced by the programme and the
    /// creator invitation ([`role_invitation_source`]), due when the
    /// accounts port schedules it. Only that port fires it, since only it
    /// holds the link token the one email carries. The plan never cancels
    /// it, and [`firing`] never builds its entry.
    pub const ROLE_INVITATION: u16 = 16;
    /// The invitation of a second tenant admin by address (J0, SoD-07,
    /// ADR-026 record of lane L18). Sourced by the tenant invitation id
    /// ([`admin_invitation_event`]), due when the accounts port schedules
    /// it. As for [`ROLE_INVITATION`], only that port fires it, the plan
    /// never cancels it, and [`super::firing`] never builds its entry.
    pub const ADMIN_INVITATION: u16 = 17;
    /// A person's open verification request became visible to the people
    /// who may record it (ADR-026 record of lane L24, lead reading of
    /// 2026-11-22). Sourced by the account and the request's ordinal, both
    /// big-endian, due at the first tick that sees it. It fires once, with
    /// one email to each recorder when the tenant has a relay.
    pub const VERIFICATION_REQUEST: u16 = 18;
}

/// A level 2 signing key is due for replacement this long after its
/// generation was made: 365 days, as the cell keystore counts it
/// (`fstp_cell::tasks::erasure::SIGNER_LIFETIME_US`, ADR-004).
pub const SIGNER_LIFETIME_US: i64 = 365 * 24 * 60 * 60 * 1_000_000;

/// The source of every `SIGNER_ROTATION_DUE` event: the notice companion
/// key, the only level 2 signer purpose of the App chain.
pub const NOTICE_COMPANION_SOURCE: &[u8] = b"notice_companion";

/// The `SIGNER_ROTATION_DUE` event of the latest generation in
/// `generations` (the instants of its `create_signer` and
/// `rotate_signer` key records): due 365 days after it. The version is
/// the generation's position, so a rotation cancels the scheduled event,
/// superseded by one a year after the new generation. A fired event is
/// not derived again for its generation. No generation, no event.
pub fn signer_events(t: &TimelineState, generations: &[Timestamp]) -> Vec<Derived> {
    let Some(last) = generations.last() else {
        return Vec::new();
    };
    let version = u64::try_from(generations.len().saturating_sub(1)).unwrap_or(u64::MAX);
    let fired = t.events().any(|(_, x)| {
        x.kind == kind::SIGNER_ROTATION_DUE
            && x.source == NOTICE_COMPANION_SOURCE
            && x.source_version == version
            && x.status == EventStatus::Fired
    });
    if fired {
        return Vec::new();
    }
    vec![Derived {
        kind: kind::SIGNER_ROTATION_DUE,
        lead: 0,
        source: NOTICE_COMPANION_SOURCE.to_vec(),
        source_version: version,
        due: last.micros().saturating_add(SIGNER_LIFETIME_US),
        offset_minutes: 0,
    }]
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

/// The source of the `ROLE_INVITATION` event of the creator invitation
/// `invitation` on `programme`: both ids, big-endian (ADR-026 record of
/// lane L5).
pub fn role_invitation_source(programme: ProgrammeId, invitation: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&programme.raw().to_be_bytes());
    out.extend_from_slice(&invitation.to_be_bytes());
    out
}

/// The programme of a `ROLE_INVITATION` event source, if it is one.
pub fn role_invitation_programme(source: &[u8]) -> Option<ProgrammeId> {
    let head: [u8; 16] = source.get(..16)?.try_into().ok()?;
    (source.len() == 32).then(|| ProgrammeId::from_raw(u128::from_be_bytes(head)))
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
    for d in retention_events(t, &retention_ends(s)) {
        put(d);
    }
    for d in period_events(t, &fstp_domain::reporting::active_reporting_periods(core)) {
        put(d);
    }
    for d in signer_events(t, s.signer_generations()) {
        put(d);
    }
    // ADR-026 record of lane L24: each open request, once visible.
    for account in s.verification_requests() {
        let (Some(ordinal), true) = (
            s.verification_request_ordinal(account),
            verification_request_visible(s, account),
        ) else {
            continue;
        };
        let source = verification_request_source(account, ordinal);
        put(Derived {
            kind: kind::VERIFICATION_REQUEST,
            lead: 0,
            due: scheduled_due(t, kind::VERIFICATION_REQUEST, &source, 0).unwrap_or(now.micros()),
            source,
            source_version: 0,
            offset_minutes: 0,
        });
    }
    for (i, _) in s.auth().suspect_flags().iter().enumerate() {
        let ordinal = u64::try_from(i).map_or(u64::MAX, |n| n.saturating_add(1));
        let source = ordinal.to_be_bytes().to_vec();
        put(Derived {
            kind: kind::PASSKEY_DISABLED,
            lead: 0,
            due: scheduled_due(t, kind::PASSKEY_DISABLED, &source, 0).unwrap_or(now.micros()),
            source,
            source_version: 0,
            offset_minutes: 0,
        });
    }
    out
}

/// Every grant whose funder retention period has a start and an end
/// (P-41, `fstp_domain::retention`), from the confirmation instants the
/// cell folded.
pub fn retention_ends(s: &CellState) -> Vec<fstp_domain::retention::RetentionEnd> {
    fstp_domain::retention::retention_ends(&s.engine().core, s.payments_confirmed())
}

/// The `RETENTION_END` events of `ends` (P-41).
///
/// The source is the grant id. An event already fired for a grant ends
/// its derivation, since retention ends once. The version counts the
/// cancelled events of the grant, so a moved end (a changed P-41)
/// cancels the scheduled event, superseded by one at the new end
/// (R-NT-01 AC), and each end is scheduled at most once per version.
pub fn retention_events(
    t: &TimelineState,
    ends: &[fstp_domain::retention::RetentionEnd],
) -> Vec<Derived> {
    let mut out = Vec::new();
    for e in ends {
        let source = e.grant.raw().to_be_bytes().to_vec();
        let mine = || {
            t.events()
                .filter(|(_, x)| x.kind == kind::RETENTION_END && x.source == source)
                .map(|(_, x)| x)
        };
        if mine().any(|x| x.status == EventStatus::Fired) {
            continue;
        }
        let cancelled = mine()
            .filter(|x| matches!(x.status, EventStatus::Cancelled(_)))
            .count();
        let cancelled = u64::try_from(cancelled).unwrap_or(u64::MAX);
        let due = e.end.micros();
        // A scheduled event at another instant is superseded: the next
        // version is derived, so `diff` cancels the old one.
        let moved = mine().any(|x| x.status == EventStatus::Scheduled && x.due != due);
        let version = if moved {
            cancelled.saturating_add(1)
        } else {
            cancelled
        };
        out.push(Derived {
            kind: kind::RETENTION_END,
            lead: 0,
            source,
            source_version: version,
            due,
            offset_minutes: 0,
        });
    }
    out
}

/// The `REPORTING_PERIOD_END` and `REPORT_DEADLINE` events of `periods`
/// (P-57, `funder-reporting.md`: "Reporting period ends and report
/// deadlines from the Data Sheet become timeline events with reminders").
///
/// The source is the programme id (16 bytes) then the period number (2
/// bytes, big-endian). Each event fires once. The version counts the
/// cancelled events of its kind and source, so a moved date (a changed
/// P-57) cancels the scheduled event, superseded by one at the new date,
/// and a period that P-57 no longer holds is cancelled.
pub fn period_events(
    t: &TimelineState,
    periods: &[(ProgrammeId, fstp_domain::reporting::ReportingPeriod)],
) -> Vec<Derived> {
    let mut out = Vec::new();
    for (programme, p) in periods {
        let mut source = programme.raw().to_be_bytes().to_vec();
        source.extend_from_slice(&p.index.to_be_bytes());
        for (kind, due) in [
            (kind::REPORTING_PERIOD_END, p.end.micros()),
            (kind::REPORT_DEADLINE, p.deadline.micros()),
        ] {
            if let Some(d) = once_event(t, kind, &source, due) {
                out.push(d);
            }
        }
    }
    out
}

/// The event of `kind` from `source` due at `due`, which fires once: none
/// once one fired, else the version that `diff` schedules, one more than
/// the cancelled ones when a scheduled event stands at another instant.
fn once_event(t: &TimelineState, kind: u16, source: &[u8], due: i64) -> Option<Derived> {
    let mine = || {
        t.events()
            .filter(move |(_, x)| x.kind == kind && x.source == source)
            .map(|(_, x)| x)
    };
    if mine().any(|x| x.status == EventStatus::Fired) {
        return None;
    }
    let cancelled = mine()
        .filter(|x| matches!(x.status, EventStatus::Cancelled(_)))
        .count();
    let cancelled = u64::try_from(cancelled).unwrap_or(u64::MAX);
    let moved = mine().any(|x| x.status == EventStatus::Scheduled && x.due != due);
    let version = if moved {
        cancelled.saturating_add(1)
    } else {
        cancelled
    };
    Some(Derived {
        kind,
        lead: 0,
        source: source.to_vec(),
        source_version: version,
        due,
        offset_minutes: 0,
    })
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
        // J2: the accounts port schedules and fires an invitation event
        // itself, so no derived set ever holds one (`kind::ROLE_INVITATION`).
        if e.status != EventStatus::Scheduled
            || derived.contains_key(id)
            || e.kind == kind::ROLE_INVITATION
            || e.kind == kind::ADMIN_INVITATION
        {
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
        // P-41: no email and no command. The fire entry records that
        // retention ended, and the API core's mailbox reminds the tenant
        // admins from the same date (module documentation).
        kind::RETENTION_END => Vec::new(),
        // P-57: no email and no command, as for retention. The API core's
        // mailbox reminds the programme managers from the same dates.
        kind::REPORTING_PERIOD_END | kind::REPORT_DEADLINE => Vec::new(),
        // ADR-004: the operator's reminder. No email and no command: the
        // operator rotates the key by hand, with step-up, through the
        // control plane (`fstp_control::api::CpApiRequest::RotateNoticeKey`).
        kind::SIGNER_ROTATION_DUE => Vec::new(),
        // J2: only the accounts port fires an invitation, with the body it
        // composed (`kind::ROLE_INVITATION`).
        kind::ROLE_INVITATION | kind::ADMIN_INVITATION => return None,
        // ADR-008, 2026-11-19: one email to the holder of the flagged
        // passkey, when the tenant has a relay.
        // ADR-026 record of lane L24: one email to each recorder, when the
        // tenant has a relay. It names no person (I-27).
        kind::VERIFICATION_REQUEST => {
            let head: [u8; 16] = e.source.get(..16)?.try_into().ok()?;
            let account = AccountId::from_raw(u128::from_be_bytes(head));
            verification_request_drafts(&verification_recorders(s, account), mail_relay_set(s))
                .into_iter()
                .map(|(to, template, bindings)| Draft {
                    to,
                    template,
                    bindings,
                })
                .collect()
        }
        kind::PASSKEY_DISABLED => {
            let ordinal = u64::from_be_bytes(e.source.as_slice().try_into().ok()?);
            let at = usize::try_from(ordinal.checked_sub(1)?).ok()?;
            let holder = *s.auth().suspect_flags().get(at)?;
            passkey_disabled_drafts(holder, mail_relay_set(s))
                .into_iter()
                .map(|(to, template, bindings)| Draft {
                    to,
                    template,
                    bindings,
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

/// The `ROLE_INVITATION` event of the creator invitation `invitation` on
/// `programme`, due at `now` (J2, ADR-026 record of lane L5). One creator
/// invitation has one event, so a retried schedule names the same event.
pub fn role_invitation_event(programme: ProgrammeId, invitation: u128, now: Timestamp) -> Derived {
    Derived {
        kind: kind::ROLE_INVITATION,
        lead: 0,
        source: role_invitation_source(programme, invitation),
        source_version: 0,
        due: now.micros(),
        offset_minutes: 0,
    }
}

/// The `ADMIN_INVITATION` event of the tenant admin invitation
/// `invitation`, due at `now` (J0, ADR-026 record of lane L18). Its source
/// is the invitation id, big-endian, so a retried schedule names the same
/// event.
pub fn admin_invitation_event(invitation: u128, now: Timestamp) -> Derived {
    Derived {
        kind: kind::ADMIN_INVITATION,
        lead: 0,
        source: invitation.to_be_bytes().to_vec(),
        source_version: 0,
        due: now.micros(),
        offset_minutes: 0,
    }
}

/// The message of the admin invitation event `event` to the address whose
/// SHA-256 digest is `address`, with the `admin-invitation` template at its
/// latest version (I-26). [`role_invitation_firing`] fires it.
pub fn admin_invitation_message(event: &EventId, address: [u8; 32]) -> Option<InvitationMessage> {
    let template = Template::latest(TemplateId::AdminInvitation, Locale::En)?;
    let idem = message_idem(event, Recipient::Address(address), CHANNEL_EMAIL);
    Some(InvitationMessage {
        outbox: outbox_id(&idem),
        idem,
        template,
    })
}

/// The one message of a `ROLE_INVITATION` firing before it is composed:
/// its row id, key and template version.
#[derive(Clone, Copy, Debug)]
pub struct InvitationMessage {
    /// The `ops.outbox` row id.
    pub outbox: [u8; 16],
    /// The idempotency key, of the event, the address and email (I-26).
    pub idem: Idem,
    /// The template version, `role-invitation` at its latest version.
    pub template: &'static Template,
}

/// The message of the invitation event `event` to the address whose
/// SHA-256 digest is `address` (I-26: one event, one recipient, one
/// channel, one key).
pub fn role_invitation_message(event: &EventId, address: [u8; 32]) -> Option<InvitationMessage> {
    let template = Template::latest(TemplateId::RoleInvitation, Locale::En)?;
    let idem = message_idem(event, Recipient::Address(address), CHANNEL_EMAIL);
    Some(InvitationMessage {
        outbox: outbox_id(&idem),
        idem,
        template,
    })
}

/// The firing of the scheduled invitation event `event` at `now`, with
/// the composed message `body` of `message` (J2, I-25). It fires an
/// `ADMIN_INVITATION` event the same way (J0, ADR-026 record of lane
/// L18). It records the template version first when the ledger does not
/// hold it, and lists the
/// one message. `None` when the event is not a scheduled, due invitation.
pub fn role_invitation_firing(
    s: &CellState,
    event: &EventId,
    message: &InvitationMessage,
    body: Vec<u8>,
    now: Timestamp,
) -> Option<Firing> {
    let t = s.timeline();
    let e = t.event(event)?;
    let port_fired = e.kind == kind::ROLE_INVITATION || e.kind == kind::ADMIN_INVITATION;
    if !port_fired || e.status != EventStatus::Scheduled || e.due > now.micros() {
        return None;
    }
    let code = template_code(message.template.id());
    let version = u16::try_from(message.template.version()).ok()?;
    let templates = match t.template(code, version) {
        Some(_) => Vec::new(),
        None => vec![TimelineRecord::TemplateVersionRecorded {
            template: code,
            version,
            locale: Locale::En.code().to_owned(),
            digest: message.template.digest(),
        }],
    };
    Some(Firing {
        command: TimelineCommand::Fire {
            event: *event,
            templates,
            messages: vec![FiredMessage {
                outbox: message.outbox,
                idem: message.idem,
                template: code,
                version,
            }],
            then: None,
        },
        bodies: vec![MessageBody {
            outbox: message.outbox,
            body,
        }],
    })
}

/// The programme the event `e` belongs to, read from its source, for the
/// programme timeline (M6 design section 6, R-NT-01, ADR-026 record of
/// lane L5). `None` for a cell-wide event, such as a signer rotation or a
/// disabled passkey, and for a source the state no longer resolves.
///
/// A sweep event's source is the digest of its command, so it is matched
/// against the sweep commands each proposal of the cell could have: its
/// stage 2 expiry, start of execution, completion, and re-entry into each
/// call of its programme.
pub fn event_programme(
    s: &CellState,
    e: &fstp_cell_core::timeline::ScheduledEvent,
) -> Option<ProgrammeId> {
    let core = &s.engine().core;
    let of_call = |c: CallId| fstp_domain::programme::call(core, c).map(|v| v.programme());
    let of_proposal = |p: ProposalId| s.proposal(p).and_then(|(c, _)| of_call(c));
    let id16 = |b: &[u8]| -> Option<u128> {
        let head: [u8; 16] = b.get(..16)?.try_into().ok()?;
        Some(u128::from_be_bytes(head))
    };
    match e.kind {
        kind::IMMEDIATE => {
            let seq = immediate_seq(&e.source)?;
            let (_, _, ev) = s.timeline().enqueued().find(|(q, _, _)| *q == seq)?;
            match ev {
                OutboxEvent::ProposalOutcome { proposal, .. }
                | OutboxEvent::IrcConcern { proposal, .. }
                | OutboxEvent::NotifiableConflict { proposal, .. }
                | OutboxEvent::CopyRequested { proposal, .. } => of_proposal(*proposal),
                OutboxEvent::BindingEnded { binding } => {
                    core.roster().binding(*binding).map(|b| b.programme)
                }
            }
        }
        kind::CORRIGENDUM => of_call(CallId::from_raw(id16(&e.source)?)),
        kind::RETENTION_END => of_proposal(ProposalId::from_raw(id16(&e.source)?)),
        kind::REPORTING_PERIOD_END | kind::REPORT_DEADLINE => {
            id16(&e.source).map(ProgrammeId::from_raw)
        }
        kind::ROLE_INVITATION => role_invitation_programme(&e.source),
        kind::STAGE2_EXPIRY | kind::RE_ENTER | kind::START_EXECUTION | kind::COMPLETE => {
            s.proposals().find_map(|(proposal, call)| {
                let programme = of_call(call)?;
                let mut candidates = vec![
                    fstp_domain::Command::ExpireStage2 { proposal },
                    fstp_domain::Command::StartExecution { proposal },
                    fstp_domain::Command::Complete { proposal },
                ];
                for (next, _) in core.calls().iter() {
                    if of_call(next) == Some(programme) {
                        candidates.push(fstp_domain::Command::ReEnter {
                            proposal,
                            call: next,
                        });
                    }
                }
                candidates
                    .iter()
                    .any(|c| command_source(c) == e.source)
                    .then_some(programme)
            })
        }
        _ => None,
    }
}

/// The template of the email an event fires, by its kind and, for an
/// immediate event, its outbox record (the delivery log read, ADR-026
/// record of lane L5). `None` for an event that sends no email.
pub fn event_template(s: &CellState, event: &EventId) -> Option<TemplateId> {
    let e = s.timeline().event(event)?;
    match e.kind {
        kind::IMMEDIATE => {
            let seq = immediate_seq(&e.source)?;
            let (_, _, ev) = s.timeline().enqueued().find(|(q, _, _)| *q == seq)?;
            match ev {
                OutboxEvent::ProposalOutcome { .. } => Some(TemplateId::ProposalOutcome),
                OutboxEvent::IrcConcern { .. } => Some(TemplateId::IrcConcern),
                OutboxEvent::NotifiableConflict { .. } => Some(TemplateId::NotifiableConflict),
                OutboxEvent::CopyRequested { .. } => Some(TemplateId::SubmissionCopy),
                OutboxEvent::BindingEnded { .. } => None,
            }
        }
        kind::CORRIGENDUM => Some(TemplateId::Corrigendum),
        kind::PASSKEY_DISABLED => Some(TemplateId::PasskeyDisabled),
        kind::ROLE_INVITATION => Some(TemplateId::RoleInvitation),
        kind::ADMIN_INVITATION => Some(TemplateId::AdminInvitation),
        kind::VERIFICATION_REQUEST => Some(TemplateId::IdCheckWaiting),
        _ => None,
    }
}

/// Whether the tenant set a mail relay (ADR-018). Without one no email
/// leaves the cell, so a notice by email is skipped.
pub fn mail_relay_set(s: &CellState) -> bool {
    s.engine()
        .tenant
        .state()
        .is_some_and(|t| t.mail_relay().is_some())
}

/// The messages of a `PASSKEY_DISABLED` event for `holder` (ADR-008,
/// 2026-11-19): one, to the holder's account, when the tenant has a relay,
/// and none otherwise. It holds one link to the platform home and no
/// other value, so no time, id, name or address reaches the email (I-27).
pub fn passkey_disabled_drafts(
    holder: AccountId,
    relay: bool,
) -> Vec<(Recipient, TemplateId, Bindings)> {
    if !relay {
        return Vec::new();
    }
    vec![(
        Recipient::Account(holder),
        TemplateId::PasskeyDisabled,
        Bindings::new().with(Slot::Link, Value::Link(LinkTarget::Home)),
    )]
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

/// The system command id of a timeline command in the cell `cell`. A
/// firing is bound to its event, so every retry of one firing has one id
/// and the store answers a repeat as a duplicate (I-23, ADR-007). A plan
/// is bound to its records, which the state fixes, so a retried plan
/// repeats its id too.
///
/// The id is an HMAC-SHA256 keyed by the cell id, as the vault-change
/// reaction ids are (`fstp_cell_core::reaction_command_id`, Daniel,
/// 2026-11-13). Two cells can hold the same command, such as the plan of
/// the P-57 period events of a programme with the same id and dates. The
/// id is stored in clear in each ledger, so an unkeyed id would link the
/// two tenants (I-20, `t_iso_i20`).
pub fn command_id(cell: [u8; 16], c: &TimelineCommand) -> [u8; 16] {
    let mut h = fstp_crypto::HmacSha256::new(&cell);
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

/// The source of the `VERIFICATION_REQUEST` event of the request of
/// `account` with `ordinal`: the account id, then the ordinal, both
/// big-endian (ADR-026 record of lane L24).
pub fn verification_request_source(account: AccountId, ordinal: u64) -> Vec<u8> {
    let mut s = account.raw().to_be_bytes().to_vec();
    s.extend_from_slice(&ordinal.to_be_bytes());
    s
}

/// Whether the request of `account` is visible to the people who may
/// record it (ADR-026 record of lane L24, R-NG-01): at once for a person
/// with no Receiving binding, and for an applicant only once a proposal
/// the person is bound to is in NEGOTIATION or later.
pub fn verification_request_visible(s: &CellState, account: AccountId) -> bool {
    use fstp_domain::roles::Group;
    let core = &s.engine().core;
    let mut receiving = false;
    for (_, b) in core.roster().bindings() {
        if b.account != account || b.group() != Group::Receiving {
            continue;
        }
        receiving = true;
        let open = b.proposal().is_some_and(|p| {
            b.held()
                && fstp_domain::view::proposal_state(core, p)
                    .is_some_and(|st| fstp_cell_core::RELEASE_STATES.contains(&st))
        });
        if open {
            return true;
        }
    }
    !receiving
}

/// The people who may record the check of `account`: every tenant admin
/// with no Judging binding, other than `account` (ADR-004 record of lane
/// L13b, ADR-026 record of lane L24). The cell decides each ticket again.
pub fn verification_recorders(s: &CellState, account: AccountId) -> BTreeSet<AccountId> {
    use fstp_domain::roles::Group;
    let core = &s.engine().core;
    s.tenant()
        .admins()
        .into_iter()
        .filter(|a| *a != account)
        .filter(|a| {
            !core
                .roster()
                .bindings()
                .any(|(_, b)| b.account == *a && b.group() == Group::Judging)
        })
        .collect()
}

/// The messages of a `VERIFICATION_REQUEST` event to `recorders` (ADR-026
/// record of lane L24): one per recorder's account, when the tenant has a
/// relay, and none otherwise. Each holds one link to the member page and
/// no other value, so no person, id or time reaches the email (I-27).
pub fn verification_request_drafts(
    recorders: &BTreeSet<AccountId>,
    relay: bool,
) -> Vec<(Recipient, TemplateId, Bindings)> {
    if !relay {
        return Vec::new();
    }
    recorders
        .iter()
        .map(|a| {
            (
                Recipient::Account(*a),
                TemplateId::IdCheckWaiting,
                Bindings::new().with(Slot::Link, Value::Link(LinkTarget::Members)),
            )
        })
        .collect()
}
