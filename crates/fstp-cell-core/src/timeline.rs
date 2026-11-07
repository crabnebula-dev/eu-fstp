//! The timeline ledger records (M6 design section 3.1, I-25, I-26,
//! R-NT-01).
//!
//! - [`event_id`]: SHA-256 over `"fstp-event-v1"`, the kind, the lead (the
//!   kind's offset from the due date, such as minus 14 days), the source
//!   reference and its version. An immediate event's source is the ledger
//!   entry and record index of its `OutboxEnqueued` record
//!   ([`immediate_source`]).
//! - [`message_idem`]: SHA-256 over `"fstp-msg-v1"`, the event, the
//!   recipient and the channel. It is the `ops.outbox.idem` of the
//!   message, so one (event, recipient, channel) has one outbox row
//!   (I-26).
//!
//! Variable-length and variant inputs carry a length or a tag, so no two
//! input tuples share a digest input.
//!
//! The fold ([`TimelineState`]) refuses a second `EventFired` for an event,
//! an idempotency key or outbox id listed twice, a fired message whose
//! template version was not recorded first (I-25), a template version
//! recorded twice, and firing or cancelling an event that is not
//! scheduled. A cancelled event stays in the state (R-NT-01 AC).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fstp_domain::FoldError as DomainFold;
use fstp_domain::id::AccountId;
use fstp_domain::record::OutboxEvent;

use crate::FoldError;

/// An event id (M6 design section 3.1).
pub type EventId = [u8; 32];

/// An idempotency key of one message (M6 design section 3.1).
pub type Idem = [u8; 32];

/// The channel byte of email (M6 design section 3.1).
pub const CHANNEL_EMAIL: u8 = 1;

/// The `ops.outbox.kind` of a timeline email message. Kind 1 is the
/// store's `PossibleDeletion` alert.
pub const OUTBOX_KIND_EMAIL: u16 = 2;

/// The longest source reference of an event.
pub const MAX_SOURCE_LEN: usize = 64;

/// The most messages one `EventFired` lists: the most outbox rows one
/// append inserts (`fstp_pgstore::MAX_OUTBOX_ROWS`).
pub const MAX_MESSAGES: usize = 1024;

/// The longest locale tag of a template version.
pub const MAX_LOCALE_LEN: usize = 16;

/// The largest recorded UTC offset, in minutes: 18 hours.
pub const MAX_OFFSET_MINUTES: i16 = 1080;

/// The recipient of a message (M6 design section 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Recipient {
    /// An account.
    Account(AccountId),
    /// The SHA-256 digest of an address an applicant gave (R-SB-04).
    Address([u8; 32]),
}

/// The event id of an event of `kind` with `lead`, from `source` at
/// `source_version` (M6 design section 3.1).
pub fn event_id(kind: u16, lead: i64, source: &[u8], source_version: u64) -> EventId {
    let len = u16::try_from(source.len()).unwrap_or(u16::MAX);
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-event-v1");
    h.update(&kind.to_be_bytes());
    h.update(&len.to_be_bytes());
    h.update(source);
    h.update(&source_version.to_be_bytes());
    h.update(&lead.to_be_bytes());
    h.finish()
}

/// The source reference of an immediate event: the ledger sequence and
/// the record index of its `OutboxEnqueued` record, big-endian.
pub fn immediate_source(seq: u64, index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out
}

/// The idempotency key of the message of `event` to `recipient` on
/// `channel` (M6 design section 3.1, I-26).
pub fn message_idem(event: &EventId, recipient: Recipient, channel: u8) -> Idem {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-msg-v1");
    h.update(event);
    match recipient {
        Recipient::Account(a) => {
            h.update(&[1]);
            h.update(&a.raw().to_be_bytes());
        }
        Recipient::Address(d) => {
            h.update(&[2]);
            h.update(&d);
        }
    }
    h.update(&[channel]);
    h.finish()
}

/// One message an `EventFired` lists (M6 design section 3.1). Its body is
/// the sealed `ops.outbox` row `outbox`, written in the same append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiredMessage {
    /// The `ops.outbox` row id.
    pub outbox: [u8; 16],
    /// The idempotency key ([`message_idem`]).
    pub idem: Idem,
    /// The template.
    pub template: u16,
    /// The template version.
    pub version: u16,
}

/// A timeline record (M6 design section 3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimelineRecord {
    /// A template version, recorded once at first use. It never changes
    /// (I-25).
    TemplateVersionRecorded {
        /// The template.
        template: u16,
        /// The version.
        version: u16,
        /// The locale tag, such as `en`.
        locale: String,
        /// The digest of the template text.
        digest: [u8; 32],
    },
    /// An event was scheduled (R-NT-01).
    EventScheduled {
        /// The event id: [`event_id`] of the fields below.
        event: EventId,
        /// The event kind.
        kind: u16,
        /// The kind's offset from the source's due date, in microseconds.
        lead: i64,
        /// The source reference.
        source: Vec<u8>,
        /// The source version.
        source_version: u64,
        /// When it is due, UTC microseconds.
        due: i64,
        /// The UTC offset recorded with the deadline, in minutes.
        offset_minutes: i16,
    },
    /// An event was cancelled, never deleted (R-NT-01 AC).
    EventCancelled {
        /// The event.
        event: EventId,
        /// The event that supersedes it, if any.
        superseded_by: Option<EventId>,
    },
    /// An event fired. Its messages' outbox rows are written in the same
    /// append (M6 design section 3.1).
    EventFired {
        /// The event.
        event: EventId,
        /// The messages.
        messages: Vec<FiredMessage>,
    },
}

/// Where an event stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventStatus {
    /// Scheduled, not fired.
    Scheduled,
    /// Cancelled, with the event that supersedes it.
    Cancelled(Option<EventId>),
    /// Fired.
    Fired,
}

/// One scheduled event and where it stands.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledEvent {
    /// The event kind.
    pub kind: u16,
    /// The lead, microseconds.
    pub lead: i64,
    /// The source reference.
    pub source: Vec<u8>,
    /// The source version.
    pub source_version: u64,
    /// When it is due.
    pub due: i64,
    /// The recorded UTC offset, minutes.
    pub offset_minutes: i16,
    /// Where it stands.
    pub status: EventStatus,
}

/// The folded timeline of a cell.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct TimelineState {
    templates: BTreeMap<(u16, u16), [u8; 32]>,
    events: BTreeMap<EventId, ScheduledEvent>,
    idems: BTreeMap<Idem, EventId>,
    outbox: BTreeSet<[u8; 16]>,
    enqueued: BTreeMap<u64, (i64, OutboxEvent)>,
}

impl fmt::Debug for TimelineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimelineState")
            .field("templates", &self.templates.len())
            .field("events", &self.events.len())
            .field("messages", &self.idems.len())
            .field("enqueued", &self.enqueued.len())
            .finish()
    }
}

impl TimelineState {
    /// The digest of a recorded template version.
    pub fn template(&self, template: u16, version: u16) -> Option<&[u8; 32]> {
        self.templates.get(&(template, version))
    }

    /// An event, scheduled at some point.
    pub fn event(&self, event: &EventId) -> Option<&ScheduledEvent> {
        self.events.get(event)
    }

    /// Every event, by id.
    pub fn events(&self) -> impl Iterator<Item = (&EventId, &ScheduledEvent)> {
        self.events.iter()
    }

    /// Whether `event` was cancelled.
    pub fn is_cancelled(&self, event: &EventId) -> bool {
        matches!(
            self.events.get(event).map(|e| e.status),
            Some(EventStatus::Cancelled(_))
        )
    }

    /// The event whose fired message holds `idem`.
    pub fn fired_idem(&self, idem: &Idem) -> Option<&EventId> {
        self.idems.get(idem)
    }

    /// Every `OutboxEnqueued` record of the ledger, by its sequence, with
    /// its entry time (M6 design section 4, kind `Immediate`).
    pub fn enqueued(&self) -> impl Iterator<Item = (u64, i64, &OutboxEvent)> {
        self.enqueued.iter().map(|(seq, (at, e))| (*seq, *at, e))
    }

    /// Keeps an `OutboxEnqueued` record folded at `seq` and `at`.
    pub(crate) fn enqueue(&mut self, seq: u64, at: i64, event: OutboxEvent) {
        self.enqueued.insert(seq, (at, event));
    }

    /// Folds one timeline record (M6 design section 3.1). A refused
    /// record leaves the state as it was.
    pub(crate) fn fold(&mut self, r: &TimelineRecord) -> Result<(), FoldError> {
        match r {
            TimelineRecord::TemplateVersionRecorded {
                template,
                version,
                locale,
                digest,
            } => {
                if !is_locale(locale) {
                    return Err(inconsistent());
                }
                // I-25: a version is recorded once and never changes.
                if self.templates.contains_key(&(*template, *version)) {
                    return Err(duplicate());
                }
                self.templates.insert((*template, *version), *digest);
            }
            TimelineRecord::EventScheduled {
                event,
                kind,
                lead,
                source,
                source_version,
                due,
                offset_minutes,
            } => {
                if source.len() > MAX_SOURCE_LEN
                    || offset_minutes.unsigned_abs() > MAX_OFFSET_MINUTES.unsigned_abs()
                    || event_id(*kind, *lead, source, *source_version) != *event
                {
                    return Err(inconsistent());
                }
                if self.events.contains_key(event) {
                    return Err(duplicate());
                }
                self.events.insert(
                    *event,
                    ScheduledEvent {
                        kind: *kind,
                        lead: *lead,
                        source: source.clone(),
                        source_version: *source_version,
                        due: *due,
                        offset_minutes: *offset_minutes,
                        status: EventStatus::Scheduled,
                    },
                );
            }
            TimelineRecord::EventCancelled {
                event,
                superseded_by,
            } => {
                let e = self.events.get_mut(event).ok_or_else(unknown)?;
                if e.status != EventStatus::Scheduled {
                    return Err(inconsistent());
                }
                e.status = EventStatus::Cancelled(*superseded_by);
            }
            TimelineRecord::EventFired { event, messages } => {
                match self.events.get(event).map(|e| e.status) {
                    Some(EventStatus::Scheduled) => {}
                    Some(_) => return Err(inconsistent()),
                    None => return Err(unknown()),
                }
                if messages.len() > MAX_MESSAGES {
                    return Err(inconsistent());
                }
                let mut idems = BTreeSet::new();
                let mut rows = BTreeSet::new();
                for m in messages {
                    // I-25: the template version is recorded first.
                    if !self.templates.contains_key(&(m.template, m.version)) {
                        return Err(unknown());
                    }
                    // I-26: one key, and one outbox row, per message.
                    if self.idems.contains_key(&m.idem)
                        || self.outbox.contains(&m.outbox)
                        || !idems.insert(m.idem)
                        || !rows.insert(m.outbox)
                    {
                        return Err(duplicate());
                    }
                }
                for idem in idems {
                    self.idems.insert(idem, *event);
                }
                self.outbox.extend(rows);
                if let Some(e) = self.events.get_mut(event) {
                    e.status = EventStatus::Fired;
                }
            }
        }
        Ok(())
    }
}

fn duplicate() -> FoldError {
    FoldError::Engine(DomainFold::DuplicateId)
}

fn unknown() -> FoldError {
    FoldError::Engine(DomainFold::UnknownEntity)
}

fn inconsistent() -> FoldError {
    FoldError::Engine(DomainFold::Inconsistent)
}

/// Whether `s` is a locale tag the codec carries: 2 to
/// [`MAX_LOCALE_LEN`] ASCII letters, digits or `-`, starting with a
/// letter.
pub fn is_locale(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=MAX_LOCALE_LEN).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// The body of one fired message, which the store seals into its
/// `ops.outbox` row in the append of its `EventFired` (M6 design section
/// 3.1). Never written to the ledger.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MessageBody {
    /// The `ops.outbox` row id, as the `EventFired` lists it.
    pub outbox: [u8; 16],
    /// The rendered message.
    pub body: Vec<u8>,
}

impl fmt::Debug for MessageBody {
    /// The body is content, so only its length shows (R-NF-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageBody")
            .field("outbox", &self.outbox)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A command of the timeline task (M6 design section 4). Only
/// `SystemTask::Timeline` issues it, so no account schedules, cancels or
/// fires an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimelineCommand {
    /// Schedule and cancel events: `EventScheduled` and `EventCancelled`
    /// records only (R-NT-01).
    Plan {
        /// The records, at most [`MAX_MESSAGES`].
        records: Vec<TimelineRecord>,
    },
    /// Fire one scheduled event that is due: its first-use template
    /// versions, the records of its System command, and `EventFired`, in
    /// one entry with the outbox rows of its messages (M6 design section
    /// 4 step 2). The bodies come from the task's inputs, in message order.
    Fire {
        /// The event.
        event: EventId,
        /// `TemplateVersionRecorded` records for versions not recorded
        /// yet.
        templates: Vec<TimelineRecord>,
        /// The messages.
        messages: Vec<FiredMessage>,
        /// The System command the event issues, if any. It must be due.
        then: Option<Box<fstp_domain::Command>>,
    },
}
