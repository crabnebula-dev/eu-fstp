//! The closed placeholder set (I-27, M6 design section 5.3).
//!
//! A template names its gaps with [`Slot`]s and the caller fills them with
//! [`Value`]s. Every value is an id, a state tag, an instant, an amount, a
//! link built from an id, or a count. No variant holds a `TextRef`, a name
//! or free text, and [`Value`] is `Copy`, so it cannot own a string. The
//! test `i_27_placeholder_enum_is_enumerated` lists every variant.

use std::collections::BTreeMap;

use fstp_domain::StateTag;
use fstp_domain::id::{CallId, ContractId, MilestoneId, ProposalId, RequestId};
use fstp_domain::time::Timestamp;
use fstp_money::Amount;

use crate::MailError;
use crate::address::Origin;

/// What a value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueKind {
    /// A proposal id.
    Proposal,
    /// A call id.
    Call,
    /// A contract id.
    Contract,
    /// A milestone id.
    Milestone,
    /// A payment request id.
    Request,
    /// A proposal state tag.
    State,
    /// An instant with its recorded offset.
    Moment,
    /// An amount of money.
    Amount,
    /// A link into the platform.
    Link,
    /// A count, such as a corrigendum number or days left.
    Count,
}

impl ValueKind {
    /// Every kind.
    pub const ALL: [ValueKind; 10] = [
        ValueKind::Proposal,
        ValueKind::Call,
        ValueKind::Contract,
        ValueKind::Milestone,
        ValueKind::Request,
        ValueKind::State,
        ValueKind::Moment,
        ValueKind::Amount,
        ValueKind::Link,
        ValueKind::Count,
    ];
}

/// A named gap in a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// The proposal.
    Proposal,
    /// The call.
    Call,
    /// The contract.
    Contract,
    /// The milestone.
    Milestone,
    /// The payment request.
    Request,
    /// The state reached.
    State,
    /// When the event happened.
    When,
    /// A due date.
    Due,
    /// An amount.
    Amount,
    /// The link to the platform page.
    Link,
    /// A count.
    Count,
}

impl Slot {
    /// Every slot.
    pub const ALL: [Slot; 11] = [
        Slot::Proposal,
        Slot::Call,
        Slot::Contract,
        Slot::Milestone,
        Slot::Request,
        Slot::State,
        Slot::When,
        Slot::Due,
        Slot::Amount,
        Slot::Link,
        Slot::Count,
    ];

    /// The kind of value this slot takes.
    pub const fn kind(self) -> ValueKind {
        match self {
            Slot::Proposal => ValueKind::Proposal,
            Slot::Call => ValueKind::Call,
            Slot::Contract => ValueKind::Contract,
            Slot::Milestone => ValueKind::Milestone,
            Slot::Request => ValueKind::Request,
            Slot::State => ValueKind::State,
            Slot::When | Slot::Due => ValueKind::Moment,
            Slot::Amount => ValueKind::Amount,
            Slot::Link => ValueKind::Link,
            Slot::Count => ValueKind::Count,
        }
    }

    /// A stable code, used in the template digest.
    pub const fn code(self) -> &'static str {
        match self {
            Slot::Proposal => "proposal",
            Slot::Call => "call",
            Slot::Contract => "contract",
            Slot::Milestone => "milestone",
            Slot::Request => "request",
            Slot::State => "state",
            Slot::When => "when",
            Slot::Due => "due",
            Slot::Amount => "amount",
            Slot::Link => "link",
            Slot::Count => "count",
        }
    }
}

/// The largest offset from UTC a deadline may record, 18 hours.
pub const MAX_OFFSET_MINUTES: i16 = 18 * 60;

/// A UTC instant with the offset of the zone it was set in. M6 renders
/// UTC plus that offset (M6 design section 1, full zone rules are out).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Moment {
    at: Timestamp,
    offset_minutes: i16,
}

impl Moment {
    /// The instant `at` with offset `offset_minutes` east of UTC.
    ///
    /// # Errors
    ///
    /// [`MailError::DateOutOfRange`] when the offset is beyond 18 hours.
    pub fn new(at: Timestamp, offset_minutes: i16) -> Result<Moment, MailError> {
        if offset_minutes.unsigned_abs() > MAX_OFFSET_MINUTES.unsigned_abs() {
            return Err(MailError::DateOutOfRange);
        }
        Ok(Moment { at, offset_minutes })
    }

    /// The instant.
    pub const fn at(self) -> Timestamp {
        self.at
    }

    /// The offset in minutes east of UTC.
    pub const fn offset_minutes(self) -> i16 {
        self.offset_minutes
    }
}

/// A page of the platform a message links to. Each target is a fixed
/// route plus at most one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkTarget {
    /// The recipient's notices, `/app/notices`.
    Notices,
    /// A proposal, `/app/proposals/{proposal}`.
    Proposal(ProposalId),
    /// A grant's progress, `/app/proposals/{proposal}/progress`.
    ProposalProgress(ProposalId),
    /// A call's Guide, `/app/calls/{call}/guide`.
    CallGuide(CallId),
    /// A call's notifiable conflicts, `/app/calls/{call}/notifiable-conflicts`.
    NotifiableConflicts(CallId),
}

impl LinkTarget {
    /// The path, starting with `/`.
    pub fn path(self) -> String {
        match self {
            LinkTarget::Notices => "/app/notices".to_owned(),
            LinkTarget::Proposal(p) => format!("/app/proposals/{}", p.raw()),
            LinkTarget::ProposalProgress(p) => format!("/app/proposals/{}/progress", p.raw()),
            LinkTarget::CallGuide(c) => format!("/app/calls/{}/guide", c.raw()),
            LinkTarget::NotifiableConflicts(c) => {
                format!("/app/calls/{}/notifiable-conflicts", c.raw())
            }
        }
    }
}

/// A value for a slot. See the module documentation for why it holds no
/// text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// A proposal id.
    Proposal(ProposalId),
    /// A call id.
    Call(CallId),
    /// A contract id.
    Contract(ContractId),
    /// A milestone id.
    Milestone(MilestoneId),
    /// A payment request id.
    Request(RequestId),
    /// A state tag, rendered with its spec name.
    State(StateTag),
    /// An instant.
    Moment(Moment),
    /// An amount, rendered as its currency code and ADR-006 spelling.
    Amount(Amount),
    /// A link.
    Link(LinkTarget),
    /// A count.
    Count(u32),
}

impl Value {
    /// The kind of this value.
    pub const fn kind(&self) -> ValueKind {
        match self {
            Value::Proposal(_) => ValueKind::Proposal,
            Value::Call(_) => ValueKind::Call,
            Value::Contract(_) => ValueKind::Contract,
            Value::Milestone(_) => ValueKind::Milestone,
            Value::Request(_) => ValueKind::Request,
            Value::State(_) => ValueKind::State,
            Value::Moment(_) => ValueKind::Moment,
            Value::Amount(_) => ValueKind::Amount,
            Value::Link(_) => ValueKind::Link,
            Value::Count(_) => ValueKind::Count,
        }
    }

    /// The value as message text. Ids are decimal, as in URLs and JSON.
    ///
    /// # Errors
    ///
    /// [`MailError::DateOutOfRange`] for an instant outside the years 0000
    /// to 9999.
    pub fn render(&self, origin: &Origin) -> Result<String, MailError> {
        Ok(match *self {
            Value::Proposal(x) => x.raw().to_string(),
            Value::Call(x) => x.raw().to_string(),
            Value::Contract(x) => x.raw().to_string(),
            Value::Milestone(x) => x.raw().to_string(),
            Value::Request(x) => x.raw().to_string(),
            Value::State(s) => s.spec_name().to_owned(),
            Value::Moment(m) => render_moment(m)?,
            Value::Amount(a) => format!("{} {a}", a.currency().code()),
            Value::Link(l) => format!("{}{}", origin.as_str(), l.path()),
            Value::Count(n) => n.to_string(),
        })
    }
}

/// Civil date of `days` since 1970-01-01, on integers only (the
/// days-to-civil algorithm of H. Hinnant). `None` outside about 2200 BCE
/// to 10000 CE.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "days is bounded below, so no step can overflow or divide by zero"
)]
pub(crate) fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    if !(-1_500_000..=3_000_000).contains(&days) {
        return None;
    }
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    Some((y, m, d))
}

/// `YYYY-MM-DD HH:MM` for `secs` since the epoch.
pub(crate) fn date_time(secs: i64) -> Result<(String, i64), MailError> {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days).ok_or(MailError::DateOutOfRange)?;
    if !(0..=9999).contains(&y) {
        return Err(MailError::DateOutOfRange);
    }
    Ok((
        format!(
            "{y:04}-{mo:02}-{d:02} {:02}:{:02}",
            rem / 3600,
            rem % 3600 / 60
        ),
        days,
    ))
}

fn render_moment(m: Moment) -> Result<String, MailError> {
    let secs = m.at.micros().div_euclid(1_000_000);
    let (utc, _) = date_time(secs)?;
    if m.offset_minutes == 0 {
        return Ok(format!("{utc} UTC"));
    }
    let off = i64::from(m.offset_minutes);
    let (local, _) = date_time(secs.saturating_add(off.saturating_mul(60)))?;
    let sign = if off < 0 { '-' } else { '+' };
    let a = off.unsigned_abs();
    Ok(format!(
        "{utc} UTC ({local} UTC{sign}{:02}:{:02})",
        a / 60,
        a % 60
    ))
}

/// The values for one rendering, one per slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bindings(BTreeMap<Slot, Value>);

impl Bindings {
    /// No bindings.
    pub fn new() -> Bindings {
        Bindings(BTreeMap::new())
    }

    /// These bindings with `slot` set to `value`, replacing any earlier one.
    #[must_use]
    pub fn with(mut self, slot: Slot, value: Value) -> Bindings {
        self.0.insert(slot, value);
        self
    }

    /// The value of `slot`.
    pub fn get(&self, slot: Slot) -> Option<&Value> {
        self.0.get(&slot)
    }

    /// The bound slots in order.
    pub fn slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.0.keys().copied()
    }
}
