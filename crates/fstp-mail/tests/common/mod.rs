//! Shared generators for the fstp-mail tests. Synthetic data only.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]

use fstp_domain::StateTag;
use fstp_domain::id::{CallId, ContractId, MilestoneId, ProposalId, RequestId};
use fstp_domain::time::Timestamp;
use fstp_mail::{
    Bindings, DisplayName, LinkTarget, MailConfig, Mailbox, Message, Moment, Origin, Slot,
    TEMPLATES, Template, Value, ValueKind,
};
use fstp_money::{Amount, Currency};
use fstp_prop::Gen;

pub fn u128_any(g: &mut Gen) -> u128 {
    (u128::from(g.u64()) << 64) | u128::from(g.u64())
}

pub fn moment(g: &mut Gen) -> Moment {
    // 1970 to about 2200, so the RFC 5322 date stays in range.
    let secs = g.i64_in(0..=7_258_118_400);
    let offset = g.i16_in(-1080..=1080);
    Moment::new(Timestamp::from_micros(secs * 1_000_000), offset).unwrap()
}

pub fn link(g: &mut Gen) -> LinkTarget {
    match g.u8_in(0..=4) {
        0 => LinkTarget::Notices,
        1 => LinkTarget::Proposal(ProposalId::from_raw(u128_any(g))),
        2 => LinkTarget::ProposalProgress(ProposalId::from_raw(u128_any(g))),
        3 => LinkTarget::CallGuide(CallId::from_raw(u128_any(g))),
        _ => LinkTarget::NotifiableConflicts(CallId::from_raw(u128_any(g))),
    }
}

/// A random value of `kind`.
pub fn value_of(g: &mut Gen, kind: ValueKind) -> Value {
    match kind {
        ValueKind::Proposal => Value::Proposal(ProposalId::from_raw(u128_any(g))),
        ValueKind::Call => Value::Call(CallId::from_raw(u128_any(g))),
        ValueKind::Contract => Value::Contract(ContractId::from_raw(u128_any(g))),
        ValueKind::Milestone => Value::Milestone(MilestoneId::from_raw(u128_any(g))),
        ValueKind::Request => Value::Request(RequestId::from_raw(u128_any(g))),
        ValueKind::State => Value::State(*g.pick(&StateTag::ALL)),
        ValueKind::Moment => Value::Moment(moment(g)),
        ValueKind::Amount => {
            let max = Amount::MAX_ABS_MINOR;
            let minor = g.i64_in(-max..=max);
            let c = Currency::Eur;
            Value::Amount(Amount::from_minor(minor, c).unwrap())
        }
        ValueKind::Link => Value::Link(link(g)),
        ValueKind::Count => Value::Count(g.u32()),
    }
}

/// Random bindings for exactly the slots `t` uses.
pub fn bindings_for(g: &mut Gen, t: &Template) -> Bindings {
    let mut b = Bindings::new();
    for slot in t.slots() {
        b = b.with(slot, value_of(g, slot.kind()));
    }
    b
}

pub fn template(g: &mut Gen) -> &'static Template {
    g.pick(TEMPLATES)
}

pub fn config() -> MailConfig {
    MailConfig {
        origin: Origin::new("https://demo-cell.example").unwrap(),
        from: Mailbox::new("noreply@tenant-a.example").unwrap(),
        from_name: Some(DisplayName::new("Synthetic Fund Zürich").unwrap()),
        dkim: Vec::new(),
    }
}

pub fn recipient(g: &mut Gen) -> Mailbox {
    let n = g.u32();
    Mailbox::new(&format!("applicant.{n}@synthetic.example")).unwrap()
}

pub fn array32(g: &mut Gen) -> [u8; 32] {
    let v = g.bytes(32..=32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

/// A random message with a random template and bindings. A PDF is
/// attached when the template allows one and `g` says so.
pub struct Owned {
    pub template: &'static Template,
    pub bindings: Bindings,
    pub to: Mailbox,
    pub idem: [u8; 32],
    pub event: [u8; 32],
    pub date: Timestamp,
    pub pdf: Option<Vec<u8>>,
}

impl Owned {
    pub fn random(g: &mut Gen) -> Owned {
        let template = template(g);
        let bindings = bindings_for(g, template);
        let pdf = if template.allows_pdf() && g.bool() {
            Some(g.bytes(0..=600))
        } else {
            None
        };
        Owned {
            template,
            bindings,
            to: recipient(g),
            idem: array32(g),
            event: array32(g),
            date: Timestamp::from_micros(g.i64_in(0..=7_258_118_400) * 1_000_000),
            pdf,
        }
    }

    pub fn message(&self) -> Message<'_> {
        Message {
            template: self.template,
            bindings: &self.bindings,
            to: &self.to,
            idem: self.idem,
            event: self.event,
            date: self.date,
            pdf: self.pdf.as_deref(),
        }
    }
}

pub fn all_slots() -> [Slot; 11] {
    Slot::ALL
}
