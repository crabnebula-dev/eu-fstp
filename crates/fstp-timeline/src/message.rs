//! The body of one fired message: what the timeline seals into its
//! `ops.outbox` row, and what the dispatcher opens and renders (M6 design
//! sections 4 step 2 and 5.1 step S2).
//!
//! A body names the template version, the event, the idempotency key,
//! the recipient, the instant the event fired and the placeholder values.
//! It holds no address of an account and no free text: every value comes
//! from the closed placeholder enum of `fstp_mail` (I-27). The dispatcher
//! resolves the recipient's address and composes the message with
//! [`MessageSpec::compose`].
//!
//! The form is RFC 8785 JSON. Every number is a decimal string, and ids,
//! digests and keys are lowercase hexadecimal. [`MessageSpec::decode`]
//! is a parser over untrusted bytes, with the fuzz target
//! `message_spec` (`crates/fstp-timeline/fuzz`).

use fstp_cell_core::timeline::{EventId, Idem, Recipient};
use fstp_domain::id::{AccountId, CallId, ContractId, MilestoneId, ProposalId, RequestId};
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_json::{Object, Value, parse, to_canonical};
use fstp_mail::{
    Bindings, LinkTarget, Locale, MailConfig, MailError, Mailbox, Message, Moment, Slot, Template,
    TemplateId,
};

/// The form version of a body.
pub const FORM: &str = "1";

/// The largest body [`MessageSpec::decode`] reads.
pub const MAX_BODY: usize = 16 * 1024;

/// One message as the timeline fired it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSpec {
    /// The template.
    pub template: TemplateId,
    /// The template version.
    pub version: u32,
    /// The locale.
    pub locale: Locale,
    /// The event.
    pub event: EventId,
    /// The idempotency key, which also gives `Message-ID`.
    pub idem: Idem,
    /// The recipient.
    pub to: Recipient,
    /// The instant the event fired, the `Date` header.
    pub date: Timestamp,
    /// The placeholder values.
    pub bindings: Bindings,
}

/// Why a body did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecError {
    /// Over [`MAX_BODY`].
    TooLarge,
    /// Not JSON.
    NotJson,
    /// JSON, but not a body of form [`FORM`]. It names the part.
    Malformed(&'static str),
}

impl MessageSpec {
    /// The template version, if this build has it.
    pub fn template(&self) -> Option<&'static Template> {
        Template::get(self.template, self.version, self.locale)
    }

    /// The RFC 8785 bytes of the body, or `None` when a value has no form
    /// here. An amount has none, because no M6 template takes one.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut o = Object::with_capacity(9);
        let mut b = Object::new();
        for slot in self.bindings.slots() {
            let v = self.bindings.get(slot)?;
            b.insert(slot.code(), value_json(v)?);
        }
        o.insert("bindings", Value::Object(b));
        o.insert("date", s(self.date.micros()));
        o.insert("event", hex(&self.event));
        o.insert("form", Value::String(FORM.to_owned()));
        o.insert("idem", hex(&self.idem));
        o.insert("locale", Value::String(self.locale.code().to_owned()));
        o.insert("template", Value::String(self.template.code().to_owned()));
        let mut to = Object::with_capacity(1);
        match self.to {
            Recipient::Account(a) => to.insert("account", s(a.raw())),
            Recipient::Address(d) => to.insert("address", hex(&d)),
        };
        o.insert("to", Value::Object(to));
        o.insert("version", s(self.version));
        to_canonical(&Value::Object(o)).ok().map(String::into_bytes)
    }

    /// Reads a body. Unknown members, unknown codes, slots of another
    /// kind and numbers out of range are refused.
    ///
    /// # Errors
    ///
    /// [`SpecError`] names why.
    pub fn decode(bytes: &[u8]) -> Result<MessageSpec, SpecError> {
        if bytes.len() > MAX_BODY {
            return Err(SpecError::TooLarge);
        }
        let v = parse(bytes).map_err(|_| SpecError::NotJson)?;
        let o = v.as_object().ok_or(SpecError::Malformed("body"))?;
        only(
            o,
            &[
                "bindings", "date", "event", "form", "idem", "locale", "template", "to", "version",
            ],
        )?;
        if str_of(o, "form")? != FORM {
            return Err(SpecError::Malformed("form"));
        }
        let code = str_of(o, "template")?;
        let template = TemplateId::ALL
            .into_iter()
            .find(|t| t.code() == code)
            .ok_or(SpecError::Malformed("template"))?;
        let locale = match str_of(o, "locale")? {
            "en" => Locale::En,
            _ => return Err(SpecError::Malformed("locale")),
        };
        let to = o
            .get("to")
            .and_then(Value::as_object)
            .ok_or(SpecError::Malformed("to"))?;
        let to = match (to.len(), to.get("account"), to.get("address")) {
            (1, Some(a), None) => Recipient::Account(AccountId::from_raw(num(a, "to")?)),
            (1, None, Some(d)) => Recipient::Address(bytes32(d, "to")?),
            _ => return Err(SpecError::Malformed("to")),
        };
        let b = o
            .get("bindings")
            .and_then(Value::as_object)
            .ok_or(SpecError::Malformed("bindings"))?;
        let mut bindings = Bindings::new();
        for (name, v) in b.iter() {
            let slot = Slot::ALL
                .into_iter()
                .find(|s| s.code() == name)
                .ok_or(SpecError::Malformed("bindings"))?;
            bindings = bindings.with(slot, value_from(slot, v)?);
        }
        Ok(MessageSpec {
            template,
            version: num(member(o, "version")?, "version")?,
            locale,
            event: bytes32(member(o, "event")?, "event")?,
            idem: bytes32(member(o, "idem")?, "idem")?,
            to,
            date: Timestamp::from_micros(num(member(o, "date")?, "date")?),
            bindings,
        })
    }

    /// Renders and builds the message to `to`, the address the dispatcher
    /// resolved for [`MessageSpec::to`] (M6 design section 5.1 step S2).
    ///
    /// # Errors
    ///
    /// [`MailError::Malformed`] when this build lacks the template
    /// version, and any error of `fstp_mail::compose`.
    pub fn compose(&self, cfg: &MailConfig, to: &Mailbox) -> Result<Vec<u8>, MailError> {
        let template = self
            .template()
            .ok_or(MailError::Malformed("template version"))?;
        fstp_mail::compose(
            cfg,
            &Message {
                template,
                bindings: &self.bindings,
                to,
                idem: self.idem,
                event: self.event,
                date: self.date,
                pdf: None,
            },
        )
    }
}

fn s(n: impl ToString) -> Value {
    Value::String(n.to_string())
}

fn hex(bytes: &[u8]) -> Value {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Value::String(out)
}

fn value_json(v: &fstp_mail::Value) -> Option<Value> {
    use fstp_mail::Value as V;
    Some(match *v {
        V::Proposal(x) => s(x.raw()),
        V::Call(x) => s(x.raw()),
        V::Contract(x) => s(x.raw()),
        V::Milestone(x) => s(x.raw()),
        V::Request(x) => s(x.raw()),
        V::State(t) => Value::String(t.spec_name().to_owned()),
        V::Moment(m) => {
            let mut o = Object::with_capacity(2);
            o.insert("at", s(m.at().micros()));
            o.insert("offset", s(m.offset_minutes()));
            Value::Object(o)
        }
        V::Amount(_) => return None,
        V::Link(l) => {
            let mut o = Object::with_capacity(2);
            let (to, id) = match l {
                LinkTarget::Notices => ("notices", None),
                LinkTarget::Proposal(p) => ("proposal", Some(p.raw())),
                LinkTarget::ProposalProgress(p) => ("proposal_progress", Some(p.raw())),
                LinkTarget::CallGuide(c) => ("call_guide", Some(c.raw())),
                LinkTarget::NotifiableConflicts(c) => ("notifiable_conflicts", Some(c.raw())),
            };
            o.insert("to", Value::String(to.to_owned()));
            if let Some(id) = id {
                o.insert("id", s(id));
            }
            Value::Object(o)
        }
        V::Count(n) => s(n),
    })
}

fn value_from(slot: Slot, v: &Value) -> Result<fstp_mail::Value, SpecError> {
    use fstp_mail::{Value as V, ValueKind as K};
    const W: &str = "bindings";
    Ok(match slot.kind() {
        K::Proposal => V::Proposal(ProposalId::from_raw(num(v, W)?)),
        K::Call => V::Call(CallId::from_raw(num(v, W)?)),
        K::Contract => V::Contract(ContractId::from_raw(num(v, W)?)),
        K::Milestone => V::Milestone(MilestoneId::from_raw(num(v, W)?)),
        K::Request => V::Request(RequestId::from_raw(num(v, W)?)),
        K::State => {
            let name = v.as_str().ok_or(SpecError::Malformed(W))?;
            V::State(
                StateTag::ALL
                    .into_iter()
                    .find(|t| t.spec_name() == name)
                    .ok_or(SpecError::Malformed(W))?,
            )
        }
        K::Moment => {
            let o = v.as_object().ok_or(SpecError::Malformed(W))?;
            only(o, &["at", "offset"])?;
            let at = Timestamp::from_micros(num(member(o, "at")?, W)?);
            let offset: i16 = num(member(o, "offset")?, W)?;
            V::Moment(Moment::new(at, offset).map_err(|_| SpecError::Malformed(W))?)
        }
        K::Amount => return Err(SpecError::Malformed(W)),
        K::Link => {
            let o = v.as_object().ok_or(SpecError::Malformed(W))?;
            let to = str_of(o, "to")?;
            let id = |o: &Object| -> Result<u128, SpecError> {
                only(o, &["id", "to"])?;
                num(member(o, "id")?, W)
            };
            V::Link(match to {
                "notices" => {
                    only(o, &["to"])?;
                    LinkTarget::Notices
                }
                "proposal" => LinkTarget::Proposal(ProposalId::from_raw(id(o)?)),
                "proposal_progress" => LinkTarget::ProposalProgress(ProposalId::from_raw(id(o)?)),
                "call_guide" => LinkTarget::CallGuide(CallId::from_raw(id(o)?)),
                "notifiable_conflicts" => LinkTarget::NotifiableConflicts(CallId::from_raw(id(o)?)),
                _ => return Err(SpecError::Malformed(W)),
            })
        }
        K::Count => V::Count(num(v, W)?),
    })
}

fn only(o: &Object, names: &[&str]) -> Result<(), SpecError> {
    if o.len() != names.len() || !names.iter().all(|n| o.contains_key(n)) {
        return Err(SpecError::Malformed("members"));
    }
    Ok(())
}

fn member<'a>(o: &'a Object, name: &'static str) -> Result<&'a Value, SpecError> {
    o.get(name).ok_or(SpecError::Malformed(name))
}

fn str_of<'a>(o: &'a Object, name: &'static str) -> Result<&'a str, SpecError> {
    member(o, name)?.as_str().ok_or(SpecError::Malformed(name))
}

/// A number written as a canonical decimal string: no sign but `-`, no
/// leading zero and no `+`, so each value has one spelling.
fn num<T: core::str::FromStr + ToString>(v: &Value, what: &'static str) -> Result<T, SpecError> {
    let text = v.as_str().ok_or(SpecError::Malformed(what))?;
    let n: T = text.parse().map_err(|_| SpecError::Malformed(what))?;
    if n.to_string() != text {
        return Err(SpecError::Malformed(what));
    }
    Ok(n)
}

fn bytes32(v: &Value, what: &'static str) -> Result<[u8; 32], SpecError> {
    let text = v.as_str().ok_or(SpecError::Malformed(what))?.as_bytes();
    if text.len() != 64 {
        return Err(SpecError::Malformed(what));
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let hi = nibble(pair.first().copied()).ok_or(SpecError::Malformed(what))?;
        let lo = nibble(pair.get(1).copied()).ok_or(SpecError::Malformed(what))?;
        *o = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(c: Option<u8>) -> Option<u8> {
    match c? {
        c @ b'0'..=b'9' => c.checked_sub(b'0'),
        c @ b'a'..=b'f' => c.checked_sub(b'a').and_then(|x| x.checked_add(10)),
        _ => None,
    }
}
