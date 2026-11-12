//! The read model of `grant.publicity.view` (M9 design section 2.2, lane
//! P1; R-PB-02, R-PB-03, I-41, I-42, I-43).
//!
//! The grantee lead's public choices of one grant, the programme maxima
//! P-50 and P-51, the minor flag that disables every level but hidden
//! (decision D4), and the accepted deliverables a finished choice may
//! include. The texts are the lead's own public texts. The model names no
//! account, no amount and no proposal text (I-86, R-PB-03).

use fstp_domain::id::{DeliverableId, ProposalId};
use fstp_json::{Array, Object, ToJson, Value};
use fstp_public::Level;

use crate::McpSafe;

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

/// One phase of the view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseView {
    /// Whether a choice of this phase can be set in the current state
    /// (I-41).
    pub open: bool,
    /// The current choice, if any.
    pub choice: Option<ChoiceView>,
}

/// The current choice of one phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceView {
    /// The level the lead chose.
    pub level: Level,
    /// The level the public pages show: the lower of the choice and the
    /// maximum, and hidden for a minor-flagged grant (I-42, I-43).
    pub effective: Level,
    /// The approved title. Empty when the store refuses the text.
    pub title: String,
    /// The approved public summary.
    pub summary: String,
    /// The approved grantee name.
    pub grantee: String,
    /// The accepted deliverables included.
    pub deliverables: Vec<DeliverableId>,
}

/// One accepted deliverable of the grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliverableView {
    /// The deliverable.
    pub id: DeliverableId,
    /// Its SPDX licence identifier.
    pub licence: String,
    /// The digest of its evidence snapshot, lowercase hexadecimal.
    pub snapshot: String,
}

/// `grant.publicity.view`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicityView {
    /// The grant, by its proposal.
    pub proposal: ProposalId,
    /// The proposal state, as the state machine names it.
    pub state: &'static str,
    /// Whether the proposal is minor-flagged, which disables every level
    /// but hidden (I-42, D4).
    pub minor: bool,
    /// P-50, the funded maximum.
    pub max_funded: Level,
    /// P-51, the finished maximum.
    pub max_finished: Level,
    /// The funded phase.
    pub funded: PhaseView,
    /// The finished phase.
    pub finished: PhaseView,
    /// The accepted deliverables of the grant.
    pub deliverables: Vec<DeliverableView>,
}

impl ToJson for ChoiceView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("level", Value::from(self.level.token()));
        let _ = o.insert("effective", Value::from(self.effective.token()));
        let _ = o.insert("title", Value::from(self.title.as_str()));
        let _ = o.insert("summary", Value::from(self.summary.as_str()));
        let _ = o.insert("grantee", Value::from(self.grantee.as_str()));
        let mut a = Array::new();
        for d in &self.deliverables {
            a.push(dec(d.raw()));
        }
        let _ = o.insert("deliverables", Value::Array(a));
        Value::Object(o)
    }
}

impl ToJson for PhaseView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("open", Value::Bool(self.open));
        let _ = o.insert(
            "choice",
            self.choice.as_ref().map_or(Value::Null, ToJson::to_json),
        );
        Value::Object(o)
    }
}

impl ToJson for DeliverableView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", dec(self.id.raw()));
        let _ = o.insert("licence", Value::from(self.licence.as_str()));
        let _ = o.insert("snapshot", Value::from(self.snapshot.as_str()));
        Value::Object(o)
    }
}

impl ToJson for PublicityView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("proposal", dec(self.proposal.raw()));
        let _ = o.insert("state", Value::from(self.state));
        let _ = o.insert("minor", Value::Bool(self.minor));
        let _ = o.insert("max_funded", Value::from(self.max_funded.token()));
        let _ = o.insert("max_finished", Value::from(self.max_finished.token()));
        let _ = o.insert("funded", self.funded.to_json());
        let _ = o.insert("finished", self.finished.to_json());
        let mut a = Array::new();
        for d in &self.deliverables {
            a.push(d.to_json());
        }
        let _ = o.insert("deliverables", Value::Array(a));
        Value::Object(o)
    }
}

impl McpSafe for PublicityView {}
