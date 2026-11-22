//! The funding cards of the tenant's active programmes (ADR-034; I-69).
//!
//! A card reads the programme's creator draft: its name, the grant
//! agreement number (`funder.action_number`) and the coordinator's name
//! and contact. A missing coordinator value falls back to the tenant's
//! defaults (`FundingDefaultsSet`). Pages, PDFs and emails show the card
//! as text only (I-68).

use fstp_brand::funding::{FundingCard, FundingDefaults};
use fstp_domain::id::ProgrammeId;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_engine::EngineState;
use fstp_json::{Object, Value};

/// The string at `path` in a draft spec's JSON form, if it is a
/// non-empty string. A gap or a stored text that the shell has not held
/// reads as `None`.
fn member(spec: &Value, path: &[&str]) -> Option<String> {
    let mut v = spec;
    for k in path {
        v = v.get(k)?;
    }
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The card of `programme` from its draft spec `spec` (the
/// `fstp.programme/1` JSON form), with no tenant default applied.
pub fn card_of_spec(programme: ProgrammeId, spec: &Value) -> FundingCard {
    let spec = spec.get("spec").unwrap_or(spec);
    FundingCard {
        programme: programme.raw(),
        name: member(spec, &["identity", "name"])
            .unwrap_or_else(|| format!("Programme {}", programme.raw())),
        grant_number: member(spec, &["funder", "action_number"]),
        coordinator_name: member(spec, &["funder", "coordinator_name"]),
        coordinator_contact: member(spec, &["funder", "coordinator_contact"]),
    }
}

/// The tenant's funding card defaults, if an admin set them.
pub(crate) fn defaults(state: &EngineState) -> Option<&FundingDefaults> {
    state.tenant.state()?.funding_defaults()
}

/// The active programmes of the tenant, in id order.
pub(crate) fn active_programmes(state: &EngineState) -> Vec<ProgrammeId> {
    let mut ids: Vec<ProgrammeId> = state
        .core
        .calls()
        .iter()
        .map(|(_, c)| c.programme())
        .chain(state.creator.drafts().map(|(p, _)| p))
        .filter(|p| programme_status(&state.core, *p) == Some(ProgrammeStatus::Active))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The card of `programme` with the tenant's defaults filling its gaps,
/// or `None` when the creator holds no draft of it.
pub(crate) fn card(state: &EngineState, programme: ProgrammeId) -> Option<FundingCard> {
    let view = fstp_creator::draft_view(&state.core, &state.creator, programme)?;
    Some(card_of_spec(programme, &view.spec).with_defaults(defaults(state)))
}

/// The card of each active programme of the tenant, in id order.
pub(crate) fn cards(state: &EngineState) -> Vec<FundingCard> {
    active_programmes(state)
        .into_iter()
        .filter_map(|p| card(state, p))
        .collect()
}

fn opt(v: Option<&str>) -> Value {
    v.map_or(Value::Null, Value::from)
}

/// The JSON answer of `GET /brand/funding` (ADR-034 section 4):
/// `{"cards": [...], "defaults": {...} | null}`. Each card holds
/// `programme` (a decimal string), `name`, `grant_number`,
/// `coordinator_name` and `coordinator_contact`, each value a string or
/// `null`.
pub fn cards_json(cards: &[FundingCard], defaults: Option<&FundingDefaults>) -> Value {
    let rows = cards
        .iter()
        .map(|c| {
            let mut o = Object::new();
            let _ = o.insert("programme", Value::String(c.programme.to_string()));
            let _ = o.insert("name", Value::from(c.name.as_str()));
            let _ = o.insert("grant_number", opt(c.grant_number.as_deref()));
            let _ = o.insert("coordinator_name", opt(c.coordinator_name.as_deref()));
            let _ = o.insert("coordinator_contact", opt(c.coordinator_contact.as_deref()));
            Value::Object(o)
        })
        .collect();
    let defaults = defaults.map_or(Value::Null, |d| {
        let mut o = Object::new();
        let _ = o.insert("name", Value::from(d.name()));
        let _ = o.insert("contact", Value::from(d.contact()));
        Value::Object(o)
    });
    let mut o = Object::new();
    let _ = o.insert("cards", Value::Array(rows));
    let _ = o.insert("defaults", defaults);
    Value::Object(o)
}

/// The funding card a public page of `programme` shows, each missing
/// value as "Not set yet" (ADR-034 section 4).
pub(crate) fn public_card(
    state: &EngineState,
    programme: ProgrammeId,
) -> Option<fstp_public::PublicFunding> {
    let c = card(state, programme)?;
    let [(_, grant), (_, coordinator), (_, contact)] = c.lines();
    Some(fstp_public::PublicFunding {
        programme: c.name.clone(),
        grant_number: grant.to_owned(),
        coordinator: coordinator.to_owned(),
        contact: contact.to_owned(),
    })
}

/// The JSON answer of `GET /brand/funding` for `state`.
pub(crate) fn answer(state: &EngineState) -> Value {
    cards_json(&cards(state), defaults(state))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
mod tests {
    use super::*;

    fn spec() -> Value {
        fstp_json::parse(
            br#"{"funder":{"action_number":"SYNTHETIC-000000000","coordinator_contact":null,"coordinator_name":"Synthetic coordinator"},"identity":{"name":"Synthetic programme"}}"#,
        )
        .unwrap()
    }

    /// I-69, ADR-034: a card reads the grant agreement number and the
    /// coordinator from the draft spec, and a gap stays a gap.
    #[test]
    fn i69_card_reads_the_draft_spec() {
        let c = card_of_spec(ProgrammeId::from_raw(7), &spec());
        assert_eq!(c.name, "Synthetic programme");
        assert_eq!(c.grant_number.as_deref(), Some("SYNTHETIC-000000000"));
        assert_eq!(c.coordinator_name.as_deref(), Some("Synthetic coordinator"));
        assert_eq!(c.coordinator_contact, None);
        assert!(!c.complete());
    }

    /// ADR-034 section 3: the tenant default fills the contact gap, and
    /// the JSON answer carries the card and the defaults.
    #[test]
    fn adr034_default_contact_fills_the_gap_in_the_json() {
        let d = FundingDefaults::new("Default org", "role@example.org").unwrap();
        let c = card_of_spec(ProgrammeId::from_raw(7), &spec()).with_defaults(Some(&d));
        assert!(c.complete());
        let v = cards_json(&[c], Some(&d));
        let text = fstp_json::to_compact(&v);
        assert!(
            text.contains(r#""coordinator_contact":"role@example.org""#),
            "{text}"
        );
        assert!(text.contains(r#""programme":"7""#), "{text}");
        assert!(text.contains(r#""defaults":{"#), "{text}");
        let none = fstp_json::to_compact(&cards_json(&[], None));
        assert_eq!(none, r#"{"cards":[],"defaults":null}"#);
    }
}
