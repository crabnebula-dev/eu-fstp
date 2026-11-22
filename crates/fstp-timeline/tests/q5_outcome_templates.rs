//! `legal/README.md` Q5 (Daniel, 2026-11-22; ADR-036 section 7): the
//! outcome email takes the template of its outcome (I-25, I-27).
//!
//! NEGOTIATION is selected (A1), NOT_SELECTED is A2, INELIGIBLE is A3 and
//! DECLINED is A4. Any other state keeps the neutral `proposal-outcome`
//! version 1. The message fills exactly the slots of its template.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::sync::OnceLock;

use common::Cell;
use fstp_cell_core::timeline::Recipient;
use fstp_domain::record::OutboxEvent;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, PR1};
use fstp_mail::{Origin, TemplateId};
use fstp_timeline::message::MessageSpec;

const MINUTE: i64 = 60_000_000;

fn base() -> Cell {
    static BASE: OnceLock<Cell> = OnceLock::new();
    BASE.get_or_init(|| Cell::from_engine(common::submitted().entries().unwrap()))
        .clone()
}

/// I-25, Q5: the template of each outcome, and the neutral one for any
/// other state.
#[test]
fn i25_q5_outcome_template_follows_the_state() {
    for (state, want) in [
        (StateTag::Negotiation, TemplateId::OutcomeSelected),
        (StateTag::NotSelected, TemplateId::OutcomeNotSelected),
        (StateTag::Ineligible, TemplateId::OutcomeIneligible),
        (StateTag::Declined, TemplateId::OutcomeDeclined),
        (StateTag::Granted, TemplateId::ProposalOutcome),
        (StateTag::Deferred, TemplateId::ProposalOutcome),
    ] {
        assert_eq!(fstp_timeline::outcome_template(state), want, "{state:?}");
    }
}

/// I-25, I-27, Q5: an outcome record fires one message to the lead under
/// the template of its outcome, whose bindings fill exactly that
/// template's slots, so the message renders.
#[test]
fn i27_q5_outcome_message_renders_under_its_template() {
    for (state, want) in [
        (StateTag::NotSelected, TemplateId::OutcomeNotSelected),
        (StateTag::Ineligible, TemplateId::OutcomeIneligible),
        (StateTag::Negotiation, TemplateId::OutcomeSelected),
        (StateTag::Declined, TemplateId::OutcomeDeclined),
        (StateTag::Granted, TemplateId::ProposalOutcome),
    ] {
        let mut c = base();
        let at = c.state.now_floor().micros() + MINUTE;
        c.enqueue(
            at,
            OutboxEvent::ProposalOutcome {
                proposal: PR1,
                state,
            },
        );
        c.tick(Timestamp::from_micros(at)).unwrap();
        assert_eq!(c.bodies.len(), 1, "{state:?}");
        let spec = MessageSpec::decode(&c.bodies[0].body).unwrap();
        assert_eq!(spec.to, Recipient::Account(L1), "{state:?}");
        assert_eq!(spec.template, want, "{state:?}");
        let t = spec.template().unwrap();
        let origin = Origin::new("https://demo-cell.example").unwrap();
        let r = t.render(&spec.bindings, &origin).unwrap();
        assert!(
            r.subject.starts_with("Proposal "),
            "{state:?}: {}",
            r.subject
        );
        assert!(r.text.contains("https://demo-cell.example/"), "{state:?}");
    }
}
