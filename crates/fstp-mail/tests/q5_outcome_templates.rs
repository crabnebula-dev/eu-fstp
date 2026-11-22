//! `legal/README.md` Q5 (Daniel, 2026-11-22; ADR-036 section 7): one
//! email template per proposal outcome, wired to drafts A1 to A4 of
//! `legal/09-emails.md` (I-25, I-27, R-NF-03).
//!
//! The drafts stay "draft, pending Daniel's approval". The tests pin the
//! shape: the ids, their slots and the place of their ledger codes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_mail::{Locale, Slot, Template, TemplateId};

const OUTCOMES: [(TemplateId, &str); 4] = [
    (TemplateId::OutcomeSelected, "outcome-selected"),
    (TemplateId::OutcomeNotSelected, "outcome-not-selected"),
    (TemplateId::OutcomeIneligible, "outcome-ineligible"),
    (TemplateId::OutcomeDeclined, "outcome-declined"),
];

/// I-25, Q5: each outcome has its own template id with a stable code,
/// at version 1, and the older ids keep their places in
/// `TemplateId::ALL`, so the ledger codes of older messages stay.
#[test]
fn i25_q5_one_template_per_outcome() {
    for (id, code) in OUTCOMES {
        assert_eq!(id.code(), code);
        let t = Template::latest(id, Locale::En).unwrap();
        assert_eq!(t.version(), 1, "{code}");
        assert!(!t.allows_pdf(), "{code}");
    }
    assert_eq!(TemplateId::ALL[0], TemplateId::ProposalOutcome);
    assert_eq!(TemplateId::ALL[11], TemplateId::IdCheckWaiting);
    assert_eq!(
        TemplateId::ALL[12..],
        OUTCOMES.map(|(id, _)| id),
        "appended after the older ids"
    );
    // The neutral version 1 stays for every other state.
    assert!(Template::get(TemplateId::ProposalOutcome, 1, Locale::En).is_some());
}

/// I-27, Q5: an outcome email carries the proposal, the time and a link
/// to the platform only. It names no state, since the template is the
/// outcome.
#[test]
fn i27_q5_outcome_templates_carry_ids_time_and_link_only() {
    for (id, code) in OUTCOMES {
        let t = Template::latest(id, Locale::En).unwrap();
        let slots: Vec<Slot> = t.slots().into_iter().collect();
        let mut want = vec![Slot::Proposal, Slot::When, Slot::Link];
        want.sort();
        assert_eq!(slots, want, "{code}");
    }
}
