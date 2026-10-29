//! I-66: an edit after the report voids the clearance (M4 design sections
//! 3.2 "Bound to a revision" and 8.4, "Machine").
//!
//! Acknowledgements bind to a revision and a warning, so an edit voids
//! them. An approval that names a revision other than the head fails with
//! `StaleRevision`. The machine weights edits after acknowledgements and
//! requests. The direct property acknowledges a warning, requests, edits
//! with a generated record kind, renews none, one or both of the
//! acknowledgement and the request, and approves. Only renewing both
//! activates. Renewing the request alone is refused for the voided
//! acknowledgement, which isolates the I-66 rule.
//!
//! Reading R1 of the reference, interim pending Daniel: openings, grants,
//! field saves, starts, narratives, invitations, withdrawals and import
//! resolutions are edits. The production tests are red until lane W2a
//! lands the creator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{ActivationMachine, Backend, Focus, System};
use fstp_api_testkit::reference::creator::{
    Base, EditKind, M1, RefCheck, RefCommand, RefEdit, RefRefusal, StepVerdict, TB, seeded_plan,
};
use fstp_prop::{Gen, check, check_machine, prop_assert, prop_assert_eq};

const KINDS: [EditKind; 7] = [
    EditKind::Policy,
    EditKind::Artefact,
    EditKind::Start,
    EditKind::Narrative,
    EditKind::Invitation,
    EditKind::InvitationWithdrawal,
    EditKind::ImportResolution,
];

fn step(s: &mut System, cmd: RefCommand) -> Result<StepVerdict, String> {
    s.apply(&cmd)
}

fn edit_property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let warnings: Vec<RefCheck> = RefCheck::warnings()
            .into_iter()
            .filter(|c| *c != RefCheck::InferenceUnreachable)
            .collect();
        let w = *g.pick(&warnings);
        let kind = *g.pick(&KINDS);
        g.note("warning", &w);
        g.note("edit kind", &kind);
        let mut s = System::open(backend, &seeded_plan(w))?;
        let ack = RefCommand::Acknowledge {
            by: M1,
            warning: w,
            base: Base::Head,
        };
        let request = RefCommand::Request {
            by: M1,
            base: Base::Head,
        };
        let approve = RefCommand::Approve {
            by: TB,
            base: Base::Head,
        };
        prop_assert_eq!(step(&mut s, ack)?, StepVerdict::Accepted, "acknowledgement");
        prop_assert_eq!(step(&mut s, request)?, StepVerdict::Accepted, "request");
        let edit = RefCommand::Edit {
            by: M1,
            kind,
            effect: RefEdit::Neutral,
            base: Base::Head,
        };
        prop_assert_eq!(step(&mut s, edit)?, StepVerdict::Accepted, "edit");
        // What is renewed after the edit: 0 nothing, 1 the request, 2 the
        // acknowledgement, 3 both.
        let renew = g.u8_in(0..=3);
        g.note("renewed after the edit", &renew);
        if renew & 2 != 0 {
            prop_assert_eq!(
                step(&mut s, ack)?,
                StepVerdict::Accepted,
                "fresh acknowledgement"
            );
        }
        if renew & 1 != 0 {
            prop_assert_eq!(
                step(&mut s, request)?,
                StepVerdict::Accepted,
                "fresh request"
            );
        }
        let verdict = step(&mut s, approve)?;
        match renew {
            3 => prop_assert_eq!(
                verdict,
                StepVerdict::Accepted,
                "the approval after a fresh acknowledgement and request"
            ),
            1 => prop_assert_eq!(
                verdict,
                StepVerdict::Refused(RefRefusal::Unacknowledged(w)),
                "I-66: the edit of kind {kind:?} must void the acknowledgement of {}",
                w.name()
            ),
            _ => prop_assert!(
                !verdict.accepted(),
                "I-66: the approval after an edit of kind {kind:?} was accepted on a voided clearance"
            ),
        }
        Ok(())
    }
}

/// I-66: random sequences with edits after reports agree with the
/// reference on production, and never activate on a voided clearance.
#[test]
fn i66_edit_after_report_voids_clearance() {
    check_machine(
        "i66_edit_after_report_voids_clearance",
        &ActivationMachine {
            backend: Backend::Production,
            focus: Focus::EditAfterReport,
        },
    );
}

/// I-66: the machine passes on the reference alone.
#[test]
fn i66_edit_after_report_voids_clearance_on_the_reference() {
    check_machine(
        "i66_edit_after_report_voids_clearance_on_the_reference",
        &ActivationMachine {
            backend: Backend::Reference,
            focus: Focus::EditAfterReport,
        },
    );
}

/// I-66: an edit of every record kind voids the acknowledgement and the
/// request, on production.
#[test]
fn i66_edit_after_report_voids_clearance_for_every_edit_kind() {
    check(
        "i66_edit_after_report_voids_clearance_for_every_edit_kind",
        edit_property(Backend::Production),
    );
}

/// I-66: the same on the reference alone.
#[test]
fn i66_edit_after_report_voids_clearance_for_every_edit_kind_on_the_reference() {
    check(
        "i66_edit_after_report_voids_clearance_for_every_edit_kind_on_the_reference",
        edit_property(Backend::Reference),
    );
}
