//! I-66 (Daniel, 2026-11-15 night): a field save that clears a field
//! seeds `FieldUnset` after the opening, which closes the generator gap
//! GAP_UNSET. A policy save and an artefact save that each clear a field
//! agree with the reference on production, step by step: the seed is
//! accepted, an activation request on the gap does not clear, and a fix
//! that saves the field again is accepted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{Backend, System};
use fstp_api_testkit::reference::creator::{
    Base, EditKind, M1, RefCheck, RefCommand, RefEdit, StepVerdict, TB, clean_plan,
};

/// The verdicts of one sequence on `backend`.
fn verdicts(backend: Backend, kind: EditKind) -> Vec<StepVerdict> {
    let mut s = System::open(backend, &clean_plan()).unwrap();
    let edit = |effect| RefCommand::Edit {
        by: M1,
        kind,
        effect,
        base: Base::Head,
    };
    let steps = [
        edit(RefEdit::Seed(RefCheck::FieldUnset)),
        RefCommand::Request {
            by: M1,
            base: Base::Head,
        },
        RefCommand::Approve {
            by: TB,
            base: Base::Head,
        },
        edit(RefEdit::Fix(RefCheck::FieldUnset)),
    ];
    steps
        .iter()
        .map(|c| {
            s.apply(c)
                .unwrap_or_else(|e| panic!("{kind:?} {c:?} on {backend:?}: {e}"))
        })
        .collect()
}

/// I-66: the clear seeds `FieldUnset` on production as the reference
/// says, for a policy save and an artefact save.
#[test]
fn i66_clear_seeds_field_unset_as_the_reference_says() {
    for kind in [EditKind::Policy, EditKind::Artefact] {
        let reference = verdicts(Backend::Reference, kind);
        let production = verdicts(Backend::Production, kind);
        assert_eq!(production, reference, "{kind:?}");
        assert_eq!(reference[0], StepVerdict::Accepted, "{kind:?}: the seed");
        assert!(
            !reference[2].accepted(),
            "{kind:?}: an approval over the gap: {:?}",
            reference[2]
        );
        assert_eq!(reference[3], StepVerdict::Accepted, "{kind:?}: the fix");
    }
}
