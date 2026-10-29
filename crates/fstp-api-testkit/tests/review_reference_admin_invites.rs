//! Review reproducer (lane W2a, M4 design section 2.2 J1).
//!
//! Journey J1 has the tenant admin A1 invite M1 as programme manager on
//! the draft, before any programme manager exists. Production admits an
//! invitation from a tenant admin (`fstp_creator::decide_creator`,
//! `manager_or_admin`). The reference refuses every `Edit`, invitations
//! included, from an account without a programme manager binding. The
//! two-way check of M-ACTIVATE generates admin edits, so once the
//! production adapter is wired it reports a correct admission as a
//! disagreement.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::reference::creator::{
    Base, EditKind, RefCommand, RefEdit, RefSystem, StepVerdict, TA, clean_plan,
};

/// R-PG-03, J1: the opening tenant admin may invite people to the draft.
#[test]
fn review_reference_admits_tenant_admin_invitation() {
    let mut s = RefSystem::open(&clean_plan()).unwrap();
    let verdict = s.apply(&RefCommand::Edit {
        by: TA,
        kind: EditKind::Invitation,
        effect: RefEdit::Neutral,
        base: Base::Head,
    });
    assert_eq!(verdict, StepVerdict::Accepted);
}
