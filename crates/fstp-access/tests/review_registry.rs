//! Review reproducers for the `OPS` registry of lane W3a (M4 design
//! sections 3.2 and 3.6). Each test fails against the registry as
//! reviewed and passes once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{CreatorKind, OPS, OpKind};

/// Whether a person issues the creator kind. The match has no wildcard,
/// so a new variant fails to compile until it is placed.
fn person_issued(k: CreatorKind) -> bool {
    match k {
        CreatorKind::OpenDraft
        | CreatorKind::ApplyStart
        | CreatorKind::SaveFields
        | CreatorKind::AcceptNarrative
        | CreatorKind::Invite
        | CreatorKind::WithdrawInvitation
        | CreatorKind::AcknowledgeWarning
        | CreatorKind::RequestActivation
        | CreatorKind::ApproveActivation
        | CreatorKind::SaveAsTenantTemplate => true,
    }
}

/// TH-49, R-PG-02, R-PG-05, design section 3.2: every `CreatorCommand` a
/// person issues has one routed operation, as every routed command kind
/// has. `AcceptNarrative` is how a manager accepts template text (TH-49),
/// `WithdrawInvitation` withdraws an invitation, and `SaveAsTenantTemplate`
/// saves a tenant-private template. Without an operation the creator pages
/// cannot reach them, and `web/src/gen/api.ts` has no entry for them.
#[test]
fn review_every_person_issued_creator_kind_is_routed() {
    let kinds = [
        CreatorKind::OpenDraft,
        CreatorKind::ApplyStart,
        CreatorKind::SaveFields,
        CreatorKind::AcceptNarrative,
        CreatorKind::Invite,
        CreatorKind::WithdrawInvitation,
        CreatorKind::AcknowledgeWarning,
        CreatorKind::RequestActivation,
        CreatorKind::ApproveActivation,
        CreatorKind::SaveAsTenantTemplate,
    ];
    let unrouted: Vec<CreatorKind> = kinds
        .into_iter()
        .filter(|k| person_issued(*k))
        .filter(|k| {
            OPS.iter()
                .filter(|o| o.kind == OpKind::Creator(*k) && o.route.is_some())
                .count()
                != 1
        })
        .collect();
    assert!(
        unrouted.is_empty(),
        "creator kinds with no routed operation: {unrouted:?}"
    );
}
