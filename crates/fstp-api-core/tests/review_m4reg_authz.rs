//! Review reproducers for lane m4reg, authorisation lens. Each test fails
//! against the lane's work as reviewed and passes once the defect it
//! names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::num::NonZeroU32;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::model::{InvitationLanding, InvitationState};
use fstp_domain::roles::Role;

/// SoD-09, `programme-creator.md` step 9 ("finance roles"): creator step
/// 9 invites finance roles, and `fstp-creator` admits every role outside
/// Receiving and tenant admin. The invitation landing must exist for each
/// such invitee, yet `InvitationLanding::new` refuses the finance roles.
#[test]
fn review_sod09_invitation_landing_exists_for_finance_roles() {
    for role in [Role::FinanceApprover, Role::PaymentReleaser] {
        assert!(
            InvitationLanding::new(role, NonZeroU32::MIN, None, None, InvitationState::Invited)
                .is_some(),
            "no invitation landing for an invited {role:?}"
        );
    }
}

/// SoD-09, R-AC-01: `people.get_invitation` admits a caller with no
/// account (`ReadRule::InvitationLink`), so the link's token is the only
/// capability. A short decimal id is guessable, so the landing route must
/// never decode one.
#[test]
fn review_sod09_invitation_landing_refuses_a_guessable_decimal_id() {
    let r = decode_route(Method::Get, "/invitations/7", b"");
    assert!(
        r.is_err(),
        "GET /invitations/7 decodes as {:?}",
        r.map(|op| op.name())
    );
}
