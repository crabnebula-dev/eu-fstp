//! SoD-07, J0, I-86 (ADR-026 record of lane L18): `tenant.invite_admin`
//! hands the address, the drawn invitee and the link token to the
//! accounts port, once the invitation is appended. The ledger holds only
//! the token's digest, and the reply names neither the token nor the
//! address. A call that asks for a step-up hands nothing over.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod signatories;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::InviteKind;
use fstp_api_core::{ApiError, Op, OpResult};
use signatories::{done, login, onboarded, stepped};

const EMAIL: &str = "third-admin@matrix.invalid";

fn invite_admin() -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        "/admin/admins",
        format!(r#"{{"email":"{EMAIL}"}}"#).as_bytes(),
    )
}

/// SoD-07, J0, I-86: the port receives one `TenantAdmin` invitation with
/// the address, and its token's digest and invitee are those the ledger
/// recorded. Before the step-up nothing reaches the port.
#[test]
fn sod07_invite_admin_hands_token_and_address_to_the_accounts_port() {
    let (c, l1, _l2) = onboarded(&[]);
    let first = c.web(&l1, invite_admin());
    assert!(
        matches!(first, Ok(OpResult::StepUpRequired(_))),
        "I-78: {first:?}"
    );
    assert!(
        c.ports.accounts.invitations().is_empty(),
        "the port heard of an invitation before its step-up"
    );
    let reply = done(stepped(&c, &l1, &invite_admin), "tenant.invite_admin by A1");
    let kinds = c.ports.accounts.invitations();
    assert_eq!(kinds.len(), 1, "{kinds:?}");
    let InviteKind::TenantAdmin {
        invitation,
        invitee,
        email,
        token,
    } = &kinds[0]
    else {
        panic!("not an admin invitation: {:?}", kinds[0]);
    };
    assert_eq!(email, EMAIL);
    let state = c.ports.engine.state();
    let recorded = state
        .tenant
        .state()
        .and_then(|t| t.invitation(*invitation))
        .expect("the ledger's admin invitation");
    assert_eq!(recorded.invitee, *invitee);
    assert!(!recorded.taken);
    assert_eq!(
        recorded.token_digest,
        fstp_tenant::TokenDigest::from_bytes(fstp_crypto::sha256(token.bytes())),
        "the port's token is the one whose digest the ledger holds"
    );
    let shown = reply.to_compact();
    assert!(!shown.contains(&token.hex()), "the token in the reply");
    assert!(!shown.contains(EMAIL), "I-86: the address in the reply");
    let printed = format!("{:?}", kinds[0]);
    assert!(
        !printed.contains(&token.hex()) && !printed.contains(EMAIL),
        "{printed}"
    );
    let _ = login;
}
