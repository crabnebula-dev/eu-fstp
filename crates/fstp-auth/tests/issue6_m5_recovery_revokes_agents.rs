//! Issue 6 M5, H-21: account recovery completion revokes every agent
//! grant and refresh token of the account (I-79, R-MC-03).
//!
//! The crate does not depend on the OAuth server. The completion calls
//! the `AgentGrants` port, and the cell wires the port to
//! `fstp_oauth::AuthorizationServer::revoke_all_agents`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::recovery::{
    AgentGrants, Case, Deployment, Evidence, RecoveryPath, Revocation, complete_revoking,
};
use fstp_auth::{RosterView, TenantView};
use fstp_domain::id::AccountId;
use fstp_webauthn::{CoseKey, NewCredential};

#[derive(Default)]
struct Grants {
    revoked: Vec<AccountId>,
}

impl AgentGrants for Grants {
    fn revoke_all_agents(&mut self, account: AccountId) -> usize {
        self.revoked.push(account);
        1
    }
}

fn case(email: bool) -> Case {
    Case {
        case: [0xCA; 16],
        holder: AccountId::from_raw(1),
        requested: RecoveryPath::EmailThenPasskey,
        evidence: Evidence {
            email,
            approval: None,
            ticket: None,
            host_console: false,
        },
    }
}

fn credential() -> NewCredential {
    NewCredential {
        id: vec![0x09; 16],
        key: CoseKey::Ed25519 { x: [0x03; 32] },
        sign_count: 0,
        user_verified: true,
    }
}

/// I-79, H-21: a completed recovery revokes the agent grants of the
/// recovered account, and only of that account.
#[test]
fn issue6_m5_completion_revokes_every_agent_grant_of_the_account() {
    let new = credential();
    let r = Revocation {
        credentials: &[],
        sessions: &[],
        new_credential: &new,
    };
    let mut grants = Grants::default();
    let records = complete_revoking(
        &case(true),
        &RosterView::default(),
        &TenantView { admins: vec![] },
        Deployment::Saas,
        &r,
        &mut grants,
    )
    .unwrap();
    assert!(!records.is_empty());
    assert_eq!(grants.revoked, vec![AccountId::from_raw(1)]);
}

/// I-79, H-21: a refused completion revokes nothing.
#[test]
fn issue6_m5_refused_completion_revokes_nothing() {
    let new = credential();
    let r = Revocation {
        credentials: &[],
        sessions: &[],
        new_credential: &new,
    };
    let mut grants = Grants::default();
    let got = complete_revoking(
        &case(false),
        &RosterView::default(),
        &TenantView { admins: vec![] },
        Deployment::Saas,
        &r,
        &mut grants,
    );
    assert!(got.is_err());
    assert!(grants.revoked.is_empty());
}
