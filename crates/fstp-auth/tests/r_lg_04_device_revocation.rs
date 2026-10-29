//! R-LG-04: users end their own linked devices. `DELETE
//! /auth/devices/{id}` revokes a credential of the actor's own account,
//! and its batch ends the passkey sessions that credential logged in.
//!
//! Reading, shared with the W1b reference `ended_by_credential_revocation`:
//! removing a device ends the sessions that device logged in, and no other
//! session.
//!
//! Lane W2b, fix round 1.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::session::{
    CredentialOwner, SessionLogin, ended_by_credential_revocation, may_revoke_credential,
};
use fstp_auth::{Method, SessionView};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

const T0: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);
const ALICE: AccountId = AccountId::from_raw(1);
const BOB: AccountId = AccountId::from_raw(2);

fn owners() -> Vec<CredentialOwner> {
    vec![
        CredentialOwner {
            account: ALICE,
            credential: vec![0xA1; 8],
        },
        CredentialOwner {
            account: BOB,
            credential: vec![0xB1; 8],
        },
    ]
}

/// R-LG-04: only the credential's own account may remove it, and only a
/// live credential.
#[test]
fn r_lg_04_only_the_owner_revokes_a_credential() {
    check(
        "r_lg_04_only_the_owner_revokes_a_credential",
        |g: &mut Gen| {
            let live = owners();
            let actor = *g.pick(&[ALICE, BOB]);
            let account = *g.pick(&[ALICE, BOB]);
            let credential = g
                .pick(&[vec![0xA1; 8], vec![0xB1; 8], vec![0xC1; 8]])
                .clone();
            let owned = live
                .iter()
                .any(|c| c.account == account && c.credential == credential);
            let want = actor == account && owned;
            prop_assert_eq!(
                may_revoke_credential(&live, actor, account, &credential),
                want,
                "{actor:?} {account:?} {credential:?}"
            );
            Ok(())
        },
    );
}

fn session(id: u8, account: AccountId, method: Method) -> SessionView {
    SessionView {
        id: [id; 16],
        account,
        method,
        started: T0,
        last_used: T0,
    }
}

/// R-LG-04: revoking a credential ends exactly the account's passkey
/// sessions that it logged in. Another credential's session, another
/// account's session and a magic-link session stay.
#[test]
fn r_lg_04_revocation_ends_the_sessions_of_that_device() {
    let live = [
        session(1, ALICE, Method::Passkey),
        session(2, ALICE, Method::Passkey),
        session(3, ALICE, Method::MagicLink),
        session(4, BOB, Method::Passkey),
    ];
    let logins = [
        SessionLogin {
            session: [1; 16],
            credential: vec![0xA1; 8],
        },
        SessionLogin {
            session: [2; 16],
            credential: vec![0xA2; 8],
        },
        SessionLogin {
            session: [4; 16],
            credential: vec![0xA1; 8],
        },
    ];
    assert_eq!(
        ended_by_credential_revocation(&live, &logins, ALICE, &[0xA1; 8]),
        vec![[1; 16]]
    );
    assert!(ended_by_credential_revocation(&live, &logins, ALICE, &[0xA3; 8]).is_empty());
}
