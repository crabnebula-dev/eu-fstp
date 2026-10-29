//! Fake MCP token grants (design sections 3.7 step 0 and 3.8).
//!
//! Gap, reported by the W3b test author: `port.rs` has no port that
//! resolves a bearer token. Dispatch step 0 needs one to build
//! `Principal::mcp`: the account, the agent client, the scopes and the
//! strength of the consenting session. This fake holds exactly that, with
//! the methods such a port would have, so the I-85 tests can issue and
//! revoke tokens. Until the lead adds the port, no dispatch can read it.
//! ADR-013 (a draft) governs token lifetimes and rotation. This fake holds
//! none of that: a token is valid until revoked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fstp_access::GrantFacts;
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AgentClientId, LoginMethod, PortError};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

use super::lock;
use super::sessions::phishing_resistant;

/// What a valid token grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenGrant {
    /// The account that consented.
    pub account: AccountId,
    /// The agent client.
    pub client: AgentClientId,
    /// The scopes of the grant.
    pub scopes: BTreeSet<Scope>,
    /// The login method of the consenting session.
    pub consented_with: LoginMethod,
    /// Whether that method is phishing-resistant. The token inherits it.
    pub phishing_resistant: bool,
}

#[derive(Debug, Default)]
struct State {
    grants: BTreeMap<Vec<u8>, (TokenGrant, bool)>,
    next: u128,
}

/// The fake token grants. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeTokens {
    state: Arc<Mutex<State>>,
}

impl FakeTokens {
    /// Issues a token for `client` of `account` with `scopes`, consented in
    /// a session that logged in with `method`. Returns the token value.
    pub fn issue(
        &self,
        account: AccountId,
        client: AgentClientId,
        scopes: impl IntoIterator<Item = Scope>,
        method: LoginMethod,
    ) -> Vec<u8> {
        let mut s = lock(&self.state);
        let n = s.next;
        s.next = n.saturating_add(1);
        let mut token = b"fake-token-".to_vec();
        token.extend_from_slice(&n.to_be_bytes());
        s.grants.insert(
            token.clone(),
            (
                TokenGrant {
                    account,
                    client,
                    scopes: scopes.into_iter().collect(),
                    consented_with: method,
                    phishing_resistant: phishing_resistant(method),
                },
                false,
            ),
        );
        token
    }

    /// The grant of `token`, if it is valid at `now`.
    pub fn grant(&self, token: &[u8], now: Timestamp) -> Result<TokenGrant, PortError> {
        let _ = now;
        match lock(&self.state).grants.get(token) {
            Some((g, false)) => Ok(g.clone()),
            Some((_, true)) | None => Err(PortError::Refused),
        }
    }

    /// The grant of `token` at `now` as `fstp_access` takes it, for the
    /// token port once `port.rs` declares it.
    pub fn grant_facts(&self, token: &[u8], now: Timestamp) -> Result<GrantFacts, PortError> {
        let g = self.grant(token, now)?;
        Ok(GrantFacts {
            account: g.account,
            agent: fstp_access::AgentClientId::from_raw(g.client.raw()),
            scopes: g.scopes.iter().copied().collect(),
            consent_method: match g.consented_with {
                LoginMethod::Passkey => fstp_access::LoginMethod::Passkey,
                LoginMethod::MagicLink => fstp_access::LoginMethod::MagicLink,
                LoginMethod::Opaque => fstp_access::LoginMethod::Opaque,
                LoginMethod::EudiWallet => fstp_access::LoginMethod::EudiWallet,
            },
        })
    }

    /// Revokes every token of `client` for `account` at once (R-MC-03).
    pub fn revoke(&self, account: AccountId, client: AgentClientId) -> Result<(), PortError> {
        let mut s = lock(&self.state);
        let mut any = false;
        for (g, revoked) in s.grants.values_mut() {
            if g.account == account && g.client == client {
                *revoked = true;
                any = true;
            }
        }
        if any { Ok(()) } else { Err(PortError::Refused) }
    }

    /// How many tokens were issued.
    pub fn issued(&self) -> usize {
        lock(&self.state).grants.len()
    }

    /// Whether every token of `client` for `account` is revoked.
    pub fn is_revoked(&self, account: AccountId, client: AgentClientId) -> bool {
        lock(&self.state)
            .grants
            .values()
            .filter(|(g, _)| g.account == account && g.client == client)
            .all(|(_, revoked)| *revoked)
    }
}
