//! The API core's `Tokens` port over the cell's authorisation server
//! (design sections 3.7 step 0 and 3.8, ADR-013, lane L2).
//!
//! Every access token is judged by `fstp-oauth` on every call, then
//! against the account's last completed recovery: a token of a family
//! that started at or before it is refused (I-79, H-21). Roles are not
//! judged here. The API core re-evaluates them on every call.
//!
//! Lane L1's composition plugs [`CellTokens`] into its `CellPorts` (lane
//! L2 seam). Until then the production cell serves the OAuth endpoints and
//! no `/mcp`.

use std::collections::BTreeSet;
use std::sync::Arc;

use fstp_access::GrantFacts;
use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AgentClientId, AgentInfo, ConsentApproval, LoginMethod, PortError};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_oauth::{Account, AuthorizeOutcome, ClientNumber, ConsentAuth, StepUpProof};

use super::AuthServer;

/// The `Tokens` port of a production cell.
#[derive(Clone, Debug)]
pub struct CellTokens {
    server: Arc<AuthServer>,
}

impl CellTokens {
    /// The port over `server`.
    pub fn new(server: Arc<AuthServer>) -> CellTokens {
        CellTokens { server }
    }

    /// The authorisation server.
    pub fn server(&self) -> &Arc<AuthServer> {
        &self.server
    }
}

/// The port's login method of an `fstp-oauth` method.
const fn port_method(m: fstp_oauth::LoginMethod) -> LoginMethod {
    match m {
        fstp_oauth::LoginMethod::Passkey => LoginMethod::Passkey,
        fstp_oauth::LoginMethod::MagicLink => LoginMethod::MagicLink,
        fstp_oauth::LoginMethod::Opaque => LoginMethod::Opaque,
        fstp_oauth::LoginMethod::EudiWallet => LoginMethod::EudiWallet,
    }
}

/// The `fstp-oauth` method of a port login method.
const fn oauth_method(m: LoginMethod) -> fstp_oauth::LoginMethod {
    match m {
        LoginMethod::Passkey => fstp_oauth::LoginMethod::Passkey,
        LoginMethod::MagicLink => fstp_oauth::LoginMethod::MagicLink,
        LoginMethod::Opaque => fstp_oauth::LoginMethod::Opaque,
        LoginMethod::EudiWallet => fstp_oauth::LoginMethod::EudiWallet,
    }
}

/// The access crate's method of an `fstp-oauth` method.
const fn access_method(m: fstp_oauth::LoginMethod) -> fstp_access::LoginMethod {
    match m {
        fstp_oauth::LoginMethod::Passkey => fstp_access::LoginMethod::Passkey,
        fstp_oauth::LoginMethod::MagicLink => fstp_access::LoginMethod::MagicLink,
        fstp_oauth::LoginMethod::Opaque => fstp_access::LoginMethod::Opaque,
        fstp_oauth::LoginMethod::EudiWallet => fstp_access::LoginMethod::EudiWallet,
    }
}

/// The API core's scopes of an `fstp-oauth` scope set, by name.
pub(crate) fn port_scopes(s: fstp_oauth::ScopeSet) -> BTreeSet<Scope> {
    s.iter()
        .filter_map(|s| Scope::ALL.into_iter().find(|x| x.as_str() == s.as_str()))
        .collect()
}

/// The `fstp-oauth` client number of a port client id, or `None` for an
/// id the server never issues.
fn client_number(c: AgentClientId) -> Option<ClientNumber> {
    u64::try_from(c.raw()).ok().map(ClientNumber::from_raw)
}

impl CellTokens {
    /// The grant of the access token `token` at `now`, under the recovery
    /// check.
    ///
    /// # Errors
    ///
    /// [`PortError::Refused`] for a token that is not valid now,
    /// [`PortError::Unavailable`] when the server cannot be loaded.
    pub async fn grant_facts(&self, token: &[u8], now: Timestamp) -> Result<GrantFacts, PortError> {
        if token.len() != 43 || !token.iter().all(u8::is_ascii_graphic) {
            return Err(PortError::Refused);
        }
        let mut header = b"Bearer ".to_vec();
        header.extend_from_slice(token);
        let resource = self.server.config().resource.clone();
        let g = self
            .server
            .read(|s, guard, _| {
                s.authenticate_guarded(Some(&header), &resource, now.micros(), guard)
            })
            .await
            .map_err(|_| PortError::Unavailable)?
            .map_err(|_| PortError::Refused)?;
        Ok(GrantFacts {
            account: AccountId::from_raw(g.account.raw()),
            agent: fstp_access::AgentClientId::from_raw(u128::from(g.client.raw())),
            scopes: port_scopes(g.scopes).into_iter().collect(),
            consent_method: access_method(g.consent_method),
        })
    }

    /// Ends every grant of `client` for `account`, durably (R-MC-03).
    ///
    /// # Errors
    ///
    /// [`PortError::Refused`] when nothing was revoked.
    pub async fn revoke_agent(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> Result<(), PortError> {
        let Some(number) = client_number(client) else {
            return Err(PortError::Refused);
        };
        let n = self
            .server
            .call(|s, _, now| {
                s.revoke_agent_by_number(Account::from_raw(account.raw()), number, now)
            })
            .await
            .map_err(|_| PortError::Unavailable)?;
        if n > 0 {
            Ok(())
        } else {
            Err(PortError::Refused)
        }
    }

    /// The approval of `c`: the API core's step-up, attested under the
    /// consent's own digest at the instant of the approval (ADR-013
    /// "Consent", I-78). The server checks the proof again.
    ///
    /// # Errors
    ///
    /// [`PortError::Refused`] for a handle the server does not hold or a
    /// proof it refuses.
    pub async fn approve(&self, c: &ConsentApproval) -> Result<String, PortError> {
        let account = Account::from_raw(c.account.raw());
        let method = oauth_method(c.method);
        let at = c.at.micros();
        let handle = c.handle.clone();
        self.server
            .call(move |s, _, _| {
                let digest = s.consent_step_up_digest(&handle, at)?;
                let auth = ConsentAuth {
                    session: method,
                    step_up: Some(StepUpProof {
                        account,
                        digest,
                        at,
                        method,
                    }),
                };
                match s.approve(&handle, account, &auth, at) {
                    AuthorizeOutcome::Redirect(to) => Some(to),
                    _ => None,
                }
            })
            .await
            .map_err(|_| PortError::Unavailable)?
            .ok_or(PortError::Refused)
    }

    /// The live agent clients of `account` at `now`, one per client with
    /// the union of the scopes (R-MC-03). A grant the recovery check
    /// refuses is not live.
    ///
    /// # Errors
    ///
    /// [`PortError::Unavailable`] when the server cannot be loaded.
    pub async fn agents_of(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> Result<Vec<AgentInfo>, PortError> {
        let grants = self
            .server
            .read(|s, guard, _| {
                let a = Account::from_raw(account.raw());
                s.agents_of(a, now.micros())
                    .into_iter()
                    .filter(|g| !guard.refused(a, g.start))
                    .collect::<Vec<_>>()
            })
            .await
            .map_err(|_| PortError::Unavailable)?;
        let mut by: std::collections::BTreeMap<AgentClientId, AgentInfo> =
            std::collections::BTreeMap::new();
        for g in grants {
            let client = AgentClientId::from_raw(u128::from(g.client.raw()));
            let e = by.entry(client).or_insert_with(|| AgentInfo {
                client,
                name: g.client_name.clone(),
                scopes: BTreeSet::new(),
                method: port_method(g.consent_method),
                since: Some(Timestamp::from_micros(g.start)),
                until: Some(Timestamp::from_micros(g.end)),
            });
            e.scopes.extend(port_scopes(g.scopes));
        }
        Ok(by.into_values().collect())
    }
}

impl fstp_api_core::port::Tokens for CellTokens {
    async fn grant(&self, token: &[u8], now: Timestamp) -> Result<GrantFacts, PortError> {
        self.grant_facts(token, now).await
    }

    async fn revoke(&self, account: AccountId, client: AgentClientId) -> Result<(), PortError> {
        self.revoke_agent(account, client).await
    }

    async fn approve_consent(&self, c: ConsentApproval) -> Result<String, PortError> {
        self.approve(&c).await
    }

    async fn agents(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> Result<Vec<AgentInfo>, PortError> {
        self.agents_of(account, now).await
    }
}
