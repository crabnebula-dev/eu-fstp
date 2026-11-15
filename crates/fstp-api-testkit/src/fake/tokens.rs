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
use fstp_api_core::port::{AgentClientId, AgentInfo, ConsentApproval, LoginMethod, PortError};
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

/// The issuer of the fake cell's authorisation server (ADR-013).
pub const OAUTH_ISSUER: &str = "https://cell.fstp.test";
/// The MCP resource of the fake cell's authorisation server.
pub const OAUTH_RESOURCE: &str = "https://cell.fstp.test/mcp";
/// The loopback redirect URI of the fake agent client (RFC 8252).
pub const OAUTH_REDIRECT: &str = "http://127.0.0.1:8765/callback";
/// P-72 and P-71 of the fake authorisation server: 12 hours and 5 minutes.
const OAUTH_P72: i64 = 43_200_000_000;
const OAUTH_P71: i64 = 300_000_000;

/// The real `fstp-oauth` authorisation server of a fake cell, with the one
/// agent client it registered.
#[derive(Debug)]
struct Oauth {
    server: fstp_oauth::AuthorizationServer,
    client_id: String,
}

/// A consent the authorize flow left for the user: its handle, and what
/// the agent keeps to redeem the code.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentStart {
    /// The handle `agents.consent` names. A secret of the browser.
    pub handle: String,
    /// The agent client.
    pub client_id: String,
    /// The redirect URI the code goes to.
    pub redirect_uri: String,
    /// The PKCE verifier of the request.
    pub verifier: String,
}

impl std::fmt::Debug for ConsentStart {
    /// Never shows the handle or the verifier.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentStart")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// The fake token grants. Cloning shares them.
#[derive(Clone, Debug, Default)]
pub struct FakeTokens {
    state: Arc<Mutex<State>>,
    /// The authorisation server of ADR-013, built on first use.
    oauth: Arc<Mutex<Option<Oauth>>>,
}

impl FakeTokens {
    /// Runs `f` on the cell's authorisation server, built with its agent
    /// client on first use.
    fn with_oauth<R>(&self, f: impl FnOnce(&mut Oauth) -> R) -> Result<R, String> {
        let mut slot = lock(&self.oauth);
        if slot.is_none() {
            let cfg = fstp_oauth::Config::new(OAUTH_ISSUER, OAUTH_RESOURCE, OAUTH_P72, OAUTH_P71);
            let mut server =
                fstp_oauth::AuthorizationServer::new(cfg).map_err(|e| e.to_string())?;
            let body = format!(
                r#"{{"client_name":"Synthetic agent","redirect_uris":["{OAUTH_REDIRECT}"]}}"#
            );
            let r = server.register(fstp_oauth::RateKey::from_raw(1), body.as_bytes(), 0);
            let client_id = fstp_json::parse(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("client_id")
                        .and_then(fstp_json::Value::as_str)
                        .map(str::to_owned)
                })
                .ok_or_else(|| format!("registration refused: {}", r.status))?;
            *slot = Some(Oauth { server, client_id });
        }
        slot.as_mut().map(f).ok_or_else(|| "no server".to_owned())
    }

    /// `GET /oauth/authorize` of the agent client at `now`, with PKCE
    /// `S256`, the scope `calls:read` and this cell's resource: the
    /// consent the user is asked for (ADR-013).
    ///
    /// # Errors
    ///
    /// When the server refuses the request or `fstp_crypto` fails.
    pub fn begin_consent(&self, now: Timestamp) -> Result<ConsentStart, String> {
        let raw = fstp_crypto::random_array::<32>().map_err(|e| format!("{e:?}"))?;
        let verifier = fstp_oauth::encode_base64url(&raw);
        let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(verifier.as_bytes()));
        self.with_oauth(|o| {
            let query = fstp_oauth::encode_form_urlencoded(&[
                ("response_type", "code"),
                ("client_id", o.client_id.as_str()),
                ("redirect_uri", OAUTH_REDIRECT),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("scope", "calls:read"),
                ("resource", OAUTH_RESOURCE),
            ]);
            match o.server.authorize_from(
                fstp_oauth::RateKey::from_raw(2),
                query.as_bytes(),
                now.micros(),
            ) {
                fstp_oauth::AuthorizeOutcome::Consent(c) => Ok(ConsentStart {
                    handle: c.handle,
                    client_id: o.client_id.clone(),
                    redirect_uri: OAUTH_REDIRECT.to_owned(),
                    verifier: verifier.clone(),
                }),
                other => Err(format!("authorize: {other:?}")),
            }
        })?
    }

    /// Redeems the code that `redirect` carries for `start` at `now`, and
    /// authenticates the access token it gives: the grant of the consent.
    ///
    /// # Errors
    ///
    /// When the redirect carries no code or the server refuses it.
    pub fn redeem(
        &self,
        start: &ConsentStart,
        redirect: &str,
        now: Timestamp,
    ) -> Result<fstp_oauth::Grant, String> {
        let code = redirect
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("code="))
            .ok_or("no code")?
            .to_owned();
        self.with_oauth(|o| {
            let body = fstp_oauth::encode_form_urlencoded(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", start.client_id.as_str()),
                ("redirect_uri", start.redirect_uri.as_str()),
                ("code_verifier", start.verifier.as_str()),
                ("resource", OAUTH_RESOURCE),
            ]);
            let r = o.server.token(body.as_bytes(), now.micros());
            let token = fstp_json::parse(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("access_token")
                        .and_then(fstp_json::Value::as_str)
                        .map(str::to_owned)
                })
                .ok_or_else(|| format!("token refused: {}", r.status))?;
            let header = format!("Bearer {token}");
            o.server
                .authenticate(Some(header.as_bytes()), OAUTH_RESOURCE, now.micros())
                .map_err(|r| format!("authenticate: {}", r.status))
        })?
    }

    /// The approval of `c` at the cell's authorisation server: the API
    /// core's step-up, attested under the consent's own digest at the
    /// instant of the approval (ADR-013 "Consent", I-78).
    fn approve(&self, c: &ConsentApproval) -> Result<String, PortError> {
        let account = u64::try_from(c.account.raw()).map_err(|_| PortError::Refused)?;
        let account = fstp_oauth::Account::from_raw(account);
        let method = match c.method {
            LoginMethod::Passkey => fstp_oauth::LoginMethod::Passkey,
            LoginMethod::MagicLink => fstp_oauth::LoginMethod::MagicLink,
            LoginMethod::Opaque => fstp_oauth::LoginMethod::Opaque,
            LoginMethod::EudiWallet => fstp_oauth::LoginMethod::EudiWallet,
        };
        let at = c.at.micros();
        self.with_oauth(|o| {
            let digest = o
                .server
                .consent_step_up_digest(&c.handle, at)
                .ok_or(PortError::Refused)?;
            let auth = fstp_oauth::ConsentAuth {
                session: method,
                step_up: Some(fstp_oauth::StepUpProof {
                    account,
                    digest,
                    at,
                    method,
                }),
            };
            match o.server.approve(&c.handle, account, &auth, at) {
                fstp_oauth::AuthorizeOutcome::Redirect(to) => Ok(to),
                _ => Err(PortError::Refused),
            }
        })
        .map_err(|_| PortError::Unavailable)?
    }

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

    /// Revokes every token of `client` for `account` at once, those it
    /// issued and those the authorisation server issued (R-MC-03).
    pub fn revoke(&self, account: AccountId, client: AgentClientId) -> Result<(), PortError> {
        let mut any = false;
        {
            let mut s = lock(&self.state);
            for (g, revoked) in s.grants.values_mut() {
                if g.account == account && g.client == client {
                    *revoked = true;
                    any = true;
                }
            }
        }
        if let (Ok(a), Ok(c)) = (u64::try_from(account.raw()), u64::try_from(client.raw()))
            && let Some(o) = lock(&self.oauth).as_mut()
        {
            let n = o.server.revoke_agent_by_number(
                fstp_oauth::Account::from_raw(a),
                fstp_oauth::ClientNumber::from_raw(c),
                0,
            );
            any = any || n > 0;
        }
        if any { Ok(()) } else { Err(PortError::Refused) }
    }

    /// The live agent clients of `account` at `now` (R-MC-03): the
    /// clients of the tokens it issued that are not revoked, and the
    /// grants of the authorisation server, one entry per client with the
    /// union of the scopes.
    pub fn agents(&self, account: AccountId, now: Timestamp) -> Vec<AgentInfo> {
        let mut by: BTreeMap<AgentClientId, AgentInfo> = BTreeMap::new();
        for (g, revoked) in lock(&self.state).grants.values() {
            if *revoked || g.account != account {
                continue;
            }
            let e = by.entry(g.client).or_insert_with(|| AgentInfo {
                client: g.client,
                name: None,
                scopes: BTreeSet::new(),
                method: g.consented_with,
                since: None,
                until: None,
            });
            e.scopes.extend(g.scopes.iter().copied());
        }
        let Ok(a) = u64::try_from(account.raw()) else {
            return by.into_values().collect();
        };
        if let Some(o) = lock(&self.oauth).as_ref() {
            for g in o
                .server
                .agents_of(fstp_oauth::Account::from_raw(a), now.micros())
            {
                let client = AgentClientId::from_raw(u128::from(g.client.raw()));
                let e = by.entry(client).or_insert_with(|| AgentInfo {
                    client,
                    name: g.client_name.clone(),
                    scopes: BTreeSet::new(),
                    method: match g.consent_method {
                        fstp_oauth::LoginMethod::Passkey => LoginMethod::Passkey,
                        fstp_oauth::LoginMethod::MagicLink => LoginMethod::MagicLink,
                        fstp_oauth::LoginMethod::Opaque => LoginMethod::Opaque,
                        fstp_oauth::LoginMethod::EudiWallet => LoginMethod::EudiWallet,
                    },
                    since: Some(Timestamp::from_micros(g.start)),
                    until: Some(Timestamp::from_micros(g.end)),
                });
                e.scopes.extend(
                    g.scopes
                        .iter()
                        .filter_map(|s| Scope::ALL.into_iter().find(|x| x.as_str() == s.as_str())),
                );
            }
        }
        by.into_values().collect()
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

impl fstp_api_core::port::Tokens for FakeTokens {
    async fn grant(&self, token: &[u8], now: Timestamp) -> Result<GrantFacts, PortError> {
        self.grant_facts(token, now)
    }

    async fn revoke(&self, account: AccountId, client: AgentClientId) -> Result<(), PortError> {
        FakeTokens::revoke(self, account, client)
    }

    async fn approve_consent(&self, c: ConsentApproval) -> Result<String, PortError> {
        self.approve(&c)
    }

    async fn agents(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> Result<Vec<AgentInfo>, PortError> {
        Ok(FakeTokens::agents(self, account, now))
    }
}
