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

/// Where the authorisation server of a fake cell lives: its issuer and
/// MCP resource, and whether it is a test cell's on a plain `http`
/// `.localhost` origin (lane mcp-demo).
#[derive(Clone, Debug)]
struct OauthSetup {
    issuer: String,
    resource: String,
    test_cell: bool,
}

impl Default for OauthSetup {
    fn default() -> OauthSetup {
        OauthSetup {
            issuer: OAUTH_ISSUER.to_owned(),
            resource: OAUTH_RESOURCE.to_owned(),
            test_cell: false,
        }
    }
}

/// Registrations a test cell admits per rate key and hour. Every client
/// behind one tunnel shares the key of its loopback peer, so the interim
/// default of 10 would end a demo early (lane mcp-demo).
const TEST_CELL_REGISTRATIONS: u32 = 200;

/// The server of `setup`.
fn build_server(setup: &OauthSetup) -> Result<fstp_oauth::AuthorizationServer, String> {
    let mut cfg = fstp_oauth::Config::new(&setup.issuer, &setup.resource, OAUTH_P72, OAUTH_P71);
    if setup.test_cell {
        cfg.registration_max = TEST_CELL_REGISTRATIONS;
        return fstp_oauth::AuthorizationServer::new_test_cell(cfg).map_err(|e| e.to_string());
    }
    fstp_oauth::AuthorizationServer::new(cfg).map_err(|e| e.to_string())
}

/// The API core's login method of a method of `fstp-oauth`.
const fn port_method(m: fstp_oauth::LoginMethod) -> LoginMethod {
    match m {
        fstp_oauth::LoginMethod::Passkey => LoginMethod::Passkey,
        fstp_oauth::LoginMethod::MagicLink => LoginMethod::MagicLink,
        fstp_oauth::LoginMethod::Opaque => LoginMethod::Opaque,
        fstp_oauth::LoginMethod::EudiWallet => LoginMethod::EudiWallet,
    }
}

/// The API core's scopes of an `fstp-oauth` scope set, by name.
fn port_scopes(s: fstp_oauth::ScopeSet) -> BTreeSet<Scope> {
    s.iter()
        .filter_map(|s| Scope::ALL.into_iter().find(|x| x.as_str() == s.as_str()))
        .collect()
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
    /// Where that server lives.
    setup: Arc<OauthSetup>,
}

impl FakeTokens {
    /// The token port of a test cell whose origin is `issuer`, such as the
    /// e2e cell's `http://a.fstp.localhost:8640`: its authorisation server
    /// names that issuer and `{issuer}/mcp` as the one resource, so the
    /// tokens it issues work on the cell's `/mcp` (lane mcp-demo).
    ///
    /// # Errors
    ///
    /// When `fstp-oauth` refuses the issuer.
    pub fn for_test_cell(issuer: &str) -> Result<FakeTokens, String> {
        let setup = OauthSetup {
            issuer: issuer.to_owned(),
            resource: format!("{issuer}/mcp"),
            test_cell: true,
        };
        build_server(&setup)?;
        Ok(FakeTokens {
            setup: Arc::new(setup),
            ..FakeTokens::default()
        })
    }

    /// A token port with no token of its own that shares this port's
    /// authorisation server, after ending every grant that server holds.
    /// The registered clients stay. A test cell that replaces its state
    /// calls it, so an agent reconnects with the client it registered,
    /// and no grant outlives the accounts it was given for.
    pub fn sharing_oauth(&self) -> FakeTokens {
        if let Some(o) = lock(&self.oauth).as_mut() {
            o.server.end_all_grants();
        }
        FakeTokens {
            state: Arc::default(),
            oauth: Arc::clone(&self.oauth),
            setup: Arc::clone(&self.setup),
        }
    }

    /// The MCP resource of the authorisation server.
    pub fn resource(&self) -> &str {
        &self.setup.resource
    }

    /// `POST /oauth/register` from `source` at `now` (RFC 7591).
    ///
    /// # Errors
    ///
    /// When the server cannot be built.
    pub fn register_client(
        &self,
        source: fstp_oauth::RateKey,
        body: &[u8],
        now: Timestamp,
    ) -> Result<fstp_oauth::Reply, String> {
        self.with_oauth(|o| o.server.register(source, body, now.micros()))
    }

    /// `GET /oauth/authorize` with `query` from the browser session keyed
    /// `session` at `now`.
    ///
    /// # Errors
    ///
    /// When the server cannot be built.
    pub fn authorize(
        &self,
        session: fstp_oauth::RateKey,
        query: &[u8],
        now: Timestamp,
    ) -> Result<fstp_oauth::AuthorizeOutcome, String> {
        self.with_oauth(|o| o.server.authorize_from(session, query, now.micros()))
    }

    /// The user's refusal of the consent `handle` at `now`.
    ///
    /// # Errors
    ///
    /// When the server cannot be built.
    pub fn deny(
        &self,
        handle: &str,
        now: Timestamp,
    ) -> Result<fstp_oauth::AuthorizeOutcome, String> {
        self.with_oauth(|o| o.server.deny(handle, now.micros()))
    }

    /// Whether the consent `handle` is live at `now`.
    pub fn consent_is_live(&self, handle: &str, now: Timestamp) -> bool {
        self.with_oauth(|o| {
            o.server
                .consent_step_up_digest(handle, now.micros())
                .is_some()
        })
        .unwrap_or(false)
    }

    /// `POST /oauth/token` with the form `body` at `now`.
    ///
    /// # Errors
    ///
    /// When the server cannot be built.
    pub fn token(&self, body: &[u8], now: Timestamp) -> Result<fstp_oauth::Reply, String> {
        self.with_oauth(|o| o.server.token(body, now.micros()))
    }

    /// `POST /oauth/revoke` with the form `body` at `now` (RFC 7009).
    ///
    /// # Errors
    ///
    /// When the server cannot be built.
    pub fn revoke_token(&self, body: &[u8], now: Timestamp) -> Result<fstp_oauth::Reply, String> {
        self.with_oauth(|o| o.server.revoke(body, now.micros()))
    }

    /// The grant of an access token of the authorisation server, as the
    /// API core reads it, if it is valid at `now` for this resource.
    fn oauth_grant(&self, token: &[u8], now: Timestamp) -> Option<TokenGrant> {
        if token.len() != 43 || !token.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        let mut header = b"Bearer ".to_vec();
        header.extend_from_slice(token);
        let resource = self.setup.resource.clone();
        let g = self
            .with_oauth(|o| {
                o.server
                    .authenticate(Some(&header), &resource, now.micros())
                    .ok()
            })
            .ok()??;
        let method = port_method(g.consent_method);
        Some(TokenGrant {
            account: AccountId::from_raw(g.account.raw()),
            client: AgentClientId::from_raw(u128::from(g.client.raw())),
            scopes: port_scopes(g.scopes),
            consented_with: method,
            phishing_resistant: phishing_resistant(method),
        })
    }

    /// Runs `f` on the cell's authorisation server, built with its agent
    /// client on first use.
    fn with_oauth<R>(&self, f: impl FnOnce(&mut Oauth) -> R) -> Result<R, String> {
        let mut slot = lock(&self.oauth);
        if slot.is_none() {
            let mut server = build_server(&self.setup)?;
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
                ("resource", self.setup.resource.as_str()),
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
                ("resource", self.setup.resource.as_str()),
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
                .authenticate(Some(header.as_bytes()), &self.setup.resource, now.micros())
                .map_err(|r| format!("authenticate: {}", r.status))
        })?
    }

    /// The approval of `c` at the cell's authorisation server: the API
    /// core's step-up, attested under the consent's own digest at the
    /// instant of the approval (ADR-013 "Consent", I-78).
    fn approve(&self, c: &ConsentApproval) -> Result<String, PortError> {
        let account = fstp_oauth::Account::from_raw(c.account.raw());
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

    /// The grant of `token`, if it is valid at `now`: a token this fake
    /// issued, or an access token of the authorisation server (lane
    /// mcp-demo).
    pub fn grant(&self, token: &[u8], now: Timestamp) -> Result<TokenGrant, PortError> {
        let issued = lock(&self.state).grants.get(token).cloned();
        match issued {
            Some((g, false)) => Ok(g),
            Some((_, true)) => Err(PortError::Refused),
            None => self.oauth_grant(token, now).ok_or(PortError::Refused),
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
        if let Ok(c) = u64::try_from(client.raw())
            && let Some(o) = lock(&self.oauth).as_mut()
        {
            let n = o.server.revoke_agent_by_number(
                fstp_oauth::Account::from_raw(account.raw()),
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
        if let Some(o) = lock(&self.oauth).as_ref() {
            for g in o
                .server
                .agents_of(fstp_oauth::Account::from_raw(account.raw()), now.micros())
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
