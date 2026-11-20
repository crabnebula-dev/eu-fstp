//! The durable records of the authorisation server and their journal
//! (lane L2, ADR-013 amendment of 2026-11-20): R-MC-01, TH-61, I-79 and
//! H-21 at the level of the sans-IO server.
//!
//! A restart is modelled as the shell does it: every change the journal
//! gave is applied to a row set, and a new server is restored from those
//! rows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use fstp_oauth::{
    Account, AuthorizationServer, AuthorizeOutcome, Change, ClientNumber, ClientRecord, Config,
    ConsentAuth, FamilyRecord, GrantGuard, LoginMethod, RateKey, Records, RefreshHash, Reply,
    StepUpProof,
};

const ISSUER: &str = "https://cell-a.example";
const MCP: &str = "https://cell-a.example/mcp";
const REDIRECT: &str = "https://agent.example/cb";
const VERIFIER: &str = "records-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
/// An account id above `u64::MAX`, as the production cell draws them.
const ACCOUNT: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;

fn config() -> Config {
    Config::new(ISSUER, MCP, 43_200_000_000, 300_000_000)
}

/// The rows a shell holds, written from the journal as the cell writes
/// them: clients insert once, families replace a lower version only,
/// refresh hashes insert once, drops delete.
#[derive(Default)]
struct Rows {
    clients: BTreeMap<u64, ClientRecord>,
    families: BTreeMap<u64, FamilyRecord>,
    refresh: BTreeMap<[u8; 32], u64>,
}

impl Rows {
    fn apply(&mut self, changes: Vec<Change>) {
        for c in changes {
            match c {
                Change::Client(r) => {
                    self.clients.entry(r.number.raw()).or_insert(r);
                }
                Change::ClientDropped(n) => {
                    self.clients.remove(&n.raw());
                    let gone: Vec<u64> = self
                        .families
                        .values()
                        .filter(|f| f.client == n)
                        .map(|f| f.id)
                        .collect();
                    for f in gone {
                        self.drop_family(f);
                    }
                }
                Change::Family(r) => {
                    let newer = self
                        .families
                        .get(&r.id)
                        .is_none_or(|old| old.version < r.version);
                    if newer {
                        self.families.insert(r.id, r);
                    }
                }
                Change::FamilyDropped(f) => self.drop_family(f),
                Change::Refresh(h) => {
                    self.refresh.entry(h.hash).or_insert(h.family);
                }
            }
        }
    }

    fn drop_family(&mut self, f: u64) {
        self.families.remove(&f);
        self.refresh.retain(|_, fam| *fam != f);
    }

    fn records(&self) -> Records {
        Records {
            clients: self.clients.values().cloned().collect(),
            families: self.families.values().cloned().collect(),
            refresh: self
                .refresh
                .iter()
                .map(|(hash, family)| RefreshHash {
                    hash: *hash,
                    family: *family,
                })
                .collect(),
        }
    }
}

/// A server with its journal on, and the rows its changes went to.
struct Shell {
    s: AuthorizationServer,
    rows: Rows,
}

impl Shell {
    fn new() -> Shell {
        Shell {
            s: AuthorizationServer::new(config()).unwrap().with_journal(),
            rows: Rows::default(),
        }
    }

    fn flush(&mut self) {
        let changes = self.s.take_changes();
        self.rows.apply(changes);
    }

    /// A process restart: a new server from the rows only.
    fn restart(&mut self) -> usize {
        self.flush();
        let restored = AuthorizationServer::restore(config(), self.rows.records()).unwrap();
        self.s = restored.server;
        restored.dropped
    }
}

fn json_str(r: &Reply, key: &str) -> String {
    fstp_json::parse(&r.body)
        .ok()
        .and_then(|v| {
            v.get(key)
                .and_then(fstp_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn register(sh: &mut Shell, now: i64) -> String {
    let r = sh.s.register(
        RateKey::from_raw(1),
        br#"{"redirect_uris":["https://agent.example/cb"],"client_name":"Records agent"}"#,
        now,
    );
    assert_eq!(r.status, 201);
    sh.flush();
    json_str(&r, "client_id")
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    fstp_oauth::encode_form_urlencoded(pairs).into_bytes()
}

/// Consents for `account` at `now` and returns the code.
fn code(sh: &mut Shell, client: &str, account: u128, now: i64) -> String {
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let q = form(&[
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read creator:draft"),
        ("resource", MCP),
    ]);
    let AuthorizeOutcome::Consent(c) = sh.s.authorize(&q, now) else {
        panic!("no consent");
    };
    let auth = ConsentAuth {
        session: LoginMethod::Passkey,
        step_up: Some(StepUpProof {
            account: Account::from_raw(account),
            digest: c.digest,
            at: now,
            method: LoginMethod::Passkey,
        }),
    };
    let AuthorizeOutcome::Redirect(loc) =
        sh.s.approve(&c.handle, Account::from_raw(account), &auth, now)
    else {
        panic!("no redirect");
    };
    sh.flush();
    loc.split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned()
}

fn redeem(sh: &mut Shell, client: &str, code: &str, now: i64) -> Reply {
    let r = sh.s.token(
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", MCP),
        ]),
        now,
    );
    sh.flush();
    r
}

fn refresh(sh: &mut Shell, client: &str, token: &str, now: i64) -> Reply {
    let r = sh.s.token(
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", client),
        ]),
        now,
    );
    sh.flush();
    r
}

fn bearer(sh: &Shell, token: &str, now: i64) -> Result<fstp_oauth::Grant, Reply> {
    let h = format!("Bearer {token}");
    sh.s.authenticate(Some(h.as_bytes()), MCP, now)
}

/// A granted shell: a client, a family for [`ACCOUNT`], and its tokens.
fn granted(now: i64) -> (Shell, String, String, String) {
    let mut sh = Shell::new();
    let client = register(&mut sh, now);
    let c = code(&mut sh, &client, ACCOUNT, now);
    let r = redeem(&mut sh, &client, &c, now);
    assert_eq!(r.status, 200);
    let access = json_str(&r, "access_token");
    let refresh = json_str(&r, "refresh_token");
    (sh, client, access, refresh)
}

/// R-MC-01: after a restart from the rows, the client is known, its
/// refresh token rotates, and the new access token works. The access
/// token issued before the restart is gone, so the client refreshes.
#[test]
fn r_mc_01_refresh_after_restart_succeeds() {
    let (mut sh, client, access, refresh_token) = granted(10);
    assert!(bearer(&sh, &access, 11).is_ok());
    assert_eq!(sh.restart(), 0);
    assert_eq!(bearer(&sh, &access, 12).unwrap_err().status, 401);
    let r = refresh(&mut sh, &client, &refresh_token, 12);
    assert_eq!(r.status, 200, "refresh after restart");
    let g = bearer(&sh, &json_str(&r, "access_token"), 13).unwrap();
    assert_eq!(g.account, Account::from_raw(ACCOUNT));
    assert_eq!(g.client_id, client);
    assert_eq!(g.start, 10);
    assert_eq!(g.scopes.to_wire(), "calls:read creator:draft");
    assert_eq!(sh.s.agents_of(Account::from_raw(ACCOUNT), 13).len(), 1);
}

/// R-MC-01: a code minted before a restart is burned by it. Codes live in
/// memory only.
#[test]
fn r_mc_01_code_minted_before_restart_is_burned() {
    let mut sh = Shell::new();
    let client = register(&mut sh, 0);
    let c = code(&mut sh, &client, ACCOUNT, 0);
    sh.restart();
    let r = redeem(&mut sh, &client, &c, 1);
    assert_eq!(r.status, 400);
    assert_eq!(json_str(&r, "error"), "invalid_grant");
}

/// R-MC-01: a restart keeps the client, so the agent need not register
/// again, and a consent after the restart names the same client.
#[test]
fn r_mc_01_client_survives_restart() {
    let mut sh = Shell::new();
    let client = register(&mut sh, 0);
    let number = sh.s.client_number(&client).unwrap();
    sh.restart();
    assert_eq!(sh.s.client_number(&client), Some(number));
    let c = code(&mut sh, &client, ACCOUNT, 5);
    assert_eq!(redeem(&mut sh, &client, &c, 5).status, 200);
    let again = register(&mut sh, 6);
    assert!(sh.s.client_number(&again).unwrap().raw() > number.raw());
}

/// TH-61: presenting a retired refresh token after a restart revokes the
/// family, as before it. The retired hash is durable.
#[test]
fn th61_refresh_reuse_after_restart_revokes_family() {
    let (mut sh, client, _, first) = granted(0);
    let second = json_str(&refresh(&mut sh, &client, &first, 1), "refresh_token");
    sh.restart();
    let reuse = refresh(&mut sh, &client, &first, 2);
    assert_eq!(json_str(&reuse, "error"), "invalid_grant");
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &second, 3), "error"),
        "invalid_grant",
        "the family is revoked"
    );
    sh.restart();
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &second, 4), "error"),
        "invalid_grant",
        "the revocation is durable"
    );
    assert!(sh.s.agents_of(Account::from_raw(ACCOUNT), 4).is_empty());
}

/// R-MC-03: a revocation through RFC 7009 and through the agents page is
/// durable at once.
#[test]
fn r_mc_03_revocation_survives_restart() {
    let (mut sh, client, _, refresh_token) = granted(0);
    let r = sh.s.revoke(
        &form(&[
            ("token", refresh_token.as_str()),
            ("client_id", client.as_str()),
        ]),
        1,
    );
    assert_eq!(r.status, 200);
    sh.restart();
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &refresh_token, 2), "error"),
        "invalid_grant"
    );

    let (mut sh, client, _, refresh_token) = granted(0);
    let number = sh.s.client_number(&client).unwrap();
    assert_eq!(
        sh.s.revoke_agent_by_number(Account::from_raw(ACCOUNT), number, 1),
        1
    );
    sh.restart();
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &refresh_token, 2), "error"),
        "invalid_grant"
    );
}

/// TH-61, R-NF-02: no durable record holds a token, a code or a consent
/// handle. Every byte string of the records is checked for each value the
/// flow handed out, raw and as text.
#[test]
fn th61_records_hold_hashes_only() {
    let (mut sh, client, access, first) = granted(0);
    let rotated = refresh(&mut sh, &client, &first, 1);
    let mut secrets = vec![access, first];
    secrets.push(json_str(&rotated, "access_token"));
    secrets.push(json_str(&rotated, "refresh_token"));
    let c = code(&mut sh, &client, ACCOUNT, 2);
    secrets.push(c);
    sh.flush();
    let rec = sh.rows.records();
    let mut stored: Vec<Vec<u8>> = Vec::new();
    for cl in &rec.clients {
        stored.push(cl.client_id.as_bytes().to_vec());
        stored.push(cl.metadata.clone());
    }
    for f in &rec.families {
        stored.push(f.current.to_vec());
    }
    for r in &rec.refresh {
        stored.push(r.hash.to_vec());
    }
    for s in &secrets {
        let raw = fstp_oauth::decode_base64url(s.as_bytes()).unwrap();
        for b in &stored {
            assert!(
                !b.windows(s.len()).any(|w| w == s.as_bytes()),
                "a record holds a secret as text"
            );
            assert!(
                !b.windows(raw.as_bytes().len()).any(|w| w == raw.as_bytes()),
                "a record holds a secret's bytes"
            );
        }
    }
}

/// The guard of the account's last completed recovery (I-79).
struct Recovered(BTreeMap<u128, i64>);

impl GrantGuard for Recovered {
    fn refused(&self, account: Account, since: i64) -> bool {
        self.0.get(&account.raw()).is_some_and(|at| since <= *at)
    }
}

/// I-79, H-21: a family that started at or before the account's last
/// completed recovery is refused on every call: its access token, its
/// refresh, and after a restart too. A family started after it holds.
#[test]
fn i79_token_family_older_than_recovery_is_refused() {
    let (mut sh, client, access, refresh_token) = granted(10);
    let guard = Recovered([(ACCOUNT, 10)].into_iter().collect());
    let h = format!("Bearer {access}");
    assert_eq!(
        sh.s.authenticate_guarded(Some(h.as_bytes()), MCP, 11, &guard)
            .unwrap_err()
            .status,
        401
    );
    sh.restart();
    let body = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", client.as_str()),
    ]);
    let r = sh.s.token_guarded(&body, 12, &guard);
    assert_eq!(json_str(&r, "error"), "invalid_grant");
    sh.flush();
    sh.restart();
    assert_eq!(
        json_str(&sh.s.token(&body, 13), "error"),
        "invalid_grant",
        "the refused family stays revoked"
    );

    let c = code(&mut sh, &client, ACCOUNT, 20);
    let r = redeem(&mut sh, &client, &c, 20);
    let h = format!("Bearer {}", json_str(&r, "access_token"));
    assert!(
        sh.s.authenticate_guarded(Some(h.as_bytes()), MCP, 21, &guard)
            .is_ok(),
        "a family started after the recovery holds"
    );
}

/// I-79, H-21: a code issued at or before the recovery is burned at
/// redemption, though its family would start after it.
#[test]
fn i79_code_issued_before_recovery_is_burned() {
    let mut sh = Shell::new();
    let client = register(&mut sh, 0);
    let c = code(&mut sh, &client, ACCOUNT, 5);
    let guard = Recovered([(ACCOUNT, 5)].into_iter().collect());
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", c.as_str()),
        ("client_id", client.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", MCP),
    ]);
    let r = sh.s.token_guarded(&body, 6, &guard);
    assert_eq!(json_str(&r, "error"), "invalid_grant");
    assert_eq!(
        json_str(&sh.s.token(&body, 7), "error"),
        "invalid_grant",
        "the code is burned"
    );
}

/// I-79, H-21: the start sweep revokes every stored family the guard
/// refuses, durably, and leaves the others.
#[test]
fn h21_start_sweep_revokes_refused_families() {
    let (mut sh, client, _, refresh_token) = granted(0);
    let other = code(&mut sh, &client, 7, 0);
    let other = json_str(&redeem(&mut sh, &client, &other, 0), "refresh_token");
    sh.restart();
    let guard = Recovered([(ACCOUNT, 0)].into_iter().collect());
    assert_eq!(sh.s.revoke_refused(&guard), 1);
    sh.restart();
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &refresh_token, 1), "error"),
        "invalid_grant"
    );
    assert_eq!(refresh(&mut sh, &client, &other, 1).status, 200);
}

/// H-21, issue 6 M5: `revoke_all_agents` is durable.
#[test]
fn h21_revoke_all_agents_is_durable() {
    let (mut sh, client, _, refresh_token) = granted(0);
    assert_eq!(sh.s.revoke_all_agents(Account::from_raw(ACCOUNT), 1), 1);
    sh.restart();
    assert_eq!(
        json_str(&refresh(&mut sh, &client, &refresh_token, 2), "error"),
        "invalid_grant"
    );
}

/// Family rows: a change that commits late never replaces a later state.
/// The journal versions rise with every change.
#[test]
fn r_mc_01_family_versions_rise() {
    let (mut sh, client, _, first) = granted(0);
    let before = sh.rows.families.values().next().unwrap().clone();
    let _ = refresh(&mut sh, &client, &first, 1);
    let after = sh.rows.families.values().next().unwrap().clone();
    assert!(after.version > before.version);
    sh.rows.apply(vec![Change::Family(before)]);
    assert_eq!(sh.rows.families.values().next(), Some(&after));
}

/// The restore drops what does not hold and counts it: metadata that
/// does not decode, a family of no client, a refresh hash of no family.
#[test]
fn r_mc_01_restore_drops_records_that_do_not_hold() {
    let (mut sh, _, _, _) = granted(0);
    sh.flush();
    let mut rec = sh.rows.records();
    let fam = rec.families[0].clone();
    rec.clients.push(ClientRecord {
        number: ClientNumber::from_raw(99),
        client_id: "x".to_owned(),
        metadata: b"{".to_vec(),
        registered: 0,
    });
    rec.families.push(FamilyRecord {
        id: 50,
        client: ClientNumber::from_raw(98),
        ..fam
    });
    rec.refresh.push(RefreshHash {
        hash: [7; 32],
        family: 51,
    });
    let restored = AuthorizationServer::restore(config(), rec).unwrap();
    assert_eq!(restored.dropped, 3);
    assert_eq!(
        restored
            .server
            .agents_of(Account::from_raw(ACCOUNT), 1)
            .len(),
        1
    );
}

/// I-86, `agents.consent_request`: the view of a live consent names the
/// client, its unverified name, the redirect host and the scopes, and no
/// account. A handle the server does not hold, or an expired one, has
/// none.
#[test]
fn i86_consent_view_names_no_identity() {
    let mut sh = Shell::new();
    let client = register(&mut sh, 0);
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let q = form(&[
        ("response_type", "code"),
        ("client_id", client.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "calls:read"),
        ("resource", MCP),
    ]);
    let AuthorizeOutcome::Consent(c) = sh.s.authorize(&q, 0) else {
        panic!("no consent");
    };
    let v = sh.s.consent_view(&c.handle, 1).unwrap();
    assert_eq!(v.client, sh.s.client_number(&client).unwrap());
    assert_eq!(v.client_name.as_deref(), Some("Records agent"));
    assert_eq!(v.redirect_host, "agent.example");
    assert!(!v.loopback_redirect);
    assert_eq!(v.scopes.to_wire(), "calls:read");
    assert_eq!(v.expires, fstp_oauth::CONSENT_LIFETIME_MICROS);
    assert!(sh.s.consent_view("not-a-handle", 1).is_none());
    assert!(
        sh.s.consent_view(&c.handle, fstp_oauth::CONSENT_LIFETIME_MICROS)
            .is_none()
    );
}
