//! Fuzz target `server_requests` of `fstp-oauth` (TH-26, H-05, M4 design
//! section 9, ADR-013).
//!
//! Design checks: the endpoints behind the decoders never panic, answer
//! only the statuses of the profile, and give JSON or empty bodies. The
//! input is a program: each step is an opcode byte, a length byte and that
//! many payload bytes. Some opcodes send the payload to an endpoint. Others
//! drive a real flow (consent, exchange, refresh, revocation, a clock move)
//! so the fuzzer reaches rotation and reuse. A granted token is always
//! bound to the MCP URL, no token works after its agent is ended, and the
//! authorisation endpoint never redirects before the user acts (TW-4).

#![no_main]

use fstp_oauth::{
    Account, AuthorizationServer, AuthorizeOutcome, Config, ConsentAuth, LoginMethod, RateKey,
    Reply, StepUpProof,
};
use libfuzzer_sys::fuzz_target;

const ISSUER: &str = "https://cell-a.example";
const MCP: &str = "https://cell-a.example/mcp";
const REDIRECT: &str = "https://agent.example/cb";
const VERIFIER: &str = "fuzz-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

fn check_reply(r: &Reply) {
    assert!(
        [200, 201, 400, 401, 403, 429, 500, 503].contains(&r.status),
        "status {}",
        r.status
    );
    if !r.body.is_empty() {
        assert!(fstp_json::parse(&r.body).is_ok(), "a body is not JSON");
    }
}

/// TW-4: the authorisation endpoint never redirects before the user acts.
fn assert_no_redirect(o: &AuthorizeOutcome) {
    assert!(
        !matches!(o, AuthorizeOutcome::Redirect(_)),
        "the authorisation endpoint redirected before the user acted"
    );
}

fn json_str(r: &Reply, key: &str) -> Option<String> {
    fstp_json::parse(&r.body)
        .ok()?
        .get(key)?
        .as_str()
        .map(str::to_owned)
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    fstp_oauth::encode_form_urlencoded(pairs).into_bytes()
}

struct World {
    s: AuthorizationServer,
    client: String,
    now: i64,
    consent: Option<fstp_oauth::ConsentRequest>,
    code: Option<String>,
    refresh: Vec<String>,
    access: Vec<String>,
    dead_refresh: Vec<String>,
    dead_access: Vec<String>,
}

impl World {
    fn new() -> Option<World> {
        let mut s =
            AuthorizationServer::new(Config::new(ISSUER, MCP, 43_200_000_000, 300_000_000)).ok()?;
        let r = s.register(
            RateKey::from_raw(0),
            br#"{"redirect_uris":["https://agent.example/cb","http://127.0.0.1/cb"]}"#,
            0,
        );
        let client = json_str(&r, "client_id")?;
        Some(World {
            s,
            client,
            now: 0,
            consent: None,
            code: None,
            refresh: Vec::new(),
            access: Vec::new(),
            dead_refresh: Vec::new(),
            dead_access: Vec::new(),
        })
    }

    fn outcome(&mut self, o: AuthorizeOutcome) {
        match o {
            AuthorizeOutcome::Consent(c) => self.consent = Some(c),
            AuthorizeOutcome::Redirect(loc) => {
                assert!(loc.starts_with(REDIRECT) || loc.starts_with("http://127.0.0.1"));
                if let Some(code) = loc.split(['?', '&']).find_map(|p| p.strip_prefix("code=")) {
                    self.code = Some(code.to_owned());
                }
            }
            AuthorizeOutcome::Refused(r) => check_reply(&r),
        }
    }

    fn tokens(&mut self, r: &Reply) {
        check_reply(r);
        if r.status == 200 {
            let access = json_str(r, "access_token");
            let refresh = json_str(r, "refresh_token");
            let (Some(a), Some(t)) = (access, refresh) else {
                panic!("a 200 token reply lacks a token");
            };
            self.access.push(a);
            self.refresh.push(t);
        }
    }

    fn step(&mut self, op: u8, payload: &[u8]) {
        let pick = |v: &[String]| -> Option<String> {
            let i = usize::from(payload.first().copied().unwrap_or(0));
            if v.is_empty() {
                None
            } else {
                v.get(i % v.len()).cloned()
            }
        };
        match op % 12 {
            0 => check_reply(&self.s.register(RateKey::from_raw(1), payload, self.now)),
            1 => {
                let o = self.s.authorize(payload, self.now);
                assert_no_redirect(&o);
                self.outcome(o);
            }
            2 => {
                let r = self.s.token(payload, self.now);
                self.tokens(&r);
            }
            3 => check_reply(&self.s.revoke(payload, self.now)),
            4 => match self.s.authenticate(Some(payload), MCP, self.now) {
                Ok(g) => assert_eq!(g.audience, MCP),
                Err(r) => check_reply(&r),
            },
            5 => {
                let challenge =
                    fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
                let state = String::from_utf8_lossy(payload).into_owned();
                let q = form(&[
                    ("response_type", "code"),
                    ("client_id", &self.client),
                    ("redirect_uri", REDIRECT),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                    ("scope", "calls:read calls:draft"),
                    ("resource", MCP),
                    ("state", &state),
                ]);
                let o = self.s.authorize(&q, self.now);
                assert_no_redirect(&o);
                self.outcome(o);
            }
            6 => {
                if let Some(c) = self.consent.clone() {
                    let flags = payload.first().copied().unwrap_or(0);
                    let strong = |bit: u8| {
                        if flags & bit == 0 {
                            LoginMethod::Passkey
                        } else {
                            LoginMethod::MagicLink
                        }
                    };
                    let auth = ConsentAuth {
                        session: strong(1),
                        step_up: (flags & 2 == 0).then_some(StepUpProof {
                            account: Account::from_raw(7),
                            digest: c.digest,
                            at: self.now - i64::from(flags >> 4) * 30_000_000,
                            method: strong(4),
                        }),
                    };
                    let o = self
                        .s
                        .approve(&c.handle, Account::from_raw(7), &auth, self.now);
                    self.outcome(o);
                }
            }
            7 => {
                if let Some(code) = self.code.clone() {
                    let verifier = if payload.first().is_some_and(|b| b & 1 == 1) {
                        "fuzz-verifier-wrong-0123456789abcdefghijklmnopqrstuv"
                    } else {
                        VERIFIER
                    };
                    let body = form(&[
                        ("grant_type", "authorization_code"),
                        ("code", &code),
                        ("client_id", &self.client),
                        ("redirect_uri", REDIRECT),
                        ("code_verifier", verifier),
                        ("resource", MCP),
                    ]);
                    let r = self.s.token(&body, self.now);
                    self.tokens(&r);
                }
            }
            8 => {
                let dead = payload.get(1).is_some_and(|b| b & 1 == 1);
                let pool = if dead {
                    &self.dead_refresh
                } else {
                    &self.refresh
                };
                if let Some(t) = pick(pool) {
                    let body = form(&[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &t),
                        ("client_id", &self.client),
                    ]);
                    let r = self.s.token(&body, self.now);
                    assert!(
                        !dead || r.status != 200,
                        "a refresh token works after its agent was ended"
                    );
                    self.tokens(&r);
                }
            }
            9 => {
                let dead = payload.get(1).is_some_and(|b| b & 1 == 1);
                let pool = if dead {
                    &self.dead_access
                } else {
                    &self.access
                };
                if let Some(t) = pick(pool) {
                    let header = format!("Bearer {t}");
                    match self.s.authenticate(Some(header.as_bytes()), MCP, self.now) {
                        Ok(g) => {
                            assert!(!dead, "an access token works after its agent was ended");
                            assert_eq!(g.audience, MCP);
                        }
                        Err(r) => check_reply(&r),
                    }
                }
            }
            10 => {
                if let Some(t) = pick(&self.refresh) {
                    let body = form(&[("token", &t), ("client_id", &self.client)]);
                    check_reply(&self.s.revoke(&body, self.now));
                }
            }
            _ => {
                let b = payload.first().copied().unwrap_or(0);
                if b == 0xff {
                    self.s
                        .revoke_agent(Account::from_raw(7), &self.client, self.now);
                    self.dead_refresh.append(&mut self.refresh);
                    self.dead_access.append(&mut self.access);
                    self.code = None;
                } else if b == 0xfe {
                    self.s.purge(self.now);
                } else {
                    self.now = self.now.saturating_add(i64::from(b) * 10_000_000);
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(mut w) = World::new() else {
        return;
    };
    let mut rest = data;
    let mut steps = 0usize;
    while let [op, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (payload, next) = tail.split_at(n);
        w.step(*op, payload);
        rest = next;
        steps += 1;
        if steps >= 64 {
            break;
        }
    }
});
