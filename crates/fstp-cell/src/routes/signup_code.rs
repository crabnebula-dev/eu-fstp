//! The typed registration code (Daniel, 2026-11-22, ADR-008
//! "Registration code").
//!
//! The registration email carries the link and a 6-digit code. Either
//! completes the registration. The code is a function of the proof token
//! (`fstp_auth::ceremony::signup_code`), so both name the same proof.
//!
//! [`CodeBook`] keeps, per address digest, only:
//!
//! - an HMAC-SHA-256 of the code under a key drawn when the book is made,
//!   so the code is never kept in the clear;
//! - the proof token and its issue instant, in process memory, as the
//!   pending sign-up address already is (`crate::routes::pg`, interim).
//!   A restart loses the code, and the link still works.
//!
//! The rules:
//!
//! - one live code per address: a new sign-up request replaces it;
//! - it expires with the proof (`SIGNUP_PROOF_US`, 15 minutes);
//! - it is compared in constant time and is single use;
//! - a code allows [`ATTEMPTS_PER_CODE`] wrong attempts, then it is dead;
//! - an address allows [`FAILURES_PER_ADDRESS`] wrong attempts an hour,
//!   across its codes, unknown addresses included;
//! - every refusal looks the same, so the answer tells nothing about the
//!   address.
//!
//! [`decode_signup_code`] reads `POST /auth/signup/code` bodies. Fuzzed
//! (`signup_code_decode`).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use fstp_auth::ceremony::{SIGNUP_CODE_DIGITS, parse_signup_code};

use crate::http::body::{self, BodyRefusal};

/// Wrong attempts one code allows before it is dead.
pub const ATTEMPTS_PER_CODE: u8 = 5;

/// Wrong attempts one address allows within [`FAILURE_WINDOW_US`].
pub const FAILURES_PER_ADDRESS: usize = 10;

/// The window of [`FAILURES_PER_ADDRESS`]: one hour.
pub const FAILURE_WINDOW_US: i64 = 3_600_000_000;

/// The most addresses the book holds. At the bound, expired entries are
/// swept, and a new code past it is not kept (the link still works).
const MAX_ENTRIES: usize = 65_536;

/// The longest body of `POST /auth/signup/code`.
pub const CODE_BODY_LIMIT: usize = 1024;

/// The longest address.
const MAX_EMAIL: usize = 254;

/// Decodes `{"code":"<6 digits>","email":"<address>"}`. Fuzzed
/// (`signup_code_decode`).
///
/// # Errors
///
/// The first [`BodyRefusal`] that applies.
pub fn decode_signup_code(bytes: &[u8]) -> Result<(String, [u8; SIGNUP_CODE_DIGITS]), BodyRefusal> {
    let o = body::object(bytes, CODE_BODY_LIMIT)?;
    body::members(&o, &["code", "email"], &[])?;
    let code = parse_signup_code(body::string(&o, "code")?).ok_or(BodyRefusal::Member("code"))?;
    let email = body::string(&o, "email")?;
    if email.is_empty() || email.len() > MAX_EMAIL || !email.contains('@') {
        return Err(BodyRefusal::Member("email"));
    }
    Ok((email.to_owned(), code))
}

struct Entry {
    mac: [u8; 32],
    token: [u8; 32],
    issued_at: i64,
    wrong: u8,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<[u8; 32], Entry>,
    failures: BTreeMap<[u8; 32], VecDeque<i64>>,
}

/// The live codes of one cell front (module documentation).
pub(crate) struct CodeBook {
    key: [u8; 32],
    lifetime_us: i64,
    state: Mutex<State>,
}

impl CodeBook {
    /// A book whose codes live `lifetime_us`, under a key drawn now. With
    /// no random source the key is a fixed one, and the book keeps
    /// nothing, so only the link works.
    pub(crate) fn new(lifetime_us: i64) -> CodeBook {
        let key = fstp_crypto::random_array::<32>().ok();
        CodeBook {
            key: key.unwrap_or([0; 32]),
            lifetime_us: if key.is_some() { lifetime_us } else { 0 },
            state: Mutex::default(),
        }
    }

    fn mac(&self, code: &[u8; SIGNUP_CODE_DIGITS]) -> [u8; 32] {
        fstp_crypto::hmac_sha256(&self.key, code)
    }

    /// Keeps the code of `token` for the address digest `address`,
    /// replacing any earlier code of that address.
    pub(crate) fn issue(&self, address: [u8; 32], token: [u8; 32], now_us: i64) {
        let code = fstp_auth::ceremony::signup_code(&token);
        let mac = self.mac(&code);
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.entries.len() >= MAX_ENTRIES {
            let lifetime = self.lifetime_us;
            st.entries
                .retain(|_, e| now_us.saturating_sub(e.issued_at) < lifetime);
            if st.entries.len() >= MAX_ENTRIES && !st.entries.contains_key(&address) {
                return;
            }
        }
        st.entries.insert(
            address,
            Entry {
                mac,
                token,
                issued_at: now_us,
                wrong: 0,
            },
        );
    }

    /// The proof token of the live code `code` of `address`, once. Any
    /// other case answers `None` and counts as a wrong attempt.
    pub(crate) fn redeem(
        &self,
        address: [u8; 32],
        code: &[u8; SIGNUP_CODE_DIGITS],
        now_us: i64,
    ) -> Option<[u8; 32]> {
        let given = self.mac(code);
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let from = now_us.saturating_sub(FAILURE_WINDOW_US);
        let failed = st.failures.entry(address).or_default();
        while failed.front().is_some_and(|t| *t <= from) {
            failed.pop_front();
        }
        let locked = failed.len() >= FAILURES_PER_ADDRESS;
        let lifetime = self.lifetime_us;
        let outcome = match st.entries.get_mut(&address) {
            Some(e)
                if !locked
                    && e.wrong < ATTEMPTS_PER_CODE
                    && now_us.saturating_sub(e.issued_at) < lifetime
                    && now_us >= e.issued_at =>
            {
                if fstp_crypto::constant_time_eq(&e.mac, &given) {
                    Some(e.token)
                } else {
                    e.wrong = e.wrong.saturating_add(1);
                    None
                }
            }
            _ => None,
        };
        match outcome {
            Some(token) => {
                st.entries.remove(&address);
                Some(token)
            }
            None => {
                if !locked {
                    st.failures.entry(address).or_default().push_back(now_us);
                }
                if st.failures.len() > MAX_ENTRIES {
                    st.failures
                        .retain(|_, q| q.back().is_some_and(|t| *t > from));
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIFE: i64 = 900_000_000;
    const T: [u8; 32] = [7; 32];
    const A: [u8; 32] = [1; 32];

    fn code() -> [u8; 6] {
        fstp_auth::ceremony::signup_code(&T)
    }

    fn wrong() -> [u8; 6] {
        let mut c = code();
        c[5] = if c[5] == b'9' {
            b'0'
        } else {
            c[5].saturating_add(1)
        };
        c
    }

    /// ADR-008 "Registration code": the right code answers the token once,
    /// and only for its own address.
    #[test]
    fn adr008_code_redeems_once_for_its_address() {
        let b = CodeBook::new(LIFE);
        b.issue(A, T, 10);
        assert_eq!(b.redeem([2; 32], &code(), 11), None);
        assert_eq!(b.redeem(A, &code(), 11), Some(T));
        assert_eq!(b.redeem(A, &code(), 12), None, "single use");
    }

    /// ADR-008: a code expires with the proof.
    #[test]
    fn adr008_code_expires_with_the_proof() {
        let b = CodeBook::new(LIFE);
        b.issue(A, T, 10);
        assert_eq!(b.redeem(A, &code(), 10 + LIFE), None);
    }

    /// ADR-008: five wrong attempts kill a code, even for the right code
    /// after them.
    #[test]
    fn adr008_code_dies_after_five_wrong_attempts() {
        let b = CodeBook::new(LIFE);
        b.issue(A, T, 10);
        for i in 0..ATTEMPTS_PER_CODE {
            assert_eq!(b.redeem(A, &wrong(), 11 + i64::from(i)), None);
        }
        assert_eq!(b.redeem(A, &code(), 20), None);
    }

    /// ADR-008: an address allows ten wrong attempts an hour across its
    /// codes. A new code does not reset the count, and it recovers after
    /// the hour.
    #[test]
    fn adr008_address_allows_ten_wrong_attempts_an_hour() {
        let b = CodeBook::new(LIFE);
        for round in 0..2i64 {
            b.issue(A, T, round * 10);
            for i in 0..5i64 {
                assert_eq!(b.redeem(A, &wrong(), round * 10 + i + 1), None);
            }
        }
        b.issue(A, T, 100);
        assert_eq!(b.redeem(A, &code(), 101), None, "the address is locked");
        b.issue(A, T, FAILURE_WINDOW_US + 200);
        assert_eq!(b.redeem(A, &code(), FAILURE_WINDOW_US + 201), Some(T));
    }

    /// ADR-008, TH-26: the body takes exactly a 6-digit code and an
    /// address, in canonical JSON.
    #[test]
    fn adr008_th26_code_body_decodes_strictly() {
        let ok = br#"{"code":"012345","email":"a@example.test"}"#;
        let (email, c) = decode_signup_code(ok).unwrap();
        assert_eq!((email.as_str(), &c), ("a@example.test", b"012345"));
        for bad in [
            &br#"{"code":"12345","email":"a@example.test"}"#[..],
            br#"{"code":12345,"email":"a@example.test"}"#,
            br#"{"code":"012345","email":"nobody"}"#,
            br#"{"code":"012345","email":"a@example.test","x":"1"}"#,
            br#"{"email":"a@example.test","code":"012345"}"#,
            br#"{"code":"012345","email":"a@example.test","minor":true}"#,
        ] {
            assert!(
                decode_signup_code(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
