//! The pure rules of anonymous drafts (ADR-032, Daniel 2026-11-22):
//! the resume token, the draft text, the lifetime and the in-memory
//! store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_core::anon::{
    AnonymousDrafts, Draft, LIFETIME_US, MAX_NARRATIVE, MAX_SUMMARY, MAX_TITLE,
    MemoryAnonymousDrafts, Row, TOKEN_BYTES, Token, expires_at, is_live,
};
use fstp_domain::id::CallId;
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check};

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("the memory store never waits"),
    }
}

fn token(g: &mut Gen) -> Token {
    let b = g.bytes(TOKEN_BYTES..=TOKEN_BYTES);
    Token::from_bytes(b.try_into().unwrap())
}

fn text(g: &mut Gen, max: usize) -> String {
    let mut s = String::new();
    let n = g.usize_in(0..=40);
    for _ in 0..n {
        let c = match g.usize_in(0..=3) {
            0 => '\n',
            1 => g.ascii_char(),
            _ => g.char(),
        };
        let c = if c.is_control() && c != '\n' { 'x' } else { c };
        let c = if matches!(c, '\u{2028}' | '\u{2029}') {
            'y'
        } else {
            c
        };
        if s.len() + c.len_utf8() > max {
            break;
        }
        s.push(c);
    }
    s
}

fn draft(g: &mut Gen) -> Draft {
    Draft {
        title: text(g, MAX_TITLE),
        summary: text(g, MAX_SUMMARY),
        narrative: text(g, MAX_NARRATIVE),
    }
}

/// ADR-032, R-NF-02: a token survives its link spelling, its `Debug`
/// prints no byte, and the digest the store keeps is its SHA-256, never
/// the token.
#[test]
fn adr032_r_nf_02_token_round_trips_and_never_prints() {
    check("adr032_r_nf_02_token_round_trips_and_never_prints", |g| {
        let t = token(g);
        let hex = t.hex();
        if hex.len() != 64 || Token::parse(&hex) != Some(t.clone()) {
            return Err(format!("round trip failed for {hex}"));
        }
        if format!("{t:?}") != "Token(..)" || format!("{t:?}").contains(&hex[..8]) {
            return Err("Debug shows the token".to_owned());
        }
        let d = t.digest();
        if d.to_vec() == fstp_crypto::sha256(&hex_bytes(&hex)).to_vec() && d.len() == 32 {
            Ok(())
        } else {
            Err("the digest is not the SHA-256 of the token".to_owned())
        }
    });
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// ADR-032: only 64 lowercase hexadecimal characters spell a token.
#[test]
fn adr032_token_refuses_every_other_spelling() {
    let good = "ab".repeat(32);
    assert!(Token::parse(&good).is_some());
    for bad in [
        String::new(),
        "ab".repeat(31),
        "ab".repeat(33),
        "AB".repeat(32),
        format!("{}g0", "ab".repeat(31)),
        format!("{} ", "ab".repeat(31)),
        format!("+{}", &"ab".repeat(32)[1..]),
    ] {
        assert!(Token::parse(&bad).is_none(), "{bad:?}");
    }
    let a = Token::fresh().unwrap();
    let b = Token::fresh().unwrap();
    assert_ne!(a, b, "two fresh tokens differ");
}

/// ADR-032, R-SB-01: a draft within the workspace limits survives its
/// sealed encoding, and the encoding holds the three sections only.
#[test]
fn adr032_r_sb_01_draft_round_trips_within_limits() {
    check("adr032_r_sb_01_draft_round_trips_within_limits", |g| {
        let d = draft(g);
        let bytes = d.encode().ok_or("a fitting draft does not encode")?;
        match Draft::decode(&bytes) {
            Some(back) if back == d => Ok(()),
            other => Err(format!("decoded {other:?}")),
        }
    });
}

/// ADR-032: a section over its limit, a control character other than tab
/// and line breaks, a line separator and any extra member are refused.
#[test]
fn adr032_draft_outside_the_rules_is_refused() {
    let over = [
        Draft {
            title: "t".repeat(MAX_TITLE + 1),
            ..Draft::default()
        },
        Draft {
            summary: "s".repeat(MAX_SUMMARY + 1),
            ..Draft::default()
        },
        Draft {
            narrative: "n".repeat(MAX_NARRATIVE + 1),
            ..Draft::default()
        },
        Draft {
            title: "a\u{7}b".to_owned(),
            ..Draft::default()
        },
        Draft {
            narrative: "a\u{2028}b".to_owned(),
            ..Draft::default()
        },
    ];
    for d in over {
        assert!(!d.fits(), "{d:?}");
        assert!(d.encode().is_none(), "{d:?}");
    }
    let ok = Draft {
        title: "Synthetic title".to_owned(),
        summary: "Line one\r\nLine two\tend".to_owned(),
        narrative: "Synthetic narrative\n".to_owned(),
    };
    assert!(ok.fits());
    for bad in [
        &br#"{"narrative":"","summary":"","title":"","name":"x"}"#[..],
        br#"{"narrative":"","summary":""}"#,
        br#"{"narrative":"","summary":"","title":"a\u0007"}"#,
        br#"[]"#,
        b"",
    ] {
        assert!(
            Draft::decode(bad).is_none(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// ADR-032 (Daniel 2026-11-22, open point 3): a draft expires 30 days
/// after its start, or at its call's deadline if that is earlier. It is
/// live strictly before that instant and never after.
#[test]
fn adr032_lifetime_is_30_days_or_the_deadline() {
    check("adr032_lifetime_is_30_days_or_the_deadline", |g| {
        let start = g.i64_in(0..=4_000_000_000_000_000);
        let deadline = g.i64_in(0..=4_100_000_000_000_000);
        let e = expires_at(
            Timestamp::from_micros(start),
            Timestamp::from_micros(deadline),
        );
        let want = (start + LIFETIME_US).min(deadline);
        if e.micros() != want {
            return Err(format!("expires {} want {want}", e.micros()));
        }
        let live_before = want == i64::MIN || is_live(e, Timestamp::from_micros(want - 1));
        if !live_before || is_live(e, e) || is_live(e, Timestamp::from_micros(want + 1)) {
            return Err("liveness is wrong around the expiry".to_owned());
        }
        Ok(())
    });
    assert_eq!(LIFETIME_US, 30 * 24 * 3_600 * 1_000_000);
}

fn row(call: u128, started: i64, expires: i64) -> Row {
    Row {
        call: CallId::from_raw(call),
        draft: Draft {
            title: "Synthetic".to_owned(),
            ..Draft::default()
        },
        started: Timestamp::from_micros(started),
        expires: Timestamp::from_micros(expires),
    }
}

/// ADR-032, I-21: the store answers a draft only to its token's digest,
/// never serves an expired draft, refuses a digest in use, and its sweep
/// deletes exactly the expired drafts.
#[test]
fn adr032_i21_memory_store_serves_live_drafts_by_digest_only() {
    check(
        "adr032_i21_memory_store_serves_live_drafts_by_digest_only",
        |g| {
            let s = MemoryAnonymousDrafts::new();
            let now = 1_000_000_000_i64;
            let n = g.usize_in(1..=12);
            let mut live = 0u64;
            let mut tokens = Vec::new();
            for i in 0..n {
                let t = token(g);
                let expires = now + g.i64_in(-5..=5);
                if expires > now {
                    live += 1;
                }
                block(s.start(t.digest(), row(7, 0, expires)))
                    .map_err(|e| format!("start {i}: {e:?}"))?;
                if block(s.start(t.digest(), row(7, 0, expires))).is_ok() {
                    return Err("a digest in use was taken again".to_owned());
                }
                tokens.push((t, expires));
            }
            let at = Timestamp::from_micros(now);
            if block(s.live(at)).unwrap() != live {
                return Err("live count".to_owned());
            }
            for (t, expires) in &tokens {
                let got = block(s.open(t.digest(), at)).unwrap();
                if got.is_some() != (*expires > now) {
                    return Err(format!("open at expiry {expires}"));
                }
                let saved = block(s.save(t.digest(), Draft::default(), at)).unwrap();
                if saved != (*expires > now) {
                    return Err("save of an expired draft".to_owned());
                }
            }
            let other = token(g);
            if block(s.open(other.digest(), at)).unwrap().is_some() {
                return Err("an unknown digest opened a draft".to_owned());
            }
            let swept = block(s.sweep(at)).unwrap();
            if swept != n as u64 - live || s.len() as u64 != live {
                return Err(format!("swept {swept}, left {}", s.len()));
            }
            Ok(())
        },
    );
}

/// ADR-032: after a removal the token opens nothing, so a claimed or
/// discarded draft's link stops working.
#[test]
fn adr032_removed_draft_never_opens_again() {
    let s = MemoryAnonymousDrafts::new();
    let t = Token::fresh().unwrap();
    block(s.start(t.digest(), row(1, 0, i64::MAX))).unwrap();
    let at = Timestamp::from_micros(10);
    assert!(block(s.open(t.digest(), at)).unwrap().is_some());
    assert!(block(s.remove(t.digest())).unwrap());
    assert!(block(s.open(t.digest(), at)).unwrap().is_none());
    assert!(!block(s.save(t.digest(), Draft::default(), at)).unwrap());
    assert!(!block(s.remove(t.digest())).unwrap());
}
