//! I-78 over the lane W2b production API: the action digest, the
//! challenge, P-71, the step-up rule and the step-up ceremony (ADR-008
//! "Step-up", design section 8.4).
//!
//! Lane W2b implementer. The oracle is written from ADR-008, not from the
//! production predicate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod passkey;

use fstp_auth::stepup::{
    P71_DEFAULT_US, PolicyDeny, StepUp, StepUpDeny, StepUpRequest, action_digest, admit_step_up,
    challenge, consumption, effective_p71, validate_p71, verify_step_up,
};
use fstp_auth::{AuthRecord, Method, SessionView};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_prop::{Gen, check, prop_assert_eq};

const NOW: Timestamp = Timestamp::from_micros(1_700_000_000_000_000);

fn session(method: Method) -> SessionView {
    SessionView {
        id: [0x5E; 16],
        account: AccountId::from_raw(1),
        method,
        started: NOW,
        last_used: NOW,
    }
}

fn fresh(digest: [u8; 32]) -> StepUp {
    StepUp {
        id: [0x51; 16],
        session: [0x5E; 16],
        action_digest: digest,
        asserted_at: NOW,
        method: Method::Passkey,
        uv: true,
        consumed: false,
    }
}

/// I-78, ADR-008: the action digest is SHA-256 over the canonical command
/// followed by the command id, so another id gives another digest.
#[test]
fn i78_action_digest_binds_the_command_and_its_id() {
    let cmd = br#"{"type":"ReleasePayment"}"#;
    let mut input = cmd.to_vec();
    input.extend_from_slice(&[7; 16]);
    assert_eq!(action_digest(cmd, [7; 16]), fstp_crypto::sha256(&input));
    assert_ne!(action_digest(cmd, [7; 16]), action_digest(cmd, [8; 16]));
}

/// I-78, ADR-008: the challenge binds the prefix, cell, session, digest
/// and nonce, each of fixed length.
#[test]
fn i78_challenge_binds_cell_session_digest_and_nonce() {
    let mut input = b"fstp-stepup-v1".to_vec();
    for part in [&[1u8; 16][..], &[2; 16], &[3; 32], &[4; 32]] {
        input.extend_from_slice(part);
    }
    let c = challenge([1; 16], [2; 16], [3; 32], [4; 32]);
    assert_eq!(c, fstp_crypto::sha256(&input));
    assert_ne!(c, challenge([9; 16], [2; 16], [3; 32], [4; 32]));
    assert_ne!(c, challenge([1; 16], [9; 16], [3; 32], [4; 32]));
    assert_ne!(c, challenge([1; 16], [2; 16], [9; 32], [4; 32]));
    assert_ne!(c, challenge([1; 16], [2; 16], [3; 32], [9; 32]));
}

/// I-78, P-71: a tenant value may only shorten freshness.
#[test]
fn i78_effective_p71_only_shortens() {
    check("i78_effective_p71_only_shortens", |g: &mut Gen| {
        let v = g.i64();
        let got = effective_p71(v);
        let want = if v > 0 && v <= P71_DEFAULT_US {
            v
        } else {
            P71_DEFAULT_US
        };
        prop_assert_eq!(got, want, "tenant value {v}");
        Ok(())
    });
}

/// I-78, P-71: `SetLoginPolicy` refuses a longer or a non-positive P-71.
#[test]
fn i78_set_login_policy_refuses_a_longer_p71() {
    assert_eq!(validate_p71(P71_DEFAULT_US), Ok(()));
    assert_eq!(validate_p71(1), Ok(()));
    assert_eq!(validate_p71(P71_DEFAULT_US + 1), Err(PolicyDeny::P71Longer));
    assert_eq!(validate_p71(0), Err(PolicyDeny::P71NotPositive));
    assert_eq!(validate_p71(i64::MIN), Err(PolicyDeny::P71NotPositive));
}

/// I-78: a step-up exactly P-71 old admits; one microsecond older or
/// dated after now refuses as stale.
#[test]
fn i78_step_up_freshness_is_inclusive_at_p71() {
    let d = [0xD1; 32];
    let s = session(Method::Passkey);
    let at = |age: i64| StepUp {
        asserted_at: Timestamp::from_micros(NOW.micros() - age),
        ..fresh(d)
    };
    let admit = |u: &StepUp| admit_step_up(&s, d, Some(u), NOW, P71_DEFAULT_US);
    assert_eq!(admit(&at(P71_DEFAULT_US)), Ok(()));
    assert_eq!(admit(&at(P71_DEFAULT_US + 1)), Err(StepUpDeny::Stale));
    assert_eq!(admit(&at(-1)), Err(StepUpDeny::Stale));
}

/// I-78, ADR-008: each condition of the step-up rule refuses on its own.
#[test]
fn i78_each_step_up_condition_refuses() {
    let d = [0xD1; 32];
    let s = session(Method::Passkey);
    let admit = |s: &SessionView, u: Option<&StepUp>| admit_step_up(s, d, u, NOW, P71_DEFAULT_US);
    assert_eq!(admit(&s, Some(&fresh(d))), Ok(()));
    assert_eq!(
        admit(&session(Method::MagicLink), Some(&fresh(d))),
        Err(StepUpDeny::MagicLinkSession)
    );
    assert_eq!(admit(&s, None), Err(StepUpDeny::Required));
    let cases = [
        (
            StepUp {
                session: [0; 16],
                ..fresh(d)
            },
            StepUpDeny::OtherSession,
        ),
        (fresh([0xD2; 32]), StepUpDeny::OtherCommand),
        (
            StepUp {
                method: Method::MagicLink,
                ..fresh(d)
            },
            StepUpDeny::WeakMethod,
        ),
        (
            StepUp {
                uv: false,
                ..fresh(d)
            },
            StepUpDeny::NoUserVerification,
        ),
        (
            StepUp {
                consumed: true,
                ..fresh(d)
            },
            StepUpDeny::Consumed,
        ),
    ];
    for (u, want) in cases {
        assert_eq!(admit(&s, Some(&u)), Err(want), "{u:?}");
    }
}

/// I-78: the step-up rule admits exactly a fresh, unused, verified
/// passkey step-up of this session for this digest, in a strong session.
#[test]
fn i78_admit_step_up_matches_the_adr008_rule() {
    check(
        "i78_admit_step_up_matches_the_adr008_rule",
        |g: &mut Gen| {
            let d = [0xD1; 32];
            let s = session(*g.pick(&Method::ALL));
            let u = g.option(|g| StepUp {
                id: [0x51; 16],
                session: *g.pick(&[[0x5E; 16], [0; 16]]),
                action_digest: *g.pick(&[d, [0xD2; 32]]),
                asserted_at: Timestamp::from_micros(
                    NOW.micros() - g.i64_in(-2..=P71_DEFAULT_US + 2),
                ),
                method: *g.pick(&Method::ALL),
                uv: g.bool(),
                consumed: g.bool(),
            });
            let p71 = g.i64_in(-1..=2 * P71_DEFAULT_US);
            let want = s.method.phishing_resistant()
                && u.is_some_and(|u| {
                    let age = NOW.micros() - u.asserted_at.micros();
                    u.session == s.id
                        && u.action_digest == d
                        && u.method.phishing_resistant()
                        && u.uv
                        && (0..=effective_p71(p71)).contains(&age)
                        && !u.consumed
                });
            let got = admit_step_up(&s, d, u.as_ref(), NOW, p71);
            prop_assert_eq!(got.is_ok(), want, "{s:?} {u:?} p71 {p71}");
            Ok(())
        },
    );
}

fn request() -> StepUpRequest {
    StepUpRequest {
        id: [0x51; 16],
        cell: [0xCE; 16],
        action_digest: [0xD1; 32],
        nonce: [0x0A; 32],
        rp: passkey::rp(),
    }
}

/// I-78, ADR-008: a step-up assertion with user verification over the
/// challenge records `StepUpGranted` with its action digest.
#[test]
fn i78_step_up_logged_with_its_action_digest() {
    let key = passkey::Passkey::new(5);
    let s = session(Method::Passkey);
    let req = request();
    let c = challenge(req.cell, s.id, req.action_digest, req.nonce);
    let got = verify_step_up(
        &s,
        &req,
        &key.assert(&c, 1, true),
        &key.stored(0),
        s.account,
        NOW,
    )
    .unwrap();
    assert_eq!(
        got.record,
        AuthRecord::StepUpGranted {
            id: req.id,
            action_digest: req.action_digest,
            session: s.id,
        }
    );
    assert_eq!(
        admit_step_up(
            &s,
            req.action_digest,
            Some(&got.stepup),
            NOW,
            P71_DEFAULT_US
        ),
        Ok(())
    );
    assert_eq!(
        consumption(&got.stepup),
        AuthRecord::StepUpConsumed { id: req.id }
    );
}

/// I-78, ADR-008: a step-up without user verification, over another
/// challenge, or from a magic-link session is refused.
#[test]
fn i78_step_up_needs_uv_the_challenge_and_a_strong_session() {
    let key = passkey::Passkey::new(5);
    let s = session(Method::Passkey);
    let req = request();
    let c = challenge(req.cell, s.id, req.action_digest, req.nonce);
    assert_eq!(
        verify_step_up(
            &s,
            &req,
            &key.assert(&c, 1, false),
            &key.stored(0),
            s.account,
            NOW
        ),
        Err(StepUpDeny::NoUserVerification)
    );
    assert!(matches!(
        verify_step_up(
            &s,
            &req,
            &key.assert(&[0; 32], 1, true),
            &key.stored(0),
            s.account,
            NOW
        ),
        Err(StepUpDeny::Assertion(_))
    ));
    assert_eq!(
        verify_step_up(
            &session(Method::MagicLink),
            &req,
            &key.assert(&c, 1, true),
            &key.stored(0),
            s.account,
            NOW
        ),
        Err(StepUpDeny::MagicLinkSession)
    );
}

/// I-78, ADR-008: only a credential of the session's own account steps
/// up. A holder of a stolen cookie who answers with their own passkey is
/// refused before the assertion is verified.
#[test]
fn i78_step_up_credential_belongs_to_the_session_account() {
    let key = passkey::Passkey::new(5);
    let s = session(Method::Passkey);
    let req = request();
    let c = challenge(req.cell, s.id, req.action_digest, req.nonce);
    assert_eq!(
        verify_step_up(
            &s,
            &req,
            &key.assert(&c, 1, true),
            &key.stored(0),
            AccountId::from_raw(2),
            NOW
        ),
        Err(StepUpDeny::OtherAccount)
    );
}

/// ADR-008 "Sign counts": a step-up whose signed sign count went down is
/// reported as a suspect credential, as a login is, so the cell records
/// `CredentialSuspect`.
#[test]
fn adr008_step_up_sign_count_regression_is_credential_suspect() {
    let key = passkey::Passkey::new(5);
    let s = session(Method::Passkey);
    let req = request();
    let c = challenge(req.cell, s.id, req.action_digest, req.nonce);
    assert_eq!(
        verify_step_up(
            &s,
            &req,
            &key.assert(&c, 4, true),
            &key.stored(9),
            s.account,
            NOW
        ),
        Err(StepUpDeny::CredentialSuspect)
    );
}
