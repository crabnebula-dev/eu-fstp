//! `fstp_auth::admit_method`: I-77 at login and the P-70 method setting
//! (`authentication.md` "Login methods" and "Strong methods", ADR-008
//! "Methods in M3", design section 8.1 and 8.2, Q10 A).
//!
//! - I-77: an account that holds a Drafting, Judging, Operations or tenant
//!   admin role logs in with a phishing-resistant method only. Passkeys and
//!   the EUDI Wallet are phishing resistant. OPAQUE and magic links are not.
//! - P-70: passkeys are always available. The EUDI Wallet, OPAQUE and
//!   magic links are per tenant.
//! - M3 builds passkeys and magic links only. The EUDI Wallet and OPAQUE
//!   are refused until M4 and a later ADR-001 addition, even where a
//!   tenant lists them.
//!
//! Lane W2b test author. Red until lane W2b lands `admit_method`, because
//! the W0 stub refuses every call with `NotImplemented`, which each test
//! treats as a failure.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::{METHODS, assert_real, every_enabled_list, real, want_method};
use fstp_auth::{EnabledMethods, LoginDeny, Method, admit_method};
use fstp_prop::{Gen, check, prop_assert_eq};

/// The tenant setting that lists every method.
fn all_enabled() -> EnabledMethods {
    EnabledMethods {
        methods: METHODS.to_vec(),
    }
}

/// I-77: a management holder is refused a magic-link login as
/// `WeakMethodForRole`, even where the tenant enables magic links.
#[test]
fn i77_holder_magic_link_login_refused_as_weak() {
    let got = admit_method(true, Method::MagicLink, &all_enabled());
    assert_real("holder by magic link", &got);
    assert_eq!(got, Err(LoginDeny::WeakMethodForRole));
}

/// I-77: OPAQUE is not phishing resistant, so a management holder is
/// refused it as `WeakMethodForRole`, even where the tenant lists it.
#[test]
fn i77_holder_opaque_login_refused_as_weak() {
    let got = admit_method(true, Method::Opaque, &all_enabled());
    assert_real("holder by OPAQUE", &got);
    assert_eq!(got, Err(LoginDeny::WeakMethodForRole));
}

/// I-77: a management holder logs in by passkey under every tenant
/// setting, since P-70 makes passkeys always available.
#[test]
fn i77_holder_passkey_login_admitted_under_every_setting() {
    for enabled in every_enabled_list() {
        let got = admit_method(true, Method::Passkey, &enabled);
        assert_real("holder by passkey", &got);
        assert_eq!(got, Ok(()), "holder by passkey under {enabled:?}");
    }
}

/// I-77: no weak method admits a holder under any tenant setting.
#[test]
fn i77_holder_never_admitted_with_a_weak_method() {
    for enabled in every_enabled_list() {
        for m in [Method::MagicLink, Method::Opaque] {
            let got = admit_method(true, m, &enabled);
            assert_real("holder by a weak method", &got);
            assert!(got.is_err(), "holder admitted by {m:?} under {enabled:?}");
        }
    }
}

/// P-70: passkeys are always available, so a passkey login of a
/// non-holder is admitted even when the tenant list omits passkeys.
#[test]
fn p70_passkey_always_available_to_non_holders() {
    let got = admit_method(false, Method::Passkey, &EnabledMethods::default());
    assert_real("non-holder by passkey, empty list", &got);
    assert_eq!(got, Ok(()));
}

/// P-70: a non-holder logs in by magic link only where the tenant enables
/// magic links.
#[test]
fn p70_magic_link_admitted_only_where_enabled() {
    let on = EnabledMethods {
        methods: vec![Method::Passkey, Method::MagicLink],
    };
    let off = EnabledMethods {
        methods: vec![Method::Passkey],
    };
    let got_on = admit_method(false, Method::MagicLink, &on);
    let got_off = admit_method(false, Method::MagicLink, &off);
    assert_real("magic link enabled", &got_on);
    assert_real("magic link disabled", &got_off);
    assert_eq!(got_on, Ok(()));
    assert_eq!(got_off, Err(LoginDeny::MethodDisabled));
}

/// P-70, Q10 A: M3 refuses the EUDI Wallet to everyone, even where a
/// tenant lists it. It arrives in M4 (ADR-008 "Methods in M3").
#[test]
fn p70_eudi_wallet_refused_in_m3_even_where_listed() {
    for holds in [false, true] {
        let got = admit_method(holds, Method::EudiWallet, &all_enabled());
        assert_real("EUDI Wallet", &got);
        assert_eq!(
            got,
            Err(LoginDeny::MethodDisabled),
            "EUDI Wallet, holds {holds}"
        );
    }
}

/// P-70, Q10 A: M3 refuses OPAQUE to a non-holder, even where a tenant
/// lists it. It waits for an ADR-001 addition (ADR-008 "Methods in M3").
#[test]
fn p70_opaque_refused_in_m3_even_where_listed() {
    let got = admit_method(false, Method::Opaque, &all_enabled());
    assert_real("non-holder by OPAQUE", &got);
    assert_eq!(got, Err(LoginDeny::MethodDisabled));
}

/// I-77, P-70: `admit_method` equals the spec rule for every holding,
/// method and enabled list (all 128 cases).
#[test]
fn i77_admit_method_matches_the_spec_rule_exhaustively() {
    for enabled in every_enabled_list() {
        for m in METHODS {
            for holds in [false, true] {
                let got = admit_method(holds, m, &enabled);
                assert_real("admit_method", &got);
                assert_eq!(
                    got,
                    want_method(holds, m, &enabled),
                    "holds {holds}, {m:?}, {enabled:?}"
                );
            }
        }
    }
}

/// P-70: the answer depends on which methods the tenant lists, not on
/// their order or on repeats.
#[test]
fn p70_enabled_list_order_and_repeats_do_not_matter() {
    check(
        "p70_enabled_list_order_and_repeats_do_not_matter",
        |g: &mut Gen| {
            let holds = g.bool();
            let m = *g.pick(&METHODS);
            let mut methods = g.vec(0..=8, |g| *g.pick(&METHODS));
            let mut set = methods.clone();
            set.sort();
            set.dedup();
            g.shuffle(&mut methods);
            let base = admit_method(holds, m, &EnabledMethods { methods: set });
            let got = admit_method(holds, m, &EnabledMethods { methods });
            real("admit_method", &base)?;
            real("admit_method", &got)?;
            prop_assert_eq!(got, base, "holds {holds}, {m:?}");
            Ok(())
        },
    );
}
