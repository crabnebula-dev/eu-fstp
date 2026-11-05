//! P-32, email only (`SPEC/02-domain/policy-parameters.md`, P-32 row).
//!
//! Daniel deferred Matrix and its group types on 2026-11-04 (B-05), and
//! WhatsApp on the same day (B-03). The SuperSAFE cell of P-32 now reads
//! "Email only". The parameter id stays reserved, and its value names the
//! enabled channels.
//!
//! Lane m4/roles, test author. The value schema is pinned here as
//! `{"channels":["email"]}`: the old members `group_types` and
//! `whatsapp_account` describe deferred channels only, so they go. A value
//! that names Matrix or WhatsApp is refused with a plain reason that names
//! the deferral and its B-ID. These tests are red until `kinds.rs` takes
//! the new schema. The two `r_pg_01` tests cover the fixture and the
//! reading of the spec cell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_programme::{FieldId, decode_field_value, encode_field_value};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

/// The one P-32 value the spec allows.
const EMAIL_ONLY: &str = r#"{"channels":["email"]}"#;

/// The P-32 value of the SuperSAFE fixture before the deferral.
const OLD_SUPERSAFE: &str = r#"{"channels":["email","matrix","whatsapp"],"group_types":["programme_announcements","committee_group","grantee_cohort","project_group"],"whatsapp_account":"tenant_owned"}"#;

/// The reason a refusal gives, as its text.
fn refusal(text: &str) -> Result<String, String> {
    match decode_field_value(FieldId::P32, text.as_bytes()) {
        Ok(v) => Err(format!("P-32: {text} was accepted as {v:?}")),
        Err(e) => Ok(e.to_string()),
    }
}

/// Whether `reason` names the deferral of `b_id`.
fn names_deferral(reason: &str, b_id: &str) -> bool {
    reason.to_ascii_lowercase().contains("deferred") && reason.contains(b_id)
}

/// P-32: email alone is accepted, and it reads back as the same canonical
/// text.
#[test]
fn p32_email_alone_is_accepted_and_round_trips() {
    let v = decode_field_value(FieldId::P32, EMAIL_ONLY.as_bytes())
        .unwrap_or_else(|e| panic!("P-32: email only was refused: {e}"));
    assert_eq!(encode_field_value(&v), EMAIL_ONLY, "P-32: round trip");
}

/// P-32, B-05: a value that names Matrix is refused. The reason names the
/// deferral and B-05.
#[test]
fn p32_a_value_naming_matrix_names_the_b05_deferral() {
    for text in [
        r#"{"channels":["matrix"]}"#,
        r#"{"channels":["email","matrix"]}"#,
    ] {
        let reason = refusal(text).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            names_deferral(&reason, "B-05"),
            "P-32: the refusal of {text} does not name the B-05 deferral: {reason}"
        );
    }
}

/// P-32, B-03: a value that names WhatsApp is refused. The reason names
/// the deferral and B-03.
#[test]
fn p32_a_value_naming_whatsapp_names_the_b03_deferral() {
    for text in [
        r#"{"channels":["whatsapp"]}"#,
        r#"{"channels":["email","whatsapp"]}"#,
    ] {
        let reason = refusal(text).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            names_deferral(&reason, "B-03"),
            "P-32: the refusal of {text} does not name the B-03 deferral: {reason}"
        );
    }
}

/// P-32: the value the SuperSAFE fixture held before the deferral, with
/// its group types and WhatsApp account, is refused.
#[test]
fn p32_the_value_before_the_deferral_is_refused() {
    let _ = refusal(OLD_SUPERSAFE).unwrap_or_else(|e| panic!("{e}"));
}

/// P-32, property: a channel list drawn from email, Matrix and WhatsApp,
/// repeats allowed, is accepted exactly when it is email alone. A list
/// that names Matrix or WhatsApp is refused, and the reason names the
/// deferral of one channel it holds. Any other list, such as email twice,
/// is refused.
#[test]
fn p32_only_email_alone_is_accepted() {
    check_with(
        "p32_only_email_alone_is_accepted",
        Config::from_env().with_cases(128),
        |g| {
            let names = ["email", "matrix", "whatsapp"];
            let list: Vec<&str> = g.vec(1..=4, |g| *g.pick(&names));
            let text = format!(
                r#"{{"channels":[{}]}}"#,
                list.iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            g.note("value", &text);
            let got = decode_field_value(FieldId::P32, text.as_bytes());
            let matrix = list.contains(&"matrix");
            let whatsapp = list.contains(&"whatsapp");
            if list == ["email"] {
                prop_assert!(got.is_ok(), "P-32: email only was refused: {:?}", got);
                return Ok(());
            }
            let reason = match got {
                Ok(v) => return Err(format!("P-32: {text} was accepted as {v:?}")),
                Err(e) => e.to_string(),
            };
            if matrix || whatsapp {
                let named = (matrix && names_deferral(&reason, "B-05"))
                    || (whatsapp && names_deferral(&reason, "B-03"));
                prop_assert_eq!(
                    named,
                    true,
                    "P-32: the refusal of {} names no deferral: {}",
                    text,
                    reason
                );
            }
            Ok(())
        },
    );
}
