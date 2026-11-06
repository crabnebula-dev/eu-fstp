//! The authorisation matrix through HTTP (T-AUTHZ-MATRIX, H-01, I-84, M4
//! design section 8.3, exit criterion "the authorisation matrix is green").
//!
//! `t_authz_matrix_http` runs every cell of the matrix through the HTTP
//! routes of `fstp-web` over `fstp_rt::duplex`, and compares each outcome
//! with the independent reference, both ways. For `Deny(c)` the reply is a
//! refusal whose rule maps to `c`. For `Allow` the reply is no refusal
//! under an authorisation rule. The harness sends valid CSRF fields on
//! every cell, so a CSRF refusal never agrees with any expectation.
//!
//! This file holds the HTTP channel's part: reading an HTTP reply as an
//! outcome ([`observe`]) and the two-way agreement ([`agrees`]), with their
//! self-tests. The matrix, its reference and the harness (lanes W3a and
//! W3b) run the cells, and the harness reads each reply as [`observe`]
//! does.
//!
//! # Readings of the HTTP replies
//!
//! Design section 3.7 fixes the bodies, not the status codes, so the
//! outcome is read from the body. Each reading is interim, pending Daniel.
//!
//! - A refusal is `{"code":"refused","rule":<rule>}` (section 3.7).
//! - A prepared action is `{"status":"awaiting_confirmation",...}`
//!   (section 3.7, step 6). Through HTTP it never arises, since only MCP
//!   prepares.
//! - `{"code":"step_up_required",...}` and
//!   `{"code":"strong_method_required"}` are the step-up answers that
//!   `stepup.ts` handles (section 3.9).
//! - A refusal under `ADR-014` (CSRF) or `ADR-013` (a surface not built)
//!   comes from the adapter, not from the authorisation path.
//! - Any other 2xx reply is a completed operation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::{harness, matrix};

/// What one HTTP reply says about its operation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum HttpOutcome {
    /// A 2xx reply that is not a pending action.
    Done,
    /// A pending action awaiting confirmation in the platform.
    Pending,
    /// A step-up is needed first.
    StepUp,
    /// The account must add a phishing-resistant method first.
    StrongMethod,
    /// A refusal under a domain or authorisation rule.
    Refused(String),
    /// A refusal of the adapter itself, under `ADR-014` or `ADR-013`.
    Adapter(String),
    /// Anything else, with its status.
    Other(u16),
}

/// Reads an HTTP reply as an outcome.
fn observe(status: u16, body: &[u8]) -> HttpOutcome {
    let members = fstp_json::parse(body).ok().and_then(|v| {
        v.as_object().map(|o| {
            o.iter()
                .map(|(k, v)| (k.to_owned(), v.as_str().map(str::to_owned)))
                .collect::<Vec<_>>()
        })
    });
    let get = |key: &str| -> Option<String> {
        members
            .as_ref()?
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.clone())
    };
    match (get("code").as_deref(), get("rule")) {
        (Some("refused"), Some(rule)) if rule == "ADR-014" || rule == "ADR-013" => {
            return HttpOutcome::Adapter(rule);
        }
        (Some("not_available"), Some(rule)) => return HttpOutcome::Adapter(rule),
        (Some("refused"), Some(rule)) => return HttpOutcome::Refused(rule),
        (Some("step_up_required"), _) => return HttpOutcome::StepUp,
        (Some("strong_method_required"), _) => return HttpOutcome::StrongMethod,
        _ => {}
    }
    if get("status").as_deref() == Some("awaiting_confirmation") {
        return HttpOutcome::Pending;
    }
    if (200..300).contains(&status) && get("code").is_none() {
        HttpOutcome::Done
    } else {
        HttpOutcome::Other(status)
    }
}

/// The key a refusal is classified by: the rule of a refusal, or the code
/// of a step-up answer.
fn refusal_key(o: &HttpOutcome) -> Option<&str> {
    match o {
        HttpOutcome::Refused(rule) => Some(rule),
        HttpOutcome::StepUp => Some("step_up_required"),
        HttpOutcome::StrongMethod => Some("strong_method_required"),
        _ => None,
    }
}

/// What the reference expects of one cell, over the reference's own
/// denial classes `C`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Want<C> {
    /// The operation completes.
    Allow,
    /// The operation becomes a pending action.
    Pending,
    /// The operation is refused under class `C`.
    Deny(C),
}

/// The two-way agreement of design section 8.3. `class_of` is the
/// reference's map from a refusal key to its denial class, `None` for a
/// key that is no authorisation rule.
fn agrees<C: PartialEq + std::fmt::Debug>(
    want: &Want<C>,
    got: &HttpOutcome,
    class_of: impl Fn(&str) -> Option<C>,
) -> Result<(), String> {
    if let HttpOutcome::Adapter(rule) = got {
        return Err(format!(
            "the adapter refused under {rule}, which no cell expects"
        ));
    }
    match want {
        Want::Deny(c) => match refusal_key(got).map(&class_of) {
            Some(Some(k)) if k == *c => Ok(()),
            other => Err(format!(
                "want Deny({c:?}), got {got:?} classified as {other:?}"
            )),
        },
        Want::Allow => match (got, refusal_key(got).map(&class_of)) {
            (HttpOutcome::Done, _) | (_, Some(None)) => Ok(()),
            (_, Some(Some(k))) => Err(format!("want Allow, got a refusal of class {k:?}")),
            (other, None) => Err(format!("want Allow, got {other:?}")),
        },
        Want::Pending => match got {
            HttpOutcome::Pending => Ok(()),
            other => Err(format!("want Pending, got {other:?}")),
        },
    }
}

/// T-AUTHZ-MATRIX, H-01, I-84: every matrix cell through the HTTP routes
/// equals the reference, both ways. The harness's HTTP channel sends
/// each web cell through the routes of `fstp-web` over `fstp_rt::duplex`,
/// and reads the reply with `harness::observed_of_http`. MCP cells run
/// through dispatch, since `/mcp` waits for ADR-013 (lane W3c). The
/// comparison is the one of `t_authz_matrix_direct`, so the two channels
/// are judged alike.
#[test]
fn t_authz_matrix_http() {
    let m = matrix::matrix().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        m.missing_from_ops().is_empty(),
        "reference operations OPS lacks: {:?}",
        m.missing_from_ops()
    );
    assert!(
        m.unknown_to_reference().is_empty(),
        "OPS entries the reference does not judge: {:?}",
        m.unknown_to_reference()
    );
    let ops = matrix::OpFilter::from_env().unwrap_or_else(|e| panic!("{e}"));
    let m = m.narrowed(&ops);
    let shard = matrix::Shard::from_env().unwrap_or_else(|e| panic!("{e}"));
    let c = matrix::compare_grouped(&m, &matrix::http_channel, matrix::threads_from_env(), shard)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(c.clean(), "HTTP channel: {}", c.report());
}

/// T-AUTHZ-MATRIX: the harness reads every HTTP reply shape of design
/// sections 3.7 and 3.9 as this file's [`observe`] does, so the HTTP
/// channel's reading is the one its self-tests pin.
#[test]
fn t_authz_matrix_http_harness_reads_replies_as_observe() {
    use matrix::Observed;
    let cases: [(u16, &[u8]); 5] = [
        (200, b"{\"items\":[]}"),
        (
            202,
            b"{\"confirm_path\":\"/app/pending/1\",\"expires\":\"2026-10-30T12:00:00Z\",\"status\":\"awaiting_confirmation\"}",
        ),
        (403, b"{\"code\":\"refused\",\"rule\":\"I-03\"}"),
        (401, b"{\"challenge\":\"00\",\"code\":\"step_up_required\"}"),
        (403, b"{\"code\":\"strong_method_required\"}"),
    ];
    for (status, body) in cases {
        let got = harness::observed_of_http(status, body);
        let want = match observe(status, body) {
            HttpOutcome::Done => Observed::Completed,
            HttpOutcome::Pending => Observed::Pending,
            HttpOutcome::StepUp => Observed::StepUpRequired,
            HttpOutcome::StrongMethod => Observed::StrongMethodRequired,
            HttpOutcome::Refused(r) => Observed::Refused(Some(r)),
            other => panic!("{other:?} has no harness reading"),
        };
        assert_eq!(got, Ok(want), "{}", String::from_utf8_lossy(body));
    }
}

/// T-AUTHZ-MATRIX: [`observe`] reads every reply shape of design sections
/// 3.7 and 3.9.
#[test]
fn t_authz_matrix_http_observe_reads_every_reply_shape() {
    let cases: [(u16, &[u8], HttpOutcome); 10] = [
        (200, b"{\"items\":[]}", HttpOutcome::Done),
        (201, b"", HttpOutcome::Done),
        (
            202,
            b"{\"confirm_path\":\"/app/pending/1\",\"expires\":\"2026-10-30T12:00:00Z\",\"status\":\"awaiting_confirmation\"}",
            HttpOutcome::Pending,
        ),
        (403, b"{\"code\":\"refused\",\"rule\":\"I-03\"}", HttpOutcome::Refused("I-03".to_owned())),
        (401, b"{\"challenge\":\"00\",\"code\":\"step_up_required\"}", HttpOutcome::StepUp),
        (403, b"{\"code\":\"strong_method_required\"}", HttpOutcome::StrongMethod),
        (403, b"{\"code\":\"refused\",\"rule\":\"ADR-014\"}", HttpOutcome::Adapter("ADR-014".to_owned())),
        (
            501,
            b"{\"code\":\"not_available\",\"rule\":\"ADR-013\"}",
            HttpOutcome::Adapter("ADR-013".to_owned()),
        ),
        (404, b"{\"code\":\"not_found\"}", HttpOutcome::Other(404)),
        (500, b"not json", HttpOutcome::Other(500)),
    ];
    for (status, body, want) in cases {
        assert_eq!(
            observe(status, body),
            want,
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

/// A denial class of the self-test, standing for the reference's classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Actor,
    StepUp,
}

/// The self-test's rule map: `I-03` is an actor rule and the step-up
/// answer is the step-up class. `R-XX` is no authorisation rule.
fn class_of(key: &str) -> Option<Class> {
    match key {
        "I-03" => Some(Class::Actor),
        "step_up_required" => Some(Class::StepUp),
        _ => None,
    }
}

/// T-AUTHZ-MATRIX: [`agrees`] holds exactly for the pairs design section
/// 8.3 allows, in both directions.
#[test]
fn t_authz_matrix_http_agreement_is_two_way() {
    let refused = |r: &str| HttpOutcome::Refused(r.to_owned());
    let csrf = HttpOutcome::Adapter("ADR-014".to_owned());
    let cases: Vec<(Want<Class>, HttpOutcome, bool)> = vec![
        (Want::Deny(Class::Actor), refused("I-03"), true),
        (Want::Deny(Class::StepUp), HttpOutcome::StepUp, true),
        (Want::Deny(Class::Actor), HttpOutcome::StepUp, false),
        (Want::Deny(Class::Actor), HttpOutcome::Done, false),
        (Want::Deny(Class::Actor), refused("R-XX"), false),
        (Want::Deny(Class::Actor), csrf.clone(), false),
        (Want::Allow, HttpOutcome::Done, true),
        (Want::Allow, refused("R-XX"), true),
        (Want::Allow, refused("I-03"), false),
        (Want::Allow, HttpOutcome::StepUp, false),
        (Want::Allow, HttpOutcome::Pending, false),
        (Want::Allow, csrf.clone(), false),
        (Want::Allow, HttpOutcome::Other(404), false),
        (Want::Pending, HttpOutcome::Pending, true),
        (Want::Pending, HttpOutcome::Done, false),
        (Want::Pending, csrf, false),
    ];
    for (want, got, ok) in cases {
        assert_eq!(
            agrees(&want, &got, class_of).is_ok(),
            ok,
            "{want:?} against {got:?}"
        );
    }
}
