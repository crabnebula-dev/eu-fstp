//! Decoder tests for the tenant operations (M4 design sections 2.2 J0,
//! 3.5 and 3.7 step 1, ADR-006, lane m4tenant).
//!
//! Written by the m4tenant test author before the tenant decoders exist.
//! Each test drives `decode_route`, the decoder a web adapter uses, with
//! the routes of the registry. Until the tenant decoders exist, a tenant
//! body is not judged, so every malformed body below decodes and each
//! refusal test is red for that reason.
//!
//! The bodies follow the onboarding pages of `web/src/onboarding`, which
//! the e2e journeys run (`e2e/onboarding.spec.ts`):
//!
//! - `tenant.save_step` takes `{base, values}`. `base` is the tenant
//!   revision as a canonical decimal string. `values` is the step's
//!   values in the `fstp-tenant` codec form, except that the data
//!   protection contact is the free text itself, which dispatch stores
//!   and replaces by its text reference (design 3.7 step 1). The step in
//!   the path names the values.
//! - Each `tenant.set_*` takes `{value}`, the setting in the `fstp-tenant`
//!   codec form of its parameter.
//! - `tenant.invite_admin` takes `{email}`. `tenant.complete` and
//!   `admin.approve_self_grant` take an empty object.
//!
//! JSON numbers are refused everywhere (ADR-006 and the tenant codec). A
//! set goes out strictly ascending, as the codec takes it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OPS, OpKind};
use fstp_api_core::decode::{Method, decode_route, decode_tool};
use fstp_api_core::{ApiError, ErrorCode, Op};

fn route(method: Method, path: &str, body: &str) -> Result<Op, ApiError> {
    decode_route(method, path, body.as_bytes())
}

/// The operation a decode gave, or a description of the error.
fn decoded(r: &Result<Op, ApiError>) -> Result<&'static str, String> {
    match r {
        Ok(op) => Ok(op.name()),
        Err(e) => Err(format!("{e:?}")),
    }
}

fn assert_op(r: &Result<Op, ApiError>, want: &str, what: &str) {
    assert_eq!(decoded(r), Ok(want), "{what}");
}

/// Whether `r` is refused: a strict-decoder refusal of a matched route,
/// or no route at all.
fn refused(r: &Result<Op, ApiError>) -> bool {
    matches!(
        r,
        Err(ApiError::Refused {
            code: ErrorCode::BadRequest | ErrorCode::NotFound,
            ..
        })
    )
}

fn assert_refused(r: &Result<Op, ApiError>, what: &str) {
    assert!(refused(r), "{what}: wanted a refusal, got {:?}", decoded(r));
}

/// The first tenant admin of the e2e cell, as a decimal account id.
const A1: &str = "2561";
/// The second tenant admin.
const A2: &str = "2562";

/// A valid `values` object of each onboarding step, as the onboarding
/// pages send it.
fn step_values() -> Vec<(&'static str, String)> {
    vec![
        (
            "organisation",
            format!(
                r#"{{"data_protection_contact":"Synthetic data protection contact.","signatories":["{A1}"]}}"#
            ),
        ),
        (
            "agreements",
            r#"{"dpa":"1","saas_terms":"1","sub_processors":"1"}"#.to_owned(),
        ),
        ("branding", r#"{"package":"default"}"#.to_owned()),
        (
            "domains_and_email",
            r#"{"sending_domain":"mail.e2e.invalid"}"#.to_owned(),
        ),
        (
            "identity",
            r#"{"p18":["document_upload","eudi_wallet"],"p45":"tenant_registration"}"#.to_owned(),
        ),
        (
            "inference",
            r#"{"fallbacks":[],"primary":"placeholder-model","provider":"placeholder"}"#.to_owned(),
        ),
        (
            "payments",
            r#"{"bank_interface":"not_connected"}"#.to_owned(),
        ),
        (
            "channels",
            r#"{"matrix_homeserver":null,"whatsapp":false}"#.to_owned(),
        ),
        ("administrators", format!(r#"{{"admins":["{A1}","{A2}"]}}"#)),
    ]
}

fn save(step: &str, body: &str) -> Result<Op, ApiError> {
    route(Method::Put, &format!("/admin/onboarding/{step}"), body)
}

fn save_body(values: &str) -> String {
    format!(r#"{{"base":"0","values":{values}}}"#)
}

/// R-TN-01, design 3.7 step 1: `tenant.save_step` decodes the values of
/// every onboarding step in the form the onboarding pages send.
#[test]
fn r_tn_01_save_step_decodes_the_values_of_every_step() {
    for (step, values) in step_values() {
        assert_op(
            &save(step, &save_body(&values)),
            "tenant.save_step",
            &format!("R-TN-01: the {step} values"),
        );
    }
    assert_op(
        &route(Method::Get, "/admin/onboarding/organisation", ""),
        "tenant.get_step",
        "R-TN-01: the step read",
    );
}

/// R-TN-01, design 3.7 step 1: the strict decoder of `tenant.save_step`
/// refuses a request it cannot take whole. A step name no step has, the
/// values of another step, an unknown or missing member, a set out of
/// order or with a repeat, and a mistyped value are each refused.
#[test]
fn r_tn_01_save_step_decoder_refuses_malformed_requests() {
    let org =
        format!(r#"{{"data_protection_contact":"Synthetic contact.","signatories":["{A1}"]}}"#);
    let cases: Vec<(&str, &str, String)> = vec![
        ("an unknown step", "invented", save_body(&org)),
        ("the completion path as a step", "complete", save_body(&org)),
        (
            "the values of another step",
            "organisation",
            save_body(r#"{"package":"default"}"#),
        ),
        ("no base", "organisation", format!(r#"{{"values":{org}}}"#)),
        ("no values", "organisation", r#"{"base":"0"}"#.to_owned()),
        (
            "an unknown top member",
            "organisation",
            format!(r#"{{"base":"0","extra":"x","values":{org}}}"#),
        ),
        (
            "an unknown values member",
            "branding",
            save_body(r#"{"extra":"x","package":"default"}"#),
        ),
        (
            "a missing values member",
            "identity",
            save_body(r#"{"p18":["eudi_wallet"]}"#),
        ),
        (
            "a set out of order",
            "identity",
            save_body(r#"{"p18":["eudi_wallet","document_upload"],"p45":"tenant_registration"}"#),
        ),
        (
            "a set with a repeat",
            "administrators",
            save_body(&format!(r#"{{"admins":["{A1}","{A1}"]}}"#)),
        ),
        (
            "an account that is not a canonical decimal",
            "administrators",
            save_body(r#"{"admins":["02561"]}"#),
        ),
        (
            "an unknown name",
            "branding",
            save_body(r#"{"package":"invented"}"#),
        ),
        (
            "a contact that is not text",
            "organisation",
            save_body(&format!(
                r#"{{"data_protection_contact":{{"id":"1"}},"signatories":["{A1}"]}}"#
            )),
        ),
        (
            "a boolean as text",
            "channels",
            save_body(r#"{"matrix_homeserver":null,"whatsapp":"false"}"#),
        ),
        (
            "a sending domain that is not a domain name",
            "domains_and_email",
            save_body(r#"{"sending_domain":"not a domain"}"#),
        ),
        ("a values array", "branding", save_body(r#"["default"]"#)),
    ];
    for (what, step, body) in cases {
        assert_refused(&save(step, &body), &format!("R-TN-01: {what}"));
    }
}

/// ADR-006 and the tenant codec: a JSON number is refused wherever a
/// tenant request holds a number, as a revision, an id, a version or a
/// duration.
#[test]
fn adr006_tenant_requests_refuse_json_numbers() {
    let org =
        format!(r#"{{"data_protection_contact":"Synthetic contact.","signatories":["{A1}"]}}"#);
    assert_refused(
        &save("organisation", &format!(r#"{{"base":0,"values":{org}}}"#)),
        "ADR-006: the base revision as a number",
    );
    assert_refused(
        &save(
            "organisation",
            &save_body(r#"{"data_protection_contact":"Synthetic contact.","signatories":[2561]}"#),
        ),
        "ADR-006: an account as a number",
    );
    assert_refused(
        &save(
            "agreements",
            &save_body(r#"{"dpa":1,"saas_terms":1,"sub_processors":1}"#),
        ),
        "ADR-006: agreement versions as numbers",
    );
    assert_refused(
        &route(
            Method::Put,
            "/admin/settings/step-up-freshness",
            r#"{"value":300000000}"#,
        ),
        "ADR-006: P-71 as a number",
    );
    assert_refused(
        &route(
            Method::Put,
            "/admin/settings/session-lifetimes",
            r#"{"value":{"absolute_us":43200000000,"idle_us":1800000000}}"#,
        ),
        "ADR-006: P-72 as numbers",
    );
}

/// One tenant setting route: its operation, a valid value and invalid
/// ones.
struct Setting {
    path: &'static str,
    op: &'static str,
    good: &'static [&'static str],
    bad: &'static [&'static str],
}

fn settings() -> Vec<Setting> {
    vec![
        Setting {
            path: "/admin/settings/payment-mode",
            op: "tenant.set_payment_mode",
            good: &[r#""record_only""#, r#""execution""#],
            bad: &[r#""invented""#, "null", r#"["record_only"]"#],
        },
        Setting {
            path: "/admin/settings/template-licence",
            op: "tenant.set_template_licence",
            good: &[r#""MIT""#, r#""CC-BY-4.0""#],
            bad: &["null", r#"["MIT"]"#, "true"],
        },
        Setting {
            path: "/admin/settings/login-methods",
            op: "tenant.set_login_methods",
            good: &[r#"["passkey"]"#, r#"["eudi_wallet","passkey"]"#],
            bad: &[
                r#""passkey""#,
                r#"["passkey","eudi_wallet"]"#,
                r#"["passkey","passkey"]"#,
                r#"["invented","passkey"]"#,
            ],
        },
        Setting {
            path: "/admin/settings/step-up-freshness",
            op: "tenant.set_step_up_freshness",
            good: &[r#""300000000""#, r#""60000000""#],
            bad: &[r#""+5""#, r#""-0""#, r#""05""#, r#""five""#],
        },
        Setting {
            path: "/admin/settings/session-lifetimes",
            op: "tenant.set_session_lifetimes",
            good: &[r#"{"absolute_us":"43200000000","idle_us":"1800000000"}"#],
            bad: &[
                r#"{"idle_us":"1800000000"}"#,
                r#"{"absolute_us":"43200000000","extra":"1","idle_us":"1800000000"}"#,
                r#""1800000000""#,
            ],
        },
        Setting {
            path: "/admin/settings/mcp",
            op: "tenant.set_mcp",
            good: &[
                r#"{"enabled":true,"public_tools":true,"roles":null}"#,
                r#"{"enabled":false,"public_tools":false,"roles":[]}"#,
                r#"{"enabled":true,"public_tools":true,"roles":["Applicant","Programme manager"]}"#,
            ],
            bad: &[
                r#"{"enabled":"yes","public_tools":true,"roles":null}"#,
                r#"{"enabled":true,"roles":null}"#,
                r#"{"enabled":true,"public_tools":true,"roles":["Invented role"]}"#,
                r#"{"enabled":true,"public_tools":true,"roles":["Programme manager","Applicant"]}"#,
            ],
        },
    ]
}

/// R-LG-03, design 3.5: each tenant setting has its own operation, which
/// takes exactly `{value}` in the codec form of its parameter. A value of
/// the wrong shape, an unknown member and a missing value are refused.
#[test]
fn r_lg_03_setting_decoders_take_one_value_in_the_codec_form() {
    for s in settings() {
        for v in s.good {
            assert_op(
                &route(Method::Put, s.path, &format!(r#"{{"value":{v}}}"#)),
                s.op,
                &format!("R-LG-03: {} with {v}", s.op),
            );
        }
        for v in s.bad {
            assert_refused(
                &route(Method::Put, s.path, &format!(r#"{{"value":{v}}}"#)),
                &format!("R-LG-03: {} with {v}", s.op),
            );
        }
        let v = s.good[0];
        assert_refused(
            &route(Method::Put, s.path, "{}"),
            &format!("R-LG-03: {} with no value", s.op),
        );
        assert_refused(
            &route(
                Method::Put,
                s.path,
                &format!(r#"{{"extra":"x","value":{v}}}"#),
            ),
            &format!("R-LG-03: {} with an unknown member", s.op),
        );
    }
}

/// SoD-07, design 2.2 J0: `tenant.invite_admin` takes exactly `{email}`
/// as text. `tenant.complete` and `admin.approve_self_grant` take no
/// member.
#[test]
fn sod07_admin_and_completion_decoders_are_strict() {
    assert_op(
        &route(
            Method::Post,
            "/admin/admins",
            r#"{"email":"a2@e2e.invalid"}"#,
        ),
        "tenant.invite_admin",
        "SoD-07: an invitation",
    );
    for body in [
        "{}",
        r#"{"email":5}"#,
        r#"{"email":null}"#,
        r#"{"email":"a2@e2e.invalid","role":"Tenant admin"}"#,
    ] {
        assert_refused(
            &route(Method::Post, "/admin/admins", body),
            &format!("SoD-07: an invitation with {body}"),
        );
    }
    assert_op(
        &route(Method::Post, "/admin/onboarding/complete", "{}"),
        "tenant.complete",
        "R-TN-01: completion",
    );
    assert_refused(
        &route(
            Method::Post,
            "/admin/onboarding/complete",
            r#"{"by":"2561"}"#,
        ),
        "R-TN-01: completion names no actor",
    );
    assert_op(
        &route(Method::Post, "/admin/approvals/7", "{}"),
        "admin.approve_self_grant",
        "SoD-07: an approval",
    );
    assert_refused(
        &route(Method::Post, "/admin/approvals/7", r#"{"grantee":"2561"}"#),
        "SoD-07: an approval names its grant by id only",
    );
}

/// R-TN-01: a read of a step name that no onboarding step has is
/// refused, so no read model is built for it.
#[test]
fn r_tn_01_get_step_refuses_an_unknown_step() {
    for step in ["invented", "complete", "summary", "Organisation"] {
        assert_refused(
            &route(Method::Get, &format!("/admin/onboarding/{step}"), ""),
            &format!("R-TN-01: a read of step {step}"),
        );
    }
}

/// I-85, design 2.2 J0: no tenant operation is an MCP tool. Every tenant
/// operation completes or grants tenant administration, so an agent never
/// reaches one, and `decode_tool` has no name for it.
#[test]
fn i85_no_tenant_operation_is_an_mcp_tool() {
    let tenant: Vec<_> = OPS
        .iter()
        .filter(|s| matches!(s.kind, OpKind::Tenant(_)))
        .collect();
    assert!(!tenant.is_empty());
    for spec in tenant {
        assert!(spec.tool.is_none(), "I-85: {} has a tool", spec.name);
        assert!(
            decode_tool(spec.name, b"{}").is_err(),
            "I-85: {} decodes as a tool",
            spec.name
        );
    }
}
