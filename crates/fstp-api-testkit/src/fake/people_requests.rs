//! The people operations of journey J2, built through the adapter-facing
//! decoder `fstp_api_core::decode::decode_route` (M4 design section 2.2,
//! lane inv).
//!
//! Routes are the registry's. Bodies follow the pages of
//! `web/src/people`, which name the invitation by the link token:
//!
//! - `people.get_invitation`: `GET /invitations/{token}`, no body.
//! - `people.accept_invitation`: `POST /invitations/{token}/accept` with
//!   `{terms_version}`, the version the landing showed, as a JSON number.
//! - `people.begin_verification`: `POST /invitations/{token}/verification`
//!   with `{}`.
//! - `roles.grant` from the people admin page: `POST /programmes/{p}/roles`
//!   with `{invitation}` or `{invitation, approval}` (`grantBody` of
//!   `web/src/people/model.ts`, asserted by `e2e/creator/pages_wire.spec.ts`).
//! - `roles.grant` by account: the M2 form `{account, role, start}` that
//!   the authorisation matrix harness sends.
//!
//! The test author of lane inv wrote this file before the production
//! code. Each form is an interim reading, pending Daniel.

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::{ApiError, Op};
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_json::{Number, Value};

use super::creator_requests::{body, s};

/// `people.get_invitation`: `GET /invitations/{token}`.
pub fn get_invitation(token: &str) -> Result<Op, ApiError> {
    decode_route(Method::Get, &format!("/invitations/{token}"), &[])
}

/// `people.accept_invitation` of the terms version `version`.
pub fn accept_invitation(token: &str, version: u64) -> Result<Op, ApiError> {
    accept_invitation_raw(
        token,
        &String::from_utf8_lossy(&body(vec![(
            "terms_version",
            Value::Number(Number::from(version)),
        )])),
    )
}

/// `people.accept_invitation` with a raw JSON body, for the strictness
/// tests.
pub fn accept_invitation_raw(token: &str, json: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/invitations/{token}/accept"),
        json.as_bytes(),
    )
}

/// `people.begin_verification`: `POST /invitations/{token}/verification`.
pub fn begin_verification(token: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/invitations/{token}/verification"),
        &body(Vec::new()),
    )
}

/// `roles.grant` of the accepted invitation `invitation`, as the people
/// admin page sends it.
pub fn grant_invitation(p: ProgrammeId, invitation: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/roles", p.raw()),
        &body(vec![("invitation", s(invitation))]),
    )
}

/// `roles.grant` of `role`, spelled as the M2 form takes it (such as
/// `"ProgrammeManager"`), to `account` from `start`, with the M2
/// confidentiality text a Drafting or Judging binding needs and the
/// committee organisation `organisation`. So the only J2 fact a grant of
/// this form can lack is the `TermsAccepted` record.
pub fn grant_account(
    p: ProgrammeId,
    account: AccountId,
    role: &str,
    start: Timestamp,
    organisation: Option<u128>,
) -> Result<Op, ApiError> {
    let start = u128::try_from(start.micros()).unwrap_or(0);
    let mut members = vec![
        ("account", s(&account.raw().to_string())),
        ("role", s(role)),
        ("start", s(&start.to_string())),
        (
            "confidentiality",
            s("SYNTHETIC CONFIDENTIALITY TERMS. NOT LEGAL TEXT."),
        ),
    ];
    if let Some(o) = organisation {
        members.push(("organisation", s(&o.to_string())));
    }
    decode_route(
        Method::Post,
        &format!("/programmes/{}/roles", p.raw()),
        &body(members),
    )
}
