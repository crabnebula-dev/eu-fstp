//! The creator and import operations of journey J1, built through the
//! adapter-facing decoders `fstp_api_core::decode::{decode_route,
//! decode_tool}` (M4 design sections 2.2, 3.2, 3.3 and 3.7 step 1).
//!
//! Routes are the registry's. Request bodies follow the creator pages of
//! `web/src/creator/pages` and `web/src/people/invite.ts`, which lane W4a
//! wrote against the same design:
//!
//! - `creator.open_draft` sends `{}`. The server draws the programme and
//!   its first policy version, and takes the default funder profile.
//! - `creator.apply_start` sends `{base, start}`, where `start` is
//!   `{kind: "blank"}`, `{kind: "template", template, version}` or
//!   `{kind: "clone", source}`.
//! - `creator.save_fields` sends `{base, fields: [{field, value}]}`, where
//!   `field` is the `<step>.<member>` key of `fstp_programme::FieldId::key`
//!   and `value` its spec JSON, with amounts as ADR-006 strings.
//! - `creator.accept_narrative` sends `{base}` on the field's route.
//! - `creator.invite` sends `{email, role, organisation?}` with the role
//!   keys of `e2e/creator/contract.ts`. The server draws the invitation.
//! - `creator.acknowledge` sends `{revision, warning}`, with the result's
//!   `key` of the report as `warning`.
//! - `creator.request_activation` and `creator.approve_activation` send
//!   `{revision}`.
//! - `import.upload` sends `{media, text}`. The server draws the document.
//! - `import.resolve` sends `{base, conflict_acknowledged, resolution,
//!   shown}`, where `resolution` is `{kind: "confirm", value}`, `{kind:
//!   "edit", value}` or `{kind: "dismiss"}` and `shown` the proposal's
//!   `digest` of the import list.
//!
//! A revision is the opaque string of the `revision` member of
//! `creator.get_draft`. The test author of lane m4wire wrote this file
//! before the decoders exist, so every form here is an interim reading,
//! pending the production agent's decoders and Daniel. A change touches
//! this file only.

use fstp_api_core::decode::{Method, decode_route, decode_tool};
use fstp_api_core::{ApiError, Op};
use fstp_domain::id::ProgrammeId;
use fstp_json::{Object, Value};

/// The MCP tool that saves draft fields (`creator.save_fields`).
pub const TOOL_SAVE_FIELDS: &str = "fstp_creator_save_fields";
/// The MCP tool that reads a draft (`creator.get_draft`).
pub const TOOL_GET_DRAFT: &str = "fstp_creator_get_draft";
/// The MCP tool that reads a draft's report (`creator.get_report`).
pub const TOOL_GET_REPORT: &str = "fstp_creator_get_report";

/// The compact JSON bytes of an object of `members`.
pub fn body(members: Vec<(&str, Value)>) -> Vec<u8> {
    Value::Object(object(members)).to_compact().into_bytes()
}

/// An object of `members`.
pub fn object(members: Vec<(&str, Value)>) -> Object {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    o
}

/// A JSON string.
pub fn s(text: &str) -> Value {
    Value::String(text.to_owned())
}

/// The route segment of `p`.
fn seg(p: ProgrammeId) -> String {
    p.raw().to_string()
}

/// Any route with a raw JSON body text, for the strictness tests.
pub fn raw(method: Method, path: &str, json: &str) -> Result<Op, ApiError> {
    decode_route(method, path, json.as_bytes())
}

/// `creator.open_draft`: `POST /programmes` with `{}`.
pub fn open_draft() -> Result<Op, ApiError> {
    decode_route(Method::Post, "/programmes", &body(Vec::new()))
}

/// `creator.list_programmes`: `GET /programmes`.
pub fn list_programmes() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/programmes", &[])
}

/// `creator.list_templates`: `GET /templates`.
pub fn list_templates() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/templates", &[])
}

/// `creator.get_draft`: `GET /programmes/{p}/draft`.
pub fn get_draft(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(Method::Get, &format!("/programmes/{}/draft", seg(p)), &[])
}

/// `creator.get_draft` through MCP: `fstp_creator_get_draft`.
pub fn get_draft_tool(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_tool(TOOL_GET_DRAFT, &body(vec![("programme", s(&seg(p)))]))
}

/// `creator.get_report`: `GET /programmes/{p}/draft/report`.
pub fn get_report(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Get,
        &format!("/programmes/{}/draft/report", seg(p)),
        &[],
    )
}

/// `creator.preview`: `GET /programmes/{p}/draft/previews/{kind}`, with
/// `kind` one of `guide`, `public` and `contract` (J1).
pub fn preview(p: ProgrammeId, kind: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Get,
        &format!("/programmes/{}/draft/previews/{kind}", seg(p)),
        &[],
    )
}

/// `creator.impact`: `GET /programmes/{p}/draft/impact` (R-PG-04).
pub fn impact(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Get,
        &format!("/programmes/{}/draft/impact", seg(p)),
        &[],
    )
}

/// `creator.invitations`: `GET /programmes/{p}/invitations`.
pub fn invitations(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Get,
        &format!("/programmes/{}/invitations", seg(p)),
        &[],
    )
}

/// `creator.apply_start`: `POST /programmes/{p}/draft/start`.
pub fn apply_start(p: ProgrammeId, base: &str, start: Value) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/draft/start", seg(p)),
        &body(vec![("base", s(base)), ("start", start)]),
    )
}

/// The start of the shipped SuperSAFE template, id 1 version 1
/// (`fstp_programme::SUPERSAFE_TEMPLATE`).
pub fn supersafe_start() -> Value {
    Value::Object(object(vec![
        ("kind", s("template")),
        ("template", s("1")),
        ("version", Value::Number(fstp_json::Number::from(1u32))),
    ]))
}

/// The field edits of a save, as `[{field, value}]`.
fn edits(fields: &[(&str, Value)]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|(k, v)| Value::Object(object(vec![("field", s(k)), ("value", v.clone())])))
            .collect(),
    )
}

/// `creator.save_fields`: `PUT /programmes/{p}/draft/fields`.
pub fn save_fields(p: ProgrammeId, base: &str, fields: &[(&str, Value)]) -> Result<Op, ApiError> {
    decode_route(
        Method::Put,
        &format!("/programmes/{}/draft/fields", seg(p)),
        &body(vec![("base", s(base)), ("fields", edits(fields))]),
    )
}

/// `creator.save_fields` through MCP: `fstp_creator_save_fields`.
pub fn save_fields_tool(
    p: ProgrammeId,
    base: &str,
    fields: &[(&str, Value)],
) -> Result<Op, ApiError> {
    decode_tool(
        TOOL_SAVE_FIELDS,
        &body(vec![
            ("programme", s(&seg(p))),
            ("base", s(base)),
            ("fields", edits(fields)),
        ]),
    )
}

/// `creator.accept_narrative`:
/// `POST /programmes/{p}/draft/narratives/{field}/acceptance`.
pub fn accept_narrative(p: ProgrammeId, field: &str, base: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/draft/narratives/{field}/acceptance", seg(p)),
        &body(vec![("base", s(base))]),
    )
}

/// `creator.invite`: `POST /programmes/{p}/invitations`.
pub fn invite(
    p: ProgrammeId,
    email: &str,
    role: &str,
    organisation: Option<&str>,
) -> Result<Op, ApiError> {
    let mut m = vec![("email", s(email)), ("role", s(role))];
    if let Some(o) = organisation {
        m.push(("organisation", s(o)));
    }
    decode_route(
        Method::Post,
        &format!("/programmes/{}/invitations", seg(p)),
        &body(m),
    )
}

/// `creator.withdraw_invitation`:
/// `DELETE /programmes/{p}/invitations/{invitation}`.
pub fn withdraw_invitation(p: ProgrammeId, invitation: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Delete,
        &format!("/programmes/{}/invitations/{invitation}", seg(p)),
        &body(Vec::new()),
    )
}

/// `creator.acknowledge`: `POST /programmes/{p}/draft/acknowledgements`.
pub fn acknowledge(p: ProgrammeId, revision: &str, warning: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/draft/acknowledgements", seg(p)),
        &body(vec![("revision", s(revision)), ("warning", s(warning))]),
    )
}

/// `creator.request_activation`: `POST /programmes/{p}/activation-request`.
pub fn request_activation(p: ProgrammeId, revision: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/activation-request", seg(p)),
        &body(vec![("revision", s(revision))]),
    )
}

/// `creator.approve_activation`: `POST /programmes/{p}/activation`
/// (high-risk, no tool).
pub fn approve_activation(p: ProgrammeId, revision: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/activation", seg(p)),
        &body(vec![("revision", s(revision))]),
    )
}

/// `creator.save_as_template`: `POST /programmes/{p}/templates` with
/// `{}`. The server draws the template (Q17, tenant-private).
pub fn save_as_template(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/templates", seg(p)),
        &body(Vec::new()),
    )
}

/// `import.upload`: `POST /programmes/{p}/imports`.
pub fn import_upload(p: ProgrammeId, media: &str, text: &str) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!("/programmes/{}/imports", seg(p)),
        &body(vec![("media", s(media)), ("text", s(text))]),
    )
}

/// `import.list`: `GET /programmes/{p}/imports/proposals`.
pub fn import_list(p: ProgrammeId) -> Result<Op, ApiError> {
    decode_route(
        Method::Get,
        &format!("/programmes/{}/imports/proposals", seg(p)),
        &[],
    )
}

/// `import.resolve`:
/// `POST /programmes/{p}/imports/proposals/{q}/resolution`.
pub fn import_resolve(
    p: ProgrammeId,
    proposal: &str,
    base: &str,
    shown: &str,
    resolution: Value,
    conflict_acknowledged: bool,
) -> Result<Op, ApiError> {
    decode_route(
        Method::Post,
        &format!(
            "/programmes/{}/imports/proposals/{proposal}/resolution",
            seg(p)
        ),
        &body(vec![
            ("base", s(base)),
            ("conflict_acknowledged", Value::Bool(conflict_acknowledged)),
            ("resolution", resolution),
            ("shown", s(shown)),
        ]),
    )
}

/// A confirmation of `value` for `import.resolve`.
pub fn confirm(value: Value) -> Value {
    Value::Object(object(vec![("kind", s("confirm")), ("value", value)]))
}

/// `admin.approvals`: `GET /admin/approvals`, the approval inbox.
pub fn approvals() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/approvals", &[])
}
