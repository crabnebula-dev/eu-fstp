//! The HTTP layer of the cell (design sections 2.3, 8.2, 8.7, 11.1, 11.2
//! and 15, ADR-008, ADR-009).
//!
//! - [`front`] is the tunnel listener's front and the loopback health
//!   listener. It runs the checks every route shares, sets the cell CSP
//!   and writes one typed log event per request.
//! - [`pages`] holds the compiled auth pages of `web/src/auth`, which the
//!   front serves on the cell origin when they are loaded.
//! - [`cookie`] writes and reads the `__Host-fstp` session cookie (B11).
//! - [`body`] decodes request bodies: canonical JSON, schema members only,
//!   and no `minor` member at any depth (I-18).
//! - [`decode_command_request`] decodes the body of
//!   `POST /api/v1/commands`. It is fuzzed (`command_request_decode`).

pub mod body;
pub mod cookie;
pub mod front;
pub mod pages;

pub use body::BodyRefusal;
pub use cookie::{
    COOKIE_NAME, CookieRefusal, clear_session_cookie, read_session_cookie,
    read_session_cookie_values, set_session_cookie,
};
pub use front::{Front, FrontConfig, FrontError, LogSink, MemoryLog, StderrLog};

use fstp_cell_core::CellCommand;

use crate::CellError;

/// The size limit of a command request body. No M3 command needs more,
/// and the route refuses a longer body with 413 before decoding it.
pub const COMMAND_BODY_LIMIT: usize = 256 * 1024;

/// A decoded command request body.
///
/// The body is the canonical JSON object `{command?, command_id,
/// stepup?}`. `command_id` and `stepup` are 32 lowercase hexadecimal
/// digits. `command` is the canonical JSON of a cell command, as
/// `fstp_cell_core::encode_cell_command` writes it, but without any
/// `minor` member. The decoder sets the minor flag of a `CreateDraft` to
/// true itself, so the flag never comes from a request (I-18, NOTE 14).
///
/// `POST /api/v1/commands` needs `command`. A route whose path names the
/// command, such as `POST /auth/recovery/{case}/approve`, refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRequest {
    /// The command id.
    pub command_id: [u8; 16],
    /// The step-up id, if the command is high risk.
    pub stepup: Option<[u8; 16]>,
    /// The command, when the body names one.
    pub command: Option<Box<CellCommand>>,
}

/// Decodes a command request body. Fuzzed (`command_request_decode`). A
/// `minor` field is refused (I-18): the flag never comes from a request.
///
/// # Errors
///
/// Every refusal of [`decode_command_body`], as a [`CellError`]. See
/// [`body_refusal`] for the mapping.
pub fn decode_command_request(bytes: &[u8]) -> Result<CommandRequest, CellError> {
    decode_command_body(bytes).map_err(body_refusal)
}

/// The [`CellError`] of a body refusal: [`CellError::Request`]. It keeps
/// the typed refusal, which names a rule or a schema member and never
/// request content (R-NF-02). The route layer uses
/// [`decode_command_body`] and its typed refusal directly.
pub const fn body_refusal(r: BodyRefusal) -> CellError {
    CellError::Request(r)
}

/// The members of a command request body.
const REQUIRED: [&str; 1] = ["command_id"];
/// The optional members of a command request body.
const OPTIONAL: [&str; 2] = ["command", "stepup"];

/// Decodes a command request body with a typed refusal (design sections
/// 8.4, 8.7 and 15). The size limit is [`COMMAND_BODY_LIMIT`].
///
/// # Errors
///
/// A [`BodyRefusal`] naming the first rule the body breaks.
pub fn decode_command_body(bytes: &[u8]) -> Result<CommandRequest, BodyRefusal> {
    let o = body::object(bytes, COMMAND_BODY_LIMIT)?;
    body::members(&o, &REQUIRED, &OPTIONAL)?;
    let command_id = body::hex_member::<16>(&o, "command_id")?;
    let stepup = body::optional_hex::<16>(&o, "stepup")?;
    let command = match o.get("command") {
        None => None,
        Some(v) => Some(Box::new(command_member(v)?)),
    };
    Ok(CommandRequest {
        command_id,
        stepup,
        command,
    })
}

/// Decodes the `command` member: the canonical JSON of a cell command.
///
/// A `CreateDraft` names no `minor` member, since [`body::object`] refuses
/// one. The route sets it to `true` before the codec reads the command, so
/// every draft starts minor-flagged and the domain derives the flag from
/// the vault (I-18, NOTE 14). The decoded command is checked to carry
/// that value.
fn command_member(v: &fstp_json::Value) -> Result<CellCommand, BodyRefusal> {
    let mut value = v.clone();
    if let Some(core) = value
        .as_object_mut()
        .and_then(|o| o.get_mut("core"))
        .and_then(fstp_json::Value::as_object_mut)
        && core.get("type").and_then(fstp_json::Value::as_str) == Some("CreateDraft")
    {
        core.insert("minor", fstp_json::Value::Bool(true));
    }
    let text = fstp_json::to_canonical(&value).map_err(|_| BodyRefusal::Command)?;
    let command =
        fstp_cell_core::decode_cell_command(text.as_bytes()).map_err(|_| BodyRefusal::Command)?;
    if let CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::command::Command::CreateDraft { minor, .. },
    )) = &command
        && !*minor
    {
        return Err(BodyRefusal::MinorMember);
    }
    Ok(command)
}
