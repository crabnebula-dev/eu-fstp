//! HTTP request bodies of the cell routes (design section 8.7).

use crate::CellError;

/// A decoded command request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRequest {
    /// The command id.
    pub command_id: [u8; 16],
    /// The step-up id, if the command is high risk.
    pub stepup: Option<[u8; 16]>,
}

/// Decodes a command request body. Fuzzed (`command_request_decode`). A
/// `minor` field is refused (I-18): the flag never comes from a request.
pub fn decode_command_request(bytes: &[u8]) -> Result<CommandRequest, CellError> {
    let _ = bytes;
    Err(CellError::NotImplemented(
        "fstp_cell::http::decode_command_request",
    ))
}
