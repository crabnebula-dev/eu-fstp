//! The client of the self-hosted file custody server `fstp-keyd` (Q32).

use crate::CustodyError;

/// A custody client that talks to `fstp-keyd` over its Unix socket.
#[derive(Debug)]
pub struct KeydCustody {
    socket: std::path::PathBuf,
}

impl KeydCustody {
    /// A client for the server at `socket`.
    pub fn new(socket: &std::path::Path) -> Result<KeydCustody, CustodyError> {
        let _ = socket;
        Err(CustodyError::NotImplemented(
            "fstp_custody::KeydCustody::new",
        ))
    }

    /// The socket path.
    pub fn socket(&self) -> &std::path::Path {
        &self.socket
    }
}

crate::refusing_custody!(KeydCustody, "fstp_custody::KeydCustody");

/// One frame of the keyd protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeydFrame {
    /// The frame kind.
    pub kind: u8,
    /// The frame body.
    pub body: Vec<u8>,
}

/// Decodes one frame from the server. Fuzzed (`keyd_frame_decode`).
pub fn decode_frame(bytes: &[u8]) -> Result<KeydFrame, CustodyError> {
    let _ = bytes;
    Err(CustodyError::NotImplemented(
        "fstp_custody::keyd::decode_frame",
    ))
}
