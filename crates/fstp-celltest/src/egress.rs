//! The egress recorder: a test transport on `fstp_rt::duplex`, above TLS
//! (design section 14.3). Lane W1a.

/// Where a capture went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// The cell's vault.
    Vault,
    /// The control plane.
    ControlPlane,
    /// The witness.
    Witness,
    /// Custody.
    Custody,
    /// A CrabNebula host.
    CrabNebula,
}

/// One plaintext capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// The peer.
    pub peer: Peer,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// Every capture of a world.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressLog {
    captures: Vec<Capture>,
}

impl EgressLog {
    /// The captures, in order.
    pub fn captures(&self) -> &[Capture] {
        &self.captures
    }
}
