//! The control plane's private operator API (design section 9.2).
//!
//! A request is a value of the closed [`CpApiRequest`] enum, sent by the
//! operator tool. It carries random ids and closed enums only, never a
//! tenant name or any free text (I-19, I-20). The operator's passkey
//! assertion and step-up travel beside the request in the authenticated
//! session, not inside it.
//!
//! A frame is the version octet [`API_VERSION`], an operation octet, then
//! the operation's fields. The encoding is a bijection, so each request
//! has one frame.

use fstp_cp_proto::CellId;

use crate::ControlError;
use crate::placement::ClusterId;
use crate::provision::CellMode;

/// An opaque reference into CrabNebula's accounting system (design
/// section 4.4). No legal name or contact (Q20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrgRef(pub [u8; 16]);

/// A decoded control plane API request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpApiRequest {
    /// `provision-cell --org <ref> --mode shared|dedicated` (design
    /// section 9.2).
    ProvisionCell {
        /// The organisation.
        org: OrgRef,
        /// The mode.
        mode: CellMode,
    },
    /// `erase-cell`: the cell's erasure (R-SW-02). Destructive, so it
    /// needs two operators (ADR-011).
    EraseCell {
        /// The cell.
        cell: CellId,
    },
    /// Runs the isolation auditor on one cluster now (design section 9.3).
    PrivilegeAudit {
        /// The cluster.
        cluster: ClusterId,
    },
}

/// The version octet that opens every request frame.
pub const API_VERSION: u8 = 1;

const OP_PROVISION_CELL: u8 = 1;
const OP_ERASE_CELL: u8 = 2;
const OP_PRIVILEGE_AUDIT: u8 = 3;

/// Encodes a request.
pub fn encode_cp_api(req: &CpApiRequest) -> Vec<u8> {
    let mut out = vec![API_VERSION];
    match req {
        CpApiRequest::ProvisionCell { org, mode } => {
            out.push(OP_PROVISION_CELL);
            out.extend_from_slice(&org.0);
            out.push(match mode {
                CellMode::Shared => 0,
                CellMode::Dedicated => 1,
            });
        }
        CpApiRequest::EraseCell { cell } => {
            out.push(OP_ERASE_CELL);
            out.extend_from_slice(&cell.0);
        }
        CpApiRequest::PrivilegeAudit { cluster } => {
            out.push(OP_PRIVILEGE_AUDIT);
            out.extend_from_slice(&cluster.0);
        }
    }
    out
}

fn id16(b: Option<&[u8]>) -> Result<[u8; 16], ControlError> {
    b.and_then(|b| b.try_into().ok())
        .ok_or(ControlError::Request("length"))
}

/// Decodes an API request. Fuzzed (`cp_api_decode`).
///
/// # Errors
///
/// [`ControlError::Request`] naming the rule broken. Empty input and free
/// text are refused.
pub fn decode_cp_api(bytes: &[u8]) -> Result<CpApiRequest, ControlError> {
    let (Some(&API_VERSION), Some(op), body) = (bytes.first(), bytes.get(1), bytes.get(2..)) else {
        return Err(ControlError::Request("version"));
    };
    let req = match *op {
        OP_PROVISION_CELL => {
            let body = body.unwrap_or_default();
            let (org, mode) = (id16(body.get(..16))?, body.get(16..));
            let mode = match mode {
                Some([0]) => CellMode::Shared,
                Some([1]) => CellMode::Dedicated,
                _ => return Err(ControlError::Request("mode")),
            };
            CpApiRequest::ProvisionCell {
                org: OrgRef(org),
                mode,
            }
        }
        OP_ERASE_CELL => CpApiRequest::EraseCell {
            cell: CellId(id16(body)?),
        },
        OP_PRIVILEGE_AUDIT => CpApiRequest::PrivilegeAudit {
            cluster: ClusterId(id16(body)?),
        },
        _ => return Err(ControlError::Request("operation")),
    };
    if encode_cp_api(&req) != bytes {
        return Err(ControlError::Request("not canonical"));
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TH-26: every request round-trips, and a cut or extended frame is
    /// refused.
    #[test]
    fn th_26_cp_api_requests_round_trip() {
        for req in [
            CpApiRequest::ProvisionCell {
                org: OrgRef([7; 16]),
                mode: CellMode::Dedicated,
            },
            CpApiRequest::EraseCell {
                cell: CellId([8; 16]),
            },
            CpApiRequest::PrivilegeAudit {
                cluster: ClusterId([9; 16]),
            },
        ] {
            let b = encode_cp_api(&req);
            assert_eq!(decode_cp_api(&b), Ok(req.clone()));
            let mut longer = b.clone();
            longer.push(0);
            assert!(decode_cp_api(&longer).is_err());
            assert!(decode_cp_api(b.get(..b.len().saturating_sub(1)).unwrap_or_default()).is_err());
        }
    }
}
