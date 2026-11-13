//! The control plane link of a SaaS cell (design sections 1.3 and 9.1,
//! B4, ADR-009, R-NF-09). Lane F-ISO.
//!
//! A cell sends only `fstp_cp_proto::CellToCp` messages and reads only
//! `CpToCell` replies, so nothing outside the closed protocol crosses to
//! the control plane (I-19, Q36). The link runs mutual TLS: the client
//! configuration trusts the control plane CA alone and presents the
//! cell's client certificate.
//!
//! Interim, pending Daniel: the wire framing of `CellToCp` is not
//! designed yet (design section 9.1). Until it is, one connection carries
//! one exchange. The cell writes the encoded message in one write, closes
//! its sending side, and reads the encoded reply up to the peer's close.
//!
//! [`heartbeat_task`] sends `CellToCp::Heartbeat` once at start and then
//! every [`HEARTBEAT_INTERVAL`] until the cell shuts down. A self-hosted
//! cell has no control plane and never builds the link
//! ([`crate::egress::EgressRefusal::NoControlPlaneWhenSelfHosted`]).

use std::net::SocketAddr;
use std::time::Duration;

use fstp_cp_proto::{CellId, CellToCp, CpToCell, Health, ProductVersion};
use fstp_rt::{IoExt, Runtime, ShutdownSignal};

use crate::config::Mode;
use crate::egress::EgressRefusal;

/// How long one exchange, connection and handshake included, may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The time between two heartbeats. Interim, pending Daniel: design
/// section 9.1 names no interval.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// The longest reply the cell reads. Every `CpToCell` value fits.
pub const MAX_REPLY_LEN: usize = 64 * 1024;

/// The product version a cell reports, as `crate::process` configures it.
pub const PRODUCT_VERSION: ProductVersion = ProductVersion::new(0, 3, 0);

/// Where and how a cell reaches the control plane.
#[derive(Clone, Debug)]
pub struct ControlPlaneEndpoint {
    /// The control plane address.
    pub addr: SocketAddr,
    /// The name its server certificate carries.
    pub server_name: String,
    /// The client configuration: the control plane CA as the only root,
    /// and the cell's client certificate and key.
    pub tls: fstp_tls::ClientConfig,
}

/// Why an exchange with the control plane failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPlaneFault {
    /// The connection, the handshake or the exchange failed or timed out.
    Unreachable,
    /// The message did not encode.
    Encode,
    /// The reply is not one `CpToCell` value.
    Reply,
}

/// The heartbeat of `cell`: its id, [`PRODUCT_VERSION`] and
/// [`Health::Ok`].
#[must_use]
pub fn heartbeat(cell: [u8; 16]) -> CellToCp {
    CellToCp::Heartbeat {
        cell: CellId(cell),
        version: PRODUCT_VERSION,
        health: Health::Ok,
    }
}

/// Whether a cell in `mode` may reach the control plane.
///
/// # Errors
///
/// [`EgressRefusal::NoControlPlaneWhenSelfHosted`] for a self-hosted cell.
pub fn allowed(mode: Mode) -> Result<(), EgressRefusal> {
    match mode {
        Mode::Saas => Ok(()),
        Mode::SelfHosted => Err(EgressRefusal::NoControlPlaneWhenSelfHosted),
    }
}

/// One exchange: `message` to the control plane at `endpoint`, and its
/// reply (module documentation for the framing).
///
/// # Errors
///
/// [`ControlPlaneFault`] for a message that does not encode, a failed or
/// late exchange, and a reply that does not decode.
pub async fn exchange<R: Runtime>(
    rt: &R,
    endpoint: &ControlPlaneEndpoint,
    message: &CellToCp,
) -> Result<CpToCell, ControlPlaneFault> {
    let bytes = fstp_cp_proto::encode_cell_to_cp(message).map_err(|_| ControlPlaneFault::Encode)?;
    let run = async {
        let tcp = rt.connect_tcp(endpoint.addr).await?;
        let mut tls = fstp_tls::connect(&endpoint.tls, &endpoint.server_name, tcp).await?;
        tls.write_all(&bytes).await?;
        tls.flush().await?;
        tls.shutdown().await?;
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply, MAX_REPLY_LEN).await?;
        Ok::<Vec<u8>, std::io::Error>(reply)
    };
    let reply = match fstp_rt::timeout(rt, EXCHANGE_TIMEOUT, run).await {
        Ok(Ok(r)) => r,
        _ => return Err(ControlPlaneFault::Unreachable),
    };
    fstp_cp_proto::decode_cp_to_cell(&reply).map_err(|_| ControlPlaneFault::Reply)
}

/// The heartbeat loop of `cell` (module documentation). A failed
/// heartbeat is not retried before the next interval: the control plane
/// reads a missing heartbeat as the cell's health. The loop ends when
/// `signal` is triggered.
pub async fn heartbeat_task<R: Runtime>(
    rt: R,
    endpoint: ControlPlaneEndpoint,
    cell: [u8; 16],
    signal: ShutdownSignal,
) {
    let message = heartbeat(cell);
    loop {
        let round = async {
            let _ = exchange(&rt, &endpoint, &message).await;
            rt.sleep(HEARTBEAT_INTERVAL).await;
        };
        if signal.run_until(round).await.is_none() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-19, Q36: the heartbeat names the cell, the version and a closed
    /// health, and decodes as the same `CellToCp` value.
    #[test]
    fn i19_heartbeat_round_trips_through_the_closed_codec() {
        let m = heartbeat([7; 16]);
        let bytes = fstp_cp_proto::encode_cell_to_cp(&m).unwrap_or_default();
        assert_eq!(fstp_cp_proto::decode_cell_to_cp(&bytes).ok(), Some(m));
    }

    /// B12, I-38: a self-hosted cell has no control plane link.
    #[test]
    fn i19_self_hosted_cell_has_no_control_plane() {
        assert_eq!(allowed(Mode::Saas), Ok(()));
        assert_eq!(
            allowed(Mode::SelfHosted),
            Err(EgressRefusal::NoControlPlaneWhenSelfHosted)
        );
    }
}
