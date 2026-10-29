//! The closed set of outbound destinations of a cell and the connector
//! policy (B4, I-16, I-38, ADR-009 "Outbound destinations").
//!
//! The cell's connector opens connections only to a [`Destination`], and
//! the host firewall holds the same list. No variant reaches a payment
//! service or names a platform account (I-16).
//! `i16_cell_egress_has_no_payment_destination` enumerates the enum. A new
//! variant needs an amendment of ADR-009.
//!
//! # Policy (I-38)
//!
//! - Only [`Destination::CrabNebula`] may reach a CrabNebula host, and
//!   only the host its `CnCall` names. [`check_host`] refuses a CrabNebula
//!   host for every other destination.
//! - Only a self-hosted cell builds a CrabNebula call. A SaaS cell is
//!   refused before any byte is written (B12).
//! - The request bytes are exactly `fstp_release::egress::encode` of the
//!   call. No other code builds them.
//!
//! [`CnClient`] applies this policy over a [`CnTransport`]. The TLS
//! transport to the two service hosts needs a root store for their public
//! certificates, which no allowlisted crate provides yet, and Q34 is open
//! (design section 10.1). It is the seam a transport fills.

use std::future::Future;

use fstp_release::egress::{CnCall, EgressResponse, LICENCE_HOST, UPDATE_HOST};

use crate::config::Mode;

/// Where a cell may open a connection. Closed and exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `c_<cell>` on its application cluster, one pool per role.
    AppDatabase,
    /// Its own vault, over internal mTLS.
    Vault,
    /// Its own App and CellBackup custody entries.
    Custody,
    /// SaaS only: the control plane, through `CellToCp`. A self-hosted
    /// cell never builds it.
    ControlPlane,
    /// The witness, for the App chain's prepares, aborts and receipts.
    Witness,
    /// Self-hosted only: a CrabNebula host. The request is built only by
    /// `fstp_release::egress` (I-38). A SaaS cell never builds it.
    CrabNebula(CnCall),
    /// The `<cell>/keystore/` object storage prefix only. Proposed by
    /// ADR-012 and pending Daniel, so no connector builds it yet.
    KeystoreSnapshots,
}

/// Why the connector refused a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressRefusal {
    /// A CrabNebula host for a destination other than
    /// [`Destination::CrabNebula`], or a CrabNebula call to a host other
    /// than the one it names (I-38).
    CrabNebulaHost,
    /// A SaaS cell never reaches a CrabNebula host (B12, I-38).
    SaasNeverReachesCrabNebula,
    /// A self-hosted cell has no control plane.
    NoControlPlaneWhenSelfHosted,
    /// The destination is pending a decision, so no connector builds it
    /// (ADR-012 "Keystore snapshot path").
    PendingDecision,
}

/// Whether `host` is a CrabNebula service host, compared without case
/// and without a trailing dot.
pub fn is_crabnebula_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    [LICENCE_HOST, UPDATE_HOST]
        .iter()
        .any(|c| h.eq_ignore_ascii_case(c))
        || h.to_ascii_lowercase().ends_with(".crabnebula.dev")
        || h.eq_ignore_ascii_case("crabnebula.dev")
}

/// Checks that the connector may open `to` at `host` (I-38).
///
/// # Errors
///
/// [`EgressRefusal::CrabNebulaHost`] for a CrabNebula host and any
/// destination but `CrabNebula`, and for a CrabNebula call to another
/// host. [`EgressRefusal::PendingDecision`] for
/// [`Destination::KeystoreSnapshots`].
pub fn check_host(to: &Destination, host: &str) -> Result<(), EgressRefusal> {
    match to {
        Destination::CrabNebula(call) => {
            if host.trim_end_matches('.').eq_ignore_ascii_case(call.host()) {
                Ok(())
            } else {
                Err(EgressRefusal::CrabNebulaHost)
            }
        }
        Destination::KeystoreSnapshots => Err(EgressRefusal::PendingDecision),
        Destination::AppDatabase
        | Destination::Vault
        | Destination::Custody
        | Destination::ControlPlane
        | Destination::Witness => {
            if is_crabnebula_host(host) {
                Err(EgressRefusal::CrabNebulaHost)
            } else {
                Ok(())
            }
        }
    }
}

/// Checks that a cell in `mode` may build `to` at all.
///
/// # Errors
///
/// [`EgressRefusal::SaasNeverReachesCrabNebula`],
/// [`EgressRefusal::NoControlPlaneWhenSelfHosted`] or
/// [`EgressRefusal::PendingDecision`].
pub fn check_mode(mode: Mode, to: &Destination) -> Result<(), EgressRefusal> {
    match (mode, to) {
        (Mode::Saas, Destination::CrabNebula(_)) => Err(EgressRefusal::SaasNeverReachesCrabNebula),
        (Mode::SelfHosted, Destination::ControlPlane) => {
            Err(EgressRefusal::NoControlPlaneWhenSelfHosted)
        }
        (_, Destination::KeystoreSnapshots) => Err(EgressRefusal::PendingDecision),
        _ => Ok(()),
    }
}

/// Checks that `to` is a destination a connector builds, at the host its
/// own definition fixes: a CrabNebula call only at the host it names. The
/// full check of a configured host is [`connect_to`].
///
/// # Errors
///
/// [`EgressRefusal::PendingDecision`] for
/// [`Destination::KeystoreSnapshots`].
pub fn connect(to: &Destination) -> Result<(), crate::CellError> {
    match to {
        Destination::CrabNebula(call) => check_host(to, call.host()),
        Destination::KeystoreSnapshots => Err(EgressRefusal::PendingDecision),
        Destination::AppDatabase
        | Destination::Vault
        | Destination::Custody
        | Destination::ControlPlane
        | Destination::Witness => Ok(()),
    }
    .map_err(crate::CellError::Egress)
}

/// Checks `to` at `host` for a cell in `mode`: [`check_mode`], then
/// [`check_host`].
///
/// # Errors
///
/// The first refusal of the two checks.
pub fn connect_to(mode: Mode, to: &Destination, host: &str) -> Result<(), crate::CellError> {
    check_mode(mode, to)
        .and_then(|()| check_host(to, host))
        .map_err(crate::CellError::Egress)
}

/// Why a CrabNebula call gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnFault {
    /// The connector refused the call before any byte was written.
    Refused(EgressRefusal),
    /// The connection failed.
    Unreachable,
    /// The service answered with an error status.
    Status(u16),
    /// The answer did not decode.
    Malformed,
}

/// The byte link to a CrabNebula host, above TLS. The transport presents
/// the host as SNI and no client certificate (design section 10.1).
pub trait CnTransport: Send + Sync + 'static {
    /// Sends `request` to `host` and gives the whole response.
    fn exchange(
        &self,
        host: &'static str,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, CnFault>> + Send;
}

/// The client of the CrabNebula services. It is the only caller of a
/// [`CnTransport`], and it builds request bytes only through
/// `fstp_release::egress::encode` (I-38).
#[derive(Debug)]
pub struct CnClient<T> {
    mode: Mode,
    transport: T,
}

impl<T: CnTransport> CnClient<T> {
    /// A client for a cell in `mode`.
    pub fn new(mode: Mode, transport: T) -> CnClient<T> {
        CnClient { mode, transport }
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Sends `call` to the host it names and decodes the answer.
    ///
    /// # Errors
    ///
    /// [`CnFault::Refused`] for a SaaS cell, before any byte is written;
    /// otherwise the transport's fault, a non-2xx status, or a malformed
    /// answer.
    pub async fn call(&self, call: CnCall) -> Result<EgressResponse, CnFault> {
        let to = Destination::CrabNebula(call);
        let host = call.host();
        check_mode(self.mode, &to)
            .and_then(|()| check_host(&to, host))
            .map_err(CnFault::Refused)?;
        let bytes = fstp_release::egress::encode(&call).map_err(|_| CnFault::Malformed)?;
        let answer = self.transport.exchange(host, bytes).await?;
        let response =
            fstp_release::egress::decode_response(&answer).map_err(|_| CnFault::Malformed)?;
        if (200..300).contains(&response.status) {
            Ok(response)
        } else {
            Err(CnFault::Status(response.status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_release::egress::{Channel, ProductVersion, UpdateCheck};

    /// I-38: every destination but `CrabNebula` is refused at both
    /// CrabNebula hosts, and a call is refused at the other host.
    #[test]
    fn i38_connector_refuses_crabnebula_hosts_for_other_destinations() {
        let others = [
            Destination::AppDatabase,
            Destination::Vault,
            Destination::Custody,
            Destination::ControlPlane,
            Destination::Witness,
        ];
        for d in others {
            for h in [LICENCE_HOST, UPDATE_HOST, "LICENCES.fstp.crabnebula.dev."] {
                assert_eq!(check_host(&d, h), Err(EgressRefusal::CrabNebulaHost));
            }
            assert_eq!(check_host(&d, "db.cell.internal"), Ok(()));
        }
        let call = CnCall::Update(UpdateCheck {
            version: ProductVersion(0, 3, 0),
            channel: Channel::Stable,
        });
        let to = Destination::CrabNebula(call);
        assert_eq!(check_host(&to, UPDATE_HOST), Ok(()));
        assert_eq!(
            check_host(&to, LICENCE_HOST),
            Err(EgressRefusal::CrabNebulaHost)
        );
        assert_eq!(
            check_mode(Mode::Saas, &to),
            Err(EgressRefusal::SaasNeverReachesCrabNebula)
        );
    }
}
