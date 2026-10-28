//! Account recovery (I-79, ADR-008 Recovery, Q15).

use crate::{AuthError, AuthRecord};

/// The recovery path an account must take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPath {
    /// Receiving roles only, or no role: email proof, then a new passkey.
    EmailThenPasskey,
    /// Another tenant admin approves with a step-up.
    SecondAdmin,
    /// The sole tenant admin of a SaaS cell: an operator ticket.
    OperatorProcess,
    /// The sole tenant admin of a self-hosted cell: a host console command.
    HostConsole,
}

/// The role holdings that decide the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holdings {
    /// Receiving roles only, or no role.
    ReceivingOnly,
    /// A role outside Receiving.
    Management,
    /// The tenant admin role.
    TenantAdmin,
}

/// How the cell is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deployment {
    /// Hosted by CrabNebula.
    Saas,
    /// Self-hosted.
    SelfHosted,
}

/// The path for an account, decided at request time and again at
/// completion.
pub fn recovery_path(
    holdings: Holdings,
    other_admins: usize,
    mode: Deployment,
) -> Result<RecoveryPath, AuthError> {
    let _ = (holdings, other_admins, mode);
    Err(AuthError::NotImplemented(
        "fstp_auth::recovery::recovery_path",
    ))
}

/// Completes a recovery: revokes every credential and ends every session.
pub fn complete(path: RecoveryPath) -> Result<Vec<AuthRecord>, AuthError> {
    let _ = path;
    Err(AuthError::NotImplemented("fstp_auth::recovery::complete"))
}
