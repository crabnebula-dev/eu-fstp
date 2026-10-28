//! Tenant commands and records: tenant admin grants, the SoD-07 self-grant
//! approval and the login policy (design section 5.1).

use fstp_domain::id::AccountId;

/// A tenant command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantCommand {
    /// Grant the tenant admin role.
    GrantTenantAdmin {
        /// The account.
        account: AccountId,
    },
    /// End the tenant admin role.
    EndTenantAdmin {
        /// The account.
        account: AccountId,
    },
    /// A second tenant admin approves a self-grant (SoD-07).
    ApproveSelfGrant {
        /// SHA-256 over the canonical grant and its command id.
        grant_digest: [u8; 32],
    },
    /// Set the login policy (P-70 to P-72).
    SetLoginPolicy {
        /// The policy, canonical.
        policy: Vec<u8>,
    },
}

/// A tenant record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantRecord {
    /// The tenant admin role was granted.
    TenantAdminGranted {
        /// The account.
        account: AccountId,
    },
    /// The tenant admin role ended.
    TenantAdminEnded {
        /// The account.
        account: AccountId,
    },
    /// A self-grant was approved.
    SelfGrantApproved {
        /// The approving admin.
        approver: AccountId,
        /// The grant digest.
        grant_digest: [u8; 32],
        /// UTC microseconds after which the approval lapses.
        expires_at: i64,
    },
    /// A self-grant approval was used by its grant.
    SelfGrantApprovalUsed {
        /// The grant digest.
        grant_digest: [u8; 32],
    },
    /// The login policy changed.
    LoginPolicySet {
        /// The policy, canonical.
        policy: Vec<u8>,
    },
}
