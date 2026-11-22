//! The setup gate (ADR-021, decided by Daniel on 2026-11-14).
//!
//! Until a second tenant admin approves the activation of the
//! organisation (SoD-18), the cell refuses every command, read and grant
//! outside tenant onboarding. Dispatch asks [`setup_admits`] after the
//! session strength and channel rules, before rate limits and any dry
//! run, and refuses what it does not admit under [`SETUP_RULE`].
//!
//! - Any caller keeps the account security operations
//!   ([`ACCOUNT_SECURITY_OPS`]). Reading: R-LG-04 says users can see and
//!   end their sessions and linked devices, and it ranks above the ADR.
//! - Any caller keeps its personal display preferences
//!   ([`PERSONAL_PREFERENCE_OPS`]): the theme choice of ADR-030.
//! - A tenant admin keeps the onboarding operations ([`onboarding_op`]):
//!   every `tenant.*` operation and the onboarding approvals. The grants
//!   among them are the second tenant admin and the Financial and Legal
//!   signatories (SoD-14, SoD-15).
//! - A tenant admin keeps its own roles and verification
//!   ([`ADMIN_OWN_OPS`]). Reading: the home page reads the roles, and
//!   completion needs two verified admins.
//!
//! An admitted operation is then judged by its own rules.

use crate::principal::Principal;
use crate::registry::OpSpec;

/// The rule a refusal of the setup gate names.
pub const SETUP_RULE: &str = "ADR-021";

/// The operations every caller keeps before activation (R-LG-04): its
/// own sessions and passkeys.
pub const ACCOUNT_SECURITY_OPS: [&str; 3] = ["me.sessions", "me.end_session", "me.add_passkey"];

/// The personal display preferences every caller keeps before activation:
/// the theme choice (ADR-030, lead reading of 2026-11-22). It is no
/// organisation data, so the setup gate has nothing to hold it for.
pub const PERSONAL_PREFERENCE_OPS: [&str; 1] = ["me.set_theme"];

/// The admin operations of onboarding besides the `tenant.*` ones: the
/// approval list, the SoD-07 self-grant approval and account recovery.
pub const ONBOARDING_ADMIN_OPS: [&str; 3] = [
    "admin.approvals",
    "admin.approve_self_grant",
    "admin.approve_recovery",
];

/// A tenant admin's own operations before activation: its roles for the
/// home page, and its own verification, since completion needs two
/// verified admins.
pub const ADMIN_OWN_OPS: [&str; 3] = ["me.roles", "me.get_verification", "me.begin_verification"];

/// Whether `name` is an operation of tenant onboarding: a `tenant.*`
/// operation or an onboarding approval.
pub fn onboarding_op(name: &str) -> bool {
    name.starts_with("tenant.") || ONBOARDING_ADMIN_OPS.contains(&name)
}

/// Whether the setup gate admits `op` for `p` while the organisation is
/// not yet activated (ADR-021).
pub fn setup_admits(op: &OpSpec, p: &Principal) -> bool {
    ACCOUNT_SECURITY_OPS.contains(&op.name)
        || PERSONAL_PREFERENCE_OPS.contains(&op.name)
        || (p.tenant_admin() && (onboarding_op(op.name) || ADMIN_OWN_OPS.contains(&op.name)))
}
