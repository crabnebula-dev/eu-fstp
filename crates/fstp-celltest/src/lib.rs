//! The M3 isolation harness (M3 design section 14.3). Test only: never
//! published and never a dependency of a shipped crate (layering rule 9).
//!
//! It holds multi-cell worlds, the custody simulator, the software
//! authenticator, canaries, scanners, the egress recorder, independent
//! references, the models and the vault fact seeder (section 6.9).
//!
//! Lane W1a owns the harness files, and each W1 lane owns its `reference`
//! and `mc` files (design section 19). A part that waits for another lane
//! refuses with [`NotImplemented`] and names what it waits for. Nothing
//! here answers a check with an empty result, so no test passes on a
//! missing part.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

pub mod backups;
pub mod canary;
pub mod custody_sim;
pub mod cycle;
pub mod egress;
pub mod mc;
pub mod procmem;
pub mod reference;
pub mod relay;
pub mod scan;
pub mod seeded_vault;
pub mod soft_authn;
pub mod vault_seed;
pub mod world;
pub mod world_mail;
pub mod world_shell;

/// The refusal of a W0 stub. It names the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotImplemented {
    /// The operation that refused.
    pub operation: &'static str,
}

impl NotImplemented {
    /// The refusal of `operation`.
    pub const fn new(operation: &'static str) -> NotImplemented {
        NotImplemented { operation }
    }
}

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not implemented yet", self.operation)
    }
}

impl std::error::Error for NotImplemented {}
