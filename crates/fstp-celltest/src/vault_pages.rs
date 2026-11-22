//! The loader pages of a world cell's vault origin (ADR-009 "Vault
//! origin" and "Delivery", M3 design section 11.2, lane
//! m3/devstack-scenarios). Test only.
//!
//! The loader itself is the shipped vault's (`fstp_vault::pages`, ADR-004
//! record of lane L13b). The world reads the repository tree with
//! [`VaultPages::load`] and serves it on its seeded vault's origin.

pub use fstp_vault::pages::{LOADER_CSP, MAX_FILE, PageReply, SHELL_PATHS, VaultPages};
