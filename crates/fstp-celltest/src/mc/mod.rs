//! The M3 models (design section 14.2). Each model drives a production
//! pure core. Each W1 lane owns its model files; `tripwires` holds the
//! measured state counts.

pub mod audit_model;
pub mod auth_model;
pub mod driver_model;
pub mod licence_model;
pub mod place_model;
pub mod recover_model;
pub mod shred_model;
pub mod stepup_model;
pub mod tripwires;
pub mod vcp_model;
