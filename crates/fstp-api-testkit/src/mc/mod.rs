//! The M4 models (M4 design section 8.5). State explored by `fstp-mc` uses
//! `BTreeMap` and `BTreeSet` (rule A10). Module list from M4 step W0. Each
//! lane owns its own file. M-BALLOT lives in `fstp-domain-testkit`.

pub mod activate_model;
pub mod import_model;
pub mod oauth_model;
pub mod parity_model;
pub mod prep_model;
pub mod public_model;
