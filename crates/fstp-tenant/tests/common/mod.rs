//! Shared parts of the `fstp-tenant` test binaries (M4 design sections
//! 3.5, 8.8 and 13, lane W2d).
//!
//! - [`vocab`]: the test vocabulary. Tests state operations and
//!   observations in it, so they never name a production type that the W0
//!   stub lacks.
//! - [`reference`]: an independent reference of tenant onboarding, the
//!   admin set, the tenant settings, the tenant defaults and the inference
//!   record. It is written from `SPEC/02-domain/programme-creator.md`,
//!   `roles-and-sod.md`, `policy-parameters.md` and design section 3.5,
//!   not from the production code.
//! - [`prod`]: the one adapter over the production API. Every test reaches
//!   `fstp-tenant` through it. Each call that the W0 stub lacks returns
//!   `TenantError::NotImplemented` with a seam message that names the
//!   missing API, so a test that needs it is red for that reason only.
//! - [`gens`]: generators of operations and inputs.
//! - [`machine`]: the state machine that runs the reference and the
//!   adapter side by side.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "a shared test module: each test binary uses part of it"
)]

pub mod gens;
pub mod machine;
pub mod prod;
pub mod reference;
pub mod vocab;

use fstp_tenant::TenantError;

use crate::common::prod::{Outcome, Sut};
use crate::common::vocab::{Env, Op, Verdict};

/// Runs `ops` in order from the genesis of `env`, and returns the system
/// under test with each outcome.
pub fn drive(env: &Env, ops: &[Op]) -> Result<(Sut, Vec<Outcome>), TenantError> {
    let mut sut = Sut::genesis(env)?;
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        out.push(sut.run(op)?);
    }
    Ok((sut, out))
}

/// Runs `ops` and fails with the step and the operation when one of them
/// is not accepted. Setup sequences of the properties use it.
pub fn setup(env: &Env, ops: &[Op]) -> Result<Sut, String> {
    let mut sut = Sut::genesis(env).map_err(|e| e.to_string())?;
    for (i, op) in ops.iter().enumerate() {
        let o = sut.run(op).map_err(|e| e.to_string())?;
        if o.verdict != Verdict::Accepted {
            return Err(format!("setup step {i} was refused: {op:?}"));
        }
    }
    Ok(sut)
}
