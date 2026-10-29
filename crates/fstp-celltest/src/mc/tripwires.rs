//! Measured state counts of the M3 models (design sections 14.1 and 19).
//!
//! Each model runs exhaustively under a `max_states` tripwire at twice its
//! measured count, as in M2. Lane W4 records each measured count here.
//!
//! Status: M-AUTH, M-STEPUP and M-RECOVER were measured by the lead on
//! 2026-10-29 after lane W1b merged. M-VCP and M-DRIVER followed lane W1c,
//! M-SHRED lane W1d, M-AUDIT lane W1e and M-LICENCE lane W1g. Every other
//! count is [`NOT_MEASURED`], which is zero. A tripwire of zero states
//! stops every run at once, so no model can pass on a placeholder.

/// The placeholder for a count that is not measured yet.
pub const NOT_MEASURED: usize = 0;

/// M-AUTH (I-77).
pub const M_AUTH: usize = 1905;
/// M-STEPUP (I-78).
pub const M_STEPUP: usize = 13184;
/// M-RECOVER (I-79).
pub const M_RECOVER: usize = 5006;
/// M-VCP (I-04, I-06, I-18, NOTE 4).
pub const M_VCP: usize = 33796;
/// M-DRIVER (I-23).
pub const M_DRIVER: usize = 2262;
/// M-SHRED (I-81).
pub const M_SHRED: usize = 99514;
/// M-AUDIT (I-24).
pub const M_AUDIT: usize = 90834;
/// M-PLACE (I-82, I-83).
pub const M_PLACE: usize = NOT_MEASURED;
/// M-LICENCE (I-39).
pub const M_LICENCE: usize = 1425;

/// The tripwire for a measured count: twice the count.
pub const fn tripwire(measured: usize) -> usize {
    measured.saturating_mul(2)
}
