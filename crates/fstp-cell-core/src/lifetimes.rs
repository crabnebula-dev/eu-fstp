//! The token lifetimes that ADR-008 "Unset lifetimes" leaves open (design
//! sections 8.3 and 8.5). `SPEC/` sets none: P-71 is the step-up
//! freshness and P-72 the session lifetimes, and neither covers these
//! tokens.
//!
//! Each value below is Interim, pending Daniel. ADR-008 lists them under
//! that open point as a proposal. A route or a check that needs one reads
//! it from here, so the amendment changes one place.

/// One minute, in microseconds.
const MINUTE_US: i64 = 60 * 1_000_000;

/// One hour, in microseconds.
const HOUR_US: i64 = 60 * MINUTE_US;

/// How long a magic link stays valid: 15 minutes. Interim, pending
/// Daniel (ADR-008 "Unset lifetimes").
pub const MAGIC_LINK_US: i64 = 15 * MINUTE_US;

/// How long a recovery enrolment token stays valid: 24 hours. Interim,
/// pending Daniel (ADR-008 "Unset lifetimes").
pub const RECOVERY_ENROLMENT_TOKEN_US: i64 = 24 * HOUR_US;

/// How long a recovery case stays open: 72 hours, as the invitation
/// lifetime of ADR-008. Interim, pending Daniel (ADR-008 "Unset
/// lifetimes").
pub const RECOVERY_CASE_US: i64 = 72 * HOUR_US;

/// How long a staff assertion of the operator process stays valid: 15
/// minutes. Interim, pending Daniel (ADR-008 "Unset lifetimes").
pub const STAFF_ASSERTION_US: i64 = 15 * MINUTE_US;

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-008 "Unset lifetimes" (interim): the proposed values, so a
    /// change to one is a visible change to this test and to the ADR.
    #[test]
    fn adr008_interim_token_lifetimes_are_the_proposed_values() {
        assert_eq!(MAGIC_LINK_US, 900_000_000);
        assert_eq!(RECOVERY_ENROLMENT_TOKEN_US, 86_400_000_000);
        assert_eq!(RECOVERY_CASE_US, 259_200_000_000);
        assert_eq!(STAFF_ASSERTION_US, 900_000_000);
    }
}
