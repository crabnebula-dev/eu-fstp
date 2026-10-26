//! Placeholder from milestone M2 step W0, so the `tests/` directory exists.
//!
//! The invariant suites land here from step W3 on, one file per invariant
//! group, named after their identifiers (design section 6.1). Lane W2 may
//! delete this file once its harness self-tests land.

/// Links every crate the suites test, so a broken module tree fails here.
#[test]
fn testkit_links_every_domain_crate() {
    use fstp_domain as _;
    use fstp_domain_testkit as _;
    use fstp_engine as _;
    use fstp_findings as _;
    use fstp_ledger as _;
    use fstp_money as _;
}
