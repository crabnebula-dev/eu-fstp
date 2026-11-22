//! Fuzz target `admin_config_decode` of `fstp-admin` (TH-26, H-05,
//! ADR-028 "One configuration file", R-NF-02). Lane L19.
//!
//! Design checks: no panic; limits enforced; deterministic. A decoded
//! configuration names a valid domain and email, absolute paths, and a
//! port range that holds the public port outside it. A refusal names a
//! member of printable ASCII, at most 40 characters for an unknown one.

#![no_main]

use fstp_admin::config::{MAX_CONFIG_LEN, PORT_SPAN, decode, is_email, is_host_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode(data);
    assert_eq!(first, decode(data), "not deterministic");
    match first {
        Ok(c) => {
            assert!(data.len() <= MAX_CONFIG_LEN);
            assert!(is_host_name(&c.domain));
            assert!(is_email(&c.operator_email));
            for p in [
                &c.paths.bin,
                &c.paths.etc,
                &c.paths.state,
                &c.paths.share,
                &c.paths.pg_bin,
            ] {
                assert!(p.is_absolute());
            }
            let end = c.base_port.checked_add(PORT_SPAN).expect("port range");
            assert!(!(c.base_port..end).contains(&c.public_port));
            assert!(
                c.custody_simulator.is_none() || c.services == fstp_admin::config::Services::Direct
            );
        }
        Err(e) => {
            assert!(e.field.bytes().all(|b| b.is_ascii_graphic()));
            assert!(e.field.len() <= 120);
        }
    }
});
