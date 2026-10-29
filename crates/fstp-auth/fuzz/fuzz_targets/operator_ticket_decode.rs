//! Fuzz target `operator_ticket_decode` of `fstp-auth` (TH-26, H-05, M3 design section 15).
//!
//! The operator ticket is a parser added by lane W2b (ADR-008
//! "Recovery"), so it gets a target from its first commit
//! (`.claude/CLAUDE.md`). Checks: no panic; constant length only; an
//! accepted ticket re-encodes byte for byte; verification under a key of
//! the wrong length is refused without a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = fstp_auth::codec::decode_operator_ticket(data);
    let shown = format!("{got:?}");
    assert!(!shown.is_empty());
    if let Ok(signed) = got {
        assert_eq!(
            data.len(),
            fstp_auth::codec::TICKET_LEN,
            "accepted a ticket of another length"
        );
        let again = fstp_auth::codec::encode_operator_ticket(&signed.ticket, &signed.signature);
        assert_eq!(again.as_deref(), Ok(data), "the ticket does not re-encode");
    }
    assert!(fstp_auth::recovery::verify_ticket(data, &[0u8; 7]).is_err());
});
