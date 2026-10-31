//! Fuzz target `session_cookie_decode` of `fstp-auth` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; round trip; constant-length tokens only.
//!
//! ADR-008: the cookie value is the 16-byte cell id followed by the
//! 32-byte token. The target checks that an accepted input is exactly 48
//! bytes, that the decoded fields hold them unchanged by position, and
//! that `encode_session_cookie` gives the input bytes back. `Debug` of a
//! cookie redacts the token, so the formatted result never shows it.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The cell id length.
const CELL_LEN: usize = 16;
/// ADR-008: the cookie value length, cell id and token.
const COOKIE_LEN: usize = CELL_LEN + 32;

fuzz_target!(|data: &[u8]| {
    let got = fstp_auth::codec::decode_session_cookie(data);
    let shown = format!("{got:?}");
    assert!(!shown.is_empty());
    if let Ok(cookie) = got {
        assert_eq!(
            data.len(),
            COOKIE_LEN,
            "accepted a cookie of another length"
        );
        let (cell, token) = data.split_at(CELL_LEN);
        assert_eq!(
            &cookie.session[..],
            cell,
            "the cell id does not hold its input"
        );
        assert_eq!(&cookie.tag[..], token, "the token does not hold its input");
        let bytes = fstp_auth::codec::encode_session_cookie(&cookie);
        assert_eq!(&bytes[..], data, "the cookie does not re-encode");
    }
});
