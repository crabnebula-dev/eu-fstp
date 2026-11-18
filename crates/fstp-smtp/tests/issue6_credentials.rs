//! Issue 6 L8: `Credentials::try_new` refuses what AUTH PLAIN cannot carry.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fstp_smtp::client::{Credentials, CredentialsError, MAX_CREDENTIAL_LEN};

#[test]
fn issue6_l8_try_new_refuses_nul_crlf_and_bad_lengths() {
    assert!(Credentials::try_new("demo", "secret").is_ok());
    assert!(Credentials::try_new(&"u".repeat(MAX_CREDENTIAL_LEN), "p").is_ok());
    for (u, p, want) in [
        ("", "p", CredentialsError::Length),
        ("u", "", CredentialsError::Length),
        (
            &"u".repeat(MAX_CREDENTIAL_LEN + 1),
            "p",
            CredentialsError::Length,
        ),
        (
            "u",
            &"p".repeat(MAX_CREDENTIAL_LEN + 1),
            CredentialsError::Length,
        ),
        ("u\0x", "p", CredentialsError::Byte),
        ("u", "p\0x", CredentialsError::Byte),
        ("u\r\nAUTH", "p", CredentialsError::Byte),
        ("u", "p\n", CredentialsError::Byte),
    ] {
        assert_eq!(Credentials::try_new(u, p).unwrap_err(), want, "{u:?} {p:?}");
    }
}
