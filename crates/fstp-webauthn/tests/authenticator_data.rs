//! Authenticator data, `fstp_webauthn::parse_authenticator_data`
//! (WebAuthn Level 2 section 6.1, ADR-008, design section 8.1, TH-26).
//!
//! The layout is the SHA-256 of the RP id (32 bytes), the flags (1 byte),
//! the signature counter (4 bytes, big-endian), then the attested
//! credential data when the AT flag is set, then the extensions when the
//! ED flag is set. The parser reads all of it and refuses any rest.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::authn::{Attested, HOST, Key, auth_data, flags};
use common::{assert_refused, refused};
use fstp_prop::{check, prop_assert_eq};
use fstp_webauthn::{AuthenticatorData, parse_authenticator_data};

/// The fields `parse_authenticator_data` must report for `bytes`.
fn fields(bytes: &[u8]) -> AuthenticatorData {
    AuthenticatorData {
        rp_id_hash: bytes[..32].try_into().unwrap(),
        flags: bytes[32],
        sign_count: u32::from_be_bytes(bytes[33..37].try_into().unwrap()),
    }
}

/// Registration authenticator data for `key` with the credential `id`.
fn attested(key: &Key, id: &[u8]) -> Vec<u8> {
    let cose = key.cose();
    let a = Attested {
        aaguid: [0; 16],
        id,
        cose: &cose,
    };
    auth_data(HOST, flags::UP | flags::UV | flags::AT, 0, Some(&a))
}

/// R-LG-01: assertion authenticator data (37 bytes, AT and ED clear)
/// decodes to its RP id hash, flags and counter.
#[test]
fn r_lg_01_auth_data_of_an_assertion_decodes() {
    let bytes = auth_data(HOST, flags::UP | flags::UV, 0x0102_0304, None);
    assert_eq!(bytes.len(), 37);
    let want = AuthenticatorData {
        rp_id_hash: fstp_crypto::sha256(HOST.as_bytes()),
        flags: flags::UP | flags::UV,
        sign_count: 0x0102_0304,
    };
    assert_eq!(parse_authenticator_data(&bytes), Ok(want));
}

/// R-LG-01: registration authenticator data with attested credential
/// data decodes, for ES256 and Ed25519 credential keys.
#[test]
fn r_lg_01_auth_data_with_attested_credential_decodes() {
    for key in [Key::es256(), Key::ed25519(1)] {
        let bytes = attested(&key, &[0xc1; 16]);
        assert_eq!(parse_authenticator_data(&bytes), Ok(fields(&bytes)));
    }
}

/// R-LG-01: the backup flags BE and BS of WebAuthn Level 3, which synced
/// passkeys set, do not make authenticator data invalid.
#[test]
fn r_lg_01_auth_data_backup_flags_are_accepted() {
    let bits = flags::UP | flags::UV | flags::BE | flags::BS;
    let bytes = auth_data(HOST, bits, 9, None);
    assert_eq!(parse_authenticator_data(&bytes), Ok(fields(&bytes)));
}

/// TH-26: every input shorter than 37 bytes is refused.
#[test]
fn th_26_auth_data_shorter_than_37_bytes_refused() {
    let full = auth_data(HOST, flags::UP, 1, None);
    for len in 0..37 {
        assert_refused(
            &format!("{len} bytes"),
            &parse_authenticator_data(&full[..len]),
        );
    }
}

/// ADR-008: bytes after the data the flags announce are refused, with AT
/// clear and after the attested credential key.
#[test]
fn adr008_auth_data_trailing_bytes_refused() {
    let mut plain = auth_data(HOST, flags::UP, 1, None);
    plain.push(0x00);
    assert_refused("38 bytes with AT clear", &parse_authenticator_data(&plain));
    let mut with_key = attested(&Key::ed25519(2), &[0xc1; 16]);
    with_key.push(0xa0);
    assert_refused(
        "a byte after the COSE key",
        &parse_authenticator_data(&with_key),
    );
}

/// ADR-008: attested credential data without the AT flag is refused, and
/// the AT flag without complete attested credential data is refused at
/// every truncation.
#[test]
fn adr008_auth_data_at_flag_and_credential_data_must_agree() {
    let full = attested(&Key::ed25519(3), &[0xc1; 16]);
    let mut no_at = full.clone();
    no_at[32] &= !flags::AT;
    assert_refused(
        "credential data with AT clear",
        &parse_authenticator_data(&no_at),
    );
    for len in 37..full.len() {
        assert_refused(
            &format!("AT with {len} of {} bytes", full.len()),
            &parse_authenticator_data(&full[..len]),
        );
    }
}

/// ADR-008: a credential id length beyond the data, or above 1023 bytes
/// (WebAuthn Level 3 section 6.5.1), is refused.
#[test]
fn adr008_auth_data_credential_id_length_is_bounded() {
    let key = Key::ed25519(4);
    let long = attested(&key, &[0xc1; 1024]);
    assert_refused("1024-byte credential id", &parse_authenticator_data(&long));
    let mut overlong = attested(&key, &[0xc1; 16]);
    // The length field follows the 37 fixed bytes and the 16-byte AAGUID.
    overlong[53..55].copy_from_slice(&0xffff_u16.to_be_bytes());
    assert_refused(
        "length beyond the data",
        &parse_authenticator_data(&overlong),
    );
    let max = attested(&key, &[0xc1; 1023]);
    assert_eq!(parse_authenticator_data(&max), Ok(fields(&max)));
}

/// ADR-008: the ED flag without extension data is refused, as is ED with
/// bytes that are not one CBOR map.
#[test]
fn adr008_auth_data_ed_flag_without_extensions_refused() {
    let bare = auth_data(HOST, flags::UP | flags::ED, 1, None);
    assert_refused("ED with nothing after", &parse_authenticator_data(&bare));
    let mut not_a_map = bare.clone();
    not_a_map.push(0x01);
    assert_refused("ED with an integer", &parse_authenticator_data(&not_a_map));
}

/// ADR-008: the attested credential key must be strict CBOR. A key with a
/// non-shortest head inside authenticator data is refused.
#[test]
fn adr008_auth_data_attested_key_must_be_strict_cbor() {
    let mut cose = Key::ed25519(6).cose();
    assert_eq!(cose[1], 0x01);
    cose.splice(1..2, [0x18, 0x01]);
    let a = Attested {
        aaguid: [0; 16],
        id: &[0xc1; 16],
        cose: &cose,
    };
    let bytes = auth_data(HOST, flags::UP | flags::AT, 0, Some(&a));
    assert_refused("non-shortest COSE label", &parse_authenticator_data(&bytes));
}

/// R-LG-01: any 37 bytes with AT and ED clear decode to exactly their
/// fields, whatever the hash, the UP, UV, BE and BS flags and the
/// counter. The reserved bits 0x02 and 0x20 stay clear, since whether a
/// strict parser refuses them is not settled (lane report).
#[test]
fn r_lg_01_auth_data_fixed_part_round_trips() {
    check("r_lg_01_auth_data_fixed_part_round_trips", |g| {
        let mut bytes = g.bytes(37..=37);
        bytes[32] &= flags::UP | flags::UV | flags::BE | flags::BS;
        g.note("input", &bytes);
        prop_assert_eq!(parse_authenticator_data(&bytes), Ok(fields(&bytes)));
        Ok(())
    });
}

/// TH-26: one changed byte of registration authenticator data is either
/// refused for a real reason, or decodes to the fields of its first 37
/// bytes.
#[test]
fn th_26_auth_data_mutation_is_refused_or_decodes_its_fields() {
    let base = attested(&Key::es256(), &[0xc1; 20]);
    check(
        "th_26_auth_data_mutation_is_refused_or_decodes_its_fields",
        |g| {
            let mut bytes = base.clone();
            let at = g.usize_in(0..=bytes.len() - 1);
            bytes[at] ^= g.u8_in(1..=255);
            g.note("input", &bytes);
            match parse_authenticator_data(&bytes) {
                Ok(got) => {
                    prop_assert_eq!(got, fields(&bytes));
                    Ok(())
                }
                other => refused("mutated authenticator data", &other),
            }
        },
    );
}
