//! TH-26 and design section 15: the auth codecs round-trip, give every
//! value one spelling and refuse what they do not accept. B11: a cookie
//! of another cell is refused before any lookup.
//!
//! Lane W2b implementer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::codec::{
    CodecError, MAX_CREDENTIAL_LEN, SessionCookie, TICKET_LEN, Token, decode_auth_command,
    decode_auth_record, decode_operator_ticket, decode_session_cookie, decode_session_cookie_for,
    decode_token, encode_auth_command, encode_auth_record, encode_operator_ticket,
    encode_session_cookie, encode_token,
};
use fstp_auth::recovery::{OperatorTicket, RecoveryPath, StaffRef};
use fstp_auth::{AuthCommand, AuthRecord};
use fstp_domain::id::AccountId;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_webauthn::CoseKey;

fn arr16(g: &mut Gen) -> [u8; 16] {
    g.bytes(16..=16).try_into().unwrap()
}

fn arr32(g: &mut Gen) -> [u8; 32] {
    g.bytes(32..=32).try_into().unwrap()
}

fn account(g: &mut Gen) -> AccountId {
    AccountId::from_raw(if g.bool() {
        u128::from(g.u64())
    } else {
        *g.pick(&[0, 1, u128::MAX])
    })
}

fn credential(g: &mut Gen) -> Vec<u8> {
    let n = if g.bool() {
        g.usize_in(1..=40)
    } else {
        *g.pick(&[1, MAX_CREDENTIAL_LEN])
    };
    g.bytes(n..=n)
}

/// The P-256 base point, a valid ES256 key.
const P256_G_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_G_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// A COSE key of each admitted algorithm. An RSA modulus is odd, has no
/// leading zero octet and is 256 to 1024 octets long.
fn key(g: &mut Gen) -> CoseKey {
    match g.u8_in(0..=2) {
        0 => CoseKey::Ed25519 { x: arr32(g) },
        1 => CoseKey::Es256 {
            x: P256_G_X,
            y: P256_G_Y,
        },
        _ => {
            let len = *g.pick(&[256, 384, 512, 1024]);
            let mut n = g.bytes(len..=len);
            n[0] |= 0x80;
            n[len - 1] |= 0x01;
            let e = g.pick(&[vec![3], vec![1, 0, 1]]).clone();
            CoseKey::Rs256 { n, e }
        }
    }
}

fn path(g: &mut Gen) -> RecoveryPath {
    *g.pick(&RecoveryPath::ALL)
}

fn record(g: &mut Gen) -> AuthRecord {
    match g.u8_in(0..=12) {
        0 => AuthRecord::CredentialRegistered {
            account: account(g),
            credential: credential(g),
            key: key(g),
            user_verified: g.bool(),
        },
        1 => AuthRecord::StepUpGranted {
            id: arr16(g),
            action_digest: arr32(g),
            session: arr16(g),
        },
        2 => AuthRecord::SessionEnded { session: arr16(g) },
        3 => AuthRecord::CredentialRevoked {
            account: account(g),
            credential: credential(g),
        },
        4 => AuthRecord::CredentialSuspect {
            account: account(g),
            credential: credential(g),
        },
        5 => AuthRecord::StepUpConsumed { id: arr16(g) },
        6 => AuthRecord::RecoveryRequested {
            case: arr16(g),
            account: account(g),
            path: path(g),
        },
        7 => AuthRecord::RecoveryEmailProven { case: arr16(g) },
        8 => AuthRecord::RecoveryApproved {
            case: arr16(g),
            approver: account(g),
        },
        9 => {
            let path = path(g);
            AuthRecord::RecoveryCompleted {
                case: arr16(g),
                account: account(g),
                path,
                shown_to_tenant: path.shown_to_tenant(),
            }
        }
        10 => {
            let first_admin = g.bool();
            AuthRecord::InvitationIssued {
                invitation: arr16(g),
                account: account(g),
                token_digest: arr32(g),
                first_admin,
                split: first_admin && g.bool(),
            }
        }
        11 => AuthRecord::InvitationConsumed {
            invitation: arr16(g),
        },
        _ => AuthRecord::FirstAdminEnrolled {
            account: account(g),
        },
    }
}

fn command(g: &mut Gen) -> AuthCommand {
    match g.u8_in(0..=7) {
        0 => AuthCommand::RegisterCredential {
            account: account(g),
            credential: credential(g),
        },
        1 => AuthCommand::RevokeCredential {
            account: account(g),
            credential: credential(g),
        },
        2 => AuthCommand::GrantStepUp {
            session: arr16(g),
            action_digest: arr32(g),
        },
        3 => AuthCommand::EndSession { session: arr16(g) },
        4 => AuthCommand::RequestRecovery {
            case: arr16(g),
            account: account(g),
        },
        5 => AuthCommand::ProveRecoveryEmail { case: arr16(g) },
        6 => AuthCommand::ApproveRecovery { case: arr16(g) },
        _ => AuthCommand::CompleteRecovery {
            case: arr16(g),
            credential: credential(g),
        },
    }
}

/// TH-26, design section 15: every auth record encodes, and decodes back
/// to itself.
#[test]
fn th_26_every_auth_record_round_trips() {
    check("th_26_every_auth_record_round_trips", |g: &mut Gen| {
        let r = record(g);
        let bytes = encode_auth_record(&r).map_err(|e| format!("{r:?}: {e:?}"))?;
        prop_assert_eq!(decode_auth_record(&bytes), Ok(r));
        Ok(())
    });
}

/// TH-26, design section 15: every auth command encodes, and decodes
/// back to itself.
#[test]
fn th_26_every_auth_command_round_trips() {
    check("th_26_every_auth_command_round_trips", |g: &mut Gen| {
        let c = command(g);
        let bytes = encode_auth_command(&c).map_err(|e| format!("{c:?}: {e:?}"))?;
        prop_assert_eq!(decode_auth_command(&bytes), Ok(c));
        Ok(())
    });
}

/// TH-26, I-23: a record has one spelling. A one-byte change of a valid
/// encoding either is refused or decodes to a record that re-encodes to
/// exactly the changed bytes.
#[test]
fn th_26_accepted_record_bytes_re_encode_byte_for_byte() {
    check(
        "th_26_accepted_record_bytes_re_encode_byte_for_byte",
        |g: &mut Gen| {
            let mut bytes = encode_auth_record(&record(g)).map_err(|e| format!("{e:?}"))?;
            let i = g.usize_in(0..=bytes.len() - 1);
            bytes[i] = g.u8();
            if let Ok(r) = decode_auth_record(&bytes) {
                prop_assert_eq!(encode_auth_record(&r), Ok(bytes));
            }
            Ok(())
        },
    );
}

/// TH-26: whitespace, reordered members, an unknown member, a missing
/// member, upper-case hexadecimal and a non-canonical id are refused.
#[test]
fn th_26_non_canonical_and_off_schema_records_refused() {
    let good = br#"{"session":"00000000000000000000000000000000","type":"SessionEnded"}"#;
    assert!(decode_auth_record(good).is_ok());
    for bad in [
        &br#"{ "session":"00000000000000000000000000000000","type":"SessionEnded"}"#[..],
        br#"{"type":"SessionEnded","session":"00000000000000000000000000000000"}"#,
        br#"{"extra":"","session":"00000000000000000000000000000000","type":"SessionEnded"}"#,
        br#"{"type":"SessionEnded"}"#,
        br#"{"session":"0000000000000000000000000000000A","type":"SessionEnded"}"#,
        br#"{"session":"000000000000000000000000000000","type":"SessionEnded"}"#,
        br#"{"account":"01","type":"FirstAdminEnrolled"}"#,
        br#"{"account":"-1","type":"FirstAdminEnrolled"}"#,
        br#"{"account":1,"type":"FirstAdminEnrolled"}"#,
        br#"{"account":"340282366920938463463374607431768211456","type":"FirstAdminEnrolled"}"#,
        br#"{"type":"NoSuchRecord"}"#,
        br#"[]"#,
    ] {
        assert!(
            decode_auth_record(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// TH-26: a credential id is 1 to 1023 bytes, in the encoder and the
/// decoder.
#[test]
fn th_26_credential_id_length_is_bounded() {
    let r = |n: usize| AuthRecord::CredentialRegistered {
        account: AccountId::from_raw(1),
        credential: vec![7; n],
        key: CoseKey::Ed25519 { x: [9; 32] },
        user_verified: true,
    };
    assert!(encode_auth_record(&r(MAX_CREDENTIAL_LEN)).is_ok());
    assert!(encode_auth_record(&r(MAX_CREDENTIAL_LEN + 1)).is_err());
    assert!(encode_auth_record(&r(0)).is_err());
}

/// ADR-008, design section 15: a token re-encodes to its bytes.
#[test]
fn adr008_token_round_trips() {
    check("adr008_token_round_trips", |g: &mut Gen| {
        let t = Token(arr32(g));
        prop_assert_eq!(decode_token(&encode_token(&t)), Ok(t));
        Ok(())
    });
}

/// B11, ADR-008: a cookie re-encodes byte for byte, and a cookie of
/// another cell is refused.
#[test]
fn b11_cookie_round_trips_and_another_cell_is_refused() {
    check(
        "b11_cookie_round_trips_and_another_cell_is_refused",
        |g: &mut Gen| {
            let cell = arr16(g);
            let other = arr16(g);
            let c = SessionCookie::new(cell, Token(arr32(g)));
            let bytes = encode_session_cookie(&c);
            prop_assert_eq!(decode_session_cookie(&bytes), Ok(c.clone()));
            prop_assert_eq!(decode_session_cookie_for(&bytes, cell), Ok(c));
            if other != cell {
                prop_assert_eq!(
                    decode_session_cookie_for(&bytes, other),
                    Err(CodecError::OtherCell)
                );
            }
            Ok(())
        },
    );
}

/// TH-26, I-20: an operator ticket has one constant length and names only
/// the case reference and two staff references. Its decoder keeps them
/// and the signature unchanged.
#[test]
fn th_26_operator_ticket_round_trips_at_one_length() {
    check(
        "th_26_operator_ticket_round_trips_at_one_length",
        |g: &mut Gen| {
            let t = OperatorTicket {
                case: arr16(g),
                staff_1: StaffRef(arr16(g)),
                staff_2: StaffRef(arr16(g)),
            };
            let sig = g.bytes(TICKET_LEN - 48..=TICKET_LEN - 48);
            let bytes = encode_operator_ticket(&t, &sig).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(bytes.len(), TICKET_LEN);
            let back = decode_operator_ticket(&bytes).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(back.ticket, t);
            prop_assert_eq!(back.signature, sig);
            let n = g.usize_in(0..=TICKET_LEN + 8);
            if n != TICKET_LEN {
                prop_assert!(decode_operator_ticket(&vec![0; n]).is_err(), "{n} bytes");
            }
            Ok(())
        },
    );
}

/// TH-26: a command has one spelling. A one-byte change of a valid
/// encoding either is refused or decodes to a command that re-encodes to
/// exactly the changed bytes.
#[test]
fn th_26_accepted_command_bytes_re_encode_byte_for_byte() {
    check(
        "th_26_accepted_command_bytes_re_encode_byte_for_byte",
        |g: &mut Gen| {
            let mut bytes = encode_auth_command(&command(g)).map_err(|e| format!("{e:?}"))?;
            let i = g.usize_in(0..=bytes.len() - 1);
            bytes[i] = g.u8();
            if let Ok(c) = decode_auth_command(&bytes) {
                prop_assert_eq!(encode_auth_command(&c), Ok(bytes));
            }
            Ok(())
        },
    );
}

/// `authentication.md` "Account recovery": the operator and host console
/// completions are shown to the tenant. The member follows the path, so a
/// record that hides an operator completion is refused, and so is the
/// reverse. Regression for the free `shown_to_tenant` member.
#[test]
fn i79_recovery_completed_shown_to_tenant_follows_the_path() {
    let case = "00000000000000000000000000000000";
    for path in RecoveryPath::ALL {
        for shown in [false, true] {
            let name = format!("{path:?}");
            let text = format!(
                "{{\"account\":\"5\",\"case\":\"{case}\",\"path\":\"{name}\",\
                 \"shown_to_tenant\":{shown},\"type\":\"RecoveryCompleted\"}}"
            );
            let got = decode_auth_record(text.as_bytes());
            if shown == path.shown_to_tenant() {
                assert!(got.is_ok(), "{text}: {got:?}");
            } else {
                assert_eq!(got, Err(CodecError::Schema("shown_to_tenant")), "{text}");
            }
        }
    }
}

/// Design section 4.2, ADR-008 "User verification": the registration
/// record carries the canonical COSE key and the UV flag. A key in another
/// map order, a key `parse_cose_key` refuses, or a record without the key
/// or the flag is refused.
#[test]
fn adr008_credential_registered_key_has_one_spelling() {
    let x = "11".repeat(32);
    let rec = |key: &str, uv: &str| {
        format!(
            "{{\"account\":\"5\",\"credential\":\"c1c1\",\"public_key\":\"{key}\",\
             \"type\":\"CredentialRegistered\",\"user_verified\":{uv}}}"
        )
    };
    let canonical = format!("a401010327200621 5820{x}").replace(' ', "");
    let got = decode_auth_record(rec(&canonical, "true").as_bytes());
    assert_eq!(
        got,
        Ok(AuthRecord::CredentialRegistered {
            account: AccountId::from_raw(5),
            credential: vec![0xc1, 0xc1],
            key: CoseKey::Ed25519 { x: [0x11; 32] },
            user_verified: true,
        })
    );
    // The same key with `alg` before `kty`.
    let reordered = format!("a403270101200621 5820{x}").replace(' ', "");
    assert_eq!(
        decode_auth_record(rec(&reordered, "true").as_bytes()),
        Err(CodecError::Schema("public_key"))
    );
    // An OKP key on another curve.
    let other_curve = format!("a401010327200721 5820{x}").replace(' ', "");
    assert_eq!(
        decode_auth_record(rec(&other_curve, "true").as_bytes()),
        Err(CodecError::Schema("public_key"))
    );
    assert!(decode_auth_record(rec(&canonical, "1").as_bytes()).is_err());
    let no_flag = format!(
        "{{\"account\":\"5\",\"credential\":\"c1c1\",\"public_key\":\"{canonical}\",\
         \"type\":\"CredentialRegistered\"}}"
    );
    assert!(decode_auth_record(no_flag.as_bytes()).is_err());
    let no_key = "{\"account\":\"5\",\"credential\":\"c1c1\",\
                  \"type\":\"CredentialRegistered\",\"user_verified\":true}";
    assert!(decode_auth_record(no_key.as_bytes()).is_err());
}

/// Q35, ADR-008 "First admin delivery": only the first admin's invitation
/// is split, so the decoder refuses a split invitation of anyone else.
#[test]
fn adr008_split_invitation_is_the_first_admins() {
    let rec = |first: bool, split: bool| {
        format!(
            "{{\"account\":\"5\",\"first_admin\":{first},\"invitation\":\"{}\",\
             \"split\":{split},\"token_digest\":\"{}\",\"type\":\"InvitationIssued\"}}",
            "00".repeat(16),
            "00".repeat(32)
        )
    };
    assert!(decode_auth_record(rec(false, false).as_bytes()).is_ok());
    assert!(decode_auth_record(rec(true, false).as_bytes()).is_ok());
    assert!(decode_auth_record(rec(true, true).as_bytes()).is_ok());
    assert_eq!(
        decode_auth_record(rec(false, true).as_bytes()),
        Err(CodecError::Schema("split"))
    );
}

/// ADR-008 "Sessions", R-NF-02: `Debug` of a token or a cookie never
/// shows the token bytes, and equality still tells tokens apart.
#[test]
fn adr008_token_debug_redacts_the_secret() {
    let t = Token([7; 32]);
    let shown = format!("{t:?}");
    assert!(!shown.contains('7'), "{shown}");
    let c = SessionCookie::new([1; 16], Token([0xAB; 32]));
    let shown = format!("{c:?}");
    assert!(!shown.contains("171"), "{shown}");
    assert_eq!(t, Token([7; 32]));
    assert_ne!(t, Token([8; 32]));
    assert_ne!(c, SessionCookie::new([1; 16], Token([0xAC; 32])));
    assert_ne!(c, SessionCookie::new([2; 16], Token([0xAB; 32])));
}
