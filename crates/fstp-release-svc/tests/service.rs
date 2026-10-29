//! Tests of the licence and update service cores (I-38, I-39, design
//! sections 10.1 and 10.2). Lane W2j wrote them with the cores.
//!
//! Each test runs the cell side through `fstp_release`, so what the
//! service answers is what a cell decodes and applies.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_prop::{Gen, check, prop_assert_eq};
use fstp_release::egress::{
    self, Channel, CnCall, LicenceRefresh, ProductVersion, UpdateCheck, decode_response,
};
use fstp_release::licence::{
    self, Ed25519Public, Ed25519SigningKey, KeySet, LicenceId, LicenceKind, VerifiedToken,
};
use fstp_release_svc::{
    HttpStatus, Issuer, LicenceRecord, LicenceRegistry, MetadataSource, ServiceError, TokenPolicy,
    http_response, issue_token, licence_response, update_response,
};

const T0: i64 = 1_800_000_000;
const DAY_S: i64 = 86_400;
const KNOWN: LicenceId = LicenceId([0x4c; 16]);

struct OneLicence;

impl LicenceRegistry for OneLicence {
    fn lookup(&self, licence: &LicenceId) -> Option<LicenceRecord> {
        (*licence == KNOWN).then_some(LicenceRecord {
            kind: LicenceKind::Noncommercial,
        })
    }
}

struct Fixed(Vec<u8>);

impl MetadataSource for Fixed {
    fn latest(&self, channel: Channel) -> Option<Vec<u8>> {
        (channel == Channel::Stable).then(|| self.0.clone())
    }
}

fn key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn policy() -> TokenPolicy {
    TokenPolicy::new(7 * DAY_S, 14 * DAY_S).unwrap()
}

fn gen_version(g: &mut Gen) -> ProductVersion {
    ProductVersion(g.u16(), g.u16(), g.u16())
}

/// I-38, I-39, design section 10.2: a refresh the cell sends gets a
/// response that the cell's egress decoder and refresh step accept. The
/// adopted token is newer, for the same licence, and signed by the
/// pinned key.
#[test]
fn i39_licence_response_is_adopted_by_the_cell() {
    let k = key(0x11);
    let issuer = Issuer {
        key: &k,
        policy: policy(),
        transition: None,
    };
    let pinned = KeySet::shipped(&[Ed25519Public(k.public_key())]).unwrap();
    check("i39_licence_response_is_adopted_by_the_cell", |g| {
        let stored = VerifiedToken {
            licence: KNOWN,
            kind: LicenceKind::Noncommercial,
            issued_at: T0,
            refresh_after: T0 + 7 * DAY_S,
            not_after: T0 + 14 * DAY_S,
        };
        let now = T0 + g.i64_in(1..=30 * DAY_S);
        let request = egress::encode(&CnCall::Licence(LicenceRefresh {
            licence: KNOWN,
            version: gen_version(g),
        }))
        .unwrap();
        let response = decode_response(&licence_response(&request, &OneLicence, &issuer, now))
            .map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(response.status, 200);
        let done = licence::apply_refresh(&stored, &pinned, &response.body, now)
            .map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(done.token.issued_at, now);
        prop_assert_eq!(done.token.licence, KNOWN);
        prop_assert_eq!(done.keys, pinned.clone());
        Ok(())
    });
}

/// I-38, design section 10.1: the licence service answers a request
/// outside the template with 400 and an unknown licence with 404, with
/// no body, so it echoes nothing.
#[test]
fn i38_licence_response_refuses_off_template_and_unknown_licences() {
    let k = key(0x11);
    let issuer = Issuer {
        key: &k,
        policy: policy(),
        transition: None,
    };
    let refresh = |licence| {
        egress::encode(&CnCall::Licence(LicenceRefresh {
            licence,
            version: ProductVersion(1, 2, 3),
        }))
        .unwrap()
    };
    let mut extra = refresh(KNOWN);
    extra.extend_from_slice(b"X");
    let off = decode_response(&licence_response(&extra, &OneLicence, &issuer, T0)).unwrap();
    assert_eq!((off.status, off.body.len()), (400, 0));
    let unknown = refresh(LicenceId([0x4d; 16]));
    let gone = decode_response(&licence_response(&unknown, &OneLicence, &issuer, T0)).unwrap();
    assert_eq!((gone.status, gone.body.len()), (404, 0));
}

/// I-39, design section 10.2: during a rotation the response carries the
/// signed transition, and the cell adds the next key from its
/// `not_before` on.
#[test]
fn i39_licence_response_carries_the_rotation() {
    let current = key(0x11);
    let next = key(0x22);
    let not_before = T0 + DAY_S;
    let transition =
        licence::sign_transition(&Ed25519Public(next.public_key()), not_before, &current).unwrap();
    let issuer = Issuer {
        key: &current,
        policy: policy(),
        transition: Some(&transition),
    };
    let pinned = KeySet::shipped(&[Ed25519Public(current.public_key())]).unwrap();
    let stored = VerifiedToken {
        licence: KNOWN,
        kind: LicenceKind::Noncommercial,
        issued_at: T0 - DAY_S,
        refresh_after: T0,
        not_after: T0 + DAY_S,
    };
    let request = egress::encode(&CnCall::Licence(LicenceRefresh {
        licence: KNOWN,
        version: ProductVersion(1, 0, 0),
    }))
    .unwrap();
    let response = decode_response(&licence_response(&request, &OneLicence, &issuer, T0)).unwrap();
    let done = licence::apply_refresh(&stored, &pinned, &response.body, T0).unwrap();
    let keys: Vec<_> = done
        .keys
        .keys()
        .iter()
        .map(|p| (p.key.0, p.not_before))
        .collect();
    assert_eq!(
        keys,
        vec![
            (current.public_key(), i64::MIN),
            (next.public_key(), not_before)
        ]
    );
}

/// I-39: an issued token's instants stay ordered, even at the end of
/// time, so no token the service issues is refused by a cell for order.
#[test]
fn i39_issued_tokens_verify_at_every_instant() {
    let k = key(0x11);
    check("i39_issued_tokens_verify_at_every_instant", |g| {
        let now = if g.bool() {
            i64::MAX - g.i64_in(0..=30 * DAY_S)
        } else {
            T0 + g.i64_in(-DAY_S..=DAY_S)
        };
        let token = issue_token(KNOWN, LicenceKind::Commercial, now, policy(), &k)
            .map_err(|e| format!("{e:?}"))?;
        let t = licence::verify_token(&token, &Ed25519Public(k.public_key()))
            .map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(t.issued_at, now);
        Ok(())
    });
}

/// I-38, design section 10.1: an update check the cell sends gets the
/// stored signed metadata unchanged, and a check outside the template
/// gets 400 with no body.
#[test]
fn i38_update_response_serves_metadata_to_the_template_only() {
    check(
        "i38_update_response_serves_metadata_to_the_template_only",
        |g| {
            let metadata = g.bytes(0..=4096);
            let source = Fixed(metadata.clone());
            let request = egress::encode(&CnCall::Update(UpdateCheck {
                version: gen_version(g),
                channel: Channel::Stable,
            }))
            .map_err(|e| format!("{e:?}"))?;
            let ok = decode_response(&update_response(&request, &source))
                .map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!((ok.status, ok.body), (200, metadata));
            let mut edited = request.clone();
            edited.insert(g.usize_in(0..=request.len()), g.u8());
            let off = decode_response(&update_response(&edited, &source))
                .map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!((off.status, off.body.len()), (400, 0));
            Ok(())
        },
    );
}

/// I-38, design section 15: every response the services build decodes
/// to its status and exactly its body through the cell's egress decoder.
#[test]
fn i38_http_response_decodes_through_egress() {
    check("i38_http_response_decodes_through_egress", |g| {
        let status = *g.pick(&HttpStatus::ALL);
        let body = g.bytes(0..=2048);
        let got = decode_response(&http_response(status, &body)).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!((got.status, got.body), (status.code(), body));
        Ok(())
    });
}

/// I-39, design section 10.2: a token policy exists only through
/// `TokenPolicy::new`, which refuses a negative or unordered lifetime with
/// `ServiceError::Policy`. Every policy it builds issues a token whose
/// instants are ordered, so a cell never refuses a token for its order.
#[test]
fn i39_token_policy_is_validated_and_issues_ordered_tokens() {
    check(
        "i39_token_policy_is_validated_and_issues_ordered_tokens",
        |g| {
            let refresh = g.i64_in(-DAY_S..=30 * DAY_S);
            let valid = g.i64_in(-DAY_S..=30 * DAY_S);
            let got = TokenPolicy::new(refresh, valid);
            if refresh < 0 || refresh > valid {
                prop_assert_eq!(got, Err(ServiceError::Policy));
                return Ok(());
            }
            let policy = got.map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(
                (policy.refresh_after_s(), policy.valid_for_s()),
                (refresh, valid)
            );
            let k = Ed25519SigningKey::from_seed(&[0x5a; 32]).unwrap();
            let now = *g.pick(&[T0, i64::MAX - DAY_S, i64::MAX]);
            let token = issue_token(KNOWN, LicenceKind::Commercial, now, policy, &k)
                .map_err(|e| format!("{e:?}"))?;
            let t = licence::verify_token(&token, &Ed25519Public(k.public_key()))
                .map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(
                t.issued_at <= t.refresh_after && t.refresh_after <= t.not_after,
                true,
                "{t:?}"
            );
            Ok(())
        },
    );
}
