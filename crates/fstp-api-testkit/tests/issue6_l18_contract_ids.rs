//! Issue 6 L18: contract operations reveal no contract id.
//!
//! An unknown id gets the refusal every non-actor of a known contract
//! gets: the `actor` rule, whatever the body holds (R-AC-01, I-86).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, ErrorCode};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::LEAD;

/// L18: every contract operation on an unknown id, with a valid or an
/// invalid body, is refused with `refused` and the rule `actor`.
#[test]
fn issue6_l18_unknown_contract_id_gets_the_actor_refusal() {
    let c = FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"));
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let cases = [
        ("/contracts/4242/changes", r#"{"clause":1,"text":"x"}"#),
        ("/contracts/4242/changes", "{}"),
        ("/contracts/4242/changes/1/decision", r#"{"accept":true}"#),
        ("/contracts/4242/changes/1/decision", "{}"),
        ("/contracts/4242/send", "{}"),
        ("/contracts/4242/signature", r#"{"route":"wallet_qes"}"#),
        ("/contracts/4242/signature", r#"{"route":"nonsense"}"#),
        (
            "/contracts/4242/advanced-approval",
            r#"{"party":"a","reason":"b"}"#,
        ),
        ("/contracts/4242/decline", r#"{"reason":"x"}"#),
    ];
    for (path, body) in cases {
        let got = c.web(&lead, decode_route(Method::Post, path, body.as_bytes()));
        match got {
            Err(ApiError::Refused { code, rule, .. }) => {
                assert_eq!(code, ErrorCode::Refused, "{path} {body}");
                assert_eq!(rule, "actor", "{path} {body}");
            }
            other => panic!("{path} {body}: {other:?}"),
        }
    }
}

/// L18: a known contract the caller may not act on is refused with
/// `refused` and the rule `actor`, the same refusal an unknown id gets
/// (the test above). The matrix generates contract cells only for a
/// GRANTED world, so no cell holds an unknown id. This one cell per
/// operation runs through the matrix's direct channel, and no matrix
/// runs.
#[test]
fn issue6_l18_known_non_actor_gets_the_actor_refusal() {
    use fstp_api_testkit::harness::harness;
    use fstp_api_testkit::matrix::{Channel as _, Observed, matrix};
    use fstp_api_testkit::reference::authz::{StateProfile, Who};
    use fstp_domain::StateTag;
    let m = matrix().unwrap();
    let mut h = harness().unwrap().direct();
    let granted = StateProfile::Proposal(StateTag::Granted);
    let want = Observed::Refused(Some("actor".to_owned()));
    for op in [
        "contract.propose_change",
        "contract.decide_change",
        "contract.send",
        "contract.sign",
        "contract.approve_advanced",
        "contract.decline",
    ] {
        let cell = m
            .cells()
            .find(|c| c.op == op && c.state == granted && c.who == Who::Unbound)
            .unwrap_or_else(|| panic!("no cell of {op}"));
        assert_eq!(h.observe(&cell).unwrap(), want, "{op}");
    }
}
