//! Decoder tests for the operations lane m4reg adds for the M4 demo (M4
//! design sections 2.2 and 3.7 step 1, ADR-006, lane scope m4reg).
//!
//! Written by the m4reg test author before the decoders exist. Each test
//! drives the public decoders an adapter uses, `decode_route` and
//! `decode_request`, with the routes the registry tests of `fstp-access`
//! pin. Until the registry holds an operation, its route answers
//! `not_found`, so each test is red for that reason.
//!
//! The command bodies follow the committee pages of `web/src/committee`
//! and the D5 command codec of `fstp-domain`: ids are canonical decimal
//! strings, the rank position is a JSON integer, votes are spelled as the
//! codec spells them (`For`, `Against`, `Abstain`), and the server draws
//! the round id. Free text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::{ApiError, ErrorCode, Op};

fn route(method: Method, path: &str, body: &str) -> Result<Op, ApiError> {
    decode_route(method, path, body.as_bytes())
}

/// The operation a decode gave, or a description of the error.
fn decoded(r: &Result<Op, ApiError>) -> Result<&'static str, String> {
    match r {
        Ok(op) => Ok(op.name()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Whether `r` is a strict-decoder refusal of a matched route.
fn bad_request(r: &Result<Op, ApiError>) -> bool {
    matches!(
        r,
        Err(ApiError::Refused {
            code: ErrorCode::BadRequest,
            ..
        })
    )
}

fn assert_op(r: &Result<Op, ApiError>, want: &str, what: &str) {
    assert_eq!(decoded(r), Ok(want), "{what}");
}

fn assert_bad(r: &Result<Op, ApiError>, what: &str) {
    assert!(
        bad_request(r),
        "{what}: wanted a bad_request refusal, got {:?}",
        decoded(r)
    );
}

const ROUND: &str = "/calls/7/cut-off-rounds";
const OPEN_OK: &str =
    r#"{"order":["11","12"],"nominated":1,"rationale":"SYNTHETIC RATIONALE","tie_breaks":null}"#;

/// R-EV-08, change D5, design section 3.7 step 1: `committee.open_round`
/// decodes a body with the order as proposal ids, the rank position, the
/// rationale and an optional tie-break. The tie-break may be absent, null
/// or text.
#[test]
fn r_ev_08_open_round_decodes_its_body() {
    assert_op(
        &route(Method::Post, ROUND, OPEN_OK),
        "committee.open_round",
        "full body",
    );
    let no_tie = r#"{"order":["11"],"nominated":0,"rationale":"SYNTHETIC RATIONALE"}"#;
    assert_op(
        &route(Method::Post, ROUND, no_tie),
        "committee.open_round",
        "no tie-break",
    );
    let tie = r#"{"order":["11","12"],"nominated":1,"rationale":"SYNTHETIC RATIONALE","tie_breaks":"SYNTHETIC TIE-BREAK"}"#;
    assert_op(
        &route(Method::Post, ROUND, tie),
        "committee.open_round",
        "a tie-break text",
    );
}

/// R-EV-08, I-84, ADR-006, design section 3.7 step 1: the open-round
/// decoder is strict. A missing rationale, an unknown member, a round id
/// the client chose, a repeated path parameter, a rank position that is
/// not a JSON integer, a proposal id sent as a JSON number and a
/// non-canonical call id are each refused as a bad request.
#[test]
fn r_ev_08_open_round_decoder_is_strict() {
    // The valid body decodes first, so a decoder that refuses everything
    // fails here.
    assert_op(
        &route(Method::Post, ROUND, OPEN_OK),
        "committee.open_round",
        "valid body",
    );
    for (body, what) in [
        (r#"{"order":["11"],"nominated":0}"#, "no rationale"),
        (
            r#"{"order":["11"],"nominated":0,"rationale":"R","x":1}"#,
            "an unknown member",
        ),
        (
            r#"{"round":"9","order":["11"],"nominated":0,"rationale":"R"}"#,
            "a client-chosen round id",
        ),
        (
            r#"{"call":"7","order":["11"],"nominated":0,"rationale":"R"}"#,
            "the path parameter repeated",
        ),
        (
            r#"{"order":["11"],"nominated":"0","rationale":"R"}"#,
            "the position as a string",
        ),
        (
            r#"{"order":["11"],"nominated":-1,"rationale":"R"}"#,
            "a negative position",
        ),
        (
            r#"{"order":["11"],"nominated":0.5,"rationale":"R"}"#,
            "a fractional position",
        ),
        (
            r#"{"order":[11],"nominated":0,"rationale":"R"}"#,
            "a proposal id as a JSON number",
        ),
        (
            r#"{"order":["011"],"nominated":0,"rationale":"R"}"#,
            "a non-canonical proposal id",
        ),
        (
            r#"{"order":["11"],"nominated":0,"rationale":7}"#,
            "a rationale that is not text",
        ),
    ] {
        assert_bad(&route(Method::Post, ROUND, body), what);
    }
    assert!(
        route(Method::Post, "/calls/07/cut-off-rounds", OPEN_OK).is_err(),
        "a non-canonical call id"
    );
}

const BALLOT: &str = "/cut-off-rounds/5/ballot";

/// R-EV-09, change D5, design section 3.7 step 1: `committee.cast` takes
/// the vote only, spelled as the command codec spells it. The ballot
/// names no voter, so no member states another member's vote.
#[test]
fn r_ev_09_cast_decodes_each_vote() {
    for vote in ["For", "Against", "Abstain"] {
        let body = format!(r#"{{"vote":"{vote}"}}"#);
        assert_op(&route(Method::Post, BALLOT, &body), "committee.cast", vote);
    }
}

/// R-EV-09, I-84, design section 3.7 step 1: the cast decoder refuses a
/// vote in another spelling, a missing vote, a named voter, a round id in
/// the body and an unknown member.
#[test]
fn r_ev_09_cast_decoder_is_strict() {
    assert_op(
        &route(Method::Post, BALLOT, r#"{"vote":"For"}"#),
        "committee.cast",
        "valid ballot",
    );
    for (body, what) in [
        (r#"{"vote":"for"}"#, "a lowercase vote"),
        (r#"{"vote":"Yes"}"#, "an unknown vote"),
        (r#"{"vote":1}"#, "a vote as a number"),
        ("{}", "no vote"),
        (r#"{"vote":"For","voter":"3"}"#, "a named voter"),
        (r#"{"vote":"For","round":"5"}"#, "the round repeated"),
        (r#"{"vote":"For","weight":2}"#, "an unknown member"),
    ] {
        assert_bad(&route(Method::Post, BALLOT, body), what);
    }
    assert!(
        route(
            Method::Post,
            "/cut-off-rounds/05/ballot",
            r#"{"vote":"For"}"#
        )
        .is_err(),
        "a non-canonical round id"
    );
}

const DELEGATION: &str = "/cut-off-rounds/5/delegation";

/// R-EV-09, P-16 NOTE 8, change D5, design section 3.7 step 1:
/// `committee.delegate` takes the member who holds the vote, as an
/// account id.
#[test]
fn r_ev_09_delegate_decodes_its_body() {
    assert_op(
        &route(Method::Post, DELEGATION, r#"{"to":"4"}"#),
        "committee.delegate",
        "a delegation",
    );
}

/// R-EV-09, P-16 NOTE 8, I-84, design section 3.7 step 1: the delegation
/// decoder refuses an account id sent as a JSON number, a non-canonical
/// id, a missing member, a named delegator and an unknown member.
#[test]
fn r_ev_09_delegate_decoder_is_strict() {
    assert_op(
        &route(Method::Post, DELEGATION, r#"{"to":"4"}"#),
        "committee.delegate",
        "valid delegation",
    );
    for (body, what) in [
        (r#"{"to":4}"#, "an account id as a JSON number"),
        (r#"{"to":"04"}"#, "a non-canonical account id"),
        ("{}", "no member"),
        (r#"{"to":"4","from":"3"}"#, "a named delegator"),
        (r#"{"to":"4","round":"5"}"#, "the round repeated"),
    ] {
        assert_bad(&route(Method::Post, DELEGATION, body), what);
    }
}

/// D11, I-84, design section 3.7 step 1: each m4reg read decodes on its
/// `GET` route with no body, and refuses a body. The `POST` on the same
/// path still reaches the write of that screen, so no read shadows a
/// write.
#[test]
fn d11_m4reg_reads_decode_without_a_body() {
    for (path, read, write) in [
        ("/admin/admins", "tenant.list_admins", "tenant.invite_admin"),
        (
            "/me/verification",
            "me.get_verification",
            "me.begin_verification",
        ),
        (
            "/programmes",
            "creator.list_programmes",
            "creator.open_draft",
        ),
        ("/templates", "creator.list_templates", ""),
        (
            "/proposals/7/assignments",
            "review.assignments",
            "review.assign",
        ),
    ] {
        assert_op(&route(Method::Get, path, ""), read, path);
        assert_bad(&route(Method::Get, path, "{}"), path);
        if !write.is_empty() {
            let r = route(Method::Post, path, "");
            assert_ne!(decoded(&r), Ok(read), "POST {path} reached the read");
            if let Ok(name) = decoded(&r) {
                assert_eq!(name, write, "POST {path}");
            }
        }
    }
    assert!(
        route(Method::Get, "/proposals/07/assignments", "").is_err(),
        "a non-canonical proposal id"
    );
}

/// A 32-digit lowercase hexadecimal invitation token, as the invitation
/// link of `web/src/people` carries it (synthetic).
const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// SoD-09, design section 2.2 J2: the invitation landing and the
/// acceptance spell the invitation parameter alike, so a link that
/// reaches one reaches the other.
#[test]
fn sod09_invitation_landing_and_acceptance_spell_the_invitation_alike() {
    let mut reached = 0usize;
    for value in ["7", TOKEN] {
        let get = route(Method::Get, &format!("/invitations/{value}"), "");
        let accept = route(Method::Post, &format!("/invitations/{value}/accept"), "");
        assert_eq!(
            decoded(&get).is_ok(),
            decoded(&accept).is_ok(),
            "{value}: landing {:?}, acceptance {:?}",
            decoded(&get),
            decoded(&accept)
        );
        if decoded(&get) == Ok("people.get_invitation") {
            reached = reached.saturating_add(1);
        }
    }
    assert!(reached > 0, "no invitation value reaches the landing");
}

/// SoD-09, design section 2.2 J2, the interim reading of lane m4reg: the
/// landing admits a caller with no account, so the invitation token is
/// the capability. The page sends the token of the link, 32 to 128
/// lowercase hexadecimal digits. The landing decodes that token, and it
/// never decodes a short decimal id, which a caller could guess.
///
/// The routes spell the parameter `{invitation_token}`, which
/// `forms::param_kind` reads as a link token.
#[test]
fn sod09_invitation_landing_takes_the_token_of_the_link() {
    assert_op(
        &route(Method::Get, &format!("/invitations/{TOKEN}"), ""),
        "people.get_invitation",
        "the 32-digit token",
    );
    assert!(
        decoded(&route(Method::Get, "/invitations/7", "")).is_err(),
        "a guessable decimal id addresses an invitation"
    );
    assert!(
        decoded(&route(
            Method::Get,
            "/invitations/0123456789ABCDEF0123456789ABCDEF",
            ""
        ))
        .is_err(),
        "an uppercase token"
    );
}

/// SoD-09, R-AC-01: a link token has 32 to 128 lowercase hexadecimal
/// digits. The landing, the acceptance and the verification refuse a
/// shorter or longer one, a non-hexadecimal one and a decimal id alike.
#[test]
fn sod09_invitation_routes_take_only_a_link_token() {
    let long = "a".repeat(128);
    let too_long = "a".repeat(129);
    let short = &TOKEN[..31];
    let not_hex = "0123456789abcdef0123456789abcdeg";
    for (method, tail, want) in [
        (Method::Get, "", "people.get_invitation"),
        (Method::Post, "/accept", "people.accept_invitation"),
        (Method::Post, "/verification", "people.begin_verification"),
    ] {
        for ok in [TOKEN, long.as_str()] {
            let r = route(method, &format!("/invitations/{ok}{tail}"), "");
            if let Ok(name) = decoded(&r) {
                assert_eq!(name, want, "{ok}{tail}");
            } else {
                assert!(bad_request(&r), "{ok}{tail}: the route did not match");
            }
        }
        for bad in ["7", "0", short, too_long.as_str(), not_hex] {
            let r = route(method, &format!("/invitations/{bad}{tail}"), "");
            assert!(
                !matches!(decoded(&r), Ok(name) if name == want),
                "{bad}{tail} reached {want}"
            );
            assert!(!bad_request(&r), "{bad}{tail} matched the route");
        }
    }
}
