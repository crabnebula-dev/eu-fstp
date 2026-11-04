//! Review reproducers for the authorisation matrix (T-AUTHZ-MATRIX,
//! design section 8.3). Each test fails against the lane's work as
//! reviewed and passes once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::matrix::{self, Observed, agrees, class_of};
use fstp_api_testkit::reference::authz::{Channel as Via, Expected, Who};

/// T-AUTHZ-MATRIX, H-01: a `not_found` reply that names a missing route,
/// tool, pending action (I-85) or agent client (R-MC-03) is no proof that
/// the system admits the caller. The matrix classes every `NotFound` as a
/// guard, and a guard agrees with `Allow` and `Pending`, so a cell whose
/// operation the system cannot even reach passes as allowed.
#[test]
fn review_authz_not_found_never_agrees_with_allow() {
    for rule in ["route", "tool", "I-85", "R-MC-03", ""] {
        let o = Observed::NotFound(rule.to_owned());
        for e in [Expected::Allow, Expected::Pending] {
            assert!(
                !agrees(e, class_of(&o)),
                "{o:?} agrees with {e:?}, so an unreachable operation passes"
            );
        }
    }
}

/// T-AUTHZ-MATRIX, H-01, R-PB-04: through the direct channel, an
/// anonymous web read of a public page never reaches the system, since
/// `decode_route` skips every `OpKind::Public` route and answers
/// `not_found` with rule `route`. The comparison still counts the cell as
/// agreeing with the reference's `Allow`, so the direct matrix passes
/// every public-page cell vacuously.
#[test]
fn review_authz_direct_public_page_cell_is_not_vacuous() {
    let m = matrix::matrix().unwrap_or_else(|e| panic!("{e}"));
    let cell = m
        .groups()
        .into_iter()
        .flat_map(|(s, p)| m.group_cells(s, p))
        .find(|c| {
            c.op == "public.programme" && c.who == Who::Anonymous && c.session.channel == Via::Web
        })
        .expect("a public.programme cell for an anonymous web caller");
    let reference =
        fstp_api_testkit::reference::authz::authz_reference().unwrap_or_else(|e| panic!("{e}"));
    let expected = reference.expected(&cell).expect("the reference judges it");
    assert_eq!(expected, Expected::Allow, "{cell:?}");
    let mut channel = matrix::direct_channel().unwrap_or_else(|e| panic!("{e}"));
    let observed = channel.observe(&cell).expect("the cell runs");
    if agrees(expected, class_of(&observed)) {
        assert_eq!(
            observed,
            Observed::Completed,
            "{cell:?} agrees with Allow without the system serving the page"
        );
    }
}
