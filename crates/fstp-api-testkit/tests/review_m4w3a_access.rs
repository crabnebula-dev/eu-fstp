//! Review reproducers for lane W3a (M4 design section 3.6). Each test
//! fails against the lane's code as reviewed and passes once the defect
//! it names is fixed. They live here because building a state from
//! genesis needs the domain testkit, which `fstp-access` does not take.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_access::{Principal, ReadKind, ReadOp, ReadTarget, authorize_read};
use fstp_domain::policy::ReadAccess;
use fstp_domain_testkit::r#gen::review::{ReviewSetup, review_truth, scenario_from};
use fstp_domain_testkit::r#gen::roster::{SodSetup, T0, call};
use fstp_domain_testkit::scenario::Scenario;

/// One programme with call 1 drafted and approved, never published, and
/// no proposal.
fn unpublished_call() -> Scenario {
    let base = SodSetup::one(0, &[1]);
    let setup = ReviewSetup {
        base,
        p38: BTreeMap::new(),
        p10: ReadAccess::AssignedReviewersOnly,
        judges: Vec::new(),
        drafts: Vec::new(),
    };
    scenario_from(&setup, review_truth(setup.accounts())).unwrap_or_else(|e| panic!("{e}"))
}

/// R-AC-01, I-87, D11: a call that is drafted but not yet published is
/// not public. The anonymous `calls.get` read (`GetPublicCall`) must not
/// clear it, since the reference judges that read on a published call
/// only and the draft text is confidential until publication.
#[test]
fn review_public_call_read_refuses_an_unpublished_call() {
    let s = unpublished_call();
    let st = s.state();
    let c = call(1);
    assert!(
        st.core.calls().get(c).is_some_and(|x| x.frozen().is_none()),
        "setup: call 1 exists and is unpublished"
    );
    let anyone = Principal::anonymous();
    let out = authorize_read(
        &ReadOp {
            kind: ReadKind::GetPublicCall,
            target: ReadTarget::Call(c),
        },
        &anyone,
        st,
        T0,
    );
    assert!(
        out.is_err(),
        "an anonymous caller is cleared to read the unpublished call: {out:?}"
    );
}

/// R-GA-01, I-87, D11: the Guide of a call exists only from publication.
/// The anonymous `calls.guide` read (`GetGuide`) must not clear an
/// unpublished call.
#[test]
fn review_public_guide_read_refuses_an_unpublished_call() {
    let s = unpublished_call();
    let st = s.state();
    let anyone = Principal::anonymous();
    let out = authorize_read(
        &ReadOp {
            kind: ReadKind::GetGuide,
            target: ReadTarget::Call(call(1)),
        },
        &anyone,
        st,
        T0,
    );
    assert!(
        out.is_err(),
        "an anonymous caller is cleared to read the Guide of an unpublished call: {out:?}"
    );
}
