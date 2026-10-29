//! I-66 and I-67: the engine refuses a core `ActivateProgramme` that
//! arrives from outside (M4 design section 3.4 D2e and 8.4, "Engine
//! decider").
//!
//! Only `Command::Creator(ApproveActivation)` composes the core command,
//! from the creator decision. A core `ActivateProgramme` passed to
//! `Engine::execute` is refused with `RuleRef::I66`, whoever sends it and
//! whatever the draft's state, so a clean draft and an eligible approver
//! are refused on this path too.
//!
//! Red until `Command::ActivateProgramme` (D2, lane W1b) and the decider
//! refusal (D2e, lane W2e) exist. Lane W2e lists the same test among its
//! tests first; the lead reconciles the two at merge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::{cast, production};
use fstp_api_testkit::reference::creator::clean_plan;

/// I-66, I-67: every cast member, the eligible approver A2 included, is
/// refused with I-66 on the outside path.
#[test]
fn i66_execute_refuses_core_activate_programme() {
    let plan = clean_plan();
    for actor in cast() {
        let rule = production::execute_core_activate(&plan, actor)
            .unwrap_or_else(|e| panic!("production: {e}"));
        assert_eq!(
            rule.as_deref(),
            Some("I66"),
            "I-66: a core ActivateProgramme by {actor:?} from outside the engine"
        );
    }
}
