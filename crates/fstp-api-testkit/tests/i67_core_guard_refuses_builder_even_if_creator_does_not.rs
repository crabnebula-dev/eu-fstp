//! I-67: the core guard refuses a builder even if the creator does not
//! (M4 design sections 3.4 D2 and 8.4, "Property with a mutant creator").
//!
//! A mutant creator skips its own approver checks and composes the core
//! `ActivateProgramme` for any actor. Mutant A passes the true creator
//! builder set; mutant B passes an empty one. The core guard refuses an
//! actor in `programme_builders(state)` or in the passed set, or one that
//! shares a verified identity with either (Q2 B). So under mutant A no
//! builder ever activates. Under mutant B the core still refuses every
//! author of a core record.
//!
//! The production test is red until lane W1b lands
//! `Command::ActivateProgramme` and its guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_api_testkit::mc::activate_model::{Backend, builders_from_raw, production, sybil_vault};
use fstp_api_testkit::reference::creator::{
    Base, M1, M2, RefCheck, RefCommand, RefSystem, StepVerdict, TA, TB, clean_plan, core_guard,
};
use fstp_domain::id::AccountId;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn pool() -> Vec<RefCommand> {
    vec![
        RefCommand::Acknowledge {
            by: TB,
            warning: RefCheck::RosterShort,
            base: Base::Head,
        },
        RefCommand::Request {
            by: TB,
            base: Base::Head,
        },
        RefCommand::Grant { by: TB, to: M2 },
        RefCommand::Request {
            by: M1,
            base: Base::Head,
        },
        RefCommand::Acknowledge {
            by: M1,
            warning: RefCheck::RosterShort,
            base: Base::Head,
        },
    ]
}

fn property(backend: Backend) -> impl Fn(&mut Gen) -> Result<(), String> {
    move |g| {
        let mut plan = clean_plan();
        plan.seeds.insert(RefCheck::RosterShort);
        let sybil = g.bool();
        if sybil {
            plan.stat.vault = sybil_vault();
        }
        let pool = pool();
        let script: Vec<RefCommand> = g.vec(0..=4, |g| *g.pick(&pool));
        let actor = *g.pick(&[TA, TB, M1, M2]);
        let mutant_a = g.bool();
        g.note("Sybil pair", &sybil);
        g.note("script", &script);
        g.note("actor", &actor);
        g.note("mutant A (true creator builders)", &mutant_a);
        let mut r = RefSystem::open(&plan).map_err(|e| format!("reference setup: {e:?}"))?;
        for cmd in &script {
            r.apply(cmd);
        }
        let builders = builders_from_raw(&r.events);
        let creator_builders: BTreeSet<AccountId> = if mutant_a {
            builders.clone()
        } else {
            BTreeSet::new()
        };
        let want = core_guard(&r.stat, &r.draft.core_builders, &creator_builders, actor);
        let got = match backend {
            Backend::Reference => match want {
                Ok(()) => StepVerdict::Accepted,
                Err(e) => StepVerdict::Refused(e),
            },
            Backend::Production => {
                production::core_activate(&plan, &script, actor, &creator_builders)
                    .map_err(|e| format!("production: {e}"))?
            }
        };
        prop_assert_eq!(
            got.accepted(),
            want.is_ok(),
            "two-way: the core guard gave {got:?}, the reference says {want:?}"
        );
        if mutant_a {
            prop_assert!(
                !(builders.contains(&actor) && got.accepted()),
                "I-67: the core guard let the builder {actor:?} activate"
            );
        }
        prop_assert!(
            !(r.draft.core_builders.contains(&actor) && got.accepted()),
            "I-67: the core guard let the core author {actor:?} activate"
        );
        Ok(())
    }
}

/// I-67, D2: defence in depth on production.
#[test]
fn i67_core_guard_refuses_builder_even_if_creator_does_not() {
    check(
        "i67_core_guard_refuses_builder_even_if_creator_does_not",
        property(Backend::Production),
    );
}

/// I-67, D2: the reference core guard against the raw-record builder set.
#[test]
fn i67_core_guard_refuses_builder_even_if_creator_does_not_on_the_reference() {
    check(
        "i67_core_guard_refuses_builder_even_if_creator_does_not_on_the_reference",
        property(Backend::Reference),
    );
}
