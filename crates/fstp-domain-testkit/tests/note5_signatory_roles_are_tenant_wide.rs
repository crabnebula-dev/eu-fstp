//! NOTE 5 of `SPEC/02-domain/roles-and-sod.md` (SA-01, decided by Daniel
//! 2026-11-01): Financial signatory and Legal signatory are Operations
//! roles that act for the whole organisation. They are tenant-wide, so a
//! binding of either names no programme. SoD-09 covers Drafting and
//! Judging only, so neither needs a verified identity at binding time.
//!
//! Lane m4/roles, test author. The tenant admin is the other tenant-wide
//! role: the tenant crate holds its set, and the shell attests it to the
//! domain core. The signatory roles follow it. So the domain core never
//! records a programme binding of either role, and its reference agrees.
//!
//! Each test finds the two roles by their spec name in `Role::ALL`. The
//! file therefore compiles against the enum as it stands, and is red,
//! naming the missing role, until the enum holds them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::BindingId;
use fstp_domain::roles::{Group, Role};
use fstp_domain_testkit::r#gen::roster::{
    A, B, Backend, C, Facts, P1, SodSetup, SodWorld, T0, grant, sod_truth,
};
use fstp_domain_testkit::reference::sod::{RefGroup, spec_group};
use fstp_prop::{Config, check_with, prop_assert};

/// The two signatory roles, by the names of the roles table.
const SIGNATORY_NAMES: [&str; 2] = ["Financial signatory", "Legal signatory"];

/// The role whose spec name is `name`, or why the enum lacks it.
fn by_name(name: &str) -> Result<Role, String> {
    Role::ALL
        .iter()
        .copied()
        .find(|r| r.spec_name() == name)
        .ok_or_else(|| format!("SA-01: Role::ALL holds no role named {name:?}"))
}

/// Both signatory roles, Financial first.
fn signatories() -> Result<[Role; 2], String> {
    let [financial, legal] = SIGNATORY_NAMES;
    Ok([by_name(financial)?, by_name(legal)?])
}

/// Whether `role` is one of the two signatory roles.
fn is_signatory(role: Role) -> bool {
    SIGNATORY_NAMES.contains(&role.spec_name())
}

/// A world with programme P1 active and one call drafted, on `backend`.
fn world(backend: Backend) -> SodWorld {
    SodWorld::from_setup(backend, sod_truth(), &SodSetup::one(1, &[1]))
        .unwrap_or_else(|e| panic!("setup: {e}"))
}

/// SoD-01, SoD-03, NOTE 5: both signatory roles are in the Operations
/// group, in the domain enum and in the reference. Operations roles need
/// no verified identity at binding time (SoD-09 covers Drafting and
/// Judging only).
#[test]
fn note5_sod09_signatory_roles_are_operations_roles_without_verification() {
    let roles = signatories().unwrap_or_else(|e| panic!("{e}"));
    for role in roles {
        assert_eq!(role.group(), Group::Operations, "SA-01: {role:?}");
        assert_eq!(
            spec_group(role),
            RefGroup::Operations,
            "SA-01: the reference groups {role:?} elsewhere"
        );
        assert!(
            !role.group().needs_verification(),
            "NOTE 5: {role:?} needs a verified identity under SoD-09"
        );
        assert!(
            !role.other_judging(),
            "SoD-02: {role:?} counts as a Judging role"
        );
    }
}

/// NOTE 5: a `GrantRole` of either signatory role names a programme, and
/// a signatory binding names none. The production core refuses it and
/// records no binding.
#[test]
fn note5_production_refuses_a_programme_grant_of_a_signatory_role() {
    let roles = signatories().unwrap_or_else(|e| panic!("{e}"));
    for (n, role) in roles.into_iter().enumerate() {
        let mut w = world(Backend::Production);
        let id = BindingId::from_raw(700_u128.saturating_add(n as u128));
        let got = w
            .exec(&grant(id, A, P1, role, T0), Facts::Effective)
            .unwrap_or_else(|e| panic!("harness: {e}"));
        assert!(
            got.is_err(),
            "NOTE 5: the core bound {role:?} to programme P1: {got:?}"
        );
        assert!(
            w.state.roster().binding(id).is_none(),
            "NOTE 5: the roster holds a programme binding of {role:?}"
        );
    }
}

/// NOTE 5: the reference refuses the same programme grant, so the
/// reference models of the SoD suites never expect a signatory binding.
#[test]
fn note5_reference_refuses_a_programme_grant_of_a_signatory_role() {
    let roles = signatories().unwrap_or_else(|e| panic!("{e}"));
    for (n, role) in roles.into_iter().enumerate() {
        let mut w = world(Backend::Reference);
        let id = BindingId::from_raw(710_u128.saturating_add(n as u128));
        let got = w
            .exec(&grant(id, A, P1, role, T0), Facts::Effective)
            .unwrap_or_else(|e| panic!("harness: {e}"));
        assert!(
            got.is_err(),
            "NOTE 5: the reference bound {role:?} to programme P1: {got:?}"
        );
        assert!(
            !w.view.bindings.contains_key(&id),
            "NOTE 5: the reference view holds a programme binding of {role:?}"
        );
    }
}

/// NOTE 5, property: over random programme grants of every role by the
/// tenant admin, to random accounts, the production roster never holds a
/// binding of a signatory role, and every signatory grant is refused.
/// Grants of the other roles are judged by the SoD rules as before, and
/// this property does not judge them.
#[test]
fn note5_no_programme_binding_ever_holds_a_signatory_role() {
    check_with(
        "note5_no_programme_binding_ever_holds_a_signatory_role",
        Config::from_env().with_cases(64),
        |g| {
            let roles = signatories()?;
            let mut w = world(Backend::Production);
            let accounts = [A, B, C];
            let n = g.usize_in(1..=8);
            for i in 0..n {
                let role = if g.bool() {
                    *g.pick(&roles)
                } else {
                    *g.pick(&Role::ALL)
                };
                let account = *g.pick(&accounts);
                let id = BindingId::from_raw(800_u128.saturating_add(i as u128));
                g.note("grant", &(id, account, role));
                let got = w
                    .exec(&grant(id, account, P1, role, T0), Facts::Effective)
                    .map_err(|e| format!("harness: {e}"))?;
                if is_signatory(role) {
                    prop_assert!(
                        got.is_err(),
                        "NOTE 5: the core bound {:?} to P1: {:?}",
                        role,
                        got
                    );
                }
                let bound: Vec<_> = w
                    .state
                    .roster()
                    .bindings()
                    .filter(|(_, b)| is_signatory(b.role))
                    .map(|(id, b)| (id, b.account, b.role))
                    .collect();
                prop_assert!(
                    bound.is_empty(),
                    "NOTE 5: programme bindings of a signatory role: {:?}",
                    bound
                );
            }
            Ok(())
        },
    );
}
