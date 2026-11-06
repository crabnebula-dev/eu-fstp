//! The Guide read with its corrigenda equals the call's effective limits
//! (I-51 for P-05 and P-13; NOTE 7, O-52, D12; Q37 C of 2026-11-06).
//!
//! After publication, live edits of P-05 and P-13 run in any order. Each
//! edit that changes the effective limits of the published call appends
//! a numbered corrigendum to its effective-limits record. The Guide page
//! then serves the stored Guide followed by every corrigendum, rendered
//! as HTML. A reader takes the latest corrigendum, or the Guide when none
//! exists. The property: what the reader takes equals the limits that
//! enforcement reads, `effective_p05` and `effective_p13`.
//!
//! The P-13 classes an edit may add carry synthetic descriptions in the
//! compiled spec the page is served with, as the creator draft that made
//! the edit would hold them. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "r_ga_support.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fstp_domain::id::{ClassId, PolicyVersionId};
use fstp_domain::policy::ExclusionClasses;
use fstp_domain_testkit::r#gen::policy::eur;
use fstp_domain_testkit::r#gen::roster::{P1, edit_policy};
use fstp_guide::NoStoredTexts;
use fstp_programme::kinds::{ExclusionClass, Keyed};
use fstp_programme::value::Narrative;
use fstp_programme::{Compiled, Field};
use fstp_prop::{Config, check_with, prop_assert};
use fstp_public::guide::{CorrigendaSource, corrigenda, served_guide};
use support::{GUIDE_CALL, GuideEnv, World, world_with};

/// The classes an edit may add, beyond the fixture's P-13.
const EXTRA: [u128; 4] = [901, 902, 903, 904];

/// The synthetic description of an added class.
fn extra_description(id: u128) -> String {
    format!("Synthetic excluded class {id} for tests.")
}

/// The compiled fixture with the extra classes described in its P-13.
fn described() -> Compiled {
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let mut spec = fixture.spec.clone();
    let Field::Set(base) = &spec.eligibility.p13_excluded_classes else {
        panic!("the fixture sets P-13");
    };
    let mut items = base.items().to_vec();
    for id in EXTRA {
        items.push(ExclusionClass {
            id: ClassId::from_raw(id),
            description: Narrative::Inline(extra_description(id)),
        });
    }
    spec.eligibility.p13_excluded_classes = Field::Set(Keyed::new(items).unwrap());
    fstp_programme::compile(
        &spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P1, PolicyVersionId::from_raw(P1.raw()), None),
    )
    .unwrap()
}

/// The world right after publication, built once.
fn published() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| world_with(GuideEnv::supersafe(), true))
}

/// The descriptions of `classes` in `compiled`, as the Guide shows them.
fn descriptions(compiled: &Compiled, classes: &ExclusionClasses) -> BTreeSet<String> {
    classes
        .0
        .iter()
        .map(|c| {
            compiled
                .artefacts
                .class_descriptions()
                .iter()
                .find(|(id, _)| id == c)
                .map(|(_, n)| match n {
                    Narrative::Inline(s) => s.clone(),
                    Narrative::Stored(_) => panic!("the fixture holds no stored class text"),
                })
                .unwrap_or_else(|| panic!("class {c:?} has no description"))
        })
        .collect()
}

/// I-51, NOTE 7, O-52, Q37 C: after any sequence of live P-05 and P-13
/// edits, the Guide read with its corrigenda equals the effective limits,
/// and the corrigenda are numbered from 1 with no gap.
#[test]
fn i51_guide_with_corrigenda_equals_effective_limits_after_tightenings() {
    let compiled = described();
    let fixture_p13 = support::supersafe_compiled().policy.live.p13.clone();
    check_with(
        "i51_guide_with_corrigenda_equals_effective_limits_after_tightenings",
        Config::default().with_cases(24),
        |g| {
            let mut w = published().clone();
            let stored = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL)
                .ok_or("no stored Guide")?
                .clone();
            let edits = g.usize_in(1..=5);
            for n in 0..edits {
                let p05 = eur(g.i64_in(200_000..=450_000) * 100)?;
                let mut p13 = fixture_p13.clone();
                for id in EXTRA {
                    if g.bool() {
                        p13.0.insert(ClassId::from_raw(id));
                    }
                }
                g.note("edit", &(p05.amount().to_string(), &p13.0));
                let head = fstp_domain::policy::head(&w.state().core, P1)
                    .cloned()
                    .ok_or("no head")?;
                let ceiling = eur(45_000_000)?;
                let id = PolicyVersionId::from_raw(9_100 + u128::try_from(n).unwrap_or(0));
                let step = edit_policy(&head, id, |v| {
                    v.live.p05 = p05;
                    v.live.p58 = Some(ceiling);
                    v.live.p13 = p13.clone();
                });
                if let Err(e) = w.run(&step) {
                    g.note("refused", &format!("{e:?}"));
                }
            }
            let core = &w.state().core;
            let source = CorrigendaSource {
                compiled: &compiled,
                texts: &NoStoredTexts,
            };
            let list = corrigenda(core, GUIDE_CALL, &source).map_err(|e| e.to_string())?;
            for (i, c) in list.iter().enumerate() {
                prop_assert!(c.number.get() as usize == i + 1, "numbering {i}: {c:?}");
            }
            let snapshot = fstp_domain::programme::call(core, GUIDE_CALL)
                .and_then(|v| v.frozen())
                .map(|f| f.snapshot().clone())
                .ok_or("no snapshot")?;
            let (read_p05, read_p13) = match list.last() {
                Some(c) => (
                    c.p05.clone(),
                    c.p13.iter().cloned().collect::<BTreeSet<_>>(),
                ),
                None => (
                    snapshot.p05.amount().to_string(),
                    descriptions(&compiled, &snapshot.p13),
                ),
            };
            let enforced_p05 = fstp_domain::policy::effective_p05(core, GUIDE_CALL)
                .map_err(|e| format!("{e:?}"))?;
            let enforced_p13 = fstp_domain::policy::effective_p13(core, GUIDE_CALL)
                .map_err(|e| format!("{e:?}"))?;
            prop_assert!(
                read_p05 == enforced_p05.amount().to_string(),
                "I-51: the Guide with corrigenda reads P-05 {read_p05}, enforcement {}",
                enforced_p05.amount()
            );
            prop_assert!(
                read_p13 == descriptions(&compiled, &enforced_p13),
                "I-51: the Guide with corrigenda reads P-13 {read_p13:?}, enforcement {enforced_p13:?}"
            );
            // The page is the stored Guide with the corrigenda after it.
            let page = served_guide(core, GUIDE_CALL, Some(&source))
                .map_err(|e| e.to_string())?
                .document;
            fstp_html::check_wellformed(page.as_bytes()).map_err(|e| format!("{e:?}"))?;
            prop_assert!(!page.contains("<script"), "a script on the Guide page");
            if list.is_empty() {
                prop_assert!(
                    page == stored.page(),
                    "I-53: the page is not the stored Guide"
                );
            } else {
                let cut = stored
                    .page()
                    .rfind("</main>")
                    .ok_or("the stored page has no main element")?;
                prop_assert!(
                    page.starts_with(&stored.page()[..cut]),
                    "I-53: the page does not begin with the stored Guide"
                );
                let mut from = cut;
                for c in &list {
                    let heading = format!("Corrigendum {}", c.number);
                    let at = page[from..]
                        .find(&heading)
                        .ok_or_else(|| format!("{heading} is not after the Guide, in order"))?;
                    from += at;
                    prop_assert!(page[from..].contains(&c.p05), "{heading}: no P-05");
                }
            }
            Ok(())
        },
    );
}

/// I-51, NOTE 7: a corrigendum names every class the effective P-13
/// holds, so it also names a class the Guide already showed.
#[test]
fn i51_corrigendum_restates_the_full_effective_p13() {
    let compiled = described();
    let mut w = published().clone();
    let head = fstp_domain::policy::head(&w.state().core, P1)
        .cloned()
        .unwrap();
    let step = edit_policy(&head, PolicyVersionId::from_raw(9_201), |v| {
        v.live.p13.0.insert(ClassId::from_raw(901));
    });
    w.run(&step).unwrap_or_else(|e| panic!("{e:?}"));
    let source = CorrigendaSource {
        compiled: &compiled,
        texts: &NoStoredTexts,
    };
    let list = corrigenda(&w.state().core, GUIDE_CALL, &source).unwrap();
    assert_eq!(list.len(), 1);
    let c = &list[0];
    let snapshot = fstp_domain::programme::call(&w.state().core, GUIDE_CALL)
        .and_then(|v| v.frozen())
        .map(|f| f.snapshot().clone())
        .unwrap();
    let mut want = descriptions(&compiled, &snapshot.p13);
    want.insert(extra_description(901));
    assert_eq!(c.p13.iter().cloned().collect::<BTreeSet<_>>(), want);
}
