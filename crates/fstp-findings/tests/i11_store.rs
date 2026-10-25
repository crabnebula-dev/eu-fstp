//! I-11: every finding of a call carries the call's pinned configuration.
//!
//! Sources: `SPEC/02-domain/invariants.md` I-11, R-LA-05,
//! `SPEC/02-domain/policy-parameters.md` P-21 NOTE 10, and
//! `docs/handoff/m2-design.md` sections 0.3 and 2.13.
//!
//! The reference below is written from the spec text. It shares only id and
//! finding types with production. It keeps, per call, the configuration of
//! its findings and their ids.
//!
//! Readings taken where the design is silent, raised in the lane report:
//! - `insert(pinned, finding)` takes the call's pinned `config_id` from the
//!   caller, which reads it from the published call (`CallPublished`);
//! - an insert is refused when the finding's config differs from the pin,
//!   and also when the call already holds findings of another config, so
//!   the store alone keeps one config per call;
//! - `replace_call(call, config, findings)` is the P-21 NOTE 10 replacement.
//!   It succeeds only when every new finding names `call` and `config`, no
//!   id repeats, and `config` is neither the call's current config nor one
//!   it held before, since a replacement takes the next model on the list.
//!   It then holds exactly the new findings, and the call's config is
//!   `config`. A refused replacement changes nothing;
//! - after a replacement, later inserts are checked against the new config.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{CALLS, CONFIGS, finding};
use fstp_domain::id::{CallId, LlmConfigId};
use fstp_findings::{Finding, FindingRefusal, FindingStore};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The reference: per call, its configuration and its findings by id, and
/// the configurations it held before.
#[derive(Clone, Debug, Default)]
struct Reference {
    calls: BTreeMap<u128, (u128, BTreeMap<u128, Finding>)>,
    retired: BTreeMap<u128, BTreeSet<u128>>,
}

impl Reference {
    /// I-11: whether an insert keeps one pinned config per call.
    fn accepts_insert(&self, pinned: u128, f: &Finding) -> bool {
        let call = f.call.raw();
        let config = f.config.raw();
        if config != pinned {
            return false;
        }
        match self.calls.get(&call) {
            Some((held, _)) => *held == config,
            None => true,
        }
    }

    fn insert(&mut self, f: Finding) {
        let entry = self
            .calls
            .entry(f.call.raw())
            .or_insert_with(|| (f.config.raw(), BTreeMap::new()));
        entry.1.insert(f.id.raw(), f);
    }

    /// P-21 NOTE 10: whether a replacement is a whole, single-config set
    /// under a config the call has not held.
    fn accepts_replace(&self, call: u128, config: u128, new: &[Finding]) -> bool {
        let held = self.calls.get(&call).is_some_and(|(c, _)| *c == config);
        let retired = self.retired.get(&call).is_some_and(|r| r.contains(&config));
        if held || retired {
            return false;
        }
        let mut ids = BTreeSet::new();
        new.iter()
            .all(|f| f.call.raw() == call && f.config.raw() == config && ids.insert(f.id.raw()))
    }

    fn replace(&mut self, call: u128, config: u128, new: Vec<Finding>) {
        let set = new.into_iter().map(|f| (f.id.raw(), f)).collect();
        if let Some((old, _)) = self.calls.insert(call, (config, set)) {
            self.retired.entry(call).or_default().insert(old);
        }
    }
}

/// The store's findings of `call`, sorted by id.
fn stored(store: &FindingStore, call: u128) -> Vec<Finding> {
    let mut v: Vec<Finding> = store
        .findings_of(CallId::from_raw(call))
        .into_iter()
        .cloned()
        .collect();
    v.sort_by_key(|f| f.id.raw());
    v
}

/// I-11 over the whole store, compared with the reference in both
/// directions: the same findings per call, and one config per call that
/// every finding of the call carries.
fn agrees(store: &FindingStore, reference: &Reference) -> Result<(), String> {
    for &call in &CALLS {
        let got = stored(store, call);
        let want: Vec<Finding> = reference
            .calls
            .get(&call)
            .map(|(_, m)| m.values().cloned().collect())
            .unwrap_or_default();
        prop_assert_eq!(&got, &want, "findings of call {}", call);

        let config = store.config_of(CallId::from_raw(call));
        match reference.calls.get(&call) {
            Some((held, _)) => {
                prop_assert_eq!(config, Some(LlmConfigId::from_raw(*held)), "call {}", call);
            }
            None => prop_assert_eq!(config, None, "call {} holds no finding", call),
        }
        for f in &got {
            prop_assert_eq!(
                f.call,
                CallId::from_raw(call),
                "finding {:?} filed under",
                f.id
            );
            prop_assert_eq!(
                Some(f.config),
                config,
                "I-11: finding {:?} of call {}",
                f.id,
                call
            );
        }
    }
    Ok(())
}

/// One insert step: a call, the finding's config and the pin passed in.
/// Weighted so that accepted inserts, foreign pins and mixed configs all
/// occur often.
fn insert_step(g: &mut Gen, reference: &Reference, next_id: &mut u128) -> (u128, Finding) {
    let call = *g.pick(&CALLS);
    let held = reference.calls.get(&call).map(|(c, _)| *c);
    let (config, pinned) = match g.weighted(&[3, 2, 2]) {
        // The pin and the finding agree with the call's config.
        0 => {
            let c = held.unwrap_or(*g.pick(&CONFIGS));
            (c, c)
        }
        // The pin and the finding agree, perhaps against the held config.
        1 => {
            let c = *g.pick(&CONFIGS);
            (c, c)
        }
        // Any finding config and any pin.
        _ => (*g.pick(&CONFIGS), *g.pick(&CONFIGS)),
    };
    let id = *next_id;
    *next_id += 1;
    (pinned, finding(g, id, call, config))
}

/// I-11, R-LA-05, design section 2.13: an insert into the finding store is
/// accepted exactly when the finding's `config_id` equals the call's pinned
/// `config_id` and the call holds no finding of another config. A refused
/// insert is an I-11 refusal and leaves the store unchanged. At every step,
/// every finding of a call carries one config.
#[test]
fn i11_store_refuses_foreign_config() {
    check("i11_store_refuses_foreign_config", |g| {
        let mut store = FindingStore::genesis();
        let mut reference = Reference::default();
        let mut next_id = 1u128;
        let steps = g.usize_in(1..=24);
        for step in 0..steps {
            let (pinned, f) = insert_step(g, &reference, &mut next_id);
            g.note_with(|| {
                format!(
                    "step {step}: call {} config {} pinned {pinned}",
                    f.call.raw(),
                    f.config.raw()
                )
            });
            let want = reference.accepts_insert(pinned, &f);
            let before = store.clone();
            let got = store.insert(LlmConfigId::from_raw(pinned), f.clone());
            match (&got, want) {
                (Ok(()), true) => reference.insert(f),
                (Err(FindingRefusal::ForeignConfig { .. }), false) => {
                    prop_assert!(store == before, "a refused insert changed the store");
                }
                (Ok(()), false) => {
                    return Err(format!(
                        "I-11: accepted a finding of config {} into call {} (pin {pinned})",
                        f.config.raw(),
                        f.call.raw()
                    ));
                }
                (Err(e), _) => {
                    return Err(format!(
                        "insert refused with {e:?}, but the reference expects {}",
                        if want { "acceptance" } else { "ForeignConfig" }
                    ));
                }
            }
            agrees(&store, &reference)?;
        }
        Ok(())
    });
}

/// How a generated replacement set is spoiled, if at all.
#[derive(Clone, Copy, Debug)]
enum Spoil {
    None,
    ForeignConfig,
    OtherCall,
    RepeatedId,
    /// The replacement names the config the call already holds.
    HeldConfig,
}

/// I-11, P-21 NOTE 10: replacing a call's findings with a new config is one
/// atomic step. When every new finding names the call and the new config,
/// with no repeated id, the call then holds exactly the new findings under
/// the new config. No earlier finding of the call survives, and other calls
/// are untouched. Any other set is refused and the store is unchanged. A
/// later insert is checked against the new config, so configs never mix.
/// A replacement under the config the call already holds is refused, since
/// a replacement takes the next model on the frozen P-21 list.
#[test]
fn i11_replacement_is_atomic() {
    check("i11_replacement_is_atomic", |g| {
        let mut store = FindingStore::genesis();
        let mut reference = Reference::default();
        let mut next_id = 1u128;

        // A start state of accepted inserts only, one config per call.
        let mut configs = BTreeMap::new();
        for &call in &CALLS {
            configs.insert(call, *g.pick(&CONFIGS));
        }
        let target = *g.pick(&CALLS);
        let start = g.vec(1..=8, |g| *g.pick(&CALLS));
        for call in std::iter::once(target).chain(start) {
            let c = configs[&call];
            let f = finding(g, next_id, call, c);
            next_id += 1;
            store
                .insert(LlmConfigId::from_raw(c), f.clone())
                .map_err(|e| format!("start insert refused: {e:?}"))?;
            reference.insert(f);
        }
        agrees(&store, &reference)?;

        // The replacement set: fresh ids, a config the call has not held
        // (P-21 NOTE 10), maybe spoiled.
        let held_config = configs[&target];
        let fresh: Vec<u128> = CONFIGS
            .iter()
            .copied()
            .filter(|&c| c != held_config)
            .collect();
        let mut new_config = *g.pick(&fresh);
        let mut new: Vec<Finding> = g.vec(1..=5, |g| {
            let f = finding(g, next_id, target, new_config);
            next_id += 1;
            f
        });
        let spoil = *g.pick(&[
            Spoil::None,
            Spoil::None,
            Spoil::ForeignConfig,
            Spoil::OtherCall,
            Spoil::RepeatedId,
            Spoil::HeldConfig,
        ]);
        let at = g.usize_in(0..=new.len() - 1);
        match spoil {
            Spoil::None => {}
            Spoil::ForeignConfig => {
                let other = CONFIGS.iter().copied().find(|&c| c != new_config).unwrap();
                new[at].config = LlmConfigId::from_raw(other);
            }
            Spoil::OtherCall => {
                let other = CALLS.iter().copied().find(|&c| c != target).unwrap();
                new[at].call = CallId::from_raw(other);
            }
            Spoil::RepeatedId => {
                let dup = finding(g, new[at].id.raw(), target, new_config);
                new.push(dup);
            }
            Spoil::HeldConfig => {
                new_config = held_config;
                for f in &mut new {
                    f.config = LlmConfigId::from_raw(held_config);
                }
            }
        }
        g.note("target", &target);
        g.note("new_config", &new_config);
        g.note("spoil", &spoil);

        let want = reference.accepts_replace(target, new_config, &new);
        prop_assert_eq!(want, matches!(spoil, Spoil::None), "reference self-check");
        let before = store.clone();
        let got = store.replace_call(
            CallId::from_raw(target),
            LlmConfigId::from_raw(new_config),
            new.clone(),
        );
        match (&got, want) {
            (Ok(()), true) => reference.replace(target, new_config, new),
            (Err(_), false) => {
                prop_assert!(store == before, "a refused replacement changed the store");
            }
            (Ok(()), false) => {
                return Err(format!("accepted a {spoil:?} replacement set"));
            }
            (Err(e), true) => {
                return Err(format!("refused a whole replacement set with {e:?}"));
            }
        }
        agrees(&store, &reference)?;

        // Configs never mix after the step: the old config of the target
        // is refused when it differs, and its current config is accepted.
        let held = store.config_of(CallId::from_raw(target)).unwrap();
        for &c in &CONFIGS {
            let f = finding(g, next_id, target, c);
            next_id += 1;
            let snapshot = store.clone();
            let r = store.insert(LlmConfigId::from_raw(c), f.clone());
            if LlmConfigId::from_raw(c) == held {
                prop_assert!(
                    r.is_ok(),
                    "insert under the current config refused: {:?}",
                    r
                );
                reference.insert(f);
            } else {
                prop_assert!(
                    matches!(r, Err(FindingRefusal::ForeignConfig { .. })),
                    "insert of config {} after replacement: {:?}",
                    c,
                    r
                );
                prop_assert!(store == snapshot, "a refused insert changed the store");
            }
        }
        agrees(&store, &reference)
    });
}
