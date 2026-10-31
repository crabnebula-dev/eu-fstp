//! Fuzz target `spec_compile` of `fstp-programme` (TH-26, H-05, R-PG-01,
//! M4 design section 9).
//!
//! The input is either a spec that `decode_spec` accepts, or a script of
//! leaf edits applied to the SuperSAFE fixture's spec. Checks:
//! - `compile` never panics, and a refusal formats;
//! - `compile` is deterministic;
//! - an accepted spec round-trips: `decompile` of what `compile` returned
//!   is the spec again;
//! - gaps round-trip: with any further fields unset, the decompiled spec
//!   compiles, names exactly those fields as unset, and decompiles back.

#![no_main]

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_json::{Value, parse_str, to_compact};
use fstp_programme::{
    CompileIds, FIELDS, FieldId, FunderProfile, ProgrammeSpec, compile, decode_spec, decompile,
};
use libfuzzer_sys::fuzz_target;

const FIXTURE: &str = include_str!("../../fixtures/supersafe.programme.json");

/// The fixture's `"spec"` member, parsed once.
fn base() -> Option<&'static Value> {
    static BASE: OnceLock<Option<Value>> = OnceLock::new();
    BASE.get_or_init(|| parse_str(FIXTURE).ok()?.get("spec").cloned())
        .as_ref()
}

/// Reads bytes from the input and yields zero once it runs out.
struct Script<'a>(&'a [u8]);

impl Script<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    fn index(&mut self, len: usize) -> usize {
        let raw = usize::from(self.byte()) << 8 | usize::from(self.byte());
        if len == 0 { 0 } else { raw % len }
    }
}

/// Whether `v` is an edit point: a leaf or a non-empty array.
fn is_point(v: &Value) -> bool {
    match v {
        Value::Object(_) => false,
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

/// The number of edit points below the root, in the order `edit` walks.
fn count_points(v: &Value) -> usize {
    let mut n = 0_usize;
    let mut stack: Vec<&Value> = vec![v];
    let mut root = true;
    while let Some(v) = stack.pop() {
        if !root && is_point(v) {
            n += 1;
        }
        root = false;
        match v {
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(o) => stack.extend(o.values()),
            _ => {}
        }
    }
    n
}

/// Applies one scripted edit to the edit point the script selects.
fn edit(v: &mut Value, s: &mut Script<'_>) {
    let target = s.index(count_points(v));
    let op = s.byte();
    let mut stack: Vec<&mut Value> = vec![v];
    let mut seen = 0_usize;
    let mut root = true;
    while let Some(v) = stack.pop() {
        let keep = !root && is_point(v);
        root = false;
        if keep {
            if seen == target {
                apply(v, op, s);
                return;
            }
            seen += 1;
        }
        match v {
            Value::Array(a) => stack.extend(a.iter_mut()),
            Value::Object(o) => stack.extend(o.iter_mut().map(|(_, x)| x)),
            _ => {}
        }
    }
}

fn apply(v: &mut Value, op: u8, s: &mut Script<'_>) {
    let new = match &*v {
        Value::Bool(b) => Value::Bool(!b),
        Value::Number(_) => Value::from(i64::from(s.byte()) - 30),
        Value::String(_) if op.is_multiple_of(2) => {
            let whole = u32::from(s.byte()) << 16 | u32::from(s.byte()) << 8 | u32::from(s.byte());
            Value::String(format!("{whole}.{:02}", s.byte() % 100))
        }
        Value::String(_) => {
            let len = usize::from(s.byte() % 24);
            let text: String = (0..len).map(|_| char::from(s.byte())).collect();
            Value::String(text)
        }
        Value::Array(a) => {
            let mut items = a.clone().into_vec();
            let at = s.index(items.len());
            if op.is_multiple_of(2) {
                if let Some(x) = items.get(at).cloned() {
                    items.push(x);
                }
            } else if at < items.len() {
                items.remove(at);
            }
            Value::from(items)
        }
        other => other.clone(),
    };
    *v = new;
}

fn ids() -> CompileIds {
    CompileIds::new(
        ProgrammeId::from_raw(0x5afe_0000_0001),
        PolicyVersionId::from_raw(0x5afe_0000_0002),
        None,
    )
}

/// The spec under test: the input itself, or the fixture with edits.
fn spec_from(data: &[u8]) -> Option<(ProgrammeSpec, Script<'_>)> {
    if let Ok(s) = decode_spec(data) {
        return Some((s, Script(&[])));
    }
    let mut v = base()?.clone();
    let mut script = Script(data);
    for _ in 0..(script.byte() % 4) {
        edit(&mut v, &mut script);
    }
    decode_spec(to_compact(&v).as_bytes())
        .ok()
        .map(|s| (s, script))
}

fuzz_target!(|data: &[u8]| {
    let Some((spec, mut script)) = spec_from(data) else {
        return;
    };
    let profile = FunderProfile::horizon_europe();
    let compiled = match compile(&spec, &profile, ids()) {
        Ok(c) => c,
        Err(e) => {
            assert!(!format!("{e:?}").is_empty());
            assert!(
                compile(&spec, &profile, ids()).is_err(),
                "compile is not deterministic"
            );
            return;
        }
    };
    assert_eq!(
        compile(&spec, &profile, ids()).as_ref().ok(),
        Some(&compiled),
        "compile is not deterministic"
    );
    let back = decompile(&compiled.policy, &compiled.artefacts, &compiled.unset);
    assert_eq!(back, spec, "decompile does not invert compile");

    let mut unset: BTreeSet<FieldId> = compiled.unset.clone();
    for f in FIELDS {
        if script.byte() % 8 == 7 {
            unset.insert(f.id);
        }
    }
    let gapped = decompile(&compiled.policy, &compiled.artefacts, &unset);
    match compile(&gapped, &profile, ids()) {
        Ok(c) => {
            assert_eq!(c.unset, unset, "compile reports other unset fields");
            let again = decompile(&c.policy, &c.artefacts, &c.unset);
            assert_eq!(again, gapped, "a spec with gaps does not round-trip");
        }
        Err(e) => panic!("a spec with gaps does not compile: {e:?}"),
    }
});
