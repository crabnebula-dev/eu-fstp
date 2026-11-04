//! I-50 and I-51 for the fields the compile step binds (M4 design
//! sections 3.1 and 3.2).
//!
//! - I-50: P-05 never exceeds P-58. A save that would break it is refused
//!   at save, naming both values (R-PG-01 AC; I-50 timing, Daniel's answer
//!   of 2026-10-31, M4 design section 15.0). So the core policy keeps P-05
//!   at or below P-58, and no draft holds a cap above the ceiling.
//! - I-51: a Guide binds its parameter values from the draft policy. The
//!   creator's part is that the core head policy is exactly the compiled
//!   draft spec, so every parameter a Guide reads equals the saved value.

use fstp_creator::CreatorRefusal;
use fstp_programme::{CompileIds, FIELDS, FieldId, FieldKind, ProgrammeSpec, compile};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use crate::harness::{
    Fail, M1, P, adr006, decode, edit, forged, full_save, he, opened, synthetic_spec, value_of,
};

/// I-51: after the save of every field of the synthetic spec, the core
/// head policy equals `fstp_programme::compile` of that spec under the
/// head's own ids. So every parameter a Guide binds from the draft policy
/// equals the value the programme manager saved.
#[test]
fn i51_core_head_policy_is_the_compiled_saved_spec() {
    let mut cell = opened();
    let spec = synthetic_spec();
    cell.save(M1, full_save(&spec, None))
        .unwrap_or_else(|f| panic!("the save is refused: {f:?}"));
    let head = cell.policy().clone();
    let want = compile(&spec, &he(), CompileIds::new(P, head.id, head.parent))
        .unwrap()
        .policy;
    assert_eq!(head, want);
}

/// I-51: a save of any one policy field of the synthetic spec makes the
/// core head equal the compiled blank spec with that field set, under the
/// head's own ids. A value the core policy validation refuses is refused
/// with the same rule and appends nothing.
#[test]
fn i51_saved_policy_field_reaches_the_core_policy_exactly() {
    let spec = synthetic_spec();
    let policy_fields: Vec<FieldId> = FIELDS
        .iter()
        .filter(|f| f.kind == FieldKind::Policy && f.id != FieldId::P53)
        .map(|f| f.id)
        .collect();
    check(
        "i51_saved_policy_field_reaches_the_core_policy_exactly",
        |g| {
            let field = *g.pick(&policy_fields);
            g.note("field", &field.key());
            let value = value_of(&spec, field);
            let mut cell = forged();
            let before = cell.policy().clone();
            let entries = cell.entries.len();
            let got = cell.save(M1, vec![edit(value.clone(), 5)]);
            let mut target: ProgrammeSpec = he().blank();
            target.set(value);
            match got {
                Ok(_) => {
                    let head = cell.policy().clone();
                    prop_assert_eq!(head.parent, Some(before.id));
                    let want = compile(&target, &he(), CompileIds::new(P, head.id, head.parent))
                        .map_err(|e| format!("{e}"))?
                        .policy;
                    prop_assert_eq!(head, want);
                }
                Err(f) => {
                    let want = compile(&target, &he(), CompileIds::new(P, before.id, None))
                        .map_err(|e| format!("{e}"))?
                        .policy;
                    let rule = fstp_domain::policy::validate(&want).err().map(|r| r.rule);
                    prop_assert!(
                        rule.is_some(),
                        "a save the core policy validation admits is refused: {:?}",
                        f
                    );
                    prop_assert!(
                        matches!(f, Fail::Core(r) if Some(r.rule) == rule),
                        "the refusal {:?} does not name the validation rule {:?}",
                        f,
                        rule
                    );
                    prop_assert_eq!(cell.entries.len(), entries);
                }
            }
            Ok(())
        },
    );
}

/// I-50, R-PG-01 AC: a save of P-05 and P-58 in one edit never leaves the
/// core policy with P-05 above P-58. When P-05 is above P-58 the save is
/// refused at save with `CapAboveCeiling`, which names both values as
/// ADR-006 strings, and appends nothing (Daniel's answer of 2026-10-31,
/// M4 design section 15.0). When P-05 is at or below P-58 the save is
/// recorded with both values.
#[test]
fn i50_p05_above_p58_never_reaches_the_core_policy_or_activation() {
    check(
        "i50_p05_above_p58_never_reaches_the_core_policy_or_activation",
        |g| {
            let p05 = g.u32_in(0..=100_000_000);
            let p58 = g.u32_in(0..=100_000_000);
            g.note("p05", &adr006(p05));
            g.note("p58", &adr006(p58));
            let mut cell = forged();
            let entries = cell.entries.len();
            let got = cell.save(
                M1,
                vec![
                    edit(decode(FieldId::P05, &format!("\"{}\"", adr006(p05))), 6),
                    edit(decode(FieldId::P58, &format!("\"{}\"", adr006(p58))), 6),
                ],
            );
            let head = cell.policy().clone();
            if let Some(c) = head.live.p58 {
                prop_assert!(
                    head.live.p05.amount().cmp_same(c.amount()) != Ok(std::cmp::Ordering::Greater),
                    "I-50: the core policy holds P-05 {} above P-58 {}",
                    head.live.p05.amount(),
                    c.amount()
                );
            }
            match (p05 > p58, got) {
                (false, Ok(_)) => {
                    prop_assert_eq!(head.live.p05.amount().to_string(), adr006(p05));
                    prop_assert_eq!(
                        head.live.p58.map(|a| a.amount().to_string()),
                        Some(adr006(p58))
                    );
                }
                (false, Err(f)) => {
                    return Err(format!("a save within the ceiling is refused: {f:?}"));
                }
                (true, Err(f)) => {
                    let named = match &f {
                        Fail::Creator(CreatorRefusal::CapAboveCeiling { p05: a, p58: b }) => {
                            a.amount().to_string() == adr006(p05)
                                && b.amount().to_string() == adr006(p58)
                        }
                        _ => false,
                    };
                    prop_assert!(
                        named,
                        "the refusal does not name I-50 with both values as ADR-006 strings: {:?}",
                        f
                    );
                    prop_assert_eq!(cell.entries.len(), entries);
                }
                (true, Ok(_)) => {
                    return Err("I-50 at save: a save of P-05 above P-58 was recorded".to_owned());
                }
            }
            Ok(())
        },
    );
}
